//! The listener's rate limit and lockout (protocol section 3, "failed-attempt
//! lockout").
//!
//! A listener answers whoever can reach the port, and one Noise handshake costs
//! real CPU, so section 3 bounds the damage twice:
//!
//! - a token bucket: 10 handshake attempts per minute per source address;
//! - a lockout: more than 5 `hello`s that did not end in a pairing, from one
//!   address and within 10 minutes, locks the listener itself for 5 minutes,
//!   doubling on each further violation.
//!
//! Both decisions are made *before* the handshake is read, because that is the
//! only point where refusing is free. The cost is that a refused connection
//! cannot be told why: the encrypted channel does not exist yet and section 2
//! has no cleartext error frame, so the PC closes the socket and that is all the
//! phone sees. `docs/windows.md` carries that consequence honestly, including
//! that the phone-side warning the spec asks for is not implemented yet.
//!
//! The lock is deliberately listener-wide rather than per address: the spec says
//! "locks the listener", and an attacker able to present several source
//! addresses would otherwise walk around a per-address lock. `docs/windows.md`
//! names the price of that choice as well.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Attempts are counted in thousandths of one.
///
/// Not for precision's sake: the refill has to be exact. A float bucket that
/// holds 0.9999999999 where the caller expects the one attempt a sixth of a
/// minute buys refuses a phone that did nothing wrong.
const MILLI: u64 = 1000;

/// How many source addresses are tracked at once.
///
/// A listener is reachable by whoever is on the network and an IPv6 attacker can
/// present a new address for every connection, so the map needs a bound. When it
/// is reached the oldest entry is forgotten, which is the least surprising thing
/// to lose: a forgotten address starts with a full bucket, which is what it
/// would have had anyway.
const MAX_TRACKED: usize = 1024;

/// How long an entry has to be quiet before it holds nothing worth keeping.
///
/// A bucket refills completely in one minute, whatever its capacity, since the
/// rate is defined per minute. Past that, an entry is indistinguishable from one
/// that was never seen, and it is dropped before anything older is.
const IDLE: Duration = Duration::from_secs(60);

/// No lock may be longer than this, whatever [`Limits`] says.
///
/// The length is added to `Instant::now()`, so a duration no clock can reach
/// would turn the ceiling into a panic. A day is longer than any lock should be.
pub const MAX_LOCK_CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// The numbers from protocol section 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Handshake attempts one source address may start per minute.
    pub attempts_per_ip_per_minute: u32,
    /// `hello`s that did not end in a pairing, from one address, before the
    /// listener locks.
    pub unattended_hellos: u32,
    /// How long those `hello`s are remembered.
    pub unattended_window: Duration,
    /// How long the first lock lasts; each further violation doubles it.
    pub first_lock: Duration,
    /// The ceiling the doubling stops at.
    ///
    /// Not in the spec, which says only "doubling per further violation". A
    /// ceiling is needed regardless, because an unbounded doubling stops being a
    /// number a clock can hold, and it earns its keep: without one, an attacker
    /// who keeps trying can hold the PC closed for as long as they care to, and
    /// the ceiling is the point at which the user gets their own PC back. An
    /// hour is long enough to matter to whoever is hammering.
    pub max_lock: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            attempts_per_ip_per_minute: 10,
            unattended_hellos: 5,
            unattended_window: Duration::from_secs(10 * 60),
            first_lock: Duration::from_secs(5 * 60),
            max_lock: Duration::from_secs(60 * 60),
        }
    }
}

/// Why a connection was closed before a byte of it was decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This source address has used up its attempts for the minute.
    RateLimited,
    /// The listener is locked because of `hello`s that never became a pairing.
    LockedOut {
        /// Time left on the lock when the connection was refused.
        remaining: Duration,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::RateLimited => write!(
                f,
                "too many handshake attempts from this address in the last minute"
            ),
            Refusal::LockedOut { remaining } => {
                // Whole seconds, rounded up: a countdown reading "0 s" while the
                // listener still refuses looks like a bug.
                let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                write!(f, "the listener is locked for another {secs} s")
            }
        }
    }
}

/// One listener's admission of one connection.
///
/// Returned by [`crate::Listener::accept`] with the socket it admitted, and
/// required by [`crate::accept`], so a connection cannot be taken up without the
/// limiter that let it in. That matters beyond tidiness: the pairing that
/// follows reports back through this value, and reporting back is what clears
/// the address's count of unattended `hello`s.
#[derive(Clone)]
pub struct Admitted {
    limit: Arc<RateLimit>,
    ip: IpAddr,
}

/// Only the address: the limiter is not what identifies an admission, and the
/// state behind it is a map of counters that nobody wants in a log line.
impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted").field("ip", &self.ip).finish()
    }
}

impl Admitted {
    pub(crate) fn new(limit: Arc<RateLimit>, ip: IpAddr) -> Self {
        Self { limit, ip }
    }

    /// The source address this connection came from.
    ///
    /// The only thing about the peer that is known before the handshake, and
    /// everything the limiter does is keyed on it.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Report a `hello` from an address whose key is not pinned.
    pub(crate) fn note_unattended_hello(&self) {
        self.limit.note_unattended_hello(self.ip);
    }

    /// Report that a pairing completed on this connection.
    pub(crate) fn note_paired(&self) {
        self.limit.note_paired(self.ip);
    }
}

/// One address's share of the limit.
#[derive(Debug)]
struct Client {
    /// Attempts left, in thousandths of one.
    tokens: u64,
    /// When `tokens` was last brought up to date.
    tokens_at: Instant,
    /// `hello`s that have not (yet) become a pairing, oldest first.
    unattended: VecDeque<Instant>,
    /// Last time this address did anything, which is what makes an entry the
    /// oldest to forget.
    last_seen: Instant,
}

impl Client {
    fn new(now: Instant, capacity: u64) -> Self {
        Self {
            tokens: capacity,
            tokens_at: now,
            unattended: VecDeque::new(),
            last_seen: now,
        }
    }

    /// Bring `tokens` up to date, capped at the capacity.
    ///
    /// The cap is the point of a bucket: coming back an hour later buys one
    /// minute's worth of attempts, not an hour's.
    fn refill(&mut self, now: Instant, capacity: u64) {
        let elapsed = now.saturating_duration_since(self.tokens_at);
        let gained = elapsed.as_millis() * u128::from(capacity) / 60_000;
        let gained = u64::try_from(gained.min(u128::from(capacity))).unwrap_or(capacity);
        self.tokens = self.tokens.saturating_add(gained).min(capacity);
        self.tokens_at = now;
    }

    /// Nothing here that a fresh entry would not have.
    fn is_idle(&self, now: Instant) -> bool {
        self.unattended.is_empty() && now.saturating_duration_since(self.last_seen) >= IDLE
    }
}

#[derive(Debug)]
struct State {
    clients: HashMap<IpAddr, Client>,
    /// Set while the listener is refusing everything.
    locked_until: Option<Instant>,
    /// Violations so far, which is what the doubling counts. They accumulate for
    /// the life of the process: the spec says "doubling per further violation"
    /// and says nothing about a violation expiring. The ceiling in [`Limits`] is
    /// what keeps that from running away.
    violations: u32,
}

impl State {
    /// The state for one address, created on first sight.
    fn entry(&mut self, ip: IpAddr, now: Instant, capacity: u64) -> &mut Client {
        if !self.clients.contains_key(&ip) && self.clients.len() >= MAX_TRACKED {
            // Drop what carries nothing first, then the quietest entries.
            // Forgetting an attacker costs at most one bucket, and this is the
            // only bound standing between this map and whoever is on the wire.
            self.clients.retain(|_, client| !client.is_idle(now));
            while self.clients.len() >= MAX_TRACKED {
                let oldest = self
                    .clients
                    .iter()
                    .min_by_key(|(_, client)| client.last_seen)
                    .map(|(ip, _)| *ip);
                match oldest {
                    Some(oldest) => {
                        self.clients.remove(&oldest);
                    }
                    // Cannot happen while the map is non-empty, but an
                    // unbounded loop would be worse than a full map.
                    None => break,
                }
            }
        }
        self.clients
            .entry(ip)
            .or_insert_with(|| Client::new(now, capacity))
    }
}

/// The failed-attempt limit for one listener.
///
/// Held by [`crate::Listener`] and shared with the sessions it accepts, so one
/// instance should cover every socket the app opens - the session listener and
/// the pairing listener both. An attacker does not care which port answers.
pub struct RateLimit {
    limits: Limits,
    state: Mutex<State>,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimit {
    /// The limits in protocol section 3.
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// The same limiter with different numbers, for tests and for a deployment
    /// that needs something other than the spec's.
    pub fn with_limits(mut limits: Limits) -> Self {
        // Clamped rather than trusted: the lock length is added to an `Instant`,
        // and a caller passing a duration no clock can reach would turn the
        // ceiling into a panic somewhere later.
        limits.max_lock = limits.max_lock.min(MAX_LOCK_CEILING);
        limits.first_lock = limits.first_lock.min(limits.max_lock);
        Self {
            limits,
            state: Mutex::new(State {
                clients: HashMap::new(),
                locked_until: None,
                violations: 0,
            }),
        }
    }

    /// The numbers in force.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Decide whether this address gets a handshake, spending one attempt if so.
    ///
    /// Called before a byte is read, so an over-limit connection costs a socket
    /// and nothing else.
    pub fn admit(&self, ip: IpAddr) -> Result<(), Refusal> {
        self.admit_at(ip, Instant::now())
    }

    /// [`admit`](Self::admit) against a caller-supplied clock, which is what the
    /// tests use to reach a lockout without waiting for one.
    pub fn admit_at(&self, ip: IpAddr, now: Instant) -> Result<(), Refusal> {
        let mut state = self.guard();

        if let Some(until) = state.locked_until {
            if until > now {
                return Err(Refusal::LockedOut {
                    remaining: until - now,
                });
            }
            state.locked_until = None;
        }

        let capacity = capacity_milli(&self.limits);
        let client = state.entry(ip, now, capacity);
        client.last_seen = now;
        client.refill(now, capacity);

        if client.tokens >= MILLI {
            client.tokens -= MILLI;
            Ok(())
        } else {
            Err(Refusal::RateLimited)
        }
    }

    /// A `hello` arrived from an address whose key is not pinned.
    ///
    /// Once one address has done this more times than the spec allows inside the
    /// window, the listener locks - every address, not just that one, because
    /// that is what the spec says and because a per-address lock is no obstacle
    /// to an attacker who can present more than one address.
    pub fn note_unattended_hello(&self, ip: IpAddr) {
        self.note_unattended_hello_at(ip, Instant::now())
    }

    /// [`note_unattended_hello`](Self::note_unattended_hello) against a
    /// caller-supplied clock.
    pub fn note_unattended_hello_at(&self, ip: IpAddr, now: Instant) {
        let mut state = self.guard();
        let capacity = capacity_milli(&self.limits);
        let window = self.limits.unattended_window;

        let mut violation = false;
        {
            let client = state.entry(ip, now, capacity);
            client.last_seen = now;

            while let Some(oldest) = client.unattended.front() {
                if now.saturating_duration_since(*oldest) >= window {
                    client.unattended.pop_front();
                } else {
                    break;
                }
            }
            client.unattended.push_back(now);

            if client.unattended.len() as u32 > self.limits.unattended_hellos {
                // Forget this address's run. The next violation has to earn its
                // own six hellos, which is what makes the doubling count
                // violations rather than hellos.
                client.unattended.clear();
                violation = true;
            }
        }

        if violation {
            state.violations = state.violations.saturating_add(1);
            let length = lock_length(&self.limits, state.violations);
            // Cannot overflow: `with_limits` clamped the length to a day.
            state.locked_until = Some(now + length);
        }
    }

    /// A pairing completed on a connection from this address.
    ///
    /// The phone is no longer a stranger, so its run of unattended `hello`s is
    /// forgotten. The attempts it spent stay spent: a phone that needed six
    /// tries to pair really did use six.
    pub fn note_paired(&self, ip: IpAddr) {
        let mut state = self.guard();
        if let Some(client) = state.clients.get_mut(&ip) {
            client.unattended.clear();
        }
    }

    /// How much longer the listener stays locked, for a UI countdown.
    pub fn lock_remaining(&self) -> Option<Duration> {
        self.lock_remaining_at(Instant::now())
    }

    /// [`lock_remaining`](Self::lock_remaining) against a caller-supplied clock.
    pub fn lock_remaining_at(&self, now: Instant) -> Option<Duration> {
        let state = self.guard();
        state
            .locked_until
            .filter(|until| *until > now)
            .map(|until| until - now)
    }

    /// The state, taken even if an earlier holder panicked.
    ///
    /// The poison lint is about protecting invariants worth protecting. These
    /// are counters, and a limiter that refused every connection for the rest of
    /// the process after one panic would be the worse bug.
    fn guard(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Attempts in thousandths, for the integer refill.
fn capacity_milli(limits: &Limits) -> u64 {
    u64::from(limits.attempts_per_ip_per_minute) * MILLI
}

/// The spec's doubling, stopped at the ceiling.
fn lock_length(limits: &Limits, violations: u32) -> Duration {
    let doublings = violations.saturating_sub(1).min(16);
    limits
        .first_lock
        .saturating_mul(1 << doublings)
        .min(limits.max_lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 168, 1, n])
    }

    /// The spec's shape, small enough to reason about: four attempts a minute,
    /// two hellos tolerated, a lock of one second doubling to eight.
    fn small() -> Limits {
        Limits {
            attempts_per_ip_per_minute: 4,
            unattended_hellos: 2,
            unattended_window: Duration::from_secs(60),
            first_lock: Duration::from_secs(1),
            max_lock: Duration::from_secs(8),
        }
    }

    #[test]
    fn the_defaults_are_the_numbers_in_the_spec() {
        let limits = Limits::default();
        assert_eq!(limits.attempts_per_ip_per_minute, 10);
        assert_eq!(limits.unattended_hellos, 5);
        assert_eq!(limits.unattended_window, Duration::from_secs(600));
        assert_eq!(limits.first_lock, Duration::from_secs(300));
        assert!(limits.max_lock >= limits.first_lock);
    }

    #[test]
    fn an_address_gets_its_attempts_and_the_next_one_is_refused() {
        let limit = RateLimit::new();
        let t = Instant::now();
        for attempt in 1..=10 {
            assert_eq!(limit.admit_at(ip(1), t), Ok(()), "attempt {attempt}");
        }
        assert_eq!(limit.admit_at(ip(1), t), Err(Refusal::RateLimited));
        // Every address has its own bucket.
        assert_eq!(limit.admit_at(ip(2), t), Ok(()));
    }

    #[test]
    fn the_bucket_refills_by_the_minute_and_does_not_bank_unused_minutes() {
        let limit = RateLimit::new();
        let t = Instant::now();
        for _ in 0..10 {
            assert_eq!(limit.admit_at(ip(1), t), Ok(()));
        }
        assert_eq!(limit.admit_at(ip(1), t), Err(Refusal::RateLimited));

        // Ten a minute is one every six seconds, exactly, which is the case the
        // integer refill exists for.
        let six = t + Duration::from_secs(6);
        assert_eq!(limit.admit_at(ip(1), six), Ok(()));
        assert_eq!(limit.admit_at(ip(1), six), Err(Refusal::RateLimited));

        // An hour later it is a full bucket, not sixty of them.
        let hour = t + Duration::from_secs(3600);
        let mut admitted = 0;
        for _ in 0..30 {
            if limit.admit_at(ip(1), hour).is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 10);
    }

    #[test]
    fn the_sixth_unattended_hello_locks_the_listener_for_five_minutes() {
        let limit = RateLimit::new();
        let t = Instant::now();
        for i in 0..5 {
            limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(i));
        }
        assert_eq!(limit.lock_remaining_at(t + Duration::from_secs(4)), None);

        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(5));
        assert_eq!(
            limit.lock_remaining_at(t + Duration::from_secs(5)),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn the_lock_stops_every_address_not_just_the_one_that_earned_it() {
        let limit = RateLimit::with_limits(small());
        let t = Instant::now();
        limit.note_unattended_hello_at(ip(1), t);
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(1));
        // Two is not more than two.
        assert_eq!(limit.admit_at(ip(2), t), Ok(()));

        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(2));
        assert_eq!(
            limit.admit_at(ip(2), t + Duration::from_secs(2)),
            Err(Refusal::LockedOut {
                remaining: Duration::from_secs(1)
            })
        );

        // And it lifts on its own, with no help from anyone.
        assert_eq!(
            limit.admit_at(ip(2), t + Duration::from_secs(4)),
            Ok(()),
            "the lock is over"
        );
        assert_eq!(limit.lock_remaining_at(t + Duration::from_secs(4)), None);
    }

    #[test]
    fn a_pairing_forgets_that_address_run_of_hellos() {
        let limit = RateLimit::with_limits(small());
        let t = Instant::now();
        limit.note_unattended_hello_at(ip(1), t);
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(1));
        limit.note_paired(ip(1));

        // The run starts again from nothing: two more hellos are still only two.
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(2));
        assert_eq!(limit.lock_remaining_at(t + Duration::from_secs(2)), None);
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(3));
        assert_eq!(limit.lock_remaining_at(t + Duration::from_secs(3)), None);

        // The third one after the pairing is the violation.
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(4));
        assert!(limit
            .lock_remaining_at(t + Duration::from_secs(4))
            .is_some());
    }

    #[test]
    fn hellos_older_than_the_window_are_forgotten() {
        let limit = RateLimit::with_limits(small());
        let t = Instant::now();
        limit.note_unattended_hello_at(ip(1), t);
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(1));

        // The next two are past the window, so the first two no longer count
        // towards anything.
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(61));
        limit.note_unattended_hello_at(ip(1), t + Duration::from_secs(62));
        assert_eq!(limit.lock_remaining_at(t + Duration::from_secs(62)), None);
    }

    #[test]
    fn the_lock_doubles_per_violation_and_stops_at_the_ceiling() {
        let limit = RateLimit::with_limits(small());
        let mut t = Instant::now();
        let mut expected = 1u64;

        for violation in 1..=5 {
            for _ in 0..3 {
                limit.note_unattended_hello_at(ip(1), t);
            }
            let remaining = limit
                .lock_remaining_at(t)
                .unwrap_or_else(|| panic!("violation {violation} should lock"));
            assert_eq!(
                remaining,
                Duration::from_secs(expected),
                "violation {violation}"
            );
            // Wait the lock out; the next violation doubles it.
            t += Duration::from_secs(remaining.as_secs() + 1);
            expected = (expected * 2).min(8);
        }
    }

    #[test]
    fn a_lock_is_never_longer_than_a_clock_can_hold() {
        let limit = RateLimit::with_limits(Limits {
            first_lock: Duration::from_secs(u64::from(u32::MAX)),
            max_lock: Duration::from_secs(u64::from(u32::MAX)),
            ..Limits::default()
        });
        let t = Instant::now();
        for _ in 0..6 {
            limit.note_unattended_hello_at(ip(1), t);
        }
        assert_eq!(
            limit.lock_remaining_at(t).expect("locked"),
            MAX_LOCK_CEILING,
            "the ceiling holds even when `Limits` asks for a century"
        );
    }

    #[test]
    fn tracked_addresses_stay_bounded_and_the_oldest_are_forgotten() {
        let limit = RateLimit::new();
        let t = Instant::now();
        let address = |n: usize| IpAddr::from([10, 0, (n >> 8) as u8, (n & 0xff) as u8]);

        for n in 0..(MAX_TRACKED + 100) {
            assert_eq!(limit.admit_at(address(n), t), Ok(()), "address {n}");
        }
        assert!(
            limit.guard().clients.len() <= MAX_TRACKED,
            "{} entries tracked",
            limit.guard().clients.len()
        );
        // Forgetting is not refusing: an address that was dropped gets a fresh
        // bucket rather than a locked door.
        assert_eq!(limit.admit_at(address(1), t), Ok(()));
    }

    #[test]
    fn a_refusal_reads_like_a_sentence() {
        assert!(Refusal::RateLimited.to_string().contains("last minute"));
        let locked = Refusal::LockedOut {
            remaining: Duration::from_millis(1500),
        };
        // Rounded up, so a countdown never says "1 s" while it still refuses.
        assert!(locked.to_string().contains("2 s"), "{locked}");
    }
}
