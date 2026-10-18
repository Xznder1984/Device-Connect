//! The PC side of one connection: listen, handshake, exchange hellos, then talk
//! on the control channel (protocol sections 2 and 3).
//!
//! A connection moves through two types, and that is the whole consent model:
//!
//! ```text
//!   TcpStream --accept--> PendingSession --confirm--> ActiveSession
//!                                       \--reject--> (closed)
//! ```
//!
//! [`PendingSession`] has already proved who the phone is - the handshake is
//! mutual, so the peer's static key is known before anyone decides anything -
//! but it will not answer a single request. [`PendingSession::confirm`] is what
//! records the decision to trust that key, and only the user can make it, after
//! comparing the six-digit code on both screens (section 3).
//!
//! Before any of that, [`Listener::accept`] decides whether the connection is
//! even worth a handshake: section 3's per-address attempt budget and its
//! lockout for repeated unattended `hello`s. A refused connection is closed
//! without reading a byte of it, so [`Arrival`] - not a bare `TcpStream` - is
//! what a listener hands over.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use dc_protocol::error_codes::ErrorCode;
use dc_protocol::framing::{mtype, Channel, Frame};
use dc_protocol::records::{handshake_over_stream, RecordError, Role, SecureTransport, WireStream};
use dc_protocol::schema::{
    request_frame, response_frame, ErrorBody, Event, Request, Response, SessionHello,
    SessionHelloAck,
};
use serde_json::{json, Value};

use crate::identity::{device_id, HostInfo, Identity};
use crate::limit::{Admitted, RateLimit, Refusal};
use crate::pairing::{confirmation_code, PairingOffer};
use crate::store::StoreError;
use crate::trust::{Peer, TrustStore};

/// How long a peer gets to finish the handshake and the `hello` exchange.
///
/// Long enough for a phone on a slow Wi-Fi link, short enough that a scanner
/// that connects and says nothing cannot hold a thread. The session swaps in the
/// reply timeout once the exchange is done.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a reply to one request.
///
/// Section 2.5 asks a server to answer within 10 s or return `BUSY`, so waiting
/// a little longer than that means a busy phone answers rather than looking
/// dead.
pub const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Something that ended a connection.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("malformed message from the phone: {0}")]
    Message(String),
    #[error("the phone speaks protocol version {peer}, this build speaks {ours}")]
    ProtocolMismatch { peer: u32, ours: u32 },
    #[error("no reply within {0:?}; this connection can no longer be trusted and must be dropped")]
    Timeout(Duration),
    #[error("the phone sent an unsolicited error: {code}: {message}")]
    Refused { code: ErrorCode, message: String },
    #[error("the phone ended the pairing; its key has been deleted")]
    Unpaired,
    #[error("the connection ended before the request was answered")]
    Closed,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The address of the PC that reaches the local network, if there is one.
///
/// `connect` on a UDP socket sends nothing; it only asks the routing table which
/// local address would be used for that destination, and the address is what the
/// phone has to dial. TEST-NET-1 is used because it is reserved and will never
/// be a real service, so no packet ever leaves.
pub fn local_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// What a listener got: either a connection worth handing to [`accept`], or one
/// it refused before reading a byte of it.
///
/// A refusal is not an error. It is the steady state of a listener under
/// attack, and a caller has to keep going either way, which is why it comes back
/// as a value with the reason rather than as a [`SessionError`].
#[derive(Debug)]
pub enum Arrival {
    /// A connection that passed the rate limit. Run [`accept`] on it.
    Connected {
        /// The socket, untouched: nothing has been read from it yet.
        stream: TcpStream,
        /// The admission this listener granted, which [`accept`] needs and which
        /// carries the address the limiter counts against.
        admitted: Admitted,
    },
    /// A connection that was closed without a handshake. The phone sees the
    /// socket close, which is all it can be told: there is no encrypted channel
    /// yet and section 2 has no cleartext error frame.
    Refused {
        /// Who was refused.
        peer: SocketAddr,
        /// Which limit they hit, for the UI.
        reason: Refusal,
    },
}

/// The socket the phone dials into.
///
/// The PC never connects out and never opens anything the user did not ask for:
/// [`Listener::bind`] is called when a session listener is started, and the
/// socket is closed as soon as the app stops listening.
///
/// Every listener carries a [`RateLimit`], and the app should give the same one
/// to all of its listeners: the session listener and the pairing listener are
/// two doors into the same PC and an attacker does not care which one answers.
pub struct Listener {
    inner: TcpListener,
    limit: Arc<RateLimit>,
}

impl Listener {
    /// Bind `port` on every interface. Port 0 asks the operating system for a
    /// free one, which is what the QR's `p` field should carry.
    ///
    /// The limiter is a fresh one; when the app opens a second listener for the
    /// pairing window, build it with [`Listener::with_limit`] and the first
    /// listener's [`Listener::rate_limit`] so both share one budget.
    pub fn bind(port: u16) -> Result<Self, SessionError> {
        Self::with_limit(port, Arc::new(RateLimit::new()))
    }

    /// [`bind`](Self::bind) with a limiter the caller already has.
    pub fn with_limit(port: u16, limit: Arc<RateLimit>) -> Result<Self, SessionError> {
        let inner = TcpListener::bind(("0.0.0.0", port))?;
        Ok(Self { inner, limit })
    }

    /// The port actually bound.
    pub fn port(&self) -> Result<u16, SessionError> {
        Ok(self.inner.local_addr()?.port())
    }

    /// This listener's limiter, for sharing and for reading the lockout
    /// countdown the UI shows.
    pub fn rate_limit(&self) -> &Arc<RateLimit> {
        &self.limit
    }

    /// Wait for the next connection and decide whether it is worth a handshake.
    ///
    /// The check happens here, before a byte is read, so an over-limit
    /// connection costs a socket and nothing else. A refused socket is shut down
    /// rather than dropped where it stands: left in the accept queue it would
    /// make the phone wait for a handshake that is never coming.
    ///
    /// The returned stream still has no read timeout: [`accept`] sets the
    /// handshake budget. Interactive traffic sets `TCP_NODELAY` so a request is
    /// not held back waiting for more bytes.
    pub fn accept(&self) -> Result<Arrival, SessionError> {
        let (stream, peer) = self.inner.accept()?;

        if let Err(reason) = self.limit.admit(peer.ip()) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            drop(stream);
            return Ok(Arrival::Refused { peer, reason });
        }

        stream.set_nodelay(true)?;
        Ok(Arrival::Connected {
            stream,
            admitted: Admitted::new(Arc::clone(&self.limit), peer.ip()),
        })
    }
}

/// Everything a session needs that is not the peer.
pub struct SessionConfig {
    pub identity: Identity,
    pub host: HostInfo,
    pub trust: Arc<dyn TrustStore>,
    /// The Noise prologue for this connection (section 2.2). Defaults to manual
    /// mode; a QR window sets it from [`PairingOffer::prologue`].
    pub prologue: Vec<u8>,
    /// What the PC offers the phone in `hello_ack`. Empty is the honest value:
    /// this build has no PC-side capability to hand over yet.
    pub caps: Vec<String>,
    /// How long a request may go unanswered before the link is declared dead.
    pub reply_timeout: Duration,
}

impl SessionConfig {
    pub fn new(identity: Identity, host: HostInfo, trust: Arc<dyn TrustStore>) -> Self {
        Self {
            identity,
            host,
            trust,
            prologue: dc_protocol::noise::prologue(None),
            caps: Vec::new(),
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
        }
    }

    /// Bind this connection to a pairing window's mode byte.
    pub fn with_offer(mut self, offer: &PairingOffer) -> Self {
        self.prologue = offer.prologue();
        self
    }

    pub fn with_reply_timeout(mut self, timeout: Duration) -> Self {
        self.reply_timeout = timeout;
        self
    }
}

/// What is known about the phone at the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The phone's static public key, as proved by the handshake. Everything
    /// else here is the phone's own claim and is display-only.
    pub peer_key: [u8; 32],
    /// Derived from `peer_key`, never trusted from the wire.
    pub peer_id: String,
    /// The name the phone reported. Display only.
    pub peer_name: String,
    pub peer_model: Option<String>,
    pub peer_os: String,
    /// Capabilities the phone says it has switched on. Advisory: the phone
    /// enforces them per request, so a change here is never the last word.
    pub peer_caps: Vec<String>,
    /// The six digits both screens must show (section 3.3).
    pub code: String,
    /// Whether this key was already pinned when the connection arrived.
    pub paired: bool,
}

/// Frame counters and the encrypted stream, shared by both session states.
struct Connection {
    wire: WireStream<TcpStream, TcpStream>,
    transport: SecureTransport,
    seq: HashMap<u8, u32>,
    next_id: u32,
    /// The read budget in force right now: the handshake budget until the hello
    /// exchange is done, the reply timeout afterwards.
    timeout: Duration,
}

impl Connection {
    fn next_seq(&mut self, channel: u8) -> u32 {
        let slot = self.seq.entry(channel).or_insert(0);
        let seq = *slot;
        *slot += 1;
        seq
    }

    /// Request ids start at 1 because section 2.5 forbids 0.
    fn next_request_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn send(&mut self, frame: &Frame) -> Result<(), SessionError> {
        self.transport.send_frame(&mut self.wire, frame)?;
        self.wire.flush()?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Frame, SessionError> {
        let timeout = self.timeout;
        match self.transport.read_frame(&mut self.wire) {
            Ok(frame) => Ok(frame),
            Err(RecordError::Incomplete) => Err(SessionError::Closed),
            Err(RecordError::Io(ref e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // A read that ran out of time may have consumed part of a record,
                // so the stream can no longer be resynchronised. Report it and
                // let the caller drop the session: retrying here would splice two
                // different records together.
                Err(SessionError::Timeout(timeout))
            }
            Err(other) => Err(SessionError::Record(other)),
        }
    }

    fn shutdown(self) {
        let _ = self
            .wire
            .reader
            .get_ref()
            .shutdown(std::net::Shutdown::Both);
    }

    /// Change how long one read may block.
    ///
    /// The timeout goes on the handle that actually reads, and that is not
    /// decoration: on Windows a socket returned by [`TcpStream::try_clone`] does
    /// not carry `SO_RCVTIMEO` with it, so a timeout set on any other handle
    /// leaves this read blocking forever. Measured on this machine: set on the
    /// original and read on the clone, a read waited 998 ms for a peer that
    /// lived 1000 ms and then reported end-of-stream; set on the reading handle,
    /// the same read gave up after 162 ms with `TimedOut`. A silent hang that
    /// looks like a dead phone is exactly the failure mode to avoid, so the
    /// timeout is always applied here, through `wire.reader`.
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), SessionError> {
        self.wire.reader.get_ref().set_read_timeout(Some(timeout))?;
        Ok(())
    }
}

/// A connection that has proved who it is and is waiting for the user.
pub struct PendingSession {
    conn: Connection,
    info: SessionInfo,
    trust: Arc<dyn TrustStore>,
    /// The admission this connection came in on, so a confirmed pairing can
    /// report itself to the limiter that let the connection through.
    admitted: Admitted,
}

impl PendingSession {
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// Whether the phone's key was already pinned before this connection.
    ///
    /// Even when this is true the code is still derived and still shown: a
    /// pinned key that suddenly produces a different code would mean the screen
    /// is being watched, which is exactly what the user needs to notice.
    pub fn already_paired(&self) -> bool {
        self.info.paired
    }

    /// Record this phone as trusted and let traffic through.
    ///
    /// This is the second half of the section 3 handshake: the user has compared
    /// the two codes on the two screens and said they match. An already-pinned
    /// phone is not re-pinned, so `paired_at` keeps meaning "when the user
    /// confirmed", not "when it last reconnected".
    pub fn confirm(mut self) -> Result<ActiveSession, SessionError> {
        if !self.info.paired {
            self.trust.pin(Peer::new(
                self.info.peer_key,
                self.info.peer_name.clone(),
                self.info.peer_model.clone(),
                crate::unix_now(),
            ))?;
            self.info.paired = true;
            // A completed pairing is what tells the limiter this address is not
            // a stranger, and clears the run of hellos that got it here.
            self.admitted.note_paired();
        }
        Ok(ActiveSession {
            conn: self.conn,
            info: self.info,
            trust: self.trust,
            events: Vec::new(),
            deferred: Vec::new(),
        })
    }

    /// The user says the codes do not match, or changed their mind.
    ///
    /// Nothing was stored, so there is nothing to undo; the connection is shut
    /// down and the phone sees a closed socket.
    pub fn reject(self) {
        self.conn.shutdown();
    }
}

/// A trusted, usable connection to one phone.
pub struct ActiveSession {
    conn: Connection,
    info: SessionInfo,
    trust: Arc<dyn TrustStore>,
    events: Vec<Event>,
    deferred: Vec<Frame>,
}

impl ActiveSession {
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// Send one request and return the phone's answer.
    ///
    /// A refusal is an answer: `ok: false` with `CAPABILITY_DISABLED` comes back
    /// as `Ok(response)`, because the phone behaved correctly. [`Err`] means the
    /// connection failed, and then it must be dropped.
    pub fn request(&mut self, cmd: &str, args: Value) -> Result<Response, SessionError> {
        let channel = Channel::Control.id();
        let id = self.conn.next_request_id();
        let seq = self.conn.next_seq(channel);
        let frame = request_frame(channel, seq, &Request::new(id, cmd, args));
        self.conn.send(&frame)?;
        self.await_response(id, cmd)
    }

    /// Read the next frame. For callers that drive their own loop; [`request`]
    /// uses it internally.
    pub fn recv(&mut self) -> Result<Frame, SessionError> {
        self.conn.recv()
    }

    /// Send one frame directly. Exposed so the app can answer an inbound request
    /// without going through [`request`].
    pub fn send(&mut self, frame: &Frame) -> Result<(), SessionError> {
        self.conn.send(frame)
    }

    /// Events seen so far, in order, removing them from the queue.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Frames read while waiting for a reply that were not the reply: anything
    /// on a non-control channel, for instance. Kept rather than dropped so the
    /// caller decides what to do with them.
    pub fn take_deferred(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.deferred)
    }

    /// Send `security.unpair`, wait for the answer, then delete the pinned key.
    ///
    /// The local key is deleted whatever the phone answers, matching the phone's
    /// own rule that a revocation must never leave the user still paired. The
    /// connection is closed either way.
    pub fn unpair(mut self) -> Result<(), SessionError> {
        let answer = self.request("security.unpair", json!({}));
        let forget = self.trust.unpin(&self.info.peer_key);
        self.conn.shutdown();
        answer?;
        forget?;
        Ok(())
    }

    /// Close the connection.
    pub fn close(self) {
        self.conn.shutdown();
    }

    fn await_response(&mut self, id: u32, cmd: &str) -> Result<Response, SessionError> {
        let control = Channel::Control.id();
        loop {
            let frame = self.conn.recv()?;

            if frame.channel != control || !frame.is_json() {
                // Video, file data and anything else the PC does not consume yet.
                self.deferred.push(frame);
                continue;
            }

            let value: Value = serde_json::from_slice(&frame.payload).map_err(|e| {
                SessionError::Message(format!("{cmd}: control payload is not JSON: {e}"))
            })?;

            // Answers carry `ok`; a response to somebody else's request is kept
            // out of the way rather than mistaken for this one.
            if value.get("ok").is_some() {
                let response: Response = serde_json::from_value(value).map_err(|e| {
                    SessionError::Message(format!("{cmd}: malformed response: {e}"))
                })?;
                if response.id == id {
                    return Ok(response);
                }
                continue;
            }

            if value.get("evt").is_some() {
                let event: Event = serde_json::from_value(value)
                    .map_err(|e| SessionError::Message(format!("{cmd}: malformed event: {e}")))?;
                self.events.push(event);
                continue;
            }

            if let Some(inbound) = value.get("cmd").and_then(Value::as_str) {
                self.serve_inbound(inbound, &value)?;
                continue;
            }

            // A session message (`t`) such as a heartbeat is not part of the
            // request/response flow and needs no answer here.
            if value.get("t").is_some() {
                continue;
            }

            // An unsolicited error frame: the phone is ending the connection.
            if let Ok(body) = serde_json::from_value::<ErrorBody>(value) {
                return Err(SessionError::Refused {
                    code: body.code,
                    message: body.message,
                });
            }

            return Err(SessionError::Message(format!(
                "{cmd}: control message was neither a response, an event nor a request"
            )));
        }
    }

    /// Answer a request the phone sent us.
    ///
    /// `security.unpair` is the only one this build acts on: it is the
    /// revocation path, and it must leave the user unpaired even if the reply
    /// never arrives, so the key is deleted before the answer is written.
    fn serve_inbound(&mut self, cmd: &str, value: &Value) -> Result<(), SessionError> {
        let id = value
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| SessionError::Message(format!("inbound {cmd} has no usable id")))?
            as u32;

        let response = if cmd == "security.unpair" {
            self.trust.unpin(&self.info.peer_key)?;
            Response::ok(id, json!({}))
        } else {
            // Nothing else is a PC command yet. Saying so is better than
            // answering something plausible that did nothing.
            Response::err(
                id,
                ErrorBody::new(ErrorCode::Unsupported, format!("{cmd} is not a PC command")),
            )
        };

        let channel = Channel::Control.id();
        let seq = self.conn.next_seq(channel);
        self.conn.send(&response_frame(channel, seq, &response))?;

        if cmd == "security.unpair" {
            return Err(SessionError::Unpaired);
        }
        Ok(())
    }
}

/// Take over a freshly admitted socket: Noise as the responder, then the hello
/// exchange.
///
/// The phone dials, so the phone is the initiator and the PC is the responder
/// (section 2.2). This returns as soon as `hello_ack` is on the wire, before any
/// channel traffic, which is what section 3.4 requires: a code the user has not
/// confirmed yet must not unlock anything.
///
/// `admitted` comes from [`Listener::accept`] and is not decoration: a `hello`
/// from a key that is not pinned is reported through it, which is the count the
/// listener-wide lockout is built on, and a confirmed pairing clears it.
pub fn accept(
    stream: TcpStream,
    config: SessionConfig,
    admitted: Admitted,
) -> Result<PendingSession, SessionError> {
    // The handshake is the one phase a slow phone may legitimately still be in,
    // so it gets its own budget; the reply timeout takes over below. The budget
    // is set on the handle that reads, for the reason in `set_read_timeout`.
    let reader = stream.try_clone()?;
    reader.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut wire = WireStream::new(reader, stream);

    let transport = handshake_over_stream(
        &mut wire,
        Role::Responder,
        &config.prologue,
        config.identity.secret(),
        // The phone's key is unknown until the handshake reveals it, so this
        // check cannot happen here; it happens against the trust store below.
        None,
        None,
    )?;
    let transport = SecureTransport::new(transport);

    let peer_key: [u8; 32] = transport
        .remote_static()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| {
            SessionError::Message("the handshake ended without the phone's key".to_string())
        })?;

    let code = confirmation_code(&config.identity.public(), &peer_key);

    let mut conn = Connection {
        wire,
        transport,
        seq: HashMap::new(),
        next_id: 1,
        timeout: HANDSHAKE_TIMEOUT,
    };

    let hello = read_hello(&mut conn)?;

    // The handshake budget is generous; normal traffic is not. From here on an
    // unanswered request means the link is dead (section 2.8 will add the
    // heartbeat that spots this sooner).
    conn.set_read_timeout(config.reply_timeout)?;
    conn.timeout = config.reply_timeout;

    let paired = config.trust.is_pinned(&peer_key)?;

    // Section 3's failed-attempt count: a `hello` that is not a reconnection
    // from a confirmed phone is an attempt, and enough of them from one address
    // lock the listener. Done before the ack, because that is where the phone
    // becomes visible as either a stranger or a known one.
    if !paired {
        admitted.note_unattended_hello();
    }

    let channel = Channel::Control.id();
    let seq = conn.next_seq(channel);
    let ack = SessionHelloAck::new(
        config.identity.device_info(&config.host),
        config.caps.clone(),
        paired,
    );
    let payload = serde_json::to_vec(&ack)
        .map_err(|e| SessionError::Message(format!("could not encode hello_ack: {e}")))?;
    conn.send(&Frame::json(channel, mtype::RESPONSE, seq, payload))?;

    if paired {
        // Keep the stored display name current. `pin` leaves `paired_at` alone,
        // and writes nothing when nothing changed.
        config.trust.pin(Peer::new(
            peer_key,
            hello.device.name.clone(),
            hello.device.model.clone(),
            crate::unix_now(),
        ))?;
    }

    Ok(PendingSession {
        conn,
        trust: config.trust,
        admitted,
        info: SessionInfo {
            peer_key,
            peer_id: device_id(&peer_key),
            peer_name: hello.device.name,
            peer_model: hello.device.model,
            peer_os: hello.device.os,
            peer_caps: hello.caps,
            code,
            paired,
        },
    })
}

/// Read and check the initiator's `hello` (section 2.2).
fn read_hello(conn: &mut Connection) -> Result<SessionHello, SessionError> {
    let frame = conn.recv()?;

    if frame.channel != Channel::Control.id() || !frame.is_json() {
        return Err(SessionError::Message(
            "the first message was not a control-channel JSON frame".to_string(),
        ));
    }

    let value: Value = serde_json::from_slice(&frame.payload)
        .map_err(|e| SessionError::Message(format!("the first message is not JSON: {e}")))?;

    if value.get("t").and_then(Value::as_str) != Some("hello") {
        return Err(SessionError::Message(
            "the first message was not a hello".to_string(),
        ));
    }

    let hello: SessionHello = serde_json::from_value(value)
        .map_err(|e| SessionError::Message(format!("malformed hello: {e}")))?;

    if hello.pv != dc_protocol::PROTOCOL_VERSION {
        // Section 2.2: say why and stop, before any other traffic. The code is
        // not in this message: a peer we cannot talk to gets no confirmation.
        let body = ErrorBody::new(
            ErrorCode::Unsupported,
            format!(
                "protocol version {} required",
                dc_protocol::PROTOCOL_VERSION
            ),
        );
        let payload = serde_json::to_vec(&body)
            .map_err(|e| SessionError::Message(format!("could not encode the refusal: {e}")))?;
        let channel = Channel::Control.id();
        let seq = conn.next_seq(channel);
        conn.send(&Frame::json(channel, mtype::ERROR, seq, payload))?;
        return Err(SessionError::ProtocolMismatch {
            peer: hello.pv,
            ours: dc_protocol::PROTOCOL_VERSION,
        });
    }

    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FileSecretStore;
    use crate::trust::FileTrustStore;

    fn identity() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSecretStore::new(dir.path());
        let identity = Identity::load_or_create(&store).expect("identity");
        (dir, identity)
    }

    fn config(identity: Identity) -> (tempfile::TempDir, SessionConfig) {
        let dir = tempfile::tempdir().expect("temp dir");
        let trust = FileTrustStore::new(dir.path().join("trusted.json"));
        (
            dir,
            SessionConfig::new(identity, HostInfo::desktop(), Arc::new(trust)),
        )
    }

    #[test]
    fn a_window_binds_the_prologue_and_a_bound_port_is_reported() {
        let (_key_dir, identity) = identity();
        let (_cfg_dir, cfg) = config(identity);

        let listener = Listener::bind(0).expect("bind");
        let port = listener.port().expect("port");
        assert_ne!(port, 0);

        let offer = PairingOffer::qr(port, Some("192.168.0.5".into()), None);
        let bound = cfg.with_offer(&offer);
        assert_eq!(bound.prologue, offer.prologue());
        assert!(offer.qr_text().is_some());
    }

    #[test]
    fn the_local_address_is_a_usable_address_when_there_is_a_route() {
        // A machine with no route out has nothing to report, and then the app
        // tells the user to read the address off the adapter list instead.
        if let Some(address) = local_address() {
            assert!(!address.is_unspecified());
        }
    }
}
