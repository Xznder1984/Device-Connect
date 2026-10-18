//! Device Connect Windows core (`dc-client`).
//!
//! This is the PC side of a connection. The phone dials in and this crate runs
//! the Noise handshake, the `hello` exchange and the control channel on top of
//! the shared codec in `dc-protocol`.
//!
//! Three rules shape everything here:
//!
//! - **The phone dials.** The PC never reaches out to a phone and never opens a
//!   port the user did not ask it to open, so there is nothing on the phone to
//!   scan for and nothing running on it when the PC is closed.
//! - **Nothing is allowed until the user says so.** A phone whose key is not
//!   already pinned gets a [`PendingSession`], not a session: no request is
//!   served until the user compares the six-digit code (protocol section 3) and
//!   calls [`PendingSession::confirm`].
//! - **Secrets stay in the store.** Keys are read from a [`SecretStore`] and
//!   handed straight to the handshake. No key and no message body is ever put in
//!   a log, an error or a panic message (protocol section 7).
//!
//! The Tauri shell under `windows-app/src-tauri` decides what to show and when
//! to ask; this crate deliberately knows nothing about the UI.

pub mod hex;
pub mod identity;
pub mod pairing;
pub mod session;
pub mod store;
pub mod trust;

#[cfg(windows)]
pub mod credman;

pub use identity::{HostInfo, Identity};
pub use pairing::PairingOffer;
pub use session::{
    accept, local_address, ActiveSession, Listener, PendingSession, SessionConfig, SessionError,
    SessionInfo,
};
pub use store::{
    default_secret_store, default_store_name, FileSecretStore, SecretStore, StoreError,
};
pub use trust::{FileTrustStore, Peer, TrustStore};

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, or 0 if the clock reads before it.
///
/// Pairing windows and pinned-at timestamps are wall-clock values that only ever
/// need to be roughly right; a wrong system clock must not panic a connection.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
