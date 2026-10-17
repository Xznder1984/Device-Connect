//! Device Connect protocol codec (reference implementation, Rust).
//!
//! Implements the wire format from `docs/protocol.md`:
//! length-prefixed framing, QR pairing payloads, pairing confirmation codes,
//! Noise XX handshake helpers and JSON envelope types. Pure and synchronous;
//! async I/O lives in the platform apps that use this crate.

pub mod confirm;
pub mod error_codes;
pub mod framing;
pub mod noise;
pub mod qr;
pub mod records;
pub mod schema;

pub use error_codes::ErrorCode;
pub use framing::{Frame, FrameError, FRAME_HEADER_LEN, MAX_BODY_LEN, MIN_BODY_LEN};

/// Protocol version frozen for v1 of the specification.
pub const PROTOCOL_VERSION: u32 = 1;

/// mDNS service type used for discovery on the local network.
pub const MDNS_SERVICE_TYPE: &str = "_deviceconnect._tcp.local.";

/// RFCOMM SDP service name used for Bluetooth discovery.
pub const RFCOMM_SERVICE_NAME: &str = "deviceconnect";
