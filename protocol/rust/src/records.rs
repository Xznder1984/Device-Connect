//! The wire record layer (docs/protocol.md section 2.2.1).
//!
//! Every message on the stream, handshake or transport, is a `u32be` length
//! followed by exactly that many bytes. The length sits *outside* the AEAD, so
//! tampering with it can only make the tag check fail and close the connection;
//! it can never desynchronize a peer into accepting different plaintext.
//!
//! The handshake and the session share one [`WireStream`]. That is not a style
//! choice: a buffered reader reads ahead, so if each phase wrapped the socket in
//! its own buffer the handshake's read-ahead would swallow the leading bytes of
//! the peer's first transport record and the session would wait forever for
//! bytes that already arrived. The JVM implementation hit exactly this, which is
//! why both sides are written against a single shared buffer.

use std::io::{self, Read, Write};

use crate::framing::{Frame, MAX_BODY_LEN};
use crate::noise::NoiseTransport;

/// Size of the `u32be` length prefix on every record.
pub const LENGTH_BYTES: usize = 4;

/// Size of the ChaChaPoly-Poly1305 authentication tag.
pub const POLY1305_TAG_LEN: usize = 16;

/// Largest `len` a handshake message may declare (protocol 2.2.1).
pub const MAX_HANDSHAKE_RECORD: usize = 65_536;

/// Largest `len` an encrypted frame record may declare: the plaintext frame
/// (`LENGTH_BYTES + MAX_BODY_LEN`) plus the AEAD tag. Section 2.2.1 states this
/// as `4 + 1_048_576 + 16`.
pub const MAX_TRANSPORT_RECORD: usize = LENGTH_BYTES + MAX_BODY_LEN as usize + POLY1305_TAG_LEN;

/// A condition that makes the connection unusable.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The stream ended, or a record was cut short.
    #[error("incomplete record")]
    Incomplete,
    /// A zero-length record, which section 2.2.1 forbids on both paths.
    #[error("record length {got} is zero")]
    BodyTooSmall { got: u32 },
    /// A declared length above the cap for this path.
    #[error("record length {got} exceeds the cap {max}")]
    BodyTooLarge { got: u32, max: usize },
    /// The peer's static key is not the one that was pinned for it.
    #[error("peer static key does not match the pinned key")]
    RemoteStaticMismatch,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] crate::framing::FrameError),
    #[error(transparent)]
    Noise(#[from] snow::Error),
}

/// Which side of the handshake this endpoint is. Either side may be either
/// (protocol 2.1), so it is a parameter rather than a property of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// One decoded record: its payload and how many buffer bytes it used.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeResult {
    Decoded { payload: Vec<u8>, bytes_consumed: usize },
    NeedMore,
}

/// Prefix `payload` with its length.
///
/// `max` is the largest `len` section 2.2.1 permits, that is the size of the
/// record *after* its 4-byte prefix. The cap is checked against the declared
/// length before any allocation, so a hostile peer cannot make the receiver
/// reserve a megabyte it never sent.
pub fn encode(payload: &[u8], max: usize) -> Result<Vec<u8>, RecordError> {
    if payload.is_empty() {
        return Err(RecordError::BodyTooSmall { got: 0 });
    }
    if payload.len() > max {
        return Err(RecordError::BodyTooLarge { got: payload.len() as u32, max });
    }
    let mut out = Vec::with_capacity(LENGTH_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental decoder for callers that feed bytes rather than read a stream.
///
/// `NeedMore` means the bytes so far are a proper prefix of a valid record, so
/// the caller should read more; a decoder that guessed here would desynchronize
/// the stream on any split TCP segment.
pub fn decode(buf: &[u8], max: usize) -> Result<DecodeResult, RecordError> {
    if buf.len() < LENGTH_BYTES {
        return Ok(DecodeResult::NeedMore);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len == 0 {
        return Err(RecordError::BodyTooSmall { got: 0 });
    }
    if len as usize > max {
        return Err(RecordError::BodyTooLarge { got: len, max });
    }
    let total = LENGTH_BYTES + len as usize;
    if buf.len() < total {
        return Ok(DecodeResult::NeedMore);
    }
    Ok(DecodeResult::Decoded {
        payload: buf[LENGTH_BYTES..total].to_vec(),
        bytes_consumed: total,
    })
}

/// Write one record and flush it.
pub fn write_record<W: Write>(writer: &mut W, payload: &[u8], max: usize) -> Result<(), RecordError> {
    let encoded = encode(payload, max)?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

/// Read exactly one record.
///
/// Returns [`RecordError::Incomplete`] when the stream ends mid-record, which
/// the caller treats as a dead connection rather than a partial message.
pub fn read_record<R: Read>(reader: &mut R, max: usize) -> Result<Vec<u8>, RecordError> {
    let mut prefix = [0u8; LENGTH_BYTES];
    read_exact(reader, &mut prefix)?;
    let len = u32::from_be_bytes(prefix);
    if len == 0 {
        return Err(RecordError::BodyTooSmall { got: 0 });
    }
    if len as usize > max {
        return Err(RecordError::BodyTooLarge { got: len, max });
    }
    let mut payload = vec![0u8; len as usize];
    read_exact(reader, &mut payload)?;
    Ok(payload)
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), RecordError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(RecordError::Incomplete),
        Err(e) => Err(RecordError::Io(e)),
    }
}

/// A buffered reader/writer pair that the handshake and the session must share.
///
/// The buffer is created once, here, and never re-created: the handshake's
/// read-ahead would otherwise swallow the peer's first transport record and the
/// session would then wait for bytes that already arrived.
pub struct WireStream<R: Read, W: Write> {
    pub reader: io::BufReader<R>,
    pub writer: io::BufWriter<W>,
}

impl<R: Read, W: Write> WireStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: io::BufReader::with_capacity(64 * 1024, reader),
            writer: io::BufWriter::with_capacity(64 * 1024, writer),
        }
    }

    /// Flush buffered output (writes are buffered, as on the JVM side).
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Drive the Noise XX handshake over `wire` and return the transport.
///
/// The caller must hand the *same* [`WireStream`] to [`SecureTransport`]: the
/// handshake reads ahead, so a second buffer would lose the peer's first frame.
pub fn handshake_over_stream<R: Read, W: Write>(
    wire: &mut WireStream<R, W>,
    role: Role,
    prologue: &[u8],
    local_static: &[u8; 32],
    expected_remote_static: Option<&[u8]>,
    fixed_ephemeral: Option<&[u8; 32]>,
) -> Result<NoiseTransport, RecordError> {
    let mut state = match role {
        Role::Initiator => {
            crate::noise::builder(prologue, local_static, fixed_ephemeral).build_initiator()?
        }
        Role::Responder => {
            crate::noise::builder(prologue, local_static, fixed_ephemeral).build_responder()?
        }
    };

    let mut send_buf = vec![0u8; MAX_HANDSHAKE_RECORD];
    let mut recv_buf = vec![0u8; MAX_HANDSHAKE_RECORD];

    // XX is write, read, write for the initiator and read, write, read for the
    // responder, so the whole exchange is decided by the role.
    let writes = match role {
        Role::Initiator => [true, false, true],
        Role::Responder => [false, true, false],
    };
    for is_write in writes {
        if is_write {
            let n = state.write_message(&[], &mut send_buf)?;
            write_record(&mut wire.writer, &send_buf[..n], MAX_HANDSHAKE_RECORD)?;
        } else {
            let record = read_record(&mut wire.reader, MAX_HANDSHAKE_RECORD)?;
            state.read_message(&record, &mut recv_buf)?;
        }
    }

    // snow hands the transport out by consuming the handshake state, so there is
    // no "split before destroy" ordering to get wrong as there is on the JVM.
    let transport = state.into_transport_mode()?;

    if let Some(expected) = expected_remote_static {
        if transport.get_remote_static() != Some(expected) {
            return Err(RecordError::RemoteStaticMismatch);
        }
    }
    Ok(NoiseTransport::from_state(transport))
}

/// A frame stream: Noise transport + record layer + frame codec, so callers
/// exchange [`Frame`]s and nothing else.
///
/// Reads are in order, as Noise's nonce counter requires; the caller serializes
/// writes so two threads can never interleave a single record.
pub struct SecureTransport {
    transport: NoiseTransport,
}

impl SecureTransport {
    pub fn new(transport: NoiseTransport) -> Self {
        Self { transport }
    }

    /// The peer's static public key, from the completed handshake.
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.transport.remote_static()
    }

    /// Encrypt one frame and write it as one record.
    pub fn send_frame<R: Read, W: Write>(
        &mut self,
        wire: &mut WireStream<R, W>,
        frame: &Frame,
    ) -> Result<(), RecordError> {
        let ciphertext = self.transport.encrypt(&frame.encode())?;
        write_record(&mut wire.writer, &ciphertext, MAX_TRANSPORT_RECORD)
    }

    /// Read the next record, decrypt it and decode one frame.
    pub fn read_frame<R: Read, W: Write>(&mut self, wire: &mut WireStream<R, W>) -> Result<Frame, RecordError> {
        let ciphertext = read_record(&mut wire.reader, MAX_TRANSPORT_RECORD)?;
        let plaintext = self.transport.decrypt(&ciphertext)?;
        match Frame::decode(&plaintext)? {
            Some(frame) => Ok(frame),
            None => Err(RecordError::Incomplete),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn golden_keys() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], Vec<u8>) {
        (
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
            crate::noise::prologue(Some(&[0x24u8; 16])),
        )
    }

    #[test]
    fn caps_match_the_spec_exactly() {
        // section 2.2.1 states both caps as literal numbers. Pinning them here,
        // and in the Kotlin suite, is what keeps two implementations from
        // drifting apart at the boundary.
        assert_eq!(MAX_HANDSHAKE_RECORD, 65_536);
        assert_eq!(MAX_TRANSPORT_RECORD, 1_048_596);
        assert_eq!(MAX_TRANSPORT_RECORD, LENGTH_BYTES + MAX_BODY_LEN as usize + POLY1305_TAG_LEN);

        // The largest legal record on each path is accepted ...
        let handshake = encode(&vec![0u8; MAX_HANDSHAKE_RECORD], MAX_HANDSHAKE_RECORD).unwrap();
        assert!(matches!(
            decode(&handshake, MAX_HANDSHAKE_RECORD).unwrap(),
            DecodeResult::Decoded { bytes_consumed, .. } if bytes_consumed == LENGTH_BYTES + MAX_HANDSHAKE_RECORD
        ));

        let transport = encode(&vec![0u8; MAX_TRANSPORT_RECORD], MAX_TRANSPORT_RECORD).unwrap();
        assert!(matches!(
            decode(&transport, MAX_TRANSPORT_RECORD).unwrap(),
            DecodeResult::Decoded { bytes_consumed, .. } if bytes_consumed == LENGTH_BYTES + MAX_TRANSPORT_RECORD
        ));

        // ... and exactly one byte more is refused.
        assert!(matches!(
            encode(&vec![0u8; MAX_TRANSPORT_RECORD + 1], MAX_TRANSPORT_RECORD),
            Err(RecordError::BodyTooLarge { .. })
        ));
        assert!(matches!(
            encode(&vec![0u8; MAX_HANDSHAKE_RECORD + 1], MAX_HANDSHAKE_RECORD),
            Err(RecordError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn partial_records_need_more() {
        let encoded = encode(b"incomplete record", MAX_TRANSPORT_RECORD).unwrap();
        for cut in 0..encoded.len() {
            assert!(
                matches!(decode(&encoded[..cut], MAX_TRANSPORT_RECORD).unwrap(), DecodeResult::NeedMore),
                "cut at {cut}"
            );
        }
        assert!(matches!(
            decode(&encoded, MAX_TRANSPORT_RECORD).unwrap(),
            DecodeResult::Decoded { payload, .. } if payload == b"incomplete record"
        ));
    }

    #[test]
    fn zero_length_is_rejected() {
        assert!(matches!(
            decode(&[0, 0, 0, 0], MAX_TRANSPORT_RECORD),
            Err(RecordError::BodyTooSmall { got: 0 })
        ));
        assert!(matches!(encode(&[], MAX_TRANSPORT_RECORD), Err(RecordError::BodyTooSmall { got: 0 })));
    }

    #[test]
    fn handshake_and_transport_share_one_buffer() {
        let (i_static, r_static, i_eph, r_eph, prologue) = golden_keys();

        // A real frame from the initiator's transport, exactly as the PC's
        // `hello` would be, encrypted with the deterministic golden keys.
        let frame = Frame::json(0x01, 0x01, 1, br#"{"t":"hello"}"#.to_vec());
        let (m1, _m2, m3, initiator_transport, _responder_transport) =
            crate::noise::handshake_in_memory(&i_static, &r_static, &i_eph, &r_eph, &prologue)
                .expect("golden handshake");
        let ciphertext = NoiseTransport::from_state(initiator_transport)
            .encrypt(&frame.encode())
            .expect("encrypt greeting");

        // Everything the responder will ever read, already in the stream. The
        // bytes are well under the 64 KiB read-ahead, so the handshake pulls the
        // greeting record into its buffer.
        let mut inbound = Vec::new();
        inbound.extend_from_slice(&encode(&m1, MAX_HANDSHAKE_RECORD).unwrap());
        inbound.extend_from_slice(&encode(&m3, MAX_HANDSHAKE_RECORD).unwrap());
        inbound.extend_from_slice(&encode(&ciphertext, MAX_TRANSPORT_RECORD).unwrap());

        let mut wire = WireStream::new(Cursor::new(inbound), Vec::new());
        let transport = handshake_over_stream(
            &mut wire,
            Role::Responder,
            &prologue,
            &r_static,
            None,
            Some(&r_eph),
        )
        .expect("responder handshake over the pre-buffered stream");

        // The same WireStream must still yield the greeting: if the handshake
        // had wrapped its own buffer, those bytes would already be gone.
        let mut secure = SecureTransport::new(transport);
        assert_eq!(secure.read_frame(&mut wire).expect("greeting after handshake"), frame);
    }

    #[test]
    fn frames_round_trip_in_both_directions() {
        let (i_static, r_static, i_eph, r_eph, prologue) = golden_keys();
        let (_m1, _m2, _m3, it, rt) =
            crate::noise::handshake_in_memory(&i_static, &r_static, &i_eph, &r_eph, &prologue)
                .unwrap();
        let mut initiator = SecureTransport::new(NoiseTransport::from_state(it));
        let mut responder = SecureTransport::new(NoiseTransport::from_state(rt));

        let to_responder = Frame::json(0x01, 0x01, 7, br#"{"t":"hello"}"#.to_vec());
        let to_initiator = Frame::new(0x09, 0x04, 8, b"world!!".to_vec());

        // Initiator -> responder, then responder -> initiator, through the
        // record layer on both ends.
        let mut outbound = WireStream::new(std::io::empty(), Vec::new());
        initiator.send_frame(&mut outbound, &to_responder).unwrap();
        outbound.flush().unwrap();
        let bytes = outbound.writer.into_inner().unwrap();
        let mut inbound = WireStream::new(Cursor::new(bytes), Vec::new());
        assert_eq!(responder.read_frame(&mut inbound).unwrap(), to_responder);

        let mut outbound = WireStream::new(std::io::empty(), Vec::new());
        responder.send_frame(&mut outbound, &to_initiator).unwrap();
        outbound.flush().unwrap();
        let bytes = outbound.writer.into_inner().unwrap();
        let mut inbound = WireStream::new(Cursor::new(bytes), Vec::new());
        assert_eq!(initiator.read_frame(&mut inbound).unwrap(), to_initiator);
    }
}
