//! Length-prefixed framing (docs/protocol.md section 2.3-2.7).

use crate::error_codes::ErrorCode;

pub const FRAME_HEADER_LEN: usize = 4;
pub const MIN_BODY_LEN: u32 = 8;
pub const MAX_BODY_LEN: u32 = 1_048_576;

/// JSON payload flag in the frame flags field.
pub const FLAG_JSON: u16 = 0b0000_0000_0000_0001;

/// Message type bytes (uniform envelope, docs/protocol.md 2.5).
pub mod mtype {
    pub const REQUEST: u8 = 0x01;
    pub const RESPONSE: u8 = 0x02;
    pub const EVENT: u8 = 0x03;
    pub const ERROR: u8 = 0x04;
    pub const FILE_DATA: u8 = 0x10;
    pub const VIDEO_CONFIG: u8 = 0x01;
    pub const VIDEO_AU: u8 = 0x02;
    pub const VIDEO_AU_FRAGMENT: u8 = 0x03;
}

/// Channel ids (docs/protocol.md 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    Control,
    Video,
    Notifications,
    Messages,
    Calls,
    Clipboard,
    Files,
    Status,
    Heartbeat,
    Unknown(u8),
}

impl Channel {
    /// The wire id of this channel.
    pub fn id(&self) -> u8 {
        match self {
            Channel::Control => 0x01,
            Channel::Video => 0x02,
            Channel::Notifications => 0x03,
            Channel::Messages => 0x04,
            Channel::Calls => 0x05,
            Channel::Clipboard => 0x06,
            Channel::Files => 0x07,
            Channel::Status => 0x08,
            Channel::Heartbeat => 0x09,
            Channel::Unknown(v) => *v,
        }
    }
}

impl From<u8> for Channel {
    fn from(v: u8) -> Self {
        match v {
            0x01 => Channel::Control,
            0x02 => Channel::Video,
            0x03 => Channel::Notifications,
            0x04 => Channel::Messages,
            0x05 => Channel::Calls,
            0x06 => Channel::Clipboard,
            0x07 => Channel::Files,
            0x08 => Channel::Status,
            0x09 => Channel::Heartbeat,
            other => Channel::Unknown(other),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("body_len {got} below minimum {MIN_BODY_LEN}")]
    BodyTooSmall { got: u32 },
    #[error("body_len {got} above maximum {MAX_BODY_LEN}")]
    BodyTooLarge { got: u32 },
    #[error("incomplete frame")]
    Incomplete,
    #[error("invalid error code in frame")]
    InvalidErrorCode,
}

/// One protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: u8,
    pub mtype: u8,
    pub flags: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(channel: u8, mtype: u8, seq: u32, payload: Vec<u8>) -> Self {
        Self {
            channel,
            mtype,
            flags: 0,
            seq,
            payload,
        }
    }

    pub fn json(channel: u8, mtype: u8, seq: u32, payload: Vec<u8>) -> Self {
        Self {
            channel,
            mtype,
            flags: FLAG_JSON,
            seq,
            payload,
        }
    }

    pub fn is_json(&self) -> bool {
        self.flags & FLAG_JSON != 0
    }

    /// Encode the complete frame (length prefix included).
    pub fn encode(&self) -> Vec<u8> {
        let body_len = (MIN_BODY_LEN as usize) + self.payload.len();
        debug_assert!(body_len as u32 <= MAX_BODY_LEN);
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.push(self.channel);
        out.push(self.mtype);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a single frame starting at the beginning of `buf`.
    /// Returns `Ok(None)` when more bytes are needed.
    pub fn decode(buf: &[u8]) -> Result<Option<Self>, FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if body_len < MIN_BODY_LEN {
            return Err(FrameError::BodyTooSmall { got: body_len });
        }
        if body_len > MAX_BODY_LEN {
            return Err(FrameError::BodyTooLarge { got: body_len });
        }
        let total = FRAME_HEADER_LEN + body_len as usize;
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some(Frame {
            channel: buf[4],
            mtype: buf[5],
            flags: u16::from_be_bytes([buf[6], buf[7]]),
            seq: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            payload: buf[12..total].to_vec(),
        }))
    }
}

/// Incremental stream decoder: feed bytes, take frames.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Extract the next complete frame, if any.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let frame = Frame::decode(&self.buf)?;
        if let Some(ref f) = frame {
            let total = FRAME_HEADER_LEN + MIN_BODY_LEN as usize + f.payload.len();
            self.buf.drain(..total);
        }
        Ok(frame)
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

/// Payload of a `files` data frame (mtype 0x10):
/// `[u32be transfer_id][u64be offset][chunk bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileData {
    pub transfer_id: u32,
    pub offset: u64,
    pub chunk: Vec<u8>,
}

pub const MAX_FILE_CHUNK: usize = 65536;

impl FileData {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.chunk.len());
        out.extend_from_slice(&self.transfer_id.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.chunk);
        out
    }

    pub fn decode(payload: &[u8]) -> Result<Self, FrameError> {
        if payload.len() < 12 {
            return Err(FrameError::Incomplete);
        }
        let transfer_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let mut off = [0u8; 8];
        off.copy_from_slice(&payload[4..12]);
        let chunk = payload[12..].to_vec();
        if chunk.len() > MAX_FILE_CHUNK {
            return Err(FrameError::BodyTooLarge {
                got: chunk.len() as u32,
            });
        }
        Ok(Self {
            transfer_id,
            offset: u64::from_be_bytes(off),
            chunk,
        })
    }
}

/// Video access unit payload: `[u64be timestamp_ms][annexb bytes]`.
/// Fragments add `[u32be index][u32be count]` after the timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoAu {
    pub timestamp_ms: u64,
    pub data: Vec<u8>,
}

impl VideoAu {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(payload: &[u8]) -> Result<Self, FrameError> {
        if payload.len() < 8 {
            return Err(FrameError::Incomplete);
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&payload[0..8]);
        Ok(Self {
            timestamp_ms: u64::from_be_bytes(ts),
            data: payload[8..].to_vec(),
        })
    }
}

/// Helper for error responses that carry no request id.
pub fn unsolicited_error_frame(seq: u32, code: ErrorCode, message: &str) -> Frame {
    let body = serde_json::json!({ "code": code.as_str(), "message": message });
    Frame::json(0x01, mtype::ERROR, seq, serde_json::to_vec(&body).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_min_frame() {
        let f = Frame::new(0x09, 0x01, 0, vec![]);
        let bytes = f.encode();
        assert_eq!(bytes.len(), 12);
        assert_eq!(Frame::decode(&bytes).unwrap().unwrap(), f);
    }

    #[test]
    fn incomplete_needs_more() {
        let f = Frame::json(0x01, 0x01, 7, b"{\"a\":1}".to_vec());
        let bytes = f.encode();
        assert_eq!(Frame::decode(&bytes[..5]).unwrap(), None);
        assert_eq!(Frame::decode(&bytes[..bytes.len() - 1]).unwrap(), None);
        assert_eq!(Frame::decode(&bytes).unwrap().unwrap(), f);
    }

    #[test]
    fn rejects_bad_len() {
        let mut bytes = vec![0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::BodyTooSmall { got: 0 })
        ));
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn decoder_stream() {
        let mut dec = FrameDecoder::new();
        let a = Frame::new(0x08, 0x03, 0, b"hello".to_vec()).encode();
        let b = Frame::new(0x09, 0x01, 1, b"world!!".to_vec()).encode();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        dec.feed(&stream[..6]);
        assert!(dec.next_frame().unwrap().is_none());
        dec.feed(&stream[6..]);
        let fa = dec.next_frame().unwrap().unwrap();
        assert_eq!(fa.payload, b"hello");
        let fb = dec.next_frame().unwrap().unwrap();
        assert_eq!(fb.payload, b"world!!");
        assert!(dec.next_frame().unwrap().is_none());
    }

    #[test]
    fn file_data_roundtrip() {
        let fd = FileData {
            transfer_id: 42,
            offset: 123456789,
            chunk: vec![9u8; 1000],
        };
        let enc = fd.encode();
        assert_eq!(FileData::decode(&enc).unwrap(), fd);
    }

    #[test]
    fn video_au_roundtrip() {
        let au = VideoAu {
            timestamp_ms: 1700000000123,
            data: vec![0, 0, 0, 1, 0x67],
        };
        let enc = au.encode();
        assert_eq!(VideoAu::decode(&enc).unwrap(), au);
    }
}
