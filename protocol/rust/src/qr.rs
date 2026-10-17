//! Pairing QR payloads (docs/protocol.md section 3).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const QR_PREFIX: &str = "dc1:";
pub const QR_VALIDITY_SECS: u64 = 120;
pub const NONCE_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QrError {
    #[error("missing or wrong prefix")]
    BadPrefix,
    #[error("payload is not valid base64url")]
    BadBase64,
    #[error("payload is not valid JSON")]
    BadJson,
    #[error("field {0} missing or invalid")]
    BadField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrPayload {
    /// Protocol version, must be 1.
    pub v: u32,
    /// One-time pairing nonce: 16 random bytes, base64url (22 chars).
    pub n: String,
    /// TCP port of the PC listener.
    pub p: u16,
    /// Host name or IP literal of the PC listener (optional, manual mode omits it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<String>,
    /// Unix seconds after which the QR must be rejected.
    pub exp: u64,
    /// PC device name for display on the phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl QrPayload {
    /// Build a payload from raw nonce bytes.
    pub fn new(
        nonce: &[u8; NONCE_LEN],
        port: u16,
        host: Option<String>,
        name: Option<String>,
        now_secs: u64,
    ) -> Self {
        Self {
            v: 1,
            n: URL_SAFE_NO_PAD.encode(nonce),
            p: port,
            h: host,
            exp: now_secs + QR_VALIDITY_SECS,
            name,
        }
    }

    /// The nonce as raw bytes (feeds the Noise prologue).
    pub fn nonce_bytes(&self) -> Result<[u8; NONCE_LEN], QrError> {
        let raw = URL_SAFE_NO_PAD
            .decode(&self.n)
            .map_err(|_| QrError::BadField("n"))?;
        let mut out = [0u8; NONCE_LEN];
        if raw.len() != NONCE_LEN {
            return Err(QrError::BadField("n"));
        }
        out.copy_from_slice(&raw);
        Ok(out)
    }

    /// Encode as shown in the QR: `dc1:` + base64url(JSON).
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("QrPayload serializes");
        format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    /// Decode and structurally validate. Expiry is checked separately so
    /// callers can report "expired" distinctly from "malformed".
    pub fn decode(text: &str) -> Result<Self, QrError> {
        let body = text
            .trim()
            .strip_prefix(QR_PREFIX)
            .ok_or(QrError::BadPrefix)?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| QrError::BadBase64)?;
        let payload: QrPayload = serde_json::from_slice(&json).map_err(|_| QrError::BadJson)?;
        if payload.v != 1 {
            return Err(QrError::BadField("v"));
        }
        if payload.p == 0 {
            return Err(QrError::BadField("p"));
        }
        if payload.n.len() != 22
            || URL_SAFE_NO_PAD.decode(&payload.n).map(|r| r.len()) != Ok(NONCE_LEN)
        {
            return Err(QrError::BadField("n"));
        }
        Ok(payload)
    }

    /// True when the payload is expired at `now_secs` (phone clock).
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs > self.exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let nonce = [7u8; NONCE_LEN];
        let p = QrPayload::new(
            &nonce,
            47321,
            Some("pc.local".into()),
            Some("Desk PC".into()),
            1_700_000_000,
        );
        let text = p.encode();
        assert!(text.starts_with("dc1:"));
        let back = QrPayload::decode(&text).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.nonce_bytes().unwrap(), nonce);
        assert!(!back.is_expired(1_700_000_000 + 100));
        assert!(back.is_expired(1_700_000_000 + 121));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(QrPayload::decode("http://x"), Err(QrError::BadPrefix));
        assert_eq!(QrPayload::decode("dc1:notb64!!"), Err(QrError::BadBase64));
        let bad = format!("dc1:{}", URL_SAFE_NO_PAD.encode(b"{\"v\":2}"));
        assert_eq!(QrPayload::decode(&bad), Err(QrError::BadJson));
    }
}
