//! Lowercase hex encoding.
//!
//! Small enough to write out rather than take a dependency: the only use is the
//! 16-character device id and test assertions.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encode `bytes` as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lowercase() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(encode(&[]), "");
    }
}
