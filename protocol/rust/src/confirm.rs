//! Pairing confirmation code (docs/protocol.md section 3.3).
//!
//! code = base10(be32(SHA256("dc-confirm-v1" || min(pkA,pkB) || max(pkA,pkB))[0..4])) mod 1_000_000

use sha2::{Digest, Sha256};

const LABEL: &[u8] = b"dc-confirm-v1";

/// Derive the 6-digit confirmation code from both static public keys.
/// Order does not matter: keys are sorted bytewise.
pub fn confirmation_code(pk_a: &[u8], pk_b: &[u8]) -> String {
    let (lo, hi) = if pk_a <= pk_b { (pk_a, pk_b) } else { (pk_b, pk_a) };
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    let be = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", be as u64 % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_order_independent_and_six_digits() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c1 = confirmation_code(&a, &b);
        let c2 = confirmation_code(&b, &a);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 6);
        assert!(c1.chars().all(|c| c.is_ascii_digit()));
    }
}
