//! Noise XX handshake helpers (docs/protocol.md section 2.2).
//!
//! Uses the `snow` implementation of the Noise Protocol Framework. No custom
//! cryptography: parameters, prologue and key handling follow the spec exactly.

use snow::{Builder, TransportState};

pub const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const PROLOGUE_LABEL: &[u8] = b"device-connect/v1\0";

/// Mode byte + optional QR nonce, appended to the label (protocol 2.2).
pub fn prologue(qr_nonce: Option<&[u8; 16]>) -> Vec<u8> {
    let mut out = PROLOGUE_LABEL.to_vec();
    match qr_nonce {
        Some(n) => {
            out.push(0x00);
            out.extend_from_slice(n);
        }
        None => out.push(0x01),
    }
    out
}

/// Build a handshake state with the prologue and local static key already mixed
/// in. `eph` fixes the ephemeral key so a transcript is reproducible; protocol
/// code never sets it, only tests and vector generation do.
pub(crate) fn builder<'a>(
    prologue: &'a [u8],
    local_static: &'a [u8; 32],
    eph: Option<&'a [u8; 32]>,
) -> Builder<'a> {
    let builder = Builder::new(PARAMS.parse().expect("valid noise params"))
        .prologue(prologue)
        .local_private_key(local_static);
    match eph {
        Some(key) => builder.fixed_ephemeral_key_for_testing_only(key),
        None => builder,
    }
}

/// What [`handshake_in_memory`] hands back: `(msg1, msg2, msg3,
/// initiator_transport, responder_transport)`.
///
/// A named type rather than an inline tuple because the order is not guessable
/// from the types - two of the five are `Vec<u8>` - and the KAT file stores
/// exactly this shape.
pub type HandshakeTranscript = (Vec<u8>, Vec<u8>, Vec<u8>, TransportState, TransportState);

/// Run the full 3-message XX handshake in memory with fixed keys.
/// Used to generate known-answer test vectors; the apps perform the same
/// steps over their socket. Fixed ephemerals make the transcript
/// deterministic, so this is ONLY for tests and vector generation.
pub fn handshake_in_memory(
    initiator_static: &[u8; 32],
    responder_static: &[u8; 32],
    initiator_eph: &[u8; 32],
    responder_eph: &[u8; 32],
    prologue: &[u8],
) -> Result<HandshakeTranscript, snow::Error> {
    let mut initiator =
        builder(prologue, initiator_static, Some(initiator_eph)).build_initiator()?;
    let mut responder =
        builder(prologue, responder_static, Some(responder_eph)).build_responder()?;

    let mut msg1 = vec![0u8; 128];
    let n1 = initiator.write_message(&[], &mut msg1)?;
    msg1.truncate(n1);

    let mut msg2 = vec![0u8; 128];
    let mut scratch = vec![0u8; 128];
    responder.read_message(&msg1, &mut scratch)?;
    let n2 = responder.write_message(&[], &mut msg2)?;
    msg2.truncate(n2);

    let mut msg3 = vec![0u8; 128];
    initiator.read_message(&msg2, &mut scratch)?;
    let n3 = initiator.write_message(&[], &mut msg3)?;
    msg3.truncate(n3);

    responder.read_message(&msg3, &mut scratch)?;

    Ok((
        msg1,
        msg2,
        msg3,
        initiator.into_transport_mode()?,
        responder.into_transport_mode()?,
    ))
}

/// Thin wrapper around a Noise transport (snow `TransportState` in transport
/// mode; `write_message` encrypts, `read_message` decrypts).
pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    pub fn from_state(state: TransportState) -> Self {
        Self { state }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = self.state.write_message(plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut out = vec![0u8; ciphertext.len()];
        let n = self.state.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// The peer's static public key, once the handshake completed.
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_handshake_transports_agree() {
        let i_static = [0x11u8; 32];
        let r_static = [0x22u8; 32];
        let i_eph = [0x33u8; 32];
        let r_eph = [0x44u8; 32];
        let pro = prologue(Some(&[0xABu8; 16]));
        let (m1, m2, m3, it, rt) =
            handshake_in_memory(&i_static, &r_static, &i_eph, &r_eph, &pro).unwrap();
        assert_eq!(m1.len(), 32);
        assert_eq!(m2.len(), 96);
        assert_eq!(m3.len(), 64);
        let mut it = NoiseTransport::from_state(it);
        let mut rt = NoiseTransport::from_state(rt);
        // Both sides learn the peer's static PUBLIC key inside the handshake
        // (never the peer's private key) - this is what pairing pins.
        let responder_pub = it.remote_static().expect("initiator learns peer static");
        let initiator_pub = rt.remote_static().expect("responder learns peer static");
        assert_eq!(responder_pub.len(), 32);
        assert_eq!(initiator_pub.len(), 32);
        assert_ne!(responder_pub, initiator_pub);
        assert_ne!(
            responder_pub,
            &r_static[..],
            "public key differs from private key"
        );
        assert_ne!(
            initiator_pub,
            &i_static[..],
            "public key differs from private key"
        );
        let ct = it.encrypt(b"ping").unwrap();
        assert_eq!(rt.decrypt(&ct).unwrap(), b"ping");
        let ct2 = rt.encrypt(b"pong").unwrap();
        assert_eq!(it.decrypt(&ct2).unwrap(), b"pong");
        // Nonce advances: same plaintext encrypts differently.
        assert_ne!(it.encrypt(b"ping").unwrap(), ct);
    }
}
