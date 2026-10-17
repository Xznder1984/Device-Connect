//! The pairing window: what the PC shows, and the prologue it binds to
//! (protocol section 3).

use rand_core::{OsRng, RngCore};

pub use dc_protocol::confirm::confirmation_code;
pub use dc_protocol::qr::{QrError, QrPayload, NONCE_LEN, QR_PREFIX, QR_VALIDITY_SECS};

/// How the phone will reach this window.
///
/// The mode byte goes into the Noise prologue, which both sides fix before the
/// first handshake message is processed, so a listener serves exactly one mode
/// at a time. The app runs a session listener with [`PairingMode::Manual`] to
/// serve pinned phones and typed addresses, and a second one with
/// [`PairingMode::Qr`] while a pairing window is open; see the "The prologue
/// fixes the mode" section of `docs/windows.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMode {
    /// The phone scans the QR: prologue byte `0x00` plus the 16-byte nonce.
    Qr,
    /// The user types `ip:port`: prologue byte `0x01`, no nonce.
    Manual,
}

/// One pairing window.
///
/// The nonce is what makes a QR replay useless: it is fresh and random per
/// window, and the prologue binds the handshake to it, so a QR photographed in
/// an earlier window cannot be replayed later. The expiry repeats the boundary
/// on the wire so the phone can reject a stale payload on its own.
#[derive(Debug, Clone)]
pub struct PairingOffer {
    /// Present in QR mode only, and always the nonce inside `payload`.
    nonce: Option<[u8; NONCE_LEN]>,
    /// The QR body, present in QR mode only.
    payload: Option<QrPayload>,
    port: u16,
    host: Option<String>,
    expires_at: u64,
}

impl PairingOffer {
    /// A window for `port`, opened at `now_secs` and good for
    /// [`QR_VALIDITY_SECS`].
    pub fn new(
        mode: PairingMode,
        port: u16,
        host: Option<String>,
        name: Option<String>,
        now_secs: u64,
    ) -> Self {
        let expires_at = now_secs + QR_VALIDITY_SECS;
        let (nonce, payload) = match mode {
            PairingMode::Qr => {
                let nonce = fresh_nonce();
                let payload = QrPayload::new(&nonce, port, host.clone(), name, now_secs);
                (Some(nonce), Some(payload))
            }
            PairingMode::Manual => (None, None),
        };
        Self {
            nonce,
            payload,
            port,
            host,
            expires_at,
        }
    }

    /// A QR window opened now, with a fresh nonce.
    pub fn qr(port: u16, host: Option<String>, name: Option<String>) -> Self {
        Self::new(PairingMode::Qr, port, host, name, crate::unix_now())
    }

    /// A typed-address window opened now.
    pub fn manual(port: u16, host: Option<String>, name: Option<String>) -> Self {
        Self::new(PairingMode::Manual, port, host, name, crate::unix_now())
    }

    pub fn mode(&self) -> PairingMode {
        if self.nonce.is_some() {
            PairingMode::Qr
        } else {
            PairingMode::Manual
        }
    }

    /// The port the phone must dial.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Unix seconds after which this window must not be used.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the window has closed at `now_secs`.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs > self.expires_at
    }

    /// The Noise prologue for this window (section 2.2).
    pub fn prologue(&self) -> Vec<u8> {
        dc_protocol::noise::prologue(self.nonce.as_ref())
    }

    /// The text to render as a QR code, or `None` in manual mode.
    pub fn qr_text(&self) -> Option<String> {
        self.payload.as_ref().map(QrPayload::encode)
    }

    /// The `host:port` to read out to the user, or `None` when no usable local
    /// address was found.
    pub fn address(&self) -> Option<String> {
        self.host.as_ref().map(|h| format!("{h}:{}", self.port))
    }
}

/// 16 random bytes from the operating system.
fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qr_window_matches_what_the_phone_will_parse() {
        let offer = PairingOffer::new(
            PairingMode::Qr,
            47_321,
            Some("192.168.1.20".into()),
            Some("Desk PC".into()),
            1_700_000_000,
        );
        let text = offer.qr_text().expect("a QR window has text");
        assert!(text.starts_with(QR_PREFIX));

        let parsed = QrPayload::decode(&text).expect("decodes");
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.p, 47_321);
        assert_eq!(parsed.h.as_deref(), Some("192.168.1.20"));
        assert_eq!(parsed.name.as_deref(), Some("Desk PC"));
        assert_eq!(parsed.exp, offer.expires_at());

        // The nonce in the QR is the nonce in the prologue. That is the whole
        // point of the window, so it is asserted rather than assumed.
        let nonce = parsed.nonce_bytes().expect("nonce");
        let mut expected = b"device-connect/v1\0".to_vec();
        expected.push(0x00);
        expected.extend_from_slice(&nonce);
        assert_eq!(offer.prologue(), expected);
        assert_eq!(offer.prologue(), dc_protocol::noise::prologue(Some(&nonce)));
    }

    #[test]
    fn two_qr_windows_never_share_a_nonce() {
        let a = PairingOffer::qr(1, None, None);
        let b = PairingOffer::qr(1, None, None);
        assert_ne!(a.qr_text().unwrap(), b.qr_text().unwrap());
        assert_ne!(nonce_in(&a), nonce_in(&b));
    }

    /// The nonce the QR carries, read back the way the phone would.
    fn nonce_in(offer: &PairingOffer) -> [u8; NONCE_LEN] {
        QrPayload::decode(&offer.qr_text().unwrap())
            .expect("decodes")
            .nonce_bytes()
            .expect("nonce")
    }

    #[test]
    fn a_manual_window_has_no_qr_and_the_bare_prologue() {
        let offer = PairingOffer::manual(47_321, Some("192.168.1.20".into()), None);
        assert_eq!(offer.mode(), PairingMode::Manual);
        assert_eq!(offer.qr_text(), None);
        assert_eq!(offer.prologue(), b"device-connect/v1\0\x01");
        assert_eq!(offer.address().as_deref(), Some("192.168.1.20:47321"));
    }

    #[test]
    fn a_window_without_an_address_has_nothing_to_read_out() {
        let offer = PairingOffer::qr(1, None, None);
        assert_eq!(offer.address(), None);
    }

    #[test]
    fn windows_expire_after_two_minutes() {
        let offer = PairingOffer::new(PairingMode::Qr, 1, None, None, 1_000);
        assert_eq!(offer.mode(), PairingMode::Qr);
        assert_eq!(offer.expires_at(), 1_000 + QR_VALIDITY_SECS);
        assert_eq!(QR_VALIDITY_SECS, 120);
        assert!(!offer.is_expired(1_000));
        assert!(!offer.is_expired(1_000 + QR_VALIDITY_SECS));
        assert!(offer.is_expired(1_000 + QR_VALIDITY_SECS + 1));
    }

    #[test]
    fn the_confirmation_code_comes_from_dc_protocol_unchanged() {
        let code = confirmation_code(&[1u8; 32], &[2u8; 32]);
        assert_eq!(
            code,
            dc_protocol::confirm::confirmation_code(&[2u8; 32], &[1u8; 32])
        );
        assert_eq!(code.len(), 6);
    }
}
