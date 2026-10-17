//! The PC's long-term key pair, and what it calls itself on the wire.

use dc_protocol::schema::DeviceInfo;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hex;
use crate::store::{SecretStore, StoreError};

/// Where the PC identity lives in the [`SecretStore`].
pub const IDENTITY_SECRET_NAME: &str = "pc-identity-v1";

/// X25519 keys are 32 bytes.
pub const KEY_LEN: usize = 32;

/// What this PC calls itself (protocol section 2.2).
///
/// The device id is not here because it is derived from the key: see
/// [`device_id`]. The rest comes from the caller, because only the app layer can
/// ask Windows for its name and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub name: String,
    pub model: Option<String>,
    pub os: String,
}

impl HostInfo {
    /// A sensible default for a desktop: the machine name and a plain OS label.
    ///
    /// The OS string here is deliberately vague. Filling in "Windows 11 24H2"
    /// means asking the registry or the Win32 API, which is the app layer's job;
    /// inventing a version string in the core would put a wrong claim on the
    /// wire.
    pub fn desktop() -> Self {
        let name = std::env::var("COMPUTERNAME")
            .ok()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "PC".to_string());
        Self {
            name,
            model: None,
            os: std::env::consts::OS.to_string(),
        }
    }
}

/// The device id for a static public key: the first 8 bytes of its SHA-256, in
/// hex, which is the 16 characters section 2.2 calls for.
///
/// Derived rather than chosen, so a key and the id shown next to it can never
/// disagree, and rotating the key cannot leave a stale id behind.
pub fn device_id(public: &[u8; KEY_LEN]) -> String {
    hex::encode(&Sha256::digest(public)[..8])
}

/// The PC's X25519 key pair.
///
/// The secret half is only ever handed to the handshake and to the store. The
/// type has no `Display`, and its `Debug` prints the public id alone, so an
/// accidental `{:?}` in a log line cannot leak it.
#[derive(Clone)]
pub struct Identity {
    secret: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl Identity {
    /// A fresh key pair from the operating system's random source.
    pub fn generate() -> Self {
        let mut secret = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut secret);
        Self::from_secret(secret)
    }

    /// The key pair with the given secret half.
    pub fn from_secret(secret: [u8; KEY_LEN]) -> Self {
        let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        Self { secret, public }
    }

    /// The stored identity, generating and storing one on first run.
    ///
    /// A stored value that is not exactly one key is treated as corrupt rather
    /// than truncated or padded into one: a mangled key would silently become a
    /// different identity, and every phone would then refuse the PC.
    pub fn load_or_create(store: &dyn SecretStore) -> Result<Self, StoreError> {
        match store.load(IDENTITY_SECRET_NAME)? {
            Some(bytes) => {
                let secret: [u8; KEY_LEN] =
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| StoreError::Corrupt {
                            name: IDENTITY_SECRET_NAME.to_string(),
                            detail: format!("expected {KEY_LEN} bytes, found {}", bytes.len()),
                        })?;
                Ok(Self::from_secret(secret))
            }
            None => {
                let identity = Self::generate();
                identity.store(store)?;
                Ok(identity)
            }
        }
    }

    /// Write this identity to `store`, replacing whatever was there.
    pub fn store(&self, store: &dyn SecretStore) -> Result<(), StoreError> {
        store.save(IDENTITY_SECRET_NAME, &self.secret)
    }

    /// The secret half. Only the handshake and the store should touch this.
    pub fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }

    /// The public half: what the phone pins, and what the id is derived from.
    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public
    }

    /// This PC's device id.
    pub fn id(&self) -> String {
        device_id(&self.public)
    }

    /// The `hello_ack` device block for this identity.
    pub fn device_info(&self, host: &HostInfo) -> DeviceInfo {
        DeviceInfo {
            id: self.id(),
            name: host.name.clone(),
            model: host.model.clone(),
            os: host.os.clone(),
        }
    }
}

/// Printing an identity prints its public id, never its key.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FileSecretStore;

    #[test]
    fn a_stored_identity_is_the_same_identity_next_run() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSecretStore::new(dir.path());

        let first = Identity::load_or_create(&store).expect("create");
        let second = Identity::load_or_create(&store).expect("load");
        assert_eq!(first.public(), second.public());
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn ids_are_derived_from_the_key_and_are_sixteen_hex_characters() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(a.id().len(), 16);
        assert!(a.id().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a.id(), device_id(&a.public()));
        assert_ne!(a.id(), b.id());
        // The public key is not the secret, and the id is not the public key.
        assert_ne!(a.public(), *a.secret());
        assert_eq!(a.public().len(), KEY_LEN);
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let identity = Identity::generate();
        let printed = format!("{identity:?}");
        assert!(printed.contains(&identity.id()));
        assert!(!printed.contains(&hex::encode(identity.secret())));
    }

    #[test]
    fn a_truncated_stored_key_is_an_error_not_a_new_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSecretStore::new(dir.path());
        store.save(IDENTITY_SECRET_NAME, &[7u8; 16]).unwrap();

        match Identity::load_or_create(&store) {
            Err(StoreError::Corrupt { name, .. }) => assert_eq!(name, IDENTITY_SECRET_NAME),
            other => panic!("expected a corrupt-key error, got {other:?}"),
        }
    }
}
