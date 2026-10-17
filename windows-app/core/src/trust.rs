//! Which phones this PC has been paired with.
//!
//! A phone is trusted only because the user compared the six-digit code on both
//! devices (protocol section 3) and this store recorded the key that was in use
//! at that moment. Nothing else - not a device name, not an address - is treated
//! as identity, because none of those are secret and all of them can be changed
//! by whoever is on the network.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::identity::{device_id, KEY_LEN};
use crate::store::{io_error, write_atomic, StoreError};

/// The trust list format this build writes.
const CURRENT_VERSION: u32 = 1;

/// One paired phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Base64url, no padding, of the pinned X25519 public key.
    pub key: String,
    /// Derived from `key` ([`crate::identity::device_id`]). Stored so the file
    /// can be read by a person, and re-checked on load so a hand-edited file is
    /// refused rather than displayed as somebody else.
    pub id: String,
    /// The name the phone gave at its last connection. Display only.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Unix seconds when the user confirmed the code.
    pub paired_at: u64,
}

impl Peer {
    pub fn new(key: [u8; KEY_LEN], name: String, model: Option<String>, paired_at: u64) -> Self {
        Self {
            key: URL_SAFE_NO_PAD.encode(key),
            id: device_id(&key),
            name,
            model,
            paired_at,
        }
    }

    /// The pinned key, or an error if the stored text is not a key.
    pub fn key_bytes(&self) -> Result<[u8; KEY_LEN], StoreError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.key)
            .map_err(|e| StoreError::Corrupt {
                name: format!("peer {}", self.id),
                detail: format!("key is not base64url: {e}"),
            })?;
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt {
                name: format!("peer {}", self.id),
                detail: format!(
                    "expected a {KEY_LEN}-byte key, found {} bytes",
                    decoded.len()
                ),
            })
    }
}

/// The pinned phones, and the operations the session needs on them.
pub trait TrustStore: Send + Sync {
    fn peers(&self) -> Result<Vec<Peer>, StoreError>;

    fn find_by_key(&self, key: &[u8; KEY_LEN]) -> Result<Option<Peer>, StoreError>;

    /// Add `peer`, or refresh the name of the peer already pinned under the same
    /// key. Re-pinning must not move `paired_at`: that timestamp is when the user
    /// compared the code, and it does not become truer by connecting again.
    fn pin(&self, peer: Peer) -> Result<(), StoreError>;

    /// Forget the peer with this key. Succeeds when nothing was pinned.
    fn unpin(&self, key: &[u8; KEY_LEN]) -> Result<(), StoreError>;

    /// Whether this exact key is pinned.
    fn is_pinned(&self, key: &[u8; KEY_LEN]) -> Result<bool, StoreError> {
        Ok(self.find_by_key(key)?.is_some())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TrustFile {
    #[serde(default = "current_version")]
    version: u32,
    #[serde(default)]
    peers: Vec<Peer>,
}

fn current_version() -> u32 {
    CURRENT_VERSION
}

/// The trust list as a JSON file.
///
/// Writes go through a temporary file and a rename, so a crash mid-write leaves
/// the previous list intact rather than a truncated one that would unpair every
/// phone at once. A `Mutex` serialises the read-modify-write inside this process;
/// the file is small and only touched on pair, connect and unpair.
pub struct FileTrustStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileTrustStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// The default location:
    /// `%APPDATA%\Device Connect\trusted-phones.json`.
    pub fn default_path() -> Result<PathBuf, StoreError> {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| StoreError::Backend("APPDATA is not set".into()))?;
        Ok(base.join("Device Connect").join("trusted-phones.json"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<TrustFile, StoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(TrustFile {
                    version: CURRENT_VERSION,
                    peers: Vec::new(),
                })
            }
            Err(e) => return Err(io_error(&self.path, e)),
        };

        let file: TrustFile = serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt {
            name: self.path.display().to_string(),
            detail: format!("not a trust list: {e}"),
        })?;

        if file.version > CURRENT_VERSION {
            // Refuse rather than drop the entries this build cannot read: losing
            // pinned peers silently would look like the phones had been tampered
            // with, and re-pairing every device is the safe way out.
            return Err(StoreError::Backend(format!(
                "{} uses trust list version {}, newer than this build understands ({CURRENT_VERSION})",
                self.path.display(),
                file.version
            )));
        }

        for peer in &file.peers {
            let key = peer.key_bytes()?;
            if peer.id != device_id(&key) {
                return Err(StoreError::Corrupt {
                    name: self.path.display().to_string(),
                    detail: format!("entry id {} does not match its key", peer.id),
                });
            }
        }
        Ok(file)
    }

    fn store(&self, file: &TrustFile) -> Result<(), StoreError> {
        let mut bytes = serde_json::to_vec_pretty(file)
            .map_err(|e| StoreError::Backend(format!("could not encode the trust list: {e}")))?;
        bytes.push(b'\n');
        write_atomic(&self.path, &bytes)
    }
}

impl TrustStore for FileTrustStore {
    fn peers(&self) -> Result<Vec<Peer>, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.load()?.peers)
    }

    fn find_by_key(&self, key: &[u8; KEY_LEN]) -> Result<Option<Peer>, StoreError> {
        let key_b64 = URL_SAFE_NO_PAD.encode(key);
        Ok(self.peers()?.into_iter().find(|p| p.key == key_b64))
    }

    fn pin(&self, peer: Peer) -> Result<(), StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.load()?;

        match file.peers.iter_mut().find(|p| p.key == peer.key) {
            Some(existing) => {
                if existing.name == peer.name && existing.model == peer.model {
                    // Nothing to record; skip the write so a reconnect does not
                    // touch the disk for no reason.
                    return Ok(());
                }
                existing.name = peer.name;
                existing.model = peer.model;
            }
            None => file.peers.push(peer),
        }
        self.store(&file)
    }

    fn unpin(&self, key: &[u8; KEY_LEN]) -> Result<(), StoreError> {
        let key_b64 = URL_SAFE_NO_PAD.encode(key);
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.load()?;

        let before = file.peers.len();
        file.peers.retain(|p| p.key != key_b64);
        if file.peers.len() == before {
            return Ok(());
        }
        self.store(&file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn store() -> (tempfile::TempDir, FileTrustStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileTrustStore::new(dir.path().join("trusted-phones.json"));
        (dir, store)
    }

    #[test]
    fn pinning_then_finding_round_trips_through_the_file() {
        let (_dir, store) = store();
        let phone = Identity::generate();
        let key = phone.public();

        assert!(!store.is_pinned(&key).unwrap());
        store
            .pin(Peer::new(
                key,
                "Pixel 8".into(),
                Some("Pixel 8".into()),
                1_700_000_000,
            ))
            .unwrap();

        let found = store.find_by_key(&key).unwrap().expect("pinned");
        assert_eq!(found.name, "Pixel 8");
        assert_eq!(found.key_bytes().unwrap(), key);
        assert_eq!(found.id, device_id(&key));
        assert!(store.is_pinned(&key).unwrap());
    }

    #[test]
    fn re_pinning_refreshes_the_name_without_moving_paired_at() {
        let (_dir, store) = store();
        let identity = Identity::generate();
        let key = identity.public();

        store
            .pin(Peer::new(key, "Old name".into(), None, 1000))
            .unwrap();
        store
            .pin(Peer::new(
                key,
                "New name".into(),
                Some("Pixel".into()),
                9999,
            ))
            .unwrap();

        let peers = store.peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "New name");
        assert_eq!(peers[0].model.as_deref(), Some("Pixel"));
        assert_eq!(
            peers[0].paired_at, 1000,
            "the confirmation time must not move"
        );
    }

    #[test]
    fn unpinning_removes_only_that_phone() {
        let (_dir, store) = store();
        let first = Identity::generate();
        let second = Identity::generate();
        store
            .pin(Peer::new(first.public(), "One".into(), None, 1))
            .unwrap();
        store
            .pin(Peer::new(second.public(), "Two".into(), None, 2))
            .unwrap();

        store.unpin(&first.public()).unwrap();
        assert!(!store.is_pinned(&first.public()).unwrap());
        assert!(store.is_pinned(&second.public()).unwrap());
        // Unpinning again is not an error.
        store.unpin(&first.public()).unwrap();
    }

    #[test]
    fn an_entry_whose_id_disagrees_with_its_key_is_refused() {
        let (dir, store) = store();
        let peer = Peer::new([3u8; KEY_LEN], "Phone".into(), None, 1);
        fs::write(
            dir.path().join("trusted-phones.json"),
            format!(
                r#"{{"version":1,"peers":[{{"key":"{}","id":"0000000000000000","name":"Phone","paired_at":1}}]}}"#,
                peer.key
            ),
        )
        .unwrap();

        match store.peers() {
            Err(StoreError::Corrupt { detail, .. }) => {
                assert!(
                    detail.contains("does not match"),
                    "unexpected detail: {detail}"
                )
            }
            other => panic!("expected a corrupt-entry error, got {other:?}"),
        }
    }

    #[test]
    fn a_newer_trust_list_version_is_refused_rather_than_emptied() {
        let (dir, store) = store();
        fs::write(
            dir.path().join("trusted-phones.json"),
            r#"{"version":99,"peers":[]}"#,
        )
        .unwrap();

        match store.peers() {
            Err(StoreError::Backend(message)) => assert!(message.contains("version 99")),
            other => panic!("expected a version error, got {other:?}"),
        }
    }
}
