//! Where the PC keeps what must not leak: its own key, and the list of phones it
//! has been paired with.
//!
//! Both are behind traits so the storage decision stays in one place per
//! platform. The file implementations here are what the tests and any headless
//! run use; the desktop shell supplies a Windows store (Credential Manager for
//! the key) when it is built. See the "Secrets" section of `docs/windows.md`
//! for which one is live, and for what the file store does not protect against.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Anything that stops a store from doing its job.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("could not use {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("stored {name} is unusable: {detail}")]
    Corrupt { name: String, detail: String },
    #[error("{0}")]
    Backend(String),
}

pub(crate) fn io_error(path: impl AsRef<Path>, source: io::Error) -> StoreError {
    StoreError::Io {
        path: path.as_ref().to_path_buf(),
        source,
    }
}

/// Replace the write target in one step.
///
/// `rename` on the same directory replaces the destination on Windows as well as
/// on Unix, so a reader never sees half a file: it sees the old bytes or the new
/// ones. A crash in between loses the update entirely, which for a key or a
/// trust list means pairing again rather than trusting something wrong.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path
        .parent()
        .ok_or_else(|| StoreError::Backend(format!("{} has no directory", path.display())))?;
    fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;

    let temp = path.with_extension("writing");
    fs::write(&temp, bytes).map_err(|e| io_error(&temp, e))?;
    fs::rename(&temp, path).map_err(|e| {
        // Leave no half-written file behind for the next run to trip over.
        let _ = fs::remove_file(&temp);
        io_error(path, e)
    })
}

/// A named secret, kept somewhere the user's other programs cannot read it.
pub trait SecretStore: Send + Sync {
    /// The secret stored under `name`, or `None` if there is none yet.
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Store `secret` under `name`, replacing any previous value.
    fn save(&self, name: &str, secret: &[u8]) -> Result<(), StoreError>;

    /// Forget `name`. Succeeds when there was nothing stored.
    fn delete(&self, name: &str) -> Result<(), StoreError>;
}

/// Secrets as files in one directory.
///
/// Real storage, used by tests and by headless runs; the file is renamed into
/// place whole, so a crash cannot leave a truncated key. It inherits the
/// protection of the directory it is given, which is the user's profile by
/// default - good enough on a single-user machine, and why the desktop shell
/// prefers the per-user Windows store for the long-term key.
pub struct FileSecretStore {
    dir: PathBuf,
}

impl FileSecretStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The default location: `%LOCALAPPDATA%\Device Connect\secrets`.
    pub fn default_dir() -> Result<PathBuf, StoreError> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| StoreError::Backend("LOCALAPPDATA is not set".into()))?;
        Ok(base.join("Device Connect").join("secrets"))
    }

    fn path(&self, name: &str) -> PathBuf {
        // Names are ours, but a separator or a dot-dot arriving through this
        // interface would write outside the directory, so nothing but letters,
        // digits, dashes and underscores survives.
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.bin"))
    }
}

impl SecretStore for FileSecretStore {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.path(name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    fn save(&self, name: &str, secret: &[u8]) -> Result<(), StoreError> {
        write_atomic(&self.path(name), secret)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        let path = self.path(name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_error(&path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_deletes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSecretStore::new(dir.path());

        assert_eq!(store.load("pc-key").unwrap(), None);
        store.save("pc-key", &[1, 2, 3]).unwrap();
        assert_eq!(store.load("pc-key").unwrap(), Some(vec![1, 2, 3]));
        store.save("pc-key", &[9]).unwrap();
        assert_eq!(store.load("pc-key").unwrap(), Some(vec![9]));
        store.delete("pc-key").unwrap();
        assert_eq!(store.load("pc-key").unwrap(), None);
        // Deleting twice is not an error: the caller wanted it gone.
        store.delete("pc-key").unwrap();
    }

    #[test]
    fn names_cannot_escape_the_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSecretStore::new(dir.path().join("secrets"));
        store.save("../../escape", b"x").unwrap();

        let written: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(written, vec!["secrets".to_string()]);
    }
}
