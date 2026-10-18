//! The PC's long-term key, in the per-user Windows Credential Manager.
//!
//! [`FileSecretStore`](crate::store::FileSecretStore) is real storage, but it is
//! a file: a backup, a sync client or a `dir /s` that reaches the profile can
//! copy it, and what protects it is the profile's ACL. A Credential Manager
//! entry is encrypted at rest with the user's DPAPI keys and never exists as a
//! file at all, which is why the desktop shell hands [`Identity`] this store
//! instead.
//!
//! What this does **not** do is separate programs. Any process running as the
//! same user can call `CredReadW` on the same target name; the entry is per
//! user, not per process. It raises the cost of a stolen disk, a roaming
//! profile or a second account on the machine, and it puts the entry where the
//! user can see and delete it in Credential Manager. It is not a sandbox.
//!
//! Three Windows rules shape the code below:
//!
//! - `CRED_MAX_CREDENTIAL_BLOB_SIZE` is 2560 bytes. A larger value is refused
//!   here, by name and size, rather than coming back as a bare `false` with an
//!   error code that says nothing about why.
//! - the API needs a logon session. A service or a scheduled task running as
//!   another account can be refused with `ERROR_NO_SUCH_LOGON_SESSION`, which is
//!   reported as what it is instead of being mistaken for a missing entry.
//! - read and write are separate calls with no transaction between them, so a
//!   `load` right after a `save` is the only way to know a `save` landed. This
//!   store therefore does not cache anything and never reports success it has
//!   not just observed. [`CredManSecretStore::probe`] checks the session before
//!   the first write, so a PC does not discover it cannot keep its key halfway
//!   through making one.
//!
//! [`Identity`]: crate::identity::Identity

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_MAX_CREDENTIAL_BLOB_SIZE,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

use crate::store::{SecretStore, StoreError};

/// The most this API will keep in one entry (wincred.h: 5 * 512).
pub const MAX_BLOB_LEN: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize;

/// Prefix of every target name this app writes, so its entries are recognisable
/// in Credential Manager and cannot collide with another program's.
pub const TARGET_PREFIX: &str = "Device Connect";

/// Shown by Credential Manager as the account this entry belongs to.
const USER_NAME: &str = "Device Connect";

/// `ERROR_NO_SUCH_LOGON_SESSION`: no interactive session for this user.
const ERROR_NO_SUCH_LOGON_SESSION: u32 = 1312;

/// Secrets in the per-user Windows Credential Manager.
///
/// A unit type: the API takes the target name on every call and keeps no state
/// here, so there is nothing to open, share or close.
#[derive(Debug, Default, Clone, Copy)]
pub struct CredManSecretStore;

impl CredManSecretStore {
    pub fn new() -> Self {
        Self
    }

    /// Check that this session can reach the Credential Manager at all.
    ///
    /// Read-only: it looks up a name this app never writes and treats "not
    /// there", which is the expected answer, as success. The shell can call it
    /// at startup and tell the user before it tries to save the key that makes
    /// the PC itself.
    pub fn probe(&self) -> Result<(), StoreError> {
        let target = wide(&format!("{TARGET_PREFIX}:probe"));
        let mut raw: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `target` is a NUL-terminated UTF-16 buffer that outlives the
        // call, `raw` is a valid out-pointer, and the type and flags are the
        // documented ones for a generic credential.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND {
                Ok(())
            } else {
                Err(failed("read", "probe", code))
            };
        }
        // Something else owns that name. Free it and still call the session
        // usable: the probe is about access, not about the name being free.
        drop(Buffer(raw));
        Ok(())
    }
}

impl SecretStore for CredManSecretStore {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let target = target_name(name)?;
        let mut raw: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: as in `probe`. On success `raw` points to a Credential Manager
        // buffer that only we may free, which `Buffer` does.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(failed("read", name, code))
            };
        }

        let held = Buffer(raw);
        // SAFETY: `CredReadW` succeeded, so it filled the pointer with a live
        // `CREDENTIALW` that stays valid until `CredFree`, which `held` owns.
        let entry = unsafe { &*held.0 };
        let len = entry.CredentialBlobSize as usize;
        if entry.CredentialBlob.is_null() || len == 0 {
            // A stored but empty value is a value, not a missing entry.
            return Ok(Some(Vec::new()));
        }
        // SAFETY: the API just reported this buffer as `len` bytes it allocated.
        let blob = unsafe { std::slice::from_raw_parts(entry.CredentialBlob, len) };
        Ok(Some(blob.to_vec()))
    }

    fn save(&self, name: &str, secret: &[u8]) -> Result<(), StoreError> {
        if secret.len() > MAX_BLOB_LEN {
            return Err(StoreError::Backend(format!(
                "a Credential Manager entry holds at most {MAX_BLOB_LEN} bytes, so {name} \
                 cannot be stored as one ({} bytes)",
                secret.len()
            )));
        }

        let mut target = target_name(name)?;
        let mut user = wide(USER_NAME);
        let mut blob = secret.to_vec();

        let entry = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            // This machine only. Roaming the key to another PC with a domain
            // profile would put the same id on two devices.
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: user.as_mut_ptr(),
            ..CREDENTIALW::default()
        };

        // SAFETY: every pointer in `entry` points into a live local buffer that
        // is not moved or dropped until after this call returns.
        let ok = unsafe { CredWriteW(&entry, 0) };
        if ok == 0 {
            return Err(failed("store", name, unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        let target = target_name(name)?;
        // SAFETY: `target` is a NUL-terminated UTF-16 buffer alive across the call.
        let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(failed("delete", name, code));
            }
        }
        Ok(())
    }
}

/// What the user sees as the target name.
///
/// Rejects anything that is not exactly representable instead of rewriting it,
/// so two different names can never land on the same entry. (The file store
/// rewrites instead, because a file name is allowed to differ from the secret's
/// name; here it would be a silent collision.)
fn target_name(name: &str) -> Result<Vec<u16>, StoreError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(StoreError::Backend(format!(
            "{name:?} is not a usable Credential Manager target name; names are letters, \
             digits, dashes and underscores"
        )));
    }
    Ok(wide(&format!("{TARGET_PREFIX}:{name}")))
}

/// A Win32 error, with the two the user can actually act on called out.
fn failed(action: &str, name: &str, code: u32) -> StoreError {
    let mut detail = io::Error::from_raw_os_error(code as i32).to_string();
    if code == ERROR_NO_SUCH_LOGON_SESSION {
        detail.push_str(" (Credential Manager needs an interactive session for this user)");
    }
    StoreError::Backend(format!(
        "Credential Manager would not {action} {TARGET_PREFIX}:{name}: {detail} (0x{code:08X})"
    ))
}

/// A NUL-terminated UTF-16 string, which is what the `*W` entry points take.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Frees what `CredReadW` allocated, whatever happens next.
///
/// A guard rather than a `CredFree` at the end of each path: the read happens
/// between the two, and a panic there would otherwise leak the entry.
struct Buffer(*mut CREDENTIALW);

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from `CredReadW` (or `CredReadW`-style
            // call), which documents that the caller owns the buffer and must
            // release it with `CredFree`.
            unsafe { CredFree(self.0.cast()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name used by exactly one test in one run.
    ///
    /// Nothing here may touch `Device Connect:pc-identity-v1`, which on a
    /// developer's machine may be a real identity, and a crashed earlier run
    /// must not collide with this one.
    fn unique(what: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_nanos();
        format!("test-{what}-{}-{nanos}", std::process::id())
    }

    /// A scratch entry that is deleted even when an assertion fails.
    struct Scratch {
        store: CredManSecretStore,
        name: String,
    }

    impl Scratch {
        fn new(what: &str) -> Self {
            Self {
                store: CredManSecretStore::new(),
                name: unique(what),
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.name);
        }
    }

    #[test]
    fn this_session_can_reach_the_credential_manager() {
        CredManSecretStore::new()
            .probe()
            .expect("a desktop session can read the vault");
    }

    #[test]
    fn a_secret_round_trips_and_the_second_write_wins() {
        let s = Scratch::new("round-trip");
        assert_eq!(s.store.load(&s.name).unwrap(), None, "nothing stored yet");

        let first = [0x11u8; 32];
        s.store.save(&s.name, &first).unwrap();
        assert_eq!(s.store.load(&s.name).unwrap(), Some(first.to_vec()));

        let second = [0x22u8; 32];
        s.store.save(&s.name, &second).unwrap();
        assert_eq!(
            s.store.load(&s.name).unwrap(),
            Some(second.to_vec()),
            "saving replaces the entry instead of adding one"
        );
    }

    #[test]
    fn delete_forgets_the_entry_and_repeating_it_is_not_an_error() {
        let s = Scratch::new("delete");
        s.store.save(&s.name, &[7u8; 32]).unwrap();

        s.store.delete(&s.name).unwrap();
        assert_eq!(s.store.load(&s.name).unwrap(), None);

        s.store
            .delete(&s.name)
            .expect("deleting what is not there is the same as deleting it");
    }

    #[test]
    fn the_largest_entry_the_api_allows_is_still_accepted() {
        let s = Scratch::new("boundary");
        let biggest = vec![0xA5u8; MAX_BLOB_LEN];
        s.store.save(&s.name, &biggest).unwrap();
        assert_eq!(s.store.load(&s.name).unwrap(), Some(biggest));
    }

    #[test]
    fn anything_larger_is_refused_by_name_and_size() {
        let s = Scratch::new("too-big");
        let err = s
            .store
            .save(&s.name, &vec![0u8; MAX_BLOB_LEN + 1])
            .expect_err("2561 bytes cannot go in one entry");
        let message = err.to_string();
        assert!(message.contains(&MAX_BLOB_LEN.to_string()), "{message}");
        assert!(
            message.contains(&(MAX_BLOB_LEN + 1).to_string()),
            "{message}"
        );
        assert_eq!(s.store.load(&s.name).unwrap(), None, "nothing was written");
    }

    #[test]
    fn a_name_that_could_not_be_told_apart_is_refused_rather_than_rewritten() {
        let store = CredManSecretStore::new();
        for bad in ["", "a/b", "a:b", "a b", "caf\u{e9}", "a\u{0}b"] {
            assert!(store.load(bad).is_err(), "load({bad:?})");
            assert!(store.save(bad, &[1]).is_err(), "save({bad:?})");
            assert!(store.delete(bad).is_err(), "delete({bad:?})");
        }
    }

    #[test]
    fn the_default_store_is_this_one() {
        assert_eq!(
            crate::store::default_store_name(),
            "Windows Credential Manager"
        );
        let store = crate::store::default_secret_store().expect("the default store exists");
        let s = Scratch {
            store: CredManSecretStore::new(),
            name: unique("default"),
        };
        store.save(&s.name, b"through the trait object").unwrap();
        assert_eq!(
            store.load(&s.name).unwrap(),
            Some(b"through the trait object".to_vec())
        );
        store.delete(&s.name).unwrap();
    }
}
