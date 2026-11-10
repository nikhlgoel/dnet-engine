//! T088 — where the cloud credential lives, and the one type that carries it (PR-03, PR-04, FR-009a).
//!
//! The wizard needs a credential that can create billable cloud resources. That is the most valuable
//! secret this product ever touches, so it has exactly one home and one type:
//!
//! - [`Secret`] holds the value, overwrites its memory when dropped, and prints as `<redacted>` from both
//!   `Debug` and `Display`. The only way to read it is [`Secret::expose_secret`], a name that is easy to
//!   find in a review. Nothing in this crate puts a `Secret` into an error, a log line, an IPC message or
//!   a progress event; the contract test PRV-02 scans every output for a known sentinel to keep it so.
//! - [`CredentialVault`] stores it. On Windows [`DpapiUserVault`] seals it with DPAPI in **user** scope:
//!   only the Windows account that stored it can open it, on this machine. It is never written to the
//!   service's configuration (the service runs as another account and could not open it anyway), and it
//!   is not machine scope: any process on the machine can open a machine-scope blob.
//!
//! The vault is for the person's *cloud* credential. Credentials for the product's own endpoints belong to
//! `dnet-config`'s secret store, which is the service's.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

/// A credential value. Wipes itself when dropped; never prints.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(material: impl Into<String>) -> Self {
        Self(Zeroizing::new(material.into()))
    }

    /// The value. Named so that every use stands out in a review.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why the vault could not do what was asked. No variant carries the credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    #[error("not a valid credential name")]
    InvalidName,
    #[error("the credential store could not be used: {0}")]
    Unavailable(String),
    #[error(
        "the stored credential could not be opened: it was sealed for another user or machine, or it was changed"
    )]
    Unreadable,
}

/// A name the vault accepts: 1 to 64 characters, lower-case letters, digits and `-`. Names become file
/// names, so nothing that could mean a path is allowed.
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Somewhere to keep a credential between the moment the person pastes it and the moment provisioning
/// finishes.
pub trait CredentialVault: Send + Sync {
    /// Store `secret` under `name`, replacing any earlier value.
    fn put(&self, name: &str, secret: &Secret) -> Result<(), VaultError>;
    /// The value under `name`, or `None` if there is none.
    fn get(&self, name: &str) -> Result<Option<Secret>, VaultError>;
    /// Forget `name`. `Ok(false)` if there was nothing to forget.
    fn delete(&self, name: &str) -> Result<bool, VaultError>;
}

/// A vault that keeps credentials in memory only. For tests, and for hosts without a sealed store.
#[derive(Default)]
pub struct MemoryVault(Mutex<HashMap<String, Secret>>);

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialVault for MemoryVault {
    fn put(&self, name: &str, secret: &Secret) -> Result<(), VaultError> {
        if !valid_name(name) {
            return Err(VaultError::InvalidName);
        }
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_owned(), secret.clone());
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Secret>, VaultError> {
        if !valid_name(name) {
            return Err(VaultError::InvalidName);
        }
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned())
    }

    fn delete(&self, name: &str) -> Result<bool, VaultError> {
        if !valid_name(name) {
            return Err(VaultError::InvalidName);
        }
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name)
            .is_some())
    }
}

#[cfg(windows)]
pub use windows_impl::DpapiUserVault;

#[cfg(windows)]
mod windows_impl {
    //! DPAPI in user scope, one sealed file per name.

    use std::path::{Path, PathBuf};

    use windows::core::w;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use zeroize::Zeroize;

    use super::{valid_name, CredentialVault, Secret, VaultError};

    /// Seals credentials with DPAPI **user** scope (no machine-scope flag): only the account that sealed
    /// a blob can open it. The name is mixed in as DPAPI's optional entropy, so a blob copied to another
    /// name does not open.
    pub struct DpapiUserVault {
        dir: PathBuf,
    }

    impl DpapiUserVault {
        /// A vault in `dir` (for the product, a folder under the person's own profile).
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            Self { dir: dir.into() }
        }

        fn path(&self, name: &str) -> Result<PathBuf, VaultError> {
            if !valid_name(name) {
                return Err(VaultError::InvalidName);
            }
            Ok(self.dir.join(format!("{name}.cloud-credential.bin")))
        }
    }

    fn entropy_for(name: &str) -> Vec<u8> {
        format!("dnet-engine/provision/cloud-credential/v1/{name}").into_bytes()
    }

    fn blob_over(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            // DPAPI does not write through the input pointer.
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Copy a DPAPI output buffer, overwrite it and free it.
    ///
    /// # Safety
    /// `out` must be an output blob filled in by a successful DPAPI call (or empty).
    unsafe fn take_output(out: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        let view = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let copy = view.to_vec();
        if wipe {
            view.zeroize();
        }
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        copy
    }

    fn seal(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, VaultError> {
        let input = blob_over(plaintext);
        let entropy = blob_over(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: both input blobs point at live slices for the call; `out` is a valid destination
        // whose buffer `take_output` frees.
        unsafe {
            CryptProtectData(
                &input,
                w!("DNet Engine cloud credential"),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|_| {
                VaultError::Unavailable("the operating system could not seal it".into())
            })?;
            Ok(take_output(out, false))
        }
    }

    fn unseal(sealed: &[u8], entropy: &[u8]) -> Result<Vec<u8>, VaultError> {
        let input = blob_over(sealed);
        let entropy = blob_over(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as for `seal`; the output holds the plaintext, which `take_output` wipes.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|_| VaultError::Unreadable)?;
            Ok(take_output(out, true))
        }
    }

    fn io_error(kind: std::io::ErrorKind) -> VaultError {
        VaultError::Unavailable(format!("the store could not be read or written ({kind})"))
    }

    fn write_replacing(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, bytes).map_err(|e| io_error(e.kind()))?;
        std::fs::rename(&temp, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            io_error(e.kind())
        })
    }

    impl CredentialVault for DpapiUserVault {
        fn put(&self, name: &str, secret: &Secret) -> Result<(), VaultError> {
            let path = self.path(name)?;
            std::fs::create_dir_all(&self.dir).map_err(|e| io_error(e.kind()))?;
            let sealed = seal(secret.expose_secret().as_bytes(), &entropy_for(name))?;
            write_replacing(&path, &sealed)
        }

        fn get(&self, name: &str) -> Result<Option<Secret>, VaultError> {
            let path = self.path(name)?;
            let sealed = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(io_error(e.kind())),
            };
            let plain = unseal(&sealed, &entropy_for(name))?;
            let text = String::from_utf8(plain).map_err(|e| {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                VaultError::Unreadable
            })?;
            Ok(Some(Secret::new(text)))
        }

        fn delete(&self, name: &str) -> Result<bool, VaultError> {
            let path = self.path(name)?;
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(io_error(e.kind())),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SENTINEL: &str = "SENTINEL-cloud-credential-7c1e";

        fn vault() -> (tempfile::TempDir, DpapiUserVault) {
            let dir = tempfile::tempdir().unwrap();
            let vault = DpapiUserVault::new(dir.path().join("vault"));
            (dir, vault)
        }

        #[test]
        fn a_credential_round_trips_and_is_not_on_disk_in_the_clear() {
            let (dir, vault) = vault();
            vault.put("oracle-main", &Secret::new(SENTINEL)).unwrap();
            let back = vault.get("oracle-main").unwrap().expect("stored");
            assert_eq!(back.expose_secret(), SENTINEL);
            for entry in std::fs::read_dir(dir.path().join("vault")).unwrap() {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                assert!(
                    !bytes
                        .windows(SENTINEL.len())
                        .any(|w| w == SENTINEL.as_bytes()),
                    "the credential is on disk in the clear"
                );
            }
        }

        #[test]
        fn a_blob_copied_to_another_name_does_not_open() {
            let (dir, vault) = vault();
            vault.put("one", &Secret::new(SENTINEL)).unwrap();
            let folder = dir.path().join("vault");
            std::fs::copy(
                folder.join("one.cloud-credential.bin"),
                folder.join("two.cloud-credential.bin"),
            )
            .unwrap();
            assert_eq!(vault.get("two"), Err(VaultError::Unreadable));
        }

        #[test]
        fn a_changed_file_does_not_open() {
            let (dir, vault) = vault();
            vault.put("one", &Secret::new(SENTINEL)).unwrap();
            let file = dir.path().join("vault").join("one.cloud-credential.bin");
            let mut bytes = std::fs::read(&file).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            std::fs::write(&file, bytes).unwrap();
            assert_eq!(vault.get("one"), Err(VaultError::Unreadable));
        }

        #[test]
        fn a_missing_credential_is_none_and_deleting_it_twice_is_fine() {
            let (_dir, vault) = vault();
            assert_eq!(vault.get("nothing").unwrap(), None);
            vault.put("one", &Secret::new("x")).unwrap();
            assert_eq!(vault.delete("one"), Ok(true));
            assert_eq!(vault.delete("one"), Ok(false));
            assert_eq!(vault.get("one").unwrap(), None);
        }

        /// "Not there" and "there but unusable" are different answers: only the first is `None` / `false`.
        #[test]
        fn a_store_that_cannot_be_read_is_an_error_not_an_empty_answer() {
            let (_dir, vault) = vault();
            vault.put("one", &Secret::new("x")).unwrap();
            let file = vault.path("one").unwrap();
            std::fs::remove_file(&file).unwrap();
            // A folder where the credential's file should be: it exists, and it is not a file.
            std::fs::create_dir(&file).unwrap();
            assert!(matches!(vault.get("one"), Err(VaultError::Unavailable(_))));
            assert!(matches!(
                vault.delete("one"),
                Err(VaultError::Unavailable(_))
            ));
        }

        #[test]
        fn putting_again_replaces_the_value() {
            let (_dir, vault) = vault();
            vault.put("one", &Secret::new("first")).unwrap();
            vault.put("one", &Secret::new("second")).unwrap();
            assert_eq!(vault.get("one").unwrap().unwrap().expose_secret(), "second");
        }

        #[test]
        fn names_that_could_be_paths_are_refused_before_any_file_is_touched() {
            let (dir, vault) = vault();
            let long = "x".repeat(65);
            for bad in ["", "..", "a/b", "a\\b", "A", "a b", "a.b", long.as_str()] {
                assert_eq!(
                    vault.put(bad, &Secret::new("x")),
                    Err(VaultError::InvalidName),
                    "{bad:?}"
                );
                assert_eq!(vault.get(bad), Err(VaultError::InvalidName));
                assert_eq!(vault.delete(bad), Err(VaultError::InvalidName));
            }
            assert!(!dir.path().join("vault").exists());
        }

        #[test]
        fn it_is_user_scope_not_machine_scope() {
            // Machine scope is requested with a flag whose name this file assembles at run time, so the
            // scan below does not find itself.
            let machine_flag = ["CRYPTPROTECT", "_LOCAL_MACHINE"].concat();
            let source = include_str!("secret.rs");
            let uses_it = source
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains(&machine_flag));
            assert!(
                !uses_it,
                "machine scope would let any process on the machine open it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints() {
        let secret = Secret::new("SENTINEL-do-not-print");
        for text in [
            format!("{secret:?}"),
            format!("{secret}"),
            format!("{secret:#?}"),
        ] {
            assert!(!text.contains("SENTINEL"), "{text}");
            assert!(text.contains("redacted"), "{text}");
        }
        assert_eq!(secret.expose_secret(), "SENTINEL-do-not-print");
    }

    #[test]
    fn a_secret_inside_a_struct_does_not_print_either() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            credential: Secret,
        }
        let shown = format!(
            "{:?}",
            Holder {
                credential: Secret::new("SENTINEL-nested")
            }
        );
        assert!(!shown.contains("SENTINEL"), "{shown}");
    }

    #[test]
    fn names_are_lower_case_digits_and_hyphens_only() {
        for good in ["a", "oracle-main", "x1-2", &"a".repeat(64)] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "",
            "A",
            "a_b",
            "a.b",
            "a/b",
            "a\\b",
            "..",
            " a",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_memory_vault_stores_replaces_and_forgets() {
        let vault = MemoryVault::new();
        assert_eq!(vault.get("one").unwrap(), None);
        vault.put("one", &Secret::new("first")).unwrap();
        vault.put("one", &Secret::new("second")).unwrap();
        assert_eq!(vault.get("one").unwrap().unwrap().expose_secret(), "second");
        assert_eq!(vault.delete("one"), Ok(true));
        assert_eq!(vault.delete("one"), Ok(false));
        assert_eq!(
            vault.put("A", &Secret::new("x")),
            Err(VaultError::InvalidName)
        );
    }
}
