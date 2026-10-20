//! T124 — the secret store: where an endpoint's credentials rest.
//!
//! The domain holds only a `CredentialRef` (data-model §1); this module is where one is resolved to
//! material, and one of the two places allowed to do so (credential-handling §2).
//!
//! **Two separate jobs, so each can change alone.**
//!
//! - A [`Sealer`] protects bytes so they are useless anywhere else. On Windows that is DPAPI in
//!   **machine** scope (service-held material; user scope is for the user's own cloud credentials,
//!   credential-handling §1). Linux will seal with `systemd-creds` (ADR-0005, T-L10).
//! - [`BlobStorage`] holds the sealed bytes by name. On Windows that is a directory only SYSTEM and
//!   Administrators control ([`crate::trusted_file`]).
//!
//! **What this does and does not protect, plainly.** A sealed blob is useless if the disk is copied
//! to another machine, and the restricted directory keeps ordinary users out. DPAPI machine scope
//! does *not* stop a process on this machine that runs as an administrator, which can unseal what
//! the service can; neither does any scheme the service itself must be able to read unattended.
//!
//! **Each blob is sealed against its own key** (as DPAPI's optional entropy), so a blob copied
//! under another key's name does not open. A blob that was swapped, altered or sealed elsewhere is
//! an error that says so, never a panic and never partial material.
//!
//! Errors and logs carry the key and the reason, never a byte of the credentials.

use std::collections::HashMap;
use std::sync::Mutex;

use dnet_core::credential::CredentialRef;
use dnet_core::ids::EndpointId;

use crate::credentials::{CredentialsError, EndpointCredentials};

/// The longest key accepted.
pub const MAX_KEY_LEN: usize = 80;

/// Why the store could not do what was asked. Never carries credential material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretStoreError {
    /// The key is not one this store will name a file after.
    #[error("the credential reference is not a valid secret-store key: {0}")]
    InvalidKey(&'static str),
    /// There is nothing to store. An endpoint with no credentials cannot connect.
    #[error("refusing to store an empty credential set")]
    Empty,
    /// The bundle is not valid, or what was read back is not a bundle this version understands.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    /// Sealing or unsealing failed: the blob was sealed on another machine, for another key, or has
    /// been altered.
    #[error("the credentials for '{key}' could not be unsealed: {reason}")]
    Seal { key: String, reason: String },
    /// The blob could not be read, written or removed.
    #[error("the credentials for '{key}' could not be stored: {reason}")]
    Storage { key: String, reason: String },
}

/// The name a bundle is stored under: the validated form of a `CredentialRef`.
///
/// 1 to 80 of `a-z`, `0-9` and `-`, neither starting nor ending with `-`. Nothing else is accepted,
/// so a key can never carry a path separator, a drive, a stream (`:`), a dot or a space into a file
/// name, whatever a configuration file or a client says.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey(String);

impl SecretKey {
    pub fn for_endpoint(id: EndpointId) -> Self {
        Self(format!("endpoint-{id}"))
    }

    pub fn parse(reference: &CredentialRef) -> Result<Self, SecretStoreError> {
        let key = reference.store_key();
        let chars_ok = key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if key.is_empty() {
            Err(SecretStoreError::InvalidKey("it is empty"))
        } else if key.len() > MAX_KEY_LEN {
            Err(SecretStoreError::InvalidKey(
                "it is longer than 80 characters",
            ))
        } else if !chars_ok {
            Err(SecretStoreError::InvalidKey(
                "it may contain only a-z, 0-9 and '-'",
            ))
        } else if key.starts_with('-') || key.ends_with('-') {
            Err(SecretStoreError::InvalidKey(
                "it may not start or end with '-'",
            ))
        } else {
            Ok(Self(key.to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The reference to put on an `Endpoint`.
    pub fn credential_ref(&self) -> CredentialRef {
        CredentialRef::new(self.0.clone())
    }

    /// The blob's name. The `secret-` prefix keeps a key such as `con` or `nul` from naming a
    /// Windows device (`con.bin` is the console).
    fn blob_name(&self) -> String {
        format!("secret-{}.bin", self.0)
    }

    /// What the sealer binds the blob to, so it opens only under this key.
    fn seal_context(&self) -> Vec<u8> {
        format!("dnet-engine/secret/v1/{}", self.0).into_bytes()
    }
}

/// Resolves a `CredentialRef` to credentials and keeps them at rest.
pub trait SecretStore: Send + Sync {
    /// Store `credentials` under `key`, replacing any earlier set. Refuses an empty or invalid set.
    fn put(
        &self,
        key: &SecretKey,
        credentials: &EndpointCredentials,
    ) -> Result<(), SecretStoreError>;
    /// The credentials under `key`, or `None` if there are none.
    fn get(&self, key: &SecretKey) -> Result<Option<EndpointCredentials>, SecretStoreError>;
    /// Forget the credentials under `key`. `Ok(false)` if there were none.
    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError>;
}

/// Protects bytes so they are useless anywhere but here. `context` binds the result to a purpose:
/// what was sealed for one context must not open under another.
pub trait Sealer: Send + Sync {
    fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, String>;
    fn unseal(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, String>;
}

/// Holds sealed bytes by name. A name is always one produced by [`SecretKey`], never free text.
pub trait BlobStorage: Send + Sync {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String>;
    fn remove(&self, name: &str) -> Result<bool, String>;
}

/// Best-effort overwrite of plaintext that held credentials, so it does not linger in freed memory.
/// The compiler may not elide volatile writes. It cannot reach copies the allocator or the OS made.
fn wipe(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A store that seals each bundle and keeps it in a [`BlobStorage`].
pub struct SealedSecretStore {
    sealer: Box<dyn Sealer>,
    blobs: Box<dyn BlobStorage>,
}

impl SealedSecretStore {
    pub fn new(sealer: Box<dyn Sealer>, blobs: Box<dyn BlobStorage>) -> Self {
        Self { sealer, blobs }
    }

    fn storage_error(key: &SecretKey, reason: String) -> SecretStoreError {
        SecretStoreError::Storage {
            key: key.as_str().to_owned(),
            reason,
        }
    }
}

impl SecretStore for SealedSecretStore {
    fn put(
        &self,
        key: &SecretKey,
        credentials: &EndpointCredentials,
    ) -> Result<(), SecretStoreError> {
        if credentials.is_empty() {
            return Err(SecretStoreError::Empty);
        }
        let mut plaintext = credentials.to_plaintext_json()?;
        let sealed = self.sealer.seal(&plaintext, &key.seal_context());
        wipe(&mut plaintext);
        let sealed = sealed.map_err(|reason| SecretStoreError::Seal {
            key: key.as_str().to_owned(),
            reason,
        })?;
        self.blobs
            .write(&key.blob_name(), &sealed)
            .map_err(|reason| Self::storage_error(key, reason))
    }

    fn get(&self, key: &SecretKey) -> Result<Option<EndpointCredentials>, SecretStoreError> {
        let Some(sealed) = self
            .blobs
            .read(&key.blob_name())
            .map_err(|reason| Self::storage_error(key, reason))?
        else {
            return Ok(None);
        };
        let mut plaintext = self
            .sealer
            .unseal(&sealed, &key.seal_context())
            .map_err(|reason| SecretStoreError::Seal {
                key: key.as_str().to_owned(),
                reason,
            })?;
        let decoded = EndpointCredentials::from_plaintext_json(&plaintext);
        wipe(&mut plaintext);
        Ok(Some(decoded?))
    }

    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError> {
        self.blobs
            .remove(&key.blob_name())
            .map_err(|reason| Self::storage_error(key, reason))
    }
}

/// A store that keeps the bundles in memory, **unsealed**. For tests and tools; it never touches a
/// disk, and nothing in the service uses it.
#[derive(Default)]
pub struct MemorySecretStore {
    entries: Mutex<HashMap<String, EndpointCredentials>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bundles are held. A store has no listing on purpose, but a test of a rollback has
    /// to be able to see that nothing was left behind.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl SecretStore for MemorySecretStore {
    fn put(
        &self,
        key: &SecretKey,
        credentials: &EndpointCredentials,
    ) -> Result<(), SecretStoreError> {
        if credentials.is_empty() {
            return Err(SecretStoreError::Empty);
        }
        // Same rules as the sealed store, so a test double cannot accept what production refuses.
        credentials.to_plaintext_json().map(|mut p| wipe(&mut p))?;
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.as_str().to_owned(), credentials.clone());
        Ok(())
    }

    fn get(&self, key: &SecretKey) -> Result<Option<EndpointCredentials>, SecretStoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key.as_str())
            .cloned())
    }

    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key.as_str())
            .is_some())
    }
}

/// Blobs in memory. For tests.
#[derive(Default)]
pub struct MemoryBlobs {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every stored blob, for tests that scan what was written.
    pub fn all(&self) -> Vec<(String, Vec<u8>)> {
        let guard = self
            .blobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl BlobStorage for MemoryBlobs {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .blobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.blobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }
    fn remove(&self, name: &str) -> Result<bool, String> {
        Ok(self
            .blobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(name)
            .is_some())
    }
}

/// A shared handle to storage is storage, so a test can keep one end and give the other to a store.
impl<T: BlobStorage + ?Sized> BlobStorage for std::sync::Arc<T> {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        (**self).read(name)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        (**self).write(name, bytes)
    }
    fn remove(&self, name: &str) -> Result<bool, String> {
        (**self).remove(name)
    }
}

#[cfg(windows)]
pub use windows_impl::{machine_secret_store, DpapiSealer, TrustedDirBlobs};

#[cfg(windows)]
mod windows_impl {
    //! DPAPI machine-scope sealing, and blobs in a directory only SYSTEM and Administrators control.

    use std::path::PathBuf;

    use windows::core::w;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::{wipe, BlobStorage, SealedSecretStore, Sealer};
    use crate::trusted_file::TrustedFile;

    /// DPAPI in machine scope: any process on this machine can unseal what the service sealed, so
    /// the protection is the restricted directory plus the blob being useless off this machine.
    /// The `context` is DPAPI's optional entropy, so a blob opens only for the key it was sealed for.
    pub struct DpapiSealer;

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
    unsafe fn take_output(out: CRYPT_INTEGER_BLOB, secret: bool) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        let view = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let copy = view.to_vec();
        if secret {
            wipe(view);
        }
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        copy
    }

    impl Sealer for DpapiSealer {
        fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            let input = blob_over(plaintext);
            let entropy = blob_over(context);
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: both input blobs point at live slices for the call; `out` is a valid
            // destination whose buffer `take_output` frees.
            unsafe {
                CryptProtectData(
                    &input,
                    w!("DNet Engine"),
                    Some(&entropy),
                    None,
                    None,
                    CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
                .map_err(|e| format!("DPAPI could not seal the credentials ({e})"))?;
                Ok(take_output(out, false))
            }
        }

        fn unseal(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            let input = blob_over(sealed);
            let entropy = blob_over(context);
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: as for `seal`; the output holds plaintext, which `take_output` wipes.
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
                .map_err(|_| {
                    "it was sealed on another machine or for another key, or it has been altered"
                        .to_string()
                })?;
                Ok(take_output(out, true))
            }
        }
    }

    /// Blobs under one directory, each a [`TrustedFile`]: written restricted to SYSTEM and
    /// Administrators, and refused on read unless the file and its directory are theirs.
    pub struct TrustedDirBlobs {
        dir: PathBuf,
    }

    impl TrustedDirBlobs {
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            Self { dir: dir.into() }
        }

        fn file(&self, name: &str) -> Result<TrustedFile, String> {
            // Names come from `SecretKey`; this is the second line of defence at the filesystem.
            let ok = name.starts_with("secret-")
                && name.ends_with(".bin")
                && name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                });
            if !ok || name.contains("..") {
                return Err("not a secret blob name".to_string());
            }
            Ok(TrustedFile::new(self.dir.join(name)))
        }
    }

    impl BlobStorage for TrustedDirBlobs {
        fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            self.file(name)?.read().map_err(|e| e.to_string())
        }
        fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
            self.file(name)?.write(bytes).map_err(|e| e.to_string())
        }
        fn remove(&self, name: &str) -> Result<bool, String> {
            self.file(name)?.remove().map_err(|e| e.to_string())
        }
    }

    /// The production store: DPAPI machine scope, blobs under `dir`
    /// (`%PROGRAMDATA%\DNet Engine\state\secrets`).
    pub fn machine_secret_store(dir: impl Into<PathBuf>) -> SealedSecretStore {
        SealedSecretStore::new(Box::new(DpapiSealer), Box::new(TrustedDirBlobs::new(dir)))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::amneziawg::{ObfuscationParams, PrivateKey};
    use crate::credentials::AmneziaWgCredentials;
    use crate::credentials::Hysteria2Bundle;
    use crate::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
    use crate::secret::Secret;
    use crate::tls::ServerTrust;

    const SENTINEL: &str = "SENTINEL-5e1c0a77b2";

    fn bundle() -> EndpointCredentials {
        EndpointCredentials {
            amneziawg: Some(AmneziaWgCredentials {
                client_private_key: PrivateKey::new(format!("{:0>64}", "ab")),
                server_public_key: format!("{:0>64}", "cd"),
                client_address: Ipv4Addr::new(10, 66, 0, 2),
                prefix_len: 24,
                obfuscation: ObfuscationParams {
                    jc: 4,
                    jmin: 40,
                    jmax: 70,
                    s1: 15,
                    s2: 20,
                    h1: 1,
                    h2: 2,
                    h3: 3,
                    h4: 4,
                },
                server_port: 51820,
            }),
            hysteria2: Some(Hysteria2Bundle {
                server_port: 44443,
                credentials: Hysteria2Credentials {
                    auth_password: Secret::new(format!("auth-{SENTINEL}")),
                    obfs_password: Secret::new(format!("obfs-{SENTINEL}")),
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PublicCa {
                        server_name: "vpn.example.com".into(),
                    },
                },
            }),
            reality: None,
            measure_origin: None,
        }
    }

    fn key(name: &str) -> SecretKey {
        SecretKey::parse(&CredentialRef::new(name)).unwrap()
    }

    // ---------------------------------------------------------------- keys

    #[test]
    fn a_key_is_a_short_lowercase_slug() {
        let id = EndpointId::new();
        let k = SecretKey::for_endpoint(id);
        assert_eq!(k.as_str(), format!("endpoint-{id}"));
        assert_eq!(SecretKey::parse(&k.credential_ref()).unwrap(), k);
        for ok in ["a", "endpoint-1", "0", "a-b-c", &"a".repeat(80)] {
            assert!(SecretKey::parse(&CredentialRef::new(ok)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn a_key_that_could_name_something_else_is_refused() {
        let too_long = "a".repeat(81);
        for bad in [
            "",
            "-a",
            "a-",
            "A",
            "a b",
            "a/b",
            "a\\b",
            "..",
            "a..b",
            "a.b",
            "a:b",
            "dpapi:oracle-mumbai",
            "C:\\x",
            "a\0b",
            "a\nb",
            "ünï",
            "a~1",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    SecretKey::parse(&CredentialRef::new(bad)),
                    Err(SecretStoreError::InvalidKey(_))
                ),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_reserved_device_name_cannot_become_a_file_name() {
        // `con.bin` is the Windows console; the prefix makes every key an ordinary file name.
        for reserved in ["con", "nul", "prn", "aux", "com1", "lpt1"] {
            let name = key(reserved).blob_name();
            assert!(
                name.starts_with("secret-") && name.ends_with(".bin"),
                "{name}"
            );
        }
    }

    // ---------------------------------------------------------------- the sealed store, with a test sealer

    /// Not cryptography: a reversible scramble bound to the context, so the store's logic (and
    /// what ends up in storage) can be tested anywhere.
    struct TestSealer;

    impl TestSealer {
        fn tag(context: &[u8]) -> [u8; 8] {
            let mut tag = [0u8; 8];
            for (i, b) in context.iter().enumerate() {
                tag[i % 8] = tag[i % 8].wrapping_mul(31).wrapping_add(*b);
            }
            tag
        }
    }

    impl Sealer for TestSealer {
        fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = Self::tag(context).to_vec();
            out.extend(plaintext.iter().map(|b| b ^ 0x5A));
            Ok(out)
        }
        fn unseal(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            if sealed.len() < 8 || sealed[..8] != Self::tag(context) {
                return Err("it was sealed for another key, or it has been altered".into());
            }
            Ok(sealed[8..].iter().map(|b| b ^ 0x5A).collect())
        }
    }

    fn sealed_store() -> (SealedSecretStore, Arc<MemoryBlobs>) {
        let blobs = Arc::new(MemoryBlobs::new());
        (
            SealedSecretStore::new(Box::new(TestSealer), Box::new(Arc::clone(&blobs))),
            blobs,
        )
    }

    #[test]
    fn put_get_delete_round_trip() {
        let (store, _) = sealed_store();
        let k = key("endpoint-one");
        assert_eq!(store.get(&k).unwrap(), None);
        store.put(&k, &bundle()).unwrap();
        assert_eq!(store.get(&k).unwrap(), Some(bundle()));
        assert_eq!(store.delete(&k), Ok(true));
        assert_eq!(store.get(&k).unwrap(), None);
        assert_eq!(store.delete(&k), Ok(false));
    }

    #[test]
    fn put_replaces_the_earlier_set() {
        let (store, _) = sealed_store();
        let k = key("endpoint-one");
        store.put(&k, &bundle()).unwrap();
        let mut changed = bundle();
        changed.hysteria2 = None;
        store.put(&k, &changed).unwrap();
        assert_eq!(store.get(&k).unwrap(), Some(changed));
    }

    #[test]
    fn an_empty_set_is_refused() {
        let (store, blobs) = sealed_store();
        assert_eq!(
            store.put(&key("endpoint-one"), &EndpointCredentials::default()),
            Err(SecretStoreError::Empty)
        );
        assert!(blobs.all().is_empty());
    }

    #[test]
    fn an_invalid_set_is_refused_and_nothing_is_stored() {
        let (store, blobs) = sealed_store();
        let mut bad = bundle();
        bad.amneziawg.as_mut().unwrap().prefix_len = 0;
        assert!(matches!(
            store.put(&key("endpoint-one"), &bad),
            Err(SecretStoreError::Credentials(_))
        ));
        assert!(blobs.all().is_empty());
    }

    #[test]
    fn what_reaches_storage_is_not_the_plaintext() {
        let (store, blobs) = sealed_store();
        store.put(&key("endpoint-one"), &bundle()).unwrap();
        let stored = blobs.all();
        assert_eq!(stored.len(), 1);
        let (name, bytes) = &stored[0];
        assert_eq!(name, "secret-endpoint-one.bin");
        let haystack = String::from_utf8_lossy(bytes);
        assert!(!haystack.contains(SENTINEL), "plaintext reached storage");
        assert!(!haystack.contains("auth-"), "plaintext reached storage");
        // The same scan on the plaintext finds it, so the check above is not vacuous.
        let plain = String::from_utf8(bundle().to_plaintext_json().unwrap()).unwrap();
        assert!(plain.contains(SENTINEL));
    }

    #[test]
    fn a_blob_copied_under_another_key_does_not_open() {
        let (store, blobs) = sealed_store();
        store.put(&key("endpoint-a"), &bundle()).unwrap();
        let (_, bytes) = blobs.all().remove(0);
        blobs.write("secret-endpoint-b.bin", &bytes).unwrap();

        let err = store.get(&key("endpoint-b")).unwrap_err();

        assert!(matches!(err, SecretStoreError::Seal { .. }), "{err:?}");
        assert!(!err.to_string().contains(SENTINEL));
        // The original still opens.
        assert_eq!(store.get(&key("endpoint-a")).unwrap(), Some(bundle()));
    }

    #[test]
    fn a_damaged_blob_is_an_error_not_a_panic_or_partial_material() {
        let (store, blobs) = sealed_store();
        let k = key("endpoint-one");
        store.put(&k, &bundle()).unwrap();
        let (name, bytes) = blobs.all().remove(0);

        for damaged in [
            Vec::new(),
            vec![0u8; 3],
            bytes[..bytes.len() / 2].to_vec(),
            {
                let mut flipped = bytes.clone();
                flipped[0] ^= 0xFF; // the tag
                flipped
            },
            {
                let mut flipped = bytes.clone();
                let last = flipped.len() - 1;
                flipped[last] ^= 0xFF; // the tail of the payload
                flipped
            },
        ] {
            blobs.write(&name, &damaged).unwrap();
            assert!(store.get(&k).is_err(), "a damaged blob must not open");
        }
    }

    #[test]
    fn a_storage_failure_names_the_key_and_the_reason_only() {
        struct Failing;
        impl BlobStorage for Failing {
            fn read(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
                Err("disk on fire".into())
            }
            fn write(&self, _: &str, _: &[u8]) -> Result<(), String> {
                Err("disk on fire".into())
            }
            fn remove(&self, _: &str) -> Result<bool, String> {
                Err("disk on fire".into())
            }
        }
        let store = SealedSecretStore::new(Box::new(TestSealer), Box::new(Failing));
        let k = key("endpoint-one");
        for err in [
            store.put(&k, &bundle()).unwrap_err(),
            store.get(&k).unwrap_err(),
            store.delete(&k).unwrap_err(),
        ] {
            let text = err.to_string();
            assert!(
                text.contains("endpoint-one") && text.contains("disk on fire"),
                "{text}"
            );
            assert!(!text.contains(SENTINEL));
        }
    }

    // ---------------------------------------------------------------- the in-memory double

    #[test]
    fn the_memory_store_applies_the_same_rules_as_the_sealed_one() {
        let store = MemorySecretStore::new();
        let k = key("endpoint-one");
        assert_eq!(store.get(&k).unwrap(), None);
        store.put(&k, &bundle()).unwrap();
        assert_eq!(store.get(&k).unwrap(), Some(bundle()));
        assert_eq!(
            store.put(&k, &EndpointCredentials::default()),
            Err(SecretStoreError::Empty)
        );
        let mut bad = bundle();
        bad.amneziawg.as_mut().unwrap().prefix_len = 0;
        assert!(
            store.put(&k, &bad).is_err(),
            "a double must not accept what production refuses"
        );
        assert_eq!(store.delete(&k), Ok(true));
        assert_eq!(store.delete(&k), Ok(false));
    }

    #[test]
    fn wipe_overwrites_every_byte() {
        let mut data = vec![0xAAu8; 37];
        wipe(&mut data);
        assert!(data.iter().all(|b| *b == 0));
    }

    // ---------------------------------------------------------------- DPAPI (Windows)

    #[cfg(windows)]
    mod dpapi {
        use super::*;
        use crate::secret_store::{DpapiSealer, TrustedDirBlobs};

        #[test]
        fn dpapi_seals_and_unseals_and_the_blob_is_not_the_plaintext() {
            let sealed = DpapiSealer.seal(SENTINEL.as_bytes(), b"ctx").unwrap();
            assert!(!String::from_utf8_lossy(&sealed).contains(SENTINEL));
            assert_eq!(
                DpapiSealer.unseal(&sealed, b"ctx").unwrap(),
                SENTINEL.as_bytes()
            );
        }

        #[test]
        fn dpapi_binds_a_blob_to_its_context() {
            let sealed = DpapiSealer.seal(b"payload", b"endpoint-a").unwrap();
            assert!(DpapiSealer.unseal(&sealed, b"endpoint-b").is_err());
            assert!(DpapiSealer.unseal(&sealed, b"").is_err());
        }

        #[test]
        fn dpapi_refuses_a_tampered_or_truncated_blob() {
            let sealed = DpapiSealer.seal(b"payload", b"ctx").unwrap();
            let mut flipped = sealed.clone();
            let mid = flipped.len() / 2;
            flipped[mid] ^= 0xFF;
            assert!(DpapiSealer.unseal(&flipped, b"ctx").is_err());
            assert!(DpapiSealer
                .unseal(&sealed[..sealed.len() - 4], b"ctx")
                .is_err());
            assert!(DpapiSealer.unseal(&[], b"ctx").is_err());
            assert!(DpapiSealer.unseal(&[1, 2, 3], b"ctx").is_err());
        }

        #[test]
        fn dpapi_handles_empty_and_large_payloads() {
            for size in [0usize, 1, 4096, 1 << 20] {
                let data = vec![0x42u8; size];
                let sealed = DpapiSealer.seal(&data, b"ctx").unwrap();
                assert_eq!(
                    DpapiSealer.unseal(&sealed, b"ctx").unwrap(),
                    data,
                    "size {size}"
                );
            }
        }

        /// The whole path with real DPAPI and an in-memory disk: what reaches storage is sealed.
        #[test]
        fn a_dpapi_store_keeps_no_plaintext_and_round_trips() {
            let blobs = Arc::new(MemoryBlobs::new());
            let store = SealedSecretStore::new(Box::new(DpapiSealer), Box::new(Arc::clone(&blobs)));
            let k = key("endpoint-one");
            store.put(&k, &bundle()).unwrap();

            for (_, bytes) in blobs.all() {
                let text = String::from_utf8_lossy(&bytes);
                for needle in [SENTINEL, "auth-", "obfs-", "vpn.example.com", "version"] {
                    assert!(!text.contains(needle), "{needle} reached storage in clear");
                }
            }
            assert_eq!(store.get(&k).unwrap(), Some(bundle()));

            // A blob moved under another key's name does not open.
            let (_, bytes) = blobs.all().remove(0);
            blobs.write("secret-endpoint-two.bin", &bytes).unwrap();
            assert!(matches!(
                store.get(&key("endpoint-two")),
                Err(SecretStoreError::Seal { .. })
            ));
        }

        #[test]
        fn the_blob_directory_refuses_any_name_that_is_not_a_secret_blob() {
            let dir = tempfile::tempdir().unwrap();
            let blobs = TrustedDirBlobs::new(dir.path());
            for bad in [
                "../secret-x.bin",
                "secret-x.bin\\..\\y",
                "secret-.bin.exe",
                "x.bin",
                "secret-X.bin",
                "secret-a b.bin",
                "secret-a..b.bin",
                "secret-a:b.bin",
                "",
            ] {
                assert!(blobs.read(bad).is_err(), "{bad:?}");
                assert!(blobs.write(bad, b"x").is_err(), "{bad:?}");
                assert!(blobs.remove(bad).is_err(), "{bad:?}");
            }
            assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        }

        #[test]
        fn a_missing_blob_reads_as_none() {
            let dir = tempfile::tempdir().unwrap();
            let blobs = TrustedDirBlobs::new(dir.path());
            assert_eq!(blobs.read("secret-nothing-here.bin"), Ok(None));
        }

        /// Real DPAPI, real restricted files. Elevated, because it restricts a directory to
        /// SYSTEM and Administrators.
        #[test]
        #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-config -- --ignored)"]
        fn the_machine_store_round_trips_through_restricted_files() {
            use crate::secret_store::machine_secret_store;
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("state").join("secrets");
            let store = machine_secret_store(&dir);
            let k = key("endpoint-one");

            store.put(&k, &bundle()).unwrap();

            let on_disk = std::fs::read(dir.join("secret-endpoint-one.bin")).unwrap();
            assert!(!String::from_utf8_lossy(&on_disk).contains(SENTINEL));
            assert_eq!(store.get(&k).unwrap(), Some(bundle()));
            assert_eq!(store.delete(&k), Ok(true));
            assert_eq!(store.get(&k).unwrap(), None);
        }
    }
}
