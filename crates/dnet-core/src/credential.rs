//! A reference to secret material, never the material itself.
//!
//! `CredentialRef` is an opaque handle into a secret store. It exposes the store
//! *key* (which is not sensitive) but has **no accessor that returns plaintext**.
//! Only `dnet-provision` and `dnet-config` resolve a reference to real material, at
//! the system boundary; every other crate — including all of `dnet-core`, the IPC
//! layer, and the UI — handles references alone (data-model §1, Principle V).

/// An opaque handle identifying secret material held in the OS-protected store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialRef {
    store_key: String,
}

impl CredentialRef {
    /// Create a reference to the secret stored under `store_key`.
    ///
    /// `store_key` is an identifier (e.g. a DPAPI blob name), not the secret.
    pub fn new(store_key: impl Into<String>) -> Self {
        Self {
            store_key: store_key.into(),
        }
    }

    /// The store key. Deliberately the *only* accessor: there is no method that
    /// returns the underlying secret, so no `dnet-core` code path can leak it.
    pub fn store_key(&self) -> &str {
        &self.store_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_key_but_never_plaintext() {
        let cred = CredentialRef::new("dpapi:oracle-mumbai");
        assert_eq!(cred.store_key(), "dpapi:oracle-mumbai");
        // Compile-time guarantee: there is no `.secret()` / `.plaintext()` accessor.
        // If one were ever added, this comment and the review checklist should catch it.
    }
}
