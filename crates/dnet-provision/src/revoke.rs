// SPDX-License-Identifier: GPL-3.0-or-later
//! T096 — what happens to the cloud credential when provisioning is over (PR-05, research R10).
//!
//! The credential was only ever needed to create the endpoint. Keeping it afterwards keeps a key that can
//! create billable resources on the person's machine for no reason, so once provisioning has succeeded the
//! wizard offers to delete it, and **the default is to delete**. Keeping it is possible, but it is a
//! choice, not what happens when someone clicks through.
//!
//! What this removes is the *stored copy*. The key still exists in the person's cloud account until they
//! delete it there; [`REMINDER`] says so, because "deleted" must not be read as "revoked".

use crate::secret::{CredentialVault, VaultError};

/// What to do with the stored credential. `Delete` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disposition {
    #[default]
    Delete,
    Keep,
}

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    /// Whether the stored copy was removed (it is `false` when the person chose to keep it, and when there
    /// was nothing stored).
    pub deleted: bool,
}

/// Shown after the credential is deleted: the stored copy is gone, the key in the account is not.
pub const REMINDER: &str = "The key has been removed from this computer. It still exists in your cloud account until you delete it there; delete it there too if you no longer need it.";

/// Apply `choice` to the credential stored under `name`.
pub fn finish(
    vault: &dyn CredentialVault,
    name: &str,
    choice: Disposition,
) -> Result<Finished, VaultError> {
    match choice {
        Disposition::Keep => Ok(Finished { deleted: false }),
        Disposition::Delete => Ok(Finished {
            deleted: vault.delete(name)?,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{MemoryVault, Secret};

    fn vault_with(name: &str) -> MemoryVault {
        let vault = MemoryVault::new();
        vault
            .put(name, &Secret::new("SENTINEL-credential"))
            .unwrap();
        vault
    }

    #[test]
    fn deleting_is_what_happens_by_default() {
        assert_eq!(Disposition::default(), Disposition::Delete);
        let vault = vault_with("oracle");
        let done = finish(&vault, "oracle", Disposition::default()).unwrap();
        assert!(done.deleted);
        assert_eq!(vault.get("oracle").unwrap(), None);
    }

    #[test]
    fn keeping_it_is_a_choice_that_leaves_it_alone() {
        let vault = vault_with("oracle");
        let done = finish(&vault, "oracle", Disposition::Keep).unwrap();
        assert!(!done.deleted);
        assert!(vault.get("oracle").unwrap().is_some());
    }

    #[test]
    fn deleting_what_is_not_there_is_fine_and_says_so() {
        let vault = MemoryVault::new();
        assert_eq!(
            finish(&vault, "oracle", Disposition::Delete),
            Ok(Finished { deleted: false })
        );
    }

    #[test]
    fn a_bad_name_is_an_error_not_a_silent_success() {
        let vault = MemoryVault::new();
        assert_eq!(
            finish(&vault, "../x", Disposition::Delete),
            Err(VaultError::InvalidName)
        );
    }

    #[test]
    fn the_reminder_says_the_key_still_exists_in_the_account() {
        assert!(REMINDER.contains("still exists in your cloud account"));
        assert!(!REMINDER.contains("SENTINEL"));
    }
}
