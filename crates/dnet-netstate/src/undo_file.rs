//! T037 (OS half) — the durable undo journal on disk.
//!
//! `%PROGRAMDATA%\DNet Engine\state\undo.json`, restricted to SYSTEM and Administrators.
//!
//! **The journal is an instruction list replayed by LocalSystem**, so it is only trusted if
//! it is owned by SYSTEM or Administrators and nobody else holds any access to it. The
//! owner check matters because `%PROGRAMDATA%` lets any user create a subdirectory: someone
//! who pre-creates the directory keeps implicit rights to it and could plant a journal
//! there. A file they plant is owned by them, and is refused.
//!
//! The journal's directory must also be owned by SYSTEM or Administrators, since a
//! directory owner can always regain the right to replace or delete what is inside.
//! Ownership of the directories above it is the installer's to establish (T114).
//!
//! Each write goes to a temporary file that is flushed to disk and then renamed over the
//! journal, so a crash leaves either the old journal or the new one, never a torn one.
//!
//! These rules are not specific to the journal: the persisted configuration and the protected
//! secrets (T124) need the same ones, so they live in `dnet_config::trusted_file`, and this store
//! is that file holding a journal.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use dnet_config::trusted_file::TrustedFile;
use dnet_config::write;

use crate::error::NetstateError;
use crate::undo::{UndoJournal, UndoStore};

// Kept under their original names for the callers and tests that already use them.
pub use dnet_config::trusted_file::{is_trusted_sddl, write_durably};

/// Where `dnetd` keeps the journal: `%PROGRAMDATA%\DNet Engine\state\undo.json`.
pub fn default_journal_path() -> PathBuf {
    write::default_run_dir()
        .with_file_name("state")
        .join("undo.json")
}

/// The journal file store.
pub struct FileStore {
    file: TrustedFile,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file: TrustedFile::new(path),
        }
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

fn journal_error(e: impl std::fmt::Display) -> NetstateError {
    NetstateError::Journal(e.to_string())
}

impl UndoStore for FileStore {
    fn load(&self) -> Result<UndoJournal, NetstateError> {
        match self.file.read().map_err(journal_error)? {
            None => Ok(UndoJournal::default()),
            Some(bytes) => UndoJournal::from_json(&bytes),
        }
    }

    fn save(&self, journal: &UndoJournal) -> Result<(), NetstateError> {
        self.file.write(&journal.to_json()).map_err(journal_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_config::write::win;

    #[test]
    fn a_missing_journal_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("state").join("undo.json"));
        assert_eq!(store.load().unwrap(), UndoJournal::default());
    }

    #[test]
    fn a_journal_anyone_can_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undo.json");
        std::fs::write(&path, UndoJournal::default().to_json()).unwrap();
        win::apply_protected_dacl(&path, "D:P(A;;FA;;;WD)").unwrap();

        let err = FileStore::new(&path).load().unwrap_err();

        assert!(err.to_string().contains("refusing"), "{err}");
        // Relax so the tempdir can be removed.
        win::apply_protected_dacl(&path, "D:P(A;;FA;;;WD)").unwrap();
    }

    #[test]
    fn the_default_journal_is_beside_the_run_directory() {
        assert!(default_journal_path().ends_with(r"DNet Engine\state\undo.json"));
    }

    /// Saving restricts the directory and file, and what was saved loads back as trusted.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn a_saved_journal_is_restricted_and_loads_back() {
        use crate::undo::{Mutation, UndoRecord, UndoRegistry};
        use std::net::{IpAddr, Ipv4Addr};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state").join("undo.json");
        let record = UndoRecord::HostRoute {
            interface_luid: 17,
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let registry = UndoRegistry::open(Box::new(FileStore::new(&path))).unwrap();
        registry
            .apply(record.clone(), || Ok(Mutation::Applied))
            .unwrap();
        drop(registry);

        assert!(is_trusted_sddl(
            &win::read_owner_and_dacl_sddl(&path).unwrap()
        ));
        let reopened = UndoRegistry::open(Box::new(FileStore::new(&path))).unwrap();
        assert_eq!(reopened.outstanding()[0].record, record);
    }
}
