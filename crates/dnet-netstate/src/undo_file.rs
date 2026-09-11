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

#![cfg(windows)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use dnet_config::write::{self, win};

use crate::error::NetstateError;
use crate::undo::{UndoJournal, UndoStore};

/// Where `dnetd` keeps the journal: `%PROGRAMDATA%\DNet Engine\state\undo.json`.
pub fn default_journal_path() -> PathBuf {
    write::default_run_dir()
        .with_file_name("state")
        .join("undo.json")
}

/// Whether an owner-and-DACL SDDL string describes an object only SYSTEM and
/// Administrators control: owner `SY` or `BA`, a protected DACL, and every ACE naming one
/// of those two.
pub fn is_trusted_sddl(sddl: &str) -> bool {
    let Some(rest) = sddl.strip_prefix("O:") else {
        return false;
    };
    let Some((owner, dacl)) = rest.split_once("D:") else {
        return false;
    };
    if !matches!(owner, "SY" | "BA") {
        return false;
    }
    // Flags precede the first ACE; `P` (protected) must be among them.
    let Some((flags, aces)) = dacl.split_once('(') else {
        return false;
    };
    if !flags.contains('P') {
        return false;
    }
    // `aces` is `A;;FA;;;SY)(A;;FA;;;BA)`: the trustee is each ACE's last field.
    aces.split(')')
        .map(|ace| ace.trim_start_matches('('))
        .filter(|ace| !ace.is_empty())
        .all(|ace| ace.ends_with(";;;SY") || ace.ends_with(";;;BA"))
}

/// Replace `path` with `contents` so a crash leaves the old file or the new one intact.
pub fn write_durably(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// The journal file store.
pub struct FileStore {
    path: PathBuf,
    dir_restricted: AtomicBool,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            dir_restricted: AtomicBool::new(false),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn journal_error(&self, what: &str, e: impl std::fmt::Display) -> NetstateError {
        NetstateError::Journal(format!("{what} {}: {e}", self.path.display()))
    }
}

impl FileStore {
    fn dir(&self) -> Result<&Path, NetstateError> {
        self.path
            .parent()
            .ok_or_else(|| self.journal_error("no parent directory for", "invalid path"))
    }

    fn untrusted(&self, what: &Path, sddl: &str) -> NetstateError {
        NetstateError::Journal(format!(
            "refusing {}: not controlled only by SYSTEM and Administrators ({sddl})",
            what.display()
        ))
    }

    /// The directory's owner must be SYSTEM or Administrators: an owner keeps implicit
    /// rights to rewrite the DACL, and with it to replace or delete the journal.
    fn check_dir_owner(&self) -> Result<(), NetstateError> {
        let dir = self.dir()?;
        let sddl = win::read_owner_and_dacl_sddl(dir)
            .map_err(|e| self.journal_error("reading the security of the directory of", e))?;
        if !sddl.starts_with("O:SY") && !sddl.starts_with("O:BA") {
            return Err(self.untrusted(dir, &sddl));
        }
        Ok(())
    }
}

impl UndoStore for FileStore {
    fn load(&self) -> Result<UndoJournal, NetstateError> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(UndoJournal::default()),
            Err(e) => return Err(self.journal_error("opening", e)),
        };
        // Check the security of the handle and read through the same handle, so the file
        // cannot be swapped between the check and the read.
        let sddl = win::read_owner_and_dacl_sddl_of(&file)
            .map_err(|e| self.journal_error("reading the security of", e))?;
        if !is_trusted_sddl(&sddl) {
            return Err(self.untrusted(&self.path, &sddl));
        }
        self.check_dir_owner()?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)
            .map_err(|e| self.journal_error("reading", e))?;
        UndoJournal::from_json(&bytes)
    }

    fn save(&self, journal: &UndoJournal) -> Result<(), NetstateError> {
        if !self.dir_restricted.load(Ordering::SeqCst) {
            let dir = self.dir()?;
            std::fs::create_dir_all(dir)
                .map_err(|e| self.journal_error("creating the directory of", e))?;
            // Restrict the directory first, so the file inherits the restriction on creation.
            win::apply_protected_dacl(dir, write::RUN_DIR_SDDL)
                .map_err(|e| self.journal_error("restricting the directory of", e))?;
            // Refuse a directory someone else pre-created: without a durable record, no
            // mutation happens (UndoRegistry::apply), which is the safe failure.
            self.check_dir_owner()?;
            self.dir_restricted.store(true, Ordering::SeqCst);
        }
        write_durably(&self.path, &journal.to_json())
            .map_err(|e| self.journal_error("writing", e))?;
        win::apply_protected_dacl(&self.path, write::RUN_FILE_SDDL)
            .map_err(|e| self.journal_error("restricting", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_system_or_administrator_owned_protected_journals_are_trusted() {
        for trusted in [
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:P(A;;FA;;;BA)",
        ] {
            assert!(is_trusted_sddl(trusted), "should trust {trusted}");
        }
        for untrusted in [
            // owned by an ordinary user: they keep implicit rights to change the DACL
            "O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)(A;;FA;;;BA)",
            // not protected: inheritable grants from the parent could apply
            "O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAD:AI(A;;FA;;;SY)(A;;FA;;;BA)",
            // someone else has access
            "O:BAD:P(A;;FA;;;SY)(A;;FR;;;BU)",
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;WD)",
            // an empty DACL grants nothing but proves nothing either; a NULL DACL grants all
            "O:BAD:P",
            "O:BAD:NO_ACCESS_CONTROL",
            "D:P(A;;FA;;;SY)",
            "",
        ] {
            assert!(!is_trusted_sddl(untrusted), "should refuse {untrusted}");
        }
    }

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
    fn a_durable_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undo.json");
        write_durably(&path, b"first").unwrap();
        write_durably(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("undo.json")]);
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
