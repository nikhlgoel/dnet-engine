//! T124 — a state file that only SYSTEM and Administrators control.
//!
//! The undo journal (T037), the persisted configuration and the protected secrets (T124) all live
//! under `%PROGRAMDATA%\DNet Engine\state\` and all have the same threat: `%PROGRAMDATA%` lets any
//! user create a subdirectory, and the owner of a directory keeps the right to rewrite its DACL and
//! so to replace or delete what is inside. A file someone else planted there would be read by a
//! LocalSystem service. So a file is trusted only if
//!
//! - it is owned by SYSTEM or Administrators, and its DACL is protected and names nobody else; and
//! - its directory is owned by SYSTEM or Administrators.
//!
//! The file's security is read from the same handle the contents are read through, so it cannot be
//! swapped between the check and the read. Ownership of the directories above the state directory is
//! the installer's to establish (T114).
//!
//! Each write goes to a temporary file that is flushed to disk and renamed over the target, so a
//! crash leaves the old file or the new one, never a torn one.

#![cfg(windows)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::write::{self, win};

/// Why a trusted file could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedFileError {
    /// The operating system refused, or the path is unusable.
    #[error("{0}")]
    Io(String),
    /// The file or its directory is not controlled only by SYSTEM and Administrators. Nothing was
    /// read from it.
    #[error("{0}")]
    Untrusted(String),
}

/// Whether an owner-and-DACL SDDL string describes an object only SYSTEM and Administrators
/// control: owner `SY` or `BA`, a protected DACL, and every ACE naming one of those two.
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

/// One file under the protected state directory.
pub struct TrustedFile {
    path: PathBuf,
    dir_restricted: AtomicBool,
}

impl TrustedFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            dir_restricted: AtomicBool::new(false),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn io_error(&self, what: &str, e: impl std::fmt::Display) -> TrustedFileError {
        TrustedFileError::Io(format!("{what} {}: {e}", self.path.display()))
    }

    fn untrusted(&self, what: &Path, sddl: &str) -> TrustedFileError {
        TrustedFileError::Untrusted(format!(
            "refusing {}: not controlled only by SYSTEM and Administrators ({sddl})",
            what.display()
        ))
    }

    fn dir(&self) -> Result<&Path, TrustedFileError> {
        self.path
            .parent()
            .ok_or_else(|| self.io_error("no parent directory for", "invalid path"))
    }

    /// The directory's owner must be SYSTEM or Administrators: an owner keeps implicit rights to
    /// rewrite the DACL, and with it to replace or delete the file.
    fn check_dir_owner(&self) -> Result<(), TrustedFileError> {
        let dir = self.dir()?;
        let sddl = win::read_owner_and_dacl_sddl(dir)
            .map_err(|e| self.io_error("reading the security of the directory of", e))?;
        if !sddl.starts_with("O:SY") && !sddl.starts_with("O:BA") {
            return Err(self.untrusted(dir, &sddl));
        }
        Ok(())
    }

    /// The file's bytes, `None` if it does not exist, or `Untrusted` if it is not controlled only
    /// by SYSTEM and Administrators (in which case nothing is read from it).
    pub fn read(&self) -> Result<Option<Vec<u8>>, TrustedFileError> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.io_error("opening", e)),
        };
        // Check the security of the handle and read through the same handle, so the file cannot be
        // swapped between the check and the read.
        let sddl = win::read_owner_and_dacl_sddl_of(&file)
            .map_err(|e| self.io_error("reading the security of", e))?;
        if !is_trusted_sddl(&sddl) {
            return Err(self.untrusted(&self.path, &sddl));
        }
        self.check_dir_owner()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| self.io_error("reading", e))?;
        Ok(Some(bytes))
    }

    /// Replace the file with `contents`, restricted to SYSTEM and Administrators. The directory is
    /// created and restricted first, so the file inherits the restriction from the moment it exists,
    /// and a directory someone else pre-created is refused.
    pub fn write(&self, contents: &[u8]) -> Result<(), TrustedFileError> {
        self.prepare_dir()?;
        write_durably(&self.path, contents).map_err(|e| self.io_error("writing", e))?;
        win::apply_protected_dacl(&self.path, write::RUN_FILE_SDDL)
            .map_err(|e| self.io_error("restricting", e))
    }

    /// Delete the file. `Ok(false)` if it was not there. The directory is checked first, as for a
    /// write: deleting inside a directory someone else controls would prove nothing.
    pub fn remove(&self) -> Result<bool, TrustedFileError> {
        if !self.path.exists() {
            return Ok(false);
        }
        self.check_dir_owner()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(self.io_error("removing", e)),
        }
    }

    fn prepare_dir(&self) -> Result<(), TrustedFileError> {
        if self.dir_restricted.load(Ordering::SeqCst) {
            return Ok(());
        }
        let dir = self.dir()?;
        std::fs::create_dir_all(dir).map_err(|e| self.io_error("creating the directory of", e))?;
        // Restrict the directory first, so the file inherits the restriction on creation.
        win::apply_protected_dacl(dir, write::RUN_DIR_SDDL)
            .map_err(|e| self.io_error("restricting the directory of", e))?;
        self.check_dir_owner()?;
        self.dir_restricted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_system_or_administrator_owned_protected_files_are_trusted() {
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
    fn a_durable_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_durably(&path, b"first").unwrap();
        write_durably(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
    }

    #[test]
    fn a_missing_file_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = TrustedFile::new(dir.path().join("state").join("absent.json"));
        assert_eq!(file.read(), Ok(None));
    }

    #[test]
    fn a_file_anyone_can_write_is_refused_and_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"planted").unwrap();
        win::apply_protected_dacl(&path, "D:P(A;;FA;;;WD)").unwrap();

        let err = TrustedFile::new(&path).read().unwrap_err();

        assert!(matches!(err, TrustedFileError::Untrusted(_)), "{err:?}");
        assert!(err.to_string().contains("refusing"), "{err}");
        // Nothing of the planted contents may appear in the error.
        assert!(!err.to_string().contains("planted"));
    }

    #[test]
    fn removing_a_file_that_is_not_there_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = TrustedFile::new(dir.path().join("absent.bin"));
        assert_eq!(file.remove(), Ok(false));
    }

    /// Saving restricts the directory and file, and what was saved reads back as trusted.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-config -- --ignored)"]
    fn a_written_file_is_restricted_and_reads_back_and_can_be_removed() {
        let root = tempfile::tempdir().unwrap();
        let file = TrustedFile::new(root.path().join("state").join("config.json"));

        file.write(b"{\"v\":1}").unwrap();

        assert!(is_trusted_sddl(
            &win::read_owner_and_dacl_sddl(file.path()).unwrap()
        ));
        assert_eq!(file.read().unwrap().as_deref(), Some(&b"{\"v\":1}"[..]));
        assert_eq!(file.remove(), Ok(true));
        assert_eq!(file.read(), Ok(None));
    }
}
