//! T049 — writing generated configuration with a restricted ACL (CC-08, FR-035).
//!
//! The generated primary-core configuration lives under
//! `%PROGRAMDATA%\DNet Engine\run\` and must be readable only by SYSTEM and
//! Administrators. The run **directory** gets a protected, inheritable DACL *before* any
//! file is written into it, so a new file inherits the restriction from the moment it
//! exists — there is no window in which it carries a broader ACL. Each file is then
//! written to a temporary name, renamed into place, and given an explicit protected DACL.

#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

/// Protected, inheritable: SYSTEM and Administrators full control; nothing inherited
/// from the parent, and child objects receive the same two ACEs.
pub const RUN_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Protected: SYSTEM and Administrators full control, nothing else.
pub const RUN_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// The run directory: `%PROGRAMDATA%\DNet Engine\run`.
pub fn default_run_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("DNet Engine").join("run")
}

/// Write `contents` to `dir/file_name` with the SYSTEM + Administrators ACL, returning
/// the final path. Requires the privilege to set a DACL on `dir` (LocalSystem or an
/// elevated Administrator).
#[cfg(windows)]
pub fn write_restricted(dir: &Path, file_name: &str, contents: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    // Restrict the directory first, so the file inherits the restriction on creation.
    win::apply_protected_dacl(dir, RUN_DIR_SDDL)?;

    let final_path = dir.join(file_name);
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, &final_path)?;
    win::apply_protected_dacl(&final_path, RUN_FILE_SDDL)?;
    Ok(final_path)
}

#[cfg(windows)]
pub mod win {
    //! Setting and reading a path's DACL from SDDL.

    use std::io;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, BOOL, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        GetSecurityInfo, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Replace `path`'s DACL with the one described by `sddl`, marked protected so no
    /// ACEs are inherited from the parent.
    pub fn apply_protected_dacl(path: &Path, sddl: &str) -> io::Result<()> {
        let sddl_w = wide(sddl);
        let path_w = wide_path(path);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `sddl_w` is NUL-terminated and outlives the call; `descriptor` is a
        // valid out-pointer, LocalAlloc'd on success and freed below on every path.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(|e| io::Error::other(e.to_string()))?;
        }

        let result = (|| {
            let mut present = BOOL::default();
            let mut defaulted = BOOL::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            // SAFETY: `descriptor` is a valid self-relative descriptor from the call
            // above; `dacl` points into it and is only used while it is alive.
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
            // SAFETY: `path_w` is NUL-terminated; `dacl` is valid for the call. Owner and
            // group are left unchanged (null PSIDs with no OWNER/GROUP info flags).
            let status = unsafe {
                SetNamedSecurityInfoW(
                    PCWSTR(path_w.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    PSID::default(),
                    PSID::default(),
                    Some(dacl as *const ACL),
                    None,
                )
            };
            if status.is_err() {
                return Err(io::Error::from_raw_os_error(status.0 as i32));
            }
            Ok(())
        })();

        // SAFETY: `descriptor` was allocated by ConvertStringSecurityDescriptor... above.
        unsafe {
            let _ = LocalFree(HLOCAL(descriptor.0));
        }
        result
    }

    /// Read `path`'s DACL back as SDDL (for verification).
    pub fn read_dacl_sddl(path: &Path) -> io::Result<String> {
        read_sddl(path, DACL_SECURITY_INFORMATION)
    }

    /// Read `path`'s owner and DACL as SDDL, e.g. `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`.
    pub fn read_owner_and_dacl_sddl(path: &Path) -> io::Result<String> {
        read_sddl(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
    }

    /// Read an open file's owner and DACL as SDDL. Checking the handle, then reading through
    /// the same handle, cannot be raced by swapping the file at its path in between.
    pub fn read_owner_and_dacl_sddl_of(file: &std::fs::File) -> io::Result<String> {
        use std::os::windows::io::AsRawHandle;
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the handle is open for the lifetime of `file`, which outlives the call;
        // `descriptor` receives a LocalAlloc'd buffer freed by `descriptor_to_sddl`.
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                info,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        descriptor_to_sddl(descriptor, info)
    }

    fn read_sddl(path: &Path, info: OBJECT_SECURITY_INFORMATION) -> io::Result<String> {
        let path_w = wide_path(path);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `path_w` is NUL-terminated; `descriptor` receives a LocalAlloc'd
        // buffer freed by `descriptor_to_sddl`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                info,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        descriptor_to_sddl(descriptor, info)
    }

    /// Convert and free a LocalAlloc'd security descriptor.
    fn descriptor_to_sddl(
        descriptor: PSECURITY_DESCRIPTOR,
        info: OBJECT_SECURITY_INFORMATION,
    ) -> io::Result<String> {
        let mut text = PWSTR::null();
        // SAFETY: `descriptor` is valid; `text` receives a LocalAlloc'd string.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                info,
                &mut text,
                None,
            )
        };
        let sddl = converted
            .map_err(|e| io::Error::other(e.to_string()))
            // SAFETY: on success `text` is a valid NUL-terminated UTF-16 string.
            .and_then(|()| unsafe { text.to_string() }.map_err(io::Error::other));

        // SAFETY: both buffers were allocated by the calls above (null-safe).
        unsafe {
            if !text.is_null() {
                let _ = LocalFree(HLOCAL(text.0 as *mut core::ffi::c_void));
            }
            let _ = LocalFree(HLOCAL(descriptor.0));
        }
        sddl
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::win::{apply_protected_dacl, read_dacl_sddl};
    use super::*;

    /// Every ACE in a protected DACL grants to SYSTEM or Administrators only.
    fn assert_only_system_and_admins(sddl: &str) {
        assert!(sddl.starts_with("D:P"), "DACL must be protected: {sddl}");
        let aces: Vec<&str> = sddl
            .trim_start_matches("D:P")
            .split(')')
            .filter(|a| !a.is_empty())
            .collect();
        assert!(!aces.is_empty(), "DACL has no ACEs: {sddl}");
        for ace in aces {
            assert!(
                ace.ends_with(";;;SY") || ace.ends_with(";;;BA"),
                "ACE grants to someone other than SYSTEM/Administrators: {ace}"
            );
        }
    }

    /// Runs unelevated: the file's owner keeps implicit READ_CONTROL and WRITE_DAC, so it
    /// can set, read back, and then relax the DACL for cleanup.
    #[test]
    fn a_protected_dacl_restricts_a_file_to_system_and_administrators() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("primary-core.json");
        std::fs::write(&file, b"{}").unwrap();

        apply_protected_dacl(&file, RUN_FILE_SDDL).unwrap();
        assert_only_system_and_admins(&read_dacl_sddl(&file).unwrap());

        // Relax so the tempdir can be removed by the unelevated test user.
        apply_protected_dacl(&file, "D:P(A;;FA;;;WD)").unwrap();
    }

    #[test]
    fn default_run_dir_is_under_programdata() {
        let dir = default_run_dir();
        assert!(dir.ends_with(r"DNet Engine\run"));
    }

    /// The full directory-first flow needs rights to set a DACL on a directory and then
    /// write into it as a member of Administrators.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-config -- --ignored)"]
    fn write_restricted_leaves_no_broader_acl_on_dir_or_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("run");
        let path = write_restricted(&dir, "primary-core.json", b"{\"log\":{}}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"log\":{}}");
        assert_only_system_and_admins(&read_dacl_sddl(&dir).unwrap());
        assert_only_system_and_admins(&read_dacl_sddl(&path).unwrap());
    }
}
