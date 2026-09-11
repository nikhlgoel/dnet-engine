//! T045 (OS half) — orphaned-core discovery and termination (SUP-05).
//!
//! Enumerates processes with a Toolhelp snapshot and matches each candidate's **full
//! image path** against the supervised binaries. A file-name match alone is never
//! enough: an unrelated program that happens to share a name must not be killed. The
//! service's own process is always excluded.

use std::path::{Path, PathBuf};

/// Whether two image paths name the same file: case-insensitive, separator-normalised,
/// and ignoring the `\\?\` verbatim prefix — the forms Windows reports image paths in.
pub fn same_image(a: &Path, b: &Path) -> bool {
    fn norm(p: &Path) -> String {
        let s = p.to_string_lossy().replace('/', "\\");
        s.strip_prefix(r"\\?\")
            .unwrap_or(&s)
            .trim_end_matches('\\')
            .to_lowercase()
    }
    norm(a) == norm(b)
}

#[cfg(windows)]
mod win {
    use super::*;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    use crate::error::SupervisorError;

    /// Closes a handle on drop.
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle was returned open by a Win32 call and is closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn file_name_of(entry: &PROCESSENTRY32W) -> String {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        String::from_utf16_lossy(&entry.szExeFile[..len])
    }

    fn full_image_path(pid: u32) -> Option<PathBuf> {
        // SAFETY: OpenProcess with a limited query right; the handle is closed by Owned.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let handle = Owned(handle);
        let mut buf = vec![0u16; 32_768];
        let mut size = buf.len() as u32;
        // SAFETY: `buf` holds `size` UTF-16 units; `size` is updated to the length written.
        unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
        }
        .ok()?;
        Some(PathBuf::from(String::from_utf16_lossy(
            &buf[..size as usize],
        )))
    }

    /// Process ids whose full image path matches one of `images`, excluding this process.
    pub fn find_by_image(images: &[PathBuf]) -> Result<Vec<u32>, SupervisorError> {
        let wanted_names: Vec<String> = images
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_lowercase())
            .collect();
        let me = std::process::id();

        // SAFETY: a process snapshot; the handle is closed by Owned.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| SupervisorError::Runtime(format!("process snapshot failed: {e}")))?;
        let snapshot = Owned(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = Vec::new();
        // SAFETY: `entry.dwSize` is set as the API requires; the snapshot is valid.
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
        while more {
            let pid = entry.th32ProcessID;
            // Cheap name filter first; confirm with the full path before accepting.
            if pid != me && wanted_names.contains(&file_name_of(&entry).to_lowercase()) {
                if let Some(path) = full_image_path(pid) {
                    if images.iter().any(|img| same_image(&path, img)) {
                        found.push(pid);
                    }
                }
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
        }
        Ok(found)
    }

    /// Terminate a process by id. A process that has already exited is not an error.
    pub fn terminate(pid: u32) -> Result<(), SupervisorError> {
        // SAFETY: OpenProcess for termination; the handle is closed by Owned.
        let handle = match unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
            Ok(h) => Owned(h),
            Err(_) => return Ok(()), // gone already
        };
        // SAFETY: the handle carries PROCESS_TERMINATE.
        unsafe { TerminateProcess(handle.0, 1) }
            .map_err(|e| SupervisorError::Runtime(format!("terminating pid {pid}: {e}")))
    }

    /// Find and terminate every orphaned core. Returns the ids that were terminated.
    pub fn reap(images: &[PathBuf]) -> Result<Vec<u32>, SupervisorError> {
        let pids = find_by_image(images)?;
        for &pid in &pids {
            terminate(pid)?;
            tracing::warn!(pid, "reaped an orphaned core left by a previous run");
        }
        Ok(pids)
    }
}

#[cfg(windows)]
pub use win::{find_by_image, reap, terminate};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_comparison_ignores_case_separators_and_verbatim_prefix() {
        assert!(same_image(
            Path::new(r"C:\Program Files\DNet Engine\core.exe"),
            Path::new(r"\\?\c:/program files/dnet engine/CORE.EXE"),
        ));
        assert!(!same_image(
            Path::new(r"C:\Program Files\DNet Engine\core.exe"),
            Path::new(r"C:\Other\core.exe"),
        ));
    }

    /// Helper process for the reaping test: a copy of this test binary runs only this
    /// test, which sleeps. Without the env var it returns at once, so normal runs and
    /// `--ignored` runs are unaffected.
    #[test]
    #[ignore = "helper spawned by orphans_are_found_by_full_path_and_terminated"]
    fn orphan_probe_sleeper() {
        if std::env::var_os("DNET_ORPHAN_PROBE").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    /// A simulated orphan: a uniquely-named copy of this test binary is started, found
    /// by its full image path, and terminated (SUP-T3 against the real OS).
    #[cfg(windows)]
    #[test]
    fn orphans_are_found_by_full_path_and_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir
            .path()
            .join(format!("dnet-orphan-probe-{}.exe", std::process::id()));
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();

        let mut child = std::process::Command::new(&image)
            .args([
                "--ignored",
                "--exact",
                "orphans::tests::orphan_probe_sleeper",
            ])
            .env("DNET_ORPHAN_PROBE", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        // The snapshot may lag the spawn very slightly.
        let mut pids = Vec::new();
        for _ in 0..50 {
            pids = find_by_image(std::slice::from_ref(&image)).unwrap();
            if !pids.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(pids, vec![child.id()], "exactly the orphan is matched");

        assert_eq!(
            reap(std::slice::from_ref(&image)).unwrap(),
            vec![child.id()]
        );
        let status = child.wait().unwrap();
        assert!(
            !status.success(),
            "the orphan was terminated, not left to finish"
        );
        assert!(find_by_image(std::slice::from_ref(&image))
            .unwrap()
            .is_empty());
    }
}
