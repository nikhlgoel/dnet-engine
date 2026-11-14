// SPDX-License-Identifier: GPL-3.0-or-later
//! T045 (OS half) — orphaned-core discovery and termination (SUP-05).
//!
//! Enumerates processes with a Toolhelp snapshot and matches each candidate's **full
//! image path** against the supervised binaries. A file-name match alone is never
//! enough: an unrelated program that happens to share a name must not be killed. The
//! service's own process is always excluded.

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

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
        GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    use crate::error::SupervisorError;

    /// The exit code a process reports while it is still running.
    const STILL_ACTIVE: u32 = 259;

    /// Whether the process behind `handle` has already ended. Ending one that has is refused by the system
    /// with "access denied" while anything still holds a handle to it, which is not a process left running.
    /// Needs `PROCESS_QUERY_LIMITED_INFORMATION`; without it, or when the code cannot be read, the answer
    /// is "no", so a real refusal is never hidden.
    fn has_ended(handle: &Owned) -> bool {
        let mut code = 0u32;
        // SAFETY: the handle is open; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(handle.0, &mut code) }.is_ok() && code != STILL_ACTIVE
    }

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
        image_path_of(&Owned(handle))
    }

    /// The full image path of the process an open handle refers to.
    fn image_path_of(handle: &Owned) -> Option<PathBuf> {
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

    /// Whether a failure to open a process means it no longer exists. Only `ERROR_INVALID_PARAMETER`
    /// does; access denied and the rest mean it may well be running and out of reach.
    pub(super) fn is_gone(error: &windows::core::Error) -> bool {
        const ERROR_INVALID_PARAMETER: u32 = 87;
        error.code() == windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER)
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

    /// Terminate a process by id. A process that has already exited is not an error; one that
    /// cannot be opened for any other reason is, because it may still be running.
    pub fn terminate(pid: u32) -> Result<(), SupervisorError> {
        // SAFETY: OpenProcess for termination (and the exit code, to tell an ended process from a refusal);
        // the handle is closed by Owned.
        let handle = match unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
        } {
            Ok(h) => Owned(h),
            Err(e) if is_gone(&e) => return Ok(()),
            Err(e) => {
                return Err(SupervisorError::Runtime(format!(
                    "opening pid {pid} to end it: {e}"
                )))
            }
        };
        // SAFETY: the handle carries PROCESS_TERMINATE.
        match unsafe { TerminateProcess(handle.0, 1) } {
            Ok(()) => Ok(()),
            // It ended by itself between the scan and now: nothing is left to end.
            Err(_) if has_ended(&handle) => Ok(()),
            Err(e) => Err(SupervisorError::Runtime(format!(
                "terminating pid {pid}: {e}"
            ))),
        }
    }

    /// End `pid` if, and only if, it is still one of `images`. The check and the kill are made
    /// through one handle: opening a second time by id after the scan would end whatever had been
    /// given the id in between. `Ok(false)` is a process that is gone or is no longer ours.
    pub(super) fn terminate_if_image(
        pid: u32,
        images: &[PathBuf],
    ) -> Result<bool, SupervisorError> {
        let rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
        // SAFETY: OpenProcess for query and termination; the handle is closed by Owned.
        let handle = match unsafe { OpenProcess(rights, false, pid) } {
            Ok(h) => Owned(h),
            Err(e) if is_gone(&e) => return Ok(false),
            Err(e) => {
                return Err(SupervisorError::Runtime(format!(
                    "opening pid {pid} to end it: {e}"
                )))
            }
        };
        let ours = image_path_of(&handle)
            .is_some_and(|path| images.iter().any(|image| same_image(&path, image)));
        if !ours {
            return Ok(false);
        }
        // SAFETY: the handle carries PROCESS_TERMINATE.
        match unsafe { TerminateProcess(handle.0, 1) } {
            Ok(()) => Ok(true),
            // It ended by itself after the check: it is gone, and not ended by this call.
            Err(_) if has_ended(&handle) => Ok(false),
            Err(e) => Err(SupervisorError::Runtime(format!(
                "terminating pid {pid}: {e}"
            ))),
        }
    }

    /// Find and terminate every orphaned core. Returns the ids that were terminated.
    ///
    /// Every orphan is tried even if one cannot be ended: an orphan left running holds the adapter
    /// or a port, and another one that could have been ended must not be left beside it. The first
    /// failure is returned once all have been tried.
    pub fn reap(images: &[PathBuf]) -> Result<Vec<u32>, SupervisorError> {
        let mut reaped = Vec::new();
        let mut first_failure = None;
        for pid in find_by_image(images)? {
            match terminate_if_image(pid, images) {
                Ok(true) => {
                    tracing::warn!(pid, "reaped an orphaned core left by a previous run");
                    reaped.push(pid);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(pid, %error, "an orphaned core could not be ended");
                    first_failure.get_or_insert(error);
                }
            }
        }
        match first_failure {
            Some(error) => Err(error),
            None => Ok(reaped),
        }
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

    /// Only "there is no such process" means the orphan is gone. Every other refusal (access
    /// denied above all) means it may still be running, and saying "gone" would leave it holding
    /// the adapter and the ports while the service believes the way is clear.
    #[cfg(windows)]
    #[test]
    fn only_no_such_process_means_gone() {
        use windows::core::{Error, HRESULT};
        let win32 = |code: u32| Error::from(HRESULT::from_win32(code));
        assert!(
            win::is_gone(&win32(87)),
            "ERROR_INVALID_PARAMETER: no such pid"
        );
        assert!(
            !win::is_gone(&win32(5)),
            "ERROR_ACCESS_DENIED: still running"
        );
        assert!(!win::is_gone(&win32(6)));
    }

    #[cfg(windows)]
    #[test]
    fn ending_a_process_that_does_not_exist_is_not_an_error() {
        // 0xFFFFFFF0 is not a process id any system hands out.
        terminate(0xFFFF_FFF0).expect("a process that is gone is not an error");
    }

    /// The id may have been given to another program since the scan. Whatever has it now is not
    /// ours to end, however the id came to be asked about.
    #[cfg(windows)]
    #[test]
    fn a_process_that_is_not_one_of_ours_is_left_alone() {
        let _one_at_a_time = crate::process::spawning();
        // `set /p` is a built-in that waits for input from a stdin nobody closes: one process, no child under it, so
        // ending it can never strand a suspended grandchild holding the test run's pipes (T190).
        let mut bystander = std::process::Command::new("cmd")
            .args(["/C", "set /p x="])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let someone_elses = [std::path::PathBuf::from(
            r"C:\Program Files\DNet Engine\core.exe",
        )];

        let ended = win::terminate_if_image(bystander.id(), &someone_elses).unwrap();

        let still_running = bystander.try_wait().unwrap().is_none();
        let _ = bystander.kill();
        let _ = bystander.wait();
        assert!(!ended, "reported as ended");
        assert!(still_running, "a process that is not one of ours was ended");
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

        let _one_at_a_time = crate::process::spawning();
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

#[cfg(all(test, windows))]
mod pinned_tests {
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    use super::*;

    fn sleeper() -> std::process::Child {
        let _one_at_a_time = crate::process::spawning();
        // See the note in `a_process_that_is_not_one_of_ours_is_left_alone`: a built-in waiting on an open stdin.
        std::process::Command::new("cmd")
            .args(["/C", "set /p x="])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    fn handles() -> u32 {
        let mut count = 0u32;
        // SAFETY: the pseudo-handle for this process is always valid; `count` is a valid out-pointer.
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) }.unwrap();
        count
    }

    #[test]
    fn a_process_is_ended_by_its_id_and_leaves_with_the_code_it_was_given() {
        let mut child = sleeper();
        terminate(child.id()).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(1),
            "ended by the supervisor, not finished"
        );
    }

    #[test]
    fn ending_a_process_twice_is_not_an_error_the_second_time() {
        let mut child = sleeper();
        let pid = child.id();
        terminate(pid).unwrap();
        child.wait().unwrap();
        terminate(pid).expect("a process that is gone is not an error");
    }

    #[test]
    fn a_process_that_is_gone_is_not_ended_and_not_an_error() {
        let someone = [PathBuf::from(r"C:\Program Files\DNet Engine\core.exe")];
        assert!(!win::terminate_if_image(0xFFFF_FFF0, &someone).unwrap());
    }

    /// The service never ends itself, however its own image is listed.
    #[test]
    fn the_scan_never_includes_the_process_asking() {
        let me = std::process::id();
        let found = find_by_image(&[std::env::current_exe().unwrap()]).unwrap();
        assert!(
            !found.contains(&me),
            "{found:?} includes this process ({me})"
        );
    }

    #[test]
    fn a_scan_for_an_image_nobody_runs_finds_nothing() {
        let found =
            find_by_image(&[PathBuf::from(r"C:\no\such\dir\dnet-nothing-runs-this.exe")]).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn a_scan_for_no_images_finds_nothing() {
        assert!(find_by_image(&[]).unwrap().is_empty());
    }

    #[test]
    fn scanning_and_ending_do_not_leak_handles() {
        let _warm = find_by_image(&[PathBuf::from("dnet-warm.exe")]).unwrap();
        let before = handles();
        for _ in 0..200 {
            let _ = find_by_image(&[PathBuf::from("dnet-leak-check.exe")]).unwrap();
            let _ = terminate(0xFFFF_FFF0);
        }
        let after = handles();
        assert!(after < before + 150, "{before} handles became {after}");
    }

    #[test]
    fn a_real_process_is_ended_through_its_image_and_a_look_alike_is_not() {
        let mut ours = sleeper();
        let mut other = sleeper();
        // The image of both is the same program; only the path given decides.
        let cmd_path =
            PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
                .join("System32")
                .join("cmd.exe");
        let not_cmd = [PathBuf::from(r"C:\elsewhere\cmd.exe")];
        assert!(!win::terminate_if_image(other.id(), &not_cmd).unwrap());
        assert!(
            other.try_wait().unwrap().is_none(),
            "a look-alike was ended"
        );

        assert!(win::terminate_if_image(ours.id(), std::slice::from_ref(&cmd_path)).unwrap());
        assert_eq!(ours.wait().unwrap().code(), Some(1));
        let _ = other.kill();
        let _ = other.wait();
    }
}
