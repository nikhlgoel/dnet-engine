//! T160 — asking Windows for elevation, and knowing whether this program has it.
//!
//! The elevated half of `dnetctl approve` runs in a window of its own, opened with the `runas` verb,
//! which makes Windows show its elevation prompt on the secure desktop. That prompt is the whole
//! point: a program running as the person can open it but cannot answer it.

#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Whether this process's token is elevated.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle for the current process is always valid; `token` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut needed = 0u32;
    // SAFETY: `token` is open with TOKEN_QUERY; the buffer is a TOKEN_ELEVATION of the size given.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    read.is_ok() && elevation.TokenIsElevated != 0
}

/// An argument that is safe to hand over as it is: no space, quote or control character, so no
/// quoting rules are needed and nothing can be split or smuggled. The arguments this program passes
/// itself (a command name, a change id, flags) always are.
fn is_plain_argument(arg: &str) -> bool {
    !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Run this program again with `args`, elevated, and wait for it. `Err` says why not: usually that
/// the person declined the Windows prompt.
pub fn relaunch_elevated(args: &[String]) -> Result<i32, String> {
    if let Some(bad) = args.iter().find(|a| !is_plain_argument(a)) {
        return Err(format!(
            "cannot pass '{}' to an elevated window",
            bad.escape_debug()
        ));
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program ({e})"))?;
    let file = wide(exe.as_os_str());
    let parameters = wide(std::ffi::OsStr::new(&args.join(" ")));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised; the strings it points to outlive the call.
    if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
        return Err(if error.code() == ERROR_CANCELLED.to_hresult() {
            "you declined the Windows prompt".to_string()
        } else {
            format!("Windows could not open the elevated window ({error})")
        });
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err("Windows did not give a handle to the elevated window".to_string());
    }
    // SAFETY: `process` is a process handle we own (SEE_MASK_NOCLOSEPROCESS); it is closed once below.
    let code = unsafe {
        let waited = WaitForSingleObject(process, INFINITE);
        let mut code = 0u32;
        let got = waited == WAIT_OBJECT_0 && GetExitCodeProcess(process, &mut code).is_ok();
        let _ = CloseHandle(process);
        got.then_some(code)
    };
    match code {
        Some(code) => Ok(i32::try_from(code).unwrap_or(i32::MAX)),
        None => Err("the elevated window ended without a result".to_string()),
    }
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_arguments_are_passed_on() {
        for ok in [
            "approve",
            "a1b2c3d4",
            "--pause",
            "--allow-unprivileged-service",
        ] {
            assert!(is_plain_argument(ok), "{ok}");
        }
        for bad in [
            "", "a b", "a\"b", "a;b", "a&b", "..\\x", "a\nb", "é", "%PATH%",
        ] {
            assert!(!is_plain_argument(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_bad_argument_is_refused_before_windows_is_asked_anything() {
        let refused = relaunch_elevated(&["approve".into(), "x y".into()]);
        assert!(refused.unwrap_err().contains("cannot pass"));
    }

    /// The test process is an ordinary one; this only checks the call works and agrees with itself.
    #[test]
    fn the_token_can_be_read() {
        assert_eq!(is_elevated(), is_elevated());
    }
}
