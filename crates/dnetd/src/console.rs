//! Resolving the interactive console user, against which mutating IPC requests are
//! authorized.
//!
//! `dnetd` runs as LocalSystem, which holds `SeTcbPrivilege` and can therefore query
//! the console session's user token. When no user is logged on at the console — or
//! when running unprivileged in `--console` dev mode — this yields `None`, which
//! denies every mutating request (fail closed).

#![cfg(windows)]

use std::ffi::c_void;

use dnet_ipc::authz::ConsoleSession;
use windows::core::PWSTR;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};

/// The session id returned when there is no active console session.
const NO_SESSION: u32 = 0xFFFF_FFFF;

/// The interactive console user, or `None` if there is none / it cannot be queried.
pub fn active_console_session() -> Option<ConsoleSession> {
    // SAFETY: no arguments; returns a plain session id. NO_SESSION means none active.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == NO_SESSION {
        return None;
    }

    // SAFETY: WTSQueryUserToken writes a token handle we own and close below. It needs
    // SeTcbPrivilege (LocalSystem has it); it fails otherwise, which we treat as "no
    // console user" — fail closed.
    let sid = unsafe {
        let mut token = HANDLE::default();
        WTSQueryUserToken(session_id, &mut token).ok()?;
        let sid = token_user_sid(token);
        let _ = CloseHandle(token);
        sid
    }?;

    Some(ConsoleSession {
        session_id,
        user_sid: sid,
    })
}

/// Read the user SID from an access token as a string.
///
/// SAFETY: `token` is a valid, open access token handle.
unsafe fn token_user_sid(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    // First call sizes the buffer; expected to fail with insufficient buffer.
    let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
    if needed == 0 {
        return None;
    }

    // u64 elements, so the buffer is aligned for the pointer inside `TOKEN_USER`; a byte buffer
    // need not be, and reading the struct through a misaligned reference is undefined behaviour.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    GetTokenInformation(
        token,
        TokenUser,
        Some(buffer.as_mut_ptr() as *mut c_void),
        needed,
        &mut needed,
    )
    .ok()?;

    let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
    let mut sid_string = PWSTR::null();
    ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string).ok()?;

    let sid = sid_string.to_string().ok();
    if !sid_string.is_null() {
        let _ = LocalFree(HLOCAL(sid_string.0 as *mut c_void));
    }
    sid
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::*;

    /// The shape of a security identifier as text: `S-1-<authority>-<sub>-...`, digits only.
    fn looks_like_a_sid(text: &str) -> bool {
        let mut parts = text.split('-');
        parts.next() == Some("S")
            && parts.next() == Some("1")
            && parts.clone().count() >= 2
            && parts.all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }

    fn own_token() -> HANDLE {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo-handle for this process is always valid; `token` is a valid out-pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .expect("a process can open its own token for query");
        token
    }

    #[test]
    fn the_shape_check_itself_is_not_fooled() {
        assert!(looks_like_a_sid("S-1-5-18"));
        assert!(looks_like_a_sid(
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        ));
        for bad in [
            "",
            "S",
            "S-1",
            "S-1-",
            "S-2-5-18",
            "s-1-5-18",
            "S-1-5-x",
            "S-1-5--18",
            "1-5-18",
            "S-1-5-18-",
        ] {
            assert!(!looks_like_a_sid(bad), "{bad:?}");
        }
    }

    #[test]
    fn this_process_user_is_read_as_a_sid() {
        let token = own_token();
        // SAFETY: `token` is a valid, open access token handle.
        let sid = unsafe { token_user_sid(token) };
        // SAFETY: the handle was opened above and is closed once.
        let _ = unsafe { CloseHandle(token) };
        let sid = sid.expect("the user of this process can be read");
        assert!(looks_like_a_sid(&sid), "{sid}");
    }

    #[test]
    fn reading_the_user_twice_gives_the_same_answer() {
        let token = own_token();
        // SAFETY: `token` is a valid, open access token handle.
        let (a, b) = unsafe { (token_user_sid(token), token_user_sid(token)) };
        // SAFETY: the handle was opened above and is closed once.
        let _ = unsafe { CloseHandle(token) };
        assert!(a.is_some());
        assert_eq!(a, b);
    }

    #[test]
    fn the_same_user_is_read_from_a_second_token() {
        let (first, second) = (own_token(), own_token());
        // SAFETY: both are valid, open access token handles.
        let (a, b) = unsafe { (token_user_sid(first), token_user_sid(second)) };
        // SAFETY: each handle was opened above and is closed once.
        unsafe {
            let _ = CloseHandle(first);
            let _ = CloseHandle(second);
        }
        assert_eq!(a, b);
    }

    /// From an ordinary program the console user cannot be asked for (that takes the service's own right),
    /// and the answer is then "none", which refuses every change. Under the service it is the real user.
    /// Either way it never panics, and an answer is always a real session and a real SID.
    #[test]
    fn asking_for_the_console_user_without_the_right_is_none_or_a_real_user() {
        match active_console_session() {
            None => {}
            Some(session) => {
                assert_ne!(session.session_id, NO_SESSION);
                assert!(looks_like_a_sid(&session.user_sid), "{}", session.user_sid);
            }
        }
    }

    #[test]
    fn asking_many_times_never_panics_and_never_changes_its_mind() {
        let first = active_console_session();
        for _ in 0..50 {
            assert_eq!(active_console_session(), first);
        }
    }

    #[test]
    fn the_no_session_marker_is_the_documented_value() {
        assert_eq!(NO_SESSION, u32::MAX);
    }
}
