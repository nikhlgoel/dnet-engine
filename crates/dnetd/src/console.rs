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

    let mut buffer = vec![0u8; needed as usize];
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
