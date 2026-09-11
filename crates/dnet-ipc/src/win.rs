//! Windows-specific IPC: building the pipe's security descriptor from SDDL, and
//! capturing the connecting client's real identity via impersonation.
//!
//! This is the OS half of the privilege boundary (T034/T035). Everything here is
//! `#[cfg(windows)]`; the pure decision that consumes a `ClientIdentity` lives in
//! `authz` and is platform-independent.

#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::io::RawHandle;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenSessionId, TokenUser, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::authz::ClientIdentity;

/// The well-known anonymous-logon SID. A client that resolves to this is not a real
/// authenticated principal.
const ANONYMOUS_SID: &str = "S-1-5-7";

/// A security descriptor built from SDDL, owning the `LocalAlloc`ed buffer so it is
/// freed on drop, plus the `SECURITY_ATTRIBUTES` that points at it.
///
/// The `SECURITY_ATTRIBUTES` borrows the descriptor buffer, so this struct must
/// outlive the pipe-creation call that reads it.
pub struct SecurityAttributes {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl SecurityAttributes {
    /// Build a security descriptor from an SDDL string (e.g. `pipe_sddl()`).
    pub fn from_sddl(sddl: &str) -> windows::core::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call;
        // `descriptor` is a valid out-pointer. On success the function allocates the
        // descriptor with LocalAlloc, which `Drop` frees.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }

        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    /// A pointer suitable for tokio's `create_with_security_attributes_raw`.
    ///
    /// Valid only while `self` is alive.
    pub fn as_ptr(&self) -> *const c_void {
        &self.attributes as *const _ as *const c_void
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            // SAFETY: the descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW with LocalAlloc, and
            // is freed exactly once here.
            unsafe {
                let _ = LocalFree(HLOCAL(self.descriptor.0));
            }
        }
    }
}

/// Capture the connecting client's identity from a connected named-pipe handle.
///
/// Performs the impersonation dance synchronously — impersonate, open the thread
/// token, read the user SID and session id, revert — so the impersonation token never
/// outlives this call and no `await` runs while it is in effect. The pipe MUST have
/// had at least one message read from the client first, or impersonation fails; the
/// caller primes the pipe with a first read.
///
/// On any failure the client is reported unauthenticated, which denies every mutating
/// request (fail closed).
pub fn capture_client_identity(handle: RawHandle) -> ClientIdentity {
    let pipe = HANDLE(handle);

    // SAFETY: `pipe` is a live named-pipe server handle owned by the caller for the
    // duration of this call. Impersonation is reverted before returning on every path,
    // and no await runs while it is in effect.
    unsafe {
        if ImpersonateNamedPipeClient(pipe).is_err() {
            return unauthenticated();
        }
        let captured = read_impersonated_identity();
        let _ = RevertToSelf();
        captured.unwrap_or_else(unauthenticated)
    }
}

/// Reads the impersonated thread token. Called only while impersonating.
///
/// SAFETY: the current thread is impersonating the pipe client; the token handle is
/// closed before returning.
unsafe fn read_impersonated_identity() -> Option<ClientIdentity> {
    let mut token = HANDLE::default();
    // OpenAsSelf = true: use the process's own context to open the thread token, so
    // this succeeds even when the impersonated client could not open it.
    OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).ok()?;

    let identity = (|| {
        let sid = token_user_sid(token)?;
        let session_id = token_session_id(token).unwrap_or(0);
        let authenticated = sid != ANONYMOUS_SID && !sid.is_empty();
        Some(ClientIdentity {
            sid,
            session_id,
            authenticated,
        })
    })();

    let _ = CloseHandle(token);
    identity
}

/// SAFETY: `token` is an open access token handle with `TOKEN_QUERY`.
unsafe fn token_user_sid(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    // First call sizes the buffer; it is expected to fail with insufficient buffer.
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

/// SAFETY: `token` is an open access token handle with `TOKEN_QUERY`.
unsafe fn token_session_id(token: HANDLE) -> Option<u32> {
    let mut session_id = 0u32;
    let mut needed = 0u32;
    GetTokenInformation(
        token,
        TokenSessionId,
        Some(&mut session_id as *mut u32 as *mut c_void),
        std::mem::size_of::<u32>() as u32,
        &mut needed,
    )
    .ok()?;
    Some(session_id)
}

fn unauthenticated() -> ClientIdentity {
    ClientIdentity {
        sid: String::new(),
        session_id: 0,
        authenticated: false,
    }
}
