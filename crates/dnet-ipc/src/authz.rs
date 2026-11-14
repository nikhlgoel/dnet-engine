// SPDX-License-Identifier: GPL-3.0-or-later
//! Authorization policy for requests crossing the privilege boundary.
//!
//! The OS half — impersonating the pipe client and capturing its token — is T035, and
//! is verified end to end by attack at the T039 gate. This module is only the
//! *decision*, kept pure so the rule that is easiest to get wrong is also the easiest
//! to test.

use crate::protocol::{IpcError, RequestClass};

/// A connected client's identity, captured from its token when it connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub sid: String,
    pub session_id: u32,
    pub authenticated: bool,
    /// Whether the client's token is elevated (T160): the person said yes to a User Account Control
    /// prompt, which runs on the secure desktop where a program cannot answer for them. Read from the
    /// token, never claimed by the client; any failure to read it is `false`.
    pub elevated: bool,
}

/// The interactive console session and its logged-on user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSession {
    pub session_id: u32,
    pub user_sid: String,
}

fn unauthorized(reason: impl Into<String>) -> IpcError {
    IpcError::Unauthorized {
        reason: reason.into(),
    }
}

/// Decide whether `client` may issue a request of class `class`.
///
/// - An unauthenticated caller is refused everything.
/// - Read-only and stream requests need only an authenticated caller.
/// - Mutating requests additionally require that the client's session is the
///   interactive console session *and* its SID is the logged-on user.
///
/// Refusal is always explicit, as `IpcError::Unauthorized`; a silent no-op is a defect.
pub fn authorize(
    class: RequestClass,
    client: &ClientIdentity,
    console: Option<&ConsoleSession>,
) -> Result<(), IpcError> {
    if !client.authenticated {
        return Err(unauthorized("caller is not authenticated"));
    }

    match class {
        RequestClass::ReadOnly | RequestClass::Stream => Ok(()),
        RequestClass::Mutating => {
            let console =
                console.ok_or_else(|| unauthorized("no interactive console session is active"))?;
            let same_session = client.session_id == console.session_id;
            let same_user = client.sid == console.user_sid;
            if same_session && same_user {
                Ok(())
            } else {
                Err(unauthorized(
                    "mutating requests require the interactive console user",
                ))
            }
        }
        RequestClass::Approval => {
            // Approval is the one act a program running as the console user must not be able to do
            // alone, so it needs an elevated token (the person answered a UAC prompt) and the
            // console session. The SID may differ from the console user's: a standard user who
            // types an administrator's credentials into the prompt runs the approver as that
            // administrator, in the same session.
            if !client.elevated {
                return Err(unauthorized(
                    "approving a change needs an elevated client: run `dnetctl approve` and \
                     answer the Windows prompt",
                ));
            }
            let console =
                console.ok_or_else(|| unauthorized("no interactive console session is active"))?;
            if client.session_id == console.session_id {
                Ok(())
            } else {
                Err(unauthorized(
                    "approving a change is done from the interactive console session",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONSOLE_SESSION: u32 = 2;

    fn console() -> ConsoleSession {
        ConsoleSession {
            session_id: CONSOLE_SESSION,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
        }
    }

    fn client(sid: &str, session_id: u32, elevated: bool) -> ClientIdentity {
        ClientIdentity {
            sid: sid.into(),
            session_id,
            authenticated: true,
            elevated,
        }
    }

    #[test]
    fn an_elevated_client_in_the_console_session_may_approve() {
        let me = client("S-1-5-21-1-2-3-1001", CONSOLE_SESSION, true);
        assert_eq!(
            authorize(RequestClass::Approval, &me, Some(&console())),
            Ok(())
        );
    }

    /// The reason for the whole feature: the console user's own, unelevated program cannot approve.
    #[test]
    fn the_console_user_without_elevation_may_not_approve() {
        let me = client("S-1-5-21-1-2-3-1001", CONSOLE_SESSION, false);
        let refused = authorize(RequestClass::Approval, &me, Some(&console())).unwrap_err();
        assert!(
            matches!(&refused, IpcError::Unauthorized { reason } if reason.contains("elevated"))
        );
        // The control: the same client may do an ordinary change.
        assert_eq!(
            authorize(RequestClass::Mutating, &me, Some(&console())),
            Ok(())
        );
    }

    /// A standard user who typed an administrator's credentials runs the approver as another SID.
    #[test]
    fn an_administrator_the_person_named_in_the_prompt_may_approve_from_the_console_session() {
        let admin = client("S-1-5-21-1-2-3-500", CONSOLE_SESSION, true);
        assert_eq!(
            authorize(RequestClass::Approval, &admin, Some(&console())),
            Ok(())
        );
    }

    #[test]
    fn an_elevated_client_in_another_session_may_not_approve() {
        let remote = client("S-1-5-21-1-2-3-500", CONSOLE_SESSION + 1, true);
        assert!(authorize(RequestClass::Approval, &remote, Some(&console())).is_err());
    }

    #[test]
    fn with_no_console_session_nobody_may_approve() {
        let admin = client("S-1-5-21-1-2-3-500", CONSOLE_SESSION, true);
        assert!(authorize(RequestClass::Approval, &admin, None).is_err());
    }

    #[test]
    fn an_unauthenticated_client_may_not_approve_even_if_it_claims_elevation() {
        let mut ghost = client("", 0, true);
        ghost.authenticated = false;
        assert!(authorize(RequestClass::Approval, &ghost, Some(&console())).is_err());
    }

    /// Elevation buys nothing for the other classes: it neither widens nor narrows them.
    #[test]
    fn elevation_does_not_change_the_other_classes() {
        for class in [RequestClass::ReadOnly, RequestClass::Stream] {
            for elevated in [false, true] {
                let me = client("S-1-5-21-9-9-9-1", 7, elevated);
                assert_eq!(authorize(class, &me, None), Ok(()), "{class:?}");
            }
        }
        let stranger = client("S-1-5-21-9-9-9-1", 7, true);
        assert!(authorize(RequestClass::Mutating, &stranger, Some(&console())).is_err());
    }
}
