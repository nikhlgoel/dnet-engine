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
    }
}
