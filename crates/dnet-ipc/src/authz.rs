//! Authorization policy for requests crossing the privilege boundary.
//!
//! The OS half — impersonating the pipe client and capturing its token — is T035, and
//! is verified end to end by attack at the T039 gate. This module is only the
//! *decision*. It is kept pure so the rule that is easiest to get wrong is also the
//! easiest to test.

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

/// Decide whether `client` may issue a request of class `class`.
///
/// Mutating requests require that the client's session is the console session *and*
/// that its SID is the logged-on user. Refusal is always explicit, as
/// `IpcError::Unauthorized`; a silent no-op is a defect.
pub fn authorize(
    _class: RequestClass,
    _client: &ClientIdentity,
    _console: Option<&ConsoleSession>,
) -> Result<(), IpcError> {
    todo!("T035: implement the authorization decision")
}
