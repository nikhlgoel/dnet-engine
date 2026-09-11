//! The seam between the IPC boundary and the privileged service logic.
//!
//! The connection loop authorizes every request against the captured client identity
//! *before* asking the `Service` to act on it. A `Service` therefore never sees a
//! request the caller was not permitted to make — which is what keeps SC-019 true: an
//! unauthorized mutating request cannot reach the code that would change routing.

use crate::authz::ConsoleSession;
use crate::protocol::{IpcError, Request};

/// The privileged operations the IPC layer drives, implemented by `dnetd` (T036) and
/// stubbed by tests. It is only ever called for a request that has already passed
/// authorization.
pub trait Service: Send + Sync + 'static {
    /// The interactive console session and its logged-on user, against which mutating
    /// requests are authorized. `None` means no interactive session is active, which
    /// denies all mutating requests.
    fn console_session(&self) -> Option<ConsoleSession>;

    /// Perform an authorized request, returning the response payload (wire JSON).
    ///
    /// This is reached only after the request passed authorization, so an
    /// implementation must never re-check identity here — but it also must not assume
    /// more than that the caller was permitted this request's class.
    fn dispatch(&self, request: &Request) -> Result<String, IpcError>;
}
