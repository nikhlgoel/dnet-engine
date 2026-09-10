//! Pipe identity, its security descriptor, and the per-connection loop.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::protocol::IpcError;

/// The control pipe (contract §Transport).
pub const PIPE_NAME: &str = r"\\.\pipe\DNetEngine\control";

/// SDDL for the control pipe's security descriptor.
///
/// Contract §Authorization: `GENERIC_READ | GENERIC_WRITE` for Authenticated Users,
/// full control for SYSTEM and Administrators, and never a NULL DACL.
pub fn pipe_sddl() -> &'static str {
    todo!("T034: define the pipe security descriptor")
}

/// Serve one client until it disconnects or sends a frame that can never decode.
///
/// Must return, not linger, when the client leaves mid-request (IPC-09).
pub async fn serve_connection<S>(_stream: S) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    todo!("T034: implement the per-connection loop")
}
