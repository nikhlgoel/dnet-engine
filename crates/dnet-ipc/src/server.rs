//! Pipe identity, its security descriptor, and the per-connection loop.
//!
//! The connection loop and the security descriptor are defined here (T034). Binding
//! the descriptor to a real named pipe and dispatching decoded requests to the
//! service is the remainder of T034/T036; the loop below already enforces the
//! framing and lifecycle contract (IPC-08, IPC-09).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::frame;
use crate::protocol::IpcError;

/// The control pipe (contract §Transport).
pub const PIPE_NAME: &str = r"\\.\pipe\DNetEngine\control";

/// SDDL for the control pipe's security descriptor (contract §Authorization).
///
/// `GA` (full control) for SYSTEM (`SY`) and Administrators (`BA`); `GR|GW`
/// (read + write) for Authenticated Users (`AU`). An explicit `D:` DACL — never a
/// NULL DACL, which would grant everyone everything.
pub fn pipe_sddl() -> &'static str {
    "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
}

/// How much to read from the stream per iteration when the buffer is short.
const READ_CHUNK: usize = 4096;

/// Serve one client until it disconnects or sends a frame that can never decode.
///
/// Returns — rather than lingering — when the client leaves mid-request (IPC-09), and
/// closes the connection on an undecodable frame without panicking (IPC-08). Request
/// dispatch is layered on in T036; this loop owns the framing and lifecycle contract.
pub async fn serve_connection<S>(mut stream: S) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];

    loop {
        match frame::decode(&buf) {
            Ok(Some(frame)) => {
                buf.drain(..frame.consumed);
                // T036 dispatches the decoded request here. For now the framing
                // contract is satisfied by consuming the frame and continuing.
            }
            Ok(None) => {
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| IpcError::InternalError {
                        detail: format!("pipe read failed: {e}"),
                    })?;
                if n == 0 {
                    // Client disconnected; nothing more will arrive.
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                // Undecodable input can never become a valid frame. Close cleanly.
                return Ok(());
            }
        }
    }
}
