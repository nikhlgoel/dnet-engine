//! The control pipe: its identity and security descriptor, the framing loop, the
//! request-dispatch core, and (on Windows) the real named-pipe listener that captures
//! each client's identity and gates every request through `authz`.
//!
//! The privilege boundary is enforced here: a request is authorized against the
//! *captured* client identity before the `Service` is asked to act on it, so an
//! unauthorized mutating request never reaches routing state (SC-019).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::authz::{authorize, ClientIdentity, ConsoleSession};
use crate::frame;
use crate::protocol::{decode_request, encode_ipc_error, IpcError};
use crate::service::Service;

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

fn io_err(e: std::io::Error) -> IpcError {
    IpcError::InternalError {
        detail: format!("pipe I/O failed: {e}"),
    }
}

/// Authorize a single decoded request against the captured identity, dispatch it if
/// permitted, and return the wire response.
///
/// This is the heart of the privilege boundary and is deliberately pure and
/// platform-independent: the `Service` is only ever reached for a request the caller
/// was authorized to make, so an unauthorized mutation cannot change routing state.
pub fn dispatch_frame(
    payload: &str,
    identity: &ClientIdentity,
    console: Option<&ConsoleSession>,
    service: &dyn Service,
) -> String {
    match decode_request(payload) {
        Ok(request) => match authorize(request.class(), identity, console) {
            Ok(()) => service
                .dispatch(&request)
                .unwrap_or_else(|e| encode_ipc_error(&e)),
            Err(e) => encode_ipc_error(&e),
        },
        Err(e) => encode_ipc_error(&e),
    }
}

/// Run the framing loop over a stream, calling `on_frame` for each decoded frame and
/// writing back any response it returns.
///
/// Ends — rather than lingering — when the peer disconnects (IPC-09), and closes the
/// connection on an undecodable frame without panicking (IPC-08). `initial` seeds the
/// read buffer with bytes already taken from the stream (used after a priming read).
pub(crate) async fn frame_loop<S, F>(
    mut stream: S,
    mut buf: Vec<u8>,
    mut on_frame: F,
) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&str) -> Option<String>,
{
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match frame::decode(&buf) {
            Ok(Some(frame)) => {
                let payload = frame.payload.clone();
                buf.drain(..frame.consumed);
                if let Some(response) = on_frame(&payload) {
                    let bytes = frame::encode(&response).map_err(|e| IpcError::InternalError {
                        detail: format!("failed to encode response: {e}"),
                    })?;
                    stream.write_all(&bytes).await.map_err(io_err)?;
                }
            }
            Ok(None) => {
                let n = stream.read(&mut chunk).await.map_err(io_err)?;
                if n == 0 {
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

/// Serve one client, consuming frames without dispatching them.
///
/// Retained for the framing/lifecycle contract tests (IPC-08, IPC-09); the dispatching
/// path is [`serve_pipe_connection`].
pub async fn serve_connection<S>(stream: S) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    frame_loop(stream, Vec::new(), |_| None).await
}

// ---------------------------------------------------------------- Windows pipe

#[cfg(windows)]
mod windows_pipe {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::{frame_loop, io_err, pipe_sddl, READ_CHUNK};
    use crate::protocol::IpcError;
    use crate::service::Service;
    use crate::win::{capture_client_identity, SecurityAttributes};

    fn win_err(e: windows::core::Error) -> IpcError {
        IpcError::InternalError {
            detail: format!("pipe security descriptor: {e}"),
        }
    }

    /// Create one control-pipe server instance, applying the SDDL descriptor.
    ///
    /// The descriptor is copied into the pipe object at creation, so it is freed
    /// before returning — the returned server owns no borrowed security state.
    fn create_server(first: bool) -> Result<NamedPipeServer, IpcError> {
        let security = SecurityAttributes::from_sddl(pipe_sddl()).map_err(win_err)?;
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        // SAFETY: `security` points at a valid SECURITY_ATTRIBUTES that lives across
        // this call; CreateNamedPipe copies the descriptor, so it may be freed after.
        let server = unsafe {
            options.create_with_security_attributes_raw(
                super::PIPE_NAME,
                security.as_ptr() as *mut std::ffi::c_void,
            )
        }
        .map_err(io_err)?;
        drop(security);
        Ok(server)
    }

    /// Serve one connected pipe client: prime a read, capture its identity by
    /// impersonation, then dispatch its requests gated on that identity.
    pub async fn serve_pipe_connection(
        mut server: NamedPipeServer,
        service: Arc<dyn Service>,
    ) -> Result<(), IpcError> {
        // Prime the pipe: impersonation requires the client to have written first.
        let mut chunk = [0u8; READ_CHUNK];
        let n = server.read(&mut chunk).await.map_err(io_err)?;
        let initial = chunk[..n].to_vec();

        // Capture identity synchronously — no await runs while impersonating, and the
        // raw handle never crosses an await point, so the future stays Send.
        let identity = {
            let raw = server.as_raw_handle();
            capture_client_identity(raw)
        };

        let service_for_loop = Arc::clone(&service);
        frame_loop(server, initial, move |payload| {
            let console = service_for_loop.console_session();
            Some(super::dispatch_frame(
                payload,
                &identity,
                console.as_ref(),
                &*service_for_loop,
            ))
        })
        .await
    }

    /// Accept and serve exactly one connection on the control pipe.
    ///
    /// Used by the T039 attack test; the production entry point is
    /// [`run_control_listener`].
    pub async fn accept_one(service: Arc<dyn Service>) -> Result<(), IpcError> {
        let server = create_server(true)?;
        server.connect().await.map_err(io_err)?;
        serve_pipe_connection(server, service).await
    }

    /// Run the control pipe listener until the runtime stops.
    ///
    /// Keeps one idle instance waiting for the next client at all times, so there is no
    /// window in which a connect attempt is refused, and serves each accepted
    /// connection on its own task.
    pub async fn run_control_listener(service: Arc<dyn Service>) -> Result<(), IpcError> {
        let mut server = create_server(true)?;
        loop {
            server.connect().await.map_err(io_err)?;
            let connected = server;
            server = create_server(false)?;
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                if let Err(e) = serve_pipe_connection(connected, service).await {
                    tracing::warn!(error = %e, "control connection ended with error");
                }
            });
        }
    }
}

#[cfg(windows)]
pub use windows_pipe::{accept_one, run_control_listener, serve_pipe_connection};
