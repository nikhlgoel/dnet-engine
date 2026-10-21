//! The control pipe: its identity and security descriptor, the framing loop, the
//! request-dispatch core, and (on Windows) the real named-pipe listener that captures
//! each client's identity and gates every request through `authz`.
//!
//! The privilege boundary is enforced here: a request is authorized against the
//! *captured* client identity before the `Service` is asked to act on it, so an
//! unauthorized mutating request never reaches routing state (SC-019).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast::error::RecvError;

use crate::authz::{authorize, ClientIdentity, ConsoleSession};
use crate::frame;
use crate::protocol::{decode_request, encode_ipc_error, IpcError, Request};
use crate::service::Service;
use crate::wire::{events_lost, Subscription};

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
            Ok(()) => answered_here(&request).unwrap_or_else(|| {
                service
                    .dispatch(&request)
                    .unwrap_or_else(|e| encode_ipc_error(&e))
            }),
            Err(e) => encode_ipc_error(&e),
        },
        Err(e) => encode_ipc_error(&e),
    }
}

/// The requests the server answers itself, because the answer depends on no state: the protocol
/// version (T132). Only reached for a caller already authorized to ask.
fn answered_here(request: &Request) -> Option<String> {
    match request {
        Request::GetVersion => Some(crate::version::reply()),
        _ => None,
    }
}

/// What the server does with one request.
pub enum Reply {
    /// Write this frame and keep serving requests on the connection.
    Response(String),
    /// The connection becomes a one-way event stream (see [`stream_events`]).
    Stream(Subscription),
}

/// Authorize one decoded request against the captured identity and act on it: a `Subscribe`
/// becomes a stream (when the service offers one), every other request is dispatched.
///
/// Like [`dispatch_frame`] this is pure and platform-independent, and the `Service` is reached
/// only for a request the caller was authorized to make.
pub fn dispatch_request(
    payload: &str,
    identity: &ClientIdentity,
    console: Option<&ConsoleSession>,
    service: &dyn Service,
) -> Reply {
    let request = match decode_request(payload) {
        Ok(request) => request,
        Err(e) => return Reply::Response(encode_ipc_error(&e)),
    };
    if let Err(e) = authorize(request.class(), identity, console) {
        return Reply::Response(encode_ipc_error(&e));
    }
    if matches!(request, Request::Subscribe) {
        return match service.subscribe() {
            Ok(subscription) => Reply::Stream(subscription),
            Err(e) => Reply::Response(encode_ipc_error(&e)),
        };
    }
    if let Some(answer) = answered_here(&request) {
        return Reply::Response(answer);
    }
    Reply::Response(
        service
            .dispatch(&request)
            .unwrap_or_else(|e| encode_ipc_error(&e)),
    )
}

/// How long one write to a subscriber may take before the subscription is abandoned.
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve an event subscription: an acknowledgement, the session so far, then live events.
///
/// The connection is **one-way** from here on. Any byte the client sends afterwards, including
/// bytes already buffered behind the `Subscribe` frame (`leftover`), ends the subscription with
/// an `InvalidRequest` frame saying why: a client that has something else to ask opens another
/// connection. That keeps the read side from
/// needing a buffer, and a hostile client from being able to make it grow.
///
/// A subscriber that falls behind is told how many events it missed ([`events_lost`]) and
/// carries on. One that stops reading altogether is dropped after [`STREAM_WRITE_TIMEOUT`], so
/// it cannot hold a task and a subscriber slot forever. The subscription ends, and its slot is
/// freed, when the client disconnects (IPC-09).
pub async fn stream_events<S>(
    stream: S,
    leftover: Vec<u8>,
    subscription: Subscription,
) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream_events_with(stream, leftover, subscription, STREAM_WRITE_TIMEOUT).await
}

/// [`stream_events`] with the write timeout given, so tests need not wait ten seconds.
pub async fn stream_events_with<S>(
    mut stream: S,
    leftover: Vec<u8>,
    mut subscription: Subscription,
    write_timeout: Duration,
) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn send<S: AsyncWrite + Unpin>(
        stream: &mut S,
        payload: &str,
        write_timeout: Duration,
    ) -> Result<(), IpcError> {
        let bytes = frame::encode(payload).map_err(|e| IpcError::InternalError {
            detail: format!("failed to encode an event frame: {e}"),
        })?;
        match tokio::time::timeout(write_timeout, stream.write_all(&bytes)).await {
            Ok(written) => written.map_err(io_err),
            Err(_) => Err(IpcError::InternalError {
                detail: "the client stopped reading events, so its subscription was closed"
                    .to_string(),
            }),
        }
    }

    // The refusal a client gets for speaking on a one-way connection: said, then closed.
    let one_way = || {
        encode_ipc_error(&IpcError::InvalidRequest {
            detail: "an event subscription is one-way; open another connection to send requests"
                .to_string(),
        })
    };

    let ack = serde_json::json!({
        "subscribed": true,
        "backlog": subscription.backlog.len(),
    })
    .to_string();
    send(&mut stream, &ack, write_timeout).await?;
    if !leftover.is_empty() {
        send(&mut stream, &one_way(), write_timeout).await?;
        return Ok(());
    }
    for event in std::mem::take(&mut subscription.backlog) {
        send(&mut stream, &event, write_timeout).await?;
    }

    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            biased;
            // A client that disconnects ends the stream quietly; one that speaks is told why
            // it is being closed.
            read = stream.read(&mut probe) => {
                if matches!(read, Ok(n) if n > 0) {
                    send(&mut stream, &one_way(), write_timeout).await?;
                }
                return Ok(());
            }
            event = subscription.live.recv() => match event {
                Ok(frame) => send(&mut stream, &frame, write_timeout).await?,
                Err(RecvError::Lagged(missed)) => {
                    send(&mut stream, &events_lost(missed), write_timeout).await?;
                }
                Err(RecvError::Closed) => return Ok(()),
            },
        }
    }
}

/// Run the framing loop over a stream, calling `on_frame` for each decoded frame and
/// writing back any response it returns.
///
/// Ends — rather than lingering — when the peer disconnects (IPC-09), and closes the
/// connection on an undecodable frame without panicking (IPC-08). `initial` seeds the
/// read buffer with bytes already taken from the stream (used after a priming read). A
/// [`Reply::Stream`] turns the rest of the connection into an event stream.
pub(crate) async fn frame_loop<S, F>(
    mut stream: S,
    mut buf: Vec<u8>,
    mut on_frame: F,
) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&str) -> Option<Reply>,
{
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match frame::decode(&buf) {
            Ok(Some(frame)) => {
                let payload = frame.payload.clone();
                buf.drain(..frame.consumed);
                match on_frame(&payload) {
                    None => {}
                    Some(Reply::Response(response)) => {
                        let bytes =
                            frame::encode(&response).map_err(|e| IpcError::InternalError {
                                detail: format!("failed to encode response: {e}"),
                            })?;
                        stream.write_all(&bytes).await.map_err(io_err)?;
                    }
                    Some(Reply::Stream(subscription)) => {
                        return stream_events(stream, buf, subscription).await;
                    }
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
            Some(super::dispatch_request(
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
