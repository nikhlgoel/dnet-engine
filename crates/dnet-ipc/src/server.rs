//! The control pipe: its identity and security descriptor, the framing loop, the
//! request-dispatch core, and (on Windows) the real named-pipe listener that captures
//! each client's identity and gates every request through `authz`.
//!
//! The privilege boundary is enforced here: a request is authorized against the
//! *captured* client identity before the `Service` is asked to act on it, so an
//! unauthorized mutating request never reaches routing state (SC-019).

#[cfg(any(windows, test))]
use std::future::Future;
#[cfg(any(windows, test))]
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast::error::RecvError;
#[cfg(any(windows, test))]
use tokio::sync::Semaphore;

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

/// What the control pipe will put up with from its clients. The pipe is open to every signed-in
/// user, so a client that connects and says nothing, or a crowd of them, must not be able to keep
/// the service from answering the people who need it.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Clients served at once. One more may be connected and waiting to be served (the pipe keeps
    /// an instance listening); a client beyond that is told the pipe is busy and retries.
    pub max_connections: usize,
    /// How long a new client has to send its first byte.
    pub first_request_within: Duration,
    /// How long a client may go without sending anything between, or in the middle of, requests.
    /// Event subscriptions are a separate matter (`stream_events`).
    pub idle_for: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 32,
            first_request_within: Duration::from_secs(10),
            idle_for: Duration::from_secs(120),
        }
    }
}

/// How long to wait before trying again after `failures` failures in a row: 100 ms, doubling, never
/// more than 5 s.
#[cfg(any(windows, test))]
fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(6);
    Duration::from_millis(100u64 << doublings).min(Duration::from_secs(5))
}

/// Something that hands over one client connection at a time.
#[cfg(any(windows, test))]
pub(crate) trait Accept: Send {
    type Conn: Send + 'static;
    fn accept(&mut self) -> impl Future<Output = std::io::Result<Self::Conn>> + Send;
}

/// Accept clients for ever. A failure to accept is logged and retried after a pause; it never ends
/// the loop, because ending it ends the control pipe, and with it the service (the service stops
/// when its listener does), which would drop the tunnel and let traffic out unprotected. At most
/// `limits.max_connections` are served at once; the next client is not accepted until one is done.
#[cfg(any(windows, test))]
pub(crate) async fn accept_forever<A, F, Fut>(mut acceptor: A, limits: Limits, serve: F)
where
    A: Accept,
    F: Fn(A::Conn) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let serve = Arc::new(serve);
    let mut failures = 0u32;
    loop {
        // A slot first, then a place for the next client to connect: the number of instances of the
        // pipe can then never exceed the limit.
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return; // never closed; the loop would otherwise spin
        };
        match acceptor.accept().await {
            Ok(conn) => {
                failures = 0;
                let serve = Arc::clone(&serve);
                tokio::spawn(async move {
                    serve(conn).await;
                    drop(slot);
                });
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                tracing::warn!(%error, failures, "could not accept a control connection; trying again");
                drop(slot);
                tokio::time::sleep(backoff(failures)).await;
            }
        }
    }
}

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
    idle: Option<Duration>,
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
                let read = stream.read(&mut chunk);
                let n = match idle {
                    // Nothing for too long, between requests or in the middle of one: let go.
                    Some(limit) => match tokio::time::timeout(limit, read).await {
                        Ok(read) => read.map_err(io_err)?,
                        Err(_) => return Ok(()),
                    },
                    None => read.await.map_err(io_err)?,
                };
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
    frame_loop(stream, Vec::new(), None, |_| None).await
}

// ---------------------------------------------------------------- Windows pipe

#[cfg(windows)]
mod windows_pipe {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::{accept_forever, frame_loop, io_err, pipe_sddl, Accept, Limits, READ_CHUNK};
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
    ///
    /// A client that sends nothing within `limits.first_request_within` is let go: the identity
    /// cannot be captured until it writes, and a connection that never does would hold a pipe
    /// instance and a task for ever.
    pub async fn serve_pipe_connection(
        mut server: NamedPipeServer,
        service: Arc<dyn Service>,
        limits: Limits,
    ) -> Result<(), IpcError> {
        // Prime the pipe: impersonation requires the client to have written first.
        let mut chunk = [0u8; READ_CHUNK];
        let n = match tokio::time::timeout(limits.first_request_within, server.read(&mut chunk))
            .await
        {
            Ok(read) => read.map_err(io_err)?,
            Err(_) => return Ok(()),
        };
        let initial = chunk[..n].to_vec();

        // Capture identity synchronously — no await runs while impersonating, and the
        // raw handle never crosses an await point, so the future stays Send.
        let identity = {
            let raw = server.as_raw_handle();
            capture_client_identity(raw)
        };

        let service_for_loop = Arc::clone(&service);
        frame_loop(server, initial, Some(limits.idle_for), move |payload| {
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
        serve_pipe_connection(server, service, Limits::default()).await
    }

    /// Hands out pipe instances: one waits for the next client at all times, so there is no window
    /// in which a connect attempt is refused.
    struct PipeAcceptor {
        waiting: Option<NamedPipeServer>,
    }

    impl Accept for PipeAcceptor {
        type Conn = NamedPipeServer;

        async fn accept(&mut self) -> std::io::Result<NamedPipeServer> {
            let server = match self.waiting.take() {
                Some(server) => server,
                None => create_server(false).map_err(|e| std::io::Error::other(e.to_string()))?,
            };
            server.connect().await?;
            // The next instance at once. If it cannot be made now it is made on the next call,
            // after the pause, instead of ending the listener.
            self.waiting = create_server(false).ok();
            Ok(server)
        }
    }

    /// Run the control pipe listener until the runtime stops.
    ///
    /// The first instance is created with "first instance" required: if the pipe's name is already
    /// taken, someone else is squatting on it, and serving from beside them would be wrong, so that
    /// is the one failure that returns. Everything after it is retried (see [`accept_forever`]), and
    /// clients are limited (see [`Limits`]).
    pub async fn run_control_listener(service: Arc<dyn Service>) -> Result<(), IpcError> {
        run_control_listener_with(service, Limits::default()).await
    }

    /// [`run_control_listener`] with the limits given, so a test need not wait for the real ones.
    pub async fn run_control_listener_with(
        service: Arc<dyn Service>,
        limits: Limits,
    ) -> Result<(), IpcError> {
        let first = create_server(true)?;
        let acceptor = PipeAcceptor {
            waiting: Some(first),
        };
        accept_forever(acceptor, limits, move |connected| {
            let service = Arc::clone(&service);
            async move {
                if let Err(e) = serve_pipe_connection(connected, service, limits).await {
                    tracing::warn!(error = %e, "control connection ended with error");
                }
            }
        })
        .await;
        Ok(())
    }
}

#[cfg(windows)]
pub use windows_pipe::{
    accept_one, run_control_listener, run_control_listener_with, serve_pipe_connection,
};

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use tokio::io::{duplex, AsyncWriteExt};

    use super::*;

    // ------------------------------------------------------------------ pauses between failures

    #[test]
    fn the_pause_after_a_failure_doubles_and_is_capped() {
        let pauses: Vec<u64> = (1..=9).map(|n| backoff(n).as_millis() as u64).collect();
        assert_eq!(pauses, [100, 200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
        assert_eq!(backoff(0), Duration::from_millis(100), "never a zero pause");
        assert_eq!(backoff(u32::MAX), Duration::from_secs(5), "and no overflow");
    }

    // ------------------------------------------------------------------ a client that goes quiet

    #[tokio::test(start_paused = true)]
    async fn a_client_that_sends_nothing_is_let_go_after_the_idle_limit() {
        let (_client, server) = duplex(1024);
        let task = tokio::spawn(frame_loop(
            server,
            Vec::new(),
            Some(Duration::from_secs(10)),
            |_| None,
        ));

        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!task.is_finished(), "not yet");
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(task.is_finished());
        assert!(task.await.unwrap().is_ok(), "let go quietly, not an error");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_keeps_talking_is_not_cut_off() {
        let (mut client, server) = duplex(1024);
        let task = tokio::spawn(frame_loop(
            server,
            Vec::new(),
            Some(Duration::from_secs(10)),
            |_| None,
        ));
        let frame = frame::encode(r#"{"request":"GetState"}"#).unwrap();

        // A request every 8 s for a minute: each one restarts the clock.
        for _ in 0..8 {
            client.write_all(&frame).await.unwrap();
            tokio::time::sleep(Duration::from_secs(8)).await;
        }

        assert!(!task.is_finished());
    }

    /// A header that promises a payload which never comes holds a connection as surely as silence.
    #[tokio::test(start_paused = true)]
    async fn a_half_sent_frame_is_let_go_too() {
        let (mut client, server) = duplex(1024);
        let task = tokio::spawn(frame_loop(
            server,
            Vec::new(),
            Some(Duration::from_secs(10)),
            |_| None,
        ));
        client.write_all(&[100, 0, 0, 0, b'{']).await.unwrap(); // promises 100 bytes, sends 1

        tokio::time::sleep(Duration::from_secs(11)).await;

        assert!(task.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn without_an_idle_limit_a_quiet_client_is_kept() {
        let (_client, server) = duplex(1024);
        let task = tokio::spawn(frame_loop(server, Vec::new(), None, |_| None));
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(
            !task.is_finished(),
            "the framing-contract tests rely on this"
        );
    }

    // ------------------------------------------------------------------ the accept loop

    /// Hands out scripted results, then waits for ever.
    struct Script {
        events: VecDeque<io::Result<u32>>,
        calls: Arc<AtomicUsize>,
    }

    impl Accept for Script {
        type Conn = u32;
        fn accept(&mut self) -> impl Future<Output = io::Result<u32>> + Send {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.events.pop_front();
            async move {
                match next {
                    Some(result) => result,
                    None => std::future::pending().await,
                }
            }
        }
    }

    fn failure() -> io::Result<u32> {
        Err(io::Error::other("no instance could be made"))
    }

    /// The service stops when its listener ends, and stopping drops the tunnel: a listener that
    /// gave up on a failure would let anyone who could cause one take the protection away.
    #[tokio::test(start_paused = true)]
    async fn failures_to_accept_do_not_end_the_listener() {
        let calls = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(Mutex::new(Vec::new()));
        let acceptor = Script {
            events: VecDeque::from([failure(), failure(), failure(), Ok(7)]),
            calls: Arc::clone(&calls),
        };
        let seen = Arc::clone(&served);
        let task = tokio::spawn(accept_forever(acceptor, Limits::default(), move |conn| {
            let seen = Arc::clone(&seen);
            async move { seen.lock().unwrap().push(conn) }
        }));

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(*served.lock().unwrap(), [7], "served after three failures");
        assert!(!task.is_finished(), "and still listening");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_accept_is_not_retried_in_a_tight_loop() {
        let calls = Arc::new(AtomicUsize::new(0));
        let acceptor = Script {
            events: (0..1000).map(|_| failure()).collect(),
            calls: Arc::clone(&calls),
        };
        tokio::spawn(accept_forever(
            acceptor,
            Limits::default(),
            |_: u32| async {},
        ));

        tokio::time::sleep(Duration::from_secs(10)).await;

        let tries = calls.load(Ordering::SeqCst);
        assert!(
            (5..=12).contains(&tries),
            "{tries} attempts in 10 s: paused and backed off, neither spinning nor stopped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_more_clients_are_accepted_than_the_limit_allows() {
        let calls = Arc::new(AtomicUsize::new(0));
        let acceptor = Script {
            events: (0..10).map(Ok).collect(),
            calls: Arc::clone(&calls),
        };
        let limits = Limits {
            max_connections: 3,
            ..Limits::default()
        };
        // Every client holds its connection for a minute.
        tokio::spawn(accept_forever(acceptor, limits, |_: u32| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }));

        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "three slots, three accepts; no instance of the pipe beyond the limit"
        );

        // As clients finish, the next are let in.
        tokio::time::sleep(Duration::from_secs(40)).await;
        assert!(calls.load(Ordering::SeqCst) > 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_panics_does_not_take_the_listener_with_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let acceptor = Script {
            events: VecDeque::from([Ok(1), Ok(2)]),
            calls: Arc::clone(&calls),
        };
        let served = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&served);
        let task = tokio::spawn(accept_forever(acceptor, Limits::default(), move |conn| {
            let seen = Arc::clone(&seen);
            async move {
                if conn == 1 {
                    panic!("a bug in serving one client");
                }
                seen.lock().unwrap().push(conn);
            }
        }));

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(*served.lock().unwrap(), [2]);
        assert!(!task.is_finished());
    }
}
