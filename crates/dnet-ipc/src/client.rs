//! T127 — the client half of the control pipe: what `dnetctl` and, later, the tray speak.
//!
//! It is the mirror of `server`: the same framing ([`crate::frame`]), requests written by
//! [`crate::protocol::encode_request`], and replies read **as untrusted input**. A reply is either
//! the daemon's answer or a refusal (`{"error": ...}`); a frame that is neither, that is too large,
//! or that is not JSON is an error here and never a panic, because the other end is a privileged
//! process that may be a different version, or not the one expected.
//!
//! Everything is generic over a byte stream, so the client is tested against the real server
//! dispatch in memory. Only [`connect`] is Windows-specific.

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame;
use crate::protocol::{encode_request, Request};

/// Why a request could not be made or its reply not read. None of these carries more than a short
/// description: no payload is echoed, because a reply may hold anything the daemon chose to say.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The control pipe could not be opened: the service is not running, or not for this user.
    #[error("{0}")]
    Unreachable(String),
    /// Reading or writing the stream failed.
    #[error("the connection to the service failed ({0})")]
    Io(String),
    /// The service closed the connection before it answered.
    #[error("the service closed the connection before it answered")]
    Closed,
    /// The reply was not a frame this client accepts.
    #[error("the service sent something this client cannot read ({0})")]
    Malformed(String),
}

/// SYSTEM and Administrators: the accounts the service runs as (the first when installed, the
/// second in a development run from an elevated shell).
const SERVICE_OWNER_SIDS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// Whether the owner of the control pipe is an account the real service could be running as.
pub fn is_service_owner(sid: &str) -> bool {
    SERVICE_OWNER_SIDS.contains(&sid)
}

/// Whom a client is willing to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Only a pipe owned by SYSTEM or Administrators. What a user needs and the tray must use.
    ServiceOwnedOnly,
    /// Any process that created the pipe. Development only: it lets an unprivileged `dnetd` be
    /// driven, and it also lets any local process pose as the service.
    AnyServer,
}

/// The daemon declined a request, and said why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The stable wire code, such as `ServiceBusy` or `Unauthorized`.
    pub code: String,
    /// What to do about it, in words.
    pub detail: String,
    /// Whether trying again later may succeed.
    pub retryable: bool,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.code)
    }
}

/// The daemon's reply to one request.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// The request was carried out; this is the answer, as the daemon sent it.
    Done(Value),
    /// The request was refused.
    Refused(Refusal),
}

/// Read a reply payload as untrusted input.
pub fn classify_reply(payload: &str) -> Result<Reply, ClientError> {
    let value: Value =
        serde_json::from_str(payload).map_err(|_| ClientError::Malformed("not JSON".into()))?;
    let Some(object) = value.as_object() else {
        return Err(ClientError::Malformed("not a JSON object".into()));
    };
    match object.get("error") {
        None => Ok(Reply::Done(value)),
        Some(code) => {
            let code = code
                .as_str()
                .filter(|code| !code.is_empty())
                .ok_or_else(|| ClientError::Malformed("an error without a code".into()))?;
            let detail = object
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Ok(Reply::Refused(Refusal {
                code: code.to_owned(),
                detail: detail.to_owned(),
                retryable: object
                    .get("retryable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }))
        }
    }
}

/// A stream with a frame buffer: reads whole frames, however the bytes arrive.
pub struct Connection<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// Send one request frame.
    pub async fn send(&mut self, request: &Request) -> Result<(), ClientError> {
        let bytes = frame::encode(&encode_request(request))
            .map_err(|e| ClientError::Malformed(e.to_string()))?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| ClientError::Io(e.kind().to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| ClientError::Io(e.kind().to_string()))
    }

    /// The next frame's payload, or `None` if the service closed the stream cleanly between
    /// frames. A close in the middle of a frame is an error.
    pub async fn next_frame(&mut self) -> Result<Option<String>, ClientError> {
        let mut chunk = [0u8; 4096];
        loop {
            match frame::decode(&self.buf) {
                Ok(Some(found)) => {
                    self.buf.drain(..found.consumed);
                    return Ok(Some(found.payload));
                }
                Ok(None) => {}
                // An oversized or non-UTF-8 frame can never become valid. Not echoed.
                Err(e) => return Err(ClientError::Malformed(e.to_string())),
            }
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| ClientError::Io(e.kind().to_string()))?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ClientError::Closed)
                };
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Send one request and read its reply.
    pub async fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        self.send(request).await?;
        match self.next_frame().await? {
            Some(payload) => classify_reply(&payload),
            None => Err(ClientError::Closed),
        }
    }
}

/// Refuse a pipe that the real service did not create (see [`Trust`]).
#[cfg(windows)]
fn check_server(handle: std::os::windows::io::RawHandle, trust: Trust) -> Result<(), ClientError> {
    if trust == Trust::AnyServer {
        return Ok(());
    }
    match crate::win::pipe_owner_sid(handle) {
        Some(owner) if is_service_owner(&owner) => Ok(()),
        // The owner is named so that a person can see whose pipe it is. A SID is not a secret.
        Some(owner) => Err(ClientError::Unreachable(format!(
            "the control pipe is not owned by the DNet Engine service (it belongs to {owner}); \
             refusing to talk to it. If this is a development run, pass --allow-unprivileged-service"
        ))),
        None => Err(ClientError::Unreachable(
            "could not tell who owns the control pipe; refusing to talk to it".to_owned(),
        )),
    }
}

/// Open the control pipe and check that the real service is behind it. The service keeps one
/// instance waiting at all times, but a burst of clients can find it momentarily busy, so a busy
/// pipe is retried briefly.
#[cfg(windows)]
pub async fn connect(
    trust: Trust,
) -> Result<Connection<tokio::net::windows::named_pipe::NamedPipeClient>, ClientError> {
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;

    // ERROR_PIPE_BUSY: every instance is in use right now.
    const PIPE_BUSY: i32 = 231;
    let mut tries = 0;
    loop {
        match ClientOptions::new().open(crate::server::PIPE_NAME) {
            Ok(pipe) => {
                check_server(pipe.as_raw_handle(), trust)?;
                return Ok(Connection::new(pipe));
            }
            Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && tries < 20 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                let why = match e.kind() {
                    std::io::ErrorKind::NotFound => "the DNet Engine service is not running (the \
                         control pipe does not exist); start the service and try again"
                        .to_owned(),
                    std::io::ErrorKind::PermissionDenied => {
                        "this account may not use the DNet Engine control pipe".to_owned()
                    }
                    other => format!("the control pipe could not be opened ({other})"),
                };
                return Err(ClientError::Unreachable(why));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use tokio::io::duplex;

    use crate::authz::{ClientIdentity, ConsoleSession};
    use crate::protocol::{IpcError, Request};
    use crate::server::{dispatch_request, Reply as ServerReply};
    use crate::service::Service;

    /// A service that answers like the daemon would, and records what reached it.
    struct Stub {
        seen: Mutex<Vec<String>>,
        connect_result: Result<String, IpcError>,
    }

    impl Service for Stub {
        fn console_session(&self) -> Option<ConsoleSession> {
            Some(ConsoleSession {
                session_id: 1,
                user_sid: "S-1-5-21-1".into(),
            })
        }
        fn dispatch(&self, request: &Request) -> Result<String, IpcError> {
            self.seen.lock().unwrap().push(encode_request(request));
            match request {
                Request::Connect { .. } => self.connect_result.clone(),
                _ => Ok(r#"{"status":"Disconnected"}"#.to_string()),
            }
        }
    }

    fn stub(connect_result: Result<String, IpcError>) -> Stub {
        Stub {
            seen: Mutex::new(Vec::new()),
            connect_result,
        }
    }

    /// The real server dispatch (authorization included) on the far end of an in-memory stream.
    fn daemon(service: Stub, authenticated: bool) -> Connection<tokio::io::DuplexStream> {
        let (client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let identity = ClientIdentity {
                sid: "S-1-5-21-1".into(),
                session_id: 1,
                authenticated,
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match frame::decode(&buf) {
                    Ok(Some(found)) => {
                        buf.drain(..found.consumed);
                        let console = service.console_session();
                        if let ServerReply::Response(reply) =
                            dispatch_request(&found.payload, &identity, console.as_ref(), &service)
                        {
                            let bytes = frame::encode(&reply).unwrap();
                            if server.write_all(&bytes).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(None) => match server.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    },
                    Err(_) => return,
                }
            }
        });
        Connection::new(client)
    }

    fn connect_request() -> Request {
        Request::Connect {
            acknowledge_tier2: false,
            profile: None,
            endpoint: None,
        }
    }

    // -------------------------------------------------- who is on the other end

    #[test]
    fn only_system_and_administrators_count_as_the_service() {
        assert!(is_service_owner("S-1-5-18"));
        assert!(is_service_owner("S-1-5-32-544"));
        for not in [
            "",
            "S-1-1-0",
            "S-1-5-21-4016204387-3008203602-4053404650-1001",
            "S-1-5-181",
            "S-1-5-18 ",
            "s-1-5-18",
            "S-1-5-32-545",
        ] {
            assert!(!is_service_owner(not), "{not:?} must not count");
        }
    }

    /// The real thing: a pipe created in this process, read through a client handle. The owner is
    /// whoever created it, and the check agrees with the policy either way: an ordinary
    /// (unelevated) test run owns its pipes itself and is refused, an elevated one is Administrators
    /// and is accepted.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_owned_by_an_ordinary_user_is_refused_unless_development_says_otherwise() {
        use std::os::windows::io::AsRawHandle;
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let name = format!(
            r"\\.\pipe\dnet-test-owner-{}",
            uuid::Uuid::new_v4().simple()
        );
        let _server = ServerOptions::new().create(&name).unwrap();
        let client = ClientOptions::new().open(&name).unwrap();
        let handle = client.as_raw_handle();

        let owner =
            crate::win::pipe_owner_sid(handle).expect("the owner of our own pipe is readable");
        assert!(owner.starts_with("S-1-"), "{owner}");

        let verdict = check_server(handle, Trust::ServiceOwnedOnly);
        if is_service_owner(&owner) {
            assert!(verdict.is_ok(), "{verdict:?}");
        } else {
            let error = verdict.unwrap_err();
            assert!(matches!(error, ClientError::Unreachable(_)), "{error:?}");
            assert!(error.to_string().contains("not owned"), "{error}");
            assert!(
                error.to_string().contains("--allow-unprivileged-service"),
                "it says how to proceed in development: {error}"
            );
        }
        assert!(check_server(handle, Trust::AnyServer).is_ok());
    }

    #[tokio::test]
    async fn a_request_the_daemon_answers_comes_back_as_its_answer() {
        let mut daemon = daemon(stub(Ok(r#"{"accepted":true}"#.into())), true);

        let state = daemon.call(&Request::GetState).await.unwrap();
        assert_eq!(
            state,
            Reply::Done(serde_json::json!({ "status": "Disconnected" }))
        );

        let connect = daemon.call(&connect_request()).await.unwrap();
        assert_eq!(
            connect,
            Reply::Done(serde_json::json!({ "accepted": true }))
        );
    }

    #[tokio::test]
    async fn a_refusal_carries_its_code_its_words_and_whether_to_retry() {
        let mut daemon = daemon(stub(Err(IpcError::ServiceBusy)), true);

        let Reply::Refused(refusal) = daemon.call(&connect_request()).await.unwrap() else {
            panic!("expected a refusal")
        };

        assert_eq!(refusal.code, "ServiceBusy");
        assert!(!refusal.detail.is_empty());
        assert!(refusal.retryable);
    }

    /// The privilege boundary seen from the client: an unauthenticated caller is told so.
    #[tokio::test]
    async fn an_unauthorized_caller_is_refused_with_a_reason() {
        let mut daemon = daemon(stub(Ok("{}".into())), false);

        let Reply::Refused(refusal) = daemon.call(&Request::GetState).await.unwrap() else {
            panic!("expected a refusal")
        };

        assert_eq!(refusal.code, "Unauthorized");
        assert!(refusal.detail.contains("authenticated"), "{refusal}");
    }

    #[tokio::test]
    async fn several_requests_share_one_connection() {
        let mut daemon = daemon(stub(Ok("{}".into())), true);
        for _ in 0..5 {
            assert!(matches!(
                daemon.call(&Request::GetState).await.unwrap(),
                Reply::Done(_)
            ));
        }
    }

    // -------------------------------------------------- the other end is untrusted

    async fn reply_with(bytes: Vec<u8>) -> Result<Reply, ClientError> {
        let (client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut sink = [0u8; 256];
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(&bytes).await;
            // Dropped here: the stream closes.
        });
        Connection::new(client).call(&Request::GetState).await
    }

    fn framed(text: &str) -> Vec<u8> {
        frame::encode(text).unwrap()
    }

    #[tokio::test]
    async fn text_that_is_not_json_is_an_error_that_does_not_echo_it() {
        let error = reply_with(framed("SECRET-LOOKING-TEXT")).await.unwrap_err();
        assert!(matches!(error, ClientError::Malformed(_)), "{error:?}");
        assert!(!error.to_string().contains("SECRET"), "{error}");
    }

    #[tokio::test]
    async fn json_that_is_not_an_object_is_an_error() {
        for text in ["[1,2]", "\"hello\"", "42", "null"] {
            let error = reply_with(framed(text)).await.unwrap_err();
            assert!(
                matches!(error, ClientError::Malformed(_)),
                "{text}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_error_without_a_usable_code_is_an_error() {
        for text in [r#"{"error":""}"#, r#"{"error":7}"#, r#"{"error":null}"#] {
            let error = reply_with(framed(text)).await.unwrap_err();
            assert!(
                matches!(error, ClientError::Malformed(_)),
                "{text}: {error:?}"
            );
        }
    }

    /// A hostile length prefix is refused before the payload is waited for or allocated.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_without_reading_it() {
        let mut bytes = (u32::MAX - 16).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"junk");
        let error = reply_with(bytes).await.unwrap_err();
        assert!(matches!(error, ClientError::Malformed(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_frame_that_is_not_utf8_is_an_error() {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        let error = reply_with(bytes).await.unwrap_err();
        assert!(matches!(error, ClientError::Malformed(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_service_that_closes_without_answering_is_closed() {
        let error = reply_with(Vec::new()).await.unwrap_err();
        assert_eq!(error, ClientError::Closed);
    }

    #[tokio::test]
    async fn a_service_that_closes_in_the_middle_of_a_frame_is_closed() {
        let mut bytes = framed(r#"{"status":"Connected"}"#);
        bytes.truncate(bytes.len() - 3);
        let error = reply_with(bytes).await.unwrap_err();
        assert_eq!(error, ClientError::Closed);
    }

    /// The reply arrives a byte at a time, as a slow pipe may deliver it.
    #[tokio::test]
    async fn a_reply_that_arrives_in_pieces_is_assembled() {
        let (client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut sink = [0u8; 256];
            let _ = server.read(&mut sink).await;
            for byte in framed(r#"{"status":"Connected"}"#) {
                let _ = server.write_all(&[byte]).await;
                tokio::task::yield_now().await;
            }
        });
        let reply = Connection::new(client)
            .call(&Request::GetState)
            .await
            .unwrap();
        assert_eq!(
            reply,
            Reply::Done(serde_json::json!({ "status": "Connected" }))
        );
    }
}
