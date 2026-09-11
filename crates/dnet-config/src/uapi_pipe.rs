//! T050 (OS half) — the real UAPI named-pipe client.
//!
//! Connects to the AmneziaWG core's UAPI pipe, writes one framed `set` operation, and
//! reads the `errno=N` reply. The pipe path, framing, and reply format are verified
//! against the pinned core (`ipc/uapi_windows.go`, `device/uapi.go` `IpcHandle`) at
//! commit `b5928efb` — note the leaf directory is `AmneziaWG`, not the upstream name the
//! earlier spec text assumed.
//!
//! Errors never carry request content, and the framed operation (which contains the
//! private key) is only ever written to the pipe (AW-05, AWG-06).

#![cfg(windows)]

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use crate::uapi::{parse_set_response, UapiError, UapiRequest};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// The UAPI pipe for an adapter, as the pinned core creates it. Only Administrators and
/// SYSTEM can open it (the core sets a restrictive descriptor on the listener).
pub fn pipe_path(adapter: &str) -> String {
    format!(r"\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\{adapter}")
}

fn io_error(e: std::io::Error) -> UapiError {
    // `kind()` only — never the payload, which may include key material.
    UapiError::Io(e.kind().to_string())
}

/// Connect, retrying while the pipe does not exist yet or all instances are busy.
async fn connect(path: &str, timeout: Duration) -> Result<NamedPipeClient, UapiError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match ClientOptions::new().open(path) {
            Ok(client) => return Ok(client),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PIPE_BUSY)
                ) =>
            {
                if tokio::time::Instant::now() >= deadline {
                    return Err(UapiError::PipeUnavailable);
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
            Err(e) => return Err(io_error(e)),
        }
    }
}

/// Wait until the core is listening on its UAPI pipe — the signal that the adapter
/// exists (AW-01) — or fail after `timeout` rather than waiting forever (SUP-06).
pub async fn wait_for_pipe(path: &str, timeout: Duration) -> Result<(), UapiError> {
    connect(path, timeout).await.map(drop)
}

/// Send one `set` operation and wait for its `errno` reply.
pub async fn set(path: &str, request: &UapiRequest, timeout: Duration) -> Result<(), UapiError> {
    let operation = async {
        let client = connect(path, timeout).await?;
        let (reader, mut writer) = tokio::io::split(client);
        writer
            .write_all(request.to_set_operation().as_bytes())
            .await
            .map_err(io_error)?;
        writer.flush().await.map_err(io_error)?;

        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.map_err(io_error)? == 0 || line == "\n" {
                break;
            }
            response.push_str(&line);
        }
        parse_set_response(&response)
    };
    tokio::time::timeout(timeout, operation)
        .await
        .unwrap_or(Err(UapiError::Timeout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ServerOptions;

    fn test_pipe(tag: &str) -> String {
        format!(r"\\.\pipe\dnet-uapi-test-{}-{tag}", std::process::id())
    }

    /// A stand-in for the core's `IpcHandle`: reads one operation, replies `reply`.
    fn serve_once(path: &str, reply: &'static str) -> tokio::task::JoinHandle<String> {
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(path)
            .unwrap();
        tokio::spawn(async move {
            server.connect().await.unwrap();
            let (reader, mut writer) = tokio::io::split(server);
            let mut reader = BufReader::new(reader);
            let mut got = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                if line == "\n" {
                    break;
                }
                got.push_str(&line);
            }
            writer.write_all(reply.as_bytes()).await.unwrap();
            got
        })
    }

    #[test]
    fn pipe_path_matches_the_pinned_core() {
        assert_eq!(
            pipe_path("awg0"),
            r"\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\awg0"
        );
    }

    #[tokio::test]
    async fn set_writes_the_framed_operation_over_a_real_pipe() {
        let path = test_pipe("ok");
        let server = serve_once(&path, "errno=0\n\n");
        let mut req = UapiRequest::new();
        req.push_secret("private_key", "abcd")
            .push("replace_peers", "true");

        set(&path, &req, Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            server.await.unwrap(),
            "set=1\nprivate_key=abcd\nreplace_peers=true\n"
        );
    }

    #[tokio::test]
    async fn a_rejection_surfaces_the_errno_without_request_content() {
        let path = test_pipe("reject");
        let _server = serve_once(&path, "errno=-22\n\n");
        let mut req = UapiRequest::new();
        req.push_secret("private_key", "SECRETMATERIAL");

        let err = set(&path, &req, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(err, UapiError::Rejected(-22));
        assert!(!err.to_string().contains("SECRETMATERIAL"));
    }

    #[tokio::test]
    async fn a_missing_pipe_fails_at_the_timeout() {
        let path = test_pipe("absent");
        assert_eq!(
            wait_for_pipe(&path, Duration::from_millis(200)).await,
            Err(UapiError::PipeUnavailable)
        );
    }
}
