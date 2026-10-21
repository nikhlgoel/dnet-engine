//! The real control pipe under a crowd of clients that say nothing.
//!
//! The pipe is open to every signed-in user, and the service stops when its listener ends, so a
//! local user who could wedge or end the listener could take the tunnel down and let traffic out
//! unprotected. This runs the real Windows listener with short limits, fills it with silent
//! clients, and checks that they are let go, that the listener lives, and that a proper client is
//! then served.
//!
//! Its own test binary: the pipe name is fixed, so it must not run beside the others.

#![cfg(windows)]

use std::sync::Arc;
use std::time::Duration;

use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::frame;
use dnet_ipc::protocol::{IpcError, Request};
use dnet_ipc::server::{run_control_listener_with, Limits, PIPE_NAME};
use dnet_ipc::service::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

struct Nothing;

impl Service for Nothing {
    fn console_session(&self) -> Option<ConsoleSession> {
        None
    }
    fn dispatch(&self, _: &Request) -> Result<String, IpcError> {
        Ok("{}".to_string())
    }
}

async fn connect(deadline: Duration) -> Option<NamedPipeClient> {
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until {
        if let Ok(client) = ClientOptions::new().open(PIPE_NAME) {
            return Some(client);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

async fn ask_version(client: &mut NamedPipeClient) -> serde_json::Value {
    client
        .write_all(&frame::encode(r#"{"request":"GetVersion"}"#).unwrap())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Ok(Some(f)) = frame::decode(&buf) {
            return serde_json::from_str(&f.payload).unwrap();
        }
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("the service answers")
            .unwrap();
        assert!(n > 0, "closed before it answered");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn silent_clients_are_let_go_the_listener_lives_and_the_next_client_is_served() {
    let limits = Limits {
        max_connections: 4,
        first_request_within: Duration::from_millis(800),
        idle_for: Duration::from_millis(800),
    };
    let listener = tokio::spawn(run_control_listener_with(Arc::new(Nothing), limits));

    // As many silent clients as the limit allows: every slot is in use, so no instance of the pipe is
    // left waiting and the next client has to wait its turn.
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(
            connect(Duration::from_secs(3))
                .await
                .expect("the first clients get in"),
        );
    }

    // Past the limit a client is not served (it may connect and wait, or be told the pipe is busy),
    // and nothing crashes. Only once the silent ones are let go is it answered.
    let started = tokio::time::Instant::now();
    let mut real = connect(Duration::from_secs(8))
        .await
        .expect("a client can connect once the silent ones have been let go");
    let reply = ask_version(&mut real).await;
    assert!(reply["protocol_version"].is_number(), "{reply}");
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "it was answered after {:?}: the limit was not holding it back",
        started.elapsed()
    );

    // The silent ones were closed by the service: a read ends, it does not hang.
    for client in &mut silent {
        let mut chunk = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "a silent client was left connected: {read:?}"
        );
    }
    assert!(
        !listener.is_finished(),
        "the listener must outlive its clients"
    );
}
