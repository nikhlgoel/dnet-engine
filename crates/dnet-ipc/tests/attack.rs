//! T039 — the attack gate (SC-019).
//!
//! Proves, against a **real** Windows named pipe with **real** client-identity capture
//! by impersonation, that a request whose captured identity is not the interactive
//! console user cannot alter routing state, while a read-only request from the same
//! real client still works.
//!
//! Why this shape is a faithful SC-019 test:
//! - The pipe is a real `\\.\pipe\DNetEngine\control` with the production SDDL, and the
//!   client's identity is captured via `ImpersonateNamedPipeClient` — not asserted by
//!   the client. So this exercises the true capture → authorize → dispatch path.
//! - The stub service reports its console session as an identity that no real client
//!   can match (`session_id = u32::MAX`, an impossible SID). The connecting client is
//!   therefore treated exactly as an unprivileged / other-session caller would be: its
//!   mutating request must be refused.
//! - The routing-mutation counter is incremented only inside `dispatch`, which is
//!   reached only after authorization. If the boundary leaked, the counter would move.
//! - The read-only request is the cross-check: it succeeds **only if** identity capture
//!   produced a genuinely authenticated principal. A broken capture (empty/anonymous
//!   identity) would deny the read-only request too, so its success proves capture works
//!   *and* the mutating refusal is a real authorization decision, not blanket denial.
//!
//! A cross-process test with a genuinely lowered-integrity token is future hardening;
//! it needs `CreateProcessAsUser`, which is heavy and flaky in CI. This in-process test
//! already exercises every security-relevant code path.

#![cfg(windows)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::frame;
use dnet_ipc::protocol::{IpcError, Request};
use dnet_ipc::server::{accept_one, PIPE_NAME};
use dnet_ipc::service::Service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

/// A stub service that counts routing mutations and reports an unreachable console
/// identity, so every real client is treated as a non-console caller.
struct AttackTarget {
    routing_mutations: AtomicU32,
    read_only_calls: AtomicU32,
}

impl AttackTarget {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            routing_mutations: AtomicU32::new(0),
            read_only_calls: AtomicU32::new(0),
        })
    }
}

impl Service for AttackTarget {
    fn console_session(&self) -> Option<ConsoleSession> {
        // An identity no real client can match: mutating requests are always refused
        // for anyone connecting in the test, standing in for the unprivileged attacker.
        Some(ConsoleSession {
            session_id: u32::MAX,
            user_sid: "S-1-0-0".to_string(),
        })
    }

    fn dispatch(&self, request: &Request) -> Result<String, IpcError> {
        match request {
            // Only reached if authorization permitted a mutating request — which, for
            // this service, must never happen. Records the breach if it does.
            Request::Connect { .. } | Request::Disconnect => {
                self.routing_mutations.fetch_add(1, Ordering::SeqCst);
                Ok(r#"{"accepted":true}"#.to_string())
            }
            Request::GetState => {
                self.read_only_calls.fetch_add(1, Ordering::SeqCst);
                Ok(r#"{"status":"Disconnected","active_profile":null}"#.to_string())
            }
            _ => Ok(r#"{"ok":true}"#.to_string()),
        }
    }
}

/// Read exactly one length-prefixed frame from the client side.
async fn read_frame(client: &mut tokio::net::windows::named_pipe::NamedPipeClient) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Ok(Some(f)) = frame::decode(&buf) {
            return f.payload;
        }
        let n = client.read(&mut chunk).await.expect("read response");
        assert!(n > 0, "server closed before sending a full frame");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Connect a client to the control pipe, retrying briefly while the server instance
/// is being created (ERROR_PIPE_BUSY / not-yet-created races).
async fn connect_client() -> tokio::net::windows::named_pipe::NamedPipeClient {
    for _ in 0..50 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return client,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("could not connect to the control pipe");
}

#[tokio::test]
async fn t039_unprivileged_client_cannot_alter_routing() {
    let target = AttackTarget::new();
    let server = tokio::spawn(accept_one(Arc::clone(&target) as Arc<dyn Service>));

    let mut client = connect_client().await;

    // --- The attack: a mutating request from a non-console identity. ---
    let connect = frame::encode(r#"{"request":"Connect","acknowledge_tier2":false}"#)
        .expect("encode Connect");
    client.write_all(&connect).await.expect("send Connect");

    let response = read_frame(&mut client).await;
    let value: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");

    assert_eq!(
        value["error"], "Unauthorized",
        "a non-console client must be refused a mutating request; got {response}"
    );
    assert_eq!(
        target.routing_mutations.load(Ordering::SeqCst),
        0,
        "SC-019 VIOLATED: routing state was mutated by an unauthorized client"
    );

    // --- The cross-check: a read-only request from the SAME real client. ---
    // This succeeds only if identity capture produced an authenticated principal; a
    // broken capture would deny this too, so its success proves both that capture works
    // and that the refusal above was a real authorization decision, not blanket denial.
    let get_state = frame::encode(r#"{"request":"GetState"}"#).expect("encode GetState");
    client.write_all(&get_state).await.expect("send GetState");

    let response = read_frame(&mut client).await;
    let value: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");
    assert!(
        value.get("error").is_none(),
        "an authenticated client's read-only request must succeed; got {response}"
    );
    assert_eq!(
        value["status"], "Disconnected",
        "unexpected state response: {response}"
    );
    assert_eq!(
        target.read_only_calls.load(Ordering::SeqCst),
        1,
        "the read-only request should have reached the service exactly once"
    );

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
