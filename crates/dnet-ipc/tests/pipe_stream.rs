//! T125 — an event subscription over the real control pipe.
//!
//! The in-memory tests in `payloads.rs` prove the stream logic; this proves the real listener
//! hands a `Subscribe` from a real client to it, and that the client's identity was captured on
//! the way (a stream needs only an authenticated caller, class `Stream`).
//!
//! Its own test binary: the pipe name is fixed, so it must not run beside `attack.rs`.

#![cfg(windows)]

use std::sync::Arc;
use std::time::Duration;

use dnet_core::ids::ProfileId;
use dnet_core::session::ConnectionEvent;
use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::frame;
use dnet_ipc::protocol::{IpcError, Request};
use dnet_ipc::server::{accept_one, PIPE_NAME};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{EventBus, Subscription};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

struct Streaming {
    bus: EventBus,
}

impl Service for Streaming {
    fn console_session(&self) -> Option<ConsoleSession> {
        None
    }
    fn dispatch(&self, _: &Request) -> Result<String, IpcError> {
        Ok(r#"{"ok":true}"#.to_string())
    }
    fn subscribe(&self) -> Result<Subscription, IpcError> {
        self.bus.subscribe()
    }
}

async fn read_frame(client: &mut NamedPipeClient) -> serde_json::Value {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Ok(Some(f)) = frame::decode(&buf) {
            return serde_json::from_str(&f.payload).expect("frame is JSON");
        }
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("a frame arrives in time")
            .expect("read");
        assert!(n > 0, "server closed before sending a full frame");
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn connect_client() -> NamedPipeClient {
    for _ in 0..50 {
        if let Ok(client) = ClientOptions::new().open(PIPE_NAME) {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("could not connect to the control pipe");
}

#[tokio::test]
async fn t125_a_real_client_subscribes_and_receives_the_session_then_live_events() {
    let service = Arc::new(Streaming {
        bus: EventBus::new(),
    });
    service.bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    let server = tokio::spawn(accept_one(Arc::clone(&service) as Arc<dyn Service>));

    let mut client = connect_client().await;
    let subscribe = frame::encode(r#"{"request":"Subscribe"}"#).unwrap();
    client.write_all(&subscribe).await.unwrap();

    let ack = read_frame(&mut client).await;
    assert_eq!(ack["subscribed"], true, "{ack}");
    assert_eq!(read_frame(&mut client).await["event"], "ProbeStarted");

    service
        .bus
        .publish(&ConnectionEvent::ProfileSelected {
            profile: ProfileId::new("hy2-default"),
            because: "it carried 1.2 Mbit/s".into(),
        })
        .unwrap();
    let live = read_frame(&mut client).await;
    assert_eq!(live["event"], "ProfileSelected");
    assert_eq!(live["seq"], 2);

    // The client leaving ends the server task and frees the subscriber slot (IPC-09).
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the connection task ends when the client disconnects")
        .unwrap()
        .unwrap();
    // Held, not dropped as they are made: all slots must be takeable at the same time.
    let held: Vec<_> = (0..dnet_ipc::wire::MAX_SUBSCRIBERS)
        .map(|_| service.bus.subscribe())
        .collect();
    assert!(
        held.iter().all(Result::is_ok),
        "every slot must be free again after the only subscriber left"
    );
}
