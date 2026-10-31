//! A link to a service that is not there: it records what was asked and answers from a closure, and the
//! replies are written the way the service writes them (contract `ipc-protocol.md`), not through this
//! crate's own code, so a test that passes has agreed with the contract and not only with itself.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use dnet_config::credentials::{EndpointCredentials, RealityBundle};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_ipc::client::{ClientError, Refusal, Reply};
use dnet_ipc::protocol::Request;
use dnet_view::Link;
use serde_json::{json, Value};

pub type Answer = Box<dyn Fn(&Request) -> Result<Reply, ClientError> + Send + Sync>;

/// Records every request, answers each from `answer`.
pub struct FakeLink {
    answer: Answer,
    pub seen: Arc<Mutex<Vec<Request>>>,
}

impl FakeLink {
    pub fn new(
        answer: impl Fn(&Request) -> Result<Reply, ClientError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            answer: Box::new(answer),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Everything asked so far.
    pub fn asked(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }
}

impl Link for FakeLink {
    fn call(&self, request: Request) -> impl Future<Output = Result<Reply, ClientError>> + Send {
        let answer = (self.answer)(&request);
        self.seen.lock().unwrap().push(request);
        async move { answer }
    }
}

pub fn done(value: Value) -> Result<Reply, ClientError> {
    Ok(Reply::Done(value))
}

pub fn refusal(code: &str, detail: &str) -> Result<Reply, ClientError> {
    Ok(Reply::Refused(Refusal {
        code: code.to_owned(),
        detail: detail.to_owned(),
        retryable: false,
    }))
}

// ---------------------------------------------------------------------- what the service says

pub fn state_disconnected() -> Value {
    json!({
        "status": "Disconnected", "active_profile": null, "active_endpoint": null, "failure": null,
        "warnings": [], "routing_posture": { "posture": "FailClosed" }
    })
}

pub fn state_connected(tier: &str, warnings: &[&str]) -> Value {
    json!({
        "status": "Connected",
        "active_profile": { "id": "hy2-default", "kind": "Hysteria2", "tier": tier },
        "active_endpoint": { "id": "5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10", "label": "oracle-mumbai" },
        "failure": null, "warnings": warnings,
        "routing_posture": { "posture": "Tunnelled", "tier": tier }
    })
}

pub fn state_failed(cause: Value) -> Value {
    json!({
        "status": "Failed", "active_profile": null, "active_endpoint": null, "failure": cause,
        "warnings": [], "routing_posture": { "posture": "FailClosed" }
    })
}

pub fn paths_not_watching() -> Value {
    json!({ "as_of_unix_ms": 1_730_000_000_000_u64, "watching": false, "paths": [], "degraded": null })
}

pub fn paths_two_networks(degraded: bool) -> Value {
    let carrying = if degraded {
        json!({ "id": "7", "kind": "Wifi", "name": "Hostel-5G", "role": "Carrying", "measured": true,
                "quality": "Poor", "rtt_ms": 212.0, "jitter_ms": 38.0, "loss": 0.18,
                "trace_ms": [200.5, null, 230.0], "typical_ms": [38.0, 52.0] })
    } else {
        json!({ "id": "7", "kind": "Wifi", "name": "Hostel-5G", "role": "Carrying", "measured": true,
                "quality": "Good", "rtt_ms": 43.3, "jitter_ms": 4.0, "loss": 0.023,
                "trace_ms": [40.1, null, 45.5], "typical_ms": [38.0, 52.0] })
    };
    json!({
        "as_of_unix_ms": 1_730_000_000_000_u64, "watching": true,
        "paths": [
            carrying,
            { "id": "9", "kind": "Cellular", "name": null, "role": "Standby", "measured": true,
              "quality": "Good", "rtt_ms": 88.0, "jitter_ms": 6.0, "loss": 0.0,
              "trace_ms": [87.0, 88.5], "typical_ms": null },
            { "id": "12", "kind": "Ethernet", "name": null, "role": "Unusable", "measured": false,
              "quality": null, "rtt_ms": null, "jitter_ms": null, "loss": null,
              "trace_ms": [], "typical_ms": null }
        ],
        "degraded": if degraded { json!({ "path": "7", "quality": "Poor", "staying": "NoBetterPath" }) } else { Value::Null }
    })
}

pub fn stats_connected() -> Value {
    json!({ "connected": true, "connected_for_s": 11520, "network_changes": 2,
            "changes_that_drop_connections": 1, "method_switches": 1, "endpoint_switches": 0,
            "degraded_periods": 1, "longest_degraded_s": 6 })
}

pub fn stats_not_connected() -> Value {
    json!({ "connected": false })
}

/// A service that answers the three questions from these three values.
pub fn service(state: Value, paths: Option<Value>, stats: Option<Value>) -> FakeLink {
    FakeLink::new(move |request| match request {
        Request::GetState => done(state.clone()),
        Request::GetPaths => match &paths {
            Some(p) => done(p.clone()),
            None => refusal("InvalidRequest", "unknown request"),
        },
        Request::GetStats => match &stats {
            Some(s) => done(s.clone()),
            None => refusal("InvalidRequest", "unknown request"),
        },
        other => panic!("the test did not expect {other:?}"),
    })
}

/// A connection file the service would accept, in the form it stores one. It holds this secret, which no
/// output of this crate may ever contain.
pub const SENTINEL_UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

pub fn credentials_text() -> String {
    let bytes = EndpointCredentials {
        amneziawg: None,
        hysteria2: None,
        reality: Some(RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new(SENTINEL_UUID),
                short_id: Secret::new("0123456789abcdef"),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        }),
        measure_origin: None,
        session: None,
    }
    .to_plaintext_json()
    .unwrap();
    String::from_utf8(bytes).unwrap()
}
