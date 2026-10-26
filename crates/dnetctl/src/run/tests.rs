//! Every command, against the real server dispatch over an in-memory stream, with the clock paused.

use std::collections::VecDeque;
use std::future::{pending, Future};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnet_core::session::{ConnectionEvent, FailureCause};
use dnet_core::tier::FailoverTier;
use dnet_ipc::authz::{ClientIdentity, ConsoleSession};
use dnet_ipc::client::{ClientError, Connection};
use dnet_ipc::frame;
use dnet_ipc::protocol::{
    encode_request, encode_state_snapshot, ActiveEndpoint, ActiveProfile, ConnectionStatus,
    IpcError, Request, RoutingPosture, StateSnapshot, Warning,
};
use dnet_ipc::server::{dispatch_request, stream_events, Reply as ServerReply};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{EventBus, Subscription};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::cli;

// ------------------------------------------------------------------ states

fn disconnected() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Disconnected,
        active_profile: None,
        active_endpoint: None,
        failure: None,
        warnings: vec![],
        posture: RoutingPosture::FailClosed,
    }
}

fn probing() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Probing,
        ..disconnected()
    }
}

fn connected() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Connected,
        active_profile: Some(ActiveProfile {
            id: "hy2-default".into(),
            kind: "Hysteria2".into(),
            tier: FailoverTier::Tier2,
        }),
        active_endpoint: Some(ActiveEndpoint {
            id: "e".into(),
            label: "harness".into(),
        }),
        failure: None,
        warnings: vec![Warning::Tier2ProfileActive],
        posture: RoutingPosture::Tunnelled {
            tier: FailoverTier::Tier2,
        },
    }
}

fn failed() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Failed,
        failure: Some(FailureCause::AllProfilesBlocked),
        ..disconnected()
    }
}

// ------------------------------------------------------------------ the daemon

struct Stub {
    /// One state per `GetState`; the last repeats for ever.
    states: Mutex<VecDeque<StateSnapshot>>,
    last: Mutex<StateSnapshot>,
    log: Mutex<Vec<String>>,
    connect: Mutex<Result<(), IpcError>>,
    disconnect: Mutex<Result<(), IpcError>>,
    /// Whether a configuration change (add, remove, enable, encrypted DNS) is accepted.
    change: Mutex<Result<(), IpcError>>,
    /// What `GetPaths` and `GetStats` answer.
    paths: Mutex<Result<String, IpcError>>,
    stats: Mutex<Result<String, IpcError>>,
    bus: EventBus,
}

impl Stub {
    fn new(states: Vec<StateSnapshot>) -> Arc<Self> {
        let last = states.last().cloned().unwrap_or_else(disconnected);
        Arc::new(Self {
            states: Mutex::new(states.into()),
            last: Mutex::new(last),
            log: Mutex::new(Vec::new()),
            connect: Mutex::new(Ok(())),
            disconnect: Mutex::new(Ok(())),
            change: Mutex::new(Ok(())),
            paths: Mutex::new(Ok(dnet_ipc::netview::encode_paths(
                &Default::default(),
                false,
                0,
            ))),
            stats: Mutex::new(Ok(dnet_ipc::netview::encode_stats(None))),
            bus: EventBus::new(),
        })
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn requests_named(&self, name: &str) -> usize {
        self.log()
            .iter()
            .filter(|r| r.contains(&format!("\"request\":\"{name}\"")))
            .count()
    }
}

impl Service for Stub {
    fn console_session(&self) -> Option<ConsoleSession> {
        Some(ConsoleSession {
            session_id: 1,
            user_sid: "S-1-5-21-1".into(),
        })
    }

    fn dispatch(&self, request: &Request) -> Result<String, IpcError> {
        self.log.lock().unwrap().push(encode_request(request));
        match request {
            Request::GetState => {
                let next = self.states.lock().unwrap().pop_front();
                let state = match next {
                    Some(state) => {
                        *self.last.lock().unwrap() = state.clone();
                        state
                    }
                    None => self.last.lock().unwrap().clone(),
                };
                encode_state_snapshot(&state)
            }
            Request::Connect { .. } => self
                .connect
                .lock()
                .unwrap()
                .clone()
                .map(|()| r#"{"accepted":true}"#.to_string()),
            Request::Disconnect => self
                .disconnect
                .lock()
                .unwrap()
                .clone()
                .map(|()| r#"{"accepted":true}"#.to_string()),
            Request::AddEndpoint(_) => self.change.lock().unwrap().clone().map(|()| {
                r#"{"endpoint":"11111111-2222-4333-8444-555555555555"}"#.to_string()
            }),
            Request::FetchFeed => self
                .change
                .lock()
                .unwrap()
                .clone()
                .map(|()| r#"{"started":true,"route":"physical"}"#.to_string()),
            Request::ImportFeed(_) => self
                .change
                .lock()
                .unwrap()
                .clone()
                .map(|()| r#"{"imported":true,"changes":["Updated"]}"#.to_string()),
            Request::RemoveEndpoint { .. } | Request::SetEndpointEnabled { .. } => self
                .change
                .lock()
                .unwrap()
                .clone()
                .map(|()| r#"{"applied":true}"#.to_string()),
            Request::SetEncryptedDnsHandling { block } => {
                self.change.lock().unwrap().clone().map(|()| {
                    if *block {
                        r#"{"block":true}"#.to_string()
                    } else {
                        r#"{"block":false,"consequence":"Rules for sites will not apply to some programs."}"#
                            .to_string()
                    }
                })
            }
            Request::ListProfiles => Ok(r#"{"profiles":[{"id":"hy2-default","kind":"Hysteria2","tier":"Tier2","carrier":"Udp","brutal":false}]}"#.to_string()),
            Request::ListEndpoints => Ok(r#"{"endpoints":[]}"#.to_string()),
            Request::GetPaths => self.paths.lock().unwrap().clone(),
            Request::GetStats => self.stats.lock().unwrap().clone(),
            _ => Ok("{}".to_string()),
        }
    }

    fn subscribe(&self) -> Result<Subscription, IpcError> {
        self.bus.subscribe()
    }
}

/// Serve one connection with the real dispatch, including turning a `Subscribe` into a stream.
async fn serve(stub: Arc<Stub>, mut stream: DuplexStream, silent: bool) {
    let identity = ClientIdentity {
        sid: "S-1-5-21-1".into(),
        session_id: 1,
        authenticated: true,
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match frame::decode(&buf) {
            Ok(Some(found)) => {
                buf.drain(..found.consumed);
                if silent {
                    continue;
                }
                let console = stub.console_session();
                match dispatch_request(&found.payload, &identity, console.as_ref(), &*stub) {
                    ServerReply::Response(reply) => {
                        let bytes = frame::encode(&reply).unwrap();
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    ServerReply::Stream(subscription) => {
                        let _ = stream_events(stream, buf, subscription).await;
                        return;
                    }
                }
            }
            Ok(None) => match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            },
            Err(_) => return,
        }
    }
}

struct Fake {
    stub: Arc<Stub>,
    silent: bool,
    /// The `trust_any_service` each connection was asked for.
    trusted: Mutex<Vec<bool>>,
}

impl Connector for Fake {
    type Stream = DuplexStream;
    fn connect(
        &self,
        trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
        self.trusted.lock().unwrap().push(trust_any_service);
        let (client, server) = duplex(64 * 1024);
        tokio::spawn(serve(Arc::clone(&self.stub), server, self.silent));
        std::future::ready(Ok(Connection::new(client)))
    }
}

struct Nobody;

impl Connector for Nobody {
    type Stream = DuplexStream;
    fn connect(
        &self,
        _trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
        std::future::ready(Err(ClientError::Unreachable(
            "the DNet Engine service is not running".into(),
        )))
    }
}

/// A connector whose daemon sends back whatever bytes it is told to, in answer to the first request
/// it receives. Every command starts with a version check (T132), so this is the version stage.
struct RawScripted(Vec<u8>);

impl Connector for RawScripted {
    type Stream = DuplexStream;
    fn connect(
        &self,
        _trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
        let (client, mut server) = duplex(64 * 1024);
        let bytes = self.0.clone();
        tokio::spawn(async move {
            let mut sink = [0u8; 512];
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(&bytes).await;
        });
        std::future::ready(Ok(Connection::new(client)))
    }
}

/// A connector whose daemon passes the version check and then sends back whatever bytes it is told
/// to in answer to the next request: for the stage after the handshake.
struct Scripted(Vec<u8>);

impl Connector for Scripted {
    type Stream = DuplexStream;
    fn connect(
        &self,
        _trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
        let (client, mut server) = duplex(64 * 1024);
        let bytes = self.0.clone();
        tokio::spawn(async move {
            let mut sink = [0u8; 512];
            let _ = server.read(&mut sink).await;
            let version = frame::encode(&dnet_ipc::version::reply()).unwrap();
            let _ = server.write_all(&version).await;
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(&bytes).await;
        });
        std::future::ready(Ok(Connection::new(client)))
    }
}

/// A daemon that reports a given version reply, then answers anything else with `{}`, recording
/// the name of each request it receives.
struct Versioned {
    reply: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Versioned {
    fn reporting(min: u32, newest: u32) -> Self {
        Self {
            reply: format!(
                r#"{{"protocol_version":{newest},"min_protocol_version":{min},"service_version":"9.9.9"}}"#
            ),
            seen: Arc::default(),
        }
    }
}

impl Connector for Versioned {
    type Stream = DuplexStream;
    fn connect(
        &self,
        _trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
        let (client, mut server) = duplex(64 * 1024);
        let reply = self.reply.clone();
        let seen = Arc::clone(&self.seen);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match frame::decode(&buf) {
                    Ok(Some(found)) => {
                        buf.drain(..found.consumed);
                        let name = serde_json::from_str::<serde_json::Value>(&found.payload)
                            .ok()
                            .and_then(|v| v["request"].as_str().map(str::to_owned))
                            .unwrap_or_default();
                        let answer = if name == "GetVersion" {
                            reply.clone()
                        } else {
                            "{}".to_owned()
                        };
                        seen.lock().unwrap().push(name);
                        let bytes = frame::encode(&answer).unwrap();
                        if server.write_all(&bytes).await.is_err() {
                            return;
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
        std::future::ready(Ok(Connection::new(client)))
    }
}

#[derive(Default)]
struct Capture {
    out: Vec<String>,
    err: Vec<String>,
}

impl Sink for Capture {
    fn out(&mut self, line: &str) {
        self.out.push(line.to_string());
    }
    fn err(&mut self, line: &str) {
        self.err.push(line.to_string());
    }
}

impl Capture {
    fn out(&self) -> String {
        self.out.join("\n")
    }
    fn err(&self) -> String {
        self.err.join("\n")
    }
}

async fn go_with<C: Connector>(
    args: &[&str],
    connector: &C,
    interrupt: impl Future<Output = ()>,
) -> (i32, Capture) {
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let invocation = cli::parse(&args).expect("the test passes valid arguments");
    let mut capture = Capture::default();
    let code = run(invocation, connector, &mut capture, interrupt).await;
    (code, capture)
}

async fn go(args: &[&str], stub: &Arc<Stub>) -> (i32, Capture) {
    let fake = Fake {
        stub: Arc::clone(stub),
        silent: false,
        trusted: Mutex::new(Vec::new()),
    };
    go_with(args, &fake, pending()).await
}

// ------------------------------------------------------------------ status and lists

#[tokio::test(start_paused = true)]
async fn status_shows_the_state_in_prose_and_asks_for_nothing_else() {
    let stub = Stub::new(vec![connected()]);

    let (code, shown) = go(&["status"], &stub).await;

    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("Connected"), "{}", shown.out());
    assert!(shown.out().contains("hy2-default"), "{}", shown.out());
    assert_eq!(stub.log().len(), 1, "{:?}", stub.log());
}

#[tokio::test(start_paused = true)]
async fn status_as_json_prints_the_services_own_answer() {
    let stub = Stub::new(vec![connected()]);

    let (code, shown) = go(&["status", "--json"], &stub).await;

    assert_eq!(code, exit::OK);
    let value: serde_json::Value = serde_json::from_str(&shown.out()).expect("valid JSON");
    assert_eq!(value["status"], "Connected");
}

#[tokio::test(start_paused = true)]
async fn profiles_and_endpoints_are_listed() {
    let stub = Stub::new(vec![]);

    let (code, profiles) = go(&["profiles"], &stub).await;
    assert_eq!(code, exit::OK);
    assert!(profiles.out().contains("hy2-default"), "{}", profiles.out());

    let (code, endpoints) = go(&["endpoints"], &stub).await;
    assert_eq!(code, exit::OK);
    assert_eq!(endpoints.out(), "No endpoints are configured.");
}

// ------------------------------------------------------------------ the networks and the session (T144)

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn one_network() -> String {
    use dnet_core::ids::InterfaceId;
    use dnet_core::path::{PathKind, PathRole};
    use dnet_core::quality::QualityBand;
    use dnet_core::telemetry::{PathView, PathsSnapshot};
    let snapshot = PathsSnapshot {
        paths: vec![PathView {
            id: InterfaceId::new(7),
            kind: PathKind::Wifi,
            name: Some("Hostel-5G".into()),
            role: PathRole::Carrying,
            measured: true,
            band: Some(QualityBand::Good),
            rtt: Some(Duration::from_millis(43)),
            jitter: Some(Duration::from_millis(4)),
            loss: Some(0.02),
            trace_ms: vec![Some(40.0)],
            typical_ms: None,
        }],
        degradation: None,
    };
    dnet_ipc::netview::encode_paths(&snapshot, true, now_ms())
}

#[tokio::test(start_paused = true)]
async fn the_networks_are_shown_with_their_names_and_roles() {
    let stub = Stub::new(vec![]);
    *stub.paths.lock().unwrap() = Ok(one_network());

    let (code, shown) = go(&["paths"], &stub).await;

    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("Hostel-5G (Wi-Fi)"), "{}", shown.out());
    assert!(shown.out().contains("carrying"), "{}", shown.out());
    assert_eq!(stub.requests_named("GetPaths"), 1);
}

#[tokio::test(start_paused = true)]
async fn nothing_connected_is_said_as_nothing_watched() {
    let stub = Stub::new(vec![]);
    let (code, shown) = go(&["paths"], &stub).await;
    assert_eq!(code, exit::OK);
    assert!(
        shown.out().contains("Nothing is being watched"),
        "{}",
        shown.out()
    );
}

#[tokio::test(start_paused = true)]
async fn paths_json_is_the_services_own_answer() {
    let stub = Stub::new(vec![]);
    *stub.paths.lock().unwrap() = Ok(one_network());
    let (code, shown) = go(&["paths", "--json"], &stub).await;
    assert_eq!(code, exit::OK);
    let value: serde_json::Value = serde_json::from_str(&shown.out()).expect("valid JSON");
    assert_eq!(value["paths"][0]["id"], "7");
}

#[tokio::test(start_paused = true)]
async fn the_session_is_counted_plainly() {
    let stub = Stub::new(vec![]);
    *stub.stats.lock().unwrap() = Ok(dnet_ipc::netview::encode_stats(Some(
        dnet_core::telemetry::StatsSummary {
            connected_for: Duration::from_secs(90),
            network_changes: 1,
            changes_that_drop_connections: 1,
            method_switches: 0,
            endpoint_switches: 0,
            degraded_periods: 0,
            longest_degraded: Duration::ZERO,
        },
    )));
    let (code, shown) = go(&["stats"], &stub).await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("1 min 30 s"), "{}", shown.out());
    assert!(shown.out().contains("Tier 2"), "{}", shown.out());

    let idle = Stub::new(vec![]);
    let (code, shown) = go(&["stats"], &idle).await;
    assert_eq!(code, exit::OK);
    assert!(
        shown.out().contains("Nothing is connected"),
        "{}",
        shown.out()
    );
}

#[tokio::test(start_paused = true)]
async fn a_service_that_predates_the_request_is_told_to_update_not_shown_as_empty() {
    for command in ["paths", "stats"] {
        let stub = Stub::new(vec![]);
        let unknown = IpcError::InvalidRequest {
            detail: "unknown request \"GetPaths\"".into(),
        };
        *stub.paths.lock().unwrap() = Err(unknown.clone());
        *stub.stats.lock().unwrap() = Err(unknown);

        let (code, shown) = go(&[command], &stub).await;

        assert_eq!(code, exit::REFUSED, "{command}");
        assert!(
            shown.err().contains("older than dnetctl"),
            "{command}: {}",
            shown.err()
        );
        assert!(
            shown.out().is_empty(),
            "{command}: nothing is printed as if it were an answer"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_reply_that_is_not_what_it_should_be_is_refused_not_shown() {
    let stub = Stub::new(vec![]);
    *stub.paths.lock().unwrap() =
        Ok(r#"{"as_of_unix_ms":1,"watching":true,"paths":"fine"}"#.into());
    *stub.stats.lock().unwrap() = Ok(r#"{"connected":true}"#.into());
    for command in ["paths", "stats"] {
        let (code, shown) = go(&[command], &stub).await;
        assert_ne!(code, exit::OK, "{command}");
        assert!(shown.out().is_empty(), "{command}: {}", shown.out());
    }
}

#[tokio::test(start_paused = true)]
async fn help_needs_no_service() {
    let (code, shown) = go_with(&["help"], &Nobody, pending()).await;
    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("usage:"));
}

// ------------------------------------------------------------------ connect

#[tokio::test(start_paused = true)]
async fn connect_waits_through_connecting_and_reports_the_connected_state() {
    let stub = Stub::new(vec![probing(), probing(), connected()]);

    let (code, shown) = go(&["connect"], &stub).await;

    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("Connecting..."), "{}", shown.out());
    assert!(
        shown.out().contains("Status:    Connected"),
        "{}",
        shown.out()
    );
    assert_eq!(stub.requests_named("Connect"), 1);
    assert_eq!(stub.requests_named("GetState"), 3);
}

#[tokio::test(start_paused = true)]
async fn connect_sends_the_profile_and_the_consent_that_were_asked_for() {
    let stub = Stub::new(vec![connected()]);

    let (code, _) = go(
        &["connect", "--profile", "hy2-default", "--accept-tier2"],
        &stub,
    )
    .await;

    assert_eq!(code, exit::OK);
    let sent = stub
        .log()
        .into_iter()
        .find(|r| r.contains("\"Connect\""))
        .unwrap();
    assert!(sent.contains("\"profile\":\"hy2-default\""), "{sent}");
    assert!(sent.contains("\"acknowledge_tier2\":true"), "{sent}");
}

#[tokio::test(start_paused = true)]
async fn a_connection_that_fails_says_what_went_wrong_and_exits_1() {
    let stub = Stub::new(vec![probing(), failed()]);

    let (code, shown) = go(&["connect"], &stub).await;

    assert_eq!(code, exit::REFUSED);
    for label in ["Problem:", "Why:", "To fix:"] {
        assert!(shown.out().contains(label), "{label}: {}", shown.out());
    }
}

/// Found by the first client that polled right after the daemon accepted a connect: for an instant
/// the state is still the old one. A short run of `Disconnected` is not the connection ending.
#[tokio::test(start_paused = true)]
async fn a_brief_disconnected_right_after_the_request_is_not_the_connection_ending() {
    let stub = Stub::new(vec![disconnected(), disconnected(), probing(), connected()]);

    let (code, shown) = go(&["connect"], &stub).await;

    assert_eq!(code, exit::OK, "{}{}", shown.out(), shown.err());
}

#[tokio::test(start_paused = true)]
async fn a_connect_that_stays_disconnected_is_reported_as_ended_not_waited_on_for_ever() {
    let stub = Stub::new(vec![disconnected()]);

    let (code, shown) = go(&["connect", "--timeout", "600"], &stub).await;

    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("ended"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn a_connect_that_takes_too_long_times_out_and_says_the_work_carries_on() {
    let stub = Stub::new(vec![probing()]);

    let (code, shown) = go(&["connect", "--timeout", "5"], &stub).await;

    assert_eq!(code, exit::TIMED_OUT);
    assert!(shown.err().contains("carries on"), "{}", shown.err());
    assert!(shown.err().contains("5 s"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn no_wait_returns_as_soon_as_the_service_accepts() {
    let stub = Stub::new(vec![probing()]);

    let (code, shown) = go(&["connect", "--no-wait"], &stub).await;

    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("Connect requested"), "{}", shown.out());
    assert_eq!(stub.requests_named("GetState"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_refused_connect_is_exit_1_with_the_services_words() {
    let stub = Stub::new(vec![]);
    *stub.connect.lock().unwrap() = Err(IpcError::ServiceBusy);

    let (code, shown) = go(&["connect"], &stub).await;

    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("service busy"), "{}", shown.err());
    assert!(
        shown.err().contains("try again"),
        "retryable: {}",
        shown.err()
    );
    assert_eq!(
        stub.requests_named("GetState"),
        0,
        "no waiting after a refusal"
    );
}

#[tokio::test(start_paused = true)]
async fn a_tier_two_refusal_names_the_option_that_gives_consent() {
    let stub = Stub::new(vec![]);
    *stub.connect.lock().unwrap() = Err(IpcError::TierDowngradeRequiresConsent {
        tier: FailoverTier::Tier2,
    });

    let (code, shown) = go(&["connect"], &stub).await;

    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("--accept-tier2"), "{}", shown.err());
}

/// A profile id the service would never accept is a usage error here, and nothing is sent.
#[tokio::test(start_paused = true)]
async fn a_profile_id_the_service_would_refuse_is_caught_before_anything_is_sent() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["connect", "--profile", "../../evil"], &stub).await;

    assert_eq!(code, exit::USAGE);
    assert!(shown.err().contains("dnetctl:"), "{}", shown.err());
    assert!(stub.log().is_empty(), "{:?}", stub.log());
}

// ------------------------------------------------------------------ disconnect

#[tokio::test(start_paused = true)]
async fn disconnect_waits_until_the_service_says_disconnected() {
    let stub = Stub::new(vec![connected(), connected(), disconnected()]);

    let (code, shown) = go(&["disconnect"], &stub).await;

    assert_eq!(code, exit::OK);
    assert_eq!(shown.out(), "Disconnected.");
    assert_eq!(stub.requests_named("GetState"), 3);
}

#[tokio::test(start_paused = true)]
async fn disconnecting_when_not_connected_is_not_a_failure() {
    let stub = Stub::new(vec![]);
    *stub.disconnect.lock().unwrap() = Err(IpcError::NotConnected);

    let (code, shown) = go(&["disconnect"], &stub).await;

    assert_eq!(code, exit::OK);
    assert_eq!(shown.out(), "Not connected.");
}

#[tokio::test(start_paused = true)]
async fn disconnect_that_never_completes_times_out() {
    let stub = Stub::new(vec![connected()]);

    let (code, shown) = go(&["disconnect", "--timeout", "3"], &stub).await;

    assert_eq!(code, exit::TIMED_OUT);
    assert!(
        shown.err().contains("still disconnecting"),
        "{}",
        shown.err()
    );
}

// ------------------------------------------------------------------ events

fn publish(stub: &Stub, event: &ConnectionEvent) {
    stub.bus.publish(event).expect("a well-formed event");
}

#[tokio::test(start_paused = true)]
async fn events_prints_the_session_so_far_with_the_reason_for_each() {
    let stub = Stub::new(vec![]);
    publish(&stub, &ConnectionEvent::ProbeStarted);
    publish(
        &stub,
        &ConnectionEvent::ProfileSelected {
            profile: dnet_core::ids::ProfileId::new("hy2-default"),
            because: "it was the fastest usable profile".into(),
        },
    );

    let (code, shown) = go(&["events"], &stub).await;

    assert_eq!(code, exit::OK);
    assert_eq!(shown.out.len(), 2, "{:?}", shown.out);
    assert!(
        shown.out[0].starts_with("#1 ProbeStarted:"),
        "{:?}",
        shown.out
    );
    assert!(
        shown.out[1].contains("ProfileSelected hy2-default: it was the fastest usable profile"),
        "{:?}",
        shown.out
    );
}

#[tokio::test(start_paused = true)]
async fn events_with_nothing_to_show_says_so_instead_of_printing_nothing() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["events"], &stub).await;

    assert_eq!(code, exit::OK);
    assert_eq!(shown.out(), "No events in this session yet.");

    // As JSON there is nothing to print, and nothing is: a script reads an empty stream.
    let (_, as_json) = go(&["events", "--json"], &stub).await;
    assert!(as_json.out.is_empty(), "{:?}", as_json.out);
}

#[tokio::test(start_paused = true)]
async fn events_follow_keeps_printing_new_events_until_interrupted() {
    let stub = Stub::new(vec![]);
    publish(&stub, &ConnectionEvent::ProbeStarted);
    let later = Arc::clone(&stub);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        publish(
            &later,
            &ConnectionEvent::ProfileBlocked {
                profile: dnet_core::ids::ProfileId::new("reality-default"),
                reason: "did not respond in time".into(),
            },
        );
    });
    let fake = Fake {
        stub: Arc::clone(&stub),
        silent: false,
        trusted: Mutex::new(Vec::new()),
    };

    let (code, shown) = go_with(
        &["events", "--follow"],
        &fake,
        tokio::time::sleep(Duration::from_secs(10)),
    )
    .await;

    assert_eq!(code, exit::OK);
    assert_eq!(shown.out.len(), 2, "{:?}", shown.out);
    assert!(
        shown.out[1].contains("ProfileBlocked reality-default"),
        "{:?}",
        shown.out
    );
}

#[tokio::test(start_paused = true)]
async fn events_as_json_prints_each_frame_as_the_service_sent_it() {
    let stub = Stub::new(vec![]);
    publish(&stub, &ConnectionEvent::ProbeStarted);

    let (code, shown) = go(&["events", "--json"], &stub).await;

    assert_eq!(code, exit::OK);
    let value: serde_json::Value = serde_json::from_str(&shown.out[0]).unwrap();
    assert_eq!(value["event"], "ProbeStarted");
}

// ------------------------------------------------------------------ who it talks to

/// The check on who owns the pipe happens at connection, so the choice has to arrive there:
/// by default it is strict, and only the explicit development option relaxes it.
#[tokio::test(start_paused = true)]
async fn the_development_option_reaches_the_connection_and_is_off_otherwise() {
    let stub = Stub::new(vec![connected()]);
    let fake = Fake {
        stub: Arc::clone(&stub),
        silent: false,
        trusted: Mutex::new(Vec::new()),
    };

    go_with(&["status"], &fake, pending()).await;
    go_with(
        &["status", "--allow-unprivileged-service"],
        &fake,
        pending(),
    )
    .await;

    assert_eq!(*fake.trusted.lock().unwrap(), [false, true]);
}

/// A service that cannot be trusted is reported as unreachable, with its reason, and no request
/// is made of it.
#[tokio::test(start_paused = true)]
async fn an_impostor_pipe_is_refused_before_anything_is_asked_of_it() {
    struct Impostor;
    impl Connector for Impostor {
        type Stream = DuplexStream;
        fn connect(
            &self,
            _trust_any_service: bool,
        ) -> impl Future<Output = Result<Connection<DuplexStream>, ClientError>> {
            std::future::ready(Err(ClientError::Unreachable(
                "the control pipe is not owned by the DNet Engine service".into(),
            )))
        }
    }

    let (code, shown) = go_with(&["connect"], &Impostor, pending()).await;

    assert_eq!(code, exit::UNREACHABLE);
    assert!(shown.err().contains("not owned"), "{}", shown.err());
    assert!(shown.out.is_empty());
}

// ------------------------------------------------------------------ when things go wrong

#[tokio::test(start_paused = true)]
async fn a_service_that_is_not_running_is_exit_3_with_what_to_do() {
    let (code, shown) = go_with(&["status"], &Nobody, pending()).await;

    assert_eq!(code, exit::UNREACHABLE);
    assert!(shown.err().contains("not running"), "{}", shown.err());
    assert!(shown.out.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_service_that_does_not_answer_is_exit_5_not_a_hang() {
    let stub = Stub::new(vec![]);
    let fake = Fake {
        stub,
        silent: true,
        trusted: Mutex::new(Vec::new()),
    };

    let (code, shown) = go_with(&["status"], &fake, pending()).await;

    assert_eq!(code, exit::UNEXPECTED);
    assert!(shown.err().contains("did not answer"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn a_state_that_contradicts_itself_is_refused_not_shown() {
    // Connected, but naming no profile: the decoder refuses it, and so does the client.
    let nonsense = frame::encode(r#"{"status":"Connected"}"#).unwrap();

    let (code, shown) = go_with(&["status"], &Scripted(nonsense), pending()).await;

    assert_eq!(code, exit::UNEXPECTED);
    assert!(
        shown.err().contains("not one this client understands"),
        "{}",
        shown.err()
    );
    assert!(shown.out.is_empty());
}

#[tokio::test(start_paused = true)]
async fn garbage_from_the_service_is_exit_5_and_is_not_echoed() {
    let junk = frame::encode("SECRET-LOOKING-TEXT").unwrap();

    let (code, shown) = go_with(&["status"], &Scripted(junk), pending()).await;

    assert_eq!(code, exit::UNEXPECTED);
    assert!(!shown.err().contains("SECRET"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn an_event_stream_that_is_refused_says_why() {
    // A daemon that answers the Subscribe with a refusal instead of an acknowledgement.
    let refusal = frame::encode(
        r#"{"error":"ServiceBusy","detail":"too many subscribers","retryable":true}"#,
    )
    .unwrap();

    let (code, shown) = go_with(&["events"], &Scripted(refusal), pending()).await;

    assert_eq!(code, exit::REFUSED);
    assert!(
        shown.err().contains("too many subscribers"),
        "{}",
        shown.err()
    );
}

// ------------------------------------------------------------------ the protocol version (T132)

#[tokio::test(start_paused = true)]
async fn a_service_that_cannot_talk_to_this_program_is_exit_6_and_nothing_else_is_sent() {
    let service = Versioned::reporting(5, 7);

    let (code, shown) = go_with(&["connect"], &service, pending()).await;

    assert_eq!(code, exit::INCOMPATIBLE);
    assert!(
        shown.err().contains("Update this program"),
        "{}",
        shown.err()
    );
    assert!(shown.out.is_empty());
    // The connect was never sent: a service that may not mean what we mean is not asked to act.
    assert_eq!(*service.seen.lock().unwrap(), ["GetVersion"]);
}

#[tokio::test(start_paused = true)]
async fn every_command_asks_for_the_version_before_anything_else() {
    for args in [
        &["status"][..],
        &["profiles"],
        &["endpoints"],
        &["connect", "--no-wait"],
        &["disconnect", "--no-wait"],
        &["events"],
    ] {
        let service = Versioned::reporting(1, 1);
        let _ = go_with(args, &service, pending()).await;
        let seen = service.seen.lock().unwrap().clone();
        assert_eq!(
            seen.first().map(String::as_str),
            Some("GetVersion"),
            "{args:?}: {seen:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_service_that_predates_version_checks_is_exit_6_and_says_to_update_it() {
    let old = frame::encode(
        r#"{"error":"InvalidRequest","detail":"invalid request: unknown request \"GetVersion\"","retryable":false}"#,
    )
    .unwrap();

    let (code, shown) = go_with(&["status"], &RawScripted(old), pending()).await;

    assert_eq!(code, exit::INCOMPATIBLE);
    assert!(
        shown.err().contains("Update the DNet Engine service"),
        "{}",
        shown.err()
    );
}

#[tokio::test(start_paused = true)]
async fn a_version_reply_that_makes_no_sense_is_exit_5_and_is_not_echoed() {
    let nonsense = frame::encode(
        r#"{"protocol_version":1,"min_protocol_version":1,"service_version":"SECRET WORDS"}"#,
    )
    .unwrap();

    let (code, shown) = go_with(&["status"], &RawScripted(nonsense), pending()).await;

    assert_eq!(code, exit::UNEXPECTED);
    assert!(!shown.err().contains("SECRET"), "{}", shown.err());
    assert!(shown.out.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_busy_service_refuses_the_version_check_with_its_reason() {
    let busy =
        frame::encode(r#"{"error":"ServiceBusy","detail":"try later","retryable":true}"#).unwrap();

    let (code, shown) = go_with(&["status"], &RawScripted(busy), pending()).await;

    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("try later"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn version_shows_both_ends_and_says_they_can_talk() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["version"], &stub).await;

    assert_eq!(code, exit::OK);
    let text = shown.out();
    assert!(text.contains("dnetctl:"), "{text}");
    assert!(text.contains("service:"), "{text}");
    assert!(text.contains("They can talk to each other."), "{text}");
    assert!(
        stub.log().is_empty(),
        "the version never reaches the service's own code"
    );
}

#[tokio::test(start_paused = true)]
async fn version_as_json_is_one_object_a_script_can_read() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["version", "--json"], &stub).await;

    assert_eq!(code, exit::OK);
    let value: serde_json::Value = serde_json::from_str(&shown.out()).unwrap();
    assert_eq!(value["compatible"], true);
    assert_eq!(
        value["client"]["protocol_version"],
        dnet_ipc::version::PROTOCOL_VERSION
    );
    assert!(value["service"]["version"].is_string());
}

#[tokio::test(start_paused = true)]
async fn version_reports_a_mismatch_instead_of_stopping_at_it() {
    let service = Versioned::reporting(5, 7);

    let (code, shown) = go_with(&["version"], &service, pending()).await;

    assert_eq!(code, exit::INCOMPATIBLE);
    assert!(
        shown.out().contains("speaks protocol 5 to 7"),
        "{}",
        shown.out()
    );
    assert!(
        shown.err().contains("Update this program"),
        "{}",
        shown.err()
    );
}

#[tokio::test(start_paused = true)]
async fn the_conventional_version_flags_work() {
    for flag in ["--version", "-V"] {
        let stub = Stub::new(vec![]);
        let (code, shown) = go(&[flag], &stub).await;
        assert_eq!(code, exit::OK, "{flag}");
        assert!(shown.out().contains("dnetctl:"), "{flag}");
    }
}

// ------------------------------------------------------------------ configuration changes (Phase 9a)

const AN_ID: &str = "11111111-2222-4333-8444-555555555555";

/// A credentials file in a directory that goes away with the guard.
fn credentials_file() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.json");
    std::fs::write(&path, crate::input::tests::credentials_json()).unwrap();
    let path = path.to_string_lossy().into_owned();
    (dir, path)
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_is_added_from_a_file_and_the_person_is_told_to_delete_it() {
    let stub = Stub::new(vec![]);
    let (_dir, path) = credentials_file();

    let (code, shown) = go(
        &[
            "add-endpoint",
            "home",
            "--host",
            "203.0.113.9",
            "--credentials-file",
            &path,
        ],
        &stub,
    )
    .await;

    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("Endpoint added"), "{}", shown.out());
    assert!(shown.out().contains(AN_ID), "{}", shown.out());
    assert!(
        shown.out().contains("delete it"),
        "the file holds the keys: {}",
        shown.out()
    );
    assert!(!shown.out().contains(crate::input::tests::SENTINEL));
    assert_eq!(stub.requests_named("AddEndpoint"), 1);
    let sent = stub
        .log()
        .into_iter()
        .find(|r| r.contains("AddEndpoint"))
        .unwrap();
    assert!(
        sent.contains(r#""label":"home""#) && sent.contains("203.0.113.9"),
        "{sent}"
    );
}

#[tokio::test(start_paused = true)]
async fn what_cannot_be_a_valid_endpoint_is_a_usage_error_and_sends_nothing() {
    let stub = Stub::new(vec![]);
    let (_dir, path) = credentials_file();
    let missing = format!("{path}.missing");

    for args in [
        // A host with a scheme and a port in it.
        vec![
            "add-endpoint",
            "home",
            "--host",
            "https://x:443",
            "--credentials-file",
            &path,
        ],
        // An address no server can have.
        vec![
            "add-endpoint",
            "home",
            "--host",
            "0.0.0.0",
            "--credentials-file",
            &path,
        ],
        // A label with a control character.
        vec![
            "add-endpoint",
            "ho\u{7}me",
            "--host",
            "203.0.113.9",
            "--credentials-file",
            &path,
        ],
        // A file that is not there.
        vec![
            "add-endpoint",
            "home",
            "--host",
            "203.0.113.9",
            "--credentials-file",
            &missing,
        ],
    ] {
        let (code, shown) = go(&args, &stub).await;
        assert_eq!(code, exit::USAGE, "{args:?}: {}", shown.err());
        assert!(
            shown.err().starts_with("dnetctl:"),
            "{args:?}: {}",
            shown.err()
        );
    }
    assert!(
        stub.log().is_empty(),
        "nothing reached the service: {:?}",
        stub.log()
    );
}

#[tokio::test(start_paused = true)]
async fn a_credentials_file_that_is_not_credentials_is_refused_without_showing_it() {
    let stub = Stub::new(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-creds.json");
    std::fs::write(
        &path,
        format!("{} is not json", crate::input::tests::SENTINEL),
    )
    .unwrap();

    let (code, shown) = go(
        &[
            "add-endpoint",
            "home",
            "--host",
            "203.0.113.9",
            "--credentials-file",
            &path.to_string_lossy(),
        ],
        &stub,
    )
    .await;

    assert_eq!(code, exit::USAGE);
    assert!(!shown.err().contains("SENTINEL"), "{}", shown.err());
    assert!(stub.log().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_is_removed_enabled_and_disabled_by_id() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["remove-endpoint", AN_ID], &stub).await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("removed"), "{}", shown.out());

    let (code, shown) = go(&["disable-endpoint", AN_ID], &stub).await;
    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("disabled"), "{}", shown.out());

    let (code, shown) = go(&["enable-endpoint", AN_ID], &stub).await;
    assert_eq!(code, exit::OK);
    assert!(shown.out().contains("enabled"), "{}", shown.out());

    let sent: Vec<String> = stub
        .log()
        .into_iter()
        .filter(|r| r.contains("Endpoint"))
        .collect();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(sent[0].contains("RemoveEndpoint") && sent[0].contains(AN_ID));
    assert!(sent[1].contains(r#""enabled":false"#), "{}", sent[1]);
    assert!(sent[2].contains(r#""enabled":true"#), "{}", sent[2]);
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_id_that_is_not_one_is_a_usage_error_and_is_not_repeated() {
    let stub = Stub::new(vec![]);
    for command in ["remove-endpoint", "enable-endpoint", "disable-endpoint"] {
        let (code, shown) = go(&[command, "SENTINEL-not-an-id"], &stub).await;
        assert_eq!(code, exit::USAGE, "{command}");
        assert!(!shown.err().contains("SENTINEL"), "{}", shown.err());
    }
    assert!(stub.log().is_empty());
}

#[tokio::test(start_paused = true)]
async fn blocking_and_allowing_encrypted_dns_say_what_each_means() {
    let stub = Stub::new(vec![]);

    let (code, shown) = go(&["encrypted-dns", "block"], &stub).await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("blocked"), "{}", shown.out());

    let (code, shown) = go(&["encrypted-dns", "allow"], &stub).await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("no longer blocked"), "{}", shown.out());
    assert!(
        shown.out().contains("Rules for sites will not apply"),
        "allowing must show what it costs: {}",
        shown.out()
    );
}

#[tokio::test(start_paused = true)]
async fn json_prints_the_services_own_reply() {
    let stub = Stub::new(vec![]);
    let (code, shown) = go(&["encrypted-dns", "allow", "--json"], &stub).await;
    assert_eq!(code, exit::OK);
    let value: serde_json::Value = serde_json::from_str(&shown.out()).unwrap();
    assert_eq!(value["block"], false);
    assert!(value["consequence"].is_string());
}

#[tokio::test(start_paused = true)]
async fn a_refusal_is_shown_with_its_reason_and_fails() {
    let stub = Stub::new(vec![]);
    *stub.change.lock().unwrap() = Err(IpcError::InvalidRequest {
        detail: "disconnect before changing endpoints".into(),
    });

    for args in [
        vec!["remove-endpoint", AN_ID],
        vec!["enable-endpoint", AN_ID],
        vec!["encrypted-dns", "allow"],
    ] {
        let (code, shown) = go(&args, &stub).await;
        assert_eq!(code, exit::REFUSED, "{args:?}");
        assert!(
            shown.err().contains("disconnect before changing"),
            "{}",
            shown.err()
        );
        assert!(
            shown.out().is_empty(),
            "no success text on a refusal: {}",
            shown.out()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_reply_that_is_not_what_was_promised_is_not_reported_as_success() {
    // An add that does not name the new endpoint, and an opt-out that does not say what it costs.
    let (_dir, path) = credentials_file();
    for (args, reply) in [
        (
            vec![
                "add-endpoint",
                "home",
                "--host",
                "203.0.113.9",
                "--credentials-file",
                path.as_str(),
            ],
            "{}",
        ),
        (vec!["encrypted-dns", "allow"], r#"{"block":false}"#),
    ] {
        let (code, shown) =
            go_with(&args, &Scripted(frame::encode(reply).unwrap()), pending()).await;
        assert_eq!(code, exit::UNEXPECTED, "{args:?}: {}", shown.out());
        assert!(shown.out().is_empty(), "{}", shown.out());
    }
}

#[tokio::test(start_paused = true)]
async fn nothing_is_sent_to_a_service_this_program_cannot_talk_to() {
    let versioned = Versioned::reporting(99, 100);
    let (code, _) = go_with(&["remove-endpoint", AN_ID], &versioned, pending()).await;
    assert_eq!(code, exit::INCOMPATIBLE);
    assert_eq!(*versioned.seen.lock().unwrap(), ["GetVersion"]);
}

// ------------------------------------------------------------------ importing a profile update

fn document_file(dir: &tempfile::TempDir, name: &str, text: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    path.to_string_lossy().into_owned()
}

#[tokio::test(start_paused = true)]
async fn signed_documents_are_handed_over_from_files_and_the_change_is_described() {
    let stub = Stub::new(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let keys = document_file(&dir, "keys.json", r#"{"payloadType":"keys"}"#);
    let feed = document_file(&dir, "feed.json", r#"{"payloadType":"feed"}"#);

    let (code, shown) = go(
        &["import-feed", "--keys-file", &keys, "--feed-file", &feed],
        &stub,
    )
    .await;

    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(
        shown.out().contains("definitions updated"),
        "{}",
        shown.out()
    );
    assert!(shown.out().contains("next connection"), "{}", shown.out());
    let sent = stub
        .log()
        .into_iter()
        .find(|r| r.contains("ImportFeed"))
        .unwrap();
    assert!(sent.contains("keys") && sent.contains("feed"), "{sent}");
}

#[tokio::test(start_paused = true)]
async fn an_import_that_changes_nothing_says_so() {
    let stub = Stub::new(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let feed = document_file(&dir, "feed.json", "{}");
    let (code, shown) = go_with(
        &["import-feed", "--feed-file", &feed],
        &Scripted(frame::encode(r#"{"imported":true,"changes":[]}"#).unwrap()),
        pending(),
    )
    .await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(shown.out().contains("Nothing changed"), "{}", shown.out());
    drop(stub);
}

#[tokio::test(start_paused = true)]
async fn a_file_that_cannot_be_a_signed_document_is_a_usage_error_and_sends_nothing() {
    let stub = Stub::new(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let huge = document_file(
        &dir,
        "huge.json",
        &"x".repeat(dnet_core::feed::ENVELOPE_MAX_BYTES + 1),
    );
    let missing = format!("{}.missing", huge);
    let binary = dir.path().join("binary.json");
    std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).unwrap();

    for path in [huge, missing, binary.to_string_lossy().into_owned()] {
        let (code, shown) = go(&["import-feed", "--feed-file", &path], &stub).await;
        assert_eq!(code, exit::USAGE, "{path}: {}", shown.err());
    }
    assert!(stub.log().is_empty(), "{:?}", stub.log());
}

#[tokio::test(start_paused = true)]
async fn the_services_refusal_of_a_document_is_shown_with_its_reason() {
    let stub = Stub::new(vec![]);
    *stub.change.lock().unwrap() = Err(IpcError::InvalidRequest {
        detail: "the feed was refused: it is older than the one already accepted".into(),
    });
    let dir = tempfile::tempdir().unwrap();
    let feed = document_file(&dir, "feed.json", "{}");

    let (code, shown) = go(&["import-feed", "--feed-file", &feed], &stub).await;

    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("older than"), "{}", shown.err());
    assert!(shown.out().is_empty(), "{}", shown.out());
}

#[tokio::test(start_paused = true)]
async fn a_reply_that_is_not_what_an_import_promises_is_not_success() {
    let dir = tempfile::tempdir().unwrap();
    let feed = document_file(&dir, "feed.json", "{}");
    for reply in [
        r#"{}"#,
        r#"{"imported":false,"changes":[]}"#,
        r#"{"imported":true}"#,
    ] {
        let (code, shown) = go_with(
            &["import-feed", "--feed-file", &feed],
            &Scripted(frame::encode(reply).unwrap()),
            pending(),
        )
        .await;
        assert_eq!(code, exit::UNEXPECTED, "{reply}: {}", shown.out());
        assert!(shown.out().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn a_change_name_from_the_service_is_printed_as_plain_text() {
    let dir = tempfile::tempdir().unwrap();
    let feed = document_file(&dir, "feed.json", "{}");
    let (code, shown) = go_with(
        &["import-feed", "--feed-file", &feed],
        &Scripted(frame::encode("{\"imported\":true,\"changes\":[\"\\u001b[31mred\"]}").unwrap()),
        pending(),
    )
    .await;
    assert_eq!(code, exit::OK);
    assert!(!shown.out().contains('\u{1b}'), "{:?}", shown.out());
}

// ------------------------------------------------------------------ asking for updates

#[tokio::test(start_paused = true)]
async fn asking_for_updates_says_which_network_the_check_uses() {
    let stub = Stub::new(vec![]);
    let (code, shown) = go(&["check-updates"], &stub).await;
    assert_eq!(code, exit::OK, "{}", shown.err());
    assert!(
        shown.out().contains("directly over your network"),
        "{}",
        shown.out()
    );
    assert!(shown.out().contains("dnetctl events"), "{}", shown.out());
    assert_eq!(stub.requests_named("FetchFeed"), 1);

    let (code, shown) = go_with(
        &["check-updates"],
        &Scripted(frame::encode(r#"{"started":true,"route":"tunnel"}"#).unwrap()),
        pending(),
    )
    .await;
    assert_eq!(code, exit::OK);
    assert!(
        shown.out().contains("through your connection"),
        "{}",
        shown.out()
    );
}

#[tokio::test(start_paused = true)]
async fn a_check_that_is_already_under_way_is_a_refusal_that_may_pass() {
    let stub = Stub::new(vec![]);
    *stub.change.lock().unwrap() = Err(IpcError::ServiceBusy);
    let (code, shown) = go(&["check-updates"], &stub).await;
    assert_eq!(code, exit::REFUSED);
    assert!(shown.err().contains("try again"), "{}", shown.err());
}

#[tokio::test(start_paused = true)]
async fn a_reply_that_does_not_say_how_the_check_goes_is_not_success() {
    for reply in [
        r#"{}"#,
        r#"{"started":false,"route":"tunnel"}"#,
        r#"{"started":true}"#,
        r#"{"started":true,"route":"somewhere"}"#,
    ] {
        let (code, shown) = go_with(
            &["check-updates"],
            &Scripted(frame::encode(reply).unwrap()),
            pending(),
        )
        .await;
        assert_eq!(code, exit::UNEXPECTED, "{reply}");
        assert!(shown.out().is_empty());
    }
}
