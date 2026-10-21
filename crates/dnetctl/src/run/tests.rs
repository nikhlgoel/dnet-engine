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
            Request::ListProfiles => Ok(r#"{"profiles":[{"id":"hy2-default","kind":"Hysteria2","tier":"Tier2","carrier":"Udp","brutal":false}]}"#.to_string()),
            Request::ListEndpoints => Ok(r#"{"endpoints":[]}"#.to_string()),
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
