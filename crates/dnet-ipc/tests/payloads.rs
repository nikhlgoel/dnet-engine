//! T125 — IPC payloads for connect, disconnect, status and the event stream.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`. Written before the
//! implementation (Constitution Principle IV). The caller is hostile input (Principle V), so the
//! decode side is tested for what it *refuses* as much as for what it accepts.
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-10 | `Connect` selectors are validated server-side; every request round-trips |
//! | IPC-11 | A `StateSnapshot` round-trips, and an inconsistent one cannot be encoded |
//! | IPC-12 | Every `ConnectionEvent` encodes with a `because` that explains it (extends IPC-06) |
//! | IPC-13 | The event bus replays the session, bounds its memory and numbers its events |
//! | IPC-14 | A subscription is one-way, bounded and ends when the client goes |

use std::time::Duration;

use dnet_core::ids::{EndpointId, InterfaceId, ProfileId};
use dnet_core::profile::CoreBinding;
use dnet_core::session::{ConnectionEvent, FailureCause};
use dnet_core::tier::FailoverTier;
use dnet_ipc::authz::{ClientIdentity, ConsoleSession};
use dnet_ipc::frame;
use dnet_ipc::protocol::{
    decode_request, decode_state_snapshot, encode_request, encode_state_snapshot, ActiveEndpoint,
    ActiveProfile, ConnectionStatus, IpcError, Request, RoutingPosture, StateSnapshot, Warning,
};
use dnet_ipc::server::{dispatch_request, stream_events, stream_events_with, Reply};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{
    decode_event_view, encode_event, EventBus, Subscription, MAX_SUBSCRIBERS, SESSION_BACKLOG,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn parse(wire: &str) -> Value {
    serde_json::from_str(wire).expect("valid JSON")
}

// ====================================================================== IPC-10

#[test]
fn ipc10_connect_without_selectors_means_choose_for_me() {
    for wire in [
        r#"{"request":"Connect"}"#,
        r#"{"request":"Connect","profile":null,"endpoint":null}"#,
    ] {
        assert_eq!(
            decode_request(wire),
            Ok(Request::Connect {
                acknowledge_tier2: false,
                profile: None,
                endpoint: None,
            }),
            "{wire}"
        );
    }
}

#[test]
fn ipc10_connect_carries_a_named_profile_and_endpoint() {
    let endpoint = EndpointId::new();
    let wire = json!({
        "request": "Connect",
        "acknowledge_tier2": true,
        "profile": "hy2-default",
        "endpoint": endpoint.to_string(),
    })
    .to_string();
    assert_eq!(
        decode_request(&wire),
        Ok(Request::Connect {
            acknowledge_tier2: true,
            profile: Some(ProfileId::new("hy2-default")),
            endpoint: Some(endpoint),
        })
    );
}

#[test]
fn ipc10_a_malformed_profile_id_is_refused() {
    let too_long = "a".repeat(65);
    for bad in [
        "",
        " ",
        "HY2-default",
        "hy2 default",
        "hy2_default",
        "-hy2",
        "hy2-",
        "..\\evil",
        "hy2\u{0}",
        "hy2\n",
        "ünicode",
        too_long.as_str(),
    ] {
        let wire = json!({ "request": "Connect", "profile": bad }).to_string();
        assert!(
            matches!(decode_request(&wire), Err(IpcError::InvalidRequest { .. })),
            "profile {bad:?} must be refused"
        );
    }
}

#[test]
fn ipc10_a_profile_id_at_the_length_limit_is_accepted() {
    let longest = "a".repeat(64);
    let wire = json!({ "request": "Connect", "profile": longest }).to_string();
    assert!(decode_request(&wire).is_ok());
}

#[test]
fn ipc10_a_malformed_endpoint_id_is_refused() {
    for bad in [
        json!(""),
        json!("not-a-uuid"),
        json!("{00000000-0000-0000-0000-000000000000}"),
        json!(42),
        json!(true),
        json!(["x"]),
    ] {
        let wire = json!({ "request": "Connect", "endpoint": bad }).to_string();
        assert!(
            matches!(decode_request(&wire), Err(IpcError::InvalidRequest { .. })),
            "endpoint {bad} must be refused"
        );
    }
}

#[test]
fn ipc10_consent_must_be_a_real_boolean() {
    // A consent flag that is silently read as `false` hides a client defect; refuse it.
    for bad in [json!("true"), json!(1), json!([]), json!({})] {
        let wire = json!({ "request": "Connect", "acknowledge_tier2": bad }).to_string();
        assert!(
            matches!(decode_request(&wire), Err(IpcError::InvalidRequest { .. })),
            "acknowledge_tier2 {bad} must be refused"
        );
    }
}

#[test]
fn ipc10_every_request_round_trips() {
    let all = [
        Request::GetVersion,
        Request::GetState,
        Request::GetSession,
        Request::ListEndpoints,
        Request::ListProfiles,
        Request::ListRules,
        Request::GetDiagnostics,
        Request::Connect {
            acknowledge_tier2: true,
            profile: Some(ProfileId::new("awg-default")),
            endpoint: Some(EndpointId::new()),
        },
        Request::Connect {
            acknowledge_tier2: false,
            profile: None,
            endpoint: None,
        },
        Request::Disconnect,
        Request::AddEndpoint,
        Request::RemoveEndpoint,
        Request::SetEndpointEnabled,
        Request::AddRule,
        Request::RemoveRule,
        Request::SetProfileParams,
        Request::EnableBrutal,
        Request::SetEncryptedDnsHandling,
        Request::StartProvisioning,
        Request::CancelProvisioning,
        Request::Subscribe,
    ];
    for request in all {
        assert_eq!(
            decode_request(&encode_request(&request)),
            Ok(request.clone()),
            "{request:?}"
        );
    }
}

proptest! {
    #[test]
    fn ipc10_connect_round_trips_for_any_valid_selector(
        profile in proptest::option::of("[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?"),
        acknowledge_tier2 in any::<bool>(),
        endpoint_bits in proptest::option::of(any::<u128>()),
    ) {
        let request = Request::Connect {
            acknowledge_tier2,
            profile: profile.map(ProfileId::new),
            endpoint: endpoint_bits.map(|b| EndpointId::from_uuid(uuid::Uuid::from_u128(b))),
        };
        prop_assert_eq!(decode_request(&encode_request(&request)), Ok(request));
    }

    #[test]
    fn ipc10_decode_never_panics_on_arbitrary_text(wire in ".{0,300}") {
        let _ = decode_request(&wire);
    }
}

// ====================================================================== IPC-11

fn connected(tier: FailoverTier) -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Connected,
        active_profile: Some(ActiveProfile {
            id: "hy2-default".into(),
            kind: "Hysteria2".into(),
            tier,
        }),
        active_endpoint: Some(ActiveEndpoint {
            id: EndpointId::new().to_string(),
            label: "oracle-mumbai".into(),
        }),
        failure: None,
        warnings: vec![Warning::Tier2ProfileActive],
        posture: RoutingPosture::Tunnelled { tier },
    }
}

fn idle() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Disconnected,
        active_profile: None,
        active_endpoint: None,
        failure: None,
        warnings: vec![],
        posture: RoutingPosture::FailClosed,
    }
}

fn failed(cause: FailureCause) -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Failed,
        failure: Some(cause),
        ..idle()
    }
}

fn every_cause() -> Vec<FailureCause> {
    vec![
        FailureCause::NoEndpointReachable,
        FailureCause::AllProfilesBlocked,
        FailureCause::CaptivePortalUnsatisfied,
        FailureCause::InsufficientPrivilege,
        FailureCause::CoreFailedPersistently {
            core: CoreBinding::PrimaryCore,
        },
        FailureCause::CoreFailedPersistently {
            core: CoreBinding::AmneziaWgCore,
        },
        FailureCause::NoUsablePath,
        FailureCause::ConfigurationInvalid {
            detail: "the endpoint address is empty".into(),
        },
    ]
}

#[test]
fn ipc11_connected_snapshot_round_trips_and_always_names_the_tier() {
    for tier in [FailoverTier::Tier1, FailoverTier::Tier2] {
        let snapshot = connected(tier);
        let wire = encode_state_snapshot(&snapshot).expect("consistent snapshot encodes");
        let v = parse(&wire);
        assert_eq!(v["status"], "Connected");
        assert_eq!(
            v["active_profile"]["tier"],
            if tier == FailoverTier::Tier1 {
                "Tier1"
            } else {
                "Tier2"
            }
        );
        assert_eq!(v["active_endpoint"]["label"], "oracle-mumbai");
        assert_eq!(decode_state_snapshot(&wire), Ok(snapshot));
    }
}

#[test]
fn ipc11_idle_snapshot_has_no_active_anything() {
    let wire = encode_state_snapshot(&idle()).unwrap();
    let v = parse(&wire);
    assert_eq!(v["active_profile"], Value::Null);
    assert_eq!(v["active_endpoint"], Value::Null);
    assert_eq!(v["failure"], Value::Null);
    assert_eq!(v["warnings"], json!([]));
    assert_eq!(decode_state_snapshot(&wire), Ok(idle()));
}

#[test]
fn ipc11_every_failure_cause_survives_a_snapshot_and_explains_itself() {
    for cause in every_cause() {
        let wire = encode_state_snapshot(&failed(cause.clone())).unwrap();
        let v = parse(&wire);
        assert_eq!(v["status"], "Failed");
        let detail = v["failure"]["detail"].as_str().unwrap_or_default();
        assert!(!detail.trim().is_empty(), "{cause:?} needs a detail");
        assert!(
            !v["failure"]["action"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .is_empty(),
            "{cause:?} needs an action"
        );
        assert_eq!(
            decode_state_snapshot(&wire).unwrap().failure,
            Some(cause),
            "the cause itself must come back, not the prose"
        );
    }
}

#[test]
fn ipc11_the_posture_is_reported_as_the_engines_decision() {
    let v = parse(&encode_state_snapshot(&connected(FailoverTier::Tier2)).unwrap());
    assert_eq!(v["routing_posture"]["posture"], "Tunnelled");
    assert_eq!(v["routing_posture"]["tier"], "Tier2");
    let v = parse(&encode_state_snapshot(&idle()).unwrap());
    assert_eq!(v["routing_posture"]["posture"], "FailClosed");
    assert!(v["routing_posture"].get("tier").is_none());
}

#[test]
fn ipc11_path_fields_are_absent_not_faked() {
    // Paths arrive with Phase 7 (T080-T084). Until then the snapshot must not assert that there
    // is no carrying path or no standby path: it simply does not say.
    let v = parse(&encode_state_snapshot(&connected(FailoverTier::Tier2)).unwrap());
    assert!(v.get("carrying_path").is_none());
    assert!(v.get("standby_paths").is_none());
}

#[test]
fn ipc11_an_inconsistent_snapshot_cannot_be_encoded() {
    let mut cases: Vec<(&str, StateSnapshot)> = Vec::new();

    let mut s = connected(FailoverTier::Tier1);
    s.active_profile = None;
    cases.push(("connected without a profile", s));

    let mut s = connected(FailoverTier::Tier1);
    s.active_endpoint = None;
    cases.push(("connected without an endpoint", s));

    let mut s = connected(FailoverTier::Tier1);
    s.posture = RoutingPosture::FailClosed;
    cases.push(("connected but fail-closed", s));

    let mut s = connected(FailoverTier::Tier1);
    s.posture = RoutingPosture::Tunnelled {
        tier: FailoverTier::Tier2,
    };
    cases.push(("posture tier differs from the active profile's", s));

    let mut s = connected(FailoverTier::Tier1);
    s.failure = Some(FailureCause::NoUsablePath);
    cases.push(("connected with a failure", s));

    let mut s = idle();
    s.status = ConnectionStatus::Failed;
    cases.push(("failed without a cause", s));

    let mut s = failed(FailureCause::NoUsablePath);
    s.active_profile = Some(ActiveProfile {
        id: "x".into(),
        kind: "Hysteria2".into(),
        tier: FailoverTier::Tier2,
    });
    cases.push(("failed with an active profile", s));

    let mut s = idle();
    s.posture = RoutingPosture::Tunnelled {
        tier: FailoverTier::Tier1,
    };
    cases.push(("disconnected but tunnelled", s));

    let mut s = failed(FailureCause::AllProfilesBlocked);
    s.failure = Some(FailureCause::AllProfilesBlocked);
    s.posture = RoutingPosture::Tunnelled {
        tier: FailoverTier::Tier1,
    };
    cases.push(("failed but tunnelled", s));

    for (name, snapshot) in cases {
        assert!(
            matches!(
                encode_state_snapshot(&snapshot),
                Err(IpcError::InternalError { .. })
            ),
            "{name} must not encode"
        );
    }
}

#[test]
fn ipc11_decode_refuses_what_the_encoder_would_refuse() {
    let endpoint = r#""active_endpoint":{"id":"e","label":"l"}"#;
    for wire in [
        // connected, no endpoint
        r#"{"status":"Connected","active_profile":{"id":"a","kind":"Hysteria2","tier":"Tier2"},"active_endpoint":null,"failure":null,"warnings":[],"routing_posture":{"posture":"Tunnelled","tier":"Tier2"}}"#.to_string(),
        // failed, no cause
        r#"{"status":"Failed","active_profile":null,"active_endpoint":null,"failure":null,"warnings":[],"routing_posture":{"posture":"FailClosed"}}"#.to_string(),
        // unknown warning
        format!(r#"{{"status":"Disconnected","active_profile":null,{endpoint},"failure":null,"warnings":["Mystery"],"routing_posture":{{"posture":"FailClosed"}}}}"#),
        // unknown posture
        r#"{"status":"Disconnected","active_profile":null,"active_endpoint":null,"failure":null,"warnings":[],"routing_posture":{"posture":"Direct"}}"#.to_string(),
        // a failure cause of Unknown stays unrepresentable (FR-039)
        r#"{"status":"Failed","active_profile":null,"active_endpoint":null,"failure":{"cause":"Unknown"},"warnings":[],"routing_posture":{"posture":"FailClosed"}}"#.to_string(),
    ] {
        assert!(decode_state_snapshot(&wire).is_err(), "{wire}");
    }
}

#[test]
fn ipc11_warnings_use_the_contract_names() {
    let mut s = connected(FailoverTier::Tier2);
    s.warnings = vec![
        Warning::Tier2ProfileActive,
        Warning::BrutalEnabled,
        Warning::EncryptedDnsOverridden,
    ];
    let v = parse(&encode_state_snapshot(&s).unwrap());
    assert_eq!(
        v["warnings"],
        json!([
            "Tier2ProfileActive",
            "BrutalEnabled",
            "EncryptedDnsOverridden"
        ])
    );
}

// ====================================================================== IPC-12

fn every_event() -> Vec<ConnectionEvent> {
    let endpoint = EndpointId::new();
    let mut events = vec![
        ConnectionEvent::ProbeStarted,
        ConnectionEvent::ProfileSelected {
            profile: ProfileId::new("hy2-default"),
            because: "the AmneziaWG probe timed out; Hysteria 2 carried 1.2 Mbit/s".into(),
        },
        ConnectionEvent::ProfileBlocked {
            profile: ProfileId::new("awg-default"),
            reason: "three live checks in a row failed".into(),
        },
        ConnectionEvent::EndpointMigrated {
            from: endpoint,
            to: EndpointId::new(),
            because: "oracle-mumbai stopped answering".into(),
        },
        ConnectionEvent::CoreRestarted {
            core: CoreBinding::PrimaryCore,
            attempt: 2,
        },
        ConnectionEvent::CoreRestarted {
            core: CoreBinding::AmneziaWgCore,
            attempt: 1,
        },
    ];
    for tier in [FailoverTier::Tier1, FailoverTier::Tier2] {
        events.push(ConnectionEvent::PathChanged {
            from: Some(InterfaceId::new(u64::MAX)),
            to: InterfaceId::new(7),
            tier_at_time: tier,
        });
    }
    events.push(ConnectionEvent::PathChanged {
        from: None,
        to: InterfaceId::new(7),
        tier_at_time: FailoverTier::Tier2,
    });
    events.extend(
        every_cause()
            .into_iter()
            .map(|cause| ConnectionEvent::Failed { cause }),
    );
    events
}

#[test]
fn ipc12_every_event_carries_a_because_that_explains_it() {
    for event in every_event() {
        let wire = encode_event(&event).unwrap_or_else(|e| panic!("{event:?}: {e}"));
        let v = parse(&wire);
        let name = v["event"].as_str().expect("event name");
        let because = v["because"].as_str().expect("because");
        assert!(!because.trim().is_empty(), "{event:?}");
        assert!(!because.trim().eq_ignore_ascii_case(name), "{event:?}");
        // The decode side applies the same rule the contract states.
        let view = decode_event_view(&wire).expect("decodes");
        assert_eq!(view.event, name);
        assert_eq!(view.because, because);
    }
}

#[test]
fn ipc12_a_producer_that_forgot_its_because_is_an_error_not_a_blank() {
    let blank = ConnectionEvent::ProfileSelected {
        profile: ProfileId::new("hy2-default"),
        because: "  ".into(),
    };
    assert!(matches!(
        encode_event(&blank),
        Err(IpcError::InvalidRequest { .. })
    ));
    let blank = ConnectionEvent::EndpointMigrated {
        from: EndpointId::new(),
        to: EndpointId::new(),
        because: String::new(),
    };
    assert!(encode_event(&blank).is_err());
    let blank = ConnectionEvent::ProfileBlocked {
        profile: ProfileId::new("x"),
        reason: String::new(),
    };
    assert!(encode_event(&blank).is_err());
}

#[test]
fn ipc12_event_fields_are_stable() {
    let to = InterfaceId::new(7);
    let v = parse(
        &encode_event(&ConnectionEvent::PathChanged {
            from: Some(InterfaceId::new(u64::MAX)),
            to,
            tier_at_time: FailoverTier::Tier2,
        })
        .unwrap(),
    );
    assert_eq!(v["event"], "PathChanged");
    // 64-bit LUIDs travel as decimal strings: a JSON number loses bits above 2^53.
    assert_eq!(v["from"], "18446744073709551615");
    assert_eq!(v["to"], "7");
    assert_eq!(v["tier_at_time"], "Tier2");
    assert!(
        v["because"].as_str().unwrap().contains("will not survive"),
        "a Tier 2 path change must say established connections break"
    );

    let v = parse(
        &encode_event(&ConnectionEvent::PathChanged {
            from: None,
            to,
            tier_at_time: FailoverTier::Tier1,
        })
        .unwrap(),
    );
    assert_eq!(v["from"], Value::Null);
    assert!(v["because"].as_str().unwrap().contains("should survive"));

    let v = parse(
        &encode_event(&ConnectionEvent::Failed {
            cause: FailureCause::AllProfilesBlocked,
        })
        .unwrap(),
    );
    assert_eq!(v["failure"]["cause"], "AllProfilesBlocked");
}

#[test]
fn ipc12_event_text_never_names_the_primary_core() {
    // Branding rule: no UI-visible string may name the primary core's vendor. The wire `because`
    // reaches the UI, so scan every variant.
    for event in every_event() {
        let wire = encode_event(&event).unwrap().to_lowercase();
        // Assembled from pieces: this very file must not contain the names `lint-branding` bans.
        let forbidden = [
            ["sing", "-box"].concat(),
            ["sing", "box"].concat(),
            ["sager", "net"].concat(),
            ["win", "tun"].concat(),
            ["wire", "guard"].concat(),
        ];
        for name in &forbidden {
            assert!(!wire.contains(name.as_str()), "{name} in {wire}");
        }
    }
}

#[test]
fn ipc12_decode_refuses_an_event_without_a_real_because() {
    for wire in [
        r#"{"event":"ProbeStarted"}"#,
        r#"{"event":"ProbeStarted","because":""}"#,
        r#"{"event":"ProbeStarted","because":"ProbeStarted"}"#,
        r#"{"because":"x"}"#,
        r#"{"event":7,"because":"x"}"#,
        "[]",
        "not json",
    ] {
        assert!(decode_event_view(wire).is_err(), "{wire}");
    }
}

// ====================================================================== IPC-13

#[test]
fn ipc13_events_are_numbered_in_order() {
    let bus = EventBus::new();
    for _ in 0..3 {
        bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    }
    let sub = bus.subscribe().unwrap();
    let seqs: Vec<u64> = sub
        .backlog
        .iter()
        .map(|w| parse(w)["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 2, 3]);
}

#[tokio::test]
async fn ipc13_a_late_subscriber_gets_the_session_so_far_then_live_events_with_no_gap() {
    let bus = EventBus::new();
    bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    let mut sub = bus.subscribe().unwrap();
    assert_eq!(sub.backlog.len(), 1);
    bus.publish(&ConnectionEvent::Failed {
        cause: FailureCause::NoUsablePath,
    })
    .unwrap();
    let live = sub.live.recv().await.unwrap();
    assert_eq!(
        parse(&live)["seq"],
        2,
        "the first live event follows the backlog"
    );
}

#[test]
fn ipc13_the_backlog_is_bounded_and_keeps_the_newest() {
    let bus = EventBus::new();
    for _ in 0..(SESSION_BACKLOG + 40) {
        bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    }
    let sub = bus.subscribe().unwrap();
    assert_eq!(sub.backlog.len(), SESSION_BACKLOG);
    let last = parse(sub.backlog.last().unwrap())["seq"].as_u64().unwrap();
    assert_eq!(last, (SESSION_BACKLOG + 40) as u64);
}

#[test]
fn ipc13_a_new_session_clears_the_backlog_but_not_the_numbering() {
    let bus = EventBus::new();
    bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    bus.begin_session();
    bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    let sub = bus.subscribe().unwrap();
    assert_eq!(sub.backlog.len(), 1);
    assert_eq!(
        parse(&sub.backlog[0])["seq"],
        2,
        "numbering never repeats within a run"
    );
}

#[test]
fn ipc13_subscribers_are_capped_and_a_slot_is_released_on_drop() {
    let bus = EventBus::new();
    let held: Vec<_> = (0..MAX_SUBSCRIBERS)
        .map(|_| bus.subscribe().expect("within the cap"))
        .collect();
    assert!(matches!(bus.subscribe(), Err(IpcError::ServiceBusy)));
    drop(held);
    assert!(
        bus.subscribe().is_ok(),
        "slots come back when subscriptions end"
    );
}

#[test]
fn ipc13_publishing_with_no_subscriber_is_not_an_error() {
    let bus = EventBus::new();
    assert!(bus.publish(&ConnectionEvent::ProbeStarted).is_ok());
}

#[test]
fn ipc13_publishing_an_event_without_a_because_fails_and_records_nothing() {
    let bus = EventBus::new();
    let blank = ConnectionEvent::ProfileSelected {
        profile: ProfileId::new("x"),
        because: String::new(),
    };
    assert!(bus.publish(&blank).is_err());
    assert!(bus.subscribe().unwrap().backlog.is_empty());
}

// ====================================================================== IPC-14

struct StreamingService {
    bus: EventBus,
}

impl Service for StreamingService {
    fn console_session(&self) -> Option<ConsoleSession> {
        None
    }
    fn dispatch(&self, _: &Request) -> Result<String, IpcError> {
        Ok("{}".into())
    }
    fn subscribe(&self) -> Result<Subscription, IpcError> {
        self.bus.subscribe()
    }
}

fn authenticated() -> ClientIdentity {
    ClientIdentity {
        sid: "S-1-5-21-1".into(),
        session_id: 9,
        authenticated: true,
    }
}

fn unauthenticated() -> ClientIdentity {
    ClientIdentity {
        sid: String::new(),
        session_id: 0,
        authenticated: false,
    }
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Value {
    let mut header = [0u8; frame::HEADER_LEN];
    r.read_exact(&mut header).await.expect("header");
    let len = u32::from_le_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.expect("payload");
    parse(std::str::from_utf8(&payload).unwrap())
}

#[test]
fn ipc14_subscribe_is_authorized_as_a_stream_and_reaches_the_service() {
    let service = StreamingService {
        bus: EventBus::new(),
    };
    match dispatch_request(
        r#"{"request":"Subscribe"}"#,
        &authenticated(),
        None,
        &service,
    ) {
        Reply::Stream(_) => {}
        Reply::Response(other) => panic!("expected a stream, got {other}"),
    }
}

#[test]
fn ipc14_an_unauthenticated_client_cannot_subscribe() {
    let service = StreamingService {
        bus: EventBus::new(),
    };
    match dispatch_request(
        r#"{"request":"Subscribe"}"#,
        &unauthenticated(),
        None,
        &service,
    ) {
        Reply::Response(wire) => assert_eq!(parse(&wire)["error"], "Unauthorized"),
        Reply::Stream(_) => panic!("an unauthenticated client must not get a stream"),
    }
}

#[test]
fn ipc14_a_service_without_a_stream_refuses_with_a_reason() {
    struct NoStream;
    impl Service for NoStream {
        fn console_session(&self) -> Option<ConsoleSession> {
            None
        }
        fn dispatch(&self, _: &Request) -> Result<String, IpcError> {
            Ok("{}".into())
        }
    }
    match dispatch_request(
        r#"{"request":"Subscribe"}"#,
        &authenticated(),
        None,
        &NoStream,
    ) {
        Reply::Response(wire) => {
            let v = parse(&wire);
            assert_eq!(v["error"], "InvalidRequest");
            assert!(!v["detail"].as_str().unwrap().trim().is_empty());
        }
        Reply::Stream(_) => panic!("no stream was offered"),
    }
}

#[test]
fn ipc14_a_full_house_answers_service_busy() {
    let service = StreamingService {
        bus: EventBus::new(),
    };
    let _held: Vec<_> = (0..MAX_SUBSCRIBERS)
        .map(|_| service.bus.subscribe().unwrap())
        .collect();
    match dispatch_request(
        r#"{"request":"Subscribe"}"#,
        &authenticated(),
        None,
        &service,
    ) {
        Reply::Response(wire) => {
            let v = parse(&wire);
            assert_eq!(v["error"], "ServiceBusy");
            assert_eq!(v["retryable"], true);
        }
        Reply::Stream(_) => panic!("the cap must hold"),
    }
}

#[tokio::test]
async fn ipc14_the_stream_sends_an_ack_then_the_backlog_then_live_events() {
    let bus = EventBus::new();
    bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    let sub = bus.subscribe().unwrap();
    let (server_end, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(stream_events(server_end, Vec::new(), sub));

    let ack = read_frame(&mut client).await;
    assert_eq!(ack["subscribed"], true);
    assert_eq!(ack["backlog"], 1);
    assert_eq!(read_frame(&mut client).await["event"], "ProbeStarted");

    bus.publish(&ConnectionEvent::ProfileSelected {
        profile: ProfileId::new("hy2-default"),
        because: "it carried 1.2 Mbit/s".into(),
    })
    .unwrap();
    let live = read_frame(&mut client).await;
    assert_eq!(live["event"], "ProfileSelected");
    assert_eq!(live["seq"], 2);

    drop(client);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("the stream ends when the client goes (IPC-09)")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ipc14_a_client_that_talks_after_subscribing_is_disconnected() {
    let bus = EventBus::new();
    let sub = bus.subscribe().unwrap();
    let (server_end, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(stream_events(server_end, Vec::new(), sub));
    let _ack = read_frame(&mut client).await;

    client.write_all(b"anything").await.unwrap();
    let refusal = read_frame(&mut client).await;
    assert_eq!(refusal["error"], "InvalidRequest");
    assert!(refusal["detail"].as_str().unwrap().contains("one-way"));
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("a subscription is one-way; further input ends it")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ipc14_bytes_pipelined_behind_the_subscribe_frame_end_it() {
    let bus = EventBus::new();
    let sub = bus.subscribe().unwrap();
    let (server_end, mut client) = tokio::io::duplex(8192);
    let leftover = b"\x01\x00\x00\x00x".to_vec();
    let task = tokio::spawn(stream_events(server_end, leftover, sub));
    let _ack = read_frame(&mut client).await;
    let refusal = read_frame(&mut client).await;
    assert_eq!(refusal["error"], "InvalidRequest");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("pipelined input is a protocol violation")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ipc14_a_slow_reader_is_told_it_missed_events_and_numbering_exposes_the_gap() {
    let bus = EventBus::new();
    let sub = bus.subscribe().unwrap();
    // Overrun the live channel before the stream task gets to read anything.
    for _ in 0..(SESSION_BACKLOG * 3) {
        bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    }
    let (server_end, mut client) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(stream_events(server_end, Vec::new(), sub));

    let _ack = read_frame(&mut client).await;
    let first = read_frame(&mut client).await;
    assert_eq!(first["event"], "EventsLost");
    assert!(first["missed"].as_u64().unwrap() > 0);
    assert!(
        !first["because"].as_str().unwrap().trim().is_empty(),
        "even the loss notice explains itself"
    );
    let next = read_frame(&mut client).await;
    assert!(
        next["seq"].as_u64().unwrap() > 1,
        "the first event after the loss is not seq 1, so a client can see the gap"
    );
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}

#[tokio::test]
async fn ipc14_a_client_that_never_reads_cannot_hold_the_task_forever() {
    let bus = EventBus::new();
    let sub = bus.subscribe().unwrap();
    // A pipe with almost no buffer, and a reader that never drains it.
    let (server_end, _client) = tokio::io::duplex(16);
    let task = tokio::spawn(stream_events_with(
        server_end,
        Vec::new(),
        sub,
        Duration::from_millis(200),
    ));
    for _ in 0..8 {
        bus.publish(&ConnectionEvent::ProbeStarted).unwrap();
    }
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("a write that cannot complete is abandoned after a bounded wait")
        .unwrap();
    assert!(
        matches!(outcome, Err(IpcError::InternalError { .. })),
        "the abandoned stream reports why: {outcome:?}"
    );
}
