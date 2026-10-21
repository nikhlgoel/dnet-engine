//! Nothing the other end of the pipe sends may crash a program that reads it.
//!
//! The server reads requests from any signed-in user, and the clients (`dnetctl`, the tray) read
//! replies from whatever owns the pipe. Both ends are therefore parsers of input they cannot trust,
//! and a panic in either is a bug: in a client it is a crash on a hostile or confused peer, in the
//! service it ends a task (and, before unwinding was enabled for release, the whole process).
//!
//! These generate arbitrary text and arbitrary JSON, weighted towards the field names the parsers
//! look for so that the deeper branches run, not just "this is not JSON".

use dnet_ipc::client::{check_version, classify_reply, Reply};
use dnet_ipc::protocol::{decode_failure_cause, decode_request, decode_state_snapshot};
use dnet_ipc::version;
use dnet_ipc::wire::decode_event_view;
use proptest::prelude::*;
use serde_json::{Map, Value};

/// Names the parsers look for, so that generated objects reach their inner checks.
const KEYS: &[&str] = &[
    "status",
    "active_profile",
    "active_endpoint",
    "routing_posture",
    "posture",
    "tier",
    "id",
    "kind",
    "label",
    "failure",
    "cause",
    "title",
    "detail",
    "action",
    "warnings",
    "event",
    "because",
    "seq",
    "profile",
    "error",
    "retryable",
    "protocol_version",
    "min_protocol_version",
    "service_version",
    "request",
    "acknowledge_tier2",
    "endpoint",
    "from",
    "to",
    "core",
    "attempt",
    "missed",
    "profiles",
    "endpoints",
];

fn key() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::sample::select(KEYS).prop_map(str::to_owned),
        1 => "[a-zA-Z_]{1,10}",
    ]
}

fn json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        (-1e12f64..1e12f64).prop_map(Value::from),
        prop::sample::select(vec![
            "Connected",
            "Disconnected",
            "Probing",
            "Failed",
            "Tunnelled",
            "FailClosed",
            "Tier1",
            "Tier2",
            "AllProfilesBlocked",
            "Unknown",
            "",
        ])
        .prop_map(|s| Value::String(s.to_owned())),
        "\\PC{0,30}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 40, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec((key(), inner), 0..7)
                .prop_map(|pairs| Value::Object(pairs.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn a_reply_of_any_text_is_classified_without_panicking(text in "\\PC{0,400}") {
        let _ = classify_reply(&text);
    }

    #[test]
    fn a_reply_of_any_json_is_classified_without_panicking(value in json()) {
        let _ = classify_reply(&value.to_string());
    }

    #[test]
    fn a_state_of_any_json_is_refused_or_accepted_without_panicking(value in json()) {
        let _ = decode_state_snapshot(&value.to_string());
    }

    #[test]
    fn a_state_of_any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,400}") {
        let _ = decode_state_snapshot(&text);
    }

    #[test]
    fn an_event_of_any_json_is_refused_or_accepted_without_panicking(value in json()) {
        let _ = decode_event_view(&value.to_string());
    }

    #[test]
    fn an_event_of_any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,300}") {
        let _ = decode_event_view(&text);
    }

    #[test]
    fn a_failure_of_any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,100}") {
        let _ = decode_failure_cause(&text);
    }

    #[test]
    fn a_request_of_any_json_is_refused_or_accepted_without_panicking(value in json()) {
        let _ = decode_request(&value.to_string());
    }

    #[test]
    fn a_version_of_any_json_is_refused_or_accepted_without_panicking(value in json()) {
        let _ = version::decode(&value);
        let _ = check_version(Reply::Done(value));
    }

    /// A version the parser accepts is one a person can safely be shown and a comparison can rely
    /// on: bounded, plain, and in order.
    #[test]
    fn an_accepted_version_is_always_sane(value in json()) {
        if let Ok(v) = version::decode(&value) {
            prop_assert!(v.protocol >= 1 && v.min_protocol >= 1);
            prop_assert!(v.min_protocol <= v.protocol);
            prop_assert!(!v.service.is_empty() && v.service.len() <= 64);
            prop_assert!(v.service.bytes().all(|b| b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'-' | b'+' | b'_')));
        }
    }
}
