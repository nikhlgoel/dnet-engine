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
use dnet_ipc::netview::{
    decode_paths, decode_stats, Role, StatsReply, MAX_NAME_CHARS, MAX_PATHS, MAX_TRACE,
};
use dnet_ipc::protocol::{decode_failure_cause, decode_request, decode_state_snapshot};
use dnet_ipc::version;
use dnet_ipc::wire::decode_event_view;
use proptest::prelude::*;
use serde_json::{json, Map, Value};

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
    "paths",
    "watching",
    "as_of_unix_ms",
    "degraded",
    "name",
    "role",
    "measured",
    "rtt_ms",
    "jitter_ms",
    "loss",
    "trace_ms",
    "typical_ms",
    "quality",
    "staying",
    "connected",
    "connected_for_s",
    "network_changes",
    "changes_that_drop_connections",
    "longest_degraded_s",
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

    #[test]
    fn a_networks_reply_of_any_text_is_refused_or_accepted_without_panicking(
        text in "\\PC{0,400}"
    ) {
        let _ = decode_paths(&text);
        let _ = decode_stats(&text);
    }

    #[test]
    fn a_networks_reply_of_any_json_is_refused_or_accepted_without_panicking(value in json()) {
        let _ = decode_paths(&value.to_string());
        let _ = decode_stats(&value.to_string());
    }

    /// What is accepted obeys the rules the interface relies on: bounded, in range, consistent, and
    /// with nothing in a name that could disguise other text.
    #[test]
    fn an_accepted_networks_reply_is_always_sane(value in json()) {
        if let Ok(reply) = decode_paths(&value.to_string()) {
            prop_assert!(reply.paths.len() <= MAX_PATHS);
            prop_assert!(reply.paths.iter().filter(|p| p.role == Role::Carrying).count() <= 1);
            for p in &reply.paths {
                prop_assert!(p.id.bytes().all(|b| b.is_ascii_digit()) && !p.id.is_empty());
                prop_assert!(p.trace_ms.len() <= MAX_TRACE);
                prop_assert!(p.loss.is_none_or(|l| (0.0..=1.0).contains(&l)));
                prop_assert!(p.rtt_ms.is_none_or(|v| v.is_finite() && v >= 0.0));
                if !p.measured {
                    prop_assert!(
                        p.quality.is_none() && p.rtt_ms.is_none() && p.jitter_ms.is_none() && p.loss.is_none(),
                        "an unmeasured network claims nothing"
                    );
                }
                if let Some((lo, hi)) = p.typical_ms {
                    prop_assert!(lo <= hi);
                }
                if let Some(name) = &p.name {
                    prop_assert!(!name.is_empty() && name.chars().count() <= MAX_NAME_CHARS);
                    prop_assert!(!name.chars().any(hostile), "a name with a hostile character was accepted");
                }
            }
        }
    }

    #[test]
    fn accepted_stats_are_consistent(value in json()) {
        if let Ok(StatsReply::Connected {
            connected_for_s,
            network_changes,
            changes_that_drop_connections,
            longest_degraded_s,
            ..
        }) = decode_stats(&value.to_string())
        {
            prop_assert!(longest_degraded_s <= connected_for_s);
            prop_assert!(changes_that_drop_connections <= network_changes);
        }
    }
}

/// Characters that must never reach a screen from a peer.
fn hostile(c: char) -> bool {
    c.is_control()
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// Replies shaped like a real one: mostly valid, with a tenth of the networks carrying something
/// hostile or impossible, so that the properties are exercised on replies the decoder *accepts* and
/// not only on ones it refuses (a test below checks that it does).
fn paths_like() -> impl Strategy<Value = String> {
    let valid = (
        0u64..1_000_000,
        prop::sample::select(vec!["Wifi", "Cellular", "Ethernet", "Other"]),
        prop::option::of(r"\PC{0,90}"),
        prop::sample::select(vec!["Standby", "Standby", "Unusable", "Carrying"]),
        any::<bool>(),
        prop::sample::select(vec!["Good", "Poor", "Unusable"]),
        0f64..5000.0,
        0f64..1.0,
        prop::collection::vec(prop::option::of(0f64..5000.0), 0..50),
        (0f64..100.0, 0f64..100.0),
    );
    let garbage = (
        prop::sample::select(vec!["Leading", "Standby"]),
        prop::option::of(-10f64..2.0e7),
        prop::option::of(-0.5f64..1.5),
        prop::collection::vec(prop::option::of(-10f64..2.0e7), 0..70),
    );
    let path = (valid, garbage, 0u8..10).prop_map(
        |(
            (id, kind, name, role, measured, quality, rtt, loss, trace, (a, b)),
            (bad_role, bad_rtt, bad_loss, bad_trace),
            corrupt,
        )| {
            let mut p = json!({
                "id": id.to_string(), "kind": kind, "name": name, "role": role,
                "measured": measured,
                "quality": measured.then_some(quality),
                "rtt_ms": measured.then_some(rtt), "jitter_ms": measured.then_some(rtt),
                "loss": measured.then_some(loss),
                "trace_ms": trace, "typical_ms": measured.then(|| json!([a.min(b), a.max(b)])),
            });
            if corrupt == 0 {
                p["role"] = json!(bad_role);
                p["rtt_ms"] = json!(bad_rtt);
                p["loss"] = json!(bad_loss);
                p["trace_ms"] = json!(bad_trace);
            }
            p
        },
    );
    (prop::collection::vec(path, 0..4), any::<bool>()).prop_map(|(paths, watching)| {
        json!({ "as_of_unix_ms": 1u64, "watching": watching, "paths": paths, "degraded": null })
            .to_string()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn replies_shaped_like_real_ones_are_accepted_only_when_sane(wire in paths_like()) {
        if let Ok(reply) = decode_paths(&wire) {
            prop_assert!(reply.paths.len() <= MAX_PATHS);
            prop_assert!(reply.paths.iter().filter(|p| p.role == Role::Carrying).count() <= 1);
            for p in &reply.paths {
                prop_assert!(p.trace_ms.len() <= MAX_TRACE);
                prop_assert!(p.loss.is_none_or(|l| (0.0..=1.0).contains(&l)));
                prop_assert!(p.rtt_ms.is_none_or(|v| v.is_finite() && v >= 0.0));
                if !p.measured {
                    prop_assert!(p.quality.is_none() && p.rtt_ms.is_none() && p.loss.is_none());
                }
                if let Some(name) = &p.name {
                    prop_assert!(name.chars().count() <= MAX_NAME_CHARS);
                    prop_assert!(!name.chars().any(hostile), "a hostile name was accepted");
                }
            }
        }
    }
}

#[test]
fn a_fair_share_of_generated_replies_are_accepted() {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strategy = paths_like();
    let (mut accepted, mut with_networks, total) = (0, 0, 400);
    for _ in 0..total {
        let wire = strategy.new_tree(&mut runner).unwrap().current();
        if let Ok(reply) = decode_paths(&wire) {
            accepted += 1;
            with_networks += usize::from(!reply.paths.is_empty());
        }
    }
    assert!(
        accepted >= 20 && with_networks >= 5,
        "the property above would be vacuous: {accepted} of {total} accepted, {with_networks} with networks"
    );
}
