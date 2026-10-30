//! T105 — turning Brutal congestion control on and off (FR-006, contracts/ipc-protocol.md IPC-24).
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-24 | `EnableBrutal` names a profile, both directions in Mbit/s and the warning revision the person accepted; `DisableBrutal` names a profile. Both are Mutating, strict, bounded, round-trip, and never repeat what was sent. |
//!
//! Brutal ignores loss and so takes capacity from everyone else on the access point; it is off unless
//! a person turns it on having been shown why that matters. These tests pin what the request must carry
//! for that to be true, and what it refuses.

use dnet_core::ids::ProfileId;
use dnet_core::profile::BRUTAL_WARNING_REVISION;
use dnet_ipc::protocol::{decode_request, encode_request, IpcError, Request, RequestClass};
use proptest::prelude::*;
use serde_json::{json, Value};

fn enable() -> Value {
    json!({
        "request": "EnableBrutal",
        "profile": "hy2-default",
        "up_mbps": 50,
        "down_mbps": 200,
        "warning_revision": BRUTAL_WARNING_REVISION,
    })
}

fn decode(value: &Value) -> Result<Request, IpcError> {
    decode_request(&value.to_string())
}

fn refused(result: Result<Request, IpcError>) -> String {
    match result {
        Err(IpcError::InvalidRequest { detail }) => detail,
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn ipc_24_enable_and_disable_round_trip_and_are_mutating() {
    let on = decode(&enable()).unwrap();
    assert_eq!(
        on,
        Request::EnableBrutal {
            profile: ProfileId::new("hy2-default"),
            up_mbps: 50,
            down_mbps: 200,
            warning_revision: BRUTAL_WARNING_REVISION,
        }
    );
    let off = decode(&json!({ "request": "DisableBrutal", "profile": "hy2-default" })).unwrap();
    assert_eq!(
        off,
        Request::DisableBrutal {
            profile: ProfileId::new("hy2-default")
        }
    );
    for request in [on, off] {
        assert_eq!(request.class(), RequestClass::Mutating);
        assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    }
}

#[test]
fn ipc_24_every_field_is_required_and_nothing_else_is_taken() {
    for field in ["profile", "up_mbps", "down_mbps", "warning_revision"] {
        let mut wire = enable();
        wire.as_object_mut().unwrap().remove(field);
        let detail = refused(decode(&wire));
        assert!(detail.contains(field), "{field}: {detail}");

        let mut wire = enable();
        wire[field] = Value::Null;
        assert!(decode(&wire).is_err(), "{field}: null accepted");
    }
    let mut wire = enable();
    wire["surprise-field-name"] = json!(1);
    let detail = refused(decode(&wire));
    assert!(detail.contains("unknown field"), "{detail}");
    assert!(!detail.contains("surprise"), "repeated the field: {detail}");

    assert!(decode(&json!({ "request": "DisableBrutal" })).is_err());
    assert!(
        decode(&json!({ "request": "DisableBrutal", "profile": "hy2-default", "x": 1 })).is_err()
    );
}

/// Zero in either direction would half-enable Brutal (CC-04); a number no link has, or one that is
/// not a whole number, is a mistake, not a setting.
#[test]
fn ipc_24_the_bandwidth_must_be_a_plausible_whole_number_both_ways() {
    for (field, bad) in [
        ("up_mbps", json!(0)),
        ("down_mbps", json!(0)),
        ("up_mbps", json!(1_000_001)),
        ("down_mbps", json!(u64::MAX)),
        ("up_mbps", json!(-5)),
        ("up_mbps", json!(1.5)),
        ("down_mbps", json!("200")),
        ("down_mbps", json!(true)),
    ] {
        let mut wire = enable();
        wire[field] = bad.clone();
        let detail = refused(decode(&wire));
        assert!(detail.contains(field), "{field}={bad}: {detail}");
        assert!(
            !detail.contains(&bad.to_string()) || bad == json!(0),
            "repeated {bad}: {detail}"
        );
    }
    let mut wire = enable();
    wire["up_mbps"] = json!(1_000_000);
    wire["down_mbps"] = json!(1);
    assert!(decode(&wire).is_ok());
}

/// The revision is what the person was shown. One that is not the warning in force has not been
/// accepted, so the request is refused here, before it reaches the service.
#[test]
fn ipc_24_only_the_current_warning_counts_as_accepted() {
    for revision in [0, BRUTAL_WARNING_REVISION + 1, u32::MAX] {
        let mut wire = enable();
        wire["warning_revision"] = json!(revision);
        let detail = refused(decode(&wire));
        assert!(detail.contains("warning"), "{detail}");
    }
}

#[test]
fn ipc_24_a_profile_id_is_checked_and_not_repeated() {
    for bad in [
        "",
        "HY2",
        "hy2 default",
        "-x",
        "x-",
        "a/b",
        "hy2-default\u{202e}",
    ] {
        let mut wire = enable();
        wire["profile"] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(
            bad.is_empty() || !detail.contains(bad),
            "repeated {bad:?}: {detail}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn ipc_24_the_decoder_never_panics_on_brutal_shaped_text(
        profile in "\\PC{0,40}",
        up in any::<i64>(),
        down in prop_oneof![any::<i64>().prop_map(Value::from), "\\PC{0,8}".prop_map(Value::from)],
        revision in any::<i64>(),
    ) {
        let wire = json!({
            "request": "EnableBrutal",
            "profile": profile,
            "up_mbps": up,
            "down_mbps": down,
            "warning_revision": revision,
        });
        if let Ok(request) = decode(&wire) {
            prop_assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
        }
    }
}
