// SPDX-License-Identifier: GPL-3.0-or-later
//! T188 — adding a friend's device to the person's own server (contracts/ipc-protocol.md IPC-27).
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-27 | `RequestJoin`, `AcceptInvite`, `PrepareDevice` and `FinishDevice` are Mutating, strict and bounded, and never repeat what a client sent. Their replies are read as untrusted input like every reply. |

use dnet_ipc::devices::{
    decode_device_invited, decode_device_prepared, decode_join_requested, MAX_INVITE_CHARS,
    MAX_REQUEST_CHARS,
};
use dnet_ipc::protocol::{decode_request, encode_request, IpcError, Request, RequestClass};
use proptest::prelude::*;
use serde_json::{json, Value};

const ENDPOINT: &str = "123e4567-e89b-42d3-a456-426614174000";

fn join() -> Value {
    json!({ "request": "RequestJoin", "name": "Ravi laptop" })
}

fn accept() -> Value {
    json!({ "request": "AcceptInvite", "invite": "DNET-INVITE-1:abc-_123", "label": "Shared" })
}

fn prepare() -> Value {
    json!({ "request": "PrepareDevice", "endpoint": ENDPOINT,
            "text": "DNET-DEVICE-REQUEST {\"version\":1}" })
}

fn finish() -> Value {
    json!({ "request": "FinishDevice", "endpoint": ENDPOINT,
            "text": "DNET-DEVICE-REQUEST {\"version\":1}",
            "report": "DNET-DEVICE-REPORT {\"version\":1}" })
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
fn ipc_27_every_request_round_trips_and_is_mutating() {
    for wire in [join(), accept(), prepare(), finish()] {
        let request = decode(&wire).unwrap();
        assert_eq!(request.class(), RequestClass::Mutating, "{wire}");
        assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    }
    // The label of an invite is optional.
    let mut bare = accept();
    bare.as_object_mut().unwrap().remove("label");
    assert_eq!(
        decode(&bare).unwrap(),
        Request::AcceptInvite {
            invite: "DNET-INVITE-1:abc-_123".into(),
            label: None
        }
    );
}

#[test]
fn ipc_27_a_device_name_is_plain_and_not_repeated() {
    for bad in [
        "",
        " Ravi",
        "Ravi ",
        "Rav'i",
        "Ravi\u{202e}",
        "Ravi\n",
        "Rávi",
        &"a".repeat(33),
        "SENTINEL/slash",
    ] {
        let mut wire = join();
        wire["name"] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(!detail.contains("SENTINEL"), "{detail}");
        assert!(detail.contains("name"), "{detail}");
    }
    assert!(decode(&json!({ "request": "RequestJoin" })).is_err());
    assert!(decode(&json!({ "request": "RequestJoin", "name": 5 })).is_err());
}

#[test]
fn ipc_27_every_request_needs_its_fields_and_takes_no_other() {
    for (wire, field) in [
        (join(), "name"),
        (accept(), "invite"),
        (prepare(), "endpoint"),
        (prepare(), "text"),
        (finish(), "endpoint"),
        (finish(), "text"),
        (finish(), "report"),
    ] {
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode(&missing).is_err(), "{field} is needed");
        let mut extra = wire.clone();
        extra["surprise-field-name"] = json!(1);
        let detail = refused(decode(&extra));
        assert!(
            detail.contains("unknown field") && !detail.contains("surprise"),
            "{detail}"
        );
    }
}

#[test]
fn ipc_27_the_server_is_a_real_id_and_the_label_follows_the_rules_for_any_server() {
    for bad in ["", "not-a-uuid", "123e4567", "SENTINEL"] {
        let mut wire = prepare();
        wire["endpoint"] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(!detail.contains("SENTINEL"), "{detail}");
    }
    for bad in ["", "   ", "tab\there", "naïve", &"x".repeat(200)] {
        let mut wire = accept();
        wire["label"] = json!(bad);
        assert!(decode(&wire).is_err(), "{bad:?}");
    }
}

#[test]
fn ipc_27_pasted_text_is_bounded_and_clean_and_never_repeated() {
    let long_invite = "A".repeat(MAX_INVITE_CHARS + 1);
    let long_text = "A".repeat(MAX_REQUEST_CHARS + 1);
    for (mut wire, field, bad) in [
        (accept(), "invite", long_invite.as_str()),
        (accept(), "invite", "   "),
        (accept(), "invite", "DNET-INVITE-1:abc\u{0}"),
        (accept(), "invite", "DNET-INVITE-1:SENTINEL\u{202e}"),
        (prepare(), "text", long_text.as_str()),
        (prepare(), "text", ""),
        (prepare(), "text", "SENTINEL\u{7}"),
        (finish(), "text", long_text.as_str()),
        (finish(), "report", ""),
        (finish(), "report", "SENTINEL\u{1b}[31m"),
    ] {
        wire[field] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(!detail.contains("SENTINEL"), "{detail}");
    }
    // Line breaks and tabs are what a pasted terminal gives; they are fine.
    let mut wire = finish();
    wire["report"] = json!("root@vm:~# sh add.sh\r\nDNET-DEVICE-REPORT {}\r\n\troot@vm:~# ");
    assert!(decode(&wire).is_ok());
}

#[test]
fn ipc_27_replies_that_are_not_what_was_promised_are_refused_not_shown() {
    for wire in ["", "null", "[]", "{}", "not json", "{\"name\":\"x\"}"] {
        assert!(decode_join_requested(wire).is_err(), "{wire}");
        assert!(decode_device_prepared(wire).is_err(), "{wire}");
        assert!(decode_device_invited(wire).is_err(), "{wire}");
    }
    // A name with a direction character is refused, whatever else the reply holds.
    assert!(decode_device_invited(
        &json!({ "name": "x\u{202e}", "address": "10.9.0.3", "invite": "DNET-INVITE-1:abc" })
            .to_string()
    )
    .is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn ipc_27_no_input_makes_the_decoders_panic(text in ".{0,300}") {
        let _ = decode_request(&text);
        let _ = decode_join_requested(&text);
        let _ = decode_device_prepared(&text);
        let _ = decode_device_invited(&text);
        for field in ["name", "invite", "text", "report", "label", "endpoint"] {
            for request in ["RequestJoin", "AcceptInvite", "PrepareDevice", "FinishDevice"] {
                let wire = json!({ "request": request, field: text });
                let _ = decode_request(&wire.to_string());
            }
        }
    }
}
