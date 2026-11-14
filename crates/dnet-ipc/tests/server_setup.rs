// SPDX-License-Identifier: GPL-3.0-or-later
//! T150 — setting up the person's own server from the window (contracts/ipc-protocol.md IPC-26).
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-26 | `PrepareServer` names the kind of processor the server has; `FinishServer` carries the name, the address and what the server printed. Both are Mutating, strict and bounded; nothing a client sent is repeated back. The reply to `PrepareServer` is read as untrusted input like every reply. |

use dnet_ipc::protocol::{decode_request, encode_request, IpcError, Request, RequestClass};
use dnet_ipc::server_setup::{
    decode_prepared, encode_prepared, PortToOpen, Prepared, ServerKind, MAX_REPORT_CHARS,
    MAX_SCRIPT_CHARS,
};
use proptest::prelude::*;
use serde_json::{json, Value};

fn prepare(kind: &str) -> Value {
    json!({ "request": "PrepareServer", "arch": kind })
}

fn finish() -> Value {
    json!({
        "request": "FinishServer",
        "label": "my server",
        "host": "203.0.113.10",
        "report": "DNET-BOOTSTRAP-REPORT {\"version\":1}",
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
fn ipc_26_both_requests_round_trip_and_are_mutating() {
    for (wire, kind) in [("amd64", ServerKind::Amd64), ("arm64", ServerKind::Arm64)] {
        let request = decode(&prepare(wire)).unwrap();
        assert_eq!(request, Request::PrepareServer { arch: kind });
        assert_eq!(request.class(), RequestClass::Mutating);
        assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    }
    let request = decode(&finish()).unwrap();
    assert_eq!(request.class(), RequestClass::Mutating);
    assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    match request {
        Request::FinishServer {
            label,
            host,
            report,
        } => {
            assert_eq!(label, "my server");
            assert_eq!(host, "203.0.113.10");
            assert!(report.starts_with("DNET-BOOTSTRAP-REPORT"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn ipc_26_the_kind_of_server_is_one_of_two_and_not_repeated() {
    for bad in ["", "x86_64", "AMD64", "arm", "amd64 ", "SENTINEL"] {
        let detail = refused(decode(&prepare(bad)));
        assert!(!detail.contains("SENTINEL"), "{detail}");
        assert!(detail.contains("arch"), "{detail}");
    }
    assert!(decode(&json!({ "request": "PrepareServer" })).is_err());
    assert!(decode(&json!({ "request": "PrepareServer", "arch": 5 })).is_err());
    let mut wire = prepare("amd64");
    wire["surprise-field-name"] = json!(1);
    let detail = refused(decode(&wire));
    assert!(
        detail.contains("unknown field") && !detail.contains("surprise"),
        "{detail}"
    );
}

#[test]
fn ipc_26_finish_needs_every_field_and_takes_no_other() {
    for field in ["label", "host", "report"] {
        let mut wire = finish();
        wire.as_object_mut().unwrap().remove(field);
        assert!(refused(decode(&wire)).contains(field), "{field}");
        let mut wire = finish();
        wire[field] = Value::Null;
        assert!(decode(&wire).is_err(), "{field}: null accepted");
    }
    let mut wire = finish();
    wire["credentials"] = json!({});
    assert!(refused(decode(&wire)).contains("unknown field"));
}

/// The name and address follow the same rules as adding a server by hand, so one cannot be used to
/// smuggle in what the other would refuse.
#[test]
fn ipc_26_the_name_and_address_follow_the_rules_for_any_server() {
    for (field, bad) in [
        ("label", ""),
        ("label", "   "),
        ("label", "tab\there"),
        ("label", "SENTINEL\u{202e}"),
        ("host", ""),
        ("host", "http://203.0.113.10"),
        ("host", "203.0.113.10:51820"),
        ("host", "0.0.0.0"),
        ("host", "224.0.0.1"),
        ("host", "SENTINEL bad host"),
        ("host", "a/b"),
    ] {
        let mut wire = finish();
        wire[field] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(detail.contains(field), "{field}={bad:?}: {detail}");
        assert!(!detail.contains("SENTINEL"), "{detail}");
    }
    let mut wire = finish();
    wire["label"] = json!("x".repeat(dnet_ipc::protocol::MAX_LABEL_CHARS + 1));
    assert!(decode(&wire).is_err());
}

/// What the server printed is pasted by a person, so it may hold several lines and a prompt; it is
/// bounded and free of control characters other than line breaks and tabs, and is never repeated.
#[test]
fn ipc_26_the_pasted_text_is_bounded_and_clean_and_never_repeated() {
    let mut wire = finish();
    wire["report"] = json!(
        "last login: today\r\nroot@server:~# sh x\nDNET-BOOTSTRAP-REPORT {}\n\troot@server:~#"
    );
    assert!(decode(&wire).is_ok());

    for bad in [
        String::new(),
        "   \n  ".to_owned(),
        "SENTINEL\u{0}".to_owned(),
        "SENTINEL\u{1b}[31m".to_owned(),
        "SENTINEL\u{202e}".to_owned(),
        "x".repeat(MAX_REPORT_CHARS + 1),
    ] {
        let mut wire = finish();
        wire["report"] = json!(bad);
        let detail = refused(decode(&wire));
        assert!(detail.contains("report"), "{detail}");
        assert!(!detail.contains("SENTINEL"), "{detail}");
    }
    let mut wire = finish();
    wire["report"] = json!("x".repeat(MAX_REPORT_CHARS));
    assert!(decode(&wire).is_ok());
}

// ------------------------------------------------------------------ the reply

fn prepared() -> Prepared {
    Prepared {
        arch: ServerKind::Arm64,
        script: "#!/bin/sh\necho hi\n".to_owned(),
        ports: vec![
            PortToOpen {
                protocol: "udp".into(),
                port: 51820,
            },
            PortToOpen {
                protocol: "udp".into(),
                port: 44443,
            },
            PortToOpen {
                protocol: "tcp".into(),
                port: 8443,
            },
        ],
        valid_for_s: 3600,
    }
}

#[test]
fn ipc_26_the_reply_round_trips() {
    let reply = prepared();
    assert_eq!(decode_prepared(&encode_prepared(&reply)).unwrap(), reply);
}

#[test]
fn ipc_26_a_reply_that_is_not_what_was_promised_is_refused_not_shown() {
    let good: Value = serde_json::from_str(&encode_prepared(&prepared())).unwrap();
    let mutations: Vec<(&str, Value)> = vec![
        ("no script", {
            let mut v = good.clone();
            v.as_object_mut().unwrap().remove("script");
            v
        }),
        ("script not text", {
            let mut v = good.clone();
            v["script"] = json!(5);
            v
        }),
        ("empty script", {
            let mut v = good.clone();
            v["script"] = json!("");
            v
        }),
        ("huge script", {
            let mut v = good.clone();
            v["script"] = json!("x".repeat(MAX_SCRIPT_CHARS + 1));
            v
        }),
        ("unknown kind", {
            let mut v = good.clone();
            v["arch"] = json!("sparc");
            v
        }),
        ("no ports", {
            let mut v = good.clone();
            v["ports"] = json!([]);
            v
        }),
        ("too many ports", {
            let mut v = good.clone();
            v["ports"] = json!((0..40)
                .map(|i| json!({"protocol":"udp","port":1000+i}))
                .collect::<Vec<_>>());
            v
        }),
        ("port zero", {
            let mut v = good.clone();
            v["ports"][0]["port"] = json!(0);
            v
        }),
        ("port too big", {
            let mut v = good.clone();
            v["ports"][0]["port"] = json!(70000);
            v
        }),
        ("odd protocol", {
            let mut v = good.clone();
            v["ports"][0]["protocol"] = json!("icmp");
            v
        }),
        ("lifetime 0", {
            let mut v = good.clone();
            v["valid_for_s"] = json!(0);
            v
        }),
        ("lifetime huge", {
            let mut v = good.clone();
            v["valid_for_s"] = json!(10_000_000u64);
            v
        }),
    ];
    for (what, v) in mutations {
        assert!(
            decode_prepared(&v.to_string()).is_err(),
            "{what} was accepted"
        );
    }
    for junk in ["", "null", "[]", "not json", "{"] {
        assert!(decode_prepared(junk).is_err(), "{junk:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn ipc_26_the_decoder_never_panics_on_shaped_text(
        arch in prop_oneof![Just("amd64".to_string()), Just("arm64".to_string()), "\\PC{0,8}"],
        label in "\\PC{0,80}",
        host in "\\PC{0,300}",
        report in "\\PC{0,400}",
    ) {
        for wire in [prepare(&arch), json!({"request":"FinishServer","label":label,"host":host,"report":report})] {
            if let Ok(request) = decode(&wire) {
                prop_assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
            }
        }
    }

    #[test]
    fn ipc_26_the_reply_decoder_never_panics(text in "\\PC{0,500}") {
        let _ = decode_prepared(&text);
    }
}
