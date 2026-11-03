//! T108 — adding and removing a person's routing rules (FR-022, FR-023, contracts/ipc-protocol.md IPC-25).
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-25 | `AddRule` names what it matches (`domain`, `domain_suffix`, `ip_cidr`, `application`), the value and `tunnel` or `bypass`; `RemoveRule` names a rule id. Both are Mutating and strict; a pattern the rule model refuses is refused here; nothing is repeated back. |
//!
//! The precedence is not the client's to choose: the service puts a person's rule after every built-in,
//! so no request can place one ahead of DNS capture or the endpoint bypass.

use dnet_core::ids::RuleId;
use dnet_core::rule::{IpCidr, RuleAction, RuleMatcher};
use dnet_ipc::protocol::{decode_request, encode_request, IpcError, Request, RequestClass};
use proptest::prelude::*;
use serde_json::{json, Value};

fn add(kind: &str, value: &str, action: &str) -> Value {
    json!({ "request": "AddRule", "kind": kind, "value": value, "action": action })
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
fn ipc_25_each_kind_of_rule_round_trips_and_is_mutating() {
    let cases = [
        (
            add("domain", "example.com", "bypass"),
            RuleMatcher::Domain("example.com".into()),
            RuleAction::Bypass,
        ),
        (
            add("domain_suffix", "example.org", "tunnel"),
            RuleMatcher::DomainSuffix("example.org".into()),
            RuleAction::Tunnel,
        ),
        (
            add("ip_cidr", "198.51.100.0/24", "bypass"),
            RuleMatcher::IpCidr(IpCidr::parse("198.51.100.0/24").unwrap()),
            RuleAction::Bypass,
        ),
        (
            add("application", r"C:\Program Files\App\app.exe", "tunnel"),
            RuleMatcher::Application(r"C:\Program Files\App\app.exe".into()),
            RuleAction::Tunnel,
        ),
    ];
    for (wire, matcher, action) in cases {
        let request = decode(&wire).unwrap();
        assert_eq!(request, Request::AddRule { matcher, action });
        assert_eq!(request.class(), RequestClass::Mutating);
        assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    }
    let id = RuleId::new();
    let remove = decode(&json!({ "request": "RemoveRule", "rule": id.to_string() })).unwrap();
    assert_eq!(remove, Request::RemoveRule { rule: id });
    assert_eq!(remove.class(), RequestClass::Mutating);
    assert_eq!(decode_request(&encode_request(&remove)).unwrap(), remove);
}

#[test]
fn ipc_25_every_field_is_required_and_no_other_is_taken() {
    for field in ["kind", "value", "action"] {
        let mut wire = add("domain", "example.com", "bypass");
        wire.as_object_mut().unwrap().remove(field);
        assert!(refused(decode(&wire)).contains(field), "{field}");
    }
    let mut wire = add("domain", "example.com", "bypass");
    wire["precedence"] = json!(0);
    let detail = refused(decode(&wire));
    assert!(detail.contains("unknown field"), "{detail}");
    assert!(decode(&json!({ "request": "RemoveRule" })).is_err());
    assert!(decode(&json!({ "request": "RemoveRule", "rule": "not-an-id" })).is_err());
}

/// What only the built-in set may have is refused: port matchers, capture, reject. So is a pattern the
/// rule model would refuse: empty, not a name a connection could carry, an address range that is not
/// one or that sits inside the FakeIP pool.
#[test]
fn ipc_25_a_rule_a_person_cannot_make_is_refused_and_not_repeated() {
    for wire in [
        add("dns_port", "53", "bypass"),
        add("encrypted_dns_port", "853", "bypass"),
        add("domain", "example.com", "capture"),
        add("domain", "example.com", "reject"),
        add("domain", "", "bypass"),
        add("domain", "   ", "bypass"),
        add("domain", "SENTINEL bad name", "bypass"),
        add("domain_suffix", "SENTINEL..example", "bypass"),
        add("ip_cidr", "SENTINEL/99", "bypass"),
        add("ip_cidr", "198.18.0.0/16", "bypass"),
        add("application", "", "tunnel"),
    ] {
        let detail = refused(decode(&wire));
        assert!(!detail.contains("SENTINEL"), "{wire}: {detail}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn ipc_25_the_decoder_never_panics_on_rule_shaped_text(
        kind in prop_oneof![
            Just("domain".to_string()), Just("domain_suffix".to_string()),
            Just("ip_cidr".to_string()), Just("application".to_string()), "\\PC{0,12}"
        ],
        value in "\\PC{0,300}",
        action in prop_oneof![Just("tunnel".to_string()), Just("bypass".to_string()), "\\PC{0,8}"],
    ) {
        if let Ok(request) = decode(&add(&kind, &value, &action)) {
            prop_assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
        }
    }
}
