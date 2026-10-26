//! Configuration requests carry payloads (Phase 9; FR-010, FR-025, FR-025a, contracts/ipc-protocol.md).
//!
//! | ID     | Assertion |
//! |--------|-----------|
//! | IPC-17 | Each configuration request round-trips, and carries exactly the fields it names |
//! | IPC-18 | An unknown, missing or mistyped field is `InvalidRequest`, never ignored or defaulted |
//! | IPC-19 | An endpoint's label, address and credentials are checked by the rules the saved configuration applies |
//! | IPC-20 | No error repeats a value from the request, and nothing prints a secret |
//! | IPC-21 | The decoder never panics on damaged or hostile text |
//! | IPC-23 | `ImportFeed` carries the keys document, the feed, or both, each within the size cap; nothing else |
//!
//! The caller is hostile input (Principle V). These are the requests that change what the service does, so
//! they are tested for what they *refuse* as much as for what they accept.

mod support;

use dnet_core::ids::EndpointId;
use dnet_ipc::protocol::{
    decode_request, encode_request, FeedImport, IpcError, NewEndpoint, Request, RequestClass,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use support::{credentials, new_endpoint, SENTINEL};

fn add_wire() -> Value {
    serde_json::from_str(&encode_request(&Request::AddEndpoint(Box::new(
        new_endpoint(),
    ))))
    .unwrap()
}

fn decode_value(value: &Value) -> Result<Request, IpcError> {
    decode_request(&value.to_string())
}

fn refused(result: Result<Request, IpcError>) -> String {
    match result {
        Err(IpcError::InvalidRequest { detail }) => detail,
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

// ------------------------------------------------------------------ IPC-17

#[test]
fn ipc_17_each_configuration_request_round_trips() {
    let id = EndpointId::new();
    for request in [
        Request::AddEndpoint(Box::new(new_endpoint())),
        Request::RemoveEndpoint { endpoint: id },
        Request::SetEndpointEnabled {
            endpoint: id,
            enabled: true,
        },
        Request::SetEndpointEnabled {
            endpoint: id,
            enabled: false,
        },
        Request::SetEncryptedDnsHandling { block: true },
        Request::SetEncryptedDnsHandling { block: false },
    ] {
        assert_eq!(request.class(), RequestClass::Mutating, "{request:?}");
        assert_eq!(
            decode_request(&encode_request(&request)),
            Ok(request.clone()),
            "{request:?}"
        );
    }
}

#[test]
fn ipc_17_the_wire_form_is_what_the_contract_says() {
    let id = EndpointId::new();
    let wire: Value = serde_json::from_str(&encode_request(&Request::SetEndpointEnabled {
        endpoint: id,
        enabled: false,
    }))
    .unwrap();
    assert_eq!(
        wire,
        json!({ "request": "SetEndpointEnabled", "endpoint": id.to_string(), "enabled": false })
    );
    let wire: Value = serde_json::from_str(&encode_request(&Request::SetEncryptedDnsHandling {
        block: false,
    }))
    .unwrap();
    assert_eq!(
        wire,
        json!({ "request": "SetEncryptedDnsHandling", "block": false })
    );

    let add = add_wire();
    let mut keys: Vec<&str> = add
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["credentials", "host", "label", "request"]);
    assert_eq!(
        add["credentials"]["version"], 1,
        "the stored form, with its version"
    );
}

// ------------------------------------------------------------------ IPC-18

#[test]
fn ipc_18_an_unknown_field_is_refused_in_every_configuration_request() {
    let id = EndpointId::new().to_string();
    let requests = [
        json!({ "request": "RemoveEndpoint", "endpoint": id }),
        json!({ "request": "SetEndpointEnabled", "endpoint": id, "enabled": true }),
        json!({ "request": "SetEncryptedDnsHandling", "block": true }),
        add_wire(),
    ];
    for mut value in requests {
        let name = value["request"].as_str().unwrap().to_owned();
        assert!(
            decode_value(&value).is_ok(),
            "{name}: the base request is valid"
        );
        value["surprise"] = json!(true);
        assert!(
            refused(decode_value(&value)).contains("unknown field"),
            "{name} ignored an unknown field"
        );
    }
}

#[test]
fn ipc_18_a_missing_or_null_field_is_refused_not_defaulted() {
    let id = EndpointId::new().to_string();
    let cases: Vec<(Value, &str)> = vec![
        (json!({ "request": "RemoveEndpoint" }), "endpoint"),
        (
            json!({ "request": "RemoveEndpoint", "endpoint": null }),
            "endpoint",
        ),
        (
            json!({ "request": "SetEndpointEnabled", "endpoint": id }),
            "enabled",
        ),
        (
            json!({ "request": "SetEndpointEnabled", "enabled": true }),
            "endpoint",
        ),
        (json!({ "request": "SetEncryptedDnsHandling" }), "block"),
        (
            json!({ "request": "SetEncryptedDnsHandling", "block": null }),
            "block",
        ),
    ];
    for (wire, field) in cases {
        let detail = refused(decode_value(&wire));
        assert!(detail.contains(field), "{wire}: {detail}");
    }
    for field in ["label", "host", "credentials"] {
        let mut wire = add_wire();
        wire.as_object_mut().unwrap().remove(field);
        let detail = refused(decode_value(&wire));
        assert!(detail.contains(field), "{field}: {detail}");
    }
}

#[test]
fn ipc_18_a_flag_must_be_a_boolean_and_an_id_must_be_a_uuid() {
    let id = EndpointId::new().to_string();
    for bad in [
        json!("true"),
        json!(1),
        json!(0),
        json!("yes"),
        json!([]),
        json!({}),
    ] {
        assert!(
            decode_value(&json!({ "request": "SetEncryptedDnsHandling", "block": bad.clone() }))
                .is_err(),
            "{bad}"
        );
        assert!(
            decode_value(
                &json!({ "request": "SetEndpointEnabled", "endpoint": id, "enabled": bad.clone() })
            )
            .is_err(),
            "{bad}"
        );
    }
    for bad in [
        json!("not-a-uuid"),
        json!(""),
        json!("{11111111-2222-3333-4444-555555555555}"),
        json!("urn:uuid:11111111-2222-3333-4444-555555555555"),
        json!("11111111222233334444555555555555"),
        json!(42),
        json!(null),
    ] {
        assert!(
            decode_value(&json!({ "request": "RemoveEndpoint", "endpoint": bad.clone() })).is_err(),
            "{bad}"
        );
    }
}

// ------------------------------------------------------------------ IPC-19

#[test]
fn ipc_19_the_request_has_no_port_of_its_own_each_profile_carries_its_server_port() {
    // A port beside the credentials would be a second answer to a question the bundle already
    // answers, so the request refuses it rather than choosing between the two.
    let mut wire = add_wire();
    wire["port"] = json!(443);
    assert!(refused(decode_value(&wire)).contains("unknown field"));
}

#[test]
fn ipc_19_the_label_is_short_printable_ascii() {
    for bad in [
        "",
        "   ",
        &"x".repeat(65),
        "tab\there",
        "new\nline",
        "naïve",
        "日本語",
        "\u{202e}rtl",
        "nul\0",
    ] {
        let mut wire = add_wire();
        wire["label"] = json!(bad);
        assert!(decode_value(&wire).is_err(), "{bad:?}");
    }
    let mut wire = add_wire();
    wire["label"] = json!("  padded  ");
    let Request::AddEndpoint(new) = decode_value(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(new.label(), "padded", "trimmed");
    let mut wire = add_wire();
    wire["label"] = json!("x".repeat(64));
    assert!(decode_value(&wire).is_ok());
    let mut wire = add_wire();
    wire["label"] = json!(7);
    assert!(decode_value(&wire).is_err());
}

#[test]
fn ipc_19_the_host_is_an_address_or_a_name_and_nothing_else() {
    for bad in [
        "",
        "  ",
        "http://example.org",
        "example.org:443",
        "example.org/path",
        "exa mple.org",
        "a..b",
        "-x.example",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "user@example.org",
        &"a".repeat(300),
        "evil.example;rm",
        "x.exa\nmple",
    ] {
        let mut wire = add_wire();
        wire["host"] = json!(bad);
        assert!(decode_value(&wire).is_err(), "{bad:?}");
    }
    for good in [
        "203.0.113.9",
        "2001:db8::7",
        "vpn.example.org",
        "VPN.Example.Org",
    ] {
        let mut wire = add_wire();
        wire["host"] = json!(good);
        assert!(decode_value(&wire).is_ok(), "{good}");
    }
}

#[test]
fn ipc_19_the_credentials_are_the_stored_form_and_nothing_laxer() {
    type Edit = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "not an object",
            Box::new(|w| w["credentials"] = json!("secret")),
        ),
        (
            "an empty object",
            Box::new(|w| w["credentials"] = json!({})),
        ),
        (
            "another version",
            Box::new(|w| w["credentials"]["version"] = json!(2)),
        ),
        (
            "an unknown field",
            Box::new(|w| w["credentials"]["extra"] = json!(1)),
        ),
        (
            "no connection method",
            Box::new(|w| w["credentials"] = json!({ "version": 1 })),
        ),
        (
            "a method a generator would refuse",
            Box::new(|w| {
                w["credentials"]["hysteria2"]["obfs_password"] =
                    w["credentials"]["hysteria2"]["auth_password"].clone()
            }),
        ),
        (
            "a wrong type",
            Box::new(|w| w["credentials"]["amneziawg"]["server_port"] = json!("51820")),
        ),
    ];
    for (what, edit) in cases {
        let mut wire = add_wire();
        edit(&mut wire);
        let detail = refused(decode_value(&wire));
        assert!(detail.contains("credentials"), "{what}: {detail}");
    }
}

#[test]
fn ipc_19_a_new_endpoint_is_checked_the_same_way_when_made_directly() {
    assert!(NewEndpoint::new("ok", "203.0.113.9", credentials()).is_ok());
    assert!(NewEndpoint::new("", "203.0.113.9", credentials()).is_err());
    assert!(NewEndpoint::new("ok", "0.0.0.0", credentials()).is_err());
    assert!(NewEndpoint::new("ok", "203.0.113.9", Default::default()).is_err());
    let made = NewEndpoint::new(" ok ", " 203.0.113.9 ", credentials()).unwrap();
    assert_eq!((made.label(), made.host()), ("ok", "203.0.113.9"));
}

// ------------------------------------------------------------------ IPC-20

#[test]
fn ipc_20_no_error_repeats_a_value_from_the_request() {
    // Each hostile value carries the sentinel, and each error must be free of it.
    for key in ["label", "host"] {
        let mut wire = add_wire();
        // A control character in the label and a character no host name has: each makes the value
        // invalid while it carries the sentinel.
        wire[key] = json!(format!("{SENTINEL}\u{7}!!!"));
        let detail = refused(decode_value(&wire));
        assert!(!detail.contains("SENTINEL"), "{key}: {detail}");
    }
    let mut wire = add_wire();
    wire["credentials"]["hysteria2"]["auth_password"] = json!(SENTINEL);
    wire["credentials"]["hysteria2"]["obfs_password"] = json!(SENTINEL);
    let detail = refused(decode_value(&wire));
    assert!(!detail.contains("SENTINEL"), "{detail}");

    let mut wire = add_wire();
    wire["credentials"]["hysteria2"]["server_port"] = json!(SENTINEL);
    let detail = refused(decode_value(&wire));
    assert!(!detail.contains("SENTINEL"), "{detail}");

    let mut wire = add_wire();
    wire[format!("{SENTINEL}_field")] = json!(1);
    let detail = refused(decode_value(&wire));
    assert!(
        !detail.contains("SENTINEL"),
        "an unknown field's name is the client's text too: {detail}"
    );
}

#[test]
fn ipc_20_an_unknown_field_name_is_not_repeated_the_error_says_what_the_request_takes() {
    for name in [
        "a".repeat(500),
        "evil\n[INFO] approved\u{1b}[2J".to_owned(),
        "notaword".to_owned(),
    ] {
        let mut wire = add_wire();
        wire[name.as_str()] = json!(1);
        let detail = refused(decode_value(&wire));
        assert!(!detail.contains(&name[..name.len().min(8)]), "{detail:?}");
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
        assert!(detail.len() < 150, "{detail}");
        assert!(
            detail.contains("label, host, credentials"),
            "it says what the request takes: {detail}"
        );
    }
}

#[test]
fn ipc_20_nothing_that_prints_a_request_shows_a_secret() {
    let request = Request::AddEndpoint(Box::new(new_endpoint()));
    for shown in [format!("{request:?}"), format!("{request:#?}")] {
        assert!(!shown.contains("SENTINEL"), "{shown}");
        assert!(
            !shown.contains(&"1".repeat(64)),
            "the client private key printed"
        );
        assert!(
            !shown.contains("bf000d23-0752-40b4-affe-68f7707a9661"),
            "{shown}"
        );
        assert!(!shown.contains("0123456789abcdef"), "{shown}");
    }
}

// ------------------------------------------------------------------ IPC-21

proptest! {
    #[test]
    fn ipc_21_arbitrary_text_never_panics_the_decoder(wire in ".{0,400}") {
        let _ = decode_request(&wire);
    }

    #[test]
    fn ipc_21_a_valid_add_request_with_a_byte_changed_never_panics_and_what_it_decodes_to_is_stable(
        position in 0usize..2000,
        replacement in any::<u8>(),
    ) {
        let text = encode_request(&Request::AddEndpoint(Box::new(new_endpoint())));
        let mut bytes = text.into_bytes();
        let at = position % bytes.len();
        bytes[at] = replacement;
        if let Ok(damaged) = String::from_utf8(bytes) {
            if let Ok(request) = decode_request(&damaged) {
                // Whatever it decoded to is a request that survives its own round trip.
                prop_assert_eq!(decode_request(&encode_request(&request)), Ok(request));
            }
        }
    }

    #[test]
    fn ipc_21_deeply_nested_json_is_refused_or_read_but_never_panics(depth in 0usize..200) {
        let wire = format!(
            "{{\"request\":\"RemoveEndpoint\",\"endpoint\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let _ = decode_request(&wire);
    }
}

// ------------------------------------------------------------------ IPC-23

#[test]
fn ipc_23_an_import_round_trips_with_the_documents_it_names() {
    for (keys, feed) in [
        (Some("{\"k\":1}"), None),
        (None, Some("{\"f\":2}")),
        (Some("{\"k\":1}"), Some("{\"f\":2}")),
    ] {
        let request = Request::ImportFeed(
            FeedImport::new(keys.map(str::to_owned), feed.map(str::to_owned)).unwrap(),
        );
        let wire = encode_request(&request);
        assert_eq!(decode_request(&wire).unwrap(), request, "{wire}");
        let value: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(value.get("keys").is_some(), keys.is_some(), "{wire}");
        assert_eq!(value.get("feed").is_some(), feed.is_some(), "{wire}");
    }
    assert_eq!(
        Request::ImportFeed(FeedImport::new(Some("x".into()), None).unwrap()).class(),
        RequestClass::Mutating
    );
}

#[test]
fn ipc_23_an_import_of_nothing_is_refused() {
    for wire in [
        json!({ "request": "ImportFeed" }),
        json!({ "request": "ImportFeed", "keys": null, "feed": null }),
    ] {
        assert!(refused(decode_value(&wire)).contains("keys"), "{wire}");
    }
}

#[test]
fn ipc_23_a_document_is_text_and_within_the_cap_every_source_is_held_to() {
    for bad in [json!(1), json!(true), json!([]), json!({})] {
        assert!(
            decode_value(&json!({ "request": "ImportFeed", "keys": bad.clone() })).is_err(),
            "{bad}"
        );
    }
    let cap = dnet_core::feed::ENVELOPE_MAX_BYTES;
    assert!(FeedImport::new(Some("x".repeat(cap)), None).is_ok());
    let over = FeedImport::new(None, Some(format!("{SENTINEL}{}", "x".repeat(cap))));
    let message = over.unwrap_err().to_string();
    assert!(message.contains("`feed`"), "{message}");
    assert!(!message.contains("SENTINEL"), "{message}");
}

#[test]
fn ipc_23_an_import_takes_only_its_own_fields_and_never_repeats_an_unknown_one() {
    let wire = json!({ "request": "ImportFeed", "keys": "x", "SENTINEL_field": 1 });
    let message = refused(decode_value(&wire));
    assert!(message.contains("unknown field"), "{message}");
    assert!(!message.contains("SENTINEL"), "{message}");
}

#[test]
fn ipc_23_a_request_to_check_for_updates_takes_no_field() {
    let request = decode_value(&json!({ "request": "FetchFeed" })).unwrap();
    assert_eq!(request, Request::FetchFeed);
    assert_eq!(request.class(), RequestClass::Mutating);
    assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
    // Where to fetch from is compiled in; a request that names a place is refused, not obeyed.
    let message = refused(decode_value(
        &json!({ "request": "FetchFeed", "url": "https://SENTINEL.example/" }),
    ));
    assert!(message.contains("unknown field"), "{message}");
    assert!(!message.contains("SENTINEL"), "{message}");
}
