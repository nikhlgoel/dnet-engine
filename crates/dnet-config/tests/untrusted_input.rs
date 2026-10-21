//! Text and files the configuration code reads must not be able to crash it.
//!
//! Credentials arrive as an imported bundle (a file a person chose, from an endpoint they set up or
//! someone sent them) and the configuration is a file on disk that a damaged disk or a careless
//! edit can corrupt. Each is parsed by the service as SYSTEM at start-up, so a panic here is a
//! service that will not start. Whatever is given, the answer is a value or an error.

use dnet_config::credentials::{parse_spki_sha256_hex, EndpointCredentials};
use dnet_config::persist;
use proptest::prelude::*;

/// JSON-looking text that uses the names the parsers look for.
fn bundle_like() -> impl Strategy<Value = String> {
    let key = prop::sample::select(vec![
        "amneziawg",
        "hysteria2",
        "reality",
        "client_private_key",
        "server_public_key",
        "server_port",
        "auth_password",
        "obfs_password",
        "uuid",
        "public_key",
        "short_id",
        "server_name",
        "measure_origin",
        "version",
        "endpoints",
        "profiles",
        "id",
        "label",
        "address",
        "obfuscation",
        "jc",
        "h1",
        "peer",
        "extra",
    ]);
    let leaf = prop_oneof![
        Just("null".to_owned()),
        any::<bool>().prop_map(|b| b.to_string()),
        any::<i64>().prop_map(|n| n.to_string()),
        "[ -~]{0,24}".prop_map(|s| serde_json::Value::String(s).to_string()),
    ];
    let value = leaf.prop_recursive(3, 24, 4, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(|v| format!("[{}]", v.join(","))),
            prop::collection::vec((key.clone(), inner), 0..6).prop_map(|pairs| {
                let body: Vec<String> = pairs
                    .into_iter()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect();
                format!("{{{}}}", body.join(","))
            }),
        ]
    });
    value
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn credentials_of_any_bytes_are_refused_or_accepted_without_panicking(
        bytes in prop::collection::vec(any::<u8>(), 0..600)
    ) {
        let _ = EndpointCredentials::from_plaintext_json(&bytes);
    }

    #[test]
    fn credentials_of_any_json_are_refused_or_accepted_without_panicking(text in bundle_like()) {
        let _ = EndpointCredentials::from_plaintext_json(text.as_bytes());
    }

    #[test]
    fn a_configuration_of_any_bytes_is_refused_or_accepted_without_panicking(
        bytes in prop::collection::vec(any::<u8>(), 0..800)
    ) {
        let _ = persist::decode(&bytes);
    }

    #[test]
    fn a_configuration_of_any_json_is_refused_or_accepted_without_panicking(text in bundle_like()) {
        let _ = persist::decode(text.as_bytes());
    }

    #[test]
    fn a_pin_of_any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,100}") {
        let _ = parse_spki_sha256_hex(&text);
    }

    /// A pin that is accepted is exactly 64 lowercase hex digits and round-trips.
    #[test]
    fn an_accepted_pin_is_exactly_what_it_says(bytes in prop::array::uniform32(any::<u8>())) {
        let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        prop_assert_eq!(parse_spki_sha256_hex(&text), Some(bytes));
        prop_assert_eq!(parse_spki_sha256_hex(&text.to_uppercase()), None);
        prop_assert_eq!(parse_spki_sha256_hex(&text[..62]), None);
    }
}
