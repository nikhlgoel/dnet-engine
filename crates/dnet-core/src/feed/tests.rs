//! Contract tests FEED-01 … FEED-15 (ADR-0002 §11).
//!
//! Every key here is derived from a fixed test-only seed. None is, or may become, a real root
//! or signing key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use super::envelope::pae;
use super::*;

const NOW: u64 = 1_757_635_200;
const DAY: u64 = 86_400;

/// An edit applied to a JSON fixture.
type Edit<'a> = &'a dyn Fn(&mut Value);

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn root(i: u8) -> SigningKey {
    key(i)
}

/// Delegated signing keys use seeds from 100 up, so they never collide with roots.
fn signer(i: u8) -> SigningKey {
    key(100 + i)
}

fn trust_with_floor(min_keys_version: u64) -> FeedTrust {
    FeedTrust::new(
        [root(1), root(2), root(3)].map(|k| k.verifying_key().to_bytes()),
        min_keys_version,
    )
    .unwrap()
}

fn trust() -> FeedTrust {
    trust_with_floor(1)
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Build an envelope over exactly `payload`, signed by each of `signers`.
fn seal(payload_type: &str, payload: &[u8], signers: &[&SigningKey]) -> Vec<u8> {
    let message = pae(payload_type, payload);
    let signatures: Vec<Value> = signers
        .iter()
        .map(|k| json!({ "keyid": "", "sig": b64(&k.sign(&message).to_bytes()) }))
        .collect();
    serde_json::to_vec(&json!({
        "payload": b64(payload),
        "payloadType": payload_type,
        "signatures": signatures,
    }))
    .unwrap()
}

fn keys_value(version: u64, signing: &[&SigningKey]) -> Value {
    let keys: Vec<Value> = signing
        .iter()
        .map(|k| {
            json!({
                "public_key": b64(k.verifying_key().as_bytes()),
                "not_before": NOW - DAY,
                "not_after": NOW + 90 * DAY,
            })
        })
        .collect();
    json!({
        "keys_version": version,
        "issued_at": NOW - DAY,
        "expires_at": NOW + 300 * DAY,
        "signing_threshold": 1,
        "signing_keys": keys,
    })
}

fn keys_envelope(value: &Value) -> Vec<u8> {
    seal(
        KEYS_PAYLOAD_TYPE,
        &serde_json::to_vec(value).unwrap(),
        &[&root(1), &root(2)],
    )
}

/// The ADR-0002 §5.3 example, which must itself be valid.
fn feed_value(keys_version: u64, sequence: u64) -> Value {
    json!({
        "keys_version": keys_version,
        "sequence": sequence,
        "issued_at": NOW - 3600,
        "expires_at": NOW + 14 * DAY,
        "profiles": [
            {
                "profile_id": "awg-default",
                "kind": "amnezia_wg",
                "client":   { "jc": 6, "jmin": 40, "jmax": 90 },
                "endpoint": { "s1": 72, "s2": 41, "h1": 1873209, "h2": 5520871, "h3": 90121, "h4": 334210 }
            },
            {
                "profile_id": "hy2-default",
                "kind": "hysteria2",
                "client":   { "bbr_profile": "standard", "chrome_parrot": true },
                "endpoint": { "obfs": { "type": "gecko", "min_packet_size": 512, "max_packet_size": 1200 } }
            },
            {
                "profile_id": "reality-default",
                "kind": "vless_reality",
                "client":   { "utls_fingerprint": "chrome" },
                "endpoint": { "target_domain_candidates": ["www.example.com"] }
            }
        ]
    })
}

fn feed_envelope(value: &Value, signers: &[&SigningKey]) -> Vec<u8> {
    seal(
        FEED_PAYLOAD_TYPE,
        &serde_json::to_vec(value).unwrap(),
        signers,
    )
}

/// A state with keys document `version` accepted, delegating to `signing`.
fn with_keys(version: u64, signing: &[&SigningKey]) -> FeedState {
    match accept_keys_document(
        &trust(),
        &FeedState::default(),
        &keys_envelope(&keys_value(version, signing)),
        NOW,
    )
    .unwrap()
    {
        KeysOutcome::Accepted { state, .. } => *state,
        KeysOutcome::Unchanged => unreachable!(),
    }
}

fn applied(state: &FeedState, envelope: &[u8], now: u64) -> FeedState {
    match accept_feed(state, envelope, now).unwrap() {
        FeedOutcome::Accepted(next) => *next,
        FeedOutcome::Unchanged => panic!("expected a new feed to be accepted"),
    }
}

/// Offer a feed whose raw payload bytes are given, validly signed by `signer(1)`.
fn offer_raw_feed(payload: &[u8]) -> Result<FeedOutcome, FeedError> {
    let state = with_keys(1, &[&signer(1)]);
    accept_feed(
        &state,
        &seal(FEED_PAYLOAD_TYPE, payload, &[&signer(1)]),
        NOW,
    )
}

fn offer_feed(value: &Value) -> Result<FeedOutcome, FeedError> {
    offer_raw_feed(&serde_json::to_vec(value).unwrap())
}

// ---------------------------------------------------------------- FEED-01

#[test]
fn feed_01_a_valid_feed_applies() {
    let state = with_keys(1, &[&signer(1)]);
    let next = applied(
        &state,
        &feed_envelope(&feed_value(1, 1), &[&signer(1)]),
        NOW,
    );
    let feed = next.feed().expect("applied");
    assert_eq!(feed.document().sequence, 1);
    assert_eq!(feed.document().profiles.len(), 3);
    assert_eq!(next.status(NOW), FeedStatus::Current);
}

#[test]
fn feed_01_one_flipped_payload_byte_is_refused() {
    let state = with_keys(1, &[&signer(1)]);
    let good = feed_envelope(&feed_value(1, 1), &[&signer(1)]);
    let mut envelope: Value = serde_json::from_slice(&good).unwrap();
    let mut payload = STANDARD
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    let i = payload.len() / 2;
    payload[i] ^= 0x01;
    envelope["payload"] = json!(b64(&payload));
    let tampered = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        accept_feed(&state, &tampered, NOW),
        Err(FeedError::ThresholdNotMet {
            document: Document::Feed,
            valid: 0,
            required: 1
        })
    );
}

#[test]
fn a_feed_before_any_keys_document_is_refused() {
    let envelope = feed_envelope(&feed_value(1, 1), &[&signer(1)]);
    assert_eq!(
        accept_feed(&FeedState::default(), &envelope, NOW),
        Err(FeedError::NoKeysDocument)
    );
}

// ---------------------------------------------------------------- FEED-02

#[test]
fn feed_02_root_keys_cannot_sign_a_feed() {
    let state = with_keys(1, &[&signer(1)]);
    let by_roots = feed_envelope(&feed_value(1, 1), &[&root(1), &root(2), &root(3)]);
    assert!(matches!(
        accept_feed(&state, &by_roots, NOW),
        Err(FeedError::ThresholdNotMet { valid: 0, .. })
    ));
}

#[test]
fn feed_02_signing_keys_cannot_sign_a_keys_document() {
    let payload = serde_json::to_vec(&keys_value(1, &[&signer(1)])).unwrap();
    let by_signers = seal(KEYS_PAYLOAD_TYPE, &payload, &[&signer(1), &signer(2)]);
    assert_eq!(
        accept_keys_document(&trust(), &FeedState::default(), &by_signers, NOW),
        Err(FeedError::ThresholdNotMet {
            document: Document::Keys,
            valid: 0,
            required: ROOT_THRESHOLD
        })
    );
}

/// The payload type is inside the signed bytes: a signature made for one type does not
/// verify under the other, even over identical payload bytes.
#[test]
fn feed_02_a_signature_is_bound_to_its_payload_type() {
    let state = with_keys(1, &[&signer(1)]);
    let payload = serde_json::to_vec(&feed_value(1, 1)).unwrap();
    let signed_as_keys = seal(KEYS_PAYLOAD_TYPE, &payload, &[&signer(1)]);
    let mut envelope: Value = serde_json::from_slice(&signed_as_keys).unwrap();
    envelope["payloadType"] = json!(FEED_PAYLOAD_TYPE);
    assert!(matches!(
        accept_feed(&state, &serde_json::to_vec(&envelope).unwrap(), NOW),
        Err(FeedError::ThresholdNotMet { valid: 0, .. })
    ));
    // And the wrong type is refused before any signature is checked.
    assert_eq!(
        accept_feed(&state, &signed_as_keys, NOW),
        Err(FeedError::WrongPayloadType(Document::Feed))
    );
}

#[test]
fn feed_02_a_keys_document_may_not_delegate_to_a_root_key() {
    let value = keys_value(1, &[&root(3)]);
    assert_eq!(
        accept_keys_document(&trust(), &FeedState::default(), &keys_envelope(&value), NOW),
        Err(FeedError::InvalidField {
            field: "signing_keys.public_key",
            reason: "is a root key"
        })
    );
}

// ---------------------------------------------------------------- FEED-03

#[test]
fn feed_03_one_root_signing_twice_counts_once() {
    let payload = serde_json::to_vec(&keys_value(1, &[&signer(1)])).unwrap();
    let twice = seal(KEYS_PAYLOAD_TYPE, &payload, &[&root(1), &root(1)]);
    assert_eq!(
        accept_keys_document(&trust(), &FeedState::default(), &twice, NOW),
        Err(FeedError::ThresholdNotMet {
            document: Document::Keys,
            valid: 1,
            required: 2
        })
    );
}

#[test]
fn feed_03_one_signing_key_signing_twice_counts_once() {
    let mut keys = keys_value(1, &[&signer(1), &signer(2)]);
    keys["signing_threshold"] = json!(2);
    let state =
        match accept_keys_document(&trust(), &FeedState::default(), &keys_envelope(&keys), NOW)
            .unwrap()
        {
            KeysOutcome::Accepted { state, .. } => *state,
            KeysOutcome::Unchanged => unreachable!(),
        };
    let twice = feed_envelope(&feed_value(1, 1), &[&signer(1), &signer(1)]);
    assert!(matches!(
        accept_feed(&state, &twice, NOW),
        Err(FeedError::ThresholdNotMet {
            valid: 1,
            required: 2,
            ..
        })
    ));
    let both = feed_envelope(&feed_value(1, 1), &[&signer(1), &signer(2)]);
    assert!(matches!(
        accept_feed(&state, &both, NOW),
        Ok(FeedOutcome::Accepted(_))
    ));
}

// ---------------------------------------------------------------- FEED-04

#[test]
fn feed_04_an_older_feed_is_refused_and_the_same_feed_is_a_no_op() {
    let keys = with_keys(1, &[&signer(1)]);
    let current = feed_envelope(&feed_value(1, 5), &[&signer(1)]);
    let state = applied(&keys, &current, NOW);

    let older = feed_envelope(&feed_value(1, 4), &[&signer(1)]);
    assert_eq!(
        accept_feed(&state, &older, NOW),
        Err(FeedError::Rollback(Document::Feed))
    );
    assert_eq!(
        accept_feed(&state, &current, NOW),
        Ok(FeedOutcome::Unchanged)
    );

    let mut different = feed_value(1, 5);
    different["profiles"][0]["client"]["jc"] = json!(7);
    assert_eq!(
        accept_feed(&state, &feed_envelope(&different, &[&signer(1)]), NOW),
        Err(FeedError::Equivocation(Document::Feed))
    );
}

#[test]
fn feed_04_an_older_or_equivocating_keys_document_is_refused() {
    let state = with_keys(3, &[&signer(1)]);
    let older = keys_envelope(&keys_value(2, &[&signer(1)]));
    assert_eq!(
        accept_keys_document(&trust(), &state, &older, NOW),
        Err(FeedError::Rollback(Document::Keys))
    );
    let same = keys_envelope(&keys_value(3, &[&signer(1)]));
    assert_eq!(
        accept_keys_document(&trust(), &state, &same, NOW),
        Ok(KeysOutcome::Unchanged)
    );
    let conflicting = keys_envelope(&keys_value(3, &[&signer(2)]));
    assert_eq!(
        accept_keys_document(&trust(), &state, &conflicting, NOW),
        Err(FeedError::Equivocation(Document::Keys))
    );
}

/// A fresh install cannot be served a keys document older than the build's floor.
#[test]
fn feed_04_the_compiled_floor_refuses_old_keys_documents_on_a_fresh_install() {
    let old = keys_envelope(&keys_value(4, &[&signer(1)]));
    assert_eq!(
        accept_keys_document(&trust_with_floor(5), &FeedState::default(), &old, NOW),
        Err(FeedError::Rollback(Document::Keys))
    );
}

// ---------------------------------------------------------------- FEED-05

#[test]
fn feed_05_a_feed_signed_under_another_keys_version_is_refused() {
    let state = with_keys(2, &[&signer(1)]);
    let stale = feed_envelope(&feed_value(1, 9), &[&signer(1)]);
    assert_eq!(
        accept_feed(&state, &stale, NOW),
        Err(FeedError::KeysVersionMismatch)
    );
}

// ---------------------------------------------------------------- FEED-06

#[test]
fn feed_06_revoking_a_key_evicts_everything_it_signed_including_a_fast_forward() {
    let compromised = signer(1);
    let replacement = signer(2);
    let keys_v1 = with_keys(1, &[&compromised]);
    let fast_forward = feed_envelope(&feed_value(1, u64::MAX), &[&compromised]);
    let state = applied(&keys_v1, &fast_forward, NOW);

    let keys_v2 = keys_envelope(&keys_value(2, &[&replacement]));
    let KeysOutcome::Accepted {
        state,
        feed_evicted,
    } = accept_keys_document(&trust(), &state, &keys_v2, NOW).unwrap()
    else {
        panic!("keys v2 should be accepted")
    };
    assert!(feed_evicted);
    assert!(state.feed().is_none());
    assert_eq!(state.status(NOW), FeedStatus::BundledDefaults);

    // The replacement's first feed is accepted despite the evicted u64::MAX sequence.
    let fresh = feed_envelope(&feed_value(2, 1), &[&replacement]);
    assert!(matches!(
        accept_feed(&state, &fresh, NOW),
        Ok(FeedOutcome::Accepted(_))
    ));
}

#[test]
fn feed_06_a_feed_whose_key_stays_listed_survives_rotation() {
    let kept = signer(1);
    let state = applied(
        &with_keys(1, &[&kept]),
        &feed_envelope(&feed_value(1, 3), &[&kept]),
        NOW,
    );
    let rotated = keys_envelope(&keys_value(2, &[&kept, &signer(2)]));
    let KeysOutcome::Accepted {
        state,
        feed_evicted,
    } = accept_keys_document(&trust(), &state, &rotated, NOW).unwrap()
    else {
        panic!("keys v2 should be accepted")
    };
    assert!(!feed_evicted);
    assert_eq!(state.feed().unwrap().document().sequence, 3);

    // The next feed must name keys version 2, and it orders after (1, 3).
    let next = feed_envelope(&feed_value(2, 1), &[&signer(2)]);
    assert!(matches!(
        accept_feed(&state, &next, NOW),
        Ok(FeedOutcome::Accepted(_))
    ));
}

// ---------------------------------------------------------------- FEED-07

#[test]
fn feed_07_an_expired_feed_is_not_accepted() {
    let state = with_keys(1, &[&signer(1)]);
    let mut expired = feed_value(1, 1);
    expired["issued_at"] = json!(NOW - 20 * DAY);
    expired["expires_at"] = json!(NOW - 2 * DAY);
    assert_eq!(
        accept_feed(&state, &feed_envelope(&expired, &[&signer(1)]), NOW),
        Err(FeedError::NotCurrent {
            document: Document::Feed,
            reason: "expired"
        })
    );
}

#[test]
fn feed_07_an_applied_feed_past_expiry_is_kept_and_reported_stale() {
    let state = applied(
        &with_keys(1, &[&signer(1)]),
        &feed_envelope(&feed_value(1, 1), &[&signer(1)]),
        NOW,
    );
    let later = NOW + 20 * DAY;
    assert_eq!(state.status(later), FeedStatus::Stale);
    assert!(state.feed().is_some());
    // Staleness is expiry only: a clock reading before issued_at leaves it current.
    assert_eq!(state.status(NOW - 30 * DAY), FeedStatus::Current);
}

#[test]
fn feed_07_no_new_feed_is_accepted_under_an_expired_keys_document() {
    let state = with_keys(1, &[&signer(1)]);
    let much_later = NOW + 400 * DAY;
    let mut feed = feed_value(1, 1);
    feed["issued_at"] = json!(much_later - 3600);
    feed["expires_at"] = json!(much_later + DAY);
    assert!(matches!(
        accept_feed(&state, &feed_envelope(&feed, &[&signer(1)]), much_later),
        Err(FeedError::NotCurrent {
            document: Document::Keys,
            ..
        })
    ));
}

#[test]
fn a_signing_key_outside_its_window_does_not_count() {
    let state = with_keys(1, &[&signer(1)]);
    let after_window = NOW + 100 * DAY; // not_after is NOW + 90 days, skew is 1 day
    let mut feed = feed_value(1, 1);
    feed["issued_at"] = json!(after_window - 3600);
    feed["expires_at"] = json!(after_window + DAY);
    assert!(matches!(
        accept_feed(&state, &feed_envelope(&feed, &[&signer(1)]), after_window),
        Err(FeedError::ThresholdNotMet { valid: 0, .. })
    ));
}

// ---------------------------------------------------------------- FEED-08

#[test]
fn feed_08_an_oversized_envelope_is_refused_before_parsing() {
    let state = with_keys(1, &[&signer(1)]);
    let huge = vec![b' '; ENVELOPE_MAX_BYTES + 1];
    assert_eq!(accept_feed(&state, &huge, NOW), Err(FeedError::TooLarge));
    assert_eq!(
        accept_keys_document(&trust(), &FeedState::default(), &huge, NOW),
        Err(FeedError::TooLarge)
    );
}

// ---------------------------------------------------------------- FEED-09

fn is_malformed_payload(result: Result<FeedOutcome, FeedError>) -> bool {
    matches!(
        result,
        Err(FeedError::MalformedPayload {
            document: Document::Feed,
            ..
        })
    )
}

#[test]
fn feed_09_an_unknown_field_at_any_level_refuses_the_whole_feed() {
    let paths: [Edit; 6] = [
        &|v| v["extra"] = json!(1),
        &|v| v["profiles"][0]["extra"] = json!(1),
        &|v| v["profiles"][0]["client"]["extra"] = json!(1),
        &|v| v["profiles"][0]["endpoint"]["extra"] = json!(1),
        &|v| v["profiles"][1]["endpoint"]["obfs"]["extra"] = json!(1),
        &|v| v["profiles"][2]["client"]["extra"] = json!(1),
    ];
    for (i, add) in paths.iter().enumerate() {
        let mut value = feed_value(1, 1);
        add(&mut value);
        assert!(is_malformed_payload(offer_feed(&value)), "path {i}");
    }
}

#[test]
fn feed_09_salamander_refuses_gecko_options() {
    let mut value = feed_value(1, 1);
    value["profiles"][1]["endpoint"]["obfs"] =
        json!({ "type": "salamander", "min_packet_size": 512 });
    assert!(is_malformed_payload(offer_feed(&value)));
}

#[test]
fn feed_09_duplicate_keys_fractions_exponents_and_a_bom_are_refused() {
    let good = serde_json::to_string(&feed_value(1, 1)).unwrap();
    let duplicate_top = good.replacen("{\"expires_at\"", "{\"sequence\":2,\"expires_at\"", 1);
    assert_ne!(
        duplicate_top, good,
        "fixture must contain the replaced text"
    );
    let duplicate_nested = good.replacen("\"jc\":6", "\"jc\":6,\"jc\":7", 1);
    let fraction = good.replacen("\"sequence\":1", "\"sequence\":1.0", 1);
    let exponent = good.replacen("\"jc\":6", "\"jc\":6e0", 1);
    let bom = format!("\u{feff}{good}");
    for (label, text) in [
        ("duplicate top-level key", duplicate_top),
        ("duplicate nested key", duplicate_nested),
        ("fraction", fraction),
        ("exponent", exponent),
        ("byte-order mark", bom),
    ] {
        assert_ne!(text, good, "{label}: fixture unchanged");
        assert!(
            is_malformed_payload(offer_raw_feed(text.as_bytes())),
            "{label} accepted"
        );
    }
}

#[test]
fn feed_09_an_unknown_field_in_the_envelope_or_keys_document_is_refused() {
    let state = with_keys(1, &[&signer(1)]);
    let mut envelope: Value =
        serde_json::from_slice(&feed_envelope(&feed_value(1, 1), &[&signer(1)])).unwrap();
    envelope["signatures"][0]["cert"] = json!("x");
    assert_eq!(
        accept_feed(&state, &serde_json::to_vec(&envelope).unwrap(), NOW),
        Err(FeedError::MalformedEnvelope("structure"))
    );

    let mut keys = keys_value(1, &[&signer(1)]);
    keys["revoked"] = json!([]);
    assert!(matches!(
        accept_keys_document(&trust(), &FeedState::default(), &keys_envelope(&keys), NOW),
        Err(FeedError::MalformedPayload {
            document: Document::Keys,
            ..
        })
    ));
}

// ---------------------------------------------------------------- FEED-10

fn feed_with(edit: impl Fn(&mut Value)) -> Result<FeedOutcome, FeedError> {
    let mut value = feed_value(1, 1);
    edit(&mut value);
    offer_feed(&value)
}

#[test]
fn feed_10_out_of_bounds_values_refuse_the_whole_feed() {
    let cases: [(&str, Edit); 13] = [
        ("h1 is a plain message type", &|v| {
            v["profiles"][0]["endpoint"]["h1"] = json!(1)
        }),
        ("h above 2^31-1", &|v| {
            v["profiles"][0]["endpoint"]["h1"] = json!(3_175_921_403u64)
        }),
        ("repeated header", &|v| {
            v["profiles"][0]["endpoint"]["h2"] = json!(1873209)
        }),
        ("jmin == jmax", &|v| {
            v["profiles"][0]["client"]["jmin"] = json!(90)
        }),
        ("jc above 16", &|v| {
            v["profiles"][0]["client"]["jc"] = json!(17)
        }),
        ("jmax above 1280", &|v| {
            v["profiles"][0]["client"]["jmax"] = json!(1281)
        }),
        ("s1 + 56 == s2", &|v| {
            v["profiles"][0]["endpoint"]["s2"] = json!(128)
        }),
        ("s1 above 1132", &|v| {
            v["profiles"][0]["endpoint"]["s1"] = json!(1133)
        }),
        ("gecko max above 1400", &|v| {
            v["profiles"][1]["endpoint"]["obfs"]["max_packet_size"] = json!(1401)
        }),
        ("IP-literal target", &|v| {
            v["profiles"][2]["endpoint"]["target_domain_candidates"] = json!(["203.0.113.9"])
        }),
        ("bypassed target", &|v| {
            v["profiles"][2]["endpoint"]["target_domain_candidates"] =
                json!(["www.msftconnecttest.com"])
        }),
        ("repeated target", &|v| {
            v["profiles"][2]["endpoint"]["target_domain_candidates"] =
                json!(["www.example.com", "WWW.EXAMPLE.COM"])
        }),
        ("no targets", &|v| {
            v["profiles"][2]["endpoint"]["target_domain_candidates"] = json!([])
        }),
    ];
    for (label, edit) in cases {
        assert!(
            matches!(feed_with(edit), Err(FeedError::InvalidField { .. })),
            "{label} accepted"
        );
    }
}

#[test]
fn feed_10_an_unlisted_fingerprint_or_bbr_profile_is_refused() {
    assert!(is_malformed_payload(feed_with(|v| {
        v["profiles"][2]["client"]["utls_fingerprint"] = json!("randomized")
    })));
    assert!(is_malformed_payload(feed_with(|v| {
        v["profiles"][1]["client"]["bbr_profile"] = json!("brutal")
    })));
}

#[test]
fn feed_10_catalogue_references_are_enforced() {
    assert_eq!(
        feed_with(|v| v["profiles"][0]["profile_id"] = json!("awg-extra")),
        Err(FeedError::UnknownProfile("awg-extra".into()))
    );
    assert_eq!(
        feed_with(|v| v["profiles"][0]["profile_id"] = json!("hy2-default")),
        Err(FeedError::KindMismatch("hy2-default".into()))
    );
    assert_eq!(
        feed_with(|v| {
            let first = v["profiles"][0].clone();
            v["profiles"].as_array_mut().unwrap().push(first);
        }),
        Err(FeedError::DuplicateProfile("awg-default".into()))
    );
    assert_eq!(
        feed_with(|v| {
            v["profiles"][1] = json!({ "profile_id": "hy2-default", "kind": "hysteria2" })
        }),
        Err(FeedError::EmptyProposal("hy2-default".into()))
    );
    assert!(matches!(
        feed_with(|v| v["profiles"] = json!([])),
        Err(FeedError::InvalidField {
            field: "profiles",
            ..
        })
    ));
    assert!(matches!(
        feed_with(|v| {
            v["expires_at"] = json!(NOW + 31 * DAY);
        }),
        Err(FeedError::InvalidField {
            field: "feed lifetime",
            ..
        })
    ));
}

#[test]
fn merging_rechecks_cross_field_rules_against_values_in_effect() {
    let FeedOutcome::Accepted(state) = feed_with(|v| {
        v["profiles"][0]["client"] = json!({ "jmin": 100 });
        v["profiles"][0]["endpoint"] = json!({ "h1": 90121 });
    })
    .unwrap() else {
        panic!("accepted")
    };
    let document::ProposedParams::AmneziaWg { client, endpoint } =
        &state.feed().unwrap().document().profiles[0].params
    else {
        panic!("amneziawg entry")
    };
    use document::{AmneziaWgHeaders, JunkPackets};
    // jmin 100 over a current jmax of 90 is invalid; over 120 it is fine.
    let current = JunkPackets {
        jc: 4,
        jmin: 40,
        jmax: 90,
    };
    assert!(client.merged_over(current).is_err());
    assert_eq!(
        client
            .merged_over(JunkPackets {
                jmax: 120,
                ..current
            })
            .unwrap()
            .jmin,
        100
    );
    // h1 90121 collides with a current h3 of 90121. Current values outside the feed bounds
    // (a u32 header from a user-entered endpoint) are not themselves refused.
    let headers = AmneziaWgHeaders {
        s1: 15,
        s2: 20,
        h1: 1_053_421_987,
        h2: 2_083_245_612,
        h3: 90121,
        h4: 4_012_837_465,
    };
    assert!(endpoint.merged_over(headers).is_err());
    assert!(endpoint
        .merged_over(AmneziaWgHeaders {
            h3: 3_175_921_403,
            ..headers
        })
        .is_ok());
}

// ---------------------------------------------------------------- FEED-11

#[test]
fn feed_11_a_payload_is_never_parsed_before_its_signatures_verify() {
    let state = with_keys(1, &[&signer(1)]);
    let garbage = b"{ this is not json";
    let unsigned = seal(FEED_PAYLOAD_TYPE, garbage, &[&signer(9)]);
    assert!(matches!(
        accept_feed(&state, &unsigned, NOW),
        Err(FeedError::ThresholdNotMet { .. })
    ));
    assert!(is_malformed_payload(offer_raw_feed(garbage)));
}

// ---------------------------------------------------------------- FEED-12

#[test]
fn feed_12_a_weak_signing_key_is_refused() {
    // The compressed identity point: small order, so "valid" for almost any message.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut keys = keys_value(1, &[&signer(1)]);
    keys["signing_keys"][0]["public_key"] = json!(b64(&identity));
    assert_eq!(
        accept_keys_document(&trust(), &FeedState::default(), &keys_envelope(&keys), NOW),
        Err(FeedError::InvalidField {
            field: "signing_keys.public_key",
            reason: "is a weak key"
        })
    );
}

#[test]
fn feed_12_a_non_canonical_signature_is_refused() {
    // Ed25519 group order L, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let state = with_keys(1, &[&signer(1)]);
    let good = feed_envelope(&feed_value(1, 1), &[&signer(1)]);
    let mut envelope: Value = serde_json::from_slice(&good).unwrap();
    let mut sig = STANDARD
        .decode(envelope["signatures"][0]["sig"].as_str().unwrap())
        .unwrap();
    // s' = s + L: the same scalar mod L, but not reduced. A malleated signature.
    let mut carry = 0u16;
    for (byte, l) in sig[32..].iter_mut().zip(L) {
        let sum = u16::from(*byte) + u16::from(l) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    envelope["signatures"][0]["sig"] = json!(b64(&sig));
    assert!(matches!(
        accept_feed(&state, &serde_json::to_vec(&envelope).unwrap(), NOW),
        Err(FeedError::ThresholdNotMet { valid: 0, .. })
    ));
}

#[test]
fn a_defective_trust_anchor_is_refused() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let r = |i| root(i).verifying_key().to_bytes();
    assert_eq!(
        FeedTrust::new([r(1), r(2), identity], 1).unwrap_err(),
        FeedError::InvalidTrust("root key is weak")
    );
    assert_eq!(
        FeedTrust::new([r(1), r(1), r(2)], 1).unwrap_err(),
        FeedError::InvalidTrust("root keys are not distinct")
    );
    assert!(FeedTrust::new([r(1), r(2), r(3)], 0).is_err());
}

// ---------------------------------------------------------------- FEED-13

#[test]
fn feed_13_restore_rebuilds_state_from_bytes_without_time_checks() {
    let state = applied(
        &with_keys(1, &[&signer(1)]),
        &feed_envelope(&feed_value(1, 1), &[&signer(1)]),
        NOW,
    );
    let keys_bytes = state.keys().unwrap().envelope().to_vec();
    let feed_bytes = state.feed().unwrap().envelope().to_vec();

    // Long after every expiry and key window: still restored, and reported stale.
    let restored = restore(&trust(), Some(&keys_bytes), Some(&feed_bytes));
    assert_eq!(restored.keys_discarded, None);
    assert_eq!(restored.feed_discarded, None);
    assert_eq!(restored.state, state);
    assert_eq!(restored.state.status(NOW + 1000 * DAY), FeedStatus::Stale);
}

#[test]
fn feed_13_tampered_stored_state_is_discarded_and_defaults_apply() {
    let state = applied(
        &with_keys(1, &[&signer(1)]),
        &feed_envelope(&feed_value(1, 1), &[&signer(1)]),
        NOW,
    );
    let keys_bytes = state.keys().unwrap().envelope().to_vec();
    let mut feed_bytes = state.feed().unwrap().envelope().to_vec();
    let i = feed_bytes.len() / 2;
    feed_bytes[i] ^= 0x20;

    let restored = restore(&trust(), Some(&keys_bytes), Some(&feed_bytes));
    assert!(restored.feed_discarded.is_some());
    assert!(restored.state.feed().is_none());
    assert_eq!(restored.state.status(NOW), FeedStatus::BundledDefaults);

    // Without a valid keys document, no stored feed can be trusted.
    let restored = restore(
        &trust(),
        Some(&b"not an envelope"[..]),
        Some(state.feed().unwrap().envelope()),
    );
    assert!(restored.keys_discarded.is_some());
    assert_eq!(restored.feed_discarded, Some(FeedError::NoKeysDocument));
    assert_eq!(restored.state, FeedState::default());

    // A stored keys document below a raised build floor is discarded too.
    let restored = restore(&trust_with_floor(2), Some(&keys_bytes), None);
    assert_eq!(
        restored.keys_discarded,
        Some(FeedError::Rollback(Document::Keys))
    );
}

// ---------------------------------------------------------------- FEED-14

#[test]
fn feed_14_routing_dns_endpoint_credential_brutal_and_text_fields_have_nowhere_to_go() {
    let smuggled: [(&str, Edit); 8] = [
        (
            "routing rules",
            &|v| v["rules"] = json!([{ "domain_suffix": "example.com", "action": "bypass" }]),
        ),
        ("DNS server", &|v| {
            v["dns"] = json!({ "server": "203.0.113.53" })
        }),
        ("endpoint address", &|v| {
            v["profiles"][1]["endpoint"]["server"] = json!("203.0.113.9")
        }),
        ("endpoint port", &|v| {
            v["profiles"][0]["endpoint"]["port"] = json!(51820)
        }),
        ("credential", &|v| {
            v["profiles"][1]["endpoint"]["obfs"]["password"] = json!("x")
        }),
        ("REALITY short id", &|v| {
            v["profiles"][2]["endpoint"]["short_id"] = json!("abcd")
        }),
        ("Brutal bandwidth", &|v| {
            v["profiles"][1]["client"]["up_mbps"] = json!(100)
        }),
        ("user-visible notice", &|v| {
            v["notice"] = json!("re-enter your credentials")
        }),
    ];
    for (label, add) in smuggled {
        let mut value = feed_value(1, 1);
        add(&mut value);
        assert!(is_malformed_payload(offer_feed(&value)), "{label} accepted");
    }
}

// ---------------------------------------------------------------- FEED-15

/// Known-answer vector: fixed test keys and payload give a fixed signature. The signing tool
/// (`xtask feed-sign`) must reproduce it, so the publisher and the client cannot drift.
#[test]
fn feed_15_known_answer_signature_over_the_pae() {
    let payload = br#"{"keys_version":1}"#;
    let message = pae(KEYS_PAYLOAD_TYPE, payload);
    assert_eq!(
        message,
        b"DSSEv1 45 application/vnd.dnet-engine.feed-keys.v1+json 18 {\"keys_version\":1}"
    );
    let signature = root(1).sign(&message);
    assert_eq!(b64(&signature.to_bytes()), KAT_SIGNATURE);
    assert_eq!(
        b64(root(1).verifying_key().as_bytes()),
        KAT_ROOT_1_PUBLIC_KEY
    );
}

/// Both values were produced independently with OpenSSL 3.5.7 (`openssl pkeyutl -sign -rawin`
/// over the PAE bytes, seed `[0x01; 32]` as a PKCS#8 key) and match ed25519-dalek's output.
const KAT_ROOT_1_PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const KAT_SIGNATURE: &str =
    "twmP5r2sTBCSYPpLV82VwKYuPUmFIoEyZD4snW57yiMbjCJ21XhaYUpyBcPzLf/aeQFmpOIgkw5yk5kDLcr+Dg==";
