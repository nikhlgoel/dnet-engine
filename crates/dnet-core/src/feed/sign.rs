//! T066c — signing: the publisher's half of the feed (ADR-0002 §3).
//!
//! The client half (`envelope`, `state`) verifies; this builds what it verifies. Both live in the same
//! crate so that the publisher and the client cannot drift apart: the signing tool (`cargo xtask
//! feed-sign`) calls these functions, and FEED-15's known-answer vector pins them to an independent
//! implementation.
//!
//! - [`seal`] writes the DSSE envelope: the payload, its type, and one signature per signer over the
//!   pre-authentication encoding. Ed25519 is deterministic, so the same inputs always give the same
//!   bytes.
//! - [`check_keys_payload`] and [`check_feed_payload`] run a payload through the very parsers the client
//!   will use, **before** anything is signed. A signature on a document the client would refuse is
//!   worse than no signature: it cannot be taken back, and the failure shows up on every user's machine
//!   rather than on the publisher's.
//! - [`count_valid_signatures`] lets the tool check its own output with the client's counting rule
//!   (strict verification, each key counted once) before it is published.
//!
//! No key is generated or stored here. Making and keeping keys is the publisher's ceremony (D3), done
//! by the tool outside this crate and outside the repository.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;

use super::document::FeedDocument;
use super::envelope::{count_signers, pae, parse_envelope};
use super::keys::KeysDocument;
use super::state::{accept_feed, accept_keys_document, FeedOutcome, FeedState, KeysOutcome};
use super::{Document, FeedError, FeedTrust, FEED_PAYLOAD_TYPE, KEYS_PAYLOAD_TYPE};

/// Build a DSSE envelope over exactly `payload`, signed by each of `signers` in the order given.
///
/// The `keyid` field is written empty: it is an unauthenticated hint that the client ignores, so
/// nothing is gained by filling it and nothing is leaked by leaving it blank.
pub fn seal(payload_type: &str, payload: &[u8], signers: &[&SigningKey]) -> Vec<u8> {
    let message = pae(payload_type, payload);
    let signatures: Vec<_> = signers
        .iter()
        .map(|key| json!({ "keyid": "", "sig": STANDARD.encode(key.sign(&message).to_bytes()) }))
        .collect();
    serde_json::to_vec(&json!({
        "payload": STANDARD.encode(payload),
        "payloadType": payload_type,
        "signatures": signatures,
    }))
    .expect("an envelope of strings always serialises")
}

/// Which payload type a document is signed under.
pub fn payload_type(document: Document) -> &'static str {
    match document {
        Document::Keys => KEYS_PAYLOAD_TYPE,
        Document::Feed => FEED_PAYLOAD_TYPE,
    }
}

/// Run a keys payload through the client's parser and its clock-independent rules, against the trust
/// anchor it will be verified under. `Err` is the exact reason a client would refuse it.
pub fn check_keys_payload(payload: &[u8], trust: &FeedTrust) -> Result<KeysDocument, FeedError> {
    KeysDocument::parse(payload, trust)
}

/// Run a feed payload through the client's parser and its clock-independent rules.
pub fn check_feed_payload(payload: &[u8]) -> Result<FeedDocument, FeedError> {
    FeedDocument::parse(payload)
}

/// Offer `envelope` to a client that holds nothing but the trust anchor, at time `now`, exactly as a
/// fresh install would. `Ok` is the keys document that client would accept; `Err` is the exact reason it
/// would refuse. This is the last check before a keys document is published.
pub fn rehearse_keys(
    trust: &FeedTrust,
    envelope: &[u8],
    now: u64,
) -> Result<KeysDocument, FeedError> {
    match accept_keys_document(trust, &FeedState::default(), envelope, now)? {
        KeysOutcome::Accepted { state, .. } => Ok(state
            .keys()
            .expect("an accepted keys document is in the state")
            .document()
            .clone()),
        KeysOutcome::Unchanged => unreachable!("a client with no keys cannot already hold them"),
    }
}

/// Offer `feed_envelope` to a client that has accepted `keys_envelope`, at time `now`. `Ok` is the feed
/// that client would apply; `Err` is the exact reason it would refuse. This is the last check before a
/// feed is published, and it fails if the signers are not the ones the keys document lists.
pub fn rehearse_feed(
    trust: &FeedTrust,
    keys_envelope: &[u8],
    feed_envelope: &[u8],
    now: u64,
) -> Result<FeedDocument, FeedError> {
    let state = match accept_keys_document(trust, &FeedState::default(), keys_envelope, now)? {
        KeysOutcome::Accepted { state, .. } => *state,
        KeysOutcome::Unchanged => unreachable!("a client with no keys cannot already hold them"),
    };
    match accept_feed(&state, feed_envelope, now)? {
        FeedOutcome::Accepted(next) => Ok(next
            .feed()
            .expect("an accepted feed is in the state")
            .document()
            .clone()),
        FeedOutcome::Unchanged => unreachable!("a client with no feed cannot already hold one"),
    }
}

/// How many **distinct** keys among `keys` produced a strictly valid signature on `envelope`, counted
/// by the rule the client uses. For a tool checking what it has just made.
pub fn count_valid_signatures(
    envelope: &[u8],
    document: Document,
    keys: &[VerifyingKey],
) -> Result<usize, FeedError> {
    let parsed = parse_envelope(envelope, payload_type(document), document)?;
    Ok(count_signers(
        &parsed.signed_message(),
        &parsed.signatures,
        keys,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::ROOT_THRESHOLD;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trust() -> FeedTrust {
        FeedTrust::new([1u8, 2, 3].map(|n| key(n).verifying_key().to_bytes()), 1).unwrap()
    }

    // The FEED-15 vector, produced independently with OpenSSL 3.5.7 (see `feed/tests.rs`).
    const KAT_ROOT_1_PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
    const KAT_SIGNATURE: &str =
        "twmP5r2sTBCSYPpLV82VwKYuPUmFIoEyZD4snW57yiMbjCJ21XhaYUpyBcPzLf/aeQFmpOIgkw5yk5kDLcr+Dg==";

    #[test]
    fn feed_15_the_signing_function_reproduces_the_known_answer() {
        let envelope = seal(KEYS_PAYLOAD_TYPE, br#"{"keys_version":1}"#, &[&key(1)]);
        let value: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(value["signatures"][0]["sig"], KAT_SIGNATURE);
        assert_eq!(
            STANDARD.encode(key(1).verifying_key().as_bytes()),
            KAT_ROOT_1_PUBLIC_KEY
        );
        assert_eq!(value["payloadType"], KEYS_PAYLOAD_TYPE);
        assert_eq!(value["signatures"][0]["keyid"], "");
    }

    #[test]
    fn the_same_inputs_always_give_the_same_bytes() {
        let a = seal(FEED_PAYLOAD_TYPE, b"{}", &[&key(7), &key(8)]);
        let b = seal(FEED_PAYLOAD_TYPE, b"{}", &[&key(7), &key(8)]);
        assert_eq!(a, b);
        assert_ne!(a, seal(FEED_PAYLOAD_TYPE, b"{}", &[&key(8), &key(7)]));
    }

    #[test]
    fn what_is_sealed_is_what_the_client_parses_and_counts() {
        let envelope = seal(KEYS_PAYLOAD_TYPE, b"payload", &[&key(1), &key(2)]);
        let roots: Vec<_> = [1u8, 2, 3]
            .iter()
            .map(|n| key(*n).verifying_key())
            .collect();
        let counted = count_valid_signatures(&envelope, Document::Keys, &roots).unwrap();
        assert_eq!(counted, 2, "two of the three roots signed");
        assert!(counted >= ROOT_THRESHOLD);
    }

    #[test]
    fn a_key_that_did_not_sign_is_not_counted_and_one_that_signed_twice_counts_once() {
        let envelope = seal(KEYS_PAYLOAD_TYPE, b"payload", &[&key(1), &key(1)]);
        let keys = [key(1).verifying_key(), key(2).verifying_key()];
        assert_eq!(
            count_valid_signatures(&envelope, Document::Keys, &keys),
            Ok(1)
        );
    }

    #[test]
    fn a_signature_under_another_payload_type_does_not_count() {
        // Signed as a feed, presented as keys: the type is part of what is signed.
        let envelope = seal(FEED_PAYLOAD_TYPE, b"payload", &[&key(1)]);
        assert_eq!(
            count_valid_signatures(&envelope, Document::Keys, &[key(1).verifying_key()]),
            Err(FeedError::WrongPayloadType(Document::Keys))
        );
    }

    #[test]
    fn a_payload_the_client_would_refuse_is_refused_before_signing() {
        let trust = trust();
        assert!(check_keys_payload(br#"{"keys_version":1}"#, &trust).is_err());
        assert!(check_keys_payload(b"not json", &trust).is_err());
        assert!(check_feed_payload(b"{}").is_err());
        assert!(check_feed_payload(b"not json").is_err());
    }

    fn keys_payload(public_key: &[u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys_version": 1, "issued_at": 1_000_000u64, "expires_at": 2_000_000u64,
            "signing_threshold": 1,
            "signing_keys": [{
                "public_key": STANDARD.encode(public_key),
                "not_before": 1_000_000u64, "not_after": 1_500_000u64,
            }],
        }))
        .unwrap()
    }

    #[test]
    fn a_root_key_cannot_be_delegated_as_a_signing_key() {
        // The client's parser refuses a keys document that lists a root key as a signing key, so the
        // tool refuses to sign it.
        let root = key(1).verifying_key().to_bytes();
        assert!(check_keys_payload(&keys_payload(&root), &trust()).is_err());
    }

    #[test]
    fn a_well_formed_keys_payload_passes_the_check() {
        let delegated = key(100).verifying_key().to_bytes();
        let doc = check_keys_payload(&keys_payload(&delegated), &trust()).expect("a good document");
        assert_eq!(doc.keys_version, 1);
        assert_eq!(doc.signing_keys.len(), 1);
    }

    // ------------------------------------------------------------ rehearsals

    const NOW: u64 = 1_757_635_200;
    const DAY: u64 = 86_400;

    fn current_keys_payload(signing: &SigningKey) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys_version": 1, "issued_at": NOW - DAY, "expires_at": NOW + 300 * DAY,
            "signing_threshold": 1,
            "signing_keys": [{
                "public_key": STANDARD.encode(signing.verifying_key().as_bytes()),
                "not_before": NOW - DAY, "not_after": NOW + 90 * DAY,
            }],
        }))
        .unwrap()
    }

    fn current_feed_payload(keys_version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys_version": keys_version, "sequence": 1,
            "issued_at": NOW - 3600, "expires_at": NOW + 14 * DAY,
            "profiles": [{
                "profile_id": "awg-default", "kind": "amnezia_wg",
                "client": { "jc": 6, "jmin": 40, "jmax": 90 },
                "endpoint": { "s1": 72, "s2": 41, "h1": 1873209, "h2": 5520871, "h3": 90121, "h4": 334210 },
            }],
        }))
        .unwrap()
    }

    #[test]
    fn a_keys_document_two_roots_signed_is_what_a_fresh_client_accepts() {
        let envelope = seal(
            KEYS_PAYLOAD_TYPE,
            &current_keys_payload(&key(100)),
            &[&key(1), &key(2)],
        );
        let accepted = rehearse_keys(&trust(), &envelope, NOW).expect("accepted");
        assert_eq!(accepted.keys_version, 1);
    }

    #[test]
    fn one_root_is_not_enough_and_an_expired_document_is_not_current() {
        let payload = current_keys_payload(&key(100));
        let one = seal(KEYS_PAYLOAD_TYPE, &payload, &[&key(1)]);
        assert!(matches!(
            rehearse_keys(&trust(), &one, NOW),
            Err(FeedError::ThresholdNotMet {
                document: Document::Keys,
                valid: 1,
                ..
            })
        ));
        let two = seal(KEYS_PAYLOAD_TYPE, &payload, &[&key(1), &key(2)]);
        assert!(matches!(
            rehearse_keys(&trust(), &two, NOW + 400 * DAY),
            Err(FeedError::NotCurrent { .. })
        ));
    }

    #[test]
    fn a_feed_the_listed_signing_key_signed_is_what_a_client_with_those_keys_applies() {
        let keys = seal(
            KEYS_PAYLOAD_TYPE,
            &current_keys_payload(&key(100)),
            &[&key(1), &key(3)],
        );
        let feed = seal(FEED_PAYLOAD_TYPE, &current_feed_payload(1), &[&key(100)]);
        let applied = rehearse_feed(&trust(), &keys, &feed, NOW).expect("applied");
        assert_eq!(applied.sequence, 1);
        assert_eq!(applied.keys_version, 1);
    }

    #[test]
    fn a_feed_signed_by_anyone_else_or_under_another_keys_version_is_refused() {
        let keys = seal(
            KEYS_PAYLOAD_TYPE,
            &current_keys_payload(&key(100)),
            &[&key(1), &key(2)],
        );
        // A key the keys document does not list, even a root: roots sign keys documents only.
        for stranger in [key(101), key(1)] {
            let feed = seal(FEED_PAYLOAD_TYPE, &current_feed_payload(1), &[&stranger]);
            assert!(matches!(
                rehearse_feed(&trust(), &keys, &feed, NOW),
                Err(FeedError::ThresholdNotMet {
                    document: Document::Feed,
                    valid: 0,
                    ..
                })
            ));
        }
        let other_version = seal(FEED_PAYLOAD_TYPE, &current_feed_payload(2), &[&key(100)]);
        assert_eq!(
            rehearse_feed(&trust(), &keys, &other_version, NOW),
            Err(FeedError::KeysVersionMismatch)
        );
    }
}
