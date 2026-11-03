//! T066 — feed and keys envelopes are attacker-controlled until verified (ADR-0002 §3).
//!
//! They arrive from release hosts, mirrors or a file a person imports. Whatever the bytes, offering
//! them ends in an outcome or a refusal, never a panic; and a changed envelope is never accepted as
//! anything other than the document that was signed.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dnet_core::feed::sign::seal;
use dnet_core::feed::{
    accept_feed, accept_keys_document, restore, FeedOutcome, FeedState, FeedTrust, KeysOutcome,
    FEED_PAYLOAD_TYPE, KEYS_PAYLOAD_TYPE,
};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use serde_json::json;
use std::sync::LazyLock;

const DAY: u64 = 24 * 3600;
const NOW: u64 = 1_760_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trust() -> FeedTrust {
    FeedTrust::new([1u8, 2, 3].map(|s| key(s).verifying_key().to_bytes()), 1).unwrap()
}

fn keys_envelope() -> Vec<u8> {
    let payload = json!({
        "keys_version": 1,
        "issued_at": NOW - DAY,
        "expires_at": NOW + 300 * DAY,
        "signing_threshold": 1,
        "signing_keys": [{
            "public_key": STANDARD.encode(key(101).verifying_key().as_bytes()),
            "not_before": NOW - DAY,
            "not_after": NOW + 90 * DAY,
        }],
    });
    seal(
        KEYS_PAYLOAD_TYPE,
        &serde_json::to_vec(&payload).unwrap(),
        &[&key(1), &key(2)],
    )
}

fn feed_envelope() -> Vec<u8> {
    let payload = json!({
        "keys_version": 1,
        "sequence": 1,
        "issued_at": NOW - 3600,
        "expires_at": NOW + 14 * DAY,
        "profiles": [{
            "profile_id": "awg-default",
            "kind": "amnezia_wg",
            "client": { "jc": 6, "jmin": 40, "jmax": 90 }
        }]
    });
    seal(
        FEED_PAYLOAD_TYPE,
        &serde_json::to_vec(&payload).unwrap(),
        &[&key(101)],
    )
}

/// Built once: signing and verifying are slow in a debug build, and every case needs these.
static TRUST: LazyLock<FeedTrust> = LazyLock::new(trust);
static KEYS: LazyLock<Vec<u8>> = LazyLock::new(keys_envelope);
static FEED: LazyLock<Vec<u8>> = LazyLock::new(feed_envelope);

/// The state after the good keys document: what a feed is offered against.
static WITH_KEYS: LazyLock<FeedState> = LazyLock::new(|| {
    match accept_keys_document(&TRUST, &FeedState::default(), &KEYS, NOW).unwrap() {
        KeysOutcome::Accepted { state, .. } => *state,
        KeysOutcome::Unchanged => unreachable!("nothing was held"),
    }
});

fn changed(bytes: &[u8], at: prop::sample::Index, to: u8) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let i = at.index(bytes.len());
    bytes[i] = to;
    bytes
}

#[test]
fn the_samples_are_accepted() {
    assert!(matches!(
        accept_feed(&WITH_KEYS, &FEED, NOW),
        Ok(FeedOutcome::Accepted(_))
    ));
}

proptest! {
    // Each case verifies Ed25519 signatures, which a debug build does slowly.
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn any_bytes_as_a_keys_document_are_refused_without_panicking(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        prop_assert!(accept_keys_document(&TRUST, &FeedState::default(), &bytes, NOW).is_err());
    }

    #[test]
    fn any_bytes_as_a_feed_are_refused_without_panicking(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        prop_assert!(accept_feed(&WITH_KEYS, &bytes, NOW).is_err());
    }

    #[test]
    fn any_stored_bytes_restore_to_nothing_trusted(
        keys in prop::collection::vec(any::<u8>(), 0..1024),
        feed in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let restored = restore(&TRUST, Some(&keys), Some(&feed));
        prop_assert!(restored.state.keys().is_none());
        prop_assert!(restored.state.feed().is_none());
    }

    /// A keys envelope changed in one byte is refused, or accepted as exactly the signed document
    /// (a byte outside what is signed, such as the unauthenticated key id hint, may change freely).
    #[test]
    fn a_keys_document_changed_in_one_byte_is_never_a_different_document(
        at in any::<prop::sample::Index>(),
        to in any::<u8>(),
    ) {
        let expected = WITH_KEYS.keys().unwrap().document();
        let bytes = changed(&KEYS, at, to);
        if let Ok(KeysOutcome::Accepted { state, .. }) =
            accept_keys_document(&TRUST, &FeedState::default(), &bytes, NOW)
        {
            prop_assert_eq!(state.keys().unwrap().document(), expected);
        }
        let restored = restore(&TRUST, Some(&bytes), None);
        if let Some(keys) = restored.state.keys() {
            prop_assert_eq!(keys.document(), expected);
        }
    }

    /// The same for a feed, offered live and restored from a file.
    #[test]
    fn a_feed_changed_in_one_byte_is_never_a_different_document(
        at in any::<prop::sample::Index>(),
        to in any::<u8>(),
    ) {
        static EXPECTED: LazyLock<FeedOutcome> =
            LazyLock::new(|| accept_feed(&WITH_KEYS, &FEED, NOW).unwrap());
        let FeedOutcome::Accepted(next) = &*EXPECTED else {
            panic!("the sample feed is accepted");
        };
        let expected = next.feed().unwrap().document();
        let bytes = changed(&FEED, at, to);
        if let Ok(FeedOutcome::Accepted(next)) = accept_feed(&WITH_KEYS, &bytes, NOW) {
            prop_assert_eq!(next.feed().unwrap().document(), expected);
        }
        let restored = restore(&TRUST, Some(&KEYS), Some(&bytes));
        if let Some(feed) = restored.state.feed() {
            prop_assert_eq!(feed.document(), expected);
        }
    }
}
