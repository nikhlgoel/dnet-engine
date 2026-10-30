//! The feed inside the service, against real signed documents and files that can be made to fail.
//! The decisions themselves are `dnet-core`'s and tested there; these pin what the service does
//! around them: that it remembers, restores, refuses whole, and changes nothing when it cannot save.

use std::sync::atomic::{AtomicBool, Ordering};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dnet_config::persist::MemoryStateFile;
use dnet_core::feed::sign::seal;
use dnet_core::feed::{FEED_PAYLOAD_TYPE, KEYS_PAYLOAD_TYPE};
use dnet_core::transport_params::{BbrProfile, UtlsFingerprint};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::*;

const DAY: u64 = 24 * 3600;
const NOW: u64 = 1_760_000_000;

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn trust() -> FeedTrust {
    FeedTrust::new([1u8, 2, 3].map(|s| key(s).verifying_key().to_bytes()), 1).unwrap()
}

pub(crate) fn signer(i: u8) -> SigningKey {
    key(100 + i)
}

fn keys_envelope(version: u64, signing: &[&SigningKey]) -> Vec<u8> {
    keys_envelope_at(NOW, version, signing)
}

/// A keys document valid at `now`, signed by two of the three roots.
pub(crate) fn keys_envelope_at(now: u64, version: u64, signing: &[&SigningKey]) -> Vec<u8> {
    let keys: Vec<Value> = signing
        .iter()
        .map(|k| {
            json!({
                "public_key": STANDARD.encode(k.verifying_key().as_bytes()),
                "not_before": now - DAY,
                "not_after": now + 90 * DAY,
            })
        })
        .collect();
    let payload = json!({
        "keys_version": version,
        "issued_at": now - DAY,
        "expires_at": now + 300 * DAY,
        "signing_threshold": 1,
        "signing_keys": keys,
    });
    seal(
        KEYS_PAYLOAD_TYPE,
        &serde_json::to_vec(&payload).unwrap(),
        &[&key(1), &key(2)],
    )
}

fn feed_value(keys_version: u64, sequence: u64) -> Value {
    feed_value_at(NOW, keys_version, sequence)
}

/// The ADR-0002 §5.3 example feed, valid at `now`.
pub(crate) fn feed_value_at(now: u64, keys_version: u64, sequence: u64) -> Value {
    json!({
        "keys_version": keys_version,
        "sequence": sequence,
        "issued_at": now - 3600,
        "expires_at": now + 14 * DAY,
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
                "client":   { "bbr_profile": "conservative", "chrome_parrot": false },
                "endpoint": { "obfs": { "type": "gecko", "min_packet_size": 512, "max_packet_size": 1200 } }
            },
            {
                "profile_id": "reality-default",
                "kind": "vless_reality",
                "client":   { "utls_fingerprint": "firefox" },
                "endpoint": { "target_domain_candidates": ["www.example.com"] }
            }
        ]
    })
}

pub(crate) fn feed_envelope(value: &Value, signing: &SigningKey) -> Vec<u8> {
    seal(
        FEED_PAYLOAD_TYPE,
        &serde_json::to_vec(value).unwrap(),
        &[signing],
    )
}

/// A file whose reads and writes can be made to fail, sharing its bytes with the test.
#[derive(Default)]
struct Flaky {
    inner: MemoryStateFile,
    fail_writes: AtomicBool,
    fail_reads: AtomicBool,
}

impl StateFile for Flaky {
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err("access denied".into());
        }
        self.inner.read()
    }
    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err("disk full".into());
        }
        self.inner.write(bytes)
    }
    fn remove(&self) -> Result<(), String> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err("access denied".into());
        }
        self.inner.remove()
    }
}

struct Rig {
    service: FeedService,
    keys: Arc<Flaky>,
    feed: Arc<Flaky>,
    definitions: SharedDefinitions,
    notes: Vec<FeedNote>,
}

impl Rig {
    fn new() -> Self {
        Self::over(Arc::default(), Arc::default())
    }

    /// A service started over files that may already hold something.
    fn over(keys: Arc<Flaky>, feed: Arc<Flaky>) -> Self {
        let definitions = SharedDefinitions::default();
        let (service, notes) = FeedService::start(
            trust(),
            Box::new(Arc::clone(&keys)),
            Box::new(Arc::clone(&feed)),
            Arc::clone(&definitions),
        );
        Self {
            service,
            keys,
            feed,
            definitions,
            notes,
        }
    }

    fn restarted(&self) -> Self {
        Self::over(Arc::clone(&self.keys), Arc::clone(&self.feed))
    }

    fn in_effect(&self) -> ClientDefinitions {
        *self.definitions.lock().unwrap()
    }
}

fn always(_: &FeedDocument) -> Result<(), String> {
    Ok(())
}

fn offer_valid_keys_and_feed(rig: &mut Rig, sequence: u64) -> Vec<FeedNote> {
    rig.service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap();
    rig.service
        .offer_feed(
            &feed_envelope(&feed_value(1, sequence), &signer(1)),
            NOW,
            &always,
        )
        .unwrap()
}

// ------------------------------------------------------------------ a fresh install

#[test]
fn nothing_stored_means_the_bundled_definitions_and_nothing_to_say() {
    let rig = Rig::new();
    assert!(rig.notes.is_empty());
    assert_eq!(rig.in_effect(), ClientDefinitions::default());
    assert_eq!(rig.service.status(NOW), FeedStatus::BundledDefaults);
    assert_eq!(rig.service.versions(), (None, None));
}

// ------------------------------------------------------------------ accepting

#[test]
fn an_accepted_feed_puts_its_client_section_in_effect_and_is_stored() {
    let mut rig = Rig::new();
    let notes = offer_valid_keys_and_feed(&mut rig, 7);

    assert_eq!(
        notes,
        vec![FeedNote::Updated {
            sequence: 7,
            endpoint_updates: 3
        }]
    );
    let in_effect = rig.in_effect();
    assert_eq!(
        in_effect.hysteria2.bbr_profile,
        Some(BbrProfile::Conservative)
    );
    assert_eq!(in_effect.hysteria2.chrome_parrot, Some(false));
    assert_eq!(
        in_effect.reality.utls_fingerprint,
        Some(UtlsFingerprint::Firefox)
    );
    assert_eq!(in_effect.sequence, Some(7));
    assert_eq!(rig.service.status(NOW), FeedStatus::Current);
    assert_eq!(rig.service.versions(), (Some(1), Some(7)));
    assert!(rig.keys.inner.bytes().is_some() && rig.feed.inner.bytes().is_some());
}

#[test]
fn the_endpoint_section_is_staged_not_applied() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    assert_eq!(rig.service.staged_endpoint_updates().len(), 3);
}

#[test]
fn the_same_documents_again_change_nothing_and_say_nothing() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    assert!(rig
        .service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap()
        .is_empty());
    assert!(rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 7), &signer(1)), NOW, &always)
        .unwrap()
        .is_empty());
}

// ------------------------------------------------------------------ remembering

#[test]
fn a_restart_restores_the_same_definitions_without_a_note() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    let before = rig.in_effect();

    let after = rig.restarted();

    assert!(after.notes.is_empty(), "{:?}", after.notes);
    assert_eq!(after.in_effect(), before);
    assert_eq!(after.service.versions(), (Some(1), Some(7)));
}

#[test]
fn a_stored_document_that_no_longer_verifies_is_dropped_and_said_so() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    // The stored feed is damaged on disk.
    let mut damaged = rig.feed.inner.bytes().unwrap();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x55;
    rig.feed.inner.write(&damaged).unwrap();

    let after = rig.restarted();

    assert_eq!(after.in_effect(), ClientDefinitions::default());
    assert!(matches!(
        after.notes.as_slice(),
        [FeedNote::Discarded {
            document: Document::Feed,
            ..
        }]
    ));
    assert_eq!(after.service.versions().0, Some(1), "the keys survive");
}

#[test]
fn garbage_where_a_document_should_be_is_dropped_and_the_service_still_works() {
    let keys: Arc<Flaky> = Arc::default();
    let feed: Arc<Flaky> = Arc::default();
    keys.inner.write(b"SENTINEL-garbage").unwrap();
    feed.inner.write(&[0u8, 255, 17]).unwrap();

    let mut rig = Rig::over(keys, feed);

    assert_eq!(rig.notes.len(), 2);
    for note in &rig.notes {
        let FeedNote::Discarded { reason, .. } = note else {
            panic!("{note:?}");
        };
        assert!(!reason.contains("SENTINEL"), "{reason}");
    }
    // And a good pair is accepted afterwards.
    offer_valid_keys_and_feed(&mut rig, 1);
    assert_eq!(rig.in_effect().sequence, Some(1));
}

#[test]
fn a_file_that_cannot_be_read_is_reported_not_trusted() {
    let keys: Arc<Flaky> = Arc::default();
    keys.fail_reads.store(true, Ordering::SeqCst);
    let rig = Rig::over(keys, Arc::default());
    assert!(matches!(
        rig.notes.as_slice(),
        [FeedNote::Discarded {
            document: Document::Keys,
            reason
        }] if reason.contains("could not be read")
    ));
}

// ------------------------------------------------------------------ refusing

#[test]
fn a_feed_one_profile_of_which_would_not_generate_is_refused_whole() {
    let mut rig = Rig::new();
    rig.service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap();
    let refuse = |_: &FeedDocument| Err("the Hysteria 2 profile".to_string());

    let refusal = rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 3), &signer(1)), NOW, &refuse)
        .unwrap_err();

    assert!(matches!(refusal, FeedRefusal::TrialFailed(_)), "{refusal}");
    assert!(rig.feed.inner.bytes().is_none(), "nothing was stored");
    assert_eq!(rig.in_effect(), ClientDefinitions::default());
    assert_eq!(rig.service.versions(), (Some(1), None));
    // The refusal consumed nothing: the same feed is accepted once the trial passes.
    rig.service
        .offer_feed(&feed_envelope(&feed_value(1, 3), &signer(1)), NOW, &always)
        .unwrap();
    assert_eq!(rig.in_effect().sequence, Some(3));
}

#[test]
fn a_feed_that_cannot_be_saved_changes_nothing() {
    let mut rig = Rig::new();
    rig.service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap();
    rig.feed.fail_writes.store(true, Ordering::SeqCst);

    let refusal = rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 3), &signer(1)), NOW, &always)
        .unwrap_err();

    assert!(matches!(refusal, FeedRefusal::Storage(_)));
    assert_eq!(rig.in_effect(), ClientDefinitions::default());
    assert_eq!(rig.service.versions(), (Some(1), None));
}

#[test]
fn keys_that_cannot_be_saved_are_not_held() {
    let mut rig = Rig::new();
    rig.keys.fail_writes.store(true, Ordering::SeqCst);
    let refusal = rig
        .service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap_err();
    assert!(matches!(refusal, FeedRefusal::Storage(_)));
    assert_eq!(rig.service.versions(), (None, None));
}

#[test]
fn an_older_feed_is_a_rollback_and_is_refused() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    let refusal = rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 6), &signer(1)), NOW, &always)
        .unwrap_err();
    assert_eq!(
        refusal,
        FeedRefusal::Rejected(FeedError::Rollback(Document::Feed))
    );
    assert_eq!(rig.in_effect().sequence, Some(7));
}

#[test]
fn a_feed_before_any_keys_is_refused() {
    let mut rig = Rig::new();
    let refusal = rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 1), &signer(1)), NOW, &always)
        .unwrap_err();
    assert_eq!(refusal, FeedRefusal::Rejected(FeedError::NoKeysDocument));
}

#[test]
fn keys_signed_by_too_few_roots_are_refused_and_not_stored() {
    let mut rig = Rig::new();
    let payload = serde_json::to_vec(&json!({
        "keys_version": 1, "issued_at": NOW - DAY, "expires_at": NOW + 300 * DAY,
        "signing_threshold": 1,
        "signing_keys": [{
            "public_key": STANDARD.encode(signer(1).verifying_key().as_bytes()),
            "not_before": NOW - DAY, "not_after": NOW + 90 * DAY
        }],
    }))
    .unwrap();
    let one_root = seal(KEYS_PAYLOAD_TYPE, &payload, &[&key(1)]);

    let refusal = rig.service.offer_keys(&one_root, NOW).unwrap_err();

    assert!(matches!(
        refusal,
        FeedRefusal::Rejected(FeedError::ThresholdNotMet { .. })
    ));
    assert!(rig.keys.inner.bytes().is_none());
}

#[test]
fn a_feed_signed_by_a_key_nobody_delegated_is_refused() {
    let mut rig = Rig::new();
    rig.service
        .offer_keys(&keys_envelope(1, &[&signer(1)]), NOW)
        .unwrap();
    let refusal = rig
        .service
        .offer_feed(&feed_envelope(&feed_value(1, 1), &signer(2)), NOW, &always)
        .unwrap_err();
    assert!(matches!(
        refusal,
        FeedRefusal::Rejected(FeedError::ThresholdNotMet { .. })
    ));
}

#[test]
fn what_is_refused_is_never_repeated_back() {
    let mut rig = Rig::new();
    for hostile in [
        b"SENTINEL-not-an-envelope".to_vec(),
        br#"{"payload":"SENTINEL","payloadType":"x","signatures":[]}"#.to_vec(),
    ] {
        let keys = rig
            .service
            .offer_keys(&hostile, NOW)
            .unwrap_err()
            .to_string();
        let feed = rig
            .service
            .offer_feed(&hostile, NOW, &always)
            .unwrap_err()
            .to_string();
        assert!(!keys.contains("SENTINEL"), "{keys}");
        assert!(!feed.contains("SENTINEL"), "{feed}");
    }
}

// ------------------------------------------------------------------ rule R and staleness

#[test]
fn a_keys_document_that_drops_the_signing_key_evicts_the_feed() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    assert_eq!(rig.in_effect().sequence, Some(7));

    let notes = rig
        .service
        .offer_keys(&keys_envelope(2, &[&signer(2)]), NOW)
        .unwrap();

    assert_eq!(notes, vec![FeedNote::Evicted]);
    assert_eq!(
        rig.in_effect(),
        ClientDefinitions::default(),
        "what a revoked key signed is no longer in effect"
    );
    assert_eq!(rig.service.versions(), (Some(2), None));

    // The eviction is stored, not left for the next start to rediscover: the feed's file is gone,
    // so a restart agrees without a "stored feed no longer verifies" note at every start.
    assert_eq!(rig.feed.inner.bytes(), None);
    let after = rig.restarted();
    assert_eq!(after.in_effect(), ClientDefinitions::default());
    assert!(after.notes.is_empty(), "{:?}", after.notes);
}

/// An evicted feed stays evicted. A later keys document that lists its signer again must not bring
/// it back at the next start, when the running service did not (rule R decides at rotation).
#[test]
fn an_evicted_feed_does_not_come_back_when_a_later_keys_document_lists_its_signer_again() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    rig.service
        .offer_keys(&keys_envelope(2, &[&signer(2)]), NOW)
        .unwrap();
    rig.service
        .offer_keys(&keys_envelope(3, &[&signer(1), &signer(2)]), NOW)
        .unwrap();
    assert_eq!(rig.in_effect(), ClientDefinitions::default());

    let after = rig.restarted();
    assert_eq!(after.in_effect(), ClientDefinitions::default());
    assert_eq!(after.service.versions(), (Some(3), None));
}

/// Removing the evicted feed's file is tidying, not a condition of the rotation: if it fails, the
/// new keys still apply and the stored feed is discarded at the next start, as before.
#[test]
fn an_eviction_whose_file_cannot_be_removed_still_rotates_the_keys() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    rig.feed.fail_writes.store(true, Ordering::SeqCst);

    let notes = rig
        .service
        .offer_keys(&keys_envelope(2, &[&signer(2)]), NOW)
        .unwrap();

    assert_eq!(notes.first(), Some(&FeedNote::Evicted));
    assert!(
        matches!(
            notes.get(1),
            Some(FeedNote::Discarded {
                document: Document::Feed,
                ..
            })
        ),
        "{notes:?}"
    );
    assert_eq!(rig.service.versions(), (Some(2), None));
    let after = rig.restarted();
    assert_eq!(after.in_effect(), ClientDefinitions::default());
}

#[test]
fn a_keys_document_that_keeps_the_signing_key_keeps_the_feed() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    let notes = rig
        .service
        .offer_keys(&keys_envelope(2, &[&signer(1), &signer(2)]), NOW)
        .unwrap();
    assert!(notes.is_empty());
    assert_eq!(rig.in_effect().sequence, Some(7));
}

#[test]
fn an_expired_feed_stays_in_effect_and_is_reported_out_of_date_once() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    let much_later = NOW + 60 * DAY;

    assert_eq!(rig.service.status(much_later), FeedStatus::Stale);
    assert_eq!(rig.service.check_staleness(NOW), None, "not yet");
    assert_eq!(
        rig.service.check_staleness(much_later),
        Some(FeedNote::OutOfDate)
    );
    assert_eq!(rig.service.check_staleness(much_later), None, "once");
    assert_eq!(
        rig.in_effect().sequence,
        Some(7),
        "reverting would only substitute older definitions"
    );
}

#[test]
fn a_restart_does_not_drop_a_feed_for_being_old() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    // Restore is not given a clock: the time checks gate accepting a document, not keeping one.
    let after = rig.restarted();
    assert_eq!(after.in_effect().sequence, Some(7));
    assert!(after.notes.is_empty());
}

#[test]
fn a_fresh_feed_after_an_out_of_date_one_is_current_and_can_go_out_of_date_in_turn() {
    let mut rig = Rig::new();
    offer_valid_keys_and_feed(&mut rig, 7);
    let later = NOW + 60 * DAY;
    assert!(rig.service.check_staleness(later).is_some());

    let mut fresh = feed_value(1, 8);
    fresh["issued_at"] = json!(later - 3600);
    fresh["expires_at"] = json!(later + 14 * DAY);
    let notes = rig
        .service
        .offer_feed(&feed_envelope(&fresh, &signer(1)), later, &always)
        .unwrap();

    assert!(matches!(
        notes.as_slice(),
        [FeedNote::Updated { sequence: 8, .. }]
    ));
    assert_eq!(rig.service.status(later), FeedStatus::Current);
    assert_eq!(rig.service.check_staleness(later), None);
    // The mark was cleared by the new feed, so its own expiry is reported too.
    assert_eq!(
        rig.service.check_staleness(later + 60 * DAY),
        Some(FeedNote::OutOfDate)
    );
}
