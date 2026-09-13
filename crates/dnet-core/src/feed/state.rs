//! Acceptance, rollback protection, rule R and restore (ADR-0002 §4).
//!
//! Every operation is a pure function from (trust, state, bytes, now) to a new state or a
//! refusal. The caller persists the returned state's envelope bytes and nothing else: stored
//! state is always rebuilt from bytes by [`restore`], never trusted in parsed form.
//!
//! **Ordering checks** (versions, sequences, digests) do not use the clock and are the rollback
//! defence. **Time checks** gate *accepting* a document, never *keeping* one (§4 Startup).

use sha2::{Digest, Sha256};

use super::document::FeedDocument;
use super::envelope::{count_signers, parse_envelope, Envelope};
use super::keys::KeysDocument;
use super::{
    Document, FeedError, FeedTrust, CLOCK_SKEW_SECS, FEED_PAYLOAD_TYPE, KEYS_PAYLOAD_TYPE,
    ROOT_THRESHOLD,
};

/// An accepted keys document with the exact envelope bytes it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedKeys {
    envelope: Vec<u8>,
    digest: [u8; 32],
    document: KeysDocument,
}

impl AcceptedKeys {
    /// The bytes to persist.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    pub fn document(&self) -> &KeysDocument {
        &self.document
    }
}

/// An applied feed with the exact envelope bytes it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFeed {
    envelope: Vec<u8>,
    digest: [u8; 32],
    document: FeedDocument,
    /// The verified signatures, kept to re-check the feed under a new keys document (rule R).
    verified: Envelope,
}

impl AppliedFeed {
    /// The bytes to persist.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    pub fn document(&self) -> &FeedDocument {
        &self.document
    }
}

/// What has been accepted so far. `Default` is a fresh install: no keys, no feed, bundled
/// parameters in effect.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeedState {
    keys: Option<AcceptedKeys>,
    feed: Option<AppliedFeed>,
}

impl FeedState {
    pub fn keys(&self) -> Option<&AcceptedKeys> {
        self.keys.as_ref()
    }

    pub fn feed(&self) -> Option<&AppliedFeed> {
        self.feed.as_ref()
    }

    /// Whether the parameters in effect come from a current feed (ADR-0002 §6). Stale means
    /// expired and nothing else: a clock that later reads earlier than `issued_at` does not
    /// make an accepted feed stale.
    pub fn status(&self, now: u64) -> FeedStatus {
        match &self.feed {
            None => FeedStatus::BundledDefaults,
            Some(applied) if applied.document.expires_at.saturating_add(CLOCK_SKEW_SECS) > now => {
                FeedStatus::Current
            }
            Some(_) => FeedStatus::Stale,
        }
    }
}

/// Where the parameters in effect come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedStatus {
    /// No feed applied: the parameters built into this release.
    BundledDefaults,
    /// A feed that has not expired.
    Current,
    /// An applied feed past its expiry. Still in effect; reported as "definitions out of date".
    Stale,
}

/// Result of offering a keys document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysOutcome {
    /// A newer keys document was accepted. `feed_evicted` is true when rule R dropped the
    /// applied feed, which puts the bundled defaults back in effect.
    Accepted {
        state: Box<FeedState>,
        feed_evicted: bool,
    },
    /// The same document as the one already accepted.
    Unchanged,
}

/// Result of offering a feed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedOutcome {
    /// A newer feed passed every check. The caller runs trial generation for every profile
    /// (feed step 8) and commits `state` only if that succeeds.
    Accepted(Box<FeedState>),
    /// The same feed as the one already applied.
    Unchanged,
}

/// Offer a keys document (ADR-0002 §4, keys steps 1–6 and rule R).
pub fn accept_keys_document(
    trust: &FeedTrust,
    state: &FeedState,
    envelope_bytes: &[u8],
    now: u64,
) -> Result<KeysOutcome, FeedError> {
    let accepted = verify_keys(trust, envelope_bytes)?;

    let floor = state.keys.as_ref().map_or(trust.min_keys_version(), |k| {
        k.document.keys_version.max(trust.min_keys_version())
    });
    if accepted.document.keys_version < floor {
        return Err(FeedError::Rollback(Document::Keys));
    }
    if let Some(current) = &state.keys {
        if accepted.document.keys_version == current.document.keys_version {
            return if accepted.digest == current.digest {
                Ok(KeysOutcome::Unchanged)
            } else {
                Err(FeedError::Equivocation(Document::Keys))
            };
        }
    }
    accepted.document.check_current(now)?;

    // Rule R: keep the applied feed only if it still meets the threshold under the new keys.
    let feed = state
        .feed
        .as_ref()
        .filter(|applied| meets_threshold_ignoring_windows(&applied.verified, &accepted.document));
    let feed_evicted = state.feed.is_some() && feed.is_none();
    Ok(KeysOutcome::Accepted {
        state: Box::new(FeedState {
            keys: Some(accepted),
            feed: feed.cloned(),
        }),
        feed_evicted,
    })
}

/// Offer a feed document (ADR-0002 §4, feed steps 1–7 and 9).
pub fn accept_feed(
    state: &FeedState,
    envelope_bytes: &[u8],
    now: u64,
) -> Result<FeedOutcome, FeedError> {
    let envelope = parse_envelope(envelope_bytes, FEED_PAYLOAD_TYPE, Document::Feed)?;
    let keys = state.keys.as_ref().ok_or(FeedError::NoKeysDocument)?;
    if keys.document.is_expired_at(now) {
        return Err(FeedError::NotCurrent {
            document: Document::Keys,
            reason: "expired, so no new feed is accepted",
        });
    }

    let message = envelope.signed_message();
    let valid = count_signers(
        &message,
        &envelope.signatures,
        keys.document
            .signing_keys
            .iter()
            .filter(|k| k.is_valid_at(now))
            .map(|k| &k.key),
    );
    require_threshold(Document::Feed, valid, keys.document.signing_threshold)?;

    let document = FeedDocument::parse(&envelope.payload)?;
    if document.keys_version != keys.document.keys_version {
        return Err(FeedError::KeysVersionMismatch);
    }
    let digest = sha256(&envelope.payload);
    if let Some(applied) = &state.feed {
        let offered = (document.keys_version, document.sequence);
        let current = (applied.document.keys_version, applied.document.sequence);
        if offered == current && digest == applied.digest {
            return Ok(FeedOutcome::Unchanged);
        }
        if offered <= current {
            return Err(if offered == current {
                FeedError::Equivocation(Document::Feed)
            } else {
                FeedError::Rollback(Document::Feed)
            });
        }
    }
    document.check_current(now)?;

    Ok(FeedOutcome::Accepted(Box::new(FeedState {
        keys: state.keys.clone(),
        feed: Some(AppliedFeed {
            envelope: envelope_bytes.to_vec(),
            digest,
            document,
            verified: envelope,
        }),
    })))
}

/// Why a stored document was discarded at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub state: FeedState,
    /// Set when stored keys bytes existed but no longer verify.
    pub keys_discarded: Option<FeedError>,
    /// Set when stored feed bytes existed but no longer verify.
    pub feed_discarded: Option<FeedError>,
}

/// Rebuild state from persisted envelope bytes at startup (ADR-0002 §4 Startup).
///
/// Signatures, thresholds, schema and the compiled-in keys floor are checked again. Time checks
/// are not: an applied feed stays in effect past expiry and is reported stale. A document that
/// fails is discarded, never trusted. Bundled defaults are the floor, so this never fails as a
/// whole.
pub fn restore(
    trust: &FeedTrust,
    keys_bytes: Option<&[u8]>,
    feed_bytes: Option<&[u8]>,
) -> Restored {
    let mut keys_discarded = None;
    let keys = keys_bytes.and_then(|bytes| {
        match verify_keys(trust, bytes).and_then(|k| {
            if k.document.keys_version < trust.min_keys_version() {
                Err(FeedError::Rollback(Document::Keys))
            } else {
                Ok(k)
            }
        }) {
            Ok(k) => Some(k),
            Err(e) => {
                keys_discarded = Some(e);
                None
            }
        }
    });

    let mut feed_discarded = None;
    let feed = feed_bytes.and_then(|bytes| match restore_feed(keys.as_ref(), bytes) {
        Ok(applied) => Some(applied),
        Err(e) => {
            feed_discarded = Some(e);
            None
        }
    });

    Restored {
        state: FeedState { keys, feed },
        keys_discarded,
        feed_discarded,
    }
}

fn restore_feed(keys: Option<&AcceptedKeys>, bytes: &[u8]) -> Result<AppliedFeed, FeedError> {
    let keys = keys.ok_or(FeedError::NoKeysDocument)?;
    let envelope = parse_envelope(bytes, FEED_PAYLOAD_TYPE, Document::Feed)?;
    if !meets_threshold_ignoring_windows(&envelope, &keys.document) {
        return Err(FeedError::ThresholdNotMet {
            document: Document::Feed,
            valid: count_all_signing_keys(&envelope, &keys.document),
            required: keys.document.signing_threshold,
        });
    }
    let document = FeedDocument::parse(&envelope.payload)?;
    Ok(AppliedFeed {
        envelope: bytes.to_vec(),
        digest: sha256(&envelope.payload),
        document,
        verified: envelope,
    })
}

/// Keys steps 1–3 plus structural rules: envelope, root threshold, schema.
fn verify_keys(trust: &FeedTrust, bytes: &[u8]) -> Result<AcceptedKeys, FeedError> {
    let envelope = parse_envelope(bytes, KEYS_PAYLOAD_TYPE, Document::Keys)?;
    let valid = count_signers(
        &envelope.signed_message(),
        &envelope.signatures,
        trust.roots(),
    );
    require_threshold(Document::Keys, valid, ROOT_THRESHOLD)?;
    let document = KeysDocument::parse(&envelope.payload, trust)?;
    Ok(AcceptedKeys {
        envelope: bytes.to_vec(),
        digest: sha256(&envelope.payload),
        document,
    })
}

fn meets_threshold_ignoring_windows(envelope: &Envelope, keys: &KeysDocument) -> bool {
    count_all_signing_keys(envelope, keys) >= keys.signing_threshold
}

fn count_all_signing_keys(envelope: &Envelope, keys: &KeysDocument) -> usize {
    count_signers(
        &envelope.signed_message(),
        &envelope.signatures,
        keys.signing_keys.iter().map(|k| &k.key),
    )
}

fn require_threshold(document: Document, valid: usize, required: usize) -> Result<(), FeedError> {
    if valid >= required {
        Ok(())
    } else {
        Err(FeedError::ThresholdNotMet {
            document,
            valid,
            required,
        })
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
