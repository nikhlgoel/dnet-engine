//! T066: signed profile feed verification (ADR-0002, FR-007, FR-008).
//!
//! A pure decision layer. It takes envelope bytes, the current time and the stored feed state,
//! and either accepts, returning the next state, or refuses with a typed error. It does no I/O:
//! `dnetd` fetches, persists, runs the trial generation of ADR-0002 §4 feed step 8, and commits
//! the returned state only after that passes.
//!
//! **Layout**
//! - [`envelope`]: DSSE v1 parsing, PAE, canonical base64, the size cap, and signature counting.
//! - [`keys`]: the root-signed keys document that delegates signing keys.
//! - [`document`]: the closed v1 feed schema and its parameter bounds.
//! - [`state`]: acceptance order, rollback and equivocation, rule R, and restore at startup.
//! - [`fetch`]: where the files live (D1) and when fetching may use which network (D2).
//!
//! **Error contents.** An error about the envelope, which is attacker-controlled until verified,
//! names a field and never quotes the input. Errors about a payload arise only after the
//! signature threshold is met, so any text they carry was authorised by the signing keys.

pub mod document;
pub mod envelope;
pub mod fetch;
pub mod keys;
pub mod state;

use ed25519_dalek::VerifyingKey;

pub use document::FeedDocument;
pub use keys::KeysDocument;
pub use state::{
    accept_feed, accept_keys_document, restore, FeedOutcome, FeedState, FeedStatus, KeysOutcome,
    Restored,
};

/// Payload type of a keys document. Signed by root keys only.
pub const KEYS_PAYLOAD_TYPE: &str = "application/vnd.dnet-engine.feed-keys.v1+json";
/// Payload type of a feed document. Signed by delegated signing keys only.
pub const FEED_PAYLOAD_TYPE: &str = "application/vnd.dnet-engine.profile-feed.v1+json";

/// Largest envelope accepted from any source, in bytes (ADR-0002 §3).
pub const ENVELOPE_MAX_BYTES: usize = 262_144;
/// Tolerated clock difference, in seconds. Campus networks often block NTP (ADR-0002 §4).
pub const CLOCK_SKEW_SECS: u64 = 24 * 3600;

const DAY_SECS: u64 = 24 * 3600;
/// Longest keys-document lifetime (ADR-0002 §4).
pub const KEYS_MAX_LIFETIME_SECS: u64 = 366 * DAY_SECS;
/// Longest signing-key validity window (ADR-0002 §2).
pub const SIGNING_KEY_MAX_LIFETIME_SECS: u64 = 180 * DAY_SECS;
/// Longest feed lifetime (ADR-0002 §4).
pub const FEED_MAX_LIFETIME_SECS: u64 = 30 * DAY_SECS;

/// Number of root keys compiled into a build (D3).
pub const ROOT_KEY_COUNT: usize = 3;
/// Root signatures required on a keys document (D3: 2 of 3).
pub const ROOT_THRESHOLD: usize = 2;

/// Which signed document an error or check concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Document {
    Keys,
    Feed,
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Document::Keys => "keys document",
            Document::Feed => "profile feed",
        })
    }
}

/// Why a feed document or keys document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    #[error("envelope exceeds {ENVELOPE_MAX_BYTES} bytes")]
    TooLarge,

    /// The envelope is not a well-formed DSSE v1 envelope. Names the field.
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(&'static str),

    #[error("envelope carries an unexpected payload type for a {0}")]
    WrongPayloadType(Document),

    #[error("{document} signature threshold not met: {valid} valid of {required} required")]
    ThresholdNotMet {
        document: Document,
        valid: usize,
        required: usize,
    },

    /// A signed payload failed the schema: an unknown or duplicate field, a wrong type, a
    /// non-integer number. Carries the parser's message (signed content only).
    #[error("malformed {document} payload: {detail}")]
    MalformedPayload { document: Document, detail: String },

    /// A signed payload value is out of bounds.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },

    #[error("{document} is not valid at this time: {reason}")]
    NotCurrent {
        document: Document,
        reason: &'static str,
    },

    #[error("{0} is older than the one already accepted")]
    Rollback(Document),

    /// Two different documents claim the same version.
    #[error("{0} conflicts with an accepted document of the same version")]
    Equivocation(Document),

    #[error("profile feed was signed under a keys document other than the accepted one")]
    KeysVersionMismatch,

    #[error("no keys document has been accepted")]
    NoKeysDocument,

    #[error("feed names profile {0:?}, which this build does not define")]
    UnknownProfile(String),

    #[error("feed gives profile {0:?} a kind other than the one this build defines")]
    KindMismatch(String),

    #[error("feed lists profile {0:?} more than once")]
    DuplicateProfile(String),

    #[error("feed entry for profile {0:?} proposes nothing")]
    EmptyProposal(String),

    /// The compiled-in trust anchor is unusable. A build defect, never a feed defect.
    #[error("invalid feed trust anchor: {0}")]
    InvalidTrust(&'static str),
}

/// The trust anchor compiled into a build: three root keys, two of which must sign a keys
/// document (D3), and the lowest keys version this build accepts.
#[derive(Debug, Clone)]
pub struct FeedTrust {
    roots: [VerifyingKey; ROOT_KEY_COUNT],
    min_keys_version: u64,
}

impl FeedTrust {
    /// Build the anchor. Refuses a malformed, weak or repeated root key: a build with a
    /// defective anchor must fail loudly, not quietly accept fewer distinct signers.
    ///
    /// `min_keys_version` is raised at each release to the keys version current at build time,
    /// so a fresh install cannot be served an older keys document (ADR-0002 §4, §8).
    pub fn new(
        root_keys: [[u8; 32]; ROOT_KEY_COUNT],
        min_keys_version: u64,
    ) -> Result<Self, FeedError> {
        let mut roots = Vec::with_capacity(ROOT_KEY_COUNT);
        for bytes in &root_keys {
            let key = VerifyingKey::from_bytes(bytes)
                .map_err(|_| FeedError::InvalidTrust("root key is not a valid point"))?;
            if key.is_weak() {
                return Err(FeedError::InvalidTrust("root key is weak"));
            }
            if roots.contains(&key) {
                return Err(FeedError::InvalidTrust("root keys are not distinct"));
            }
            roots.push(key);
        }
        if min_keys_version == 0 {
            return Err(FeedError::InvalidTrust(
                "minimum keys version must be at least 1",
            ));
        }
        let roots = roots
            .try_into()
            .expect("exactly ROOT_KEY_COUNT keys were collected");
        Ok(Self {
            roots,
            min_keys_version,
        })
    }

    pub(crate) fn roots(&self) -> &[VerifyingKey] {
        &self.roots
    }

    pub(crate) fn min_keys_version(&self) -> u64 {
        self.min_keys_version
    }
}

#[cfg(test)]
mod tests;
