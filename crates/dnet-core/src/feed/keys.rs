//! The keys document (ADR-0002 §5.2): root-signed, and delegates the short-lived keys that
//! sign the feed.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use super::envelope::decode_canonical;
use super::{
    Document, FeedError, FeedTrust, CLOCK_SKEW_SECS, KEYS_MAX_LIFETIME_SECS,
    SIGNING_KEY_MAX_LIFETIME_SECS,
};

/// Most signing keys one keys document may delegate.
pub const MAX_SIGNING_KEYS: usize = 8;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysDocumentJson {
    keys_version: u64,
    issued_at: u64,
    expires_at: u64,
    signing_threshold: u8,
    signing_keys: Vec<SigningKeyJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeyJson {
    public_key: String,
    not_before: u64,
    not_after: u64,
}

/// A signing key delegated by a keys document, with its validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedKey {
    pub key: VerifyingKey,
    pub not_before: u64,
    pub not_after: u64,
}

impl DelegatedKey {
    /// Whether `now` is inside the window, widened by the clock skew on both sides.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.not_before.saturating_sub(CLOCK_SKEW_SECS) <= now
            && now <= self.not_after.saturating_add(CLOCK_SKEW_SECS)
    }
}

/// A keys document whose schema and structural rules have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysDocument {
    pub keys_version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signing_threshold: usize,
    pub signing_keys: Vec<DelegatedKey>,
}

impl KeysDocument {
    /// Parse a **verified** keys payload and apply the rules that do not depend on the clock
    /// (ADR-0002 §4, keys step 5 without its time checks).
    pub(crate) fn parse(payload: &[u8], trust: &FeedTrust) -> Result<Self, FeedError> {
        let json: KeysDocumentJson =
            serde_json::from_slice(payload).map_err(|e| FeedError::MalformedPayload {
                document: Document::Keys,
                detail: e.to_string(),
            })?;

        if json.keys_version == 0 {
            return Err(invalid("keys_version", "must be at least 1"));
        }
        lifetime(
            json.issued_at,
            json.expires_at,
            KEYS_MAX_LIFETIME_SECS,
            "keys document lifetime",
        )?;
        if json.signing_keys.is_empty() || json.signing_keys.len() > MAX_SIGNING_KEYS {
            return Err(invalid("signing_keys", "must list 1 to 8 keys"));
        }

        let mut signing_keys: Vec<DelegatedKey> = Vec::with_capacity(json.signing_keys.len());
        for entry in &json.signing_keys {
            let bytes: [u8; 32] = decode_canonical(&entry.public_key)
                .and_then(|b| b.try_into().ok())
                .ok_or(invalid(
                    "signing_keys.public_key",
                    "must be 32 bytes of canonical base64",
                ))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| invalid("signing_keys.public_key", "is not a valid point"))?;
            if key.is_weak() {
                return Err(invalid("signing_keys.public_key", "is a weak key"));
            }
            if trust.roots().contains(&key) {
                return Err(invalid("signing_keys.public_key", "is a root key"));
            }
            if signing_keys.iter().any(|k| k.key == key) {
                return Err(invalid("signing_keys.public_key", "is listed twice"));
            }
            lifetime(
                entry.not_before,
                entry.not_after,
                SIGNING_KEY_MAX_LIFETIME_SECS,
                "signing key validity",
            )?;
            signing_keys.push(DelegatedKey {
                key,
                not_before: entry.not_before,
                not_after: entry.not_after,
            });
        }

        let signing_threshold = usize::from(json.signing_threshold);
        if signing_threshold == 0 || signing_threshold > signing_keys.len() {
            return Err(invalid(
                "signing_threshold",
                "must be between 1 and the number of signing keys",
            ));
        }

        Ok(Self {
            keys_version: json.keys_version,
            issued_at: json.issued_at,
            expires_at: json.expires_at,
            signing_threshold,
            signing_keys,
        })
    }

    /// Whether this document has expired, allowing for clock skew.
    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at.saturating_add(CLOCK_SKEW_SECS) <= now
    }

    /// The keys time checks (ADR-0002 §4, keys step 5).
    pub(crate) fn check_current(&self, now: u64) -> Result<(), FeedError> {
        check_issued_and_expiry(Document::Keys, self.issued_at, self.expires_at, now)
    }
}

fn invalid(field: &'static str, reason: &'static str) -> FeedError {
    FeedError::InvalidField { field, reason }
}

/// `start < end` and `end - start <= max`.
pub(crate) fn lifetime(
    start: u64,
    end: u64,
    max: u64,
    field: &'static str,
) -> Result<(), FeedError> {
    if start >= end {
        return Err(invalid(field, "must end after it starts"));
    }
    if end - start > max {
        return Err(invalid(field, "exceeds the maximum lifetime"));
    }
    Ok(())
}

/// `issued_at <= now + SKEW` and `expires_at > now - SKEW`.
pub(crate) fn check_issued_and_expiry(
    document: Document,
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), FeedError> {
    if issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(FeedError::NotCurrent {
            document,
            reason: "issued in the future",
        });
    }
    if expires_at.saturating_add(CLOCK_SKEW_SECS) <= now {
        return Err(FeedError::NotCurrent {
            document,
            reason: "expired",
        });
    }
    Ok(())
}
