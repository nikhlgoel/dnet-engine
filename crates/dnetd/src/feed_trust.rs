//! T066d (the owner's part) — the trust anchor compiled into this build (ADR-0002 §2, D3).
//!
//! The three root public keys, two of which must sign every keys document, and the lowest keys version
//! this build accepts. They are **not here yet**: they come out of the offline key ceremony described in
//! `docs/feed-publishing.md`, in which the owner generates three keys on separate media and nothing
//! secret ever touches a networked machine. Until then [`ROOT_KEYS`] is `None`, the service has no feed
//! machinery at all, and everything that depends on a feed answers that it is not available. That is
//! the safe state: a build with no anchor cannot be made to accept a feed by anyone.
//!
//! To finish the ceremony: put the three public keys (32 bytes each, from `cargo xtask feed-keygen`)
//! into [`ROOT_KEYS`], set [`MIN_KEYS_VERSION`] to the keys version published at build time, and run the
//! tests. [`anchor_from`] refuses a malformed, weak or repeated key, and the build then fails loudly
//! (the service logs the reason and runs without a feed) rather than quietly trusting fewer signers.
//! Never put a private key, a seed or a signature here.

use dnet_core::feed::{FeedError, FeedTrust, ROOT_KEY_COUNT};

/// The three root public keys, or `None` until the key ceremony (T066d).
const ROOT_KEYS: Option<[[u8; 32]; ROOT_KEY_COUNT]> = None;

/// The lowest keys version this build accepts: raised at each release to the version current when it
/// was built, so a fresh install cannot be served an older keys document (ADR-0002 §4).
const MIN_KEYS_VERSION: u64 = 1;

/// The trust anchor of this build, or `None` if it has none (or it is defective, which is logged).
pub fn anchor() -> Option<FeedTrust> {
    let keys = ROOT_KEYS?;
    match anchor_from(keys, MIN_KEYS_VERSION) {
        Ok(trust) => Some(trust),
        Err(error) => {
            tracing::error!(%error, "this build's profile-feed trust anchor is unusable; running without a feed");
            None
        }
    }
}

/// Build an anchor from three keys. Refuses a key that is not a point, is weak, or repeats another.
pub fn anchor_from(
    keys: [[u8; 32]; ROOT_KEY_COUNT],
    min_keys_version: u64,
) -> Result<FeedTrust, FeedError> {
    FeedTrust::new(keys, min_keys_version)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn public(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn three_distinct_keys_make_an_anchor() {
        assert!(anchor_from([public(1), public(2), public(3)], 1).is_ok());
    }

    #[test]
    fn a_repeated_weak_or_malformed_key_does_not() {
        assert!(anchor_from([public(1), public(1), public(3)], 1).is_err());
        let identity_point = {
            let mut bytes = [0u8; 32];
            bytes[0] = 1;
            bytes
        };
        assert!(anchor_from([public(1), identity_point, public(3)], 1).is_err());
        assert!(anchor_from([public(1), public(2), public(3)], 0).is_err());
    }

    #[test]
    fn whatever_is_compiled_in_is_either_nothing_or_usable() {
        // Until the ceremony there is nothing, and the service runs without a feed. Once keys are
        // put in, they must make an anchor: a build that ships a defective one fails here.
        match ROOT_KEYS {
            None => assert!(anchor().is_none()),
            Some(keys) => assert!(anchor_from(keys, MIN_KEYS_VERSION).is_ok()),
        }
    }
}
