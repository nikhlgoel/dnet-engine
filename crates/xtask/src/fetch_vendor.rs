//! T005 - `cargo xtask fetch-vendor`
//!
//! Downloads the pinned third-party binaries and verifies each against a recorded
//! SHA-256. Wintun is fetched as the **vendor-signed prebuilt DLL only**; its source
//! is GPLv2 and must never enter this GPLv3 tree (see `verify_vendor`).
//!
//! Versions and digests are pinned so that a supply-chain substitution fails loudly.

use anyhow::Result;
use std::path::Path;

/// A pinned third-party artifact.
pub struct Pinned {
    pub name: &'static str,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    pub dest: &'static str,
}

/// Pins are filled in during T005 implementation, once versions are chosen.
/// An empty digest is rejected rather than skipped - an unpinned artifact is a
/// supply-chain hole, not a convenience.
pub const PINNED: &[Pinned] = &[];

pub fn run(_repo_root: &Path) -> Result<()> {
    if PINNED.is_empty() {
        println!("fetch-vendor: no artifacts pinned yet (T005 pending)");
        println!("  Pin versions and SHA-256 digests in crates/xtask/src/fetch_vendor.rs");
        return Ok(());
    }
    // Download + digest verification lands with the pins in T005.
    unimplemented!("T005: download and verify pinned artifacts")
}

/// Verify a downloaded artifact against its pinned digest.
pub fn verify_digest(bytes: &[u8], expected_hex: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    if expected_hex.trim().is_empty() {
        anyhow::bail!("artifact has no pinned SHA-256; refusing to accept it");
    }
    let actual = hex(&Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        anyhow::bail!("digest mismatch: expected {expected_hex}, got {actual}");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pin_is_rejected() {
        assert!(verify_digest(b"anything", "").is_err());
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        assert!(verify_digest(b"hello", &"0".repeat(64)).is_err());
    }

    #[test]
    fn correct_digest_is_accepted() {
        // SHA-256 of "hello"
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_digest(b"hello", expected).is_ok());
    }
}
