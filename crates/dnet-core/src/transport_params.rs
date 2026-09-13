//! Transport parameter values and bounds shared by the configuration generators
//! (`dnet-config`) and the profile feed ([`crate::feed`]).
//!
//! ADR-0002 §11 requires feed values to pass the same validators as bundled and user values.
//! Where a bound applies to both, it is defined once, here. Where the feed is deliberately
//! **narrower** than the cores (ADR-0002 §5.4), the constant says so: those bounds apply to
//! feed proposals only, so a value a user enters for their own endpoint (FR-010) is still
//! judged by what the core accepts.

use serde::Deserialize;

/// The Hysteria 2 BBR tuning profile used when Brutal is off. Wire names are the pinned
/// core's, and the feed's (ADR-0002 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BbrProfile {
    #[default]
    Standard,
    Conservative,
    Aggressive,
}

impl BbrProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            BbrProfile::Standard => "standard",
            BbrProfile::Conservative => "conservative",
            BbrProfile::Aggressive => "aggressive",
        }
    }
}

/// The browser ClientHello uTLS imitates. Limited to mainstream browsers (ADR-0002 §5.4): a
/// rare fingerprint is itself distinctive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UtlsFingerprint {
    #[default]
    Chrome,
    Firefox,
    Edge,
    Safari,
    Ios,
    Android,
}

impl UtlsFingerprint {
    pub fn as_str(self) -> &'static str {
        match self {
            UtlsFingerprint::Chrome => "chrome",
            UtlsFingerprint::Firefox => "firefox",
            UtlsFingerprint::Edge => "edge",
            UtlsFingerprint::Safari => "safari",
            UtlsFingerprint::Ios => "ios",
            UtlsFingerprint::Android => "android",
        }
    }
}

/// Smallest Gecko on-wire packet size accepted, from any source (ADR-0002 §5.4).
pub const GECKO_PACKET_SIZE_MIN: u16 = 256;
/// Largest Gecko on-wire packet size accepted, from any source: below the common path MTU
/// once IP and UDP headers are added (ADR-0002 §5.4).
pub const GECKO_PACKET_SIZE_MAX: u16 = 1400;

/// Whether a Gecko packet-size pair is acceptable.
pub fn gecko_packet_sizes_valid(min_packet_size: u16, max_packet_size: u16) -> bool {
    let bounds = GECKO_PACKET_SIZE_MIN..=GECKO_PACKET_SIZE_MAX;
    bounds.contains(&min_packet_size)
        && bounds.contains(&max_packet_size)
        && min_packet_size <= max_packet_size
}

/// AmneziaWG bounds for **feed proposals only** (ADR-0002 §5.4), from the Amnezia
/// documentation's constraints for a 1280-byte MTU. The pinned core accepts wider values
/// (for example any `u32` header), which user-entered endpoints may use.
pub mod amneziawg_feed {
    /// Junk packets sent before each handshake.
    pub const JC_MIN: u32 = 1;
    pub const JC_MAX: u32 = 16;
    /// Upper bound on a junk packet's size.
    pub const JUNK_SIZE_MAX: u32 = 1280;
    /// Initiation padding: 1280 − 148 (the initiation message size).
    pub const S1_MAX: u32 = 1132;
    /// Response padding: 1280 − 92 (the response message size).
    pub const S2_MAX: u32 = 1188;
    /// Initiation minus response size. `s1 + 56 == s2` makes the padded messages equal in
    /// size, which is a pattern.
    pub const INIT_RESPONSE_SIZE_DIFFERENCE: u32 = 56;
    /// Header values 1–4 are the plain message types: the unobfuscated signature.
    pub const HEADER_MIN: u32 = 5;
    pub const HEADER_MAX: u32 = i32::MAX as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gecko_bounds_are_inclusive_and_ordered() {
        assert!(gecko_packet_sizes_valid(256, 1400));
        assert!(gecko_packet_sizes_valid(600, 600));
        assert!(!gecko_packet_sizes_valid(255, 1200));
        assert!(!gecko_packet_sizes_valid(512, 1401));
        assert!(!gecko_packet_sizes_valid(1200, 512));
    }

    #[test]
    fn wire_names_match_serde_names() {
        for (fp, name) in [
            (UtlsFingerprint::Chrome, "chrome"),
            (UtlsFingerprint::Firefox, "firefox"),
            (UtlsFingerprint::Edge, "edge"),
            (UtlsFingerprint::Safari, "safari"),
            (UtlsFingerprint::Ios, "ios"),
            (UtlsFingerprint::Android, "android"),
        ] {
            assert_eq!(fp.as_str(), name);
            assert_eq!(
                serde_json::from_str::<UtlsFingerprint>(&format!("\"{name}\"")).unwrap(),
                fp
            );
        }
        for (bbr, name) in [
            (BbrProfile::Standard, "standard"),
            (BbrProfile::Conservative, "conservative"),
            (BbrProfile::Aggressive, "aggressive"),
        ] {
            assert_eq!(bbr.as_str(), name);
            assert_eq!(
                serde_json::from_str::<BbrProfile>(&format!("\"{name}\"")).unwrap(),
                bbr
            );
        }
        // Fingerprints the core knows but the feed does not offer are refused.
        for name in ["random", "randomized", "360", "qq", "chrome_pq"] {
            assert!(serde_json::from_str::<UtlsFingerprint>(&format!("\"{name}\"")).is_err());
        }
    }

    /// The feed header bound must stay inside what the core accepts (`u32`).
    #[test]
    fn feed_header_bounds_are_narrower_than_the_core() {
        const { assert!(amneziawg_feed::HEADER_MIN > 4) };
        const { assert!(amneziawg_feed::HEADER_MAX < u32::MAX) };
    }
}
