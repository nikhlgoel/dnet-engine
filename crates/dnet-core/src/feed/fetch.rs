//! Where the feed files live (D1) and which network a fetch may use (D2), ADR-0002 §7.
//!
//! `dnetd` does the HTTP. This module fixes the decisions so they are testable and cannot
//! drift: the URLs, the host allowlist for redirects, and the routing policy.
//!
//! **Integrity does not depend on any of this.** Every byte fetched is verified by
//! [`super::accept_keys_document`] and [`super::accept_feed`]. These rules limit where
//! `dnetd` connects and when, not what it trusts.

use crate::posture::RoutingPosture;

/// Repository whose releases host the feed (D1).
pub const FEED_REPOSITORY: &str = "nikhlgoel/dnet-engine";
/// A dedicated release tag whose assets are replaced in place, so feed publication is
/// independent of application releases.
pub const FEED_RELEASE_TAG: &str = "profile-feed";
/// The keys document asset.
pub const KEYS_ASSET: &str = "feed-keys.dsse.json";
/// The v1 feed asset.
pub const FEED_ASSET: &str = "profile-feed.v1.dsse.json";

/// Hosts a fetch may reach, including redirects. A release-asset download is served by
/// `github.com` and redirected once to `release-assets.githubusercontent.com` (observed
/// 2026-09-12). Anything else is refused.
pub const ALLOWED_HOSTS: &[&str] = &["github.com", "release-assets.githubusercontent.com"];
/// Most redirects a single fetch may follow.
pub const MAX_REDIRECTS: usize = 2;
/// Whole-request timeout, in seconds.
pub const FETCH_TIMEOUT_SECS: u64 = 30;
/// Interval between scheduled fetches while tunnelled, in seconds.
pub const FETCH_INTERVAL_SECS: u64 = 6 * 3600;
/// Upper bound of the random delay added to each scheduled fetch, in seconds.
pub const FETCH_JITTER_MAX_SECS: u64 = 30 * 60;

/// The download URL for a feed asset.
pub fn asset_url(asset: &str) -> String {
    format!("https://github.com/{FEED_REPOSITORY}/releases/download/{FEED_RELEASE_TAG}/{asset}")
}

/// Whether a request or redirect target may be followed: HTTPS, default port, an allowlisted
/// host, no credentials in the authority. Host comparison is exact and case-insensitive.
pub fn is_allowed_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // `user@host` and `host:port` are both refused: neither is ever needed here.
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| authority.eq_ignore_ascii_case(allowed))
}

/// What prompted a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchTrigger {
    /// Start-up or the periodic schedule.
    Scheduled,
    /// The user explicitly asked to check for updated connection methods.
    UserRequested,
}

/// Which network a fetch may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchRoute {
    /// Through the active tunnel, like any other traffic.
    ThroughTunnel,
    /// Directly over the physical network. The one flow that bypasses the fail-closed
    /// posture, so only ever the result of an explicit user request (D2).
    PhysicalNetwork,
    /// Not now.
    NotAllowed,
}

/// The D2 policy: fetch through the tunnel when one carries traffic, and over the physical
/// network only when the user asks while disconnected.
pub fn fetch_route(trigger: FetchTrigger, posture: RoutingPosture) -> FetchRoute {
    match (posture, trigger) {
        (RoutingPosture::Tunnelled { .. }, _) => FetchRoute::ThroughTunnel,
        (RoutingPosture::FailClosed, FetchTrigger::UserRequested) => FetchRoute::PhysicalNetwork,
        (RoutingPosture::FailClosed, FetchTrigger::Scheduled) => FetchRoute::NotAllowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::FailoverTier;

    #[test]
    fn asset_urls_point_at_the_dedicated_release_tag() {
        assert_eq!(
            asset_url(FEED_ASSET),
            "https://github.com/nikhlgoel/dnet-engine/releases/download/profile-feed/profile-feed.v1.dsse.json"
        );
        assert!(is_allowed_url(&asset_url(KEYS_ASSET)));
    }

    #[test]
    fn only_https_to_allowlisted_hosts_is_followed() {
        for url in [
            "https://github.com/x",
            "https://GitHub.com/x",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1?sig=a",
        ] {
            assert!(is_allowed_url(url), "{url}");
        }
        for url in [
            "http://github.com/x",
            "https://github.com.evil.example/x",
            "https://evil.example/github.com",
            "https://user@github.com/x",
            "https://github.com:8443/x",
            "https://objects.githubusercontent.com/x",
            "ftp://github.com/x",
            "https://",
        ] {
            assert!(!is_allowed_url(url), "{url}");
        }
    }

    #[test]
    fn a_scheduled_fetch_never_bypasses_fail_closed() {
        assert_eq!(
            fetch_route(FetchTrigger::Scheduled, RoutingPosture::FailClosed),
            FetchRoute::NotAllowed
        );
    }

    #[test]
    fn the_physical_network_is_used_only_on_explicit_request_while_disconnected() {
        assert_eq!(
            fetch_route(FetchTrigger::UserRequested, RoutingPosture::FailClosed),
            FetchRoute::PhysicalNetwork
        );
        let tunnelled = RoutingPosture::Tunnelled {
            tier: FailoverTier::Tier2,
        };
        for trigger in [FetchTrigger::Scheduled, FetchTrigger::UserRequested] {
            assert_eq!(fetch_route(trigger, tunnelled), FetchRoute::ThroughTunnel);
        }
    }
}
