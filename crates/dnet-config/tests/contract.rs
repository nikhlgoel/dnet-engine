//! T040 — primary-core configuration contract tests (CFG-01…CFG-07).
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §1.2.

use dnet_config::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
use dnet_config::{ActiveEndpointBypass, ConfigError};
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{BandwidthPair, ConnectionProfile, ProfileKind, ProfileParams};
use dnet_core::rule::builtin_rules;

const ADAPTER: &str = "dnet-awg0";

fn endpoint() -> EndpointAddress {
    EndpointAddress::new("edge.oracle.example", 443).unwrap()
}

fn profile(kind: ProfileKind) -> ConnectionProfile {
    ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
}

/// Generate for a profile kind with the built-in rule set for our endpoint.
fn generate(profile: &ConnectionProfile) -> dnet_config::PrimaryCoreConfig {
    let addr = endpoint();
    let bypass = ActiveEndpointBypass::new(&addr);
    let rules = builtin_rules(Some(&addr));
    generate_primary_core_config(PrimaryCoreInput {
        active_profile: profile,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: Some(ADAPTER),
    })
    .unwrap()
}

fn json_for(kind: ProfileKind) -> String {
    to_json(&generate(&profile(kind)))
}

// ---------------------------------------------------------------- CFG-01 / CFG-02

#[test]
fn cfg_01_hysteria2_without_brutal_has_no_bandwidth_key() {
    let json = json_for(ProfileKind::Hysteria2);
    assert!(
        !json.contains("bandwidth"),
        "BBR default must omit the bandwidth section entirely"
    );
    assert!(!json.contains("up_mbps") && !json.contains("down_mbps"));
}

#[test]
fn cfg_02_hysteria2_with_brutal_emits_both_up_and_down() {
    let mut p = profile(ProfileKind::Hysteria2);
    p.enable_brutal(
        BandwidthPair {
            up_mbps: 50,
            down_mbps: 200,
        },
        true,
    )
    .unwrap();
    let json = to_json(&generate(&p));
    assert!(json.contains("\"up_mbps\": 50"));
    assert!(json.contains("\"down_mbps\": 200"));
}

#[test]
fn cfg_02_partial_brutal_bandwidth_fails_generation() {
    let mut p = profile(ProfileKind::Hysteria2);
    // A zero on one side is a half-configured Brutal.
    p.enable_brutal(
        BandwidthPair {
            up_mbps: 0,
            down_mbps: 200,
        },
        true,
    )
    .unwrap();
    let addr = endpoint();
    let bypass = ActiveEndpointBypass::new(&addr);
    let rules = builtin_rules(Some(&addr));
    let result = generate_primary_core_config(PrimaryCoreInput {
        active_profile: &p,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: Some(ADAPTER),
    });
    assert_eq!(result, Err(ConfigError::PartialBrutalBandwidth));
}

// ---------------------------------------------------------------- CFG-03

#[test]
fn cfg_03_every_profile_has_the_endpoint_bypass_rule() {
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        let config = generate(&profile(kind));
        let has_endpoint_bypass =
            config.route.rules.iter().any(|r| {
                r.domain.iter().any(|d| d == "edge.oracle.example") && r.outbound == "direct"
            });
        assert!(
            has_endpoint_bypass,
            "{kind:?} config is missing the active-endpoint bypass rule"
        );
    }
}

// ---------------------------------------------------------------- CFG-04

#[test]
fn cfg_04_profile_a_binds_only_to_the_amneziawg_adapter() {
    let json = json_for(ProfileKind::AmneziaWg);
    // Exactly one bind_interface, and it is the adapter.
    assert_eq!(json.matches("bind_interface").count(), 1);
    assert!(json.contains(&format!("\"bind_interface\": \"{ADAPTER}\"")));
}

#[test]
fn cfg_04_non_profile_a_configs_have_no_bind_interface() {
    for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
        let json = json_for(kind);
        assert!(
            !json.contains("bind_interface"),
            "{kind:?} must not bind an interface"
        );
    }
}

#[test]
fn cfg_04_profile_a_requires_the_adapter_name() {
    let p = profile(ProfileKind::AmneziaWg);
    let addr = endpoint();
    let bypass = ActiveEndpointBypass::new(&addr);
    let rules = builtin_rules(Some(&addr));
    let result = generate_primary_core_config(PrimaryCoreInput {
        active_profile: &p,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: None,
    });
    assert_eq!(result, Err(ConfigError::MissingAmneziaWgAdapter));
}

// ---------------------------------------------------------------- CFG-05

#[test]
fn cfg_05_builtin_bypass_rules_are_present() {
    let config = generate(&profile(ProfileKind::Hysteria2));
    // A private range and a captive-portal probe host both survive into the config.
    let has_rfc1918 = config
        .route
        .rules
        .iter()
        .any(|r| r.ip_cidr.iter().any(|c| c == "192.168.0.0/16") && r.outbound == "direct");
    let has_portal = config
        .route
        .rules
        .iter()
        .any(|r| r.domain.iter().any(|d| d == "captive.apple.com"));
    // The DNS-capture rule is present and routes port 53 to the DNS outbound.
    let has_dns_capture = config
        .route
        .rules
        .iter()
        .any(|r| r.port.contains(&53) && r.outbound == "dns-out");
    assert!(has_rfc1918, "RFC1918 bypass missing");
    assert!(has_portal, "captive-portal bypass missing");
    assert!(has_dns_capture, "DNS-capture route missing");
}

// ---------------------------------------------------------------- CFG-06

#[test]
fn cfg_06_generation_is_deterministic_across_100_runs() {
    let first = json_for(ProfileKind::VlessReality);
    for _ in 0..100 {
        assert_eq!(json_for(ProfileKind::VlessReality), first);
    }
}

// ---------------------------------------------------------------- CFG-07

#[test]
fn cfg_07_no_artifact_names_the_primary_core_vendor() {
    // The vendor name must never appear in a generated artifact. Every spelling is
    // assembled from parts so this test file does not itself carry the literal (which
    // would trip `xtask lint-branding`, which scans crates/**).
    let stem = ["sing", "box"].join("");
    let banned = [
        ["sing", "box"].join("-"),
        stem.clone(),
        ["sing", "box"].join("_"),
    ];
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        let json = json_for(kind).to_ascii_lowercase();
        assert!(
            banned.iter().all(|b| !json.contains(b)),
            "{kind:?} config leaks the primary-core vendor name"
        );
    }
}
