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
        let has_endpoint_bypass = config.route.rules.iter().any(|r| {
            r.domain.iter().any(|d| d == "edge.oracle.example")
                && r.outbound.as_deref() == Some("direct")
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
    // Every bind_interface names the adapter — nothing is bound anywhere else.
    let total = json.matches("\"bind_interface\"").count();
    let to_adapter = json
        .matches(&format!("\"bind_interface\": \"{ADAPTER}\""))
        .count();
    assert!(total >= 1, "Profile A must bind to the adapter");
    assert_eq!(
        total, to_adapter,
        "a bind_interface names another interface"
    );
    // And the carrying (proxy) outbound specifically is the bound one.
    let config = generate(&profile(ProfileKind::AmneziaWg));
    assert!(matches!(
        &config.outbounds[0],
        dnet_config::primary::Outbound::DirectBound(o) if o.bind_interface == ADAPTER && o.tag == "proxy"
    ));
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
    let has_rfc1918 = config.route.rules.iter().any(|r| {
        r.ip_cidr.iter().any(|c| c == "192.168.0.0/16") && r.outbound.as_deref() == Some("direct")
    });
    let has_portal = config
        .route
        .rules
        .iter()
        .any(|r| r.domain.iter().any(|d| d == "captive.apple.com"));
    // The DNS-capture rule is present and hijacks port 53 into the DNS module.
    let has_dns_capture = config
        .route
        .rules
        .iter()
        .any(|r| r.port.contains(&53) && r.action == "hijack-dns" && r.outbound.is_none());
    assert!(has_rfc1918, "RFC1918 bypass missing");
    assert!(has_portal, "captive-portal bypass missing");
    assert!(has_dns_capture, "DNS-capture route missing");
}

// ---------------------------------------------------- pinned-schema guards (v1.14.0)

/// Keys and outbound types removed by the pinned primary core. Emitting any of them
/// makes the core refuse to start, which would surface only at the live gate.
#[test]
fn no_config_uses_a_field_removed_by_the_pinned_core() {
    let removed = [
        "\"inet4_address\"",   // merged into `address` (removed 1.12)
        "\"type\": \"dns\"",   // special outbound (removed 1.13)
        "\"type\": \"block\"", // special outbound (removed 1.13)
        "\"independent_cache\"",
        "\"address\": \"fakeip\"", // legacy DNS server format (removed 1.14)
    ];
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        let json = json_for(kind);
        for key in removed {
            assert!(!json.contains(key), "{kind:?} config emits removed {key}");
        }
    }
}

/// The core is built without its embedded packet-diversion kernel driver (ADR-0004
/// Finding 4), and we never ship the driver file. No generated config may reach a
/// feature that would try to install it. Checked two ways: TLS `spoof` is never emitted,
/// and inbound/outbound types stay inside the set the three profiles need. An
/// allowlist, because a blocklist would miss a driver-backed type added upstream.
#[test]
fn no_config_reaches_a_feature_that_needs_the_packet_diversion_driver() {
    const INBOUND_TYPES: &[&str] = &["tun"];
    const OUTBOUND_TYPES: &[&str] = &["direct", "hysteria2", "vless"];
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        let json = json_for(kind);
        assert!(
            !json.contains("\"spoof"),
            "{kind:?} config emits TLS spoofing"
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for (section, allowed) in [("inbounds", INBOUND_TYPES), ("outbounds", OUTBOUND_TYPES)] {
            for entry in value[section].as_array().expect(section) {
                let ty = entry["type"].as_str().expect("every entry has a type");
                assert!(allowed.contains(&ty), "{kind:?} emits {section} type {ty}");
            }
        }
    }
}

/// Every profile turns on the core's own loop guard, so bypassed traffic is bound to
/// the physical NIC rather than re-entering the TUN.
#[test]
fn every_config_enables_auto_detect_interface() {
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        assert!(generate(&profile(kind)).route.auto_detect_interface);
    }
}

/// No non-bypassed DNS query may fall through to the local resolver: A/AAAA go to FakeIP,
/// and every other type goes through the tunnel (Profile A) or is refused (B/C).
#[test]
fn no_non_bypassed_dns_query_reaches_the_local_network() {
    use dnet_config::primary::DnsRule;
    for kind in [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ] {
        let dns = generate(&profile(kind)).dns;
        assert_ne!(
            dns.final_server, "fakeip",
            "the core refuses FakeIP as default"
        );

        let n = dns.rules.len();
        let fake: &DnsRule = &dns.rules[n - 2];
        let rest: &DnsRule = &dns.rules[n - 1];
        assert_eq!(fake.query_type, ["A", "AAAA"]);
        assert!(!fake.invert);
        assert_eq!(fake.server.as_deref(), Some("fakeip"));

        assert_eq!(rest.query_type, ["A", "AAAA"]);
        assert!(
            rest.invert,
            "the last rule must catch every other query type"
        );
        match kind {
            ProfileKind::AmneziaWg => assert_eq!(rest.server.as_deref(), Some("tunnel-dns")),
            _ => assert_eq!(rest.action, "reject"),
        }
        // Only bypassed names (explicit domain rules) may use the local resolver.
        for rule in &dns.rules[..n - 2] {
            assert!(!rule.domain.is_empty() || !rule.domain_suffix.is_empty());
            assert_eq!(rule.server.as_deref(), Some("local"));
        }
    }
}

/// The TUN's own address must not fall inside the FakeIP pool it hands out.
#[test]
fn tun_address_is_outside_the_fakeip_pool() {
    let config = generate(&profile(ProfileKind::AmneziaWg));
    for addr in &config.inbounds[0].address {
        assert!(
            !addr.starts_with("198.18.") && !addr.starts_with("198.19."),
            "TUN address {addr} collides with the FakeIP pool"
        );
    }
}

/// Profile A resolves names through a DNS server bound to the AmneziaWG adapter, so its
/// lookups never leave on the physical network.
#[test]
fn profile_a_dns_is_bound_to_the_tunnel_adapter() {
    let json = json_for(ProfileKind::AmneziaWg);
    assert!(json.contains("\"tag\": \"tunnel-dns\""));
    assert!(json.contains("\"domain_resolver\": \"tunnel-dns\""));
    // bind_interface appears on the outbound and the tunnel resolver — both the adapter.
    assert_eq!(
        json.matches(&format!("\"bind_interface\": \"{ADAPTER}\""))
            .count(),
        2
    );
}

/// An IP-literal endpoint bypasses by address, which is what raw tunnel packets match.
#[test]
fn ip_literal_endpoint_bypass_is_an_ip_cidr_route() {
    let addr = EndpointAddress::new("203.0.113.9", 51820).unwrap();
    let bypass = ActiveEndpointBypass::new(&addr);
    let rules = builtin_rules(Some(&addr));
    let p = profile(ProfileKind::AmneziaWg);
    let config = generate_primary_core_config(PrimaryCoreInput {
        active_profile: &p,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: Some(ADAPTER),
    })
    .unwrap();
    assert!(config.route.rules.iter().any(|r| {
        r.ip_cidr.iter().any(|c| c == "203.0.113.9/32") && r.outbound.as_deref() == Some("direct")
    }));
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
