//! T040 — primary-core configuration contract tests (CFG-01…CFG-07).
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §1.2.

use dnet_config::hysteria2::{
    Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs,
    Hysteria2Settings, Hysteria2Transport,
};
use dnet_config::primary::{
    generate_primary_core_config, to_json, PrimaryCoreInput, PrimaryTransport, FAKEIP_INET4,
    FAKEIP_INET6,
};
use dnet_config::reality::{
    RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    RealitySettings, RealityTransport, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_config::{ActiveEndpointBypass, ConfigError};
use dnet_core::builtin_rules::builtin_rules;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{
    BandwidthPair, BrutalAcknowledgement, ConnectionProfile, ProfileKind, ProfileParams,
    BRUTAL_WARNING_REVISION,
};
use dnet_core::rule::{IpCidr, RuleMatcher};

const ADAPTER: &str = "dnet-awg0";

// Test-only credential values. Each is distinctive so a leak check can search for it.
const HY2_AUTH: &str = "hy2-auth-TESTONLY-7f3a";
const HY2_OBFS: &str = "hy2-obfs-TESTONLY-91c2";
const VLESS_UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
const REALITY_SHORT_ID: &str = "0123456789abcdef";
/// 32 bytes, unpadded URL-safe base64 (the core's REALITY key encoding).
const REALITY_PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

fn endpoint() -> EndpointAddress {
    EndpointAddress::new("edge.oracle.example", 443).unwrap()
}

fn profile(kind: ProfileKind) -> ConnectionProfile {
    ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
}

fn hysteria2_transport(obfs: Hysteria2Obfs) -> Hysteria2Transport {
    Hysteria2Transport {
        settings: Hysteria2Settings {
            client: Hysteria2ClientParams::default(),
            endpoint: Hysteria2EndpointParams {
                obfs,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: "edge.oracle.example".into(),
                    spki_sha256: [7; 32],
                },
            },
        },
        credentials: Hysteria2Credentials {
            auth_password: Secret::new(HY2_AUTH),
            obfs_password: Secret::new(HY2_OBFS),
        },
    }
}

fn reality_transport(target: &str) -> RealityTransport {
    RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams::default(),
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse(target).unwrap(),
                public_key: RealityPublicKey::parse(REALITY_PUBLIC_KEY).unwrap(),
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new(VLESS_UUID),
            short_id: Secret::new(REALITY_SHORT_ID),
        },
    }
}

fn try_generate_with(
    profile: &ConnectionProfile,
    transport: Option<PrimaryTransport<'_>>,
) -> Result<dnet_config::PrimaryCoreConfig, ConfigError> {
    let addr = endpoint();
    let bypass = ActiveEndpointBypass::new(&addr);
    let rules = builtin_rules(Some(&addr));
    generate_primary_core_config(PrimaryCoreInput {
        active_profile: profile,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: Some(ADAPTER),
        primary_transport: transport,
    })
}

/// Generate for a profile with the built-in rule set for our endpoint and the transport
/// settings its kind needs.
fn try_generate(
    profile: &ConnectionProfile,
) -> Result<dnet_config::PrimaryCoreConfig, ConfigError> {
    let hy2 = hysteria2_transport(Hysteria2Obfs::Salamander);
    let reality = reality_transport("www.example.com");
    let transport = match profile.kind() {
        ProfileKind::AmneziaWg => None,
        ProfileKind::Hysteria2 => Some(PrimaryTransport::Hysteria2(&hy2)),
        ProfileKind::VlessReality => Some(PrimaryTransport::VlessReality(&reality)),
    };
    try_generate_with(profile, transport)
}

fn generate(profile: &ConnectionProfile) -> dnet_config::PrimaryCoreConfig {
    try_generate(profile).unwrap()
}

fn ack() -> BrutalAcknowledgement {
    BrutalAcknowledgement {
        warning_revision: BRUTAL_WARNING_REVISION,
        acknowledged_at_unix: 1_757_635_200,
    }
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
        ack(),
    )
    .unwrap();
    let json = to_json(&generate(&p));
    assert!(json.contains("\"up_mbps\": 50"));
    assert!(json.contains("\"down_mbps\": 200"));
    // BBR tuning is meaningless under Brutal, so it is not emitted alongside it.
    assert!(!json.contains("bbr_profile"));
}

#[test]
fn cfg_02_partial_brutal_bandwidth_fails_generation() {
    // A zero on either side is a half-configured Brutal.
    for (up_mbps, down_mbps) in [(0, 200), (50, 0), (0, 0)] {
        let mut p = profile(ProfileKind::Hysteria2);
        p.enable_brutal(BandwidthPair { up_mbps, down_mbps }, ack())
            .unwrap();
        assert_eq!(try_generate(&p), Err(ConfigError::PartialBrutalBandwidth));
    }
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
        primary_transport: None,
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
    let has_portal = config.route.rules.iter().any(|r| {
        r.domain_suffix.iter().any(|d| d == "msftconnecttest.com")
            && r.outbound.as_deref() == Some("direct")
    });
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

/// A bypass covering part of a FakeIP pool would send those synthetic addresses around the
/// tunnel, where they lead nowhere, and silently break domain routing (CC-02, T031).
#[test]
fn cfg_05_no_builtin_bypass_overlaps_a_fakeip_pool() {
    let addr = endpoint();
    let pools = [FAKEIP_INET4, FAKEIP_INET6].map(|p| IpCidr::parse(p).unwrap());
    for rule in builtin_rules(Some(&addr)) {
        if let RuleMatcher::IpCidr(range) = rule.matcher() {
            for pool in &pools {
                assert!(
                    !range.overlaps(pool),
                    "built-in bypass {range} overlaps {pool}"
                );
            }
        }
    }
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
        primary_transport: None,
    })
    .unwrap();
    assert!(config.route.rules.iter().any(|r| {
        r.ip_cidr.iter().any(|c| c == "203.0.113.9/32") && r.outbound.as_deref() == Some("direct")
    }));
}

// ---------------------------------------------------------------- CFG-08 (T056)

/// A Hysteria 2 outbound always carries an obfuscation layer and TLS. Without the layer it is
/// a recognisable QUIC handshake, which is what the profile exists to avoid (CC-10).
#[test]
fn cfg_08_hysteria2_always_carries_obfuscation_and_tls() {
    let json: serde_json::Value = serde_json::from_str(&json_for(ProfileKind::Hysteria2)).unwrap();
    let proxy = &json["outbounds"][0];
    assert_eq!(proxy["type"], "hysteria2");
    assert_eq!(proxy["server"], "edge.oracle.example");
    assert_eq!(proxy["server_port"], 443);
    assert_eq!(proxy["password"], HY2_AUTH);
    assert_eq!(proxy["obfs"]["type"], "salamander");
    assert_eq!(proxy["obfs"]["password"], HY2_OBFS);
    assert_eq!(proxy["tls"]["enabled"], true);
    assert_eq!(proxy["tls"]["server_name"], "edge.oracle.example");
    // BBR by default, with its profile explicit and Chrome parroting left on.
    assert_eq!(proxy["bbr_profile"], "standard");
    assert!(proxy.get("disable_chrome_parrot").is_none());
}

/// A pinned self-signed endpoint is trusted by its public key, never by `insecure`.
#[test]
fn cfg_08_hysteria2_pins_the_endpoint_key_and_never_disables_verification() {
    let json = json_for(ProfileKind::Hysteria2);
    assert!(!json.contains("\"insecure\""));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    // [7; 32] in standard base64.
    assert_eq!(
        value["outbounds"][0]["tls"]["certificate_public_key_sha256"],
        serde_json::json!(["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="])
    );
}

#[test]
fn cfg_08_gecko_emits_its_packet_sizes_and_bounds_them() {
    let p = profile(ProfileKind::Hysteria2);
    let gecko = hysteria2_transport(Hysteria2Obfs::Gecko {
        min_packet_size: 512,
        max_packet_size: 1200,
    });
    let config = try_generate_with(&p, Some(PrimaryTransport::Hysteria2(&gecko))).unwrap();
    let value: serde_json::Value = serde_json::from_str(&to_json(&config)).unwrap();
    let obfs = &value["outbounds"][0]["obfs"];
    assert_eq!(obfs["type"], "gecko");
    assert_eq!(obfs["min_packet_size"], 512);
    assert_eq!(obfs["max_packet_size"], 1200);

    for (min_packet_size, max_packet_size) in [(255, 1200), (512, 1401), (1200, 512)] {
        let bad = hysteria2_transport(Hysteria2Obfs::Gecko {
            min_packet_size,
            max_packet_size,
        });
        assert_eq!(
            try_generate_with(&p, Some(PrimaryTransport::Hysteria2(&bad))),
            Err(ConfigError::InvalidGeckoPacketSize),
            "{min_packet_size}..{max_packet_size}"
        );
    }
}

/// Salamander has no packet-size options; emitting them would be a Gecko-only key on a
/// Salamander layer.
#[test]
fn cfg_08_salamander_emits_no_gecko_options() {
    let json = json_for(ProfileKind::Hysteria2);
    assert!(!json.contains("min_packet_size") && !json.contains("max_packet_size"));
}

#[test]
fn cfg_08_hysteria2_refuses_missing_or_reused_credentials() {
    let p = profile(ProfileKind::Hysteria2);
    let mut empty = hysteria2_transport(Hysteria2Obfs::Salamander);
    empty.credentials.obfs_password = Secret::new("");
    assert!(matches!(
        try_generate_with(&p, Some(PrimaryTransport::Hysteria2(&empty))),
        Err(ConfigError::InvalidCredential(_))
    ));

    let mut reused = hysteria2_transport(Hysteria2Obfs::Salamander);
    reused.credentials.obfs_password = Secret::new(HY2_AUTH);
    assert!(matches!(
        try_generate_with(&p, Some(PrimaryTransport::Hysteria2(&reused))),
        Err(ConfigError::InvalidCredential(_))
    ));
}

// ---------------------------------------------------------------- CFG-09 (T058)

/// The borrowed TLS target is configuration, not a constant (Research-Critique §4.3): what
/// goes in is what reaches the handshake (CC-11).
#[test]
fn cfg_09_reality_target_domain_is_configuration_not_a_constant() {
    let p = profile(ProfileKind::VlessReality);
    for target in ["www.example.com", "static.example.org"] {
        let transport = reality_transport(target);
        let config =
            try_generate_with(&p, Some(PrimaryTransport::VlessReality(&transport))).unwrap();
        let value: serde_json::Value = serde_json::from_str(&to_json(&config)).unwrap();
        assert_eq!(value["outbounds"][0]["tls"]["server_name"], target);
    }
}

/// The pinned core refuses REALITY without uTLS, so both are always on together (CC-11).
#[test]
fn cfg_09_reality_outbound_enables_utls_and_reality() {
    let value: serde_json::Value =
        serde_json::from_str(&json_for(ProfileKind::VlessReality)).unwrap();
    let proxy = &value["outbounds"][0];
    assert_eq!(proxy["type"], "vless");
    assert_eq!(proxy["uuid"], VLESS_UUID);
    assert_eq!(proxy["flow"], "xtls-rprx-vision");
    let tls = &proxy["tls"];
    assert_eq!(tls["enabled"], true);
    assert_eq!(tls["utls"]["enabled"], true);
    assert_eq!(tls["utls"]["fingerprint"], "chrome");
    assert_eq!(tls["reality"]["enabled"], true);
    assert_eq!(tls["reality"]["public_key"], REALITY_PUBLIC_KEY);
    assert_eq!(tls["reality"]["short_id"], REALITY_SHORT_ID);
    // REALITY authenticates the endpoint itself; no certificate options apply.
    assert!(tls.get("insecure").is_none());
    assert!(tls.get("certificate_public_key_sha256").is_none());
}

#[test]
fn cfg_09_reality_refuses_malformed_credentials_without_echoing_them() {
    let p = profile(ProfileKind::VlessReality);
    for (uuid, short_id) in [
        ("not-a-uuid-SECRETVALUE", REALITY_SHORT_ID),
        (VLESS_UUID, "abc"),                // odd length
        (VLESS_UUID, "0123456789abcdef00"), // more than 8 bytes
        (VLESS_UUID, "zz"),                 // not hex
        (VLESS_UUID, ""),                   // empty
    ] {
        let mut transport = reality_transport("www.example.com");
        transport.credentials = RealityCredentials {
            uuid: Secret::new(uuid),
            short_id: Secret::new(short_id),
        };
        let err = try_generate_with(&p, Some(PrimaryTransport::VlessReality(&transport)))
            .expect_err("malformed credential accepted");
        assert!(matches!(err, ConfigError::InvalidCredential(_)), "{err:?}");
        // The error names the field, never the value (only distinctive values are checked;
        // a two-letter value could occur in any message by chance).
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("SECRETVALUE"), "{shown}");
        assert!(!shown.contains("0123456789abcdef00"), "{shown}");
    }
}

// ---------------------------------------------------------------- CFG-10 (T057)

/// Generating a primary-core profile without its transport settings is an error, not a
/// half-built outbound.
#[test]
fn cfg_10_primary_core_profiles_require_matching_transport_settings() {
    let hy2 = hysteria2_transport(Hysteria2Obfs::Salamander);
    let reality = reality_transport("www.example.com");
    let cases = [
        (ProfileKind::Hysteria2, None),
        (
            ProfileKind::Hysteria2,
            Some(PrimaryTransport::VlessReality(&reality)),
        ),
        (ProfileKind::VlessReality, None),
        (
            ProfileKind::VlessReality,
            Some(PrimaryTransport::Hysteria2(&hy2)),
        ),
    ];
    for (kind, transport) in cases {
        assert!(
            matches!(
                try_generate_with(&profile(kind), transport),
                Err(ConfigError::MissingTransport(_))
            ),
            "{kind:?}"
        );
    }
}

// ---------------------------------------------------------------- CFG-11 (CC-08)

/// Credentials reach the config file, where the core needs them, and nowhere else: not the
/// `Debug` form of the generated config, which is what ends up in logs.
#[test]
fn cfg_11_credentials_never_appear_in_debug_output() {
    for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
        let config = generate(&profile(kind));
        let debug = format!("{config:?}");
        for secret in [HY2_AUTH, HY2_OBFS, VLESS_UUID, REALITY_SHORT_ID] {
            assert!(!debug.contains(secret), "{kind:?} Debug leaks a credential");
        }
    }
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
