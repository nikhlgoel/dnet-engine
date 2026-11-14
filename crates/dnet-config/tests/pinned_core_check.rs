// SPDX-License-Identifier: GPL-3.0-or-later
//! The generated configuration must be accepted by the **pinned primary-core binary**, not
//! merely match our reading of its documentation.
//!
//! Runs the vendored binary's offline `check` subcommand (parses and constructs the
//! configuration without starting anything, no privileges needed). Constructing an outbound
//! builds its TLS client and parses its credentials, so a malformed REALITY key, short id or
//! user id, or a TLS option the core refuses, fails here. Skips — loudly, not silently
//! passing a meaningful assertion — when the vendor binary has not been fetched.
//!
//! Credentials below are test-only values of the right shape.

use std::path::PathBuf;
use std::process::Command;

use dnet_config::hysteria2::{
    BbrProfile, Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams,
    Hysteria2Obfs, Hysteria2Settings, Hysteria2Transport,
};
use dnet_config::primary::{generate_primary_core_config, to_json, FakeIpHalf, PrimaryCoreInput};
use dnet_config::reality::{
    RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_config::{ActiveEndpointBypass, PrimaryTransport};
use dnet_core::builtin_rules::builtin_rules_for;
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{
    BandwidthPair, BrutalAcknowledgement, ConnectionProfile, ProfileKind, ProfileParams,
    BRUTAL_WARNING_REVISION,
};

fn pinned_core() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/primary-core/primary-core.exe");
    // The vendored binary is a Windows executable; on any other host it cannot run, so skip.
    (cfg!(windows) && exe.is_file()).then_some(exe)
}

/// Generate for `profile` against `endpoint` and assert the pinned core accepts the result.
fn assert_accepted(
    core: &PathBuf,
    label: &str,
    profile: &ConnectionProfile,
    endpoint: &str,
    port: u16,
    transport: Option<PrimaryTransport<'_>>,
) {
    let addr = EndpointAddress::new(endpoint, port).unwrap();
    // The full default set: it carries the encrypted-DNS block (`reject` routes and DNS rules, T070),
    // so the real core's own parser is what vouches for them. Both halves of the FakeIP pools (T131).
    for policy in [Policy::Block, Policy::Allow] {
        let rules = builtin_rules_for(Some(&addr), policy);
        for half in [FakeIpHalf::Low, FakeIpHalf::High] {
            let config = generate_primary_core_config(PrimaryCoreInput {
                active_profile: profile,
                endpoint_bypass: &ActiveEndpointBypass::new(&addr),
                rules: &rules,
                amneziawg_adapter: Some("dnet-awg0"),
                primary_transport: transport,
                fakeip: half,
            })
            .unwrap();

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("primary-core.json");
            std::fs::write(&path, to_json(&config)).unwrap();

            let out = Command::new(core)
                .args(["check", "-c"])
                .arg(&path)
                .arg("--disable-color")
                .output()
                .expect("running the pinned core");
            assert!(
                out.status.success(),
                "pinned core rejected the {label} config (endpoint {endpoint}, {policy:?}, {half:?}):\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn profile_a_config_is_accepted_by_the_pinned_core() {
    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let profile = ConnectionProfile::new(
        ProfileId::new("a"),
        ProfileKind::AmneziaWg,
        ProfileParams::new(),
    );
    for endpoint in ["203.0.113.9", "edge.example.net"] {
        assert_accepted(&core, "Profile A", &profile, endpoint, 51820, None);
    }
}

fn hysteria2(obfs: Hysteria2Obfs, trust: ServerTrust) -> Hysteria2Transport {
    Hysteria2Transport {
        settings: Hysteria2Settings {
            client: Hysteria2ClientParams {
                bbr_profile: BbrProfile::Conservative,
                chrome_parrot: true,
            },
            endpoint: Hysteria2EndpointParams { obfs, trust },
        },
        credentials: Hysteria2Credentials {
            auth_password: Secret::new("test-only-auth"),
            obfs_password: Secret::new("test-only-obfs"),
        },
    }
}

#[test]
fn hysteria2_configs_are_accepted_by_the_pinned_core() {
    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let pinned = ServerTrust::PinnedPublicKey {
        server_name: "edge.example.net".into(),
        spki_sha256: [7; 32],
    };
    let public_ca = ServerTrust::PublicCa {
        server_name: "edge.example.net".into(),
    };
    let gecko = Hysteria2Obfs::Gecko {
        min_packet_size: 512,
        max_packet_size: 1200,
    };

    let bbr = ConnectionProfile::new(
        ProfileId::new("b"),
        ProfileKind::Hysteria2,
        ProfileParams::new(),
    );
    let mut brutal = bbr.clone();
    brutal
        .enable_brutal(
            BandwidthPair {
                up_mbps: 20,
                down_mbps: 100,
            },
            BrutalAcknowledgement {
                warning_revision: BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_757_635_200,
            },
        )
        .unwrap();

    let cases = [
        (
            "Hysteria 2 salamander, pinned key",
            &bbr,
            hysteria2(Hysteria2Obfs::Salamander, pinned.clone()),
        ),
        (
            "Hysteria 2 gecko, public CA",
            &bbr,
            hysteria2(gecko, public_ca),
        ),
        ("Hysteria 2 Brutal", &brutal, hysteria2(gecko, pinned)),
    ];
    for (label, profile, transport) in &cases {
        for endpoint in ["203.0.113.9", "edge.example.net"] {
            assert_accepted(
                &core,
                label,
                profile,
                endpoint,
                8443,
                Some(PrimaryTransport::Hysteria2(transport)),
            );
        }
    }
}

#[test]
fn reality_configs_are_accepted_by_the_pinned_core() {
    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let profile = ConnectionProfile::new(
        ProfileId::new("c"),
        ProfileKind::VlessReality,
        ProfileParams::new(),
    );
    for (flow, fingerprint) in [
        (VlessFlow::Vision, UtlsFingerprint::Chrome),
        (VlessFlow::None, UtlsFingerprint::Firefox),
    ] {
        let transport = RealityTransport {
            settings: RealitySettings {
                client: RealityClientParams {
                    utls_fingerprint: fingerprint,
                },
                endpoint: RealityEndpointParams {
                    target_domain: TargetDomain::parse("www.example.com").unwrap(),
                    public_key: RealityPublicKey::parse(
                        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    )
                    .unwrap(),
                    flow,
                },
            },
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("0123456789abcdef"),
            },
        };
        for endpoint in ["203.0.113.9", "edge.example.net"] {
            assert_accepted(
                &core,
                &format!("VLESS+REALITY {flow:?}/{fingerprint:?}"),
                &profile,
                endpoint,
                443,
                Some(PrimaryTransport::VlessReality(&transport)),
            );
        }
    }
}

/// ADR-0008: the session (an endpoint dialled through a selector over the carriers, plus the control API)
/// must be accepted by the pinned core. Before the endpoint's build tag was added the core refused it as
/// "not included in this build", so this test is what keeps the tag in the pin.
#[test]
fn session_configs_are_accepted_by_the_pinned_core() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use dnet_config::session::{
        generate_session_config, Carrier, CarrierKind, ControlApi, SessionInput,
    };

    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let hy2_transport = hysteria2(
        Hysteria2Obfs::Salamander,
        ServerTrust::PinnedPublicKey {
            server_name: "edge.example.net".into(),
            spki_sha256: [7; 32],
        },
    );
    let reality_transport = RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams {
                utls_fingerprint: UtlsFingerprint::Chrome,
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
            short_id: Secret::new("0123456789abcdef"),
        },
    };
    let hy2_at = EndpointAddress::new("203.0.113.9", 8443).unwrap();
    let reality_at = EndpointAddress::new("203.0.113.9", 443).unwrap();
    let hy2_bypass = ActiveEndpointBypass::new(&hy2_at);
    let reality_bypass = ActiveEndpointBypass::new(&reality_at);
    let device_key = Secret::new(STANDARD.encode([1u8; 32]));
    let server_key = STANDARD.encode([2u8; 32]);
    let control_secret = Secret::new("c".repeat(64));

    for policy in [Policy::Block, Policy::Allow] {
        let rules = builtin_rules_for(Some(&hy2_at), policy);
        for half in [FakeIpHalf::Low, FakeIpHalf::High] {
            for (label, kinds) in [
                (
                    "both carriers",
                    vec![CarrierKind::Hysteria2, CarrierKind::Reality],
                ),
                ("Hysteria 2 only", vec![CarrierKind::Hysteria2]),
                ("REALITY only", vec![CarrierKind::Reality]),
            ] {
                let carriers: Vec<Carrier<'_>> = kinds
                    .iter()
                    .map(|kind| match kind {
                        CarrierKind::Hysteria2 => Carrier {
                            transport: PrimaryTransport::Hysteria2(&hy2_transport),
                            endpoint: &hy2_bypass,
                            brutal: None,
                        },
                        CarrierKind::Reality => Carrier {
                            transport: PrimaryTransport::VlessReality(&reality_transport),
                            endpoint: &reality_bypass,
                            brutal: None,
                        },
                    })
                    .collect();
                let config = generate_session_config(SessionInput {
                    carriers: &carriers,
                    active: kinds[0],
                    rules: &rules,
                    fakeip: half,
                    device_private_key: &device_key,
                    server_public_key: &server_key,
                    device_address: "10.9.0.2/32",
                    session_port: 25182,
                    control: ControlApi {
                        port: 29090,
                        secret: &control_secret,
                    },
                })
                .unwrap();

                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("primary-core.json");
                std::fs::write(&path, to_json(&config)).unwrap();
                let out = Command::new(&core)
                    .args(["check", "-c"])
                    .arg(&path)
                    .arg("--disable-color")
                    .output()
                    .expect("running the pinned core");
                assert!(
                    out.status.success(),
                    "pinned core rejected the session config ({label}, {policy:?}, {half:?}):\n{}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

/// A probe of one carrier through the session (ADR-0008): a loopback proxy, the carrier, and the session over
/// it. A server that serves the session refuses a probe that uses its carrier directly, so this is the probe
/// such a server gets, and the pinned core has to accept it.
#[test]
fn session_probe_configs_are_accepted_by_the_pinned_core() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use dnet_config::probe::{to_json as probe_json, SocksAuth};
    use dnet_config::session::{generate_session_probe_config, Carrier, SessionProbeInput};

    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let hy2_transport = hysteria2(
        Hysteria2Obfs::Salamander,
        ServerTrust::PinnedPublicKey {
            server_name: "edge.example.net".into(),
            spki_sha256: [7; 32],
        },
    );
    let reality_transport = RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams {
                utls_fingerprint: UtlsFingerprint::Chrome,
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
            short_id: Secret::new("0123456789abcdef"),
        },
    };
    let device_key = Secret::new(STANDARD.encode([1u8; 32]));
    let server_key = STANDARD.encode([2u8; 32]);
    let auth = SocksAuth {
        username: "probe-user".into(),
        password: Secret::new("probe-pass-0123456789"),
    };
    for (label, transport) in [
        ("Hysteria 2", PrimaryTransport::Hysteria2(&hy2_transport)),
        (
            "VLESS+REALITY",
            PrimaryTransport::VlessReality(&reality_transport),
        ),
    ] {
        for endpoint in ["203.0.113.9", "edge.example.net"] {
            let addr = EndpointAddress::new(endpoint, 8443).unwrap();
            let bypass = ActiveEndpointBypass::new(&addr);
            let config = generate_session_probe_config(SessionProbeInput {
                socks_auth: &auth,
                carrier: Carrier {
                    transport,
                    endpoint: &bypass,
                    brutal: None,
                },
                device_private_key: &device_key,
                server_public_key: &server_key,
                device_address: "10.9.0.2/32",
                session_port: 25182,
                socks_port: 51234,
            })
            .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("probe.json");
            std::fs::write(&path, probe_json(&config)).unwrap();
            let out = Command::new(&core)
                .args(["check", "-c"])
                .arg(&path)
                .arg("--disable-color")
                .output()
                .expect("running the pinned core");
            assert!(
                out.status.success(),
                "pinned core rejected the {label} session probe (endpoint {endpoint}):\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

/// A probe configuration (loopback SOCKS in, one profile out, no TUN) must also be accepted by
/// the pinned core, for an IP and for a hostname endpoint.
#[test]
fn probe_configs_are_accepted_by_the_pinned_core() {
    use dnet_config::probe::{generate_probe_config, to_json as probe_json, ProbeInput, SocksAuth};

    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let hy2_transport = hysteria2(
        Hysteria2Obfs::Salamander,
        ServerTrust::PinnedPublicKey {
            server_name: "edge.example.net".into(),
            spki_sha256: [7; 32],
        },
    );
    let reality_transport = RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams {
                utls_fingerprint: UtlsFingerprint::Chrome,
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
            short_id: Secret::new("0123456789abcdef"),
        },
    };

    for (label, kind, transport) in [
        (
            "Hysteria 2",
            ProfileKind::Hysteria2,
            PrimaryTransport::Hysteria2(&hy2_transport),
        ),
        (
            "VLESS+REALITY",
            ProfileKind::VlessReality,
            PrimaryTransport::VlessReality(&reality_transport),
        ),
    ] {
        let profile = ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new());
        for endpoint in ["203.0.113.9", "edge.example.net"] {
            let addr = EndpointAddress::new(endpoint, 8443).unwrap();
            let config = generate_probe_config(ProbeInput {
                socks_auth: &SocksAuth {
                    username: "probe-user".into(),
                    password: Secret::new("probe-pass"),
                },
                profile: &profile,
                endpoint: &ActiveEndpointBypass::new(&addr),
                transport: Some(transport),
                socks_port: 51234,
            })
            .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("probe.json");
            std::fs::write(&path, probe_json(&config)).unwrap();
            let out = Command::new(&core)
                .args(["check", "-c"])
                .arg(&path)
                .arg("--disable-color")
                .output()
                .expect("running the pinned core");
            assert!(
                out.status.success(),
                "pinned core rejected the {label} probe config (endpoint {endpoint}):\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
