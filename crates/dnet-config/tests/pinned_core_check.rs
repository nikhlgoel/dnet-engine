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
use dnet_config::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
use dnet_config::reality::{
    RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_config::{ActiveEndpointBypass, PrimaryTransport};
use dnet_core::builtin_rules::builtin_rules;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{
    BandwidthPair, BrutalAcknowledgement, ConnectionProfile, ProfileKind, ProfileParams,
    BRUTAL_WARNING_REVISION,
};

fn pinned_core() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/primary-core/primary-core.exe");
    exe.is_file().then_some(exe)
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
    let rules = builtin_rules(Some(&addr));
    let config = generate_primary_core_config(PrimaryCoreInput {
        active_profile: profile,
        endpoint_bypass: &ActiveEndpointBypass::new(&addr),
        rules: &rules,
        amneziawg_adapter: Some("dnet-awg0"),
        primary_transport: transport,
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
        "pinned core rejected the {label} config (endpoint {endpoint}):\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
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
