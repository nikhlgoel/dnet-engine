//! The generated configuration must be accepted by the **pinned primary-core binary**, not
//! merely match our reading of its documentation.
//!
//! Runs the vendored binary's offline `check` subcommand (parses and constructs the
//! configuration without starting anything, no privileges needed). Skips — loudly, not
//! silently passing a meaningful assertion — when the vendor binary has not been fetched.
//!
//! Profile A only for now: the Hysteria 2 and VLESS+REALITY outbounds gain their required
//! fields (credentials, TLS/REALITY) in Phase 5 (T056/T058), and join this test then.

use std::path::PathBuf;
use std::process::Command;

use dnet_config::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
use dnet_config::ActiveEndpointBypass;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use dnet_core::rule::builtin_rules;

fn pinned_core() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/primary-core/primary-core.exe");
    exe.is_file().then_some(exe)
}

#[test]
fn profile_a_config_is_accepted_by_the_pinned_core() {
    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };

    for endpoint in ["203.0.113.9", "edge.example.net"] {
        let addr = EndpointAddress::new(endpoint, 51820).unwrap();
        let profile = ConnectionProfile::new(
            ProfileId::new("a"),
            ProfileKind::AmneziaWg,
            ProfileParams::new(),
        );
        let rules = builtin_rules(Some(&addr));
        let config = generate_primary_core_config(PrimaryCoreInput {
            active_profile: &profile,
            endpoint_bypass: &ActiveEndpointBypass::new(&addr),
            rules: &rules,
            amneziawg_adapter: Some("dnet-awg0"),
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
            "pinned core rejected the Profile A config (endpoint {endpoint}):\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
