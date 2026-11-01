//! The view-models, pinned by files.
//!
//! Each file in `tests/fixtures` is what the window is sent for one situation. The window's own tests
//! (`apps/dnet-tray/tests/fixtures.test.ts`) read the same files with the window's own parser, so a field
//! renamed on either side fails one of the two. `UPDATE_FIXTURES=1 cargo test -p dnet-view --test golden`
//! rewrites them; read the diff before keeping it, because a changed fixture is a changed contract.

mod support;

use std::path::PathBuf;

use serde_json::{json, Value};
use support::*;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.json"))
}

/// Compare `actual` with the file, or write the file when asked to.
fn golden(name: &str, actual: &Value) {
    let path = fixture_path(name);
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = serde_json::to_string_pretty(actual).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} is missing; run with UPDATE_FIXTURES=1 and read the result",
            path.display()
        )
    });
    let expected: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        &expected, actual,
        "{name} changed: this is a change to what the window is sent"
    );
}

async fn snapshot(link: FakeLink, because: Option<&str>) -> Value {
    dnet_view::Bridge::new(link)
        .snapshot(because, 1_730_000_001_000)
        .await
        .unwrap()
}

#[tokio::test]
async fn connected_on_two_networks() {
    let link = service(
        state_connected("Tier2", &["Tier2ProfileActive"]),
        Some(paths_two_networks(false)),
        Some(stats_connected()),
    );
    golden(
        "snapshot-connected",
        &snapshot(
            link,
            Some(
                "Hysteria 2 carried 1.2 Mbit/s and AmneziaWG timed out, so Hysteria 2 was chosen.",
            ),
        )
        .await,
    );
}

#[tokio::test]
async fn connected_and_slow() {
    let link = service(
        state_connected("Tier2", &["Tier2ProfileActive", "EncryptedDnsOverridden"]),
        Some(paths_two_networks(true)),
        Some(stats_connected()),
    );
    golden("snapshot-degraded", &snapshot(link, None).await);
}

#[tokio::test]
async fn disconnected() {
    let link = service(
        state_disconnected(),
        Some(paths_not_watching()),
        Some(stats_not_connected()),
    );
    golden("snapshot-disconnected", &snapshot(link, None).await);
}

#[tokio::test]
async fn an_older_service_cannot_say_which_networks_or_what_happened() {
    let link = service(state_connected("Tier1", &[]), None, None);
    let view = snapshot(link, None).await;
    // Nothing is claimed that was not said: no networks, nothing watched, nothing counted.
    assert_eq!(view["paths"]["paths"], json!([]));
    assert_eq!(view["paths"]["watching"], json!(false));
    assert_eq!(view["stats"], json!({ "connected": false }));
    golden("snapshot-older-service", &view);
}

#[tokio::test]
async fn each_failure_has_its_own_words() {
    let causes = [
        (
            "NoEndpointReachable",
            json!({ "cause": "NoEndpointReachable" }),
        ),
        (
            "AllProfilesBlocked",
            json!({ "cause": "AllProfilesBlocked" }),
        ),
        (
            "CaptivePortalUnsatisfied",
            json!({ "cause": "CaptivePortalUnsatisfied" }),
        ),
        (
            "InsufficientPrivilege",
            json!({ "cause": "InsufficientPrivilege" }),
        ),
        (
            "CoreFailedPersistently",
            json!({ "cause": "CoreFailedPersistently", "core": "PrimaryCore" }),
        ),
        ("NoUsablePath", json!({ "cause": "NoUsablePath" })),
        (
            "ConfigurationInvalid",
            json!({ "cause": "ConfigurationInvalid", "detail": "an endpoint's address is not usable" }),
        ),
    ];
    let mut titles = std::collections::BTreeSet::new();
    for (name, cause) in causes {
        let link = service(
            state_failed(cause),
            Some(paths_not_watching()),
            Some(stats_not_connected()),
        );
        let view = snapshot(link, None).await;
        assert_eq!(view["failure"]["cause"], json!(name));
        for field in ["title", "detail", "action"] {
            let words = view["failure"][field].as_str().unwrap();
            assert!(!words.is_empty(), "{name} has no {field}");
            // The service's words are shown whole: a sentence cut short is advice nobody can follow.
            assert!(
                !words.ends_with('…'),
                "{name}'s {field} was cut short: {words}"
            );
        }
        assert!(
            titles.insert(view["failure"]["title"].as_str().unwrap().to_owned()),
            "{name} shares its title with another cause"
        );
        golden(&format!("snapshot-failed-{}", name.to_lowercase()), &view);
    }
    assert_eq!(titles.len(), 7);
}

#[tokio::test]
async fn the_endpoint_and_rule_lists() {
    let link = FakeLink::new(|request| match request {
        dnet_ipc::protocol::Request::ListEndpoints => done(json!({ "endpoints": [
            { "id": "5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10", "label": "oracle-mumbai", "address": "203.0.113.9:44443", "enabled": true, "health": "Healthy", "extra": "dropped" },
            { "id": "0a1b2c3d-0000-4000-8000-000000000001", "label": "spare", "address": "vpn.example.com:443", "enabled": false, "health": "Unknown" }
        ]})),
        dnet_ipc::protocol::Request::ListRules => done(json!({ "rules": [
            { "id": "11111111-2222-4333-8444-555555555555", "kind": "ip_cidr", "value": "10.0.0.0/8",
              "precedence": 1, "action": "Bypass", "reliability": "Deterministic", "builtin": true },
            { "id": "21111111-2222-4333-8444-555555555555", "kind": "application", "value": "C:\\Apps\\app.exe\u{202e}",
              "precedence": 200, "action": "Bypass", "reliability": "BestEffort", "builtin": false, "extra": "dropped" }
        ], "encrypted_dns": { "block": true, "needs_disclosure": false }})),
        other => panic!("unexpected {other:?}"),
    });
    let bridge = dnet_view::Bridge::new(link);
    golden("endpoints", &bridge.endpoints().await.unwrap());
    golden("rules", &bridge.rules().await.unwrap());
}

#[tokio::test]
async fn the_list_of_changes_waiting_for_approval() {
    let link = FakeLink::new(|request| match request {
        dnet_ipc::protocol::Request::ListPending => done(json!({ "pending": [
            { "id": "a1b2c3d4", "what": "Adding the server \"home\" at 203.0.113.9",
              "proposed_unix_ms": 1000, "expires_unix_ms": 601000, "extra": "dropped" },
            { "id": "0f9e8d7c", "what": "Sending example.com\u{202e} around the tunnel",
              "proposed_unix_ms": 2000, "expires_unix_ms": 602000 }
        ]})),
        other => panic!("unexpected {other:?}"),
    });
    let bridge = dnet_view::Bridge::new(link);
    golden("pending", &bridge.pending().await.unwrap());
}

#[tokio::test]
async fn poor_and_unusable_are_told_apart() {
    for quality in ["Poor", "Unusable"] {
        let mut paths = paths_two_networks(true);
        paths["degraded"]["quality"] = json!(quality);
        let link = service(
            state_connected("Tier2", &[]),
            Some(paths),
            Some(stats_connected()),
        );
        let view = snapshot(link, None).await;
        assert_eq!(view["paths"]["degraded"]["quality"], json!(quality));
        assert_eq!(view["paths"]["degraded"]["staying"], json!("NoBetterPath"));
    }
}
