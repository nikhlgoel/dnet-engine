//! The tray menu's words, for every state the window can be in, read from the same fixtures the window is tested
//! with: what the tray says is what the window says (ADR-0007 R1).

use std::path::PathBuf;

use dnet_view::tray::{text, Control};
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn connected_offers_to_turn_off() {
    let t = text(Some(&fixture("snapshot-connected")));
    assert_eq!(t.state, "Connected");
    assert_eq!(
        (t.control.as_str(), t.action),
        ("Turn off", Control::Disconnect)
    );
}

#[test]
fn a_slow_connection_says_so_in_the_menu_too() {
    let t = text(Some(&fixture("snapshot-degraded")));
    assert_eq!(t.state, "Connected, but slow");
    assert_eq!(t.action, Control::Disconnect);
}

#[test]
fn disconnected_offers_to_stabilize() {
    let t = text(Some(&fixture("snapshot-disconnected")));
    assert_eq!(t.state, "Not connected");
    assert_eq!(
        (t.control.as_str(), t.action),
        ("Stabilize", Control::Connect)
    );
}

#[test]
fn probing_has_nothing_to_press() {
    let t = text(Some(&json!({ "status": "Probing" })));
    assert_eq!(t.state, "Finding a way through");
    assert_eq!((t.control.as_str(), t.action), ("Working…", Control::None));
}

#[test]
fn a_failure_is_named_by_its_own_title_and_can_be_retried() {
    let view = fixture("snapshot-failed-noendpointreachable");
    let t = text(Some(&view));
    assert_eq!(t.state, view["failure"]["title"].as_str().unwrap());
    assert_eq!(t.action, Control::Connect);
}

#[test]
fn a_long_or_hostile_title_is_bounded_and_cleaned() {
    let view = json!({ "status": "Failed", "failure": { "title": format!("bad\u{202e}{}", "x".repeat(200)) } });
    let t = text(Some(&view));
    assert!(t.state.starts_with("bad?x"), "{}", t.state);
    assert_eq!(t.state.chars().count(), 81);
}

#[test]
fn no_answer_and_an_unreadable_answer_are_not_called_not_connected() {
    for t in [
        text(None),
        text(Some(&json!({ "status": "Wobbling" }))),
        text(Some(&json!({}))),
    ] {
        assert_eq!(t.state, "The background service did not answer.");
        assert_eq!(t.action, Control::None);
    }
}

#[test]
fn the_menu_always_offers_open_and_quit_and_quitting_says_the_connection_stays() {
    for t in [
        text(None),
        text(Some(&fixture("snapshot-connected"))),
        text(Some(&json!({ "status": "Probing" }))),
    ] {
        assert_eq!(t.open, "Open");
        assert_eq!(t.quit, "Quit this app (the connection stays up)");
    }
}
