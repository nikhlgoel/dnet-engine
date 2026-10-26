//! The shell's rules, without a window: what the window catches up on, when the web view is let go, and how
//! often the service is asked.

use std::time::Duration;

use dnet_view::session::{poll_interval, Backlog, Grace, ACTIVITY_KEPT, GRACE};
use serde_json::json;

fn line(n: u64) -> serde_json::Value {
    json!({ "seq": n, "event": "E", "because": format!("reason {n}") })
}

#[test]
fn the_backlog_keeps_the_newest_events_in_order() {
    let mut backlog = Backlog::new();
    for n in 0..(ACTIVITY_KEPT as u64 + 10) {
        backlog.push(line(n));
    }
    let items = backlog.items();
    assert_eq!(items.len(), ACTIVITY_KEPT);
    assert_eq!(items.first().unwrap()["seq"], json!(10));
    assert_eq!(
        items.last().unwrap()["seq"],
        json!(ACTIVITY_KEPT as u64 + 9)
    );
}

#[test]
fn the_latest_reason_is_the_latest_events() {
    let mut backlog = Backlog::new();
    assert_eq!(backlog.last_because(), None);
    backlog.push(line(1));
    backlog.push(line(2));
    assert_eq!(backlog.last_because(), Some("reason 2"));
    backlog.push(json!({ "seq": 3, "event": "NoReason" }));
    assert_eq!(
        backlog.last_because(),
        Some("reason 2"),
        "an item with no reason does not erase the last one"
    );
}

#[test]
fn a_new_subscription_forgets_the_events_but_not_the_latest_reason() {
    let mut backlog = Backlog::new();
    backlog.push(line(1));
    backlog.restart();
    assert!(backlog.items().is_empty());
    assert_eq!(backlog.last_because(), Some("reason 1"));
}

#[test]
fn the_web_view_is_destroyed_after_the_grace_unless_the_window_came_back() {
    let mut grace = Grace::new();
    grace.window_opened();
    let first = grace.window_closed();
    assert!(
        grace.still_current(first),
        "nothing happened since: destroy it"
    );

    let second = grace.window_closed();
    assert!(
        !grace.still_current(first),
        "a later close supersedes the earlier timer"
    );
    assert!(grace.still_current(second));

    grace.window_opened();
    assert!(
        !grace.still_current(second),
        "the window was opened again: do not destroy it"
    );
}

#[test]
fn the_grace_is_two_minutes_and_a_hidden_window_is_asked_about_rarely() {
    assert_eq!(GRACE, Duration::from_secs(120));
    assert_eq!(poll_interval(true), Duration::from_secs(2));
    assert!(poll_interval(false) >= Duration::from_secs(10));
    assert!(poll_interval(false) > poll_interval(true));
}
