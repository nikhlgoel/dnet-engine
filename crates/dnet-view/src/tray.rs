// SPDX-License-Identifier: GPL-3.0-or-later
//! T100 — the words of the tray menu (ADR-0007 R1).
//!
//! The tray is native and depends on no JavaScript, so it cannot borrow the window's words at run time. It
//! shares them at build time instead: `words.json` is the one file both this crate and the window's messages
//! are built from, so the menu and the window cannot say different things about the same state.
//!
//! The menu has four lines: what state the connection is in, the one control (FR-036), "Open", and "Quit this
//! app (the connection stays up)". Nothing else, and nothing here decides anything: the state is the
//! service's, read from the view-model [`crate::snapshot::view`] makes.

use serde_json::Value;

use crate::text::plain;

/// The shared words, parsed once from the file both sides are built from.
fn words() -> &'static Value {
    use std::sync::OnceLock;
    static WORDS: OnceLock<Value> = OnceLock::new();
    WORDS.get_or_init(|| {
        serde_json::from_str(include_str!("../words.json")).expect("words.json is valid JSON")
    })
}

fn word(key: &str) -> String {
    words()
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("words.json has no `{key}`"))
        .to_owned()
}

/// What the control does when pressed, in the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Ask the service to connect.
    Connect,
    /// Ask the service to disconnect.
    Disconnect,
    /// Nothing to press: the service is not answering, or is already working on it.
    None,
}

/// The menu's text for one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayText {
    /// The disabled first line: the state, and for a failure its title.
    pub state: String,
    /// The control's label.
    pub control: String,
    pub action: Control,
    pub open: String,
    pub quit: String,
}

fn fixed(state: String, control: String, action: Control) -> TrayText {
    TrayText {
        state,
        control,
        action,
        open: word("open"),
        quit: word("quit"),
    }
}

/// The menu for a view-model from [`crate::snapshot::view`], or for no answer at all (`None`).
#[must_use]
pub fn text(view: Option<&Value>) -> TrayText {
    let Some(view) = view else {
        return fixed(word("serviceDown"), word("stabilize"), Control::None);
    };
    match view.get("status").and_then(Value::as_str) {
        Some("Connected") => {
            let slow = view
                .pointer("/paths/degraded")
                .is_some_and(|d| !d.is_null());
            fixed(
                word(if slow { "warn" } else { "ok" }),
                word("turnOff"),
                Control::Disconnect,
            )
        }
        Some("Probing") => fixed(word("probe"), word("working"), Control::None),
        Some("Failed") => {
            let title = view
                .pointer("/failure/title")
                .and_then(Value::as_str)
                .map_or_else(|| word("off"), |t| plain(t, 80));
            fixed(title, word("stabilize"), Control::Connect)
        }
        Some("Disconnected") => fixed(word("off"), word("stabilize"), Control::Connect),
        // A status this program does not know is not "not connected": it is a reply it cannot read.
        _ => fixed(word("serviceDown"), word("stabilize"), Control::None),
    }
}
