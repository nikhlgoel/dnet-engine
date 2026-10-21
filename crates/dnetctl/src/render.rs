//! T127 — what the user is shown.
//!
//! Everything the daemon sends is treated as untrusted text on its way to a terminal: a label the
//! user typed into the configuration, a `because` from an event, a profile id. A control character
//! in it would be interpreted by the terminal (an escape sequence can move the cursor, recolour or
//! rewrite what is already on screen), and a bidirectional override can make one word read as
//! another. So every string goes through [`plain`] before it is printed.

use dnet_core::failure::explain;
use dnet_core::tier::FailoverTier;
use dnet_ipc::protocol::{ConnectionStatus, RoutingPosture, StateSnapshot, Warning};
use dnet_ipc::wire::EventView;
use serde_json::Value;

/// The longest string printed in one piece.
const MAX_SHOWN: usize = 400;

/// `text` with every character that could drive the terminal or disguise other text replaced by
/// `?`, and cut to a sensible length.
pub fn plain(text: &str) -> String {
    let mut shown: String = text
        .chars()
        .take(MAX_SHOWN)
        .map(|c| if unsafe_to_print(c) { '?' } else { c })
        .collect();
    if text.chars().count() > MAX_SHOWN {
        shown.push('…');
    }
    shown
}

fn unsafe_to_print(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Bidirectional embeddings, overrides and isolates; marks.
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
            // Zero-width characters and the byte-order mark.
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
        )
}

fn tier(tier: FailoverTier) -> &'static str {
    match tier {
        FailoverTier::Tier1 => "Tier 1",
        FailoverTier::Tier2 => "Tier 2",
    }
}

fn warning(warning: &Warning) -> &'static str {
    match warning {
        Warning::Tier2ProfileActive => {
            "This is a Tier 2 profile: established connections may break if the network interface changes."
        }
        Warning::BrutalEnabled => {
            "Brutal congestion control is on: it does not slow down on a congested link."
        }
        Warning::EncryptedDnsOverridden => {
            "This machine's encrypted DNS settings are overridden while connected."
        }
    }
}

/// A connection state in prose.
pub fn state(snapshot: &StateSnapshot) -> String {
    let status = match snapshot.status {
        ConnectionStatus::Disconnected => "Disconnected",
        ConnectionStatus::Probing => "Connecting",
        ConnectionStatus::Connected => "Connected",
        ConnectionStatus::Failed => "Failed",
    };
    let mut lines = vec![format!("Status:    {status}")];
    if let Some(profile) = &snapshot.active_profile {
        lines.push(format!(
            "Profile:   {} ({}, {})",
            plain(&profile.id),
            plain(&profile.kind),
            tier(profile.tier)
        ));
    }
    if let Some(endpoint) = &snapshot.active_endpoint {
        lines.push(format!("Endpoint:  {}", plain(&endpoint.label)));
    }
    lines.push(match snapshot.posture {
        RoutingPosture::Tunnelled { tier: t } => {
            format!("Routing:   through the tunnel ({})", tier(t))
        }
        // The posture is what the engine decided. Nothing enforces it at the operating system yet,
        // and the display must not say more than is true.
        RoutingPosture::FailClosed => {
            "Routing:   fail-closed (decided by the service; not yet enforced by the system)"
                .to_string()
        }
    });
    if let Some(cause) = &snapshot.failure {
        let words = explain(cause);
        lines.push(format!("Problem:   {}", plain(&words.title)));
        lines.push(format!("Why:       {}", plain(&words.detail)));
        lines.push(format!("To fix:    {}", plain(&words.action)));
    }
    for w in &snapshot.warnings {
        lines.push(format!("Warning:   {}", warning(w)));
    }
    lines.join("\n")
}

/// One event, on one line: its number, its name, the profile if it names one, and why.
pub fn event(view: &EventView) -> String {
    let seq = view
        .value
        .get("seq")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_string(), |n| n.to_string());
    let subject = view
        .value
        .get("profile")
        .and_then(Value::as_str)
        .map(|p| format!(" {}", plain(p)))
        .unwrap_or_default();
    format!(
        "#{seq} {}{subject}: {}",
        plain(&view.event),
        plain(&view.because)
    )
}

/// An aligned table. `rows` hold already-plain strings.
fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        // A row wider than the header would otherwise index past the widths. Callers build fixed
        // rows, but this prints what the service said, and must not trust a caller to be right.
        if row.len() > widths.len() {
            widths.resize(row.len(), 0);
        }
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                format!(
                    "{cell:<width$}",
                    width = widths.get(i).copied().unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = vec![line(headers.to_vec())];
    for row in rows {
        out.push(line(row.iter().map(String::as_str).collect()));
    }
    out.join("\n")
}

fn cell(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(s)) => plain(s),
        Some(Value::Bool(b)) => if *b { "yes" } else { "no" }.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => "?".to_string(),
    }
}

fn list<'a>(reply: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    reply
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the service's answer has no '{key}' list"))
}

/// The `ListProfiles` answer as a table.
pub fn profiles(reply: &Value) -> Result<String, String> {
    let items = list(reply, "profiles")?;
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|p| {
            ["id", "kind", "tier", "carrier", "brutal"]
                .iter()
                .map(|k| cell(p, k))
                .collect()
        })
        .collect();
    Ok(table(
        &["PROFILE", "KIND", "TIER", "CARRIER", "BRUTAL"],
        &rows,
    ))
}

/// The `ListEndpoints` answer as a table, or a sentence if there are none.
pub fn endpoints(reply: &Value) -> Result<String, String> {
    let items = list(reply, "endpoints")?;
    if items.is_empty() {
        return Ok("No endpoints are configured.".to_string());
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|e| {
            ["label", "address", "enabled", "health"]
                .iter()
                .map(|k| cell(e, k))
                .collect()
        })
        .collect();
    Ok(table(&["ENDPOINT", "ADDRESS", "ENABLED", "HEALTH"], &rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    use dnet_core::session::FailureCause;
    use dnet_ipc::protocol::{ActiveEndpoint, ActiveProfile};
    use serde_json::json;

    fn connected() -> StateSnapshot {
        StateSnapshot {
            status: ConnectionStatus::Connected,
            active_profile: Some(ActiveProfile {
                id: "hy2-default".into(),
                kind: "Hysteria2".into(),
                tier: FailoverTier::Tier2,
            }),
            active_endpoint: Some(ActiveEndpoint {
                id: "e".into(),
                label: "harness".into(),
            }),
            failure: None,
            warnings: vec![Warning::Tier2ProfileActive],
            posture: RoutingPosture::Tunnelled {
                tier: FailoverTier::Tier2,
            },
        }
    }

    #[test]
    fn a_connected_state_names_the_profile_the_endpoint_and_the_tier() {
        let text = state(&connected());
        assert!(text.contains("Status:    Connected"), "{text}");
        assert!(text.contains("hy2-default (Hysteria2, Tier 2)"), "{text}");
        assert!(text.contains("Endpoint:  harness"), "{text}");
        assert!(text.contains("through the tunnel (Tier 2)"), "{text}");
        assert!(
            text.contains("may break"),
            "the Tier 2 warning is shown: {text}"
        );
    }

    /// The display must not claim the kill switch is enforced: nothing enforces it yet.
    #[test]
    fn a_disconnected_state_does_not_overclaim_the_kill_switch() {
        let text = state(&StateSnapshot {
            status: ConnectionStatus::Disconnected,
            active_profile: None,
            active_endpoint: None,
            failure: None,
            warnings: vec![],
            posture: RoutingPosture::FailClosed,
        });
        assert!(text.contains("Disconnected"), "{text}");
        assert!(text.contains("not yet enforced"), "{text}");
    }

    #[test]
    fn a_failed_state_says_what_went_wrong_why_and_what_to_do() {
        let text = state(&StateSnapshot {
            status: ConnectionStatus::Failed,
            active_profile: None,
            active_endpoint: None,
            failure: Some(FailureCause::ConfigurationInvalid {
                detail: "endpoint 'harness' has no measurement origin".into(),
            }),
            warnings: vec![],
            posture: RoutingPosture::FailClosed,
        });
        for label in ["Problem:", "Why:", "To fix:"] {
            assert!(text.contains(label), "{label}: {text}");
        }
        assert!(text.contains("measurement origin"), "{text}");
    }

    #[test]
    fn a_connecting_state_is_called_connecting() {
        let mut snapshot = connected();
        snapshot.status = ConnectionStatus::Probing;
        snapshot.active_profile = None;
        snapshot.active_endpoint = None;
        snapshot.warnings.clear();
        snapshot.posture = RoutingPosture::FailClosed;
        assert!(state(&snapshot).contains("Status:    Connecting"));
    }

    // ------------------------------------------------ untrusted text on its way to a terminal

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let hostile = "ok\u{1b}[2J\u{1b}]0;title\u{7}\r\n\u{8}end";
        let shown = plain(hostile);
        assert!(shown.chars().all(|c| !c.is_control()), "{shown:?}");
        assert!(shown.starts_with("ok") && shown.ends_with("end"));
    }

    #[test]
    fn text_that_could_reverse_how_it_reads_is_neutralised() {
        // A right-to-left override makes the text after it read backwards.
        let shown = plain("harness\u{202E}tsilkcalb");
        assert!(!shown.contains('\u{202E}'), "{shown:?}");
        for c in ['\u{2066}', '\u{200B}', '\u{FEFF}', '\u{200F}'] {
            assert!(!plain(&format!("a{c}b")).contains(c));
        }
    }

    #[test]
    fn ordinary_text_and_non_latin_letters_are_left_alone() {
        assert_eq!(plain("hy2-default"), "hy2-default");
        assert_eq!(plain("Ünïcode ✓ 日本語"), "Ünïcode ✓ 日本語");
    }

    #[test]
    fn a_very_long_string_is_cut() {
        let shown = plain(&"x".repeat(10_000));
        assert!(shown.chars().count() <= MAX_SHOWN + 1, "{}", shown.len());
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn a_hostile_label_in_a_state_is_neutralised_everywhere_it_is_printed() {
        let mut snapshot = connected();
        snapshot.active_endpoint = Some(ActiveEndpoint {
            id: "e".into(),
            label: "evil\u{1b}[31m".into(),
        });
        snapshot.active_profile.as_mut().unwrap().id = "p\u{7}".into();
        let text = state(&snapshot);
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
    }

    // ------------------------------------------------ events and lists

    fn view(value: Value) -> EventView {
        EventView {
            event: value["event"].as_str().unwrap().to_string(),
            because: value["because"].as_str().unwrap().to_string(),
            value,
        }
    }

    #[test]
    fn an_event_is_one_line_with_its_number_name_subject_and_reason() {
        let line = event(&view(json!({
            "seq": 4, "event": "ProfileSelected", "profile": "hy2-default",
            "because": "it was the fastest usable profile"
        })));
        assert_eq!(
            line,
            "#4 ProfileSelected hy2-default: it was the fastest usable profile"
        );
    }

    #[test]
    fn an_event_without_a_number_or_subject_still_reads() {
        let line = event(&view(json!({
            "event": "EventsLost", "because": "this client read too slowly"
        })));
        assert_eq!(line, "#- EventsLost: this client read too slowly");
    }

    #[test]
    fn a_hostile_event_is_one_clean_line() {
        let line = event(&view(json!({
            "seq": 1, "event": "X\u{1b}[2J", "because": "line one\nline two\u{1b}[0m"
        })));
        assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line:?}");
    }

    #[test]
    fn profiles_and_endpoints_are_aligned_tables() {
        let text = profiles(&json!({"profiles": [
            {"id": "awg-default", "kind": "AmneziaWg", "tier": "Tier2", "carrier": "Udp", "brutal": false},
            {"id": "reality-default", "kind": "VlessReality", "tier": "Tier2", "carrier": "Tcp", "brutal": false},
        ]}))
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("PROFILE"), "{text}");
        // Columns line up: the second column starts at the same offset on every line.
        let offset = lines[1].find("AmneziaWg").unwrap();
        assert_eq!(lines[2].find("VlessReality"), Some(offset), "{text}");

        let none = endpoints(&json!({"endpoints": []})).unwrap();
        assert_eq!(none, "No endpoints are configured.");
        let some = endpoints(&json!({"endpoints": [
            {"id": "x", "label": "harness", "address": "203.0.113.10:443", "enabled": true, "health": "Unknown"}
        ]}))
        .unwrap();
        assert!(
            some.contains("harness") && some.contains("yes") && some.contains("Unknown"),
            "{some}"
        );
    }

    #[test]
    fn a_list_reply_of_the_wrong_shape_is_an_error_not_a_panic() {
        for reply in [json!({}), json!({"profiles": 3}), json!([1]), json!(null)] {
            assert!(profiles(&reply).is_err(), "{reply}");
            assert!(endpoints(&reply).is_err(), "{reply}");
        }
        // A row with missing fields shows '?', not a crash.
        let text = profiles(&json!({"profiles": [{"id": "p"}]})).unwrap();
        assert!(text.contains('?'), "{text}");
    }
}
