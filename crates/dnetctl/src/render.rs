//! T127 — what the user is shown.
//!
//! Everything the daemon sends is treated as untrusted text on its way to a terminal: a label the
//! user typed into the configuration, a `because` from an event, a profile id. A control character
//! in it would be interpreted by the terminal (an escape sequence can move the cursor, recolour or
//! rewrite what is already on screen), and a bidirectional override can make one word read as
//! another. So every string goes through [`plain`] before it is printed.

use dnet_core::failure::explain;
use dnet_core::tier::FailoverTier;
use dnet_ipc::netview::{Kind, PathsReply, Quality, Role, StatsReply};
use dnet_ipc::protocol::{ConnectionStatus, RoutingPosture, StateSnapshot, Warning};
use dnet_ipc::wire::EventView;
use serde_json::Value;

/// The longest string printed in one piece.
const MAX_SHOWN: usize = 400;

/// A reading older than this is shown as the last known, not as current.
const STALE_AFTER_SECS: u64 = 15;

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

/// The `ListRules` answer as a table, in the order the rules apply.
pub fn rules(reply: &Value) -> Result<String, String> {
    let items = list(reply, "rules")?;
    let mut rows: Vec<(u64, Vec<String>)> = Vec::with_capacity(items.len());
    for r in items {
        let precedence = r
            .get("precedence")
            .and_then(Value::as_u64)
            .ok_or("a rule has no precedence")?;
        let value = cell(r, "value");
        let what = match r.get("kind").and_then(Value::as_str) {
            Some("domain") => value,
            Some("domain_suffix") => format!("*.{value}"),
            Some("ip_cidr") => value,
            Some("application") => format!("program {value}"),
            Some("dns_port") => "port 53".to_owned(),
            Some("encrypted_dns_port") => format!("port {value}"),
            _ => "?".to_owned(),
        };
        let builtin = r.get("builtin").and_then(Value::as_bool) == Some(true);
        rows.push((
            precedence,
            vec![
                precedence.to_string(),
                what,
                cell(r, "action"),
                cell(r, "reliability"),
                if builtin {
                    "built-in".to_owned()
                } else {
                    cell(r, "id")
                },
            ],
        ));
    }
    rows.sort_by_key(|(p, _)| *p);
    let rows: Vec<Vec<String>> = rows.into_iter().map(|(_, row)| row).collect();
    Ok(table(
        &["ORDER", "MATCHES", "ACTION", "RELIABILITY", "RULE"],
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

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Wifi => "Wi-Fi",
        Kind::Cellular => "Mobile",
        Kind::Ethernet => "Cable",
        Kind::Other => "Other",
    }
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Carrying => "carrying",
        Role::Standby => "standby",
        Role::Unusable => "unavailable",
    }
}

fn quality_label(quality: Quality) -> &'static str {
    match quality {
        Quality::Good => "good",
        Quality::Poor => "poor",
        Quality::Unusable => "very poor",
    }
}

/// How long ago a reading was, for a sentence.
fn age(seconds: u64) -> String {
    match seconds {
        0..=1 => "just now".to_string(),
        2..=119 => format!("{seconds} s ago"),
        _ => format!("{} min ago", seconds / 60),
    }
}

/// Why the connection stays on a poor network, as the service names it.
fn staying_words(staying: &str) -> &'static str {
    match staying {
        "OnlyPath" => "it is the only network available, so there is nothing to switch to",
        "NoBetterPath" => "the other networks are no better",
        "Proving" => "a better network exists but has not yet proven stable",
        "Dwell" => "the connection was moved a moment ago and waits before moving again",
        "Budget" => "the limit on moves in ten minutes has been reached",
        _ => "the service gave a reason this program does not know",
    }
}

/// The `GetPaths` answer: the networks, which carries, how good each is, and whether to believe it.
///
/// `now_unix_ms` is this computer's clock. A reading older than [`STALE_AFTER_SECS`] is shown as the
/// last known, never as current.
pub fn paths(reply: &PathsReply, now_unix_ms: u64) -> String {
    let seconds = now_unix_ms.saturating_sub(reply.as_of_unix_ms) / 1000;
    let mut lines = Vec::new();
    if !reply.watching {
        lines.push(
            "Nothing is being watched: no tunnel is up, so the networks are not measured."
                .to_string(),
        );
        return lines.join("\n");
    }
    lines.push(if seconds > STALE_AFTER_SECS {
        format!(
            "Last known {} (not current: the service has not updated this for a while)",
            age(seconds)
        )
    } else {
        format!("Networks, {}", age(seconds))
    });
    if reply.paths.is_empty() {
        lines.push("No network is available.".to_string());
    } else {
        let rows: Vec<Vec<String>> = reply
            .paths
            .iter()
            .map(|p| {
                let name = match &p.name {
                    Some(name) => format!("{} ({})", plain(name), kind_label(p.kind)),
                    None => format!("{} (adapter {})", kind_label(p.kind), plain(&p.id)),
                };
                let measured = |value: Option<String>| {
                    if p.measured {
                        value.unwrap_or_else(|| "-".to_string())
                    } else {
                        "not measured".to_string()
                    }
                };
                vec![
                    name,
                    role_label(p.role).to_string(),
                    measured(p.rtt_ms.map(|ms| format!("{ms:.0} ms"))),
                    measured(p.jitter_ms.map(|ms| format!("{ms:.0} ms"))),
                    measured(p.loss.map(|l| format!("{:.1} %", l * 100.0))),
                    match (p.measured, p.typical_ms) {
                        (true, Some((lo, hi))) => format!("{lo:.0}-{hi:.0} ms"),
                        _ => "-".to_string(),
                    },
                ]
            })
            .collect();
        lines.push(table(
            &["NETWORK", "ROLE", "LATENCY", "JITTER", "LOSS", "USUALLY"],
            &rows,
        ));
    }
    if let Some(d) = &reply.degraded {
        lines.push(format!(
            "The connection is on a {} network and is staying there: {}.",
            quality_label(d.quality),
            staying_words(&d.staying)
        ));
    }
    lines.join("\n")
}

/// A length of time in words.
fn duration(seconds: u64) -> String {
    let (h, m, s) = (seconds / 3600, seconds % 3600 / 60, seconds % 60);
    match (h, m) {
        (0, 0) => format!("{s} s"),
        (0, _) => format!("{m} min {s} s"),
        _ => format!("{h} h {m} min"),
    }
}

/// The `GetStats` answer: counts of what the product did. Nothing here compares with not using it.
pub fn stats(reply: &StatsReply) -> String {
    let StatsReply::Connected {
        connected_for_s,
        network_changes,
        changes_that_drop_connections,
        method_switches,
        endpoint_switches,
        degraded_periods,
        longest_degraded_s,
    } = reply
    else {
        return "Nothing is connected, so nothing is being counted.".to_string();
    };
    let mut lines = vec![
        format!("Connected for:          {}", duration(*connected_for_s)),
        if *changes_that_drop_connections > 0 {
            format!(
                "Network changes:        {network_changes} ({changes_that_drop_connections} under a Tier 2 profile, which breaks established connections)"
            )
        } else {
            format!("Network changes:        {network_changes}")
        },
        format!("Method switches:        {method_switches}"),
        format!("Endpoint switches:      {endpoint_switches}"),
    ];
    lines.push(if *degraded_periods == 0 {
        "Poor-network periods:   0".to_string()
    } else {
        format!(
            "Poor-network periods:   {degraded_periods} (longest {})",
            duration(*longest_degraded_s)
        )
    });
    lines.push(
        "Counted on this computer since the connection came up. These are counts of what \
         happened, not a comparison with not using DNet Engine."
            .to_string(),
    );
    lines.join("\n")
}

/// The changes waiting for approval, one per line (T160). `now_ms` is the time to count the
/// minutes left from; it is given so the text can be tested.
pub fn pending(value: &Value, now_ms: u64) -> Result<String, String> {
    let waiting = value
        .get("pending")
        .and_then(Value::as_array)
        .ok_or_else(|| "the list of waiting changes is missing".to_string())?;
    if waiting.is_empty() {
        return Ok("Nothing is waiting for approval.".to_string());
    }
    let mut lines = vec![format!(
        "{} {} waiting for approval:",
        waiting.len(),
        if waiting.len() == 1 {
            "change"
        } else {
            "changes"
        }
    )];
    for item in waiting {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "a waiting change has no id".to_string())?;
        let what = item
            .get("what")
            .and_then(Value::as_str)
            .ok_or_else(|| "a waiting change does not say what it does".to_string())?;
        let expires = item
            .get("expires_unix_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| "a waiting change has no deadline".to_string())?;
        let minutes = expires.saturating_sub(now_ms).div_ceil(60_000);
        lines.push(format!(
            "  {}  {}  (dropped in {} min)",
            plain(id),
            plain(what),
            minutes
        ));
    }
    lines.push(
        "Approve one with 'dnetctl approve <id>', or drop it with 'dnetctl reject <id>'."
            .to_string(),
    );
    Ok(lines.join("\n"))
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

    // ------------------------------------------------ the networks and the session (T144)

    fn path(id: &str, name: Option<&str>, role: Role) -> dnet_ipc::netview::PathReply {
        dnet_ipc::netview::PathReply {
            id: id.into(),
            kind: Kind::Wifi,
            name: name.map(str::to_owned),
            role,
            measured: true,
            quality: Some(Quality::Good),
            rtt_ms: Some(43.2),
            jitter_ms: Some(4.1),
            loss: Some(0.023),
            trace_ms: vec![],
            typical_ms: Some((38.0, 52.0)),
        }
    }

    fn reply(paths: Vec<dnet_ipc::netview::PathReply>) -> PathsReply {
        PathsReply {
            as_of_unix_ms: 1_000_000,
            watching: true,
            paths,
            degraded: None,
        }
    }

    #[test]
    fn a_network_is_named_with_its_kind_its_role_and_what_was_measured() {
        let text = paths(
            &reply(vec![path("7", Some("Hostel-5G"), Role::Carrying)]),
            1_002_000,
        );
        assert!(text.contains("Hostel-5G (Wi-Fi)"), "{text}");
        assert!(text.contains("carrying"), "{text}");
        assert!(text.contains("43 ms"), "{text}");
        assert!(text.contains("2.3 %"), "{text}");
        assert!(text.contains("38-52 ms"), "{text}");
        assert!(text.contains("2 s ago"), "{text}");
    }

    #[test]
    fn a_network_with_no_name_is_told_apart_by_its_adapter() {
        let text = paths(
            &reply(vec![
                path("7", None, Role::Carrying),
                path("9", None, Role::Standby),
            ]),
            1_000_500,
        );
        assert!(text.contains("Wi-Fi (adapter 7)"), "{text}");
        assert!(text.contains("Wi-Fi (adapter 9)"), "{text}");
    }

    #[test]
    fn a_network_that_was_not_measured_is_not_shown_as_fine() {
        let mut p = path("9", Some("Phone"), Role::Standby);
        p.measured = false;
        p.quality = None;
        p.rtt_ms = None;
        p.jitter_ms = None;
        p.loss = None;
        p.typical_ms = None;
        let text = paths(&reply(vec![p]), 1_000_500);
        assert!(text.contains("not measured"), "{text}");
        assert!(!text.contains(" 0 ms") && !text.contains("0.0 %"), "{text}");
    }

    #[test]
    fn an_old_reading_is_called_last_known_not_current() {
        let text = paths(
            &reply(vec![path("7", Some("A"), Role::Carrying)]),
            1_000_000 + 90_000,
        );
        assert!(text.contains("Last known"), "{text}");
        assert!(text.contains("not current"), "{text}");
        let fresh = paths(
            &reply(vec![path("7", Some("A"), Role::Carrying)]),
            1_000_000 + 5_000,
        );
        assert!(!fresh.contains("Last known"), "{fresh}");
    }

    #[test]
    fn nothing_watched_is_said_plainly_and_not_as_no_networks() {
        let mut r = reply(vec![]);
        r.watching = false;
        let text = paths(&r, 1_000_000);
        assert!(text.contains("Nothing is being watched"), "{text}");
        assert!(!text.contains("No network is available"), "{text}");
        let looking = paths(&reply(vec![]), 1_000_000);
        assert!(looking.contains("No network is available"), "{looking}");
    }

    #[test]
    fn a_degradation_says_why_the_connection_stays() {
        let mut r = reply(vec![path("7", Some("A"), Role::Carrying)]);
        r.degraded = Some(dnet_ipc::netview::DegradedReply {
            path: "7".into(),
            quality: Quality::Poor,
            staying: "OnlyPath".into(),
        });
        let text = paths(&r, 1_000_000);
        assert!(text.contains("poor network and is staying there"), "{text}");
        assert!(text.contains("only network available"), "{text}");
    }

    #[test]
    fn a_hostile_name_reaches_the_terminal_as_plain_text() {
        let text = paths(
            &reply(vec![path("7", Some("Free\u{1b}[2J WiFi"), Role::Carrying)]),
            1_000_000,
        );
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }

    #[test]
    fn the_session_is_counted_without_comparing_it_with_anything() {
        let text = stats(&StatsReply::Connected {
            connected_for_s: 11_520,
            network_changes: 2,
            changes_that_drop_connections: 1,
            method_switches: 1,
            endpoint_switches: 0,
            degraded_periods: 1,
            longest_degraded_s: 6,
        });
        assert!(text.contains("3 h 12 min"), "{text}");
        assert!(text.contains("2 (1 under a Tier 2 profile"), "{text}");
        assert!(text.contains("1 (longest 6 s)"), "{text}");
        assert!(text.contains("not a comparison with not using"), "{text}");
        assert!(
            !text.contains('%'),
            "no percentage of improvement is ever invented: {text}"
        );
        assert_eq!(
            stats(&StatsReply::NotConnected),
            "Nothing is connected, so nothing is being counted."
        );
    }
}
