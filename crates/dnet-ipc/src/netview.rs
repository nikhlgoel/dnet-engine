//! T144 — the wire form of `GetPaths` and `GetStats`: the networks as the interface shows them, and
//! what the product did during the connection.
//!
//! Both halves live here: the service writes a reply with [`encode_paths`] and [`encode_stats`], and
//! a client reads it with [`decode_paths`] and [`decode_stats`]. The decoders are strict, like every
//! client-side decoder in this crate, because the other end of the pipe is not trusted: a reply that
//! is malformed, out of range or absurdly large is refused, not shown.
//!
//! - **A network's name is untrusted text.** It is chosen by whoever runs the access point. Both
//!   ends clean it ([`clean_name`]): control and bidirectional-override characters removed,
//!   whitespace trimmed, length capped, and nothing at all (`null`) if nothing is left.
//! - **Nothing is claimed that was not measured.** A network that has no recent measurement carries
//!   `measured: false` and `null` for its quality, latency, jitter and loss. A client must not read
//!   `null` as "fine".
//! - **Interface ids are decimal strings,** like the ids in events: a JSON number loses bits above
//!   2^53.

use dnet_core::path::{PathKind, PathRole};
use dnet_core::quality::QualityBand;
use dnet_core::telemetry::{PathsSnapshot, StatsSummary};
use serde_json::{json, Map, Value};

use crate::protocol::IpcError;

/// Most networks a reply may list.
pub const MAX_PATHS: usize = 32;
/// Most readings in one trace.
pub const MAX_TRACE: usize = 64;
/// Longest network name kept, in characters (a Wi-Fi name is at most 32 bytes; this leaves room for
/// multi-byte names and for what a driver appends).
pub const MAX_NAME_CHARS: usize = 64;

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
}

/// Characters that must never reach a screen from a peer: controls, and the characters that reorder
/// or hide text.
pub(crate) fn is_hostile(c: char) -> bool {
    c.is_control()
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
        || matches!(
            c,
            '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{200b}'..='\u{200d}' | '\u{feff}'
        )
}

/// A network name made safe to show: hostile characters removed, trimmed, capped; `None` if empty.
pub fn clean_name(raw: &str) -> Option<String> {
    let kept: String = raw.chars().filter(|c| !is_hostile(*c)).collect();
    let kept = kept.trim();
    if kept.is_empty() {
        return None;
    }
    Some(kept.chars().take(MAX_NAME_CHARS).collect())
}

// ------------------------------------------------------------------ the networks

/// What kind of link a network is. An unknown kind from a newer service reads as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// What a network is doing for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Carrying,
    Standby,
    Unusable,
}

/// How good a measured network is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    Good,
    Poor,
    Unusable,
}

/// One network, as a client reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct PathReply {
    pub id: String,
    pub kind: Kind,
    /// The name the system gives it (for Wi-Fi, the network name), cleaned. `None` if unknown.
    pub name: Option<String>,
    pub role: Role,
    pub measured: bool,
    pub quality: Option<Quality>,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// A fraction, `0.0..=1.0`.
    pub loss: Option<f64>,
    /// Recent latencies, oldest first; `None` for a probe that was lost.
    pub trace_ms: Vec<Option<f64>>,
    /// The 10th and 90th percentile of recent latencies, once there are enough to say.
    pub typical_ms: Option<(f64, f64)>,
}

/// The connection is on a poor network and is staying on it (T084).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedReply {
    pub path: String,
    pub quality: Quality,
    /// `OnlyPath`, `NoBetterPath`, `Proving`, `Dwell` or `Budget`.
    pub staying: String,
}

/// The reply to `GetPaths`.
#[derive(Debug, Clone, PartialEq)]
pub struct PathsReply {
    /// When this was true, as milliseconds since the Unix epoch. A client older than a few seconds
    /// by its own clock must not present it as current.
    pub as_of_unix_ms: u64,
    /// Whether the networks are being watched at all. False when nothing is connected: the empty
    /// list then means "not looking", not "no networks".
    pub watching: bool,
    pub paths: Vec<PathReply>,
    pub degraded: Option<DegradedReply>,
}

fn kind_str(kind: PathKind) -> &'static str {
    match kind {
        PathKind::Wifi => "Wifi",
        PathKind::Cellular => "Cellular",
        PathKind::Ethernet => "Ethernet",
        PathKind::Other => "Other",
    }
}

fn role_str(role: PathRole) -> &'static str {
    match role {
        PathRole::Carrying => "Carrying",
        PathRole::Standby => "Standby",
        PathRole::Unusable => "Unusable",
    }
}

fn quality_str(band: QualityBand) -> &'static str {
    match band {
        QualityBand::Good => "Good",
        QualityBand::Poor => "Poor",
        QualityBand::Unusable => "Unusable",
    }
}

/// A number safe to put in JSON: finite, and rounded to a useful precision.
fn num(value: f64, decimals: i32) -> Value {
    if !value.is_finite() {
        return Value::Null;
    }
    let scale = 10f64.powi(decimals);
    json!((value * scale).round() / scale)
}

fn millis(d: std::time::Duration) -> Value {
    num(d.as_secs_f64() * 1000.0, 1)
}

/// Write a `GetPaths` reply. The name of each network is `PathView::name`, cleaned here whatever the
/// caller did.
pub fn encode_paths(snapshot: &PathsSnapshot, watching: bool, as_of_unix_ms: u64) -> String {
    let paths: Vec<Value> = snapshot
        .paths
        .iter()
        .take(MAX_PATHS)
        .map(|p| {
            json!({
                "id": p.id.luid().to_string(),
                "kind": kind_str(p.kind),
                "name": p.name.as_deref().and_then(clean_name),
                "role": role_str(p.role),
                "measured": p.measured,
                "quality": p.band.map(quality_str),
                "rtt_ms": p.rtt.map(millis).unwrap_or(Value::Null),
                "jitter_ms": p.jitter.map(millis).unwrap_or(Value::Null),
                "loss": p.loss.map(|l| num(l.clamp(0.0, 1.0), 3)).unwrap_or(Value::Null),
                "trace_ms": p.trace_ms.iter().take(MAX_TRACE)
                    .map(|r| r.map(|ms| num(f64::from(ms), 1)).unwrap_or(Value::Null))
                    .collect::<Vec<_>>(),
                "typical_ms": p.typical_ms
                    .map(|(lo, hi)| json!([num(f64::from(lo), 1), num(f64::from(hi), 1)]))
                    .unwrap_or(Value::Null),
            })
        })
        .collect();
    let degraded = snapshot.degradation.map(|d| {
        json!({
            "path": d.path.luid().to_string(),
            "quality": quality_str(d.band),
            "staying": crate::wire::staying_name(d.staying),
        })
    });
    json!({
        "as_of_unix_ms": as_of_unix_ms,
        "watching": watching,
        "paths": paths,
        "degraded": degraded,
    })
    .to_string()
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, IpcError> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} is not an object")))
}

fn text<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a str, IpcError> {
    o.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("`{key}` is missing or not text")))
}

fn optional_f64(o: &Map<String, Value>, key: &str, max: f64) -> Result<Option<f64>, IpcError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_f64()
                .filter(|n| n.is_finite() && *n >= 0.0 && *n <= max)
                .ok_or_else(|| invalid(format!("`{key}` is not a plausible number")))?;
            Ok(Some(n))
        }
    }
}

fn parse_quality(s: &str) -> Result<Quality, IpcError> {
    match s {
        "Good" => Ok(Quality::Good),
        "Poor" => Ok(Quality::Poor),
        "Unusable" => Ok(Quality::Unusable),
        _ => Err(invalid("an unknown quality")),
    }
}

/// A latency above this is not a latency: a day.
const MAX_MS: f64 = 86_400_000.0;

fn plausible_ms(v: &Value) -> Option<f64> {
    v.as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= MAX_MS)
}

/// Read a `GetPaths` reply as untrusted input.
pub fn decode_paths(wire: &str) -> Result<PathsReply, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let o = object(&value, "the reply")?;
    let as_of_unix_ms = o
        .get("as_of_unix_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("`as_of_unix_ms` is missing or not a number"))?;
    let watching = o
        .get("watching")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("`watching` is missing or not a flag"))?;
    let list = o
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("`paths` is missing or not a list"))?;
    if list.len() > MAX_PATHS {
        return Err(invalid("too many networks"));
    }
    let mut paths = Vec::with_capacity(list.len());
    for entry in list {
        paths.push(decode_path(object(entry, "a network")?)?);
    }
    if paths.iter().filter(|p| p.role == Role::Carrying).count() > 1 {
        return Err(invalid("more than one network is carrying"));
    }
    let degraded = match o.get("degraded") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let d = object(v, "`degraded`")?;
            let staying = text(d, "staying")?;
            if !["OnlyPath", "NoBetterPath", "Proving", "Dwell", "Budget"].contains(&staying) {
                return Err(invalid("`staying` is not a known reason"));
            }
            let quality = match parse_quality(text(d, "quality")?)? {
                Quality::Good => {
                    return Err(invalid("a degradation cannot be of a good network"));
                }
                q => q,
            };
            Some(DegradedReply {
                path: text(d, "path")?.to_owned(),
                quality,
                staying: staying.to_owned(),
            })
        }
    };
    Ok(PathsReply {
        as_of_unix_ms,
        watching,
        paths,
        degraded,
    })
}

fn decode_path(p: &Map<String, Value>) -> Result<PathReply, IpcError> {
    let id = text(p, "id")?;
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("a network id is not a decimal number"));
    }
    let kind = match text(p, "kind")? {
        "Wifi" => Kind::Wifi,
        "Cellular" => Kind::Cellular,
        "Ethernet" => Kind::Ethernet,
        _ => Kind::Other,
    };
    let role = match text(p, "role")? {
        "Carrying" => Role::Carrying,
        "Standby" => Role::Standby,
        "Unusable" => Role::Unusable,
        _ => return Err(invalid("a network has an unknown role")),
    };
    let measured = p
        .get("measured")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("`measured` is missing or not a flag"))?;
    let quality = match p.get("quality") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_quality(
            v.as_str().ok_or_else(|| invalid("`quality` is not text"))?,
        )?),
    };
    let rtt_ms = optional_f64(p, "rtt_ms", MAX_MS)?;
    let jitter_ms = optional_f64(p, "jitter_ms", MAX_MS)?;
    let loss = optional_f64(p, "loss", 1.0)?;
    // A network that was not measured has nothing to say about its quality: a reply that says
    // otherwise is contradicting itself, and the client must not choose which half to believe.
    if !measured && (quality.is_some() || rtt_ms.is_some() || jitter_ms.is_some() || loss.is_some())
    {
        return Err(invalid(
            "a network that was not measured reports measurements",
        ));
    }
    let trace_ms = match p.get("trace_ms") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => {
            let list = v
                .as_array()
                .ok_or_else(|| invalid("`trace_ms` is not a list"))?;
            if list.len() > MAX_TRACE {
                return Err(invalid("a trace is too long"));
            }
            list.iter()
                .map(|r| match r {
                    Value::Null => Ok(None),
                    other => plausible_ms(other)
                        .map(Some)
                        .ok_or_else(|| invalid("a reading is not a plausible latency")),
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    let typical_ms = match p.get("typical_ms") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let pair = v
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or_else(|| invalid("`typical_ms` is not a pair"))?;
            match (plausible_ms(&pair[0]), plausible_ms(&pair[1])) {
                (Some(lo), Some(hi)) if lo <= hi => Some((lo, hi)),
                _ => return Err(invalid("`typical_ms` is not a plausible range")),
            }
        }
    };
    Ok(PathReply {
        id: id.to_owned(),
        kind,
        name: p.get("name").and_then(Value::as_str).and_then(clean_name),
        role,
        measured,
        quality,
        rtt_ms,
        jitter_ms,
        loss,
        trace_ms,
        typical_ms,
    })
}

// ------------------------------------------------------------------ the session counters

/// The reply to `GetStats`.
#[derive(Debug, Clone, PartialEq)]
pub enum StatsReply {
    /// Nothing is connected, so nothing is being counted.
    NotConnected,
    Connected {
        connected_for_s: u64,
        network_changes: u32,
        changes_that_drop_connections: u32,
        method_switches: u32,
        endpoint_switches: u32,
        degraded_periods: u32,
        longest_degraded_s: u64,
    },
}

/// Write a `GetStats` reply.
pub fn encode_stats(summary: Option<StatsSummary>) -> String {
    match summary {
        None => json!({ "connected": false }).to_string(),
        Some(s) => json!({
            "connected": true,
            "connected_for_s": s.connected_for.as_secs(),
            "network_changes": s.network_changes,
            "changes_that_drop_connections": s.changes_that_drop_connections,
            "method_switches": s.method_switches,
            "endpoint_switches": s.endpoint_switches,
            "degraded_periods": s.degraded_periods,
            "longest_degraded_s": s.longest_degraded.as_secs(),
        })
        .to_string(),
    }
}

/// Read a `GetStats` reply as untrusted input.
pub fn decode_stats(wire: &str) -> Result<StatsReply, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let o = object(&value, "the reply")?;
    let connected = o
        .get("connected")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("`connected` is missing or not a flag"))?;
    if !connected {
        return Ok(StatsReply::NotConnected);
    }
    let count = |key: &str| -> Result<u32, IpcError> {
        o.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| invalid(format!("`{key}` is not a count")))
    };
    let seconds = |key: &str| -> Result<u64, IpcError> {
        // Ten years: beyond that it is not the duration of a connection.
        o.get(key)
            .and_then(Value::as_u64)
            .filter(|n| *n <= 315_360_000)
            .ok_or_else(|| invalid(format!("`{key}` is not a plausible duration")))
    };
    let connected_for_s = seconds("connected_for_s")?;
    let longest_degraded_s = seconds("longest_degraded_s")?;
    if longest_degraded_s > connected_for_s {
        return Err(invalid(
            "the longest poor period is longer than the connection",
        ));
    }
    let network_changes = count("network_changes")?;
    let changes_that_drop_connections = count("changes_that_drop_connections")?;
    if changes_that_drop_connections > network_changes {
        return Err(invalid(
            "more changes dropped connections than there were changes",
        ));
    }
    Ok(StatsReply::Connected {
        connected_for_s,
        network_changes,
        changes_that_drop_connections,
        method_switches: count("method_switches")?,
        endpoint_switches: count("endpoint_switches")?,
        degraded_periods: count("degraded_periods")?,
        longest_degraded_s,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dnet_core::degraded::{Degradation, NoMove};
    use dnet_core::ids::InterfaceId;
    use dnet_core::telemetry::PathView;

    use super::*;

    fn view(id: u64, role: PathRole, measured: bool) -> PathView {
        PathView {
            id: InterfaceId::new(id),
            kind: PathKind::Wifi,
            name: None,
            role,
            measured,
            band: measured.then_some(QualityBand::Good),
            rtt: measured.then_some(Duration::from_micros(43_250)),
            jitter: measured.then_some(Duration::from_millis(4)),
            loss: measured.then_some(0.0234),
            trace_ms: vec![Some(40.0), None, Some(45.5)],
            typical_ms: measured.then_some((38.0, 52.0)),
        }
    }

    fn snapshot() -> PathsSnapshot {
        let mut carrying = view(7, PathRole::Carrying, true);
        carrying.name = Some("Hostel-5G".to_owned());
        PathsSnapshot {
            paths: vec![carrying, view(9, PathRole::Standby, false)],
            degradation: None,
        }
    }

    fn encode(s: &PathsSnapshot) -> String {
        encode_paths(s, true, 1_700_000_000_000)
    }

    #[test]
    fn a_reply_round_trips() {
        let reply = decode_paths(&encode(&snapshot())).unwrap();
        assert_eq!(reply.as_of_unix_ms, 1_700_000_000_000);
        assert!(reply.watching);
        assert_eq!(reply.paths.len(), 2);
        let w = &reply.paths[0];
        assert_eq!(w.id, "7");
        assert_eq!(w.kind, Kind::Wifi);
        assert_eq!(w.name.as_deref(), Some("Hostel-5G"));
        assert_eq!(w.role, Role::Carrying);
        assert_eq!(w.quality, Some(Quality::Good));
        assert_eq!(w.rtt_ms, Some(43.3), "rounded to a tenth of a millisecond");
        assert_eq!(w.loss, Some(0.023));
        assert_eq!(w.trace_ms, [Some(40.0), None, Some(45.5)]);
        assert_eq!(w.typical_ms, Some((38.0, 52.0)));
        assert_eq!(reply.degraded, None);
    }

    #[test]
    fn a_network_that_was_not_measured_claims_nothing() {
        let reply = decode_paths(&encode(&snapshot())).unwrap();
        let p = &reply.paths[1];
        assert!(!p.measured);
        assert_eq!(
            (p.quality, p.rtt_ms, p.jitter_ms, p.loss),
            (None, None, None, None)
        );
        assert_eq!(p.name, None);
    }

    #[test]
    fn a_degradation_round_trips() {
        let mut s = snapshot();
        s.degradation = Some(Degradation {
            path: InterfaceId::new(7),
            band: QualityBand::Poor,
            staying: NoMove::OnlyPath,
        });
        let reply = decode_paths(&encode(&s)).unwrap();
        assert_eq!(
            reply.degraded,
            Some(DegradedReply {
                path: "7".into(),
                quality: Quality::Poor,
                staying: "OnlyPath".into()
            })
        );
    }

    #[test]
    fn a_64_bit_id_travels_as_a_decimal_string() {
        let mut s = snapshot();
        s.paths[0].id = InterfaceId::new(u64::MAX);
        let wire = encode(&s);
        assert!(wire.contains("\"18446744073709551615\""), "{wire}");
        assert_eq!(
            decode_paths(&wire).unwrap().paths[0].id,
            "18446744073709551615"
        );
    }

    // ------------------------------------------------------------------ names

    #[test]
    fn a_name_is_cleaned_on_the_way_out_and_again_on_the_way_in() {
        assert_eq!(
            clean_name("Cafe\u{1b}[31m WiFi\n").as_deref(),
            Some("Cafe[31m WiFi")
        );
        assert_eq!(clean_name("a\u{202e}b\u{2066}c").as_deref(), Some("abc"));
        assert_eq!(clean_name("   ").as_deref(), None);
        assert_eq!(clean_name("\u{1b}\u{7}").as_deref(), None);
        let long = "x".repeat(500);
        assert_eq!(clean_name(&long).unwrap().chars().count(), MAX_NAME_CHARS);

        // The service cleans a hostile name even if its caller did not ...
        let mut s = snapshot();
        s.paths[0].name = Some("Free\u{202e} WiFi".to_owned());
        assert!(!encode(&s).contains('\u{202e}'));
        // ... and a client cleans one the service did not.
        let wire = r#"{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[
            {"id":"1","kind":"Wifi","name":"Free@@ WiFi","role":"Standby","measured":false}]}"#
            .replace("@@", "\u{202e}");
        assert_eq!(
            decode_paths(&wire).unwrap().paths[0].name.as_deref(),
            Some("Free WiFi")
        );
    }

    // ------------------------------------------------------------------ a hostile or confused service

    fn path_with(extra: &str) -> String {
        format!(
            r#"{{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[
                {{"id":"1","kind":"Wifi","role":"Carrying","measured":true {extra}}}]}}"#
        )
    }

    #[test]
    fn nonsense_is_refused_not_shown() {
        for wire in [
            "",
            "[]",
            "{}",
            r#"{"as_of_unix_ms":-1,"watching":true,"paths":[]}"#,
            r#"{"as_of_unix_ms":1,"watching":"yes","paths":[]}"#,
            r#"{"as_of_unix_ms":1,"watching":true,"paths":{}}"#,
        ] {
            assert!(decode_paths(wire).is_err(), "{wire}");
        }
        for extra in [
            r#","loss":1.5"#,
            r#","loss":-0.1"#,
            r#","rtt_ms":-3"#,
            r#","rtt_ms":1e300"#,
            r#","rtt_ms":"fast""#,
            r#","quality":"Excellent""#,
            r#","trace_ms":[1,"x"]"#,
            r#","trace_ms":[-5]"#,
            r#","typical_ms":[50,10]"#,
            r#","typical_ms":[1]"#,
        ] {
            assert!(decode_paths(&path_with(extra)).is_err(), "{extra}");
        }
    }

    #[test]
    fn an_id_that_is_not_a_decimal_number_is_refused() {
        for id in ["", "abc", "1e5", "-1", "1 2", "123456789012345678901"] {
            let wire = format!(
                r#"{{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[
                {{"id":"{id}","kind":"Wifi","role":"Standby","measured":false}}]}}"#
            );
            assert!(decode_paths(&wire).is_err(), "{id:?}");
        }
    }

    #[test]
    fn an_unknown_role_is_an_error_and_an_unknown_kind_is_other() {
        let role = path_with("").replace("Carrying", "Leading");
        assert!(decode_paths(&role).is_err());
        let kind = path_with("").replace("Wifi", "Satellite");
        assert_eq!(decode_paths(&kind).unwrap().paths[0].kind, Kind::Other);
    }

    #[test]
    fn two_carrying_networks_is_a_contradiction() {
        let one = r#"{"id":"1","kind":"Wifi","role":"Carrying","measured":false}"#;
        let two = r#"{"id":"2","kind":"Wifi","role":"Carrying","measured":false}"#;
        let wire = format!(
            r#"{{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[{one},{two}]}}"#
        );
        assert!(decode_paths(&wire).is_err());
    }

    #[test]
    fn a_network_that_was_not_measured_cannot_report_measurements() {
        let wire = r#"{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[
            {"id":"1","kind":"Wifi","role":"Standby","measured":false,"loss":0.0}]}"#;
        assert!(
            decode_paths(wire).is_err(),
            "zero loss from an unmeasured network would read as fine"
        );
    }

    #[test]
    fn a_degradation_must_name_a_known_reason_and_cannot_be_good() {
        let reply =
            |d: &str| format!(r#"{{"as_of_unix_ms":1,"watching":true,"paths":[],"degraded":{d}}}"#);
        assert!(decode_paths(&reply(
            r#"{"path":"1","quality":"Poor","staying":"OnlyPath"}"#
        ))
        .is_ok());
        assert!(decode_paths(&reply(
            r#"{"path":"1","quality":"Good","staying":"OnlyPath"}"#
        ))
        .is_err());
        assert!(decode_paths(&reply(
            r#"{"path":"1","quality":"Poor","staying":"Because"}"#
        ))
        .is_err());
    }

    #[test]
    fn too_many_networks_or_too_long_a_trace_is_refused() {
        let entry = r#"{"id":"1","kind":"Wifi","role":"Standby","measured":false}"#;
        let many = vec![entry; MAX_PATHS + 1].join(",");
        let wire =
            format!(r#"{{"as_of_unix_ms":1,"watching":true,"degraded":null,"paths":[{many}]}}"#);
        assert!(decode_paths(&wire).is_err());
        let trace = vec!["1"; MAX_TRACE + 1].join(",");
        assert!(decode_paths(&path_with(&format!(r#","trace_ms":[{trace}]"#))).is_err());
    }

    #[test]
    fn the_service_never_writes_more_than_the_client_will_read() {
        let mut s = snapshot();
        s.paths = (0..100)
            .map(|n| view(n, PathRole::Standby, false))
            .collect();
        s.paths[0].trace_ms = vec![Some(1.0); 500];
        let reply = decode_paths(&encode(&s)).expect("what the encoder writes, the decoder reads");
        assert_eq!(reply.paths.len(), MAX_PATHS);
        assert!(reply.paths.iter().all(|p| p.trace_ms.len() <= MAX_TRACE));
    }

    // ------------------------------------------------------------------ stats

    fn summary() -> StatsSummary {
        StatsSummary {
            connected_for: Duration::from_secs(11_520),
            network_changes: 2,
            changes_that_drop_connections: 1,
            method_switches: 1,
            endpoint_switches: 0,
            degraded_periods: 1,
            longest_degraded: Duration::from_secs(6),
        }
    }

    #[test]
    fn stats_round_trip_and_nothing_connected_is_said_plainly() {
        assert_eq!(
            decode_stats(&encode_stats(None)).unwrap(),
            StatsReply::NotConnected
        );
        assert_eq!(
            decode_stats(&encode_stats(Some(summary()))).unwrap(),
            StatsReply::Connected {
                connected_for_s: 11_520,
                network_changes: 2,
                changes_that_drop_connections: 1,
                method_switches: 1,
                endpoint_switches: 0,
                degraded_periods: 1,
                longest_degraded_s: 6,
            }
        );
    }

    #[test]
    fn contradictory_or_absurd_stats_are_refused() {
        let base = || {
            r#"{"connected":true,"connected_for_s":100,"network_changes":2,
                "changes_that_drop_connections":1,"method_switches":0,"endpoint_switches":0,
                "degraded_periods":0,"longest_degraded_s":0}"#
                .to_owned()
        };
        assert!(decode_stats(&base()).is_ok());
        for bad in [
            base().replace("\"longest_degraded_s\":0", "\"longest_degraded_s\":500"),
            base().replace(
                "\"changes_that_drop_connections\":1",
                "\"changes_that_drop_connections\":3",
            ),
            base().replace("\"connected_for_s\":100", "\"connected_for_s\":99999999999"),
            base().replace("\"network_changes\":2", "\"network_changes\":-1"),
            base().replace("\"method_switches\":0,", ""),
            r#"{"connected":"yes"}"#.to_owned(),
            "[]".to_owned(),
        ] {
            assert!(decode_stats(&bad).is_err(), "{bad}");
        }
    }
}
