// SPDX-License-Identifier: GPL-3.0-or-later
//! T170 — the wire form of `GetComponents`: every part of the connection, as the interface shows it.
//!
//! The service writes a reply with [`encode_components`]; a client reads it with [`decode_components`]. Like every
//! client-side decoder in this crate the decoder is strict, because the other end of the pipe is not trusted: a
//! reply that is malformed, out of range, contradicts itself or is absurdly large is refused, not shown.
//!
//! - **Words are kept whole.** A reason is the part's own account and is never cut. Hostile characters (controls
//!   and the ones that reorder or hide text) are removed on both ends; a reason that is still too long is refused
//!   by the decoder, because cutting it would change what it says.
//! - **Times are ages, not clocks.** `changed_ago_ms` is how long before `as_of_unix_ms` the part's state last
//!   changed, so a client needs no agreement with the service about the time of day.
//! - **Nothing here names a person's things.** The service never puts an endpoint's label or address or a network's
//!   name into a reading; the ids are opaque. A reply carries no field that could.
//! - **Bounded.** At most [`MAX_COMPONENTS`] parts, each id at most [`MAX_ID_CHARS`] characters and each reason at
//!   most [`MAX_REASON_CHARS`], so a full reply is far below a frame.

use std::collections::HashSet;
use std::time::Duration;

use dnet_core::registry::{roll_up, Component, ComponentKind, ComponentState, Evidence};
use serde_json::{json, Map, Value};

use crate::netview::is_hostile;
use crate::protocol::IpcError;

pub use dnet_core::registry::MAX_COMPONENTS;

/// Longest id kept, in characters. Ids are opaque (`interface-123`, an endpoint's id).
pub const MAX_ID_CHARS: usize = 64;
/// Longest reason accepted, in characters. The service's own sentences are well under this.
pub const MAX_REASON_CHARS: usize = 512;

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
}

pub fn kind_str(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::NetworkPath => "NetworkPath",
        ComponentKind::CarrierLeaf => "CarrierLeaf",
        ComponentKind::Session => "Session",
        ComponentKind::Endpoint => "Endpoint",
        ComponentKind::CoreProcess => "CoreProcess",
        ComponentKind::Adapter => "Adapter",
        ComponentKind::Routes => "Routes",
        ComponentKind::DnsHandling => "DnsHandling",
        ComponentKind::Guard => "Guard",
        ComponentKind::CaptivePortal => "CaptivePortal",
    }
}

fn parse_kind(text: &str) -> Result<ComponentKind, IpcError> {
    Ok(match text {
        "NetworkPath" => ComponentKind::NetworkPath,
        "CarrierLeaf" => ComponentKind::CarrierLeaf,
        "Session" => ComponentKind::Session,
        "Endpoint" => ComponentKind::Endpoint,
        "CoreProcess" => ComponentKind::CoreProcess,
        "Adapter" => ComponentKind::Adapter,
        "Routes" => ComponentKind::Routes,
        "DnsHandling" => ComponentKind::DnsHandling,
        "Guard" => ComponentKind::Guard,
        "CaptivePortal" => ComponentKind::CaptivePortal,
        _ => return Err(invalid("a component has an unknown kind")),
    })
}

pub fn state_str(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Unknown => "Unknown",
        ComponentState::Off => "Off",
        ComponentState::Starting => "Starting",
        ComponentState::Ok => "Ok",
        ComponentState::Degraded => "Degraded",
        ComponentState::Blocked => "Blocked",
        ComponentState::Failed => "Failed",
    }
}

fn parse_state(text: &str) -> Result<ComponentState, IpcError> {
    Ok(match text {
        "Unknown" => ComponentState::Unknown,
        "Off" => ComponentState::Off,
        "Starting" => ComponentState::Starting,
        "Ok" => ComponentState::Ok,
        "Degraded" => ComponentState::Degraded,
        "Blocked" => ComponentState::Blocked,
        "Failed" => ComponentState::Failed,
        _ => return Err(invalid("a state is not a known one")),
    })
}

/// Hostile characters removed and the ends trimmed. Never shortened.
fn clean(raw: &str) -> String {
    raw.chars()
        .filter(|c| !is_hostile(*c))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Whether an id and a reason (already cleaned) are within what a decoder accepts.
fn fits(id: &str, reason: &str) -> bool {
    !id.is_empty()
        && id.chars().count() <= MAX_ID_CHARS
        && reason.chars().count() <= MAX_REASON_CHARS
}

/// One part, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentReply {
    pub kind: ComponentKind,
    pub id: String,
    pub state: ComponentState,
    pub reason: String,
    /// How long before `as_of_unix_ms` the state last changed.
    pub changed_ago_ms: u64,
    pub evidence: Evidence,
}

/// The reply to `GetComponents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentsReply {
    /// When this was true, as milliseconds since the Unix epoch. A client older than a few seconds by its own clock
    /// must not present it as current.
    pub as_of_unix_ms: u64,
    /// The one state that stands for all the parts (the worst, `dnet_core::registry`).
    pub overall: ComponentState,
    pub components: Vec<ComponentReply>,
}

/// Write a `GetComponents` reply. `now` is the time on the clock the parts' `changed_at` were taken from.
///
/// The summary (`overall`) is worked out here from the parts that are written, never passed in, so it cannot disagree
/// with them. A part the decoder would refuse (an id that is empty once cleaned or too long, a reason too long) is left
/// out rather than written: one odd part must not make a client refuse the whole reply.
pub fn encode_components(parts: &[Component], now: Duration, as_of_unix_ms: u64) -> String {
    let written: Vec<&Component> = parts
        .iter()
        .filter(|c| fits(&clean(&c.id), &clean(&c.reason)))
        .take(MAX_COMPONENTS)
        .collect();
    let overall = roll_up(written.iter().map(|c| c.state));
    let list: Vec<Value> = written
        .iter()
        .map(|c| {
            json!({
                "kind": kind_str(c.kind),
                "id": clean(&c.id),
                "state": state_str(c.state),
                "reason": clean(&c.reason),
                "changed_ago_ms": u64::try_from(now.saturating_sub(c.changed_at).as_millis()).unwrap_or(u64::MAX),
                "latency_ms": c.evidence.latency_ms,
                "loss_permille": c.evidence.loss_permille,
                "restarts": c.evidence.restarts,
            })
        })
        .collect();
    json!({
        "as_of_unix_ms": as_of_unix_ms,
        "overall": state_str(overall),
        "components": list,
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

/// A number that may be absent or null, and must fit `max` when present.
fn optional(o: &Map<String, Value>, key: &str, max: u64) -> Result<Option<u64>, IpcError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| invalid(format!("`{key}` is not a whole number")))?;
            if n > max {
                return Err(invalid(format!("`{key}` is out of range")));
            }
            Ok(Some(n))
        }
    }
}

/// Read a `GetComponents` reply as untrusted input.
pub fn decode_components(wire: &str) -> Result<ComponentsReply, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let o = object(&value, "the reply")?;
    let as_of_unix_ms = o
        .get("as_of_unix_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("`as_of_unix_ms` is missing or not a number"))?;
    let overall = parse_state(text(o, "overall")?)?;
    let list = o
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("`components` is missing or not a list"))?;
    if list.len() > MAX_COMPONENTS {
        return Err(invalid("too many components"));
    }
    let mut seen = HashSet::new();
    let mut components = Vec::with_capacity(list.len());
    for entry in list {
        let c = decode_component(object(entry, "a component")?)?;
        if !seen.insert((c.kind, c.id.clone())) {
            return Err(invalid("a component is listed twice"));
        }
        components.push(c);
    }
    // The summary is a claim about the parts, so it is checked against them: a reply that says Ok over a Failed part,
    // or Ok over no parts at all, contradicts itself, and the client must not choose which half to believe.
    if overall != roll_up(components.iter().map(|c| c.state)) {
        return Err(invalid("the overall state does not match the parts"));
    }
    Ok(ComponentsReply {
        as_of_unix_ms,
        overall,
        components,
    })
}

fn decode_component(o: &Map<String, Value>) -> Result<ComponentReply, IpcError> {
    let kind = parse_kind(text(o, "kind")?)?;
    let id = clean(text(o, "id")?);
    if id.is_empty() || id.chars().count() > MAX_ID_CHARS {
        return Err(invalid("a component has an empty or over-long id"));
    }
    let state = parse_state(text(o, "state")?)?;
    let reason = clean(text(o, "reason")?);
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(invalid("a reason is too long"));
    }
    let changed_ago_ms = o
        .get("changed_ago_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("`changed_ago_ms` is missing or not a number"))?;
    Ok(ComponentReply {
        kind,
        id,
        state,
        reason,
        changed_ago_ms,
        evidence: Evidence {
            latency_ms: optional(o, "latency_ms", u64::from(u32::MAX))?.map(|n| n as u32),
            loss_permille: optional(o, "loss_permille", 1000)?.map(|n| n as u16),
            restarts: optional(o, "restarts", u64::from(u32::MAX))?.map(|n| n as u32),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::MAX_FRAME_LEN;

    fn part(
        kind: ComponentKind,
        id: &str,
        state: ComponentState,
        reason: &str,
        at: u64,
    ) -> Component {
        Component {
            kind,
            id: id.to_owned(),
            state,
            reason: reason.to_owned(),
            changed_at: Duration::from_secs(at),
            evidence: Evidence::default(),
        }
    }

    const NOW: Duration = Duration::from_secs(100);

    fn one_good() -> Vec<Component> {
        vec![part(
            ComponentKind::Session,
            "connection",
            ComponentState::Ok,
            "Connected",
            40,
        )]
    }

    #[test]
    fn a_reply_round_trips() {
        let mut p = part(
            ComponentKind::NetworkPath,
            "interface-7",
            ComponentState::Degraded,
            "Wi-Fi: lossy",
            90,
        );
        p.evidence = Evidence {
            latency_ms: Some(95),
            loss_permille: Some(34),
            restarts: Some(2),
        };
        let parts = vec![one_good().remove(0), p];
        let reply = decode_components(&encode_components(&parts, NOW, 1234)).unwrap();
        assert_eq!(reply.as_of_unix_ms, 1234);
        assert_eq!(reply.overall, ComponentState::Degraded);
        assert_eq!(reply.components.len(), 2);
        let c = &reply.components[0];
        assert_eq!(
            (c.kind, c.id.as_str(), c.state),
            (ComponentKind::Session, "connection", ComponentState::Ok)
        );
        assert_eq!(c.reason, "Connected");
        assert_eq!(c.changed_ago_ms, 60_000);
        assert_eq!(c.evidence, Evidence::default());
        assert_eq!(reply.components[1].evidence, parts[1].evidence);
        assert_eq!(reply.components[1].changed_ago_ms, 10_000);
    }

    #[test]
    fn an_age_never_goes_negative() {
        let parts = vec![part(ComponentKind::Guard, "g", ComponentState::Ok, "", 500)];
        let reply = decode_components(&encode_components(&parts, NOW, 1)).unwrap();
        assert_eq!(reply.components[0].changed_ago_ms, 0);
    }

    #[test]
    fn hostile_characters_are_removed_on_both_ends_and_nothing_is_cut() {
        let long = "word ".repeat(80); // 400 characters: long, but a real sentence is kept whole
        let parts = vec![part(
            ComponentKind::Session,
            "conn\u{202e}ection",
            ComponentState::Failed,
            &format!("  bad\u{202e}\u{0007} {long}  "),
            1,
        )];
        let wire = encode_components(&parts, NOW, 1);
        assert!(!wire.contains('\u{202e}'));
        let c = &decode_components(&wire).unwrap().components[0];
        assert_eq!(c.id, "connection");
        assert!(c.reason.starts_with("bad word"), "{}", c.reason);
        assert!(c.reason.ends_with("word"), "the tail is kept: {}", c.reason);
    }

    #[test]
    fn a_decoder_cleans_what_a_hostile_service_sends() {
        let wire = json!({"as_of_unix_ms": 1, "overall": "Ok", "components": [
            {"kind": "Session", "id": "a\u{202e}b", "state": "Ok", "reason": "x\u{2066}y", "changed_ago_ms": 1}
        ]})
        .to_string();
        let c = &decode_components(&wire).unwrap().components[0];
        assert_eq!((c.id.as_str(), c.reason.as_str()), ("ab", "xy"));
    }

    fn base() -> Value {
        json!({"as_of_unix_ms": 1, "overall": "Ok", "components": [
            {"kind": "Session", "id": "connection", "state": "Ok", "reason": "Connected", "changed_ago_ms": 5,
             "latency_ms": null, "loss_permille": null, "restarts": null}
        ]})
    }

    fn with(mutate: impl FnOnce(&mut Value)) -> String {
        let mut v = base();
        mutate(&mut v);
        v.to_string()
    }

    #[test]
    fn a_good_base_is_accepted_so_the_refusals_below_mean_something() {
        assert!(decode_components(&base().to_string()).is_ok());
    }

    #[test]
    fn malformed_or_contradictory_replies_are_refused() {
        let cases: Vec<(&str, String)> = vec![
            ("not json", "nope".to_owned()),
            ("not an object", "[]".to_owned()),
            (
                "no time",
                with(|v| {
                    v.as_object_mut().unwrap().remove("as_of_unix_ms");
                }),
            ),
            ("overall unknown", with(|v| v["overall"] = json!("Fine"))),
            (
                "components not a list",
                with(|v| v["components"] = json!({})),
            ),
            (
                "kind unknown",
                with(|v| v["components"][0]["kind"] = json!("Toaster")),
            ),
            (
                "state unknown",
                with(|v| v["components"][0]["state"] = json!("Great")),
            ),
            ("empty id", with(|v| v["components"][0]["id"] = json!(""))),
            (
                "id only hostile",
                with(|v| v["components"][0]["id"] = json!("\u{202e}")),
            ),
            (
                "long id",
                with(|v| v["components"][0]["id"] = json!("x".repeat(MAX_ID_CHARS + 1))),
            ),
            (
                "long reason",
                with(|v| v["components"][0]["reason"] = json!("x".repeat(MAX_REASON_CHARS + 1))),
            ),
            (
                "age negative",
                with(|v| v["components"][0]["changed_ago_ms"] = json!(-1)),
            ),
            (
                "age missing",
                with(|v| {
                    v["components"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("changed_ago_ms");
                }),
            ),
            (
                "loss above 100%",
                with(|v| v["components"][0]["loss_permille"] = json!(1001)),
            ),
            (
                "latency not a number",
                with(|v| v["components"][0]["latency_ms"] = json!("fast")),
            ),
            (
                "restarts huge",
                with(|v| v["components"][0]["restarts"] = json!(u64::MAX)),
            ),
            (
                "duplicate part",
                with(|v| {
                    let c = v["components"][0].clone();
                    v["components"].as_array_mut().unwrap().push(c);
                }),
            ),
        ];
        for (what, wire) in cases {
            assert!(
                matches!(
                    decode_components(&wire),
                    Err(IpcError::InvalidRequest { .. })
                ),
                "{what} must be refused"
            );
        }
    }

    #[test]
    fn the_summary_is_worked_out_from_the_parts_that_are_written() {
        let parts = vec![
            part(
                ComponentKind::Session,
                "connection",
                ComponentState::Ok,
                "up",
                1,
            ),
            part(
                ComponentKind::Routes,
                "posture",
                ComponentState::Blocked,
                "dropped",
                1,
            ),
        ];
        let reply = decode_components(&encode_components(&parts, NOW, 1)).unwrap();
        assert_eq!(reply.overall, ComponentState::Blocked);
        let none = decode_components(&encode_components(&[], NOW, 1)).unwrap();
        assert_eq!(
            none.overall,
            ComponentState::Unknown,
            "no parts is not fine"
        );
    }

    #[test]
    fn a_summary_that_does_not_match_the_parts_is_refused() {
        // A service (or something pretending to be one) saying Ok over a Failed part.
        let lie = with(|v| v["components"][0]["state"] = json!("Failed"));
        assert!(matches!(
            decode_components(&lie),
            Err(IpcError::InvalidRequest { .. })
        ));
        // "Ok" over no parts at all.
        let none = with(|v| v["components"] = json!([]));
        assert!(decode_components(&none).is_err());
    }

    #[test]
    fn a_part_the_decoder_would_refuse_is_left_out_so_one_odd_part_cannot_spoil_the_reply() {
        let parts = vec![
            part(
                ComponentKind::Session,
                "connection",
                ComponentState::Ok,
                "up",
                1,
            ),
            part(
                ComponentKind::Guard,
                "\u{202e}",
                ComponentState::Failed,
                "id cleans to nothing",
                1,
            ),
            part(
                ComponentKind::Endpoint,
                "e",
                ComponentState::Failed,
                &"x".repeat(MAX_REASON_CHARS + 1),
                1,
            ),
            part(
                ComponentKind::NetworkPath,
                &"y".repeat(MAX_ID_CHARS + 1),
                ComponentState::Failed,
                "long id",
                1,
            ),
        ];
        let reply = decode_components(&encode_components(&parts, NOW, 1))
            .expect("the reply is still one a client can read");
        assert_eq!(reply.components.len(), 1);
        assert_eq!(reply.components[0].id, "connection");
        assert_eq!(
            reply.overall,
            ComponentState::Ok,
            "the summary covers what is written, so it always matches"
        );
    }

    #[test]
    fn the_same_id_under_two_kinds_is_not_a_duplicate() {
        let wire = with(|v| {
            let mut other = v["components"][0].clone();
            other["kind"] = json!("Endpoint");
            v["components"].as_array_mut().unwrap().push(other);
        });
        assert_eq!(decode_components(&wire).unwrap().components.len(), 2);
    }

    #[test]
    fn more_than_the_limit_is_refused_and_exactly_the_limit_is_accepted() {
        let many = |n: usize| {
            // The encoder stops at the limit, so the over-limit reply is built by hand.
            let entries: Vec<Value> = (0..n)
                .map(|i| json!({"kind": "NetworkPath", "id": format!("interface-{i}"), "state": "Ok", "reason": "up", "changed_ago_ms": 1}))
                .collect();
            json!({"as_of_unix_ms": 1, "overall": "Ok", "components": entries}).to_string()
        };
        assert!(decode_components(&many(MAX_COMPONENTS)).is_ok());
        assert!(decode_components(&many(MAX_COMPONENTS + 1)).is_err());
    }

    #[test]
    fn the_encoder_never_writes_more_than_the_limit() {
        let parts: Vec<_> = (0..MAX_COMPONENTS + 20)
            .map(|i| {
                part(
                    ComponentKind::NetworkPath,
                    &format!("interface-{i}"),
                    ComponentState::Ok,
                    "up",
                    1,
                )
            })
            .collect();
        let reply = decode_components(&encode_components(&parts, NOW, 1)).unwrap();
        assert_eq!(reply.components.len(), MAX_COMPONENTS);
    }

    #[test]
    fn the_largest_possible_reply_fits_in_a_frame_with_room_to_spare() {
        let reason = "x".repeat(MAX_REASON_CHARS);
        let parts: Vec<_> = (0..MAX_COMPONENTS)
            .map(|i| {
                let mut id = format!("{i:0>width$}", width = MAX_ID_CHARS);
                id.truncate(MAX_ID_CHARS);
                part(
                    ComponentKind::NetworkPath,
                    &id,
                    ComponentState::Ok,
                    &reason,
                    1,
                )
            })
            .collect();
        let wire = encode_components(&parts, NOW, 1);
        assert!(wire.len() < MAX_FRAME_LEN / 4, "{} bytes", wire.len());
    }
}
