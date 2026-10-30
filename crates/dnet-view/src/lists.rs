//! T100 — the endpoint and rule lists, reduced to what the window shows.
//!
//! Only the fields the window draws are copied out of the service's reply, each cleaned and bounded, so an
//! extra field (or a different one from a newer service) never reaches the web view. A reply that is not the
//! shape the contract describes is an error with a reason, not an empty list: "no endpoints" and "could not
//! read the endpoints" are different things to tell a person.

use serde_json::{json, Value};

use crate::text::plain;

/// At most this many endpoints exist (contract §Configuration requests); a longer list is not a list of
/// endpoints.
const MAX_ENDPOINTS: usize = 64;
/// More rules than any real set holds.
const MAX_RULES: usize = 512;

/// The bundled connection methods (`dnet_core::catalogue`); a longer list is not that list.
const MAX_PROFILES: usize = 16;
const KINDS: [&str; 3] = ["AmneziaWg", "Hysteria2", "VlessReality"];
const TIERS: [&str; 2] = ["Tier1", "Tier2"];

const HEALTH: [&str; 4] = ["Unknown", "Healthy", "Degraded", "Unreachable"];
/// The service's own names (`dnetd::domain::reliability_name`): address and domain rules are deterministic,
/// application rules are best effort (Principle VI).
const RELIABILITY: [&str; 2] = ["Deterministic", "BestEffort"];
/// What a rule can match (`dnet_ipc::protocol::rule_wire`).
const RULE_KINDS: [&str; 6] = [
    "domain",
    "domain_suffix",
    "ip_cidr",
    "application",
    "dns_port",
    "encrypted_dns_port",
];

fn items<'a>(reply: &'a Value, key: &str, max: usize) -> Result<&'a Vec<Value>, String> {
    let list = reply.get(key).and_then(Value::as_array).ok_or_else(|| {
        format!("the service's list of {key} was not in the form this program reads")
    })?;
    if list.len() > max {
        return Err(format!(
            "the service sent more {key} than any real set holds"
        ));
    }
    Ok(list)
}

fn text<'a>(item: &'a Value, field: &str) -> Result<&'a str, String> {
    item.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("an entry had no `{field}`"))
}

/// `ListEndpoints` as the window's list.
pub fn endpoints(reply: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    for item in items(reply, "endpoints", MAX_ENDPOINTS)? {
        let health = text(item, "health")?;
        if !HEALTH.contains(&health) {
            return Err("an endpoint had a health this program does not know".to_owned());
        }
        out.push(json!({
            "id": plain(text(item, "id")?, 64),
            "label": plain(text(item, "label")?, 64),
            "address": plain(text(item, "address")?, 260),
            "enabled": item.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            "health": health,
        }));
    }
    Ok(json!({ "endpoints": out }))
}

/// `ListProfiles` as the window's list: which methods exist, their tier (measured, never intended), and
/// whether Brutal is on.
pub fn profiles(reply: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    for item in items(reply, "profiles", MAX_PROFILES)? {
        let kind = text(item, "kind")?;
        let tier = text(item, "tier")?;
        if !KINDS.contains(&kind) || !TIERS.contains(&tier) {
            return Err(
                "a connection method had a kind or tier this program does not know".to_owned(),
            );
        }
        out.push(json!({
            "id": plain(text(item, "id")?, 64),
            "kind": kind,
            "tier": tier,
            "brutal": item.get("brutal").and_then(Value::as_bool).unwrap_or(false),
        }));
    }
    Ok(json!({ "profiles": out }))
}

/// `ListRules` as the window's list, with the encrypted-name setting that rides along with it.
pub fn rules(reply: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    for item in items(reply, "rules", MAX_RULES)? {
        let reliability = text(item, "reliability")?;
        if !RELIABILITY.contains(&reliability) {
            return Err("a rule had a reliability this program does not know".to_owned());
        }
        let kind = text(item, "kind")?;
        if !RULE_KINDS.contains(&kind) {
            return Err("a rule matched something this program does not know".to_owned());
        }
        out.push(json!({
            "id": plain(text(item, "id")?, 64),
            "kind": kind,
            // A program path can be long; it is cleaned of anything that would reorder or hide text.
            "value": plain(text(item, "value")?, 260),
            "precedence": item.get("precedence").and_then(Value::as_u64)
                .ok_or_else(|| "a rule had no precedence".to_owned())?,
            "action": plain(text(item, "action")?, 32),
            "reliability": reliability,
            "builtin": item.get("builtin").and_then(Value::as_bool).unwrap_or(false),
        }));
    }
    let dns = reply
        .get("encrypted_dns")
        .and_then(Value::as_object)
        .ok_or_else(|| "the service did not report the encrypted-name setting".to_owned())?;
    Ok(json!({
        "rules": out,
        "encryptedDns": {
            "block": dns.get("block").and_then(Value::as_bool)
                .ok_or_else(|| "the encrypted-name setting had no `block`".to_owned())?,
            "needsDisclosure": dns.get("needs_disclosure").and_then(Value::as_bool).unwrap_or(false),
        },
    }))
}
