//! T112 — the diagnostic bundle (FR-035, IPC-07).
//!
//! When something goes wrong, a person needs to be able to hand someone enough to explain it. FR-035 says
//! what that is not: **the user's browsing destinations, and any credential**. A bundle that a person
//! cannot safely send is a bundle nobody sends, so what is left out matters more than what is put in.
//!
//! # Two layers, so one mistake does not leak
//!
//! 1. **By construction.** The bundle is built from typed facts, field by field. There is no pass-through of
//!    free text from a rule, a label, a network name or a credential: a rule contributes its action and how
//!    reliable it is, never its pattern; an endpoint contributes its health and where it came from, never
//!    its address or its name; a network contributes its kind and quality, never its name. Credentials are
//!    not among the facts at all.
//! 2. **By redaction.** The caller also passes the values it knows to be sensitive (every endpoint address
//!    and label, every rule pattern, every network name). Every string in the finished bundle is scanned
//!    for them, ignoring case, and any occurrence is replaced with `<removed>`. This is for the text that
//!    does pass through (a failure's `detail`, which the product composes but which could one day name
//!    something), and for the day someone adds a field without thinking.
//!
//! # What a person can opt in to
//!
//! Three things help a developer and cost privacy, so each is off by default and each is a separate choice
//! ([`Options`]): the endpoints' addresses and names, the rule patterns, and the Wi-Fi network names. Turning
//! one on adds it to the bundle *and* takes it off the redaction list, because the person asked for it.
//!
//! The bundle is bounded: lists are cut at a fixed length, so it fits an IPC reply however much is configured.

use serde_json::{json, Map, Value};

use dnet_core::endpoint::{Endpoint, EndpointOrigin};
use dnet_core::profile::ConnectionProfile;
use dnet_core::rule::RoutingRule;
use dnet_core::telemetry::{PathsSnapshot, StatsSummary};
use dnet_ipc::protocol::{StateSnapshot, Warning};

/// The shape of the bundle. Raised when a section changes meaning.
pub const BUNDLE_VERSION: u32 = 1;

/// Most entries of any list. Past this the list ends with a count of what was left out.
pub const MAX_LISTED: usize = 64;

/// What the person chose to include beyond the defaults. All off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Each endpoint's address and name.
    pub endpoint_addresses: bool,
    /// Each user rule's pattern (domain, address range or program).
    pub rule_patterns: bool,
    /// The names of Wi-Fi networks.
    pub network_names: bool,
}

/// Everything the bundle is made from, borrowed from the service.
pub struct Facts<'a> {
    pub generated_unix_ms: u64,
    pub state: &'a StateSnapshot,
    pub profiles: &'a [ConnectionProfile],
    pub endpoints: &'a [Endpoint],
    pub rules: &'a [RoutingRule],
    pub encrypted_dns: dnet_core::doh_block::Policy,
    pub paths: Option<&'a PathsSnapshot>,
    pub stats: Option<&'a StatsSummary>,
    /// Start-up recovery of a previous run's network changes succeeded.
    pub recovery_ok: bool,
    /// The saved configuration was refused at start-up.
    pub config_refused: bool,
    /// A connection orchestrator is attached.
    pub connecting_available: bool,
}

fn cut(list: Vec<Value>) -> Value {
    if list.len() <= MAX_LISTED {
        return Value::Array(list);
    }
    let left_out = list.len() - MAX_LISTED;
    let mut kept: Vec<Value> = list.into_iter().take(MAX_LISTED).collect();
    kept.push(json!({ "left_out": left_out }));
    Value::Array(kept)
}

fn name(debug: impl std::fmt::Debug) -> String {
    format!("{debug:?}")
}

/// Milliseconds to one decimal place.
fn millis(duration: std::time::Duration) -> f64 {
    (duration.as_secs_f64() * 10_000.0).round() / 10.0
}

/// The posture in words: whether traffic is being carried, and at which tier.
fn posture(state: &StateSnapshot) -> String {
    match state.posture {
        dnet_core::posture::RoutingPosture::FailClosed => "FailClosed".to_owned(),
        dnet_core::posture::RoutingPosture::Tunnelled { tier } => format!("Tunnelled({tier:?})"),
    }
}

fn warning(w: Warning) -> &'static str {
    match w {
        Warning::Tier2ProfileActive => "Tier2ProfileActive",
        Warning::BrutalEnabled => "BrutalEnabled",
        Warning::EncryptedDnsOverridden => "EncryptedDnsOverridden",
    }
}

/// The failure, as a name. Its `detail` (for an invalid configuration) is composed by the product, not
/// taken from the network, but it is still text, so it is kept and goes through redaction like the rest.
fn failure(state: &StateSnapshot) -> Value {
    use dnet_core::session::FailureCause as F;
    match &state.failure {
        None => Value::Null,
        Some(F::ConfigurationInvalid { detail }) => {
            json!({ "cause": "ConfigurationInvalid", "detail": detail })
        }
        Some(F::CoreFailedPersistently { core }) => {
            json!({ "cause": "CoreFailedPersistently", "core": name(core) })
        }
        Some(other) => json!({ "cause": name(other) }),
    }
}

fn endpoint(e: &Endpoint, options: Options) -> Value {
    let mut entry = Map::new();
    entry.insert("id".into(), json!(e.id().to_string()));
    entry.insert("enabled".into(), json!(e.is_enabled()));
    entry.insert("health".into(), json!(name(e.health().state)));
    let (origin, resources) = match e.origin() {
        EndpointOrigin::Manual => ("Manual", 0),
        EndpointOrigin::Provisioned { resource_ids, .. } => ("Provisioned", resource_ids.len()),
    };
    entry.insert("origin".into(), json!(origin));
    entry.insert("cloud_resources".into(), json!(resources));
    if options.endpoint_addresses {
        entry.insert("address".into(), json!(e.address().to_string()));
        entry.insert("label".into(), json!(e.label()));
    }
    Value::Object(entry)
}

fn rule(r: &RoutingRule, options: Options) -> Value {
    use dnet_core::rule::RuleMatcher as M;
    let mut entry = Map::new();
    entry.insert("precedence".into(), json!(r.precedence()));
    entry.insert("action".into(), json!(name(r.action())));
    entry.insert("reliability".into(), json!(name(r.reliability())));
    entry.insert("builtin".into(), json!(r.is_builtin()));
    // Which kind of thing it matches is not a destination; what it matches is.
    entry.insert(
        "matches".into(),
        json!(match r.matcher() {
            M::Domain(_) => "Domain",
            M::DomainSuffix(_) => "DomainSuffix",
            M::IpCidr(_) => "IpCidr",
            M::Application(_) => "Application",
            M::DnsPort => "DnsPort",
            M::EncryptedDnsPort => "EncryptedDnsPort",
        }),
    );
    if options.rule_patterns && !r.is_builtin() {
        entry.insert("pattern".into(), json!(name(r.matcher())));
    }
    Value::Object(entry)
}

fn paths(snapshot: &PathsSnapshot, options: Options) -> Value {
    let list: Vec<Value> = snapshot
        .paths
        .iter()
        .map(|p| {
            let mut entry = Map::new();
            entry.insert("kind".into(), json!(name(p.kind)));
            entry.insert("role".into(), json!(name(p.role)));
            entry.insert("measured".into(), json!(p.measured));
            // An unmeasured network claims nothing: no quality and no numbers.
            if p.measured {
                entry.insert("quality".into(), json!(p.band.map(name)));
                entry.insert("rtt_ms".into(), json!(p.rtt.map(millis)));
                entry.insert("jitter_ms".into(), json!(p.jitter.map(millis)));
                entry.insert("loss".into(), json!(p.loss));
            }
            if options.network_names {
                entry.insert("name".into(), json!(p.name));
            }
            Value::Object(entry)
        })
        .collect();
    json!({
        "paths": cut(list),
        "degraded": snapshot.degradation.map(|d| json!({
            "quality": name(d.band),
            "staying": name(d.staying),
        })),
    })
}

fn stats(s: &StatsSummary) -> Value {
    json!({
        "connected_for_secs": s.connected_for.as_secs(),
        "network_changes": s.network_changes,
        "changes_that_drop_connections": s.changes_that_drop_connections,
        "method_switches": s.method_switches,
        "endpoint_switches": s.endpoint_switches,
        "degraded_periods": s.degraded_periods,
        "longest_degraded_secs": s.longest_degraded.as_secs(),
    })
}

/// Build the bundle from `facts`, with the sensitive extras `options` allows.
pub fn build(facts: &Facts<'_>, options: Options) -> Value {
    let rule_counts = {
        let mut by_action: std::collections::BTreeMap<String, usize> = Default::default();
        for r in facts.rules {
            *by_action.entry(name(r.action())).or_default() += 1;
        }
        json!({
            "total": facts.rules.len(),
            "builtin": facts.rules.iter().filter(|r| r.is_builtin()).count(),
            "user": facts.rules.iter().filter(|r| !r.is_builtin()).count(),
            "best_effort": facts
                .rules
                .iter()
                .filter(|r| r.reliability() == dnet_core::rule::Reliability::BestEffort)
                .count(),
            "by_action": by_action,
        })
    };
    json!({
        "bundle_version": BUNDLE_VERSION,
        "generated_unix_ms": facts.generated_unix_ms,
        "product_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": dnet_ipc::version::PROTOCOL_VERSION,
        "service": {
            "recovery": if facts.recovery_ok { "ok" } else { "failed" },
            "configuration": if facts.config_refused { "refused" } else { "ok" },
            "connecting_available": facts.connecting_available,
        },
        "connection": {
            "status": name(facts.state.status),
            "posture": posture(facts.state),
            "active_profile": facts.state.active_profile.as_ref().map(|p| json!({
                "id": p.id, "kind": p.kind, "tier": name(p.tier),
            })),
            "active_endpoint": facts.state.active_endpoint.as_ref().map(|e| json!({ "id": e.id })),
            "failure": failure(facts.state),
            "warnings": facts.state.warnings.iter().copied().map(warning).collect::<Vec<_>>(),
        },
        "profiles": cut(facts.profiles.iter().map(|p| json!({
            "id": p.id().as_str(),
            "kind": name(p.kind()),
            "tier": name(p.tier()),
        })).collect()),
        "endpoints": cut(facts.endpoints.iter().map(|e| endpoint(e, options)).collect()),
        "rules": {
            "counts": rule_counts,
            "list": cut(facts.rules.iter().map(|r| rule(r, options)).collect()),
        },
        "encrypted_dns": match facts.encrypted_dns {
            dnet_core::doh_block::Policy::Block => "blocked",
            dnet_core::doh_block::Policy::Allow => "allowed",
        },
        "networks": facts.paths.map(|p| paths(p, options)),
        "session": facts.stats.map(stats),
    })
}

/// The values that must not appear in a bundle: everything sensitive the service knows, **minus** whatever
/// the person opted in to. Entries shorter than three characters are ignored (they would mangle ordinary
/// words and identify nothing). Longest first, so a longer value is removed whole before a shorter one
/// inside it.
pub fn sensitive_values(facts: &Facts<'_>, options: Options) -> Vec<String> {
    let mut values = Vec::new();
    if !options.endpoint_addresses {
        for e in facts.endpoints {
            values.push(e.address().host().to_owned());
            values.push(e.address().to_string());
            values.push(e.label().to_owned());
        }
    }
    if !options.rule_patterns {
        use dnet_core::rule::RuleMatcher as M;
        for r in facts.rules.iter().filter(|r| !r.is_builtin()) {
            match r.matcher() {
                M::Domain(p) | M::DomainSuffix(p) | M::Application(p) => values.push(p.clone()),
                M::IpCidr(c) => {
                    values.push(c.to_string());
                    values.push(c.addr().to_string());
                }
                M::DnsPort | M::EncryptedDnsPort => {}
            }
        }
    }
    if !options.network_names {
        if let Some(paths) = facts.paths {
            values.extend(paths.paths.iter().filter_map(|p| p.name.clone()));
        }
    }
    values.retain(|v| v.chars().count() >= 3);
    values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    values.dedup();
    values
}

/// `text` with every occurrence of any of `values` replaced by `<removed>`. ASCII values match ignoring
/// case; others must match exactly.
fn scrub(text: &str, values: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    'next: while at < text.len() {
        for value in values {
            if let Some(chunk) = text.get(at..at + value.len()) {
                let hit = if value.is_ascii() {
                    chunk.eq_ignore_ascii_case(value)
                } else {
                    chunk == value
                };
                if hit {
                    out.push_str("<removed>");
                    at += value.len();
                    continue 'next;
                }
            }
        }
        let c = text[at..].chars().next().expect("at is inside the text");
        out.push(c);
        at += c.len_utf8();
    }
    out
}

fn redact(value: &mut Value, values: &[String]) {
    match value {
        Value::String(s) => *s = scrub(s, values),
        Value::Array(items) => items.iter_mut().for_each(|v| redact(v, values)),
        Value::Object(map) => map.values_mut().for_each(|v| redact(v, values)),
        _ => {}
    }
}

/// The finished bundle as text: built, redacted of everything sensitive, and checked. Keys are fixed words
/// and never carry data, so only values are scrubbed.
pub fn render(facts: &Facts<'_>, options: Options) -> String {
    let mut bundle = build(facts, options);
    let values = sensitive_values(facts, options);
    redact(&mut bundle, &values);
    let text = bundle.to_string();
    // A second look at the finished text. A leak here is a defect in the redaction itself, and the bundle
    // is not sent: better an honest refusal than a bundle that leaks.
    let lower = text.to_lowercase();
    if values.iter().any(|v| lower.contains(&v.to_lowercase())) {
        return json!({
            "bundle_version": BUNDLE_VERSION,
            "error": "the diagnostic bundle could not be made safely",
        })
        .to_string();
    }
    text
}

#[cfg(test)]
mod tests;

/// What the mutation run showed the bundle's own tests did not pin: the redaction pass on its own (not only the
/// refusal that follows it), the units, the cut of a long list, and the words used for warnings.
#[cfg(test)]
mod pinned_tests {
    use super::*;
    use std::time::Duration;

    fn values() -> Vec<String> {
        vec!["secret".to_owned()]
    }

    #[test]
    fn the_redaction_pass_reaches_into_lists_and_nested_lists_and_objects() {
        let mut bundle = json!({
            "list": ["has a secret in it", "fine"],
            "nested": [["deep SECRET"], [[ "deeper secret" ]]],
            "object": { "inner": ["a secret", { "again": "secret" }] },
            "number": 7,
            "flag": true,
            "nothing": null,
        });
        redact(&mut bundle, &values());
        let text = bundle.to_string().to_lowercase();
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(bundle["list"][0], "has a <removed> in it");
        assert_eq!(bundle["list"][1], "fine");
        assert_eq!(bundle["nested"][0][0], "deep <removed>");
        assert_eq!(bundle["nested"][1][0][0], "deeper <removed>");
        assert_eq!(bundle["object"]["inner"][0], "a <removed>");
        assert_eq!(bundle["object"]["inner"][1]["again"], "<removed>");
        // What is not text is left as it was.
        assert_eq!(bundle["number"], 7);
        assert_eq!(bundle["flag"], true);
        assert!(bundle["nothing"].is_null());
    }

    #[test]
    fn a_value_is_found_ignoring_case_when_it_is_ascii_and_exactly_when_it_is_not() {
        assert_eq!(scrub("A SeCrEt here", &values()), "A <removed> here");
        assert_eq!(scrub("secretsecret", &values()), "<removed><removed>");
        let names = vec!["Zürich".to_owned()];
        assert_eq!(scrub("in Zürich today", &names), "in <removed> today");
        assert_eq!(scrub("in zürich today", &names), "in zürich today");
        assert_eq!(scrub("nothing to hide", &values()), "nothing to hide");
        assert_eq!(scrub("", &values()), "");
    }

    #[test]
    fn a_list_is_kept_whole_up_to_the_limit_and_cut_with_a_count_past_it() {
        let make = |n: usize| (0..n).map(|i| json!(i)).collect::<Vec<_>>();
        let at_limit = cut(make(MAX_LISTED));
        assert_eq!(at_limit.as_array().unwrap().len(), MAX_LISTED);
        assert!(at_limit.as_array().unwrap().iter().all(Value::is_number));
        let past = cut(make(MAX_LISTED + 1));
        let items = past.as_array().unwrap();
        assert_eq!(items.len(), MAX_LISTED + 1);
        assert_eq!(items[MAX_LISTED], json!({ "left_out": 1 }));
        let far_past = cut(make(MAX_LISTED + 30));
        assert_eq!(
            far_past.as_array().unwrap()[MAX_LISTED],
            json!({ "left_out": 30 })
        );
        assert_eq!(cut(Vec::new()), json!([]));
    }

    #[test]
    fn times_are_milliseconds_to_one_decimal_place() {
        assert_eq!(millis(Duration::from_millis(1500)), 1500.0);
        assert_eq!(millis(Duration::from_micros(1234)), 1.2);
        assert_eq!(millis(Duration::from_micros(1250)), 1.3);
        assert_eq!(millis(Duration::from_secs(2)), 2000.0);
        assert_eq!(millis(Duration::from_micros(40)), 0.0);
        assert_eq!(millis(Duration::from_micros(60)), 0.1);
        assert_eq!(millis(Duration::ZERO), 0.0);
    }

    #[test]
    fn each_warning_has_its_own_plain_name() {
        let names = [
            (Warning::Tier2ProfileActive, "Tier2ProfileActive"),
            (Warning::BrutalEnabled, "BrutalEnabled"),
            (Warning::EncryptedDnsOverridden, "EncryptedDnsOverridden"),
        ];
        for (warning_value, expected) in names {
            assert_eq!(warning(warning_value), expected);
        }
    }
}
