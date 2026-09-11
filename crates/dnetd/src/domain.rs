//! The daemon's in-memory domain store.
//!
//! Holds the endpoints, profiles, and rules the daemon knows about, and projects them
//! into the wire responses the IPC layer returns. The domain *entities* are pure
//! `dnet-core` types; this store is the application-level state that owns a set of
//! them and will later be backed by persisted configuration.

use dnet_core::endpoint::Endpoint;
use dnet_core::error::DomainError;
use dnet_core::health::HealthState;
use dnet_core::ids::EndpointId;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use dnet_core::rule::{builtin_bypass_rules, validate_rule_set, RoutingRule};
use serde_json::{json, Value};

/// Everything the daemon knows about endpoints, profiles, and routing.
pub struct DomainState {
    endpoints: Vec<Endpoint>,
    profiles: Vec<ConnectionProfile>,
    rules: Vec<RoutingRule>,
}

impl DomainState {
    /// A fresh store seeded with the three default profiles and the built-in bypass
    /// rules, and no endpoints (the user adds their own).
    pub fn seeded() -> Self {
        let profiles = vec![
            ConnectionProfile::new(
                ProfileId::new("awg-default"),
                ProfileKind::AmneziaWg,
                ProfileParams::new(),
            ),
            ConnectionProfile::new(
                ProfileId::new("hy2-default"),
                ProfileKind::Hysteria2,
                ProfileParams::new(),
            ),
            ConnectionProfile::new(
                ProfileId::new("reality-default"),
                ProfileKind::VlessReality,
                ProfileParams::new(),
            ),
        ];
        Self {
            endpoints: Vec::new(),
            profiles,
            rules: builtin_bypass_rules(None),
        }
    }

    // ----------------------------------------------------------- wire responses

    /// A `GetState` snapshot. The daemon does not yet establish tunnels (that lands in
    /// Phases 4–6), so it always reports `Disconnected` with no active profile.
    pub fn state_snapshot_json(&self) -> String {
        json!({
            "status": "Disconnected",
            "active_profile": Value::Null,
            "active_endpoint": Value::Null,
            "carrying_path": Value::Null,
            "warnings": [],
        })
        .to_string()
    }

    pub fn endpoints_json(&self) -> String {
        let items: Vec<Value> = self
            .endpoints
            .iter()
            .map(|e| {
                json!({
                    "id": e.id().to_string(),
                    "label": e.label(),
                    "address": e.address().to_string(),
                    "enabled": e.is_enabled(),
                    "health": health_name(e.health().state),
                })
            })
            .collect();
        json!({ "endpoints": items }).to_string()
    }

    pub fn profiles_json(&self) -> String {
        let items: Vec<Value> = self
            .profiles
            .iter()
            .map(|p| {
                json!({
                    "id": p.id().as_str(),
                    "kind": profile_kind_name(p.kind()),
                    "tier": tier_name(p.tier()),
                    "carrier": carrier_name(p.carrier()),
                    "brutal": p.brutal().is_some(),
                })
            })
            .collect();
        json!({ "profiles": items }).to_string()
    }

    pub fn rules_json(&self) -> String {
        let items: Vec<Value> = self
            .rules
            .iter()
            .map(|r| {
                json!({
                    "precedence": r.precedence(),
                    "action": rule_action_name(r.action()),
                    "reliability": reliability_name(r.reliability()),
                    "builtin": r.is_builtin(),
                })
            })
            .collect();
        json!({ "rules": items }).to_string()
    }

    /// A `GetSession` response. There is no active session until connect lands.
    pub fn session_json(&self) -> String {
        json!({ "session": Value::Null }).to_string()
    }

    #[cfg(test)]
    fn endpoint_labels(&self) -> Vec<&str> {
        self.endpoints.iter().map(Endpoint::label).collect()
    }
}

impl Default for DomainState {
    fn default() -> Self {
        Self::seeded()
    }
}

/// The mutation and accessor API of the store.
///
/// Exercised by the unit tests now, and called by connect logic (Phase 4+) and by
/// mutation dispatch once IPC requests carry payloads (Phase 9). It is not yet reached
/// from the shipped dispatch path, so `dead_code` is allowed here deliberately — these
/// are forward-looking, not orphaned.
#[allow(dead_code)]
impl DomainState {
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    pub fn profiles(&self) -> &[ConnectionProfile] {
        &self.profiles
    }

    pub fn rules(&self) -> &[RoutingRule] {
        &self.rules
    }

    /// Add an endpoint, rejecting a label already in use (the collection-level
    /// uniqueness invariant a single `Endpoint` cannot enforce, data-model §1).
    pub fn add_endpoint(&mut self, endpoint: Endpoint) -> Result<(), DomainError> {
        if self.endpoints.iter().any(|e| e.label() == endpoint.label()) {
            return Err(DomainError::InvalidLabel(endpoint.label().chars().count()));
        }
        self.endpoints.push(endpoint);
        Ok(())
    }

    pub fn remove_endpoint(&mut self, id: EndpointId) -> bool {
        let before = self.endpoints.len();
        self.endpoints.retain(|e| e.id() != id);
        self.endpoints.len() != before
    }

    /// Add a user rule, rejecting a precedence collision across the whole set (FR-022).
    pub fn add_rule(&mut self, rule: RoutingRule) -> Result<(), DomainError> {
        let mut candidate = self.rules.clone();
        candidate.push(rule);
        validate_rule_set(&candidate)?;
        self.rules = candidate;
        Ok(())
    }
}

fn health_name(state: HealthState) -> &'static str {
    match state {
        HealthState::Unknown => "Unknown",
        HealthState::Healthy => "Healthy",
        HealthState::Degraded => "Degraded",
        HealthState::Unreachable => "Unreachable",
    }
}

fn profile_kind_name(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::AmneziaWg => "AmneziaWg",
        ProfileKind::Hysteria2 => "Hysteria2",
        ProfileKind::VlessReality => "VlessReality",
    }
}

fn tier_name(tier: dnet_core::tier::FailoverTier) -> &'static str {
    match tier {
        dnet_core::tier::FailoverTier::Tier1 => "Tier1",
        dnet_core::tier::FailoverTier::Tier2 => "Tier2",
    }
}

fn carrier_name(carrier: dnet_core::profile::Carrier) -> &'static str {
    match carrier {
        dnet_core::profile::Carrier::Udp => "Udp",
        dnet_core::profile::Carrier::Tcp => "Tcp",
    }
}

fn rule_action_name(action: dnet_core::rule::RuleAction) -> &'static str {
    match action {
        dnet_core::rule::RuleAction::Tunnel => "Tunnel",
        dnet_core::rule::RuleAction::Bypass => "Bypass",
    }
}

fn reliability_name(reliability: dnet_core::rule::Reliability) -> &'static str {
    match reliability {
        dnet_core::rule::Reliability::Deterministic => "Deterministic",
        dnet_core::rule::Reliability::BestEffort => "BestEffort",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::credential::CredentialRef;
    use dnet_core::endpoint::{EndpointAddress, EndpointOrigin};
    use dnet_core::rule::{RuleAction, RuleMatcher};

    fn endpoint(label: &str) -> Endpoint {
        Endpoint::new(
            EndpointId::new(),
            label,
            EndpointAddress::new("vpn.example", 443).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new("dpapi:test"),
        )
        .unwrap()
    }

    #[test]
    fn seeded_store_has_three_profiles_and_builtin_rules() {
        let state = DomainState::seeded();
        assert_eq!(state.profiles().len(), 3);
        assert!(state.endpoints().is_empty());
        assert!(!state.rules().is_empty());
        assert!(state.rules().iter().all(RoutingRule::is_builtin));
    }

    #[test]
    fn seeded_profile_set_has_a_tcp_fallback() {
        let state = DomainState::seeded();
        assert_eq!(
            dnet_core::profile::validate_profile_set(state.profiles()),
            Ok(())
        );
    }

    #[test]
    fn adding_endpoints_rejects_a_duplicate_label() {
        let mut state = DomainState::seeded();
        assert!(state.add_endpoint(endpoint("home")).is_ok());
        assert!(state.add_endpoint(endpoint("home")).is_err());
        assert_eq!(state.endpoint_labels(), ["home"]);
    }

    #[test]
    fn removing_an_endpoint_reports_whether_it_existed() {
        let mut state = DomainState::seeded();
        let e = endpoint("home");
        let id = e.id();
        state.add_endpoint(e).unwrap();
        assert!(state.remove_endpoint(id));
        assert!(!state.remove_endpoint(id));
    }

    #[test]
    fn adding_a_rule_rejects_a_precedence_collision_with_builtins() {
        let mut state = DomainState::seeded();
        // Built-in rules occupy precedences 0.. ; reuse 0 to force a collision.
        let clash = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            0,
        )
        .unwrap();
        assert!(state.add_rule(clash).is_err());
    }

    #[test]
    fn adding_a_rule_with_a_free_precedence_succeeds() {
        let mut state = DomainState::seeded();
        let rule = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            10_000,
        )
        .unwrap();
        assert!(state.add_rule(rule).is_ok());
    }

    #[test]
    fn state_snapshot_reports_disconnected() {
        let json: Value =
            serde_json::from_str(&DomainState::seeded().state_snapshot_json()).unwrap();
        assert_eq!(json["status"], "Disconnected");
        assert_eq!(json["active_profile"], Value::Null);
    }

    #[test]
    fn profiles_json_lists_all_three_with_a_tier() {
        let json: Value = serde_json::from_str(&DomainState::seeded().profiles_json()).unwrap();
        let profiles = json["profiles"].as_array().unwrap();
        assert_eq!(profiles.len(), 3);
        assert!(profiles.iter().all(|p| p["tier"].is_string()));
        assert!(profiles.iter().any(|p| p["carrier"] == "Tcp"));
    }

    #[test]
    fn endpoints_json_reflects_added_endpoints() {
        let mut state = DomainState::seeded();
        state.add_endpoint(endpoint("home")).unwrap();
        let json: Value = serde_json::from_str(&state.endpoints_json()).unwrap();
        let items = json["endpoints"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["label"], "home");
        assert_eq!(items[0]["health"], "Unknown");
    }
}
