//! The daemon's in-memory domain store.
//!
//! Holds the endpoints, profiles, and rules the daemon knows about, and projects them
//! into the wire responses the IPC layer returns. The domain *entities* are pure
//! `dnet-core` types; this store is the application-level state that owns a set of
//! them and will later be backed by persisted configuration.

use dnet_core::builtin_rules::{builtin_rules_for, validate_builtin_rules_present};
use dnet_core::catalogue::BUNDLED_PROFILES;
use dnet_core::doh_block::{
    blocking_rules, validate_block_matches_policy, validate_block_outranks_user_rules,
};
use dnet_core::doh_consent::{ConsentState, OptOut};
use dnet_core::endpoint::Endpoint;
use dnet_core::error::DomainError;
use dnet_core::health::HealthState;
use dnet_core::ids::EndpointId;
use dnet_core::ids::ProfileId;
use dnet_core::ids::RuleId;
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use dnet_core::rule::{validate_dns_leak_protection, validate_rule_set, RoutingRule};
use dnet_ipc::protocol::{encode_state_snapshot, ConnectionStatus, RoutingPosture, StateSnapshot};
use serde_json::{json, Value};

use dnet_config::persist::{LoadedConfig, PersistError};

/// The outcome of reading the saved configuration at start-up.
pub struct StartupConfig {
    pub state: DomainState,
    /// Why the saved configuration was refused, if it was. Nothing may be changed or saved while
    /// this is set.
    pub refusal: Option<String>,
    /// Settings dropped because they no longer apply, for the log.
    pub notes: Vec<String>,
}

/// Everything the daemon knows about endpoints, profiles, and routing.
///
/// `Clone` so a change that fails half way can put the store back as it was (`configure`).
#[derive(Clone)]
pub struct DomainState {
    endpoints: Vec<Endpoint>,
    profiles: Vec<ConnectionProfile>,
    rules: Vec<RoutingRule>,
    /// Whether encrypted DNS is blocked and whether the person has been told (T070/T071). Kept in
    /// memory only until the saved configuration carries it: a restart returns to the protective
    /// default (block, disclosure shown again), never to an opt-out nobody confirmed.
    consent: ConsentState,
}

impl DomainState {
    /// A fresh store seeded with the three default profiles and the built-in bypass
    /// rules, and no endpoints (the user adds their own).
    pub fn seeded() -> Self {
        // From the bundled catalogue, which is also the set of ids the profile feed may
        // address (ADR-0002 §5.3).
        let profiles = BUNDLED_PROFILES
            .iter()
            .map(|entry| {
                ConnectionProfile::new(ProfileId::new(entry.id), entry.kind, ProfileParams::new())
            })
            .collect();
        let consent = ConsentState::new();
        Self {
            endpoints: Vec::new(),
            profiles,
            rules: builtin_rules_for(None, consent.policy()),
            consent,
        }
    }

    // ----------------------------------------------------------- persistence (T124)

    /// The seeded store with the saved configuration applied: each saved profile's parameters and
    /// Brutal setting, and the saved endpoints. The set of profiles is the bundled catalogue and
    /// never changes; a saved setting for a profile replaces that profile's settings, rebuilt so its
    /// tier is still the recorded measurement and its viability still `Untested`.
    pub fn from_loaded(loaded: LoadedConfig) -> Result<Self, PersistError> {
        let mut state = Self::seeded();
        for saved in loaded.profiles {
            let Some(slot) = state.profiles.iter_mut().find(|p| p.id() == &saved.id) else {
                // `dnet_config::persist::decode` refuses ids outside the catalogue; reaching here is a defect.
                return Err(PersistError::Invalid(
                    "a saved profile is not in the catalogue".into(),
                ));
            };
            let mut profile = ConnectionProfile::new(saved.id, slot.kind(), saved.params);
            if let Some((bandwidth, acknowledgement)) = saved.brutal {
                profile
                    .enable_brutal(bandwidth, acknowledgement)
                    .map_err(|e| PersistError::Invalid(e.to_string()))?;
            }
            *slot = profile;
        }
        for endpoint in loaded.endpoints {
            state
                .add_endpoint(endpoint)
                .map_err(|e| PersistError::Invalid(e.to_string()))?;
        }
        // The person's encrypted-DNS choice (T071). A file that never recorded one leaves the protective
        // default the seeded store already has.
        if let Some(saved) = loaded.encrypted_dns {
            state
                .apply_consent(saved)
                .map_err(|e| PersistError::Invalid(e.to_string()))?;
        }
        Ok(state)
    }

    /// What start-up makes of the saved configuration.
    ///
    /// - Nothing saved yet (a first run): the seeded store.
    /// - Saved and valid: that, with any notes (settings dropped because they no longer apply).
    /// - Saved but refused: the seeded store **and the reason**. The caller must keep the service
    ///   from changing anything and must not save over the file, which may be the only copy of the
    ///   user's endpoints.
    pub fn from_load_result(result: Result<Option<LoadedConfig>, PersistError>) -> StartupConfig {
        let refused = |e: PersistError| StartupConfig {
            state: Self::seeded(),
            refusal: Some(e.to_string()),
            notes: Vec::new(),
        };
        match result {
            Ok(None) => StartupConfig {
                state: Self::seeded(),
                refusal: None,
                notes: Vec::new(),
            },
            Ok(Some(loaded)) => {
                let notes = loaded.notes.clone();
                match Self::from_loaded(loaded) {
                    Ok(state) => StartupConfig {
                        state,
                        refusal: None,
                        notes,
                    },
                    Err(e) => refused(e),
                }
            }
            Err(e) => refused(e),
        }
    }

    /// The configuration in its stored form.
    pub fn to_config_bytes(&self) -> Result<Vec<u8>, PersistError> {
        // Written only once the person has chosen or been told something; otherwise the file is as it
        // always was.
        let chosen = (self.consent != ConsentState::new()).then_some(self.consent);
        dnet_config::persist::encode_full(&self.endpoints, &self.profiles, chosen)
    }

    // ----------------------------------------------------------- wire responses

    /// A `GetState` snapshot. The daemon does not yet establish tunnels (T126), so it always
    /// reports `Disconnected` with nothing active. `FailClosed` is the engine's decided posture
    /// for "no tunnel"; no component enforces it at the OS yet.
    pub fn state_snapshot_json(&self) -> String {
        encode_state_snapshot(&self.idle_snapshot())
            .expect("the idle snapshot is consistent by construction")
    }

    /// The state when nothing is connected and no orchestrator is attached.
    pub fn idle_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            status: ConnectionStatus::Disconnected,
            active_profile: None,
            active_endpoint: None,
            failure: None,
            warnings: Vec::new(),
            posture: RoutingPosture::FailClosed,
        }
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
        // The encrypted-DNS choice rides along: it is a setting about the rule set (the block is a set of
        // built-in rules), and the window needs it to show the switch and to know whether the first-run
        // disclosure is still owed. No request of its own was warranted for two booleans.
        json!({
            "rules": items,
            "encrypted_dns": {
                "block": self.consent.policy() == dnet_core::doh_block::Policy::Block,
                "needs_disclosure": self.consent.needs_disclosure(),
            },
        })
        .to_string()
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

    /// The endpoint with `id`, if there is one.
    pub fn endpoint(&self, id: EndpointId) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.id() == id)
    }

    /// Enable or disable an endpoint. `false` if there is no such endpoint.
    pub fn set_endpoint_enabled(&mut self, id: EndpointId, enabled: bool) -> bool {
        match self.endpoints.iter_mut().find(|e| e.id() == id) {
            Some(endpoint) => {
                endpoint.set_enabled(enabled);
                true
            }
            None => false,
        }
    }

    /// Add a user rule, rejecting a precedence collision across the whole set (FR-022)
    /// and any change that would weaken DNS-leak protection (the DNS-capture rule must
    /// remain present and top-priority).
    pub fn add_rule(&mut self, rule: RoutingRule) -> Result<(), DomainError> {
        let mut candidate = self.rules.clone();
        candidate.push(rule);
        self.replace_rules(candidate)
    }

    /// Remove a rule by id, reporting whether it existed. A built-in rule cannot be removed
    /// (data-model §4): the resulting set fails validation and nothing changes.
    pub fn remove_rule(&mut self, id: RuleId) -> Result<bool, DomainError> {
        let candidate: Vec<RoutingRule> = self
            .rules
            .iter()
            .filter(|r| r.id() != id)
            .cloned()
            .collect();
        if candidate.len() == self.rules.len() {
            return Ok(false);
        }
        self.replace_rules(candidate).map(|()| true)
    }

    /// Every rule-set mutation goes through here, so no mutation can break an invariant.
    fn replace_rules(&mut self, candidate: Vec<RoutingRule>) -> Result<(), DomainError> {
        Self::check_rules(&candidate, &self.consent)?;
        self.rules = candidate;
        Ok(())
    }

    fn check_rules(candidate: &[RoutingRule], consent: &ConsentState) -> Result<(), DomainError> {
        // Checked first, so deleting a built-in reports exactly that. No endpoint is
        // active in the store until connect lands (Phases 4-6).
        validate_builtin_rules_present(candidate, None)?;
        // The encrypted-DNS block goes only with the person's opt-out, never with a rule edit.
        validate_block_matches_policy(candidate, consent.policy())?;
        validate_rule_set(candidate)?;
        validate_dns_leak_protection(candidate)?;
        validate_block_outranks_user_rules(candidate)?;
        Ok(())
    }

    pub fn consent(&self) -> &ConsentState {
        &self.consent
    }

    /// The first-run flow showed the disclosure.
    pub fn acknowledge_encrypted_dns_disclosure(&mut self) {
        self.consent.acknowledge_disclosure();
    }

    /// Opt out of the encrypted-DNS block in one action (FR-025a). Returns the consequence the
    /// interface must show. Nothing changes if the resulting rule set would be invalid.
    pub fn opt_out_of_encrypted_dns_block(&mut self) -> Result<OptOut, DomainError> {
        let mut next = self.consent;
        let out = next.opt_out();
        self.apply_consent(next)?;
        Ok(out)
    }

    /// Turn the block back on. Needs no consent.
    pub fn restore_encrypted_dns_block(&mut self) -> Result<(), DomainError> {
        let mut next = self.consent;
        next.restore();
        self.apply_consent(next)
    }

    /// Choosing the block (the default) is how the first-run flow records that the person was shown the
    /// disclosure and went on: the choice is only offered next to it. Opting out records it already
    /// (`ConsentState::opt_out`).
    pub fn choose_encrypted_dns_block(&mut self) -> Result<(), DomainError> {
        let mut next = self.consent;
        next.restore();
        next.acknowledge_disclosure();
        self.apply_consent(next)
    }

    /// Swap the blocking rules for the ones `next` calls for, keeping every other rule.
    fn apply_consent(&mut self, next: ConsentState) -> Result<(), DomainError> {
        let mut candidate: Vec<RoutingRule> = self
            .rules
            .iter()
            .filter(|r| r.action() != dnet_core::rule::RuleAction::Reject)
            .cloned()
            .collect();
        candidate.extend(blocking_rules(next.policy()));
        Self::check_rules(&candidate, &next)?;
        self.rules = candidate;
        self.consent = next;
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
        dnet_core::rule::RuleAction::Capture => "Capture",
        dnet_core::rule::RuleAction::Reject => "Reject",
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
    fn disconnected_snapshot_is_fail_closed() {
        let json: Value =
            serde_json::from_str(&DomainState::seeded().state_snapshot_json()).unwrap();
        assert_eq!(json["routing_posture"]["posture"], "FailClosed");
    }

    #[test]
    fn seeded_rules_include_dns_leak_protection() {
        let state = DomainState::seeded();
        assert_eq!(
            dnet_core::rule::validate_dns_leak_protection(state.rules()),
            Ok(())
        );
        assert!(state.rules().iter().any(RoutingRule::is_dns_capture));
    }

    #[test]
    fn a_user_rule_cannot_undercut_the_dns_capture_rule() {
        let mut state = DomainState::seeded();
        // Precedence 0 is the DNS-capture rule; a user rule there collides and is
        // rejected, so DNS capture stays top-priority.
        let clash = RoutingRule::user(
            RuleMatcher::IpCidr(dnet_core::rule::IpCidr::parse("8.8.8.8/32").unwrap()),
            RuleAction::Bypass,
            0,
        )
        .unwrap();
        assert!(state.add_rule(clash).is_err());
    }

    #[test]
    fn no_builtin_rule_can_be_removed() {
        let mut state = DomainState::seeded();
        let builtin_ids: Vec<RuleId> = state.rules().iter().map(RoutingRule::id).collect();
        for id in builtin_ids {
            assert!(
                matches!(
                    state.remove_rule(id),
                    Err(DomainError::BuiltinRuleMissing(_))
                ),
                "built-in {id:?} must not be removable"
            );
        }
        assert_eq!(state.rules().len(), DomainState::seeded().rules().len());
    }

    fn blocks(state: &DomainState) -> usize {
        state
            .rules()
            .iter()
            .filter(|r| r.action() == RuleAction::Reject)
            .count()
    }

    #[test]
    fn a_fresh_store_blocks_encrypted_dns_and_still_has_to_tell_the_person() {
        let state = DomainState::seeded();
        assert!(blocks(&state) > 0);
        assert!(state.consent().needs_disclosure());
        assert_eq!(
            state.consent().policy(),
            dnet_core::doh_block::Policy::Block
        );
    }

    #[test]
    fn the_block_cannot_be_removed_by_editing_rules_only_by_the_opt_out() {
        let mut state = DomainState::seeded();
        let before = state.rules().len();
        let reject_ids: Vec<RuleId> = state
            .rules()
            .iter()
            .filter(|r| r.action() == RuleAction::Reject)
            .map(RoutingRule::id)
            .collect();
        assert!(!reject_ids.is_empty());
        for id in reject_ids {
            assert!(matches!(
                state.remove_rule(id),
                Err(DomainError::BuiltinRuleMissing(_))
            ));
        }
        assert_eq!(state.rules().len(), before);

        let out = state.opt_out_of_encrypted_dns_block().unwrap();
        assert!(out.consequence.contains("will not apply"));
        assert_eq!(blocks(&state), 0);
        assert!(!state.consent().needs_disclosure());
        // The required built-ins are untouched by the opt-out.
        assert!(state.rules().iter().any(RoutingRule::is_dns_capture));
    }

    #[test]
    fn the_block_can_be_restored_and_user_rules_survive_both_changes() {
        let mut state = DomainState::seeded();
        let rule = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            10_000,
        )
        .unwrap();
        let id = rule.id();
        state.add_rule(rule).unwrap();
        let blocked = blocks(&state);

        state.opt_out_of_encrypted_dns_block().unwrap();
        assert!(state.rules().iter().any(|r| r.id() == id));
        state.restore_encrypted_dns_block().unwrap();
        assert!(state.rules().iter().any(|r| r.id() == id));
        assert_eq!(blocks(&state), blocked);
    }

    #[test]
    fn a_user_rule_cannot_outrank_the_block_but_may_once_the_person_has_opted_out() {
        let mut state = DomainState::seeded();
        let low = || {
            RoutingRule::user(
                RuleMatcher::DomainSuffix("dns.google".into()),
                RuleAction::Bypass,
                50,
            )
            .unwrap()
        };
        assert!(matches!(
            state.add_rule(low()),
            Err(DomainError::OutranksEncryptedDnsBlock(50, _))
        ));
        state.opt_out_of_encrypted_dns_block().unwrap();
        assert_eq!(state.add_rule(low()), Ok(()));
        // And turning the block back on is refused while that rule would undo it: nothing changes.
        let before = state.rules().len();
        assert!(matches!(
            state.restore_encrypted_dns_block(),
            Err(DomainError::OutranksEncryptedDnsBlock(50, _))
        ));
        assert_eq!(state.rules().len(), before);
        assert_eq!(blocks(&state), 0);
        assert_eq!(
            state.consent().policy(),
            dnet_core::doh_block::Policy::Allow
        );
    }

    #[test]
    fn the_rules_listing_names_a_refusal() {
        let json: Value = serde_json::from_str(&DomainState::seeded().rules_json()).unwrap();
        assert!(json["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "Reject" && r["builtin"] == true));
    }

    #[test]
    fn the_encrypted_dns_choice_survives_a_save_and_a_load() {
        let mut state = DomainState::seeded();
        state.opt_out_of_encrypted_dns_block().unwrap();
        let bytes = state.to_config_bytes().unwrap();
        let reloaded =
            DomainState::from_loaded(dnet_config::persist::decode(&bytes).unwrap()).unwrap();
        assert_eq!(
            reloaded.consent().policy(),
            dnet_core::doh_block::Policy::Allow
        );
        assert_eq!(blocks(&reloaded), 0, "the rules follow the choice");
        assert!(!reloaded.consent().needs_disclosure());
        // And the other way round: a block that was restored stays restored.
        let mut again = reloaded;
        again.restore_encrypted_dns_block().unwrap();
        let back = DomainState::from_loaded(
            dnet_config::persist::decode(&again.to_config_bytes().unwrap()).unwrap(),
        )
        .unwrap();
        assert!(blocks(&back) > 0);
    }

    #[test]
    fn a_store_nobody_has_touched_writes_no_encrypted_dns_section() {
        let text = String::from_utf8(DomainState::seeded().to_config_bytes().unwrap()).unwrap();
        assert!(!text.contains("encrypted_dns"), "{text}");
        // Being told about it is recorded, even though the policy is still the default.
        let mut told = DomainState::seeded();
        told.acknowledge_encrypted_dns_disclosure();
        let text = String::from_utf8(told.to_config_bytes().unwrap()).unwrap();
        assert!(text.contains("encrypted_dns"), "{text}");
    }

    #[test]
    fn an_endpoint_can_be_enabled_and_disabled_and_a_missing_one_is_reported() {
        let mut state = DomainState::seeded();
        let e = endpoint("home");
        let id = e.id();
        state.add_endpoint(e).unwrap();
        assert!(state.set_endpoint_enabled(id, false));
        assert!(!state.endpoint(id).unwrap().is_enabled());
        assert!(state.set_endpoint_enabled(id, true));
        assert!(state.endpoint(id).unwrap().is_enabled());
        assert!(!state.set_endpoint_enabled(EndpointId::new(), true));
        assert!(state.endpoint(EndpointId::new()).is_none());
    }

    #[test]
    fn a_user_rule_can_be_removed() {
        let mut state = DomainState::seeded();
        let rule = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            10_000,
        )
        .unwrap();
        let id = rule.id();
        state.add_rule(rule).unwrap();

        assert_eq!(state.remove_rule(id), Ok(true));
        assert_eq!(state.remove_rule(id), Ok(false));
    }

    fn encrypted_dns(state: &DomainState) -> Value {
        let json: Value = serde_json::from_str(&state.rules_json()).unwrap();
        json["encrypted_dns"].clone()
    }

    #[test]
    fn the_rules_reply_says_whether_encrypted_dns_is_blocked_and_whether_the_disclosure_is_owed() {
        let mut state = DomainState::seeded();
        // The protective default, nothing yet shown.
        assert_eq!(
            encrypted_dns(&state),
            json!({ "block": true, "needs_disclosure": true })
        );
        // Choosing the default is how the first-run flow records that it showed the disclosure.
        state.choose_encrypted_dns_block().unwrap();
        assert_eq!(
            encrypted_dns(&state),
            json!({ "block": true, "needs_disclosure": false })
        );
        // Opting out records it too, and says the block is off.
        let mut state = DomainState::seeded();
        state.opt_out_of_encrypted_dns_block().unwrap();
        assert_eq!(
            encrypted_dns(&state),
            json!({ "block": false, "needs_disclosure": false })
        );
    }

    #[test]
    fn rules_json_exposes_the_capture_action() {
        let json: Value = serde_json::from_str(&DomainState::seeded().rules_json()).unwrap();
        let rules = json["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["action"] == "Capture"));
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

    // ---------------------------------------------------------------- persistence (T124)

    fn saved_endpoint(label: &str, uuid: &str) -> Endpoint {
        Endpoint::new(
            EndpointId::from_uuid(uuid.parse().unwrap()),
            label,
            EndpointAddress::new("vpn.example.com", 443).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new(format!("endpoint-{uuid}")),
        )
        .unwrap()
    }

    fn state_with_settings() -> DomainState {
        let mut state = DomainState::seeded();
        state
            .add_endpoint(saved_endpoint(
                "home",
                "123e4567-e89b-42d3-a456-426614174000",
            ))
            .unwrap();
        let hy2 = state
            .profiles
            .iter_mut()
            .find(|p| p.id().as_str() == "hy2-default")
            .unwrap();
        hy2.enable_brutal(
            dnet_core::profile::BandwidthPair {
                up_mbps: 50,
                down_mbps: 200,
            },
            dnet_core::profile::BrutalAcknowledgement {
                warning_revision: dnet_core::profile::BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_760_000_000,
            },
        )
        .unwrap();
        state
    }

    fn reload(state: &DomainState) -> StartupConfig {
        let loaded = dnet_config::persist::decode(&state.to_config_bytes().unwrap()).unwrap();
        DomainState::from_load_result(Ok(Some(loaded)))
    }

    #[test]
    fn a_first_run_starts_from_the_seeded_defaults_without_complaint() {
        let start = DomainState::from_load_result(Ok(None));
        assert!(start.refusal.is_none() && start.notes.is_empty());
        assert!(start.state.endpoints().is_empty());
        assert_eq!(start.state.profiles().len(), 3);
    }

    #[test]
    fn what_was_saved_is_what_starts() {
        let before = state_with_settings();
        let start = reload(&before);

        assert!(start.refusal.is_none() && start.notes.is_empty());
        assert_eq!(start.state.endpoints(), before.endpoints());
        let hy2 = start
            .state
            .profiles()
            .iter()
            .find(|p| p.id().as_str() == "hy2-default")
            .unwrap();
        assert_eq!(hy2.brutal().unwrap().bandwidth().up_mbps, 50);
        assert!(start.state.rules().iter().all(RoutingRule::is_builtin));
    }

    #[test]
    fn a_restored_profile_takes_its_tier_from_the_measurement_never_from_the_file() {
        // The file has no tier field at all; every restored profile is whatever the recorded
        // HV-07 result says (Tier 2 until T085), and nothing in it has been probed.
        let start = reload(&state_with_settings());
        for profile in start.state.profiles() {
            let fresh =
                ConnectionProfile::new(profile.id().clone(), profile.kind(), ProfileParams::new());
            assert_eq!(profile.tier(), fresh.tier(), "{}", profile.id());
            assert_eq!(
                profile.viability(),
                &dnet_core::profile::Viability::Untested
            );
        }
    }

    #[test]
    fn a_refused_file_starts_the_defaults_and_carries_the_reason() {
        let start = DomainState::from_load_result(Err(PersistError::Invalid(
            "endpoint 0: the host is neither an IP address nor a host name".into(),
        )));
        assert!(start.state.endpoints().is_empty());
        let reason = start.refusal.expect("a refusal must be reported");
        assert!(reason.contains("endpoint 0"), "{reason}");
    }

    #[test]
    fn notes_from_loading_are_passed_on_and_do_not_refuse_the_file() {
        let mut loaded =
            dnet_config::persist::decode(&state_with_settings().to_config_bytes().unwrap())
                .unwrap();
        loaded
            .notes
            .push("profile 'hy2-default': Brutal ... turned off".into());
        for profile in &mut loaded.profiles {
            profile.brutal = None;
        }
        let start = DomainState::from_load_result(Ok(Some(loaded)));

        assert!(start.refusal.is_none());
        assert_eq!(start.notes.len(), 1);
        assert_eq!(start.state.endpoints().len(), 1);
        assert!(start.state.profiles().iter().all(|p| p.brutal().is_none()));
    }

    #[test]
    fn the_stored_form_carries_no_secret_and_no_measurement() {
        let text = String::from_utf8(state_with_settings().to_config_bytes().unwrap())
            .unwrap()
            .to_lowercase();
        for forbidden in ["password", "private", "secret", "token", "health", "rtt"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
}
