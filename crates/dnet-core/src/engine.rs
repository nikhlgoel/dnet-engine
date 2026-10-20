//! The connection engine: one deterministic policy that joins the decision modules.
//!
//! `probe`, `selection`, `reprobe`, `endpoint_health`, `migrate` and `failure` each decide one
//! thing. This module says **when each applies**, as a state machine with no I/O and no clock.
//! The daemon feeds it what it observes ([`Input`]) and does what it asks ([`Action`]); the
//! OS-facing work (spawning cores, routes, the kill switch) stays outside, behind the seams that
//! already exist. That split is what lets every transition below be tested without a machine.
//!
//! ```text
//!            Connect                     RaceFinished(Selected)
//!   Idle ───────────────▶ Probing ─────────────────────────────▶ Starting ── TunnelUp ──▶ Connected
//!    ▲                      │  RaceFinished(NoneUsable)              │                      │
//!    │ Disconnect           ▼                                        │ StartFailed          │ 3 live checks fail
//!    └──────────────────  Failed ◀───────────────────────────────────┘                      ▼
//!                           ▲                                                          Recovering ── RaceFinished ──▶ Starting
//!                           └────────────── nothing usable left ◀───────────────────────────┘
//! ```
//!
//! **Policy decisions made here** (each is tested, and recorded in `tasks.md`):
//! - A new connect forgets every earlier viability: a profile blocked on one network may work on
//!   the next.
//! - Races include only profiles that can be probed through a proxy. AmneziaWG cannot (it needs an
//!   adapter), so it is tried by bringing it up, never raced: if it is asked for explicitly, or as a
//!   last resort once every probeable profile has failed.
//! - A block stops the tunnel *before* recovery starts. With no working profile the posture is
//!   fail-closed (`posture::select_posture`), so traffic is dropped, never leaked.
//! - A degraded active endpoint is kept; only an unusable one is replaced (`migrate`).
//! - A profile the user named is tried alone. If it fails the connect fails, saying so; another
//!   profile is never substituted silently.
//! - Before a profile is blamed for failed live checks, the machine (no path, portal, privilege) and
//!   the endpoint are ruled out. A dead endpoint is moved, in every phase that uses one.
//! - Every automatic change emits a [`ConnectionEvent`] that says why, in words.
//!
//! **Late results.** The engine gates them by phase only (and ignores a race winner that was not in
//! the current race). The orchestrator (`dnetd::orchestrator`, T126) closes the rest: every step that
//! starts background work takes an attempt number and results from older numbers never reach here.

use std::time::Instant;

use crate::endpoint::Endpoint;
use crate::endpoint_health::rank;
use crate::failure::{classify, Reach, Situation};
use crate::health::{HealthConfig, ProbeOutcome as EndpointProbeOutcome};
use crate::ids::{EndpointId, ProfileId};
use crate::migrate::{plan_migration, Migration};
use crate::probe::{judge, ProfileProbe, RaceDecision, Unusable, Verdict};
use crate::profile::{ConnectionProfile, Viability};
use crate::reprobe::{plan_reprobe, BlockDetector, Detection, LiveCheck, ReprobePlan};
use crate::session::{ConnectionEvent, FailureCause};
use crate::tier::FailoverTier;

/// Where a connection attempt stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Not connecting.
    Idle,
    /// Racing profiles to find one that carries traffic.
    Probing,
    /// A profile and endpoint are chosen and the tunnel is being brought up.
    Starting {
        profile: ProfileId,
        endpoint: EndpointId,
    },
    /// Carrying traffic.
    Connected {
        profile: ProfileId,
        endpoint: EndpointId,
    },
    /// The carrying profile was blocked; looking for another.
    Recovering,
    /// Could not connect, or lost the connection for good. Connect again to retry.
    Failed(FailureCause),
}

/// Facts about the machine the engine cannot observe itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// The service holds the privilege it needs.
    pub privileged: bool,
    /// How many network paths can carry traffic.
    pub usable_paths: usize,
    /// A captive portal is intercepting traffic.
    pub captive_portal: bool,
    /// Why the configuration cannot be used, if it cannot. Shown to the user verbatim.
    pub configuration_error: Option<String>,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            privileged: true,
            usable_paths: 1,
            captive_portal: false,
            configuration_error: None,
        }
    }
}

/// What the daemon tells the engine.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// The user asked to connect, optionally to one named profile.
    ///
    /// There is no "acknowledged Tier 2" flag: a connect races only the profiles it names (or all
    /// of them), and the race itself prefers Tier 1, so the consent case `selection::select`
    /// guards against cannot arise here. Tier 2 is warned about, not blocked (`Action::WarnTier2`).
    Connect {
        profile: Option<ProfileId>,
    },
    Disconnect,
    /// The race finished. `results` are what each probe that reported saw.
    RaceFinished {
        decision: RaceDecision,
        results: Vec<(ProfileId, ProfileProbe)>,
    },
    /// The tunnel for the profile being started is up and carrying traffic.
    TunnelUp,
    /// The tunnel could not be brought up, for this reason.
    StartFailed(FailureCause),
    /// A periodic check of the carrying profile.
    LiveCheck(LiveCheck),
    /// One health probe of an endpoint.
    EndpointProbe {
        endpoint: EndpointId,
        outcome: EndpointProbeOutcome,
    },
    Environment(Environment),
    /// Direct reachability of each endpoint, in endpoint order, made outside any profile. A connect
    /// forgets earlier reach (it describes the network the last attempt ran on), so report it
    /// after `Connect`, before the race result.
    Reach(Vec<Reach>),
}

/// What the engine asks the daemon to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Record this on the session.
    Emit(ConnectionEvent),
    /// Probe these profiles at once against this endpoint, then report `RaceFinished`.
    StartRace {
        profiles: Vec<ProfileId>,
        endpoint: EndpointId,
    },
    /// Abandon a race in progress.
    CancelRace,
    /// Bring this profile up against this endpoint, then report `TunnelUp` or `StartFailed`.
    StartTunnel {
        profile: ProfileId,
        endpoint: EndpointId,
    },
    /// Take the tunnel down. The routing posture is then fail-closed until another is up.
    StopTunnel,
    /// Tell the user before connecting that established connections may break when the network
    /// interface changes (FR-016b).
    WarnTier2 { profile: ProfileId },
}

/// The connection state machine.
#[derive(Debug)]
pub struct Engine {
    profiles: Vec<ConnectionProfile>,
    endpoints: Vec<Endpoint>,
    phase: Phase,
    environment: Environment,
    reach: Vec<Reach>,
    detector: BlockDetector,
    /// The endpoint the current attempt uses.
    endpoint: Option<EndpointId>,
    /// Profiles in the race in progress, so one that never reports can still be marked blocked.
    raced: Vec<ProfileId>,
    /// The blocked profile a recovery is replacing, so the event can say so.
    replacing: Option<ProfileId>,
    /// The profile the user named on the current connect, if any.
    requested: Option<ProfileId>,
}

impl Engine {
    pub fn new(profiles: Vec<ConnectionProfile>, endpoints: Vec<Endpoint>) -> Self {
        Self {
            profiles,
            endpoints,
            phase: Phase::Idle,
            environment: Environment::default(),
            reach: Vec::new(),
            detector: BlockDetector::new(),
            endpoint: None,
            raced: Vec::new(),
            replacing: None,
            requested: None,
        }
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn profiles(&self) -> &[ConnectionProfile] {
        &self.profiles
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Apply one input observed at `now`, returning what to do about it.
    ///
    /// An input that makes no sense in the current phase (a race result when no race is running, a
    /// live check when not connected) is ignored and returns no actions: the daemon is
    /// asynchronous, so a late result is normal, not an error.
    pub fn step(&mut self, input: Input, now: Instant) -> Vec<Action> {
        match input {
            Input::Connect { profile } => self.connect(profile),
            Input::Disconnect => self.disconnect(),
            Input::RaceFinished { decision, results } => {
                self.race_finished(decision, &results, now)
            }
            Input::TunnelUp => self.tunnel_up(now),
            Input::StartFailed(cause) => match self.phase {
                Phase::Starting { .. } => self.fail(cause, true),
                _ => Vec::new(),
            },
            Input::LiveCheck(check) => self.live_check(check, now),
            Input::EndpointProbe { endpoint, outcome } => {
                self.endpoint_probe(endpoint, outcome, now)
            }
            Input::Environment(environment) => {
                self.environment = environment;
                Vec::new()
            }
            Input::Reach(reach) => {
                self.reach = reach;
                Vec::new()
            }
        }
    }

    // ---------------------------------------------------------------- connect

    fn connect(&mut self, requested: Option<ProfileId>) -> Vec<Action> {
        if !matches!(self.phase, Phase::Idle | Phase::Failed(_)) {
            return Vec::new();
        }
        for profile in &mut self.profiles {
            profile.reset_viability();
        }
        self.detector.reset();
        self.raced.clear();
        self.replacing = None;
        self.reach.clear();
        self.requested = requested.clone();

        // Only what is known before any probing. Reach and "every profile blocked" are judged
        // after a race, when there is something to judge them against.
        if let Some(cause) = self.classify(false) {
            return self.fail(cause, false);
        }
        if let Some(id) = &requested {
            if !self.profiles.iter().any(|p| p.id() == id) {
                let detail = format!("there is no connection profile named {id}");
                return self.fail(FailureCause::ConfigurationInvalid { detail }, false);
            }
        }
        let Some(endpoint) = rank(&self.endpoints).first().copied() else {
            return self.fail(FailureCause::NoEndpointReachable, false);
        };
        self.endpoint = Some(endpoint);

        match requested {
            Some(id) if !self.is_probeable(&id) => {
                let because = format!(
                    "you asked for {id} by name; it cannot be tested ahead of time, so it is started directly"
                );
                self.start_tunnel(id, endpoint, because)
            }
            Some(id) => self.start_race(vec![id], endpoint, Phase::Probing),
            None => {
                let probeable = self.probeable_ids();
                if probeable.is_empty() {
                    match self.direct_fallback() {
                        Some(id) => {
                            let because = format!(
                                "{id} is the only profile configured; it cannot be tested ahead of time, so it is started directly"
                            );
                            self.start_tunnel(id, endpoint, because)
                        }
                        None => self.fail(FailureCause::AllProfilesBlocked, false),
                    }
                } else {
                    self.start_race(probeable, endpoint, Phase::Probing)
                }
            }
        }
    }

    fn disconnect(&mut self) -> Vec<Action> {
        let actions = match self.phase {
            Phase::Idle | Phase::Failed(_) => Vec::new(),
            Phase::Probing | Phase::Recovering => vec![Action::CancelRace],
            Phase::Starting { .. } | Phase::Connected { .. } => vec![Action::StopTunnel],
        };
        self.phase = Phase::Idle;
        self.raced.clear();
        self.replacing = None;
        actions
    }

    // ------------------------------------------------------------------ race

    fn race_finished(
        &mut self,
        decision: RaceDecision,
        results: &[(ProfileId, ProfileProbe)],
        now: Instant,
    ) -> Vec<Action> {
        if !matches!(self.phase, Phase::Probing | Phase::Recovering) {
            return Vec::new();
        }
        if decision == RaceDecision::Pending {
            return Vec::new();
        }
        // A winner this race did not run is a stale result from an abandoned one.
        if let RaceDecision::Selected { profile, .. } = &decision {
            if !self.raced.contains(profile) {
                return Vec::new();
            }
        }
        let endpoint = self.endpoint.expect("a race always has an endpoint");
        let recovering = self.phase == Phase::Recovering;
        let mut actions = self.record_results(&decision, results, now);

        match decision {
            RaceDecision::Selected {
                profile,
                bits_per_sec,
                ..
            } => {
                let because = self.race_because(&profile, bits_per_sec);
                actions.extend(self.start_tunnel(profile, endpoint, because));
            }
            RaceDecision::NoneUsable => match self.classify(true) {
                Some(cause) => actions.extend(self.fail(cause, false)),
                // The user named a profile and it failed. Do not quietly use another: say so.
                None if !recovering && self.requested.is_some() => {
                    let cause = self.named_profile_failed();
                    actions.extend(self.fail(cause, false));
                }
                None => match self.direct_fallback() {
                    Some(id) => {
                        let because = self.fallback_because(&id, recovering);
                        actions.extend(self.start_tunnel(id, endpoint, because));
                    }
                    None => actions.extend(self.fail(FailureCause::AllProfilesBlocked, false)),
                },
            },
            RaceDecision::Pending => {}
        }
        actions
    }

    /// Record what the race learned on the profiles, and say so for each one that is blocked.
    fn record_results(
        &mut self,
        decision: &RaceDecision,
        results: &[(ProfileId, ProfileProbe)],
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut reported = Vec::new();
        for (id, probe) in results {
            reported.push(id.clone());
            match judge(*probe) {
                Verdict::Usable { .. } => self.mark_working(id, now),
                Verdict::Unusable(why) => {
                    actions.extend(self.mark_blocked(id, now, unusable_reason(why)));
                }
            }
        }
        // With no winner, a profile that never reported ran out of time. With a winner, the
        // losers are aborted: they are untested on this network, not blocked, and stay candidates
        // for a later recovery.
        if *decision == RaceDecision::NoneUsable {
            let silent: Vec<ProfileId> = self
                .raced
                .iter()
                .filter(|id| !reported.contains(id))
                .cloned()
                .collect();
            for id in silent {
                actions.extend(self.mark_blocked(&id, now, "did not respond in time".to_string()));
            }
        }
        if let RaceDecision::Selected { profile, .. } = decision {
            self.mark_working(profile, now);
        }
        self.raced.clear();
        actions
    }

    fn race_because(&self, winner: &ProfileId, bits_per_sec: u64) -> String {
        let mbit = bits_per_sec as f64 / 1_000_000.0;
        let base =
            format!("{winner} carried traffic best in the probe race, at about {mbit:.1} Mbit/s");
        match &self.replacing {
            Some(old) => format!("{base}; it replaces {old}, which the network blocked"),
            None => base,
        }
    }

    fn fallback_because(&self, id: &ProfileId, recovering: bool) -> String {
        let base = format!(
            "no other profile worked on this network, so {id} is started directly (it cannot be tested ahead of time)"
        );
        match (&self.replacing, recovering) {
            (Some(old), true) => format!("{base}; it replaces {old}, which the network blocked"),
            _ => base,
        }
    }

    // ---------------------------------------------------------------- tunnel

    fn tunnel_up(&mut self, now: Instant) -> Vec<Action> {
        if let Phase::Starting { profile, endpoint } = self.phase.clone() {
            // A profile started directly was never raced; coming up is the first evidence it works.
            self.mark_working(&profile, now);
            self.detector.reset();
            self.replacing = None;
            self.phase = Phase::Connected { profile, endpoint };
        }
        Vec::new()
    }

    fn live_check(&mut self, check: LiveCheck, now: Instant) -> Vec<Action> {
        let Phase::Connected { profile, endpoint } = self.phase.clone() else {
            return Vec::new();
        };
        let Detection::Blocked { failures } = self.detector.observe(check) else {
            return Vec::new();
        };
        // Before blaming the profile, rule out the machine and the endpoint: a lost network or a
        // dead endpoint fails live checks too, and must not be reported as a block.
        if let Some(cause) = self.classify(false) {
            return self.fail(cause, true);
        }
        if let Some(actions) = self.relocate_tunnel(&profile, endpoint) {
            return actions;
        }
        let reason = format!("stopped carrying traffic: {failures} live checks failed in a row");
        // Stop first: with nothing carrying traffic the posture is fail-closed while another
        // profile is found, so nothing leaks around the dead tunnel.
        let mut actions = self.mark_blocked(&profile, now, reason);
        actions.push(Action::StopTunnel);
        self.replacing = Some(profile.clone());

        match plan_reprobe(&self.profiles, &profile) {
            ReprobePlan::AllBlocked => {
                actions.extend(self.fail(FailureCause::AllProfilesBlocked, false))
            }
            ReprobePlan::Try(candidates) => {
                let probeable: Vec<ProfileId> = candidates
                    .iter()
                    .filter(|id| self.is_probeable(id))
                    .cloned()
                    .collect();
                if probeable.is_empty() {
                    // Only profiles that cannot be raced remain.
                    let direct = candidates[0].clone();
                    let because = self.fallback_because(&direct, true);
                    actions.extend(self.start_tunnel(direct, endpoint, because));
                } else {
                    actions.extend(self.start_race(probeable, endpoint, Phase::Recovering));
                }
            }
        }
        actions
    }

    fn endpoint_probe(
        &mut self,
        endpoint: EndpointId,
        outcome: EndpointProbeOutcome,
        now: Instant,
    ) -> Vec<Action> {
        let Some(known) = self.endpoints.iter_mut().find(|e| e.id() == endpoint) else {
            return Vec::new();
        };
        let transition = known
            .health()
            .on_probe(outcome, now, &HealthConfig::default());
        known.set_health(transition.next);

        // Only the endpoint in use can move the connection, and only on the probe that makes it
        // unreachable: a slow or lossy one is kept (migrating costs a tunnel or race restart).
        if self.endpoint != Some(endpoint) || !transition.became_unreachable {
            return Vec::new();
        }
        match self.phase.clone() {
            Phase::Connected { profile, .. } | Phase::Starting { profile, .. } => {
                self.relocate_tunnel(&profile, endpoint).unwrap_or_default()
            }
            Phase::Probing | Phase::Recovering => self.relocate_race(endpoint).unwrap_or_default(),
            Phase::Idle | Phase::Failed(_) => Vec::new(),
        }
    }

    /// Move a tunnel to another endpoint if `active` is no longer usable. `None` means keep it.
    /// The tunnel stops before the new one starts, so the posture stays fail-closed in between.
    fn relocate_tunnel(&mut self, profile: &ProfileId, active: EndpointId) -> Option<Vec<Action>> {
        match plan_migration(&self.endpoints, active) {
            Migration::Stay => None,
            Migration::MoveTo { to, event } => {
                self.endpoint = Some(to);
                self.detector.reset();
                self.phase = Phase::Starting {
                    profile: profile.clone(),
                    endpoint: to,
                };
                Some(vec![
                    Action::Emit(event),
                    Action::StopTunnel,
                    Action::StartTunnel {
                        profile: profile.clone(),
                        endpoint: to,
                    },
                ])
            }
            Migration::NoEndpointReachable => {
                Some(self.fail(FailureCause::NoEndpointReachable, true))
            }
        }
    }

    /// Restart the race in progress against another endpoint if `active` is no longer usable.
    fn relocate_race(&mut self, active: EndpointId) -> Option<Vec<Action>> {
        match plan_migration(&self.endpoints, active) {
            Migration::Stay => None,
            Migration::MoveTo { to, event } => {
                self.endpoint = Some(to);
                Some(vec![
                    Action::Emit(event),
                    Action::CancelRace,
                    Action::StartRace {
                        profiles: self.raced.clone(),
                        endpoint: to,
                    },
                ])
            }
            Migration::NoEndpointReachable => {
                let mut actions = vec![Action::CancelRace];
                actions.extend(self.fail(FailureCause::NoEndpointReachable, false));
                Some(actions)
            }
        }
    }

    // --------------------------------------------------------------- helpers

    fn start_race(
        &mut self,
        profiles: Vec<ProfileId>,
        endpoint: EndpointId,
        phase: Phase,
    ) -> Vec<Action> {
        self.raced = profiles.clone();
        self.phase = phase;
        let mut actions = Vec::new();
        // The first race of a connect announces itself; a recovery already said why it is racing.
        if self.phase == Phase::Probing {
            actions.push(Action::Emit(ConnectionEvent::ProbeStarted));
        }
        actions.push(Action::StartRace { profiles, endpoint });
        actions
    }

    fn start_tunnel(
        &mut self,
        profile: ProfileId,
        endpoint: EndpointId,
        because: String,
    ) -> Vec<Action> {
        let tier2 = self
            .profiles
            .iter()
            .find(|p| p.id() == &profile)
            .is_some_and(|p| p.tier() == FailoverTier::Tier2);
        self.detector.reset();
        self.phase = Phase::Starting {
            profile: profile.clone(),
            endpoint,
        };
        let mut actions = vec![Action::Emit(ConnectionEvent::ProfileSelected {
            profile: profile.clone(),
            because,
        })];
        if tier2 {
            actions.push(Action::WarnTier2 {
                profile: profile.clone(),
            });
        }
        actions.push(Action::StartTunnel { profile, endpoint });
        actions
    }

    fn fail(&mut self, cause: FailureCause, stop_tunnel: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        if stop_tunnel {
            actions.push(Action::StopTunnel);
        }
        actions.push(Action::Emit(ConnectionEvent::Failed {
            cause: cause.clone(),
        }));
        self.phase = Phase::Failed(cause);
        self.raced.clear();
        self.replacing = None;
        actions
    }

    /// `after_race` adds what only a race can show: direct reachability and blocked profiles.
    fn classify(&self, after_race: bool) -> Option<FailureCause> {
        let reach: Vec<Reach> = (0..self.endpoints.len())
            .map(|i| match (after_race, self.reach.get(i)) {
                (true, Some(r)) => *r,
                _ => Reach::Unknown,
            })
            .collect();
        classify(&Situation {
            privileged: self.environment.privileged,
            configuration_error: self.environment.configuration_error.as_deref(),
            core_failed: None,
            usable_paths: self.environment.usable_paths,
            captive_portal: self.environment.captive_portal,
            endpoint_reach: &reach,
            profiles: &self.profiles,
        })
    }

    fn is_probeable(&self, id: &ProfileId) -> bool {
        self.profiles
            .iter()
            .any(|p| p.id() == id && p.kind().proxy_probeable())
    }

    fn probeable_ids(&self) -> Vec<ProfileId> {
        self.profiles
            .iter()
            .filter(|p| p.kind().proxy_probeable())
            .map(|p| p.id().clone())
            .collect()
    }

    fn named_profile_failed(&self) -> FailureCause {
        let name = self.requested.clone().expect("checked by the caller");
        let reason = self
            .profiles
            .iter()
            .find_map(|p| match p.viability() {
                Viability::Blocked { reason, .. } if p.id() == &name => Some(reason.as_str()),
                _ => None,
            })
            .unwrap_or("it did not work");
        FailureCause::ConfigurationInvalid {
            detail: format!(
                "{name} did not work on this network ({reason}); connect without naming a profile to try the others"
            ),
        }
    }

    /// A profile that can only be tried by bringing it up, and has not been tried. Only offered
    /// once every profile that could be raced has failed: it is the last resort, not a peer.
    fn direct_fallback(&self) -> Option<ProfileId> {
        let raced_all_failed = self
            .profiles
            .iter()
            .filter(|p| p.kind().proxy_probeable())
            .all(|p| matches!(p.viability(), Viability::Blocked { .. }));
        if !raced_all_failed {
            return None;
        }
        self.profiles
            .iter()
            .find(|p| !p.kind().proxy_probeable() && p.viability() == &Viability::Untested)
            .map(|p| p.id().clone())
    }

    fn mark_working(&mut self, id: &ProfileId, now: Instant) {
        if let Some(p) = self.profiles.iter_mut().find(|p| p.id() == id) {
            p.mark_working(now);
        }
    }

    fn mark_blocked(&mut self, id: &ProfileId, now: Instant, reason: String) -> Vec<Action> {
        let Some(p) = self.profiles.iter_mut().find(|p| p.id() == id) else {
            return Vec::new();
        };
        p.mark_blocked(now, reason.clone());
        vec![Action::Emit(ConnectionEvent::ProfileBlocked {
            profile: id.clone(),
            reason,
        })]
    }
}

/// Why a probe showed an unusable profile, in words the user can read.
fn unusable_reason(why: Unusable) -> String {
    match why {
        Unusable::HandshakeFailed => "could not connect",
        Unusable::NoTraffic => "connected, but no data came through",
        Unusable::TooLittleData => "too little data came through to judge it",
        Unusable::TooSlow => "too slow to be useful",
        Unusable::InvalidMeasurement => "the probe measurement was not valid",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_health::fixtures::{degraded, endpoint, healthy, unreachable};
    use crate::health::ProbeOutcome;
    use crate::probe::Verdict;
    use crate::profile::{ProfileKind, ProfileParams, Viability};
    use crate::reprobe::BLOCK_AFTER;
    use crate::tier::SurvivalMeasurement;
    use std::time::Duration;

    fn id(s: &str) -> ProfileId {
        ProfileId::new(s)
    }

    fn profile(name: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(id(name), kind, ProfileParams::new())
    }

    fn standard_profiles() -> Vec<ConnectionProfile> {
        vec![
            profile("awg", ProfileKind::AmneziaWg),
            profile("hy2", ProfileKind::Hysteria2),
            profile("reality", ProfileKind::VlessReality),
        ]
    }

    fn engine() -> (Engine, EndpointId) {
        let e = healthy("main", 30);
        let eid = e.id();
        (Engine::new(standard_profiles(), vec![e]), eid)
    }

    fn connect() -> Input {
        Input::Connect { profile: None }
    }

    fn good(bytes: u64) -> ProfileProbe {
        ProfileProbe::Transferred {
            bytes,
            elapsed: Duration::from_secs(1),
        }
    }

    fn selected(profile: &str, mbps: u64) -> RaceDecision {
        RaceDecision::Selected {
            profile: id(profile),
            tier: crate::tier::FailoverTier::Tier2,
            bits_per_sec: mbps * 1_000_000,
        }
    }

    fn step(e: &mut Engine, input: Input) -> Vec<Action> {
        e.step(input, Instant::now())
    }

    fn events(actions: &[Action]) -> Vec<&ConnectionEvent> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Emit(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn failed_cause(e: &Engine) -> FailureCause {
        match e.phase() {
            Phase::Failed(c) => c.clone(),
            other => panic!("expected Failed, was {other:?}"),
        }
    }

    /// Drive an engine to `Connected` on `hy2`.
    fn connected() -> (Engine, EndpointId) {
        let (mut e, eid) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut e, Input::TunnelUp);
        assert!(matches!(e.phase(), Phase::Connected { .. }));
        (e, eid)
    }

    // ------------------------------------------------------------ connecting

    #[test]
    fn a_new_engine_is_idle() {
        let (e, _) = engine();
        assert_eq!(e.phase(), &Phase::Idle);
    }

    #[test]
    fn connecting_races_the_probeable_profiles_against_the_best_endpoint() {
        let slow = healthy("slow", 200);
        let fast = healthy("fast", 15);
        let fast_id = fast.id();
        let mut e = Engine::new(standard_profiles(), vec![slow, fast]);
        let actions = step(&mut e, connect());
        assert_eq!(e.phase(), &Phase::Probing);
        assert!(actions.contains(&Action::Emit(ConnectionEvent::ProbeStarted)));
        assert!(actions.contains(&Action::StartRace {
            profiles: vec![id("hy2"), id("reality")],
            endpoint: fast_id,
        }));
    }

    #[test]
    fn amneziawg_is_never_in_a_race() {
        let (mut e, _) = engine();
        let races: Vec<Vec<ProfileId>> = step(&mut e, connect())
            .into_iter()
            .filter_map(|a| match a {
                Action::StartRace { profiles, .. } => Some(profiles),
                _ => None,
            })
            .collect();
        assert_eq!(races.len(), 1, "a race must have started");
        assert!(!races[0].contains(&id("awg")));
    }

    #[test]
    fn connecting_without_an_endpoint_fails_with_a_configuration_cause() {
        let mut e = Engine::new(standard_profiles(), vec![]);
        let actions = step(&mut e, connect());
        assert!(matches!(
            failed_cause(&e),
            FailureCause::ConfigurationInvalid { ref detail } if detail.contains("endpoint")
        ));
        assert!(matches!(
            events(&actions).last(),
            Some(ConnectionEvent::Failed { .. })
        ));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::StartRace { .. })));
    }

    #[test]
    fn connecting_with_every_endpoint_unusable_fails_as_no_endpoint_reachable() {
        let mut e = Engine::new(standard_profiles(), vec![unreachable("down")]);
        step(&mut e, connect());
        assert_eq!(failed_cause(&e), FailureCause::NoEndpointReachable);
    }

    #[test]
    fn the_environment_can_stop_a_connect_before_any_probing() {
        for (env, expected) in [
            (
                Environment {
                    privileged: false,
                    ..Environment::default()
                },
                FailureCause::InsufficientPrivilege,
            ),
            (
                Environment {
                    usable_paths: 0,
                    ..Environment::default()
                },
                FailureCause::NoUsablePath,
            ),
            (
                Environment {
                    captive_portal: true,
                    ..Environment::default()
                },
                FailureCause::CaptivePortalUnsatisfied,
            ),
        ] {
            let (mut e, _) = engine();
            step(&mut e, Input::Environment(env));
            let actions = step(&mut e, connect());
            assert_eq!(failed_cause(&e), expected);
            assert!(!actions
                .iter()
                .any(|a| matches!(a, Action::StartRace { .. })));
        }
    }

    #[test]
    fn a_configuration_error_from_the_environment_reaches_the_failure() {
        let (mut e, _) = engine();
        step(
            &mut e,
            Input::Environment(Environment {
                configuration_error: Some("the REALITY key is not valid".into()),
                ..Environment::default()
            }),
        );
        step(&mut e, connect());
        assert_eq!(
            failed_cause(&e),
            FailureCause::ConfigurationInvalid {
                detail: "the REALITY key is not valid".into()
            }
        );
    }

    #[test]
    fn a_requested_probeable_profile_is_the_only_one_raced() {
        let (mut e, eid) = engine();
        let actions = step(
            &mut e,
            Input::Connect {
                profile: Some(id("reality")),
            },
        );
        assert!(actions.contains(&Action::StartRace {
            profiles: vec![id("reality")],
            endpoint: eid
        }));
    }

    #[test]
    fn a_requested_amneziawg_profile_is_started_directly_without_a_race() {
        let (mut e, eid) = engine();
        let actions = step(
            &mut e,
            Input::Connect {
                profile: Some(id("awg")),
            },
        );
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("awg"),
            endpoint: eid
        }));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::StartRace { .. })));
        assert!(matches!(e.phase(), Phase::Starting { .. }));
    }

    #[test]
    fn a_request_for_an_unknown_profile_fails_naming_it() {
        let (mut e, _) = engine();
        step(
            &mut e,
            Input::Connect {
                profile: Some(id("nope")),
            },
        );
        assert!(matches!(
            failed_cause(&e),
            FailureCause::ConfigurationInvalid { ref detail } if detail.contains("nope")
        ));
    }

    #[test]
    fn connecting_while_already_connecting_or_connected_does_nothing() {
        let (mut e, _) = connected();
        assert!(step(&mut e, connect()).is_empty());
        assert!(matches!(e.phase(), Phase::Connected { .. }));
        let (mut e, _) = engine();
        step(&mut e, connect());
        assert!(step(&mut e, connect()).is_empty());
        assert_eq!(e.phase(), &Phase::Probing);
    }

    #[test]
    fn a_new_connect_forgets_what_an_earlier_network_taught() {
        let mut e = Engine::new(
            vec![
                profile("hy2", ProfileKind::Hysteria2),
                profile("reality", ProfileKind::VlessReality),
            ],
            vec![healthy("main", 30)],
        );
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert!(matches!(failed_cause(&e), FailureCause::AllProfilesBlocked));
        assert!(e
            .profiles()
            .iter()
            .any(|p| matches!(p.viability(), Viability::Blocked { .. })));
        let actions = step(&mut e, connect());
        assert!(
            e.profiles()
                .iter()
                .all(|p| p.viability() == &Viability::Untested),
            "a retry starts from Untested"
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::StartRace { .. })));
    }

    // ------------------------------------------------------------- the race

    #[test]
    fn a_race_winner_starts_a_tunnel_with_an_event_that_says_why() {
        let (mut e, eid) = engine();
        step(&mut e, connect());
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: selected("reality", 85),
                results: vec![
                    (id("reality"), good(1_000_000)),
                    (id("hy2"), ProfileProbe::HandshakeFailed),
                ],
            },
        );
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("reality"),
            endpoint: eid
        }));
        let because = events(&actions)
            .into_iter()
            .find_map(|ev| match ev {
                ConnectionEvent::ProfileSelected { profile, because }
                    if *profile == id("reality") =>
                {
                    Some(because.clone())
                }
                _ => None,
            })
            .expect("a ProfileSelected event");
        assert!(because.contains("85"), "{because}");
        assert!(matches!(
            e.phase(),
            Phase::Starting { profile, .. } if *profile == id("reality")
        ));
    }

    #[test]
    fn the_race_results_are_recorded_on_the_profiles() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("reality", 85),
                results: vec![
                    (id("reality"), good(1_000_000)),
                    (id("hy2"), ProfileProbe::HandshakeFailed),
                ],
            },
        );
        let by_id = |name: &str| {
            e.profiles()
                .iter()
                .find(|p| p.id() == &id(name))
                .unwrap()
                .viability()
                .clone()
        };
        assert!(matches!(by_id("reality"), Viability::Working { .. }));
        assert!(
            matches!(by_id("hy2"), Viability::Blocked { ref reason, .. } if reason.contains("connect"))
        );
        assert_eq!(by_id("awg"), Viability::Untested);
    }

    #[test]
    fn a_profile_that_never_reported_is_blocked_only_when_nobody_won() {
        // No winner: the silent profile ran out of time.
        let (mut e, _) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("reality"), ProfileProbe::HandshakeFailed)],
            },
        );
        let hy2 = e.profiles().iter().find(|p| p.id() == &id("hy2")).unwrap();
        assert!(matches!(
            hy2.viability(),
            Viability::Blocked { reason, .. } if reason.contains("in time")
        ));

        // A winner: the aborted loser is untested, not blocked.
        let (mut e, _) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("reality", 85),
                results: vec![(id("reality"), good(1_000_000))],
            },
        );
        let hy2 = e.profiles().iter().find(|p| p.id() == &id("hy2")).unwrap();
        assert_eq!(hy2.viability(), &Viability::Untested);
    }

    #[test]
    fn a_tier2_winner_warns_before_connecting() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        assert!(actions.contains(&Action::WarnTier2 { profile: id("hy2") }));
    }

    #[test]
    fn a_tier1_winner_does_not_warn() {
        let e = healthy("main", 30);
        let tier1 = ConnectionProfile::measured(
            id("hy2"),
            ProfileKind::Hysteria2,
            ProfileParams::new(),
            SurvivalMeasurement::Survived,
        );
        let mut engine = Engine::new(vec![tier1], vec![e]);
        step(&mut engine, connect());
        let actions = step(
            &mut engine,
            Input::RaceFinished {
                decision: RaceDecision::Selected {
                    profile: id("hy2"),
                    tier: crate::tier::FailoverTier::Tier1,
                    bits_per_sec: 1_000_000,
                },
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::WarnTier2 { .. })));
    }

    #[test]
    fn nothing_usable_tries_amneziawg_directly_as_a_last_resort() {
        let (mut e, eid) = engine();
        step(&mut e, connect());
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![
                    (id("hy2"), ProfileProbe::HandshakeFailed),
                    (id("reality"), ProfileProbe::HandshakeOnly),
                ],
            },
        );
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("awg"),
            endpoint: eid
        }));
        let because = events(&actions)
            .into_iter()
            .find_map(|ev| match ev {
                ConnectionEvent::ProfileSelected { because, .. } => Some(because.clone()),
                _ => None,
            })
            .unwrap();
        assert!(because.to_lowercase().contains("directly"), "{because}");
    }

    #[test]
    fn nothing_usable_and_nothing_left_to_try_is_all_profiles_blocked() {
        let e = healthy("main", 30);
        let mut engine = Engine::new(
            vec![
                profile("hy2", ProfileKind::Hysteria2),
                profile("reality", ProfileKind::VlessReality),
            ],
            vec![e],
        );
        step(&mut engine, connect());
        step(
            &mut engine,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![
                    (id("hy2"), ProfileProbe::HandshakeFailed),
                    (id("reality"), ProfileProbe::HandshakeFailed),
                ],
            },
        );
        assert_eq!(failed_cause(&engine), FailureCause::AllProfilesBlocked);
    }

    /// When no profile worked, the direct reachability check says whether the endpoint is at fault.
    #[test]
    fn unreachable_endpoints_make_a_failed_race_no_endpoint_reachable() {
        let mut engine = Engine::new(
            vec![profile("hy2", ProfileKind::Hysteria2)],
            vec![healthy("main", 30)],
        );
        step(&mut engine, connect());
        step(&mut engine, Input::Reach(vec![Reach::Unreachable]));
        step(
            &mut engine,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert_eq!(failed_cause(&engine), FailureCause::NoEndpointReachable);
    }

    #[test]
    fn a_race_result_outside_a_race_is_ignored() {
        let (mut e, _) = engine();
        assert!(step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 1),
                results: vec![]
            }
        )
        .is_empty());
        assert_eq!(e.phase(), &Phase::Idle);
    }

    // ------------------------------------------------------------- starting

    #[test]
    fn the_tunnel_coming_up_makes_the_connection() {
        let (e, _) = connected();
        assert!(matches!(
            e.phase(),
            Phase::Connected { profile, .. } if *profile == id("hy2")
        ));
    }

    #[test]
    fn the_tunnel_failing_to_start_fails_the_connection_and_stops_it() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 10),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        let cause = FailureCause::CoreFailedPersistently {
            core: crate::profile::CoreBinding::PrimaryCore,
        };
        let actions = step(&mut e, Input::StartFailed(cause.clone()));
        assert_eq!(failed_cause(&e), cause);
        assert!(actions.contains(&Action::StopTunnel));
    }

    #[test]
    fn tunnel_up_or_failed_outside_starting_are_ignored() {
        let (mut e, _) = engine();
        assert!(step(&mut e, Input::TunnelUp).is_empty());
        assert!(step(&mut e, Input::StartFailed(FailureCause::NoUsablePath)).is_empty());
        assert_eq!(e.phase(), &Phase::Idle);
    }

    // --------------------------------------------------------- live checks

    #[test]
    fn live_checks_outside_a_connection_are_ignored() {
        let (mut e, _) = engine();
        assert!(step(&mut e, Input::LiveCheck(LiveCheck::Failed)).is_empty());
    }

    #[test]
    fn a_flaky_connection_is_not_blocked() {
        let (mut e, _) = connected();
        for _ in 0..20 {
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
            step(&mut e, Input::LiveCheck(LiveCheck::Passed));
        }
        assert!(matches!(e.phase(), Phase::Connected { .. }));
    }

    #[test]
    fn a_block_stops_the_tunnel_then_races_what_is_left() {
        let (mut e, eid) = connected();
        let mut last = Vec::new();
        for _ in 0..BLOCK_AFTER {
            last = step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        assert_eq!(e.phase(), &Phase::Recovering);
        // The tunnel stops first, so the posture is fail-closed while another is found.
        let stop = last.iter().position(|a| *a == Action::StopTunnel).unwrap();
        let race = last
            .iter()
            .position(|a| matches!(a, Action::StartRace { .. }))
            .unwrap();
        assert!(stop < race);
        assert!(last.contains(&Action::StartRace {
            profiles: vec![id("reality")],
            endpoint: eid
        }));
        assert!(events(&last).iter().any(|ev| matches!(
            ev,
            ConnectionEvent::ProfileBlocked { profile, reason }
                if *profile == id("hy2") && !reason.is_empty()
        )));
    }

    #[test]
    fn live_checks_after_a_block_are_ignored_while_recovering() {
        let (mut e, _) = connected();
        for _ in 0..BLOCK_AFTER {
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        assert_eq!(e.phase(), &Phase::Recovering);
        assert!(step(&mut e, Input::LiveCheck(LiveCheck::Failed)).is_empty());
        assert_eq!(e.phase(), &Phase::Recovering);
    }

    #[test]
    fn recovery_that_finds_a_profile_replaces_the_blocked_one() {
        let (mut e, eid) = connected();
        for _ in 0..BLOCK_AFTER {
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: selected("reality", 40),
                results: vec![(id("reality"), good(1_000_000))],
            },
        );
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("reality"),
            endpoint: eid
        }));
        let because = events(&actions)
            .into_iter()
            .find_map(|ev| match ev {
                ConnectionEvent::ProfileSelected { because, .. } => Some(because.clone()),
                _ => None,
            })
            .unwrap();
        assert!(
            because.contains("hy2"),
            "names the profile it replaces: {because}"
        );
    }

    #[test]
    fn a_block_with_nothing_left_to_try_fails_at_once() {
        let e = healthy("main", 30);
        let mut engine = Engine::new(vec![profile("hy2", ProfileKind::Hysteria2)], vec![e]);
        step(&mut engine, connect());
        step(
            &mut engine,
            Input::RaceFinished {
                decision: selected("hy2", 10),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut engine, Input::TunnelUp);
        let mut last = Vec::new();
        for _ in 0..BLOCK_AFTER {
            last = step(&mut engine, Input::LiveCheck(LiveCheck::Failed));
        }
        assert_eq!(failed_cause(&engine), FailureCause::AllProfilesBlocked);
        assert!(last.contains(&Action::StopTunnel));
    }

    #[test]
    fn a_block_with_only_amneziawg_left_tries_it_directly() {
        let (mut e, eid) = connected();
        for _ in 0..BLOCK_AFTER {
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        // reality loses the recovery race, so only amneziawg remains.
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("reality"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("awg"),
            endpoint: eid
        }));
    }

    // ------------------------------------------------------------ endpoints

    fn probe_failed(e: &mut Engine, endpoint: EndpointId) -> Vec<Action> {
        step(
            e,
            Input::EndpointProbe {
                endpoint,
                outcome: ProbeOutcome::Failed,
            },
        )
    }

    #[test]
    fn an_endpoint_that_stops_answering_moves_the_connection_to_another() {
        let active = healthy("active", 30);
        let other = healthy("other", 60);
        let (aid, oid) = (active.id(), other.id());
        let mut e = Engine::new(standard_profiles(), vec![active, other]);
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut e, Input::TunnelUp);

        assert!(probe_failed(&mut e, aid).is_empty());
        assert!(probe_failed(&mut e, aid).is_empty());
        let actions = probe_failed(&mut e, aid);

        assert!(actions.contains(&Action::StopTunnel));
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("hy2"),
            endpoint: oid
        }));
        assert!(events(&actions).iter().any(|ev| matches!(
            ev,
            ConnectionEvent::EndpointMigrated { from, to, because }
                if *from == aid && *to == oid && !because.is_empty()
        )));
        assert!(matches!(
            e.phase(),
            Phase::Starting { endpoint, .. } if *endpoint == oid
        ));
    }

    #[test]
    fn losing_the_only_endpoint_fails_as_no_endpoint_reachable() {
        let (mut e, eid) = connected();
        probe_failed(&mut e, eid);
        probe_failed(&mut e, eid);
        let actions = probe_failed(&mut e, eid);
        assert_eq!(failed_cause(&e), FailureCause::NoEndpointReachable);
        assert!(actions.contains(&Action::StopTunnel));
    }

    #[test]
    fn a_degraded_active_endpoint_is_kept() {
        let active = degraded("slow", 320);
        let aid = active.id();
        let mut e = Engine::new(standard_profiles(), vec![active]);
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 5),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut e, Input::TunnelUp);
        // Slow, lossy answers over and over still answer: the endpoint is kept.
        for _ in 0..20 {
            let slow_probe = Input::EndpointProbe {
                endpoint: aid,
                outcome: ProbeOutcome::Ok {
                    rtt: Duration::from_millis(400),
                    loss: true,
                },
            };
            assert!(step(&mut e, slow_probe).is_empty());
        }
        assert!(matches!(e.phase(), Phase::Connected { .. }));
    }

    #[test]
    fn probing_an_endpoint_that_is_not_in_use_only_updates_its_health() {
        let active = healthy("active", 30);
        let spare = endpoint("spare");
        let sid = spare.id();
        let mut e = Engine::new(standard_profiles(), vec![active, spare]);
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut e, Input::TunnelUp);
        assert!(probe_failed(&mut e, sid).is_empty());
        let spare = e.endpoints().iter().find(|x| x.id() == sid).unwrap();
        assert_eq!(
            spare.health().state,
            crate::health::HealthState::Unreachable
        );
        assert!(matches!(e.phase(), Phase::Connected { .. }));
    }

    #[test]
    fn a_probe_of_an_unknown_endpoint_is_ignored() {
        let (mut e, _) = engine();
        assert!(probe_failed(&mut e, EndpointId::new()).is_empty());
    }

    // ----------------------------------------------------------- disconnect

    #[test]
    fn disconnecting_from_idle_or_failed_does_nothing() {
        let (mut e, _) = engine();
        assert!(step(&mut e, Input::Disconnect).is_empty());
        let mut e = Engine::new(standard_profiles(), vec![]);
        step(&mut e, connect());
        assert!(step(&mut e, Input::Disconnect).is_empty());
        assert_eq!(e.phase(), &Phase::Idle);
    }

    #[test]
    fn disconnecting_while_connected_stops_the_tunnel() {
        let (mut e, _) = connected();
        let actions = step(&mut e, Input::Disconnect);
        assert_eq!(actions, vec![Action::StopTunnel]);
        assert_eq!(e.phase(), &Phase::Idle);
    }

    #[test]
    fn disconnecting_while_probing_or_recovering_cancels_the_race() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        assert_eq!(step(&mut e, Input::Disconnect), vec![Action::CancelRace]);
        assert_eq!(e.phase(), &Phase::Idle);

        let (mut e, _) = connected();
        for _ in 0..BLOCK_AFTER {
            step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        assert_eq!(step(&mut e, Input::Disconnect), vec![Action::CancelRace]);
    }

    #[test]
    fn disconnecting_while_starting_stops_the_tunnel() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        assert_eq!(step(&mut e, Input::Disconnect), vec![Action::StopTunnel]);
    }

    // ------------------------------------------------------------- honesty

    /// Every automatic event must explain itself (IPC-06): never empty, never just its own name.
    #[test]
    fn every_event_in_a_full_run_has_a_real_because() {
        let (mut e, _) = engine();
        let mut all = Vec::new();
        all.extend(step(&mut e, connect()));
        all.extend(step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        ));
        all.extend(step(&mut e, Input::TunnelUp));
        for _ in 0..BLOCK_AFTER {
            all.extend(step(&mut e, Input::LiveCheck(LiveCheck::Failed)));
        }
        for ev in events(&all) {
            let (name, because) = match ev {
                ConnectionEvent::ProfileSelected { because, .. } => {
                    ("ProfileSelected", because.as_str())
                }
                ConnectionEvent::ProfileBlocked { reason, .. } => {
                    ("ProfileBlocked", reason.as_str())
                }
                ConnectionEvent::EndpointMigrated { because, .. } => {
                    ("EndpointMigrated", because.as_str())
                }
                _ => continue,
            };
            assert!(
                !because.trim().is_empty(),
                "{name} has an empty explanation"
            );
            assert!(
                !because.trim().eq_ignore_ascii_case(name),
                "{name} only restates its name"
            );
        }
    }

    #[test]
    fn the_unusable_reasons_read_as_words() {
        for (probe, word) in [
            (ProfileProbe::HandshakeFailed, "connect"),
            (ProfileProbe::HandshakeOnly, "no data"),
            (good(10), "little data"),
            (
                ProfileProbe::Transferred {
                    bytes: 1_048_576,
                    elapsed: Duration::from_secs(60),
                },
                "slow",
            ),
        ] {
            let (mut e, _) = engine();
            step(&mut e, connect());
            step(
                &mut e,
                Input::RaceFinished {
                    decision: selected("reality", 5),
                    results: vec![(id("reality"), good(1_000_000)), (id("hy2"), probe)],
                },
            );
            let hy2 = e.profiles().iter().find(|p| p.id() == &id("hy2")).unwrap();
            let Viability::Blocked { reason, .. } = hy2.viability() else {
                panic!("hy2 should be blocked");
            };
            assert!(
                reason.to_lowercase().contains(word),
                "{probe:?} -> {reason:?} should mention {word:?}"
            );
            // judge agrees it was unusable.
            assert!(matches!(crate::probe::judge(probe), Verdict::Unusable(_)));
        }
    }

    // ------------------------------------------------- review follow-ups

    #[test]
    fn a_named_profile_that_fails_is_reported_not_replaced() {
        let (mut e, _) = engine();
        step(
            &mut e,
            Input::Connect {
                profile: Some(id("hy2")),
            },
        );
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::StartTunnel { .. })));
        let FailureCause::ConfigurationInvalid { detail } = failed_cause(&e) else {
            panic!("expected a configuration failure naming the profile");
        };
        assert!(
            detail.contains("hy2") && detail.contains("without naming"),
            "{detail}"
        );
        // The others were never tried, so they stay untested rather than blocked.
        let reality = e
            .profiles()
            .iter()
            .find(|p| p.id() == &id("reality"))
            .unwrap();
        assert_eq!(reality.viability(), &Viability::Untested);
    }

    #[test]
    fn amneziawg_is_a_last_resort_only_after_every_raced_profile_failed() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        // hy2 failed and reality never reported, but a winner-less race blocks both.
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::StartTunnel { profile, .. } if *profile == id("awg")
        )));
    }

    #[test]
    fn a_directly_started_profile_is_working_once_its_tunnel_is_up() {
        let (mut e, _) = engine();
        step(
            &mut e,
            Input::Connect {
                profile: Some(id("awg")),
            },
        );
        step(&mut e, Input::TunnelUp);
        let awg = e.profiles().iter().find(|p| p.id() == &id("awg")).unwrap();
        assert!(matches!(awg.viability(), Viability::Working { .. }));
    }

    #[test]
    fn a_block_while_the_network_is_down_is_not_blamed_on_the_profile() {
        let (mut e, _) = connected();
        step(
            &mut e,
            Input::Environment(Environment {
                usable_paths: 0,
                ..Environment::default()
            }),
        );
        let mut last = Vec::new();
        for _ in 0..BLOCK_AFTER {
            last = step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        assert_eq!(failed_cause(&e), FailureCause::NoUsablePath);
        assert!(last.contains(&Action::StopTunnel));
        assert!(
            e.profiles()
                .iter()
                .all(|p| !matches!(p.viability(), Viability::Blocked { .. })),
            "no profile is blamed for a lost network"
        );
    }

    #[test]
    fn a_block_on_an_endpoint_that_is_no_longer_usable_moves_the_endpoint_not_the_profile() {
        let active = healthy("active", 30);
        let other = healthy("other", 60);
        let oid = other.id();
        let mut e = Engine::new(standard_profiles(), vec![active, other]);
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        step(&mut e, Input::TunnelUp);
        e.endpoints[0].set_enabled(false);
        let mut last = Vec::new();
        for _ in 0..BLOCK_AFTER {
            last = step(&mut e, Input::LiveCheck(LiveCheck::Failed));
        }
        assert!(last.contains(&Action::StartTunnel {
            profile: id("hy2"),
            endpoint: oid
        }));
        let hy2 = e.profiles().iter().find(|p| p.id() == &id("hy2")).unwrap();
        assert!(!matches!(hy2.viability(), Viability::Blocked { .. }));
    }

    #[test]
    fn an_endpoint_that_dies_while_the_tunnel_is_starting_is_replaced() {
        let active = healthy("active", 30);
        let other = healthy("other", 60);
        let (aid, oid) = (active.id(), other.id());
        let mut e = Engine::new(standard_profiles(), vec![active, other]);
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: selected("hy2", 100),
                results: vec![(id("hy2"), good(1_000_000))],
            },
        );
        assert!(matches!(e.phase(), Phase::Starting { .. }));
        probe_failed(&mut e, aid);
        probe_failed(&mut e, aid);
        let actions = probe_failed(&mut e, aid);
        assert!(actions.contains(&Action::StopTunnel));
        assert!(actions.contains(&Action::StartTunnel {
            profile: id("hy2"),
            endpoint: oid
        }));
    }

    #[test]
    fn an_endpoint_that_dies_during_a_race_restarts_the_race_elsewhere() {
        let active = healthy("active", 30);
        let other = healthy("other", 60);
        let (aid, oid) = (active.id(), other.id());
        let mut e = Engine::new(standard_profiles(), vec![active, other]);
        step(&mut e, connect());
        probe_failed(&mut e, aid);
        probe_failed(&mut e, aid);
        let actions = probe_failed(&mut e, aid);
        assert_eq!(e.phase(), &Phase::Probing);
        let cancel = actions
            .iter()
            .position(|a| *a == Action::CancelRace)
            .unwrap();
        let restart = actions
            .iter()
            .position(|a| {
                *a == Action::StartRace {
                    profiles: vec![id("hy2"), id("reality")],
                    endpoint: oid,
                }
            })
            .unwrap();
        assert!(cancel < restart);
    }

    #[test]
    fn the_only_endpoint_dying_during_a_race_fails_the_connect() {
        let (mut e, eid) = engine();
        step(&mut e, connect());
        probe_failed(&mut e, eid);
        probe_failed(&mut e, eid);
        let actions = probe_failed(&mut e, eid);
        assert!(actions.contains(&Action::CancelRace));
        assert_eq!(failed_cause(&e), FailureCause::NoEndpointReachable);
    }

    #[test]
    fn a_winner_from_an_abandoned_race_is_ignored() {
        let (mut e, _) = engine();
        step(&mut e, connect());
        // "ghost" was never in this race: the result belongs to an earlier attempt.
        let actions = step(
            &mut e,
            Input::RaceFinished {
                decision: selected("ghost", 50),
                results: vec![],
            },
        );
        assert!(actions.is_empty());
        assert_eq!(e.phase(), &Phase::Probing);
    }

    #[test]
    fn reach_from_an_earlier_attempt_does_not_leak_into_a_new_one() {
        let mut e = Engine::new(
            vec![profile("hy2", ProfileKind::Hysteria2)],
            vec![healthy("main", 30)],
        );
        step(&mut e, connect());
        step(&mut e, Input::Reach(vec![Reach::Unreachable]));
        step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert_eq!(failed_cause(&e), FailureCause::NoEndpointReachable);
        // Same network, new attempt, no new reach report: the old one must not decide it.
        step(&mut e, connect());
        step(
            &mut e,
            Input::RaceFinished {
                decision: RaceDecision::NoneUsable,
                results: vec![(id("hy2"), ProfileProbe::HandshakeFailed)],
            },
        );
        assert_eq!(failed_cause(&e), FailureCause::AllProfilesBlocked);
    }
}
