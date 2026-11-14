// SPDX-License-Identifier: GPL-3.0-or-later
//! T170 — what the Registry is told (ADR-0008 section 3.6; step 2 of T170).
//!
//! The service already holds the facts: how the connection is doing (`StateSnapshot`) and how each network is
//! doing (`PathsSnapshot`). This turns them into one reading per part, and applies the readings to a
//! [`Registry`]. It is pure: nothing here reads a clock or touches the machine, so the whole mapping is tested
//! without Windows.
//!
//! **What is reported, and what is not (yet).** Network paths, the connection, the endpoint carrying it, the
//! routing decision, a sign-in page in the way, and each transport process the runtime can speak for. Not yet:
//! the adapter, name-server handling, the guard and each carrier, because nothing the service holds says how they
//! are doing, and a part with no facts must be absent rather than shown as fine.
//!
//! **Nothing sensitive.** A reading carries an opaque id and words about the part's state. It never carries an
//! endpoint's label or address or a network's name: those are what the diagnostics bundle redacts, and this feeds
//! a request any client of the pipe may make.
//!
//! **The routing reading is a decision, not proof.** `RoutingPosture` is what the engine decided; nothing at the
//! operating-system level enforces it yet (README, known limits), and the reading says so.

use std::time::Duration;

use tokio::time::Instant;

use dnet_core::failure::explain;
use dnet_core::path::{PathKind, PathRole};
use dnet_core::posture::RoutingPosture;
use dnet_core::profile::CoreBinding;
use dnet_core::quality::QualityBand;
use dnet_core::registry::{
    ComponentKind, ComponentState, Evidence, Observation, Registry, StateChange,
};
use dnet_core::session::FailureCause;
use dnet_core::telemetry::{PathView, PathsSnapshot};
use dnet_core::tier::FailoverTier;
use dnet_ipc::componentview::encode_components;
use dnet_ipc::protocol::{ConnectionStatus, StateSnapshot};
use dnet_supervisor::runtime::CoreHealth;

/// The kinds of part this module reports. A part of one of these kinds that is not in the latest readings is
/// gone (a network that was unplugged) and is removed; a part of any other kind belongs to someone else.
pub const OWNED_KINDS: [ComponentKind; 6] = [
    ComponentKind::NetworkPath,
    ComponentKind::Session,
    ComponentKind::Endpoint,
    ComponentKind::Routes,
    ComponentKind::CaptivePortal,
    ComponentKind::CoreProcess,
];

/// One part's account of itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub kind: ComponentKind,
    pub id: String,
    pub state: ComponentState,
    pub reason: String,
    pub evidence: Evidence,
}

/// The readings for the facts the service holds now, ordered by kind and id, with no word on the transport
/// processes.
pub fn readings(state: &StateSnapshot, paths: &PathsSnapshot) -> Vec<Reading> {
    readings_with_cores(state, paths, &[])
}

/// The same, with what the runtime says about each transport process. A process the runtime cannot speak for
/// (`CoreHealth::Unknown`) is left out: a part with no facts must be absent, not shown as fine.
pub fn readings_with_cores(
    state: &StateSnapshot,
    paths: &PathsSnapshot,
    cores: &[(CoreBinding, CoreHealth)],
) -> Vec<Reading> {
    let mut out = vec![session_reading(state), routes_reading(state)];
    out.extend(
        cores
            .iter()
            .filter_map(|(core, health)| core_reading(*core, *health)),
    );
    if let Some(endpoint) = &state.active_endpoint {
        out.extend(endpoint_reading(state.status, &endpoint.id));
    }
    if matches!(state.failure, Some(FailureCause::CaptivePortalUnsatisfied)) {
        out.push(Reading {
            kind: ComponentKind::CaptivePortal,
            id: "sign-in".into(),
            state: ComponentState::Blocked,
            reason: explain(&FailureCause::CaptivePortalUnsatisfied).title,
            evidence: Evidence::default(),
        });
    }
    out.extend(
        paths
            .paths
            .iter()
            .map(|view| path_reading(view, paths.degradation.as_ref())),
    );
    out.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    out
}

/// A transport process, named by role and never by what it is built from (the branding rule).
fn core_reading(core: CoreBinding, health: CoreHealth) -> Option<Reading> {
    let (id, name) = match core {
        CoreBinding::PrimaryCore => ("primary", "primary"),
        CoreBinding::AmneziaWgCore => ("amneziawg", "AmneziaWG"),
    };
    let (state, reason) = match health {
        CoreHealth::Unknown => return None,
        CoreHealth::Running => (
            ComponentState::Ok,
            format!("The {name} transport process is running"),
        ),
        CoreHealth::Exited { code } => {
            // Windows writes a crash as a hexadecimal status (0xC0000005), not as the signed number it arrives as.
            let how = match code {
                Some(code) if code < 0 => format!("exit code 0x{:08X}", code as u32),
                Some(code) => format!("exit code {code}"),
                None => "no exit code".to_owned(),
            };
            (
                ComponentState::Failed,
                format!("The {name} transport process stopped unexpectedly ({how})"),
            )
        }
    };
    Some(reading(ComponentKind::CoreProcess, id, state, reason))
}

fn reading(kind: ComponentKind, id: &str, state: ComponentState, reason: String) -> Reading {
    Reading {
        kind,
        id: id.to_owned(),
        state,
        reason,
        evidence: Evidence::default(),
    }
}

fn session_reading(state: &StateSnapshot) -> Reading {
    let (part, reason) = match state.status {
        ConnectionStatus::Disconnected => (ComponentState::Off, "Not connected".to_owned()),
        ConnectionStatus::Probing => (
            ComponentState::Starting,
            "Choosing a connection method".to_owned(),
        ),
        ConnectionStatus::Connected => (ComponentState::Ok, connected_words(state)),
        ConnectionStatus::Failed => (
            ComponentState::Failed,
            state
                .failure
                .as_ref()
                .map(|cause| explain(cause).title)
                .unwrap_or_else(|| "The connection failed".to_owned()),
        ),
    };
    reading(ComponentKind::Session, "connection", part, reason)
}

fn connected_words(state: &StateSnapshot) -> String {
    match &state.active_profile {
        Some(profile) => {
            let tier = match profile.tier {
                FailoverTier::Tier1 => "Open connections survive a change of network.",
                FailoverTier::Tier2 => "Open connections drop when the network changes.",
            };
            format!("Connected through {}. {tier}", profile.kind)
        }
        None => "Connected".to_owned(),
    }
}

/// The routing reading is the engine's decision; the words say it is not yet enforced by the system.
fn routes_reading(state: &StateSnapshot) -> Reading {
    const DECISION: &str =
        "This is the service's decision, not yet enforced by the operating system";
    let (part, reason) = match (state.status, &state.posture) {
        (ConnectionStatus::Disconnected, _) => (ComponentState::Off, "Not connected".to_owned()),
        (ConnectionStatus::Connected, RoutingPosture::Tunnelled { .. }) => (
            ComponentState::Ok,
            format!("Traffic that needs the tunnel goes through it. {DECISION}"),
        ),
        (_, RoutingPosture::Tunnelled { .. }) => (
            ComponentState::Starting,
            "The tunnel is coming up".to_owned(),
        ),
        (_, RoutingPosture::FailClosed) => (
            ComponentState::Blocked,
            format!("No usable tunnel: traffic that needs it is dropped (fail closed). {DECISION}"),
        ),
    };
    reading(ComponentKind::Routes, "posture", part, reason)
}

/// Named by its opaque id only: the label is the person's own and is never put in a reading.
fn endpoint_reading(status: ConnectionStatus, id: &str) -> Option<Reading> {
    let (part, reason) = match status {
        ConnectionStatus::Connected => (ComponentState::Ok, "Carrying the connection"),
        ConnectionStatus::Probing => (ComponentState::Starting, "Being tried"),
        ConnectionStatus::Failed => (ComponentState::Failed, "Could not be used"),
        ConnectionStatus::Disconnected => return None,
    };
    Some(reading(
        ComponentKind::Endpoint,
        id,
        part,
        reason.to_owned(),
    ))
}

fn path_reading(
    view: &PathView,
    degradation: Option<&dnet_core::degraded::Degradation>,
) -> Reading {
    // A reported degradation is a judgement about this network that has already waited out its own clocks, so
    // it wins over the latest single band. A band without a measurement behind it is not a band.
    let reported = degradation.filter(|d| d.path == view.id).map(|d| d.band);
    let band = reported.or(if view.measured { view.band } else { None });
    let kind = match view.kind {
        PathKind::Wifi => "Wi-Fi",
        PathKind::Cellular => "Cellular",
        PathKind::Ethernet => "Ethernet",
        PathKind::Other => "Network",
    };
    let (part, reason) = match (view.role, band) {
        (PathRole::Unusable, _) | (PathRole::Standby, Some(QualityBand::Unusable)) => {
            (ComponentState::Off, format!("{kind}: not usable right now"))
        }
        (PathRole::Carrying, None) => (
            ComponentState::Unknown,
            format!("{kind}: carrying the connection; not measured yet"),
        ),
        (PathRole::Carrying, Some(QualityBand::Good)) => (
            ComponentState::Ok,
            format!("{kind}: carrying the connection"),
        ),
        (PathRole::Carrying, Some(QualityBand::Poor)) => (
            ComponentState::Degraded,
            format!("{kind}: carrying the connection, but lossy or slow"),
        ),
        (PathRole::Carrying, Some(QualityBand::Unusable)) => (
            ComponentState::Failed,
            format!("{kind}: carrying the connection, but not usable"),
        ),
        (PathRole::Standby, None) => (
            ComponentState::Unknown,
            format!("{kind}: available; not measured yet"),
        ),
        (PathRole::Standby, Some(QualityBand::Good)) => (
            ComponentState::Ok,
            format!("{kind}: available, not carrying"),
        ),
        (PathRole::Standby, Some(QualityBand::Poor)) => (
            ComponentState::Degraded,
            format!("{kind}: available but lossy or slow, not carrying"),
        ),
    };
    Reading {
        kind: ComponentKind::NetworkPath,
        id: format!("interface-{}", view.id.luid()),
        state: part,
        reason,
        evidence: Evidence {
            latency_ms: view
                .rtt
                .map(|rtt| u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)),
            loss_permille: view
                .loss
                .map(|loss| (loss * 1000.0).round().clamp(0.0, 1000.0) as u16),
            restarts: None,
        },
    }
}

/// A part that was added, changed state, or was removed by [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub kind: ComponentKind,
    pub id: String,
    pub change: Option<StateChange>,
    pub removed: bool,
}

/// Bring `registry` in line with `readings` at `now`: report each one, and remove any part of an owned kind that
/// is no longer reported. Returns only what changed. A full registry refuses a new part; that part is left out
/// rather than another being dropped, and the rest are still applied.
pub fn apply(registry: &mut Registry, readings: &[Reading], now: Duration) -> Vec<Applied> {
    let mut applied = Vec::new();
    for r in readings {
        let seen = Observation::new(r.state, &r.reason).with_evidence(r.evidence);
        match registry.report(r.kind, &r.id, seen, now) {
            Ok(Some(change)) => applied.push(Applied {
                kind: r.kind,
                id: r.id.clone(),
                change: Some(change),
                removed: false,
            }),
            Ok(None) => {}
            // A full registry or an empty id: this part is left out and the rest are still applied. Say so,
            // because a part that is silently missing from the map would read as healthy.
            Err(error) => tracing::warn!(kind = ?r.kind, %error, "a component was not recorded"),
        }
    }
    let gone: Vec<_> = registry
        .snapshot()
        .into_iter()
        .filter(|c| OWNED_KINDS.contains(&c.kind))
        .filter(|c| !readings.iter().any(|r| r.kind == c.kind && r.id == c.id))
        .collect();
    for part in gone {
        registry.remove(part.kind, &part.id);
        applied.push(Applied {
            kind: part.kind,
            id: part.id,
            change: None,
            removed: true,
        });
    }
    applied
}

/// The service's one Registry, and the clock its times are taken from (time since the service started, so
/// the wall clock being set backward or forward never moves a part's age).
pub struct Tracker {
    registry: Registry,
    epoch: Instant,
    /// What the runtime last said about each transport process.
    cores: Vec<(CoreBinding, CoreHealth)>,
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            registry: Registry::new(),
            epoch: Instant::now(),
            cores: Vec::new(),
        }
    }

    /// Replace what is known about the transport processes. A process left out is gone from the map at the next
    /// observation.
    pub fn set_cores(&mut self, cores: Vec<(CoreBinding, CoreHealth)>) {
        self.cores = cores;
    }

    /// Record what the service knows at `now`. Returns what changed.
    pub fn observe_at(
        &mut self,
        now: Duration,
        state: &StateSnapshot,
        paths: &PathsSnapshot,
    ) -> Vec<Applied> {
        apply(
            &mut self.registry,
            &readings_with_cores(state, paths, &self.cores),
            now,
        )
    }

    /// Write the reply for `GetComponents` from what has been recorded, ages counted back from `now`.
    pub fn encode(&self, now: Duration, as_of_unix_ms: u64) -> String {
        encode_components(&self.registry.snapshot(), now, as_of_unix_ms)
    }

    /// Record the facts now. The service calls this every second, so a state's age is the moment it changed.
    pub fn refresh(&mut self, state: &StateSnapshot, paths: &PathsSnapshot) {
        let now = self.epoch.elapsed();
        self.observe_at(now, state, paths);
    }

    /// Look at the facts now, record them, and answer.
    pub fn reply(
        &mut self,
        state: &StateSnapshot,
        paths: &PathsSnapshot,
        as_of_unix_ms: u64,
    ) -> String {
        let now = self.epoch.elapsed();
        self.observe_at(now, state, paths);
        self.encode(now, as_of_unix_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::degraded::{Degradation, NoMove};
    use dnet_core::ids::InterfaceId;
    use dnet_ipc::protocol::{ActiveEndpoint, ActiveProfile};

    const T0: Duration = Duration::from_secs(10);

    fn state(status: ConnectionStatus) -> StateSnapshot {
        StateSnapshot {
            status,
            active_profile: None,
            active_endpoint: None,
            failure: None,
            warnings: vec![],
            posture: RoutingPosture::FailClosed,
        }
    }

    fn connected() -> StateSnapshot {
        StateSnapshot {
            active_profile: Some(ActiveProfile {
                id: "p1".into(),
                kind: "Hysteria2".into(),
                tier: FailoverTier::Tier2,
            }),
            active_endpoint: Some(ActiveEndpoint {
                id: "e1".into(),
                label: "my-secret-server".into(),
            }),
            posture: RoutingPosture::Tunnelled {
                tier: FailoverTier::Tier2,
            },
            ..state(ConnectionStatus::Connected)
        }
    }

    fn view(luid: u64, kind: PathKind, role: PathRole, band: Option<QualityBand>) -> PathView {
        PathView {
            id: InterfaceId::new(luid),
            kind,
            name: Some("HomeWifi".into()),
            role,
            measured: band.is_some(),
            band,
            rtt: None,
            jitter: None,
            loss: None,
            trace_ms: vec![],
            typical_ms: None,
        }
    }

    fn paths(views: Vec<PathView>) -> PathsSnapshot {
        PathsSnapshot {
            paths: views,
            degradation: None,
        }
    }

    fn find<'a>(rs: &'a [Reading], kind: ComponentKind, id: &str) -> &'a Reading {
        rs.iter()
            .find(|r| r.kind == kind && r.id == id)
            .unwrap_or_else(|| panic!("no reading for {kind:?} {id}: {rs:#?}"))
    }

    fn kinds(rs: &[Reading]) -> Vec<ComponentKind> {
        rs.iter().map(|r| r.kind).collect()
    }

    #[test]
    fn disconnected_reports_the_connection_and_routing_as_off_and_nothing_else() {
        let rs = readings(&state(ConnectionStatus::Disconnected), &paths(vec![]));
        assert_eq!(
            kinds(&rs),
            vec![ComponentKind::Session, ComponentKind::Routes]
        );
        assert_eq!(
            find(&rs, ComponentKind::Session, "connection").state,
            ComponentState::Off
        );
        assert_eq!(
            find(&rs, ComponentKind::Routes, "posture").state,
            ComponentState::Off
        );
    }

    #[test]
    fn a_connected_service_reports_the_connection_endpoint_and_routing_as_ok() {
        let rs = readings(&connected(), &paths(vec![]));
        let session = find(&rs, ComponentKind::Session, "connection");
        assert_eq!(session.state, ComponentState::Ok);
        assert!(session.reason.contains("Hysteria2"), "{}", session.reason);
        assert!(
            session.reason.contains("drop"),
            "a Tier 2 connection says established connections drop: {}",
            session.reason
        );
        assert_eq!(
            find(&rs, ComponentKind::Endpoint, "e1").state,
            ComponentState::Ok
        );
        assert_eq!(
            find(&rs, ComponentKind::Routes, "posture").state,
            ComponentState::Ok
        );
    }

    #[test]
    fn a_tier_1_connection_says_established_connections_survive() {
        let mut s = connected();
        s.active_profile.as_mut().unwrap().tier = FailoverTier::Tier1;
        let rs = readings(&s, &paths(vec![]));
        assert!(find(&rs, ComponentKind::Session, "connection")
            .reason
            .contains("survive"));
    }

    #[test]
    fn probing_is_starting_and_routing_is_blocked_until_a_tunnel_exists() {
        let mut s = state(ConnectionStatus::Probing);
        s.active_endpoint = Some(ActiveEndpoint {
            id: "e1".into(),
            label: "x".into(),
        });
        let rs = readings(&s, &paths(vec![]));
        assert_eq!(
            find(&rs, ComponentKind::Session, "connection").state,
            ComponentState::Starting
        );
        assert_eq!(
            find(&rs, ComponentKind::Endpoint, "e1").state,
            ComponentState::Starting
        );
        let routes = find(&rs, ComponentKind::Routes, "posture");
        assert_eq!(routes.state, ComponentState::Blocked);
        assert!(routes.reason.contains("fail closed"), "{}", routes.reason);
    }

    #[test]
    fn a_tunnel_still_coming_up_is_starting_not_ok() {
        let mut s = connected();
        s.status = ConnectionStatus::Probing;
        let rs = readings(&s, &paths(vec![]));
        assert_eq!(
            find(&rs, ComponentKind::Routes, "posture").state,
            ComponentState::Starting
        );
    }

    #[test]
    fn a_failure_is_the_services_own_title_and_routing_is_blocked() {
        let mut s = state(ConnectionStatus::Failed);
        s.failure = Some(FailureCause::NoUsablePath);
        let rs = readings(&s, &paths(vec![]));
        let session = find(&rs, ComponentKind::Session, "connection");
        assert_eq!(session.state, ComponentState::Failed);
        assert_eq!(session.reason, explain(&FailureCause::NoUsablePath).title);
        assert_eq!(
            find(&rs, ComponentKind::Routes, "posture").state,
            ComponentState::Blocked
        );
    }

    #[test]
    fn a_failure_with_no_cause_still_says_something() {
        let rs = readings(&state(ConnectionStatus::Failed), &paths(vec![]));
        assert!(!find(&rs, ComponentKind::Session, "connection")
            .reason
            .is_empty());
    }

    #[test]
    fn a_sign_in_page_in_the_way_is_its_own_blocked_part_and_only_then() {
        let mut s = state(ConnectionStatus::Failed);
        s.failure = Some(FailureCause::CaptivePortalUnsatisfied);
        let rs = readings(&s, &paths(vec![]));
        assert_eq!(
            find(&rs, ComponentKind::CaptivePortal, "sign-in").state,
            ComponentState::Blocked
        );
        let rs = readings(&connected(), &paths(vec![]));
        assert!(!kinds(&rs).contains(&ComponentKind::CaptivePortal));
    }

    #[test]
    fn each_network_is_reported_by_what_it_is_doing() {
        let rs = readings(
            &connected(),
            &paths(vec![
                view(
                    1,
                    PathKind::Wifi,
                    PathRole::Carrying,
                    Some(QualityBand::Good),
                ),
                view(
                    2,
                    PathKind::Ethernet,
                    PathRole::Standby,
                    Some(QualityBand::Good),
                ),
                view(
                    3,
                    PathKind::Cellular,
                    PathRole::Standby,
                    Some(QualityBand::Poor),
                ),
                view(4, PathKind::Other, PathRole::Unusable, None),
                view(5, PathKind::Wifi, PathRole::Standby, None),
            ]),
        );
        let state_of = |id: &str| find(&rs, ComponentKind::NetworkPath, id).state;
        assert_eq!(state_of("interface-1"), ComponentState::Ok);
        assert_eq!(state_of("interface-2"), ComponentState::Ok);
        assert_eq!(state_of("interface-3"), ComponentState::Degraded);
        assert_eq!(state_of("interface-4"), ComponentState::Off);
        assert_eq!(
            state_of("interface-5"),
            ComponentState::Unknown,
            "a network nobody has measured is not shown as fine"
        );
    }

    #[test]
    fn the_carrying_network_is_judged_harder_than_a_standby_one() {
        let rs = readings(
            &connected(),
            &paths(vec![
                view(
                    1,
                    PathKind::Wifi,
                    PathRole::Carrying,
                    Some(QualityBand::Poor),
                ),
                view(
                    2,
                    PathKind::Wifi,
                    PathRole::Carrying,
                    Some(QualityBand::Unusable),
                ),
                view(3, PathKind::Wifi, PathRole::Carrying, None),
            ]),
        );
        let state_of = |id: &str| find(&rs, ComponentKind::NetworkPath, id).state;
        assert_eq!(state_of("interface-1"), ComponentState::Degraded);
        assert_eq!(state_of("interface-2"), ComponentState::Failed);
        assert_eq!(state_of("interface-3"), ComponentState::Unknown);
    }

    #[test]
    fn a_reported_degradation_overrides_the_measured_band_of_that_network() {
        let mut p = paths(vec![view(
            1,
            PathKind::Wifi,
            PathRole::Carrying,
            Some(QualityBand::Good),
        )]);
        p.degradation = Some(Degradation {
            path: InterfaceId::new(1),
            band: QualityBand::Poor,
            staying: NoMove::OnlyPath,
        });
        let rs = readings(&connected(), &p);
        assert_eq!(
            find(&rs, ComponentKind::NetworkPath, "interface-1").state,
            ComponentState::Degraded
        );
    }

    #[test]
    fn evidence_is_the_measured_latency_and_loss() {
        let mut v = view(
            1,
            PathKind::Wifi,
            PathRole::Carrying,
            Some(QualityBand::Good),
        );
        v.rtt = Some(Duration::from_millis(95));
        v.loss = Some(0.034);
        let rs = readings(&connected(), &paths(vec![v]));
        let e = find(&rs, ComponentKind::NetworkPath, "interface-1").evidence;
        assert_eq!(e.latency_ms, Some(95));
        assert_eq!(e.loss_permille, Some(34));
        assert_eq!(e.restarts, None);
    }

    #[test]
    fn no_endpoint_label_and_no_network_name_reaches_a_reading() {
        let rs = readings(
            &connected(),
            &paths(vec![view(
                1,
                PathKind::Wifi,
                PathRole::Carrying,
                Some(QualityBand::Good),
            )]),
        );
        for r in &rs {
            for secret in ["my-secret-server", "HomeWifi"] {
                assert!(
                    !r.reason.contains(secret) && !r.id.contains(secret),
                    "{secret} leaked: {r:?}"
                );
            }
        }
    }

    #[test]
    fn the_free_text_a_failure_carries_never_reaches_a_reading() {
        // `ConfigurationInvalid` and `CoreFailedPersistently` keep their free text in the *detail* of an
        // explanation; the reading uses only the title. If a title ever began to include the detail, this fails.
        let marker = "SECRET-DETAIL-MARKER";
        for cause in [
            FailureCause::ConfigurationInvalid {
                detail: marker.to_string(),
            },
            FailureCause::CoreFailedPersistently {
                core: dnet_core::profile::CoreBinding::PrimaryCore,
            },
        ] {
            let mut s = state(ConnectionStatus::Failed);
            s.failure = Some(cause);
            for r in readings(&s, &paths(vec![])) {
                assert!(
                    !r.reason.contains(marker) && !r.id.contains(marker),
                    "{r:?}"
                );
            }
        }
    }

    #[test]
    fn readings_come_ordered_by_kind_then_id() {
        let rs = readings(
            &connected(),
            &paths(vec![
                view(
                    9,
                    PathKind::Wifi,
                    PathRole::Standby,
                    Some(QualityBand::Good),
                ),
                view(
                    2,
                    PathKind::Wifi,
                    PathRole::Carrying,
                    Some(QualityBand::Good),
                ),
            ]),
        );
        let order: Vec<_> = rs.iter().map(|r| (r.kind, r.id.clone())).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
    }

    #[test]
    fn the_first_apply_adds_everything_and_the_second_changes_nothing() {
        let mut reg = Registry::new();
        let rs = readings(
            &connected(),
            &paths(vec![view(
                1,
                PathKind::Wifi,
                PathRole::Carrying,
                Some(QualityBand::Good),
            )]),
        );
        let first = apply(&mut reg, &rs, T0);
        assert_eq!(first.len(), rs.len());
        assert!(first.iter().all(|a| a.change.is_some() && !a.removed));
        assert!(apply(&mut reg, &rs, T0 + Duration::from_secs(5)).is_empty());
        assert_eq!(reg.len(), rs.len());
    }

    #[test]
    fn a_change_of_state_is_returned_with_what_it_was() {
        let mut reg = Registry::new();
        apply(&mut reg, &readings(&connected(), &paths(vec![])), T0);
        let later = readings(&state(ConnectionStatus::Disconnected), &paths(vec![]));
        let changes = apply(&mut reg, &later, T0 + Duration::from_secs(60));
        let session = changes
            .iter()
            .find(|a| a.kind == ComponentKind::Session)
            .expect("the connection changed");
        assert_eq!(
            session.change,
            Some(StateChange {
                from: Some(ComponentState::Ok),
                to: ComponentState::Off
            })
        );
        assert_eq!(
            reg.get(ComponentKind::Session, "connection")
                .unwrap()
                .changed_at,
            T0 + Duration::from_secs(60)
        );
    }

    #[test]
    fn a_network_that_goes_away_is_removed_and_so_is_the_endpoint_when_disconnected() {
        let mut reg = Registry::new();
        let p = paths(vec![view(
            1,
            PathKind::Wifi,
            PathRole::Carrying,
            Some(QualityBand::Good),
        )]);
        apply(&mut reg, &readings(&connected(), &p), T0);
        let changes = apply(
            &mut reg,
            &readings(&state(ConnectionStatus::Disconnected), &paths(vec![])),
            T0,
        );
        assert!(reg.get(ComponentKind::NetworkPath, "interface-1").is_none());
        assert!(reg.get(ComponentKind::Endpoint, "e1").is_none());
        assert!(changes
            .iter()
            .any(|a| a.removed && a.kind == ComponentKind::NetworkPath));
    }

    #[test]
    fn parts_of_other_kinds_are_left_alone() {
        let mut reg = Registry::new();
        reg.report(
            ComponentKind::Guard,
            "main",
            Observation::new(ComponentState::Ok, "installed"),
            T0,
        )
        .unwrap();
        apply(
            &mut reg,
            &readings(&state(ConnectionStatus::Disconnected), &paths(vec![])),
            T0,
        );
        assert!(reg.get(ComponentKind::Guard, "main").is_some());
    }

    #[test]
    fn a_tracker_answers_with_a_reply_a_client_can_read() {
        let mut tracker = Tracker::new();
        let wire = tracker.reply(
            &connected(),
            &paths(vec![view(
                1,
                PathKind::Wifi,
                PathRole::Carrying,
                Some(QualityBand::Good),
            )]),
            1_700_000_000_000,
        );
        let reply = dnet_ipc::componentview::decode_components(&wire)
            .expect("the service only serves what a client can read");
        assert_eq!(reply.as_of_unix_ms, 1_700_000_000_000);
        assert_eq!(reply.overall, ComponentState::Ok);
        assert!(reply
            .components
            .iter()
            .any(|c| c.kind == ComponentKind::Session && c.state == ComponentState::Ok));
    }

    #[test]
    fn a_state_that_stays_the_same_keeps_its_age_across_answers() {
        let mut tracker = Tracker::new();
        let facts = (connected(), paths(vec![]));
        tracker.observe_at(T0, &facts.0, &facts.1);
        tracker.observe_at(T0 + Duration::from_secs(60), &facts.0, &facts.1);
        let wire = tracker.encode(T0 + Duration::from_secs(60), 1);
        let reply = dnet_ipc::componentview::decode_components(&wire).unwrap();
        let session = reply
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Session)
            .unwrap();
        assert_eq!(
            session.changed_ago_ms, 60_000,
            "ok since the first look, not since the last"
        );
    }

    #[test]
    fn a_state_that_changes_restarts_its_age() {
        let mut tracker = Tracker::new();
        tracker.observe_at(T0, &connected(), &paths(vec![]));
        tracker.observe_at(
            T0 + Duration::from_secs(60),
            &state(ConnectionStatus::Disconnected),
            &paths(vec![]),
        );
        let wire = tracker.encode(T0 + Duration::from_secs(90), 1);
        let reply = dnet_ipc::componentview::decode_components(&wire).unwrap();
        let session = reply
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Session)
            .unwrap();
        assert_eq!(session.state, ComponentState::Off);
        assert_eq!(session.changed_ago_ms, 30_000);
    }

    #[test]
    fn no_reason_the_mapper_can_write_is_longer_than_a_client_will_accept() {
        let mut every = vec![
            state(ConnectionStatus::Disconnected),
            state(ConnectionStatus::Probing),
            connected(),
        ];
        for cause in [
            FailureCause::NoEndpointReachable,
            FailureCause::AllProfilesBlocked,
            FailureCause::CaptivePortalUnsatisfied,
            FailureCause::InsufficientPrivilege,
            FailureCause::NoUsablePath,
        ] {
            let mut s = state(ConnectionStatus::Failed);
            s.failure = Some(cause);
            every.push(s);
        }
        for s in &every {
            for r in readings(
                s,
                &paths(vec![view(
                    1,
                    PathKind::Cellular,
                    PathRole::Carrying,
                    Some(QualityBand::Unusable),
                )]),
            ) {
                assert!(
                    r.reason.chars().count() <= dnet_ipc::componentview::MAX_REASON_CHARS,
                    "{} characters: {}",
                    r.reason.chars().count(),
                    r.reason
                );
                assert!(r.id.chars().count() <= dnet_ipc::componentview::MAX_ID_CHARS);
            }
        }
    }

    #[test]
    fn a_full_registry_leaves_out_the_new_part_and_still_applies_the_rest() {
        let mut reg = Registry::new();
        for i in 0..dnet_core::registry::MAX_COMPONENTS {
            reg.report(
                ComponentKind::Guard,
                &format!("g{i}"),
                Observation::new(ComponentState::Ok, ""),
                T0,
            )
            .unwrap();
        }
        let applied = apply(&mut reg, &readings(&connected(), &paths(vec![])), T0);
        assert!(applied.is_empty(), "nothing new fits");
        assert_eq!(reg.len(), dnet_core::registry::MAX_COMPONENTS);
    }

    // ------------------------------------------------------------------------- the transport processes (T170)

    use dnet_core::profile::CoreBinding;
    use dnet_supervisor::runtime::CoreHealth;

    fn core_readings(cores: &[(CoreBinding, CoreHealth)]) -> Vec<Reading> {
        readings_with_cores(&connected(), &paths(vec![]), cores)
    }

    #[test]
    fn a_running_core_reads_ok() {
        let rs = core_readings(&[(CoreBinding::PrimaryCore, CoreHealth::Running)]);
        let r = find(&rs, ComponentKind::CoreProcess, "primary");
        assert_eq!(r.state, ComponentState::Ok);
        assert_eq!(r.reason, "The primary transport process is running");
    }

    #[test]
    fn a_core_that_exited_reads_failed_and_says_how() {
        let rs = core_readings(&[(
            CoreBinding::AmneziaWgCore,
            CoreHealth::Exited { code: Some(3) },
        )]);
        let r = find(&rs, ComponentKind::CoreProcess, "amneziawg");
        assert_eq!(r.state, ComponentState::Failed);
        assert_eq!(
            r.reason,
            "The AmneziaWG transport process stopped unexpectedly (exit code 3)"
        );
        let rs = core_readings(&[(CoreBinding::PrimaryCore, CoreHealth::Exited { code: None })]);
        assert!(find(&rs, ComponentKind::CoreProcess, "primary")
            .reason
            .ends_with("(no exit code)"));
    }

    #[test]
    fn a_crash_code_is_shown_as_windows_writes_it() {
        let rs = core_readings(&[(
            CoreBinding::PrimaryCore,
            CoreHealth::Exited {
                code: Some(-1_073_741_819),
            },
        )]);
        assert_eq!(
            find(&rs, ComponentKind::CoreProcess, "primary").reason,
            "The primary transport process stopped unexpectedly (exit code 0xC0000005)"
        );
    }

    #[test]
    fn a_core_nobody_can_speak_for_is_absent_not_shown_as_fine() {
        let rs = core_readings(&[(CoreBinding::PrimaryCore, CoreHealth::Unknown)]);
        assert!(!kinds(&rs).contains(&ComponentKind::CoreProcess), "{rs:#?}");
    }

    #[test]
    fn without_cores_the_readings_are_what_they_were() {
        assert_eq!(readings(&connected(), &paths(vec![])), core_readings(&[]));
    }

    #[test]
    fn no_core_reading_names_the_primary_cores_vendor() {
        let rs = core_readings(&[
            (CoreBinding::PrimaryCore, CoreHealth::Running),
            (
                CoreBinding::AmneziaWgCore,
                CoreHealth::Exited { code: Some(1) },
            ),
        ]);
        for r in rs.iter().filter(|r| r.kind == ComponentKind::CoreProcess) {
            let text = format!("{} {}", r.id, r.reason).to_lowercase();
            // Built at runtime: the branding lint reads this file for the names themselves.
            let banned = [
                ["sing", "-box"].concat(),
                ["sing", "box"].concat(),
                ["sager", "net"].concat(),
                ["wire", "guard"].concat(),
                ["win", "tun"].concat(),
            ];
            for banned in banned {
                assert!(!text.contains(&banned), "{text}");
            }
        }
    }

    #[test]
    fn a_core_that_goes_away_is_removed_from_the_map() {
        let mut tracker = Tracker::new();
        tracker.set_cores(vec![(CoreBinding::PrimaryCore, CoreHealth::Running)]);
        tracker.observe_at(T0, &connected(), &paths(vec![]));
        assert!(tracker
            .registry
            .get(ComponentKind::CoreProcess, "primary")
            .is_some());
        tracker.set_cores(vec![]);
        tracker.observe_at(T0 + Duration::from_secs(1), &connected(), &paths(vec![]));
        assert!(tracker
            .registry
            .get(ComponentKind::CoreProcess, "primary")
            .is_none());
    }

    #[test]
    fn a_core_that_dies_turns_failed_in_the_map() {
        let mut tracker = Tracker::new();
        tracker.set_cores(vec![(CoreBinding::PrimaryCore, CoreHealth::Running)]);
        tracker.observe_at(T0, &connected(), &paths(vec![]));
        tracker.set_cores(vec![(
            CoreBinding::PrimaryCore,
            CoreHealth::Exited { code: Some(1) },
        )]);
        let applied = tracker.observe_at(T0 + Duration::from_secs(5), &connected(), &paths(vec![]));
        assert!(applied
            .iter()
            .any(|a| a.kind == ComponentKind::CoreProcess && a.change.is_some()));
        let part = tracker
            .registry
            .get(ComponentKind::CoreProcess, "primary")
            .unwrap();
        assert_eq!(part.state, ComponentState::Failed);
    }
}

/// How a transport process's exit is worded: a crash status is shown the way Windows writes it (hexadecimal), and an
/// ordinary exit code is shown as the number it is. The edge between them is zero and minus one.
#[cfg(test)]
mod exit_wording_tests {
    use super::*;

    fn reason(code: Option<i32>) -> String {
        core_reading(CoreBinding::PrimaryCore, CoreHealth::Exited { code })
            .expect("an exited process is reported")
            .reason
    }

    #[test]
    fn an_exit_code_of_zero_is_the_number_zero_and_not_a_crash_status() {
        let text = reason(Some(0));
        assert!(text.ends_with("(exit code 0)"), "{text}");
        assert!(!text.contains("0x"), "{text}");
    }

    #[test]
    fn a_positive_exit_code_is_shown_as_the_number() {
        for code in [1, 2, 255, 1_000_000] {
            let text = reason(Some(code));
            assert!(text.ends_with(&format!("(exit code {code})")), "{text}");
        }
    }

    #[test]
    fn a_negative_status_is_shown_the_way_windows_writes_a_crash() {
        assert!(reason(Some(-1)).ends_with("(exit code 0xFFFFFFFF)"));
        assert!(reason(Some(-1_073_741_819)).ends_with("(exit code 0xC0000005)"));
        assert!(reason(Some(i32::MIN)).ends_with("(exit code 0x80000000)"));
    }

    #[test]
    fn an_exit_with_no_code_says_so_and_both_cores_are_named_by_role() {
        assert!(reason(None).ends_with("(no exit code)"));
        let awg = core_reading(
            CoreBinding::AmneziaWgCore,
            CoreHealth::Exited { code: Some(3) },
        )
        .unwrap();
        assert!(awg.reason.contains("AmneziaWG"), "{}", awg.reason);
        assert_eq!(awg.id, "amneziawg");
        let primary = core_reading(CoreBinding::PrimaryCore, CoreHealth::Running).unwrap();
        assert_eq!(primary.id, "primary");
        assert!(core_reading(CoreBinding::PrimaryCore, CoreHealth::Unknown).is_none());
    }
}

/// What the map forgets: a part is removed only when no reading names *that kind and that id*, never because some
/// other part of the same kind, or another kind with the same id, is still reported.
#[cfg(test)]
mod removal_tests {
    use super::*;

    const AT: Duration = Duration::from_secs(10);

    fn one(kind: ComponentKind, id: &str) -> Reading {
        reading(kind, id, ComponentState::Ok, "fine".to_owned())
    }

    fn present(registry: &Registry) -> Vec<(ComponentKind, String)> {
        let mut parts: Vec<_> = registry
            .snapshot()
            .into_iter()
            .map(|c| (c.kind, c.id))
            .collect();
        parts.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        parts
    }

    #[test]
    fn a_part_is_removed_when_another_of_its_kind_is_still_reported() {
        let mut registry = Registry::new();
        apply(
            &mut registry,
            &[
                one(ComponentKind::NetworkPath, "wifi"),
                one(ComponentKind::NetworkPath, "ethernet"),
            ],
            AT,
        );
        let changes = apply(
            &mut registry,
            &[one(ComponentKind::NetworkPath, "wifi")],
            AT + Duration::from_secs(1),
        );
        assert_eq!(
            present(&registry),
            [(ComponentKind::NetworkPath, "wifi".to_owned())]
        );
        let removed: Vec<_> = changes.iter().filter(|c| c.removed).collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].id, "ethernet");
    }

    #[test]
    fn a_part_is_removed_when_a_part_of_another_kind_has_the_same_id() {
        let mut registry = Registry::new();
        apply(
            &mut registry,
            &[
                one(ComponentKind::NetworkPath, "same"),
                one(ComponentKind::CoreProcess, "same"),
            ],
            AT,
        );
        apply(
            &mut registry,
            &[one(ComponentKind::CoreProcess, "same")],
            AT + Duration::from_secs(1),
        );
        assert_eq!(
            present(&registry),
            [(ComponentKind::CoreProcess, "same".to_owned())]
        );
    }

    #[test]
    fn a_part_that_is_still_reported_is_kept_and_nothing_is_said_about_it() {
        let mut registry = Registry::new();
        let readings = [
            one(ComponentKind::NetworkPath, "wifi"),
            one(ComponentKind::CoreProcess, "primary"),
        ];
        apply(&mut registry, &readings, AT);
        let again = apply(&mut registry, &readings, AT + Duration::from_secs(1));
        assert!(again.is_empty(), "{again:?}");
        assert_eq!(present(&registry).len(), 2);
    }
}
