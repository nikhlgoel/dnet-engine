//! T133 — the path monitor: what the machine's paths are, how good each is, and which carries.
//!
//! The three pieces that come before it each do one thing. `paths` (in `dnet-netstate`) reads the
//! operating system's list. `quality` smooths probe results. `failover` decides which path carries.
//! Nothing holds them together, and the glue has rules of its own, which this module owns:
//!
//! - **The operating system's list is replaced often; what was measured is not forgotten.** A
//!   refresh keeps the quality of every interface that is still there, starts a new one unmeasured,
//!   and drops one that is gone. Without that, every network event would wipe the history that the
//!   failover logic needs to be calm.
//! - **Roles are the monitor's to set.** The system says a path is usable or not; the monitor marks
//!   exactly one usable path `Carrying` (never two: `validate_paths`), after every refresh and every
//!   decision.
//! - **A change of gateway on the carrying path is reported as its own thing.** Moving to another
//!   adapter is a failover decision; the same adapter getting a different router (a new access
//!   point, a DHCP change) is not, but the tunnel's host route still points at the old one and must
//!   be rewritten and the tunnel rebound (T083, AW-03). Only the monitor sees both lists, so only it
//!   can say so.
//! - **A refresh that changes nothing says so,** because the system raises several events for one
//!   change and the caller should not redo its work for the ones that carry no news.
//!
//! Pure logic: no clock of its own, no I/O.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::failover::{Decision, FailoverConfig, FailoverState};
use crate::ids::InterfaceId;
use crate::path::{NetworkPath, PathKind, PathQuality, PathRole};
use crate::quality::PathSample;

/// The carrying path kept its adapter but its gateway changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayChange {
    pub interface: InterfaceId,
    pub from: Option<IpAddr>,
    pub to: Option<IpAddr>,
}

/// What a refresh of the system's list amounted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathsDelta {
    /// Whether a path appeared, vanished, changed kind, gateway or usability. Quality is not part
    /// of this: it moves with every probe.
    pub changed: bool,
    /// Set when the path that was carrying is still there but its gateway differs.
    pub carrying_gateway: Option<GatewayChange>,
}

/// How often each kind of path is probed. A probe is a real connection to the user's endpoint, so
/// the cost is real: the carrying path is watched closely because the connection depends on it, and
/// the others only often enough that a move to one is made on fresh evidence. A path the system says
/// is down is not probed at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeCadence {
    pub carrying_every: Duration,
    pub standby_every: Duration,
}

impl Default for ProbeCadence {
    fn default() -> Self {
        Self {
            carrying_every: Duration::from_secs(10),
            standby_every: Duration::from_secs(30),
        }
    }
}

/// The paths, their measured quality, and the failover state.
#[derive(Debug, Clone)]
pub struct PathMonitor {
    cfg: FailoverConfig,
    cadence: ProbeCadence,
    paths: Vec<NetworkPath>,
    state: FailoverState,
    /// When each path was last handed out to be probed.
    probed_at: HashMap<InterfaceId, Instant>,
    /// When each path last produced a sample.
    sampled_at: HashMap<InterfaceId, Instant>,
}

/// A sample older than this many probe intervals is no longer evidence: probes stopped arriving
/// (the link dropped probes silently, the probe task stalled, the endpoint went away) and what was
/// measured before says nothing about now.
const STALE_AFTER_INTERVALS: u32 = 3;

type Shape = (InterfaceId, PathKind, Option<IpAddr>, bool);

/// What identifies a path for the purpose of "did anything change": everything but quality and the
/// role the monitor itself assigns.
fn shape(path: &NetworkPath) -> Shape {
    (
        path.interface_id,
        path.kind,
        path.gateway,
        path.role != PathRole::Unusable,
    )
}

fn shapes(paths: &[NetworkPath]) -> Vec<Shape> {
    let mut shapes: Vec<Shape> = paths.iter().map(shape).collect();
    shapes.sort_by_key(|s| s.0.luid());
    shapes
}

impl PathMonitor {
    pub fn new(cfg: FailoverConfig) -> Self {
        Self {
            cfg,
            cadence: ProbeCadence::default(),
            paths: Vec::new(),
            state: FailoverState::new(),
            probed_at: HashMap::new(),
            sampled_at: HashMap::new(),
        }
    }

    /// The same monitor with a different probing cadence.
    #[must_use]
    pub fn with_cadence(mut self, cadence: ProbeCadence) -> Self {
        self.cadence = cadence;
        self
    }

    /// The paths to probe at `now`, and mark them as handed out. A path never probed is due at
    /// once; the carrying path is due every `carrying_every`, any other usable one every
    /// `standby_every`; a path the system calls unusable is never due.
    #[must_use]
    pub fn due_probes(&mut self, now: Instant) -> Vec<InterfaceId> {
        let mut due = Vec::new();
        for path in &self.paths {
            if path.role == PathRole::Unusable {
                continue;
            }
            let every = if path.role == PathRole::Carrying {
                self.cadence.carrying_every
            } else {
                self.cadence.standby_every
            };
            let is_due = self
                .probed_at
                .get(&path.interface_id)
                .is_none_or(|last| now.saturating_duration_since(*last) >= every);
            if is_due {
                due.push(path.interface_id);
            }
        }
        for id in &due {
            self.probed_at.insert(*id, now);
        }
        due
    }

    /// The paths, with `Carrying` on the one that carries.
    pub fn paths(&self) -> &[NetworkPath] {
        &self.paths
    }

    /// The path carrying traffic now, if any.
    pub fn carrying(&self) -> Option<InterfaceId> {
        self.state.carrying()
    }

    /// Say which path carries, for a tunnel that was started on a particular one (or found running
    /// after a restart). Failover decisions continue from here.
    pub fn set_carrying(&mut self, path: InterfaceId, now: Instant) {
        self.state = FailoverState::carrying_on(path, now);
        self.apply_roles();
    }

    /// Replace the system's list. Quality already measured is kept for every interface that is
    /// still present.
    pub fn paths_changed(&mut self, mut observed: Vec<NetworkPath>) -> PathsDelta {
        let before = shapes(&self.paths);
        let carrying_before = self
            .state
            .carrying()
            .and_then(|id| self.paths.iter().find(|p| p.interface_id == id))
            .cloned();

        for path in &mut observed {
            if let Some(known) = self
                .paths
                .iter()
                .find(|p| p.interface_id == path.interface_id)
            {
                path.quality = known.quality.clone();
            }
        }
        let after = shapes(&observed);

        let carrying_gateway = carrying_before.and_then(|old| {
            let new = observed
                .iter()
                .find(|p| p.interface_id == old.interface_id)?;
            (new.role != PathRole::Unusable && new.gateway != old.gateway).then_some(
                GatewayChange {
                    interface: old.interface_id,
                    from: old.gateway,
                    to: new.gateway,
                },
            )
        });

        // A path that went down, or vanished, is forgotten: it is probed at once when it returns.
        self.probed_at.retain(|id, _| {
            observed
                .iter()
                .any(|p| p.interface_id == *id && p.role != PathRole::Unusable)
        });
        self.sampled_at
            .retain(|id, _| observed.iter().any(|p| p.interface_id == *id));
        self.paths = observed;
        self.apply_roles();
        PathsDelta {
            changed: before != after,
            carrying_gateway,
        }
    }

    /// Fold one probe result into a path's quality. A sample for a path not in the list is dropped:
    /// it was probed just before the path went away.
    pub fn observe(&mut self, path: InterfaceId, sample: PathSample, now: Instant) {
        if let Some(p) = self.paths.iter_mut().find(|p| p.interface_id == path) {
            p.quality = p.quality.observe(sample);
            self.sampled_at.insert(path, now);
        }
    }

    /// The paths as the decision should see them: one whose last sample has gone stale reads as
    /// unmeasured, so it can neither be moved to on old evidence nor have its history count as
    /// proof of stability.
    fn evidence(&self, now: Instant) -> Vec<NetworkPath> {
        self.paths
            .iter()
            .map(|path| {
                let every = if path.role == PathRole::Carrying {
                    self.cadence.carrying_every
                } else {
                    self.cadence.standby_every
                };
                let fresh = self.sampled_at.get(&path.interface_id).is_some_and(|at| {
                    now.saturating_duration_since(*at) <= every * STALE_AFTER_INTERVALS
                });
                let mut seen = path.clone();
                if !fresh {
                    seen.quality = PathQuality::unmeasured();
                }
                seen
            })
            .collect()
    }

    /// Decide which path should carry at `now`.
    #[must_use]
    pub fn evaluate(&mut self, now: Instant) -> Decision {
        let evidence = self.evidence(now);
        let (next, decision) = self.state.evaluate(&evidence, now, &self.cfg);
        self.state = next;
        self.apply_roles();
        decision
    }

    /// Exactly the carrying path is `Carrying`; paths the system calls unusable stay so.
    fn apply_roles(&mut self) {
        let carrying = self.state.carrying();
        for path in &mut self.paths {
            path.role = if path.role == PathRole::Unusable {
                PathRole::Unusable
            } else if Some(path.interface_id) == carrying {
                PathRole::Carrying
            } else {
                PathRole::Standby
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::failover::MoveReason;
    use crate::path::{validate_paths, PathQuality};

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }

    fn gw(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)))
    }

    /// A path as the system reports it: usable or not, with no quality yet.
    fn os(
        n: u64,
        kind: PathKind,
        preference: i32,
        gateway: Option<IpAddr>,
        usable: bool,
    ) -> NetworkPath {
        NetworkPath {
            interface_id: id(n),
            kind,
            gateway,
            quality: PathQuality::unmeasured(),
            role: if usable {
                PathRole::Standby
            } else {
                PathRole::Unusable
            },
            preference,
        }
    }

    fn wifi(n: u64) -> NetworkPath {
        os(n, PathKind::Wifi, 10, gw(1), true)
    }
    fn cell(n: u64) -> NetworkPath {
        os(n, PathKind::Cellular, 0, None, true)
    }

    struct Clock(Instant);
    impl Clock {
        fn new() -> Self {
            Clock(Instant::now())
        }
        fn at(&self, s: u64) -> Instant {
            self.0 + Duration::from_secs(s)
        }
    }

    fn monitor() -> PathMonitor {
        PathMonitor::new(FailoverConfig::default())
    }

    fn lose(m: &mut PathMonitor, at: Instant, path: u64, times: usize) {
        for _ in 0..times {
            m.observe(id(path), PathSample::Lost, at);
        }
    }

    fn answer(m: &mut PathMonitor, at: Instant, path: u64, times: usize) {
        for _ in 0..times {
            m.observe(
                id(path),
                PathSample::Answered {
                    rtt: Duration::from_millis(40),
                },
                at,
            );
        }
    }

    fn carrying_roles(m: &PathMonitor) -> Vec<u64> {
        m.paths()
            .iter()
            .filter(|p| p.role == PathRole::Carrying)
            .map(|p| p.interface_id.luid())
            .collect()
    }

    // ------------------------------------------------------------------ acquiring

    #[test]
    fn the_first_list_gives_a_carrying_path_and_exactly_one() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);

        let d = m.evaluate(c.at(0));

        assert!(matches!(
            d,
            Decision::Move {
                reason: MoveReason::Acquired,
                ..
            }
        ));
        assert_eq!(carrying_roles(&m), [1], "wifi is preferred");
        assert_eq!(validate_paths(m.paths()), Ok(()));
        assert_eq!(m.carrying(), Some(id(1)));
    }

    #[test]
    fn with_no_usable_path_nothing_carries() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![os(1, PathKind::Wifi, 10, None, false)]);

        assert_eq!(m.evaluate(c.at(0)), Decision::NoPath);
        assert!(carrying_roles(&m).is_empty());
        assert_eq!(m.carrying(), None);
    }

    #[test]
    fn a_tunnel_started_on_a_known_path_is_adopted() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        m.set_carrying(id(2), c.at(0));

        assert_eq!(carrying_roles(&m), [2]);
        assert_eq!(m.evaluate(c.at(1)), Decision::Stay, "no reason to move yet");
    }

    // ------------------------------------------------------------------ refreshing the list

    #[test]
    fn a_refresh_keeps_what_was_measured_for_interfaces_that_remain() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        lose(&mut m, c.at(0), 1, 3);
        let measured = m
            .paths()
            .iter()
            .find(|p| p.interface_id == id(1))
            .unwrap()
            .quality
            .clone();
        assert!(measured.loss_ewma > 0.0);

        m.paths_changed(vec![wifi(1), cell(2)]);

        let after = m.paths().iter().find(|p| p.interface_id == id(1)).unwrap();
        assert_eq!(after.quality, measured);
    }

    #[test]
    fn a_new_interface_starts_unmeasured_and_a_vanished_one_is_gone() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1)]);
        let _ = m.evaluate(c.at(0));

        m.paths_changed(vec![wifi(1), cell(2)]);
        let new = m.paths().iter().find(|p| p.interface_id == id(2)).unwrap();
        assert_eq!(new.quality, PathQuality::unmeasured());

        m.paths_changed(vec![cell(2)]);
        assert!(m.paths().iter().all(|p| p.interface_id != id(1)));
    }

    #[test]
    fn a_refresh_that_changes_nothing_says_so_even_if_the_order_differs() {
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);

        let same = m.paths_changed(vec![wifi(1), cell(2)]);
        let reordered = m.paths_changed(vec![cell(2), wifi(1)]);

        assert!(!same.changed);
        assert!(!reordered.changed);
        assert_eq!(same.carrying_gateway, None);
    }

    #[test]
    fn quality_alone_is_not_a_change() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1)]);
        let _ = m.evaluate(c.at(0));
        lose(&mut m, c.at(0), 1, 5);

        assert!(!m.paths_changed(vec![wifi(1)]).changed);
    }

    #[test]
    fn an_appearing_path_a_new_gateway_and_a_lost_link_are_each_a_change() {
        let mut m = monitor();
        m.paths_changed(vec![wifi(1)]);

        assert!(m.paths_changed(vec![wifi(1), cell(2)]).changed, "appeared");
        assert!(
            m.paths_changed(vec![os(1, PathKind::Wifi, 10, gw(9), true), cell(2)])
                .changed,
            "gateway"
        );
        assert!(
            m.paths_changed(vec![os(1, PathKind::Wifi, 10, gw(9), false), cell(2)])
                .changed,
            "link lost"
        );
    }

    // ------------------------------------------------------------------ the gateway of the carrying path

    #[test]
    fn a_new_gateway_on_the_carrying_adapter_is_reported_for_a_rebind() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1)]);
        let _ = m.evaluate(c.at(0));

        let delta = m.paths_changed(vec![os(1, PathKind::Wifi, 10, gw(77), true)]);

        assert_eq!(
            delta.carrying_gateway,
            Some(GatewayChange {
                interface: id(1),
                from: gw(1),
                to: gw(77)
            })
        );
        assert_eq!(
            m.evaluate(c.at(1)),
            Decision::Stay,
            "same adapter: not a failover move"
        );
    }

    #[test]
    fn a_new_gateway_on_a_path_that_is_not_carrying_is_not_reported() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), os(2, PathKind::Ethernet, 0, gw(5), true)]);
        let _ = m.evaluate(c.at(0));

        let delta = m.paths_changed(vec![wifi(1), os(2, PathKind::Ethernet, 0, gw(6), true)]);

        assert!(delta.changed);
        assert_eq!(delta.carrying_gateway, None);
    }

    #[test]
    fn a_carrying_adapter_that_lost_its_link_is_a_lost_path_not_a_gateway_change() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));

        let delta = m.paths_changed(vec![os(1, PathKind::Wifi, 10, gw(1), false), cell(2)]);

        assert_eq!(delta.carrying_gateway, None);
        assert!(matches!(
            m.evaluate(c.at(1)),
            Decision::Move {
                reason: MoveReason::Lost,
                ..
            }
        ));
        assert_eq!(carrying_roles(&m), [2]);
    }

    // ------------------------------------------------------------------ deciding

    #[test]
    fn samples_drive_a_move_away_from_a_path_that_stays_bad() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        // The alternative proves itself for a minute; then the carrying path goes bad.
        for t in 1..=60 {
            answer(&mut m, c.at(t), 2, 1);
            let _ = m.evaluate(c.at(t));
        }
        let mut moved = None;
        for t in 61..=200 {
            lose(&mut m, c.at(t), 1, 1);
            answer(&mut m, c.at(t), 2, 1);
            if let Decision::Move { to, reason, .. } = m.evaluate(c.at(t)) {
                moved = Some((to, reason));
                break;
            }
        }

        let (to, reason) = moved.expect("a path that stays unusable is left");
        assert_eq!((to, reason), (id(2), MoveReason::Degraded));
        assert_eq!(carrying_roles(&m), [2]);
        assert_eq!(validate_paths(m.paths()), Ok(()));
    }

    #[test]
    fn a_dead_first_choice_is_left_quickly_not_after_a_dwell() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        let mut left_at = None;
        for t in 1..=100 {
            // Wi-Fi is up but dead upstream from the start; the second path works.
            lose(&mut m, c.at(t), 1, 1);
            answer(&mut m, c.at(t), 2, 1);
            if matches!(m.evaluate(c.at(t)), Decision::Move { .. }) {
                left_at = Some(t);
                break;
            }
        }
        // No 120 s dwell is owed after merely choosing a first path: the stability proof of the
        // alternative (30 s) is the only wait that applies, and a dead path asks for less.
        let t = left_at.expect("left");
        assert!(t < 60, "left after {t} s");
    }

    #[test]
    fn a_decision_never_leaves_two_paths_carrying() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        for t in 0..1200u64 {
            // Quality swaps between the two every 7 s.
            let first_bad = (t / 7) % 2 == 0;
            for (path, bad) in [(1u64, first_bad), (2, !first_bad)] {
                if bad {
                    lose(&mut m, c.at(t), path, 1);
                } else {
                    answer(&mut m, c.at(t), path, 1);
                }
            }
            let _ = m.evaluate(c.at(t));
            assert!(carrying_roles(&m).len() <= 1, "t={t}");
            assert_eq!(validate_paths(m.paths()), Ok(()), "t={t}");
        }
    }

    // ------------------------------------------------------------------ what to probe, and when

    fn due(m: &mut PathMonitor, c: &Clock, t: u64) -> Vec<u64> {
        let mut ids: Vec<u64> = m.due_probes(c.at(t)).iter().map(|i| i.luid()).collect();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn every_usable_path_is_due_the_first_time_and_then_not_again_until_its_turn() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));

        assert_eq!(due(&mut m, &c, 0), [1, 2]);
        assert_eq!(
            due(&mut m, &c, 1),
            Vec::<u64>::new(),
            "asking again is not a reason to probe"
        );
        assert_eq!(due(&mut m, &c, 9), Vec::<u64>::new());
        assert_eq!(due(&mut m, &c, 10), [1], "the carrying path every 10 s");
        assert_eq!(
            due(&mut m, &c, 29),
            [1],
            "the other path not before its 30 s"
        );
        assert_eq!(due(&mut m, &c, 30), [2]);
    }

    #[test]
    fn a_path_the_system_calls_unusable_is_never_probed() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), os(2, PathKind::Cellular, 0, None, false)]);
        let _ = m.evaluate(c.at(0));

        for t in [0, 10, 100, 1000] {
            assert!(!due(&mut m, &c, t).contains(&2), "t={t}");
        }
    }

    #[test]
    fn a_path_that_comes_back_is_probed_at_once_not_on_its_old_schedule() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        assert_eq!(due(&mut m, &c, 0), [1, 2]);

        m.paths_changed(vec![wifi(1), os(2, PathKind::Cellular, 0, None, false)]);
        m.paths_changed(vec![wifi(1), cell(2)]);

        assert_eq!(
            due(&mut m, &c, 5),
            [2],
            "only 5 s since it was last probed, but it was gone"
        );
    }

    #[test]
    fn a_refresh_that_keeps_a_path_keeps_its_schedule() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        let _ = due(&mut m, &c, 0);

        m.paths_changed(vec![wifi(1), cell(2)]);

        assert_eq!(
            due(&mut m, &c, 1),
            Vec::<u64>::new(),
            "a refresh does not reset the clock"
        );
    }

    #[test]
    fn the_cadence_follows_whichever_path_is_carrying() {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        m.set_carrying(id(2), c.at(0));
        let _ = due(&mut m, &c, 0);

        assert_eq!(
            due(&mut m, &c, 10),
            [2],
            "now the cellular path is the watched one"
        );
    }

    #[test]
    fn the_cadence_can_be_changed() {
        let c = Clock::new();
        let mut m = monitor().with_cadence(ProbeCadence {
            carrying_every: Duration::from_secs(2),
            standby_every: Duration::from_secs(4),
        });
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        let _ = due(&mut m, &c, 0);

        assert_eq!(due(&mut m, &c, 2), [1]);
        assert_eq!(due(&mut m, &c, 4), [1, 2]);
    }

    // ------------------------------------------------------------------ evidence that goes stale

    /// Both paths healthy from `from` to `to`; the alternative stops being sampled after `alt_until`.
    fn healthy(m: &mut PathMonitor, c: &Clock, from: u64, to: u64, alt_until: u64) {
        for t in from..=to {
            answer(m, c.at(t), 1, 1);
            if t <= alt_until {
                answer(m, c.at(t), 2, 1);
            }
            let _ = m.evaluate(c.at(t));
        }
    }

    /// From `from` to `to` the carrying path is *poor* (every third probe lost: about a third of
    /// them), not dead, so no gamble is warranted; the alternative answers while `alt_until` has not
    /// passed. Returns the first move, if any.
    fn poor_carrying(
        m: &mut PathMonitor,
        c: &Clock,
        from: u64,
        to: u64,
        alt_until: u64,
    ) -> Option<(u64, Decision)> {
        for t in from..=to {
            if t % 3 == 0 {
                lose(m, c.at(t), 1, 1);
            } else {
                answer(m, c.at(t), 1, 1);
            }
            if t <= alt_until {
                answer(m, c.at(t), 2, 1);
            }
            let d = m.evaluate(c.at(t));
            if matches!(d, Decision::Move { .. }) {
                return Some((t, d));
            }
        }
        None
    }

    fn started() -> (Clock, PathMonitor) {
        let c = Clock::new();
        let mut m = monitor();
        m.paths_changed(vec![wifi(1), cell(2)]);
        let _ = m.evaluate(c.at(0));
        (c, m)
    }

    /// If the probes of the other path stop arriving, what they once said is not a reason to move:
    /// a link that quietly stopped answering would otherwise keep looking healthy for ever.
    #[test]
    fn a_path_whose_probes_stopped_is_not_moved_to_on_what_it_once_said() {
        let (c, mut m) = started();
        // Both healthy; the alternative's probes stop at t=40. By t=150 that evidence is 110 s old.
        healthy(&mut m, &c, 1, 150, 40);

        let moved = poor_carrying(&mut m, &c, 151, 600, 40);

        assert_eq!(moved, None, "moved on evidence that was more than 90 s old");
    }

    #[test]
    fn when_the_probes_resume_the_proof_starts_again_from_zero() {
        let (c, mut m) = started();
        healthy(&mut m, &c, 1, 150, 40);
        assert_eq!(poor_carrying(&mut m, &c, 151, 300, 40), None);

        // The alternative's probes come back at t=301; the carrying path is still poor.
        let (t, d) =
            poor_carrying(&mut m, &c, 301, 600, 600).expect("moves once the proof is complete");

        assert!(matches!(d, Decision::Move { to, .. } if to == id(2)));
        assert!(
            (331..345).contains(&t),
            "moved at {t}: 30 s of fresh, unbroken evidence were owed, and no more"
        );
    }

    #[test]
    fn evidence_that_keeps_arriving_never_goes_stale() {
        let (c, mut m) = started();
        healthy(&mut m, &c, 1, 150, 150);

        // The alternative keeps answering; the carrying path goes poor. A move is made promptly.
        let (t, _) = poor_carrying(&mut m, &c, 151, 400, 400).expect("a move");

        assert!(t < 175, "moved at {t}");
    }

    #[test]
    fn a_sample_for_a_path_that_is_not_there_is_dropped() {
        let mut m = monitor();
        m.paths_changed(vec![wifi(1)]);
        m.observe(id(99), PathSample::Lost, Instant::now());
        assert_eq!(m.paths().len(), 1);
    }
}
