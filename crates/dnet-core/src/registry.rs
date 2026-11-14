// SPDX-License-Identifier: GPL-3.0-or-later
//! T170 — the Registry: every part of the connection as a component with a state, a reason in words,
//! the time it last changed and the evidence behind it (ADR-0008 section 3.6; P1 in section 7).
//!
//! Pure: no clock is read and nothing is sent. The caller says what it saw and when (as a time since
//! any fixed point, as `tick_gap` does), and the Registry keeps the latest account of each part. The
//! service fills it from what it already knows; the window's live map and the diagnostics bundle read
//! it. It never decides what is wrong, it only holds what the parts reported, so two readers cannot
//! disagree about the state of the same part.
//!
//! **Two rules that keep it honest.** (1) `changed_at` is the time the *state* last changed, not the
//! time of the last report: a part that says "fine" every second has been fine since it first said so.
//! (2) The Registry is bounded, and when it is full a new part is **refused**, never swapped in for an
//! old one: a part that silently vanishes from the map would read as healthy.

use std::collections::BTreeMap;
use std::time::Duration;

use thiserror::Error;

/// The most parts the Registry holds. The product has about a dozen kinds and a handful of each; this
/// is a ceiling against a bug that invents a new id on every tick, not a limit anyone should reach.
pub const MAX_COMPONENTS: usize = 128;

/// What sort of part a component is (ADR-0008 section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComponentKind {
    NetworkPath,
    CarrierLeaf,
    Session,
    Endpoint,
    CoreProcess,
    Adapter,
    Routes,
    DnsHandling,
    Guard,
    CaptivePortal,
}

/// How a part is doing. `Off` is a part that is not meant to be running; `Unknown` is a part nobody
/// has measured, which is not the same thing and is never shown as fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentState {
    Unknown,
    Off,
    Starting,
    Ok,
    Degraded,
    Blocked,
    Failed,
}

/// What was measured, when it was. Every field is optional because most parts measure one thing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evidence {
    pub latency_ms: Option<u32>,
    /// Packet loss in parts per thousand (50 is 5 %).
    pub loss_permille: Option<u16>,
    pub restarts: Option<u32>,
}

/// What a part says about itself in one report: its state, why, and what it measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation<'a> {
    pub state: ComponentState,
    /// Why, in words a person can read. Kept whole: it is the part's own account.
    pub reason: &'a str,
    pub evidence: Evidence,
}

impl<'a> Observation<'a> {
    pub fn new(state: ComponentState, reason: &'a str) -> Self {
        Self {
            state,
            reason,
            evidence: Evidence::default(),
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = evidence;
        self
    }
}

/// One part, as last reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub kind: ComponentKind,
    pub id: String,
    pub state: ComponentState,
    /// Why, in words a person can read. Never cut: it is the part's own account.
    pub reason: String,
    /// When `state` last changed, as a time since the caller's fixed point.
    pub changed_at: Duration,
    pub evidence: Evidence,
}

/// A change of state, returned so the caller can send an event for exactly the changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateChange {
    /// `None` when the part was not in the Registry before.
    pub from: Option<ComponentState>,
    pub to: ComponentState,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("the registry already holds {MAX_COMPONENTS} components; a new one is refused")]
    Full,
    #[error("a component needs a non-empty id")]
    EmptyId,
}

/// The latest account of every part, keyed by kind and id.
#[derive(Debug, Default)]
pub struct Registry {
    components: BTreeMap<(ComponentKind, String), Component>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what a part reported at `now`. The state change is returned when the state differs from
    /// the last report (or the part is new); a repeat of the same state refreshes the reason and the
    /// evidence but keeps `changed_at`.
    pub fn report(
        &mut self,
        kind: ComponentKind,
        id: &str,
        seen: Observation<'_>,
        now: Duration,
    ) -> Result<Option<StateChange>, RegistryError> {
        if id.is_empty() {
            return Err(RegistryError::EmptyId);
        }
        let key = (kind, id.to_owned());
        match self.components.get_mut(&key) {
            Some(held) => {
                held.reason = seen.reason.to_owned();
                held.evidence = seen.evidence;
                if held.state == seen.state {
                    return Ok(None);
                }
                let from = held.state;
                held.state = seen.state;
                held.changed_at = now;
                Ok(Some(StateChange {
                    from: Some(from),
                    to: seen.state,
                }))
            }
            None => {
                if self.components.len() >= MAX_COMPONENTS {
                    return Err(RegistryError::Full);
                }
                self.components.insert(
                    key,
                    Component {
                        kind,
                        id: id.to_owned(),
                        state: seen.state,
                        reason: seen.reason.to_owned(),
                        changed_at: now,
                        evidence: seen.evidence,
                    },
                );
                Ok(Some(StateChange {
                    from: None,
                    to: seen.state,
                }))
            }
        }
    }

    pub fn get(&self, kind: ComponentKind, id: &str) -> Option<&Component> {
        self.components.get(&(kind, id.to_owned()))
    }

    /// Forget a part that no longer exists (an endpoint the person removed). Returns whether it was
    /// there.
    pub fn remove(&mut self, kind: ComponentKind, id: &str) -> bool {
        self.components.remove(&(kind, id.to_owned())).is_some()
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Every part, ordered by kind and then id, so two snapshots of the same Registry are equal and a
    /// golden file can be compared.
    pub fn snapshot(&self) -> Vec<Component> {
        self.components.values().cloned().collect()
    }

    /// The one state that stands for the whole Registry: that of its worst part by `severity`. An
    /// empty Registry is `Unknown`, because nothing has been measured.
    pub fn overall(&self) -> ComponentState {
        roll_up(self.components.values().map(|c| c.state))
    }
}

/// The one state that stands for a set of parts: the worst by `severity`, and `Unknown` for no parts at all. A client
/// that holds only the parts can compute the same summary the service does, and so notice one that does not match.
pub fn roll_up(states: impl IntoIterator<Item = ComponentState>) -> ComponentState {
    states
        .into_iter()
        .max_by_key(|s| severity(*s))
        .unwrap_or(ComponentState::Unknown)
}

/// How much a state should weigh in the roll-up; higher is worse. Every state has its own weight, so
/// the summary never depends on the order the parts happen to be stored in.
///
/// The order (decided 2026-11-03 under T170; the owner may overrule it, and the table test
/// `the_roll_up_order_is_the_documented_one` must then change with it):
/// - `Off` is lowest: a part that is off by design is not a fault, so mixed with `Ok` the summary
///   reads `Ok`, and only a Registry that is entirely off reads `Off`.
/// - `Unknown` is above `Ok` and `Starting`: nothing is shown as fine without a measurement.
/// - Any known fault (`Degraded`, `Blocked`, `Failed`) outranks not knowing, and `Blocked` outranks
///   `Degraded` because a blocked part passes nothing at all.
fn severity(state: ComponentState) -> u8 {
    match state {
        ComponentState::Off => 0,
        ComponentState::Ok => 1,
        ComponentState::Starting => 2,
        ComponentState::Unknown => 3,
        ComponentState::Degraded => 4,
        ComponentState::Blocked => 5,
        ComponentState::Failed => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Duration = Duration::from_secs(100);

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn report(
        r: &mut Registry,
        kind: ComponentKind,
        id: &str,
        state: ComponentState,
        now: Duration,
    ) {
        r.report(kind, id, Observation::new(state, "because"), now)
            .unwrap();
    }

    #[test]
    fn a_new_component_is_a_change_from_nothing() {
        let mut r = Registry::new();
        let seen = Observation::new(ComponentState::Ok, "filters installed");
        let change = r.report(ComponentKind::Guard, "main", seen, T0).unwrap();
        assert_eq!(
            change,
            Some(StateChange {
                from: None,
                to: ComponentState::Ok
            })
        );
        let c = r.get(ComponentKind::Guard, "main").unwrap();
        assert_eq!(c.state, ComponentState::Ok);
        assert_eq!(c.reason, "filters installed");
        assert_eq!(c.changed_at, T0);
    }

    #[test]
    fn a_new_state_is_a_change_and_moves_the_time() {
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Session,
            "s",
            ComponentState::Ok,
            at(10),
        );
        let seen = Observation::new(ComponentState::Degraded, "loss");
        let change = r.report(ComponentKind::Session, "s", seen, at(20)).unwrap();
        assert_eq!(
            change,
            Some(StateChange {
                from: Some(ComponentState::Ok),
                to: ComponentState::Degraded
            })
        );
        assert_eq!(
            r.get(ComponentKind::Session, "s").unwrap().changed_at,
            at(20)
        );
    }

    #[test]
    fn the_same_state_is_no_change_and_keeps_the_time() {
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Session,
            "s",
            ComponentState::Ok,
            at(10),
        );
        let seen = Observation::new(ComponentState::Ok, "still fine");
        let change = r.report(ComponentKind::Session, "s", seen, at(99)).unwrap();
        assert_eq!(change, None);
        let c = r.get(ComponentKind::Session, "s").unwrap();
        assert_eq!(c.changed_at, at(10), "fine since 10, not since 99");
        assert_eq!(c.reason, "still fine", "the reason is refreshed");
    }

    #[test]
    fn a_repeat_refreshes_the_evidence() {
        let mut r = Registry::new();
        let first = Evidence {
            latency_ms: Some(40),
            ..Evidence::default()
        };
        let second = Evidence {
            latency_ms: Some(95),
            loss_permille: Some(20),
            restarts: Some(1),
        };
        let ok = Observation::new(ComponentState::Ok, "");
        r.report(
            ComponentKind::CarrierLeaf,
            "h2",
            ok.with_evidence(first),
            at(1),
        )
        .unwrap();
        r.report(
            ComponentKind::CarrierLeaf,
            "h2",
            ok.with_evidence(second),
            at(2),
        )
        .unwrap();
        assert_eq!(
            r.get(ComponentKind::CarrierLeaf, "h2").unwrap().evidence,
            second
        );
    }

    #[test]
    fn the_same_id_under_two_kinds_is_two_components() {
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Endpoint,
            "x",
            ComponentState::Ok,
            at(1),
        );
        report(
            &mut r,
            ComponentKind::CarrierLeaf,
            "x",
            ComponentState::Failed,
            at(1),
        );
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.get(ComponentKind::Endpoint, "x").unwrap().state,
            ComponentState::Ok
        );
        assert_eq!(
            r.get(ComponentKind::CarrierLeaf, "x").unwrap().state,
            ComponentState::Failed
        );
    }

    #[test]
    fn an_empty_id_is_refused() {
        let mut r = Registry::new();
        let seen = Observation::new(ComponentState::Ok, "");
        let err = r.report(ComponentKind::Guard, "", seen, T0).unwrap_err();
        assert_eq!(err, RegistryError::EmptyId);
        assert!(r.is_empty());
    }

    fn fill(r: &mut Registry) {
        for i in 0..MAX_COMPONENTS {
            report(
                r,
                ComponentKind::NetworkPath,
                &format!("p{i}"),
                ComponentState::Ok,
                at(1),
            );
        }
    }

    #[test]
    fn a_full_registry_refuses_a_new_part_and_keeps_the_old_ones() {
        let mut r = Registry::new();
        fill(&mut r);
        let seen = Observation::new(ComponentState::Ok, "");
        let err = r
            .report(ComponentKind::NetworkPath, "one-too-many", seen, at(2))
            .unwrap_err();
        assert_eq!(err, RegistryError::Full);
        assert_eq!(r.len(), MAX_COMPONENTS);
        assert!(r.get(ComponentKind::NetworkPath, "p0").is_some());
    }

    #[test]
    fn a_full_registry_still_updates_a_part_it_holds() {
        let mut r = Registry::new();
        fill(&mut r);
        let seen = Observation::new(ComponentState::Failed, "cable out");
        let change = r
            .report(ComponentKind::NetworkPath, "p0", seen, at(2))
            .unwrap();
        assert!(change.is_some());
        assert_eq!(r.len(), MAX_COMPONENTS);
    }

    #[test]
    fn remove_forgets_a_part_and_says_whether_it_was_there() {
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Endpoint,
            "e",
            ComponentState::Ok,
            at(1),
        );
        assert!(r.remove(ComponentKind::Endpoint, "e"));
        assert!(!r.remove(ComponentKind::Endpoint, "e"));
        assert!(r.get(ComponentKind::Endpoint, "e").is_none());
    }

    #[test]
    fn removing_makes_room_in_a_full_registry() {
        let mut r = Registry::new();
        fill(&mut r);
        assert!(r.remove(ComponentKind::NetworkPath, "p0"));
        let seen = Observation::new(ComponentState::Ok, "");
        assert!(r
            .report(ComponentKind::NetworkPath, "fresh", seen, at(2))
            .is_ok());
    }

    #[test]
    fn the_snapshot_is_ordered_by_kind_then_id_whatever_the_order_of_reports() {
        let mut r = Registry::new();
        report(&mut r, ComponentKind::Guard, "b", ComponentState::Ok, at(1));
        report(
            &mut r,
            ComponentKind::NetworkPath,
            "z",
            ComponentState::Ok,
            at(1),
        );
        report(&mut r, ComponentKind::Guard, "a", ComponentState::Ok, at(1));
        let order: Vec<_> = r.snapshot().into_iter().map(|c| (c.kind, c.id)).collect();
        assert_eq!(
            order,
            vec![
                (ComponentKind::NetworkPath, "z".to_string()),
                (ComponentKind::Guard, "a".to_string()),
                (ComponentKind::Guard, "b".to_string()),
            ]
        );
    }

    #[test]
    fn an_unknown_part_is_held_as_unknown_not_as_ok() {
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Adapter,
            "a",
            ComponentState::Unknown,
            at(1),
        );
        assert_eq!(
            r.get(ComponentKind::Adapter, "a").unwrap().state,
            ComponentState::Unknown
        );
    }

    #[test]
    fn roll_up_is_what_overall_uses_and_nothing_rolls_up_to_unknown() {
        assert_eq!(roll_up([]), ComponentState::Unknown);
        assert_eq!(
            roll_up([
                ComponentState::Ok,
                ComponentState::Blocked,
                ComponentState::Off
            ]),
            ComponentState::Blocked
        );
        let mut r = Registry::new();
        report(
            &mut r,
            ComponentKind::Guard,
            "g",
            ComponentState::Degraded,
            at(1),
        );
        report(
            &mut r,
            ComponentKind::Routes,
            "r",
            ComponentState::Ok,
            at(1),
        );
        assert_eq!(
            r.overall(),
            roll_up(r.snapshot().iter().map(|c| c.state)),
            "a client that holds only the parts can compute the same summary"
        );
    }

    #[test]
    fn an_empty_registry_is_unknown_overall() {
        assert_eq!(Registry::new().overall(), ComponentState::Unknown);
    }

    fn overall_of(states: &[ComponentState]) -> ComponentState {
        let mut r = Registry::new();
        // Different kinds, so the result cannot depend on which one is stored first or last.
        let kinds = [
            ComponentKind::Guard,
            ComponentKind::Session,
            ComponentKind::Routes,
        ];
        for (kind, state) in kinds.iter().zip(states) {
            report(&mut r, *kind, "p", *state, at(1));
        }
        r.overall()
    }

    #[test]
    fn the_roll_up_order_is_the_documented_one() {
        use ComponentState::*;
        // (parts, what the summary must say). Each row pins one of the decisions in `severity`.
        let rows: &[(&[ComponentState], ComponentState)] = &[
            (&[Off, Off], Off),               // nothing running by design reads Off, not Ok
            (&[Off, Ok], Ok),                 // a part that is deliberately off is not a fault
            (&[Ok, Off], Ok), // and the order the parts are stored in does not matter
            (&[Ok, Starting], Starting), // not up yet is not "fine"
            (&[Starting, Unknown], Unknown), // an unmeasured part is not fine, and says less than a starting one
            (&[Ok, Unknown], Unknown),       // never shown as fine without a measurement
            (&[Unknown, Degraded], Degraded), // a known fault outranks not knowing
            (&[Degraded, Blocked], Blocked), // blocked passes nothing; degraded passes something
            (&[Blocked, Failed], Failed),
        ];
        for (parts, expected) in rows {
            assert_eq!(overall_of(parts), *expected, "{parts:?}");
        }
    }

    #[test]
    fn overall_is_the_state_of_the_worst_part() {
        let mut r = Registry::new();
        report(&mut r, ComponentKind::Guard, "g", ComponentState::Ok, at(1));
        report(
            &mut r,
            ComponentKind::Session,
            "s",
            ComponentState::Failed,
            at(1),
        );
        report(
            &mut r,
            ComponentKind::Routes,
            "r",
            ComponentState::Degraded,
            at(1),
        );
        assert_eq!(r.overall(), ComponentState::Failed);
    }
}
