//! T063 — moving to another endpoint when the active one stops answering (FR-012, SC-008).
//!
//! The active endpoint is only abandoned when it is *unusable* (disabled or `Unreachable`). A
//! merely `Degraded` endpoint is kept: switching on quality alone would flap, and FR-012 asks
//! only for a move when the endpoint becomes unreachable.
//!
//! A move always yields a [`ConnectionEvent::EndpointMigrated`] whose `because` says what
//! happened in words, so the user is told rather than silently migrated (FR-012, IPC-06). When
//! nothing is usable the answer is [`Migration::NoEndpointReachable`], never a quiet fall back
//! to a broken endpoint (FR-014).

use crate::endpoint::Endpoint;
use crate::endpoint_health::{is_candidate, rank, smoothed_rtt};
use crate::health::HealthState;
use crate::ids::EndpointId;
use crate::session::ConnectionEvent;

/// What to do about the active endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// The active endpoint is still usable.
    Stay,
    /// Move to `to` and record `event`.
    MoveTo {
        to: EndpointId,
        event: ConnectionEvent,
    },
    /// The active endpoint is unusable and no other endpoint is a candidate.
    NoEndpointReachable,
}

/// Decide whether to leave `active`, and for where.
pub fn plan_migration(endpoints: &[Endpoint], active: EndpointId) -> Migration {
    let current = endpoints.iter().find(|e| e.id() == active);
    if current.is_some_and(is_candidate) {
        return Migration::Stay;
    }

    // The active endpoint is not a candidate, so `rank` can never offer it as its own
    // destination.
    let Some(to) = rank(endpoints).into_iter().next() else {
        return Migration::NoEndpointReachable;
    };
    let target = endpoints
        .iter()
        .find(|e| e.id() == to)
        .expect("rank returns ids from the same slice");

    let from_label = current.map_or_else(|| active.to_string(), |e| e.label().to_string());
    let why = match current {
        None => "is no longer configured".to_string(),
        Some(e) if !e.is_enabled() => "was disabled".to_string(),
        Some(e) => {
            let n = e.health().consecutive_failures;
            let probes = if n == 1 { "probe" } else { "probes" };
            format!("stopped answering after {n} failed {probes}")
        }
    };
    let state = match target.health().state {
        HealthState::Healthy => "healthy",
        HealthState::Degraded => "degraded",
        _ => "not yet measured",
    };
    let rtt = smoothed_rtt(target)
        .map(|r| format!(" with a smoothed round trip of {} ms", r.as_millis()))
        .unwrap_or_default();

    Migration::MoveTo {
        to,
        event: ConnectionEvent::EndpointMigrated {
            from: active,
            to,
            because: format!(
                "endpoint \"{from_label}\" {why}; moved to \"{}\", which is {state}{rtt}",
                target.label()
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_health::fixtures::*;

    fn moved_to(m: &Migration) -> Option<EndpointId> {
        match m {
            Migration::MoveTo { to, .. } => Some(*to),
            _ => None,
        }
    }

    #[test]
    fn a_usable_active_endpoint_stays() {
        let active = healthy("active", 60);
        let better = healthy("better", 10);
        assert_eq!(
            plan_migration(&[active.clone(), better], active.id()),
            Migration::Stay,
            "a faster endpoint elsewhere is no reason to leave a working one"
        );
    }

    #[test]
    fn a_degraded_active_endpoint_stays() {
        let active = degraded("slow", 320);
        let other = healthy("other", 10);
        assert_eq!(
            plan_migration(&[active.clone(), other], active.id()),
            Migration::Stay
        );
    }

    #[test]
    fn an_unreachable_active_endpoint_moves_to_the_best_candidate() {
        let active = unreachable("down");
        let slow = healthy("slow", 150);
        let fast = healthy("fast", 20);
        let plan = plan_migration(&[active.clone(), slow, fast.clone()], active.id());
        assert_eq!(moved_to(&plan), Some(fast.id()));
    }

    #[test]
    fn a_disabled_active_endpoint_moves_too() {
        let mut active = healthy("off", 20);
        active.set_enabled(false);
        let other = healthy("other", 40);
        let plan = plan_migration(&[active.clone(), other.clone()], active.id());
        assert_eq!(moved_to(&plan), Some(other.id()));
    }

    #[test]
    fn the_event_names_both_endpoints_and_explains_the_move() {
        let active = unreachable("campus-mumbai");
        let to = healthy("backup-frankfurt", 120);
        let plan = plan_migration(&[active.clone(), to.clone()], active.id());
        let Migration::MoveTo { event, .. } = plan else {
            panic!("expected a move");
        };
        let ConnectionEvent::EndpointMigrated {
            from,
            to: dest,
            because,
        } = event
        else {
            panic!("expected EndpointMigrated");
        };
        assert_eq!(from, active.id());
        assert_eq!(dest, to.id());
        assert!(because.contains("campus-mumbai"), "{because}");
        assert!(because.contains("backup-frankfurt"), "{because}");
        assert!(
            because.contains("120"),
            "the RTT helps the user judge: {because}"
        );
        assert!(!because.trim().eq_ignore_ascii_case("EndpointMigrated"));
    }

    #[test]
    fn with_no_other_candidate_nothing_is_reachable() {
        let active = unreachable("down");
        let also_down = unreachable("also");
        let mut off = healthy("off", 10);
        off.set_enabled(false);
        assert_eq!(
            plan_migration(&[active.clone(), also_down, off], active.id()),
            Migration::NoEndpointReachable
        );
    }

    #[test]
    fn an_active_endpoint_that_is_not_in_the_set_is_treated_as_gone() {
        let ghost = healthy("ghost", 10);
        let other = healthy("other", 40);
        let plan = plan_migration(std::slice::from_ref(&other), ghost.id());
        assert_eq!(moved_to(&plan), Some(other.id()));
        assert_eq!(
            plan_migration(&[], ghost.id()),
            Migration::NoEndpointReachable
        );
    }

    #[test]
    fn the_active_endpoint_is_never_its_own_destination() {
        let active = unreachable("down");
        let plan = plan_migration(std::slice::from_ref(&active), active.id());
        assert_eq!(plan, Migration::NoEndpointReachable);
    }
}
