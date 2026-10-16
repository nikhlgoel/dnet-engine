//! T062 — ranking endpoints by observed health (FR-011, FR-012).
//!
//! `health.rs` turns probes into a state and a smoothed RTT. This ranks the result: which
//! endpoint to use, and in what order to try the others.
//!
//! - Disabled and `Unreachable` endpoints are never candidates. `Unreachable` is not terminal:
//!   a later good probe makes the endpoint rankable again (US4-3).
//! - Known-working beats unmeasured: `Healthy`, then `Degraded`, then `Unknown`. A degraded
//!   endpoint is slow but answering; an unprobed one is a gamble that costs a failed attempt.
//! - Within a state the lower smoothed RTT wins; an endpoint with no RTT yet sorts last.
//! - Ties keep the order the endpoints were given, so the result is deterministic.

use std::time::Duration;

use crate::endpoint::Endpoint;
use crate::health::HealthState;
use crate::ids::EndpointId;

/// Whether an endpoint may be used at all right now.
pub fn is_candidate(endpoint: &Endpoint) -> bool {
    endpoint.is_enabled() && endpoint.health().state != HealthState::Unreachable
}

/// Candidate endpoints, best first.
pub fn rank(endpoints: &[Endpoint]) -> Vec<EndpointId> {
    let mut candidates: Vec<&Endpoint> = endpoints.iter().filter(|e| is_candidate(e)).collect();
    // `sort_by_key` is stable, so ties keep the given order.
    candidates.sort_by_key(|e| {
        let health = e.health();
        let rtt = match health.rtt_ewma {
            Some(rtt) => (0u8, rtt),
            None => (1u8, Duration::ZERO),
        };
        (state_rank(health.state), rtt)
    });
    candidates.iter().map(|e| e.id()).collect()
}

/// Lower is better. `Unreachable` is never ranked (see [`is_candidate`]).
fn state_rank(state: HealthState) -> u8 {
    match state {
        HealthState::Healthy => 0,
        HealthState::Degraded => 1,
        HealthState::Unknown => 2,
        HealthState::Unreachable => 3,
    }
}

/// The smoothed RTT, for messages. `None` before the first successful probe.
pub fn smoothed_rtt(endpoint: &Endpoint) -> Option<Duration> {
    endpoint.health().rtt_ewma
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::time::{Duration, Instant};

    use crate::credential::CredentialRef;
    use crate::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
    use crate::health::{EndpointHealth, HealthConfig, ProbeOutcome};
    use crate::ids::EndpointId;

    pub fn endpoint(label: &str) -> Endpoint {
        Endpoint::new(
            EndpointId::new(),
            label,
            EndpointAddress::new("198.51.100.1", 443).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new("k"),
        )
        .unwrap()
    }

    fn probed(outcomes: &[ProbeOutcome]) -> EndpointHealth {
        let cfg = HealthConfig::default();
        let mut health = EndpointHealth::new();
        for outcome in outcomes {
            health = health.on_probe(*outcome, Instant::now(), &cfg).next;
        }
        health
    }

    fn ok(ms: u64) -> ProbeOutcome {
        ProbeOutcome::Ok {
            rtt: Duration::from_millis(ms),
            loss: false,
        }
    }

    pub fn healthy(label: &str, ms: u64) -> Endpoint {
        let mut e = endpoint(label);
        e.set_health(probed(&[ok(ms)]));
        e
    }

    /// Two slow probes in a row move a healthy endpoint to `Degraded`.
    pub fn degraded(label: &str, ms: u64) -> Endpoint {
        let mut e = endpoint(label);
        e.set_health(probed(&[ok(ms.max(300)), ok(ms.max(300))]));
        e
    }

    pub fn unreachable(label: &str) -> Endpoint {
        let mut e = endpoint(label);
        e.set_health(probed(&[ProbeOutcome::Failed]));
        e
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn ids(list: &[&Endpoint]) -> Vec<EndpointId> {
        list.iter().map(|e| e.id()).collect()
    }

    #[test]
    fn fixtures_produce_the_states_they_name() {
        assert_eq!(healthy("a", 20).health().state, HealthState::Healthy);
        assert_eq!(degraded("b", 320).health().state, HealthState::Degraded);
        assert_eq!(unreachable("c").health().state, HealthState::Unreachable);
        assert_eq!(endpoint("d").health().state, HealthState::Unknown);
    }

    #[test]
    fn disabled_and_unreachable_endpoints_are_never_candidates() {
        let mut off = healthy("off", 10);
        off.set_enabled(false);
        let down = unreachable("down");
        let up = healthy("up", 50);
        let ranked = rank(&[off, down, up.clone()]);
        assert_eq!(ranked, ids(&[&up]));
    }

    #[test]
    fn known_working_beats_unmeasured() {
        let healthy_slow = healthy("healthy", 200);
        let degraded_fast = degraded("degraded", 300);
        let unknown = endpoint("unknown");
        let ranked = rank(&[unknown.clone(), degraded_fast.clone(), healthy_slow.clone()]);
        assert_eq!(ranked, ids(&[&healthy_slow, &degraded_fast, &unknown]));
    }

    #[test]
    fn within_a_state_the_lower_rtt_wins() {
        let slow = healthy("slow", 180);
        let fast = healthy("fast", 20);
        let mid = healthy("mid", 90);
        let ranked = rank(&[slow.clone(), fast.clone(), mid.clone()]);
        assert_eq!(ranked, ids(&[&fast, &mid, &slow]));
    }

    #[test]
    fn ties_keep_the_given_order() {
        let a = healthy("a", 40);
        let b = healthy("b", 40);
        assert_eq!(rank(&[a.clone(), b.clone()]), ids(&[&a, &b]));
        assert_eq!(rank(&[b.clone(), a.clone()]), ids(&[&b, &a]));
    }

    #[test]
    fn nothing_usable_ranks_nothing() {
        assert!(rank(&[]).is_empty());
        assert!(rank(&[unreachable("x")]).is_empty());
    }

    /// US4-3: a blocked endpoint that answers again rejoins the ranking.
    #[test]
    fn a_recovered_endpoint_is_rankable_again() {
        use crate::health::{HealthConfig, ProbeOutcome};
        use std::time::Instant;
        let mut e = unreachable("back");
        assert!(rank(std::slice::from_ref(&e)).is_empty());
        let recovered = e
            .health()
            .on_probe(
                ProbeOutcome::Ok {
                    rtt: Duration::from_millis(30),
                    loss: false,
                },
                Instant::now(),
                &HealthConfig::default(),
            )
            .next;
        e.set_health(recovered);
        assert_eq!(rank(std::slice::from_ref(&e)), ids(&[&e]));
    }

    #[test]
    fn the_smoothed_rtt_is_exposed_once_measured() {
        assert_eq!(smoothed_rtt(&endpoint("n")), None);
        assert_eq!(
            smoothed_rtt(&healthy("h", 25)),
            Some(Duration::from_millis(25))
        );
    }
}
