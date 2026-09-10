//! T023 — `EndpointHealth` transition tests (data-model §1.1).
//!
//! Written before the implementation (Constitution Principle IV), then completed once
//! the spec gaps were resolved on 2026-09-11:
//! - `Degraded`: entered after 2 consecutive probes with rtt > 250ms or loss; left
//!   after 3 consecutive good probes.
//! - A failed probe from `Unknown` goes immediately to `Unreachable`.
//! - RTT smoothing uses the standard TCP weights α = 1/8, β = 1/4.

use std::time::{Duration, Instant};

use dnet_core::health::{
    EndpointHealth, HealthConfig, HealthState, ProbeOutcome, DEFAULT_UNREACHABLE_AFTER,
    DEGRADED_AFTER_BAD, HEALTHY_AFTER_GOOD,
};
use proptest::prelude::*;

/// A good-quality success: fast and lossless.
fn ok(ms: u64) -> ProbeOutcome {
    ProbeOutcome::Ok {
        rtt: Duration::from_millis(ms),
        loss: false,
    }
}

/// A successful but slow probe (> 250ms): bad quality, not a failure.
fn slow(ms: u64) -> ProbeOutcome {
    assert!(ms > 250, "slow() must exceed the 250ms threshold");
    ProbeOutcome::Ok {
        rtt: Duration::from_millis(ms),
        loss: false,
    }
}

/// A successful but lossy probe: bad quality regardless of RTT.
fn lossy(ms: u64) -> ProbeOutcome {
    ProbeOutcome::Ok {
        rtt: Duration::from_millis(ms),
        loss: true,
    }
}

const FAIL: ProbeOutcome = ProbeOutcome::Failed;

/// Applies outcomes one second apart. Returns the final health, how many probes
/// reported crossing into `Unreachable`, and the time of the last probe.
fn run(outcomes: &[ProbeOutcome], cfg: &HealthConfig) -> (EndpointHealth, usize, Instant) {
    let mut at = Instant::now();
    let mut health = EndpointHealth::new();
    let mut crossings = 0;
    for &outcome in outcomes {
        at += Duration::from_secs(1);
        let transition = health.on_probe(outcome, at, cfg);
        if transition.became_unreachable {
            crossings += 1;
        }
        health = transition.next;
    }
    (health, crossings, at)
}

fn failures(n: u32) -> Vec<ProbeOutcome> {
    vec![FAIL; n as usize]
}

// ------------------------------------------------------------------ constants

#[test]
fn default_thresholds_match_the_spec() {
    assert_eq!(DEFAULT_UNREACHABLE_AFTER, 3);
    assert_eq!(HealthConfig::default().unreachable_after, 3);
    assert_eq!(DEGRADED_AFTER_BAD, 2);
    assert_eq!(HEALTHY_AFTER_GOOD, 3);
}

#[test]
fn new_endpoint_starts_unknown_and_unprobed() {
    let h = EndpointHealth::new();
    assert_eq!(h.state, HealthState::Unknown);
    assert_eq!(h.last_probe, None);
    assert_eq!(h.consecutive_failures, 0);
    assert_eq!(h.rtt_ewma, None);
    assert_eq!(h.rttvar_ewma, None);
}

// ------------------------------------------------------------------ Unknown

#[test]
fn unknown_becomes_healthy_on_first_good_probe() {
    let (h, _, _) = run(&[ok(40)], &HealthConfig::default());
    assert_eq!(h.state, HealthState::Healthy);
}

#[test]
fn first_failed_probe_from_unknown_is_immediately_unreachable() {
    // An endpoint we know nothing about, whose first contact fails, is not used.
    let (h, crossings, _) = run(&[FAIL], &HealthConfig::default());
    assert_eq!(h.state, HealthState::Unreachable);
    assert_eq!(h.consecutive_failures, 1);
    assert_eq!(crossings, 1, "entering Unreachable is a reported crossing");
}

// ------------------------------------------------------------------ Unreachable

#[test]
fn healthy_becomes_unreachable_exactly_at_the_failure_threshold() {
    let cfg = HealthConfig::default();

    let (below, _, _) = run(&[ok(40), FAIL, FAIL], &cfg);
    assert_ne!(
        below.state,
        HealthState::Unreachable,
        "2 failures is below the threshold of 3"
    );

    let (at, _, _) = run(&[ok(40), FAIL, FAIL, FAIL], &cfg);
    assert_eq!(at.state, HealthState::Unreachable);
}

#[test]
fn failure_threshold_comes_from_configuration() {
    let cfg = HealthConfig {
        unreachable_after: 5,
    };
    let mut seq = vec![ok(40)];
    seq.extend(failures(4));
    let (below, _, _) = run(&seq, &cfg);
    assert_ne!(below.state, HealthState::Unreachable);

    seq.push(FAIL);
    let (at, _, _) = run(&seq, &cfg);
    assert_eq!(at.state, HealthState::Unreachable);
}

#[test]
fn unreachable_returns_to_healthy_on_a_successful_probe() {
    let mut seq = vec![ok(40)];
    seq.extend(failures(DEFAULT_UNREACHABLE_AFTER));
    seq.push(ok(55));
    let (h, _, _) = run(&seq, &HealthConfig::default());
    assert_eq!(h.state, HealthState::Healthy);
}

#[test]
fn successful_probe_resets_consecutive_failures() {
    let (h, _, _) = run(&[ok(40), FAIL, FAIL, ok(42)], &HealthConfig::default());
    assert_eq!(h.consecutive_failures, 0);
}

#[test]
fn failures_count_consecutively_not_cumulatively() {
    // Four failures total, but never three in a row.
    let (h, _, _) = run(
        &[ok(40), FAIL, FAIL, ok(41), FAIL, FAIL],
        &HealthConfig::default(),
    );
    assert_ne!(h.state, HealthState::Unreachable);
}

#[test]
fn crossing_into_unreachable_is_reported_exactly_once_per_outage() {
    let mut seq = vec![ok(40)];
    seq.extend(failures(6)); // stays down well past the threshold
    let (_, crossings, _) = run(&seq, &HealthConfig::default());
    assert_eq!(crossings, 1, "staying unreachable is not a new transition");
}

#[test]
fn each_separate_outage_is_reported() {
    let mut seq = vec![ok(40)];
    seq.extend(failures(3));
    seq.push(ok(40));
    seq.extend(failures(3));
    let (_, crossings, _) = run(&seq, &HealthConfig::default());
    assert_eq!(crossings, 2);
}

// ------------------------------------------------------------------ Degraded

#[test]
fn healthy_becomes_degraded_after_two_slow_probes() {
    let (one, _, _) = run(&[ok(40), slow(300)], &HealthConfig::default());
    assert_eq!(
        one.state,
        HealthState::Healthy,
        "one slow probe is not yet degraded"
    );

    let (two, _, _) = run(&[ok(40), slow(300), slow(300)], &HealthConfig::default());
    assert_eq!(two.state, HealthState::Degraded);
}

#[test]
fn loss_triggers_degraded_like_a_slow_probe() {
    let (h, _, _) = run(&[ok(40), lossy(40), lossy(40)], &HealthConfig::default());
    assert_eq!(
        h.state,
        HealthState::Degraded,
        "loss is bad quality even when fast"
    );
}

#[test]
fn degraded_returns_to_healthy_after_three_good_probes() {
    let mut seq = vec![ok(40), slow(300), slow(300)]; // now Degraded
    seq.extend([ok(40), ok(40)]); // only 2 good
    let (two_good, _, _) = run(&seq, &HealthConfig::default());
    assert_eq!(
        two_good.state,
        HealthState::Degraded,
        "2 good probes is not yet recovered"
    );

    seq.push(ok(40)); // third good probe
    let (three_good, _, _) = run(&seq, &HealthConfig::default());
    assert_eq!(three_good.state, HealthState::Healthy);
}

#[test]
fn one_good_probe_resets_the_bad_quality_run() {
    // bad, bad would degrade — but a good probe between them resets the count.
    let (h, _, _) = run(
        &[ok(40), slow(300), ok(40), slow(300)],
        &HealthConfig::default(),
    );
    assert_eq!(h.state, HealthState::Healthy);
}

#[test]
fn degraded_still_becomes_unreachable_on_repeated_failures() {
    let mut seq = vec![ok(40), slow(300), slow(300)]; // Degraded
    seq.extend(failures(DEFAULT_UNREACHABLE_AFTER));
    let (h, _, _) = run(&seq, &HealthConfig::default());
    assert_eq!(h.state, HealthState::Unreachable);
}

// ------------------------------------------------------------------ bookkeeping

#[test]
fn every_probe_records_its_time() {
    let cfg = HealthConfig::default();
    let at = Instant::now();
    assert_eq!(
        EndpointHealth::new()
            .on_probe(FAIL, at, &cfg)
            .next
            .last_probe,
        Some(at)
    );
    assert_eq!(
        EndpointHealth::new()
            .on_probe(ok(30), at, &cfg)
            .next
            .last_probe,
        Some(at)
    );
}

#[test]
fn successful_probe_establishes_an_rtt() {
    let (h, _, _) = run(&[ok(40)], &HealthConfig::default());
    assert!(h.rtt_ewma.is_some());
    assert!(h.rttvar_ewma.is_some());
}

#[test]
fn failed_probe_does_not_invent_an_rtt() {
    // A failed probe measured nothing, so there is no sample to smooth.
    let (h, _, _) = run(&[FAIL], &HealthConfig::default());
    assert_eq!(h.rtt_ewma, None);
    assert_eq!(h.rttvar_ewma, None);
}

#[test]
fn failed_probe_leaves_the_rtt_estimate_untouched() {
    let (before, _, at) = run(&[ok(40), ok(44)], &HealthConfig::default());
    let after = before.on_probe(FAIL, at + Duration::from_secs(1), &HealthConfig::default());
    assert_eq!(after.next.rtt_ewma, before.rtt_ewma);
    assert_eq!(after.next.rttvar_ewma, before.rttvar_ewma);
}

#[test]
fn first_rtt_sample_seeds_the_estimate_directly() {
    let (h, _, _) = run(&[ok(40)], &HealthConfig::default());
    assert_eq!(h.rtt_ewma, Some(Duration::from_millis(40)));
}

// ---------------------------------------------------------------- properties

fn any_outcome() -> impl Strategy<Value = ProbeOutcome> {
    prop_oneof![
        (1u64..5_000, any::<bool>()).prop_map(|(ms, loss)| ProbeOutcome::Ok {
            rtt: Duration::from_millis(ms),
            loss,
        }),
        Just(FAIL),
    ]
}

fn outcomes() -> impl Strategy<Value = Vec<ProbeOutcome>> {
    prop::collection::vec(any_outcome(), 0..60)
}

/// A reference model of the crossing rule alone (no quality, no RTT): a crossing
/// occurs on entering `Unreachable`, which happens on the first failure from
/// `Unknown` and on the `N`th consecutive failure otherwise.
fn expected_crossings(seq: &[ProbeOutcome], threshold: u32) -> usize {
    let mut unreachable = false;
    let mut seen_probe = false; // !seen_probe == Unknown
    let mut consecutive = 0u32;
    let mut crossings = 0;
    for o in seq {
        match o {
            ProbeOutcome::Failed => {
                consecutive += 1;
                let becomes = !seen_probe || consecutive >= threshold;
                if becomes && !unreachable {
                    crossings += 1;
                }
                // Once Unreachable, stay there until a successful probe. A later
                // sub-threshold failure never clears it.
                if becomes {
                    unreachable = true;
                }
            }
            ProbeOutcome::Ok { .. } => {
                consecutive = 0;
                unreachable = false;
            }
        }
        seen_probe = true;
    }
    crossings
}

proptest! {
    /// FR-012, US4-3: whatever happened before, an unreachable endpoint returns to
    /// the pool on its next successful probe.
    #[test]
    fn unreachable_is_never_terminal(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let mut all = seq;
        all.extend(failures(cfg.unreachable_after)); // guarantees Unreachable
        let (h, _, at) = run(&all, &cfg);
        prop_assert_eq!(h.state, HealthState::Unreachable);

        let t = h.on_probe(ok(30), at + Duration::from_secs(1), &cfg);
        prop_assert_eq!(t.next.state, HealthState::Healthy);
    }

    #[test]
    fn reaching_the_threshold_always_means_unreachable(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (h, _, _) = run(&seq, &cfg);
        if h.consecutive_failures >= cfg.unreachable_after {
            prop_assert_eq!(h.state, HealthState::Unreachable);
        }
    }

    #[test]
    fn a_failed_probe_never_promotes_toward_healthy(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (h, _, at) = run(&seq, &cfg);
        let before = h.state;
        let after = h.on_probe(FAIL, at + Duration::from_secs(1), &cfg).next.state;
        // A failure never leaves Unreachable, and never turns a non-Healthy state into
        // Healthy. (A single failure from Healthy legitimately *stays* Healthy — it
        // takes N consecutive failures to fall to Unreachable.)
        prop_assert!(!(before == HealthState::Unreachable && after != HealthState::Unreachable));
        if before != HealthState::Healthy {
            prop_assert_ne!(after, HealthState::Healthy);
        }
    }

    #[test]
    fn a_successful_probe_always_resets_the_failure_count(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (h, _, at) = run(&seq, &cfg);
        let t = h.on_probe(ok(30), at + Duration::from_secs(1), &cfg);
        prop_assert_eq!(t.next.consecutive_failures, 0);
    }

    #[test]
    fn crossings_match_the_reference_model(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (_, crossings, _) = run(&seq, &cfg);
        prop_assert_eq!(crossings, expected_crossings(&seq, cfg.unreachable_after));
    }

    /// Any convex moving average stays within the range of its samples. A 1ms
    /// tolerance allows for `Duration` rounding in a correct implementation.
    #[test]
    fn rtt_ewma_stays_within_the_observed_range(
        rtts in prop::collection::vec(1u64..10_000, 1..40)
    ) {
        let seq: Vec<ProbeOutcome> = rtts.iter().map(|&ms| ok(ms)).collect();
        let (h, _, _) = run(&seq, &HealthConfig::default());
        let ewma = h.rtt_ewma.expect("rtt_ewma exists after successful probes");

        let lo = Duration::from_millis(*rtts.iter().min().expect("non-empty"));
        let hi = Duration::from_millis(*rtts.iter().max().expect("non-empty"));
        let tol = Duration::from_millis(1);
        prop_assert!(
            ewma + tol >= lo && ewma <= hi + tol,
            "ewma {:?} outside observed range [{:?}, {:?}]", ewma, lo, hi
        );
    }
}
