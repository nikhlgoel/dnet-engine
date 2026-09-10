//! T023 — `EndpointHealth` transition tests (data-model §1.1).
//!
//! Written before the implementation (Constitution Principle IV). This suite fails
//! until T025, because `on_probe` is declared with a `todo!()` body: it compiles and
//! fails at runtime for the right reason.
//!
//! Assertions come from the data model. Where the model is silent, a test asserts only
//! what must hold under any reasonable reading, and names the gap:
//!
//! - **`Degraded` has no specified entry or exit.** It is in the state table but in no
//!   transition, so no test asserts anything about it. Resolve this in the spec before
//!   T025 implements it.
//! - **A failed probe from `Unknown`** is drawn ambiguously. The tests assume the
//!   failure threshold applies from any state, and only assert that a failure never
//!   *promotes* an endpoint to `Healthy`.
//! - **The EWMA weight is unspecified.** The tests only assert properties every convex
//!   moving average has: it exists once a probe succeeds, and it stays within the range
//!   of the samples seen.

use std::time::{Duration, Instant};

use dnet_core::health::{
    EndpointHealth, HealthConfig, HealthState, ProbeOutcome, DEFAULT_UNREACHABLE_AFTER,
};
use proptest::prelude::*;

fn ok(ms: u64) -> ProbeOutcome {
    ProbeOutcome::Ok {
        rtt: Duration::from_millis(ms),
    }
}

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
    vec![ProbeOutcome::Failed; n as usize]
}

// ------------------------------------------------------------------ examples

#[test]
fn default_failure_threshold_is_three() {
    assert_eq!(DEFAULT_UNREACHABLE_AFTER, 3);
    assert_eq!(HealthConfig::default().unreachable_after, 3);
}

#[test]
fn new_endpoint_starts_unknown_and_unprobed() {
    let h = EndpointHealth::new();
    assert_eq!(h.state, HealthState::Unknown);
    assert_eq!(h.last_probe, None);
    assert_eq!(h.consecutive_failures, 0);
    assert_eq!(h.rtt_ewma, None);
}

#[test]
fn unknown_becomes_healthy_on_first_successful_probe() {
    let (h, _, _) = run(&[ok(40)], &HealthConfig::default());
    assert_eq!(h.state, HealthState::Healthy);
}

#[test]
fn healthy_becomes_unreachable_exactly_at_the_failure_threshold() {
    let cfg = HealthConfig::default();

    let (below, _, _) = run(&[ok(40), ProbeOutcome::Failed, ProbeOutcome::Failed], &cfg);
    assert_ne!(
        below.state,
        HealthState::Unreachable,
        "2 failures is below the threshold of 3"
    );

    let (at, _, _) = run(
        &[
            ok(40),
            ProbeOutcome::Failed,
            ProbeOutcome::Failed,
            ProbeOutcome::Failed,
        ],
        &cfg,
    );
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

    seq.push(ProbeOutcome::Failed);
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
    let seq = [ok(40), ProbeOutcome::Failed, ProbeOutcome::Failed, ok(42)];
    let (h, _, _) = run(&seq, &HealthConfig::default());
    assert_eq!(h.consecutive_failures, 0);
}

#[test]
fn failures_count_consecutively_not_cumulatively() {
    // Four failures in total, but never three in a row.
    let seq = [
        ok(40),
        ProbeOutcome::Failed,
        ProbeOutcome::Failed,
        ok(41),
        ProbeOutcome::Failed,
        ProbeOutcome::Failed,
    ];
    let (h, _, _) = run(&seq, &HealthConfig::default());
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

#[test]
fn every_probe_records_its_time() {
    let cfg = HealthConfig::default();
    let at = Instant::now();

    let failed = EndpointHealth::new().on_probe(ProbeOutcome::Failed, at, &cfg);
    assert_eq!(failed.next.last_probe, Some(at));

    let succeeded = EndpointHealth::new().on_probe(ok(30), at, &cfg);
    assert_eq!(succeeded.next.last_probe, Some(at));
}

#[test]
fn successful_probe_establishes_an_rtt() {
    let (h, _, _) = run(&[ok(40)], &HealthConfig::default());
    assert!(h.rtt_ewma.is_some());
}

#[test]
fn failed_probe_does_not_invent_an_rtt() {
    // A failed probe measured nothing, so there is no sample to smooth.
    let (h, _, _) = run(&[ProbeOutcome::Failed], &HealthConfig::default());
    assert_eq!(h.rtt_ewma, None);
}

// ---------------------------------------------------------------- properties

fn outcome() -> impl Strategy<Value = ProbeOutcome> {
    prop_oneof![(1u64..5_000).prop_map(ok), Just(ProbeOutcome::Failed)]
}

fn outcomes() -> impl Strategy<Value = Vec<ProbeOutcome>> {
    prop::collection::vec(outcome(), 0..60)
}

/// Number of maximal runs of consecutive failures that reach the threshold.
fn expected_outages(seq: &[ProbeOutcome], threshold: u32) -> usize {
    let mut outages = 0;
    let mut run_len = 0u32;
    for o in seq {
        match o {
            ProbeOutcome::Failed => {
                run_len += 1;
                if run_len == threshold {
                    outages += 1;
                }
            }
            ProbeOutcome::Ok { .. } => run_len = 0,
        }
    }
    outages
}

proptest! {
    /// FR-012, US4-3: whatever happened before, an unreachable endpoint returns to
    /// the pool on its next successful probe.
    #[test]
    fn unreachable_is_never_terminal(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let mut all = seq;
        all.extend(failures(cfg.unreachable_after));
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
    fn a_failed_probe_never_promotes_to_healthy(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (h, _, at) = run(&seq, &cfg);
        if h.state != HealthState::Healthy {
            let t = h.on_probe(ProbeOutcome::Failed, at + Duration::from_secs(1), &cfg);
            prop_assert_ne!(t.next.state, HealthState::Healthy);
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
    fn crossings_are_reported_once_per_outage(seq in outcomes()) {
        let cfg = HealthConfig::default();
        let (_, crossings, _) = run(&seq, &cfg);
        prop_assert_eq!(crossings, expected_outages(&seq, cfg.unreachable_after));
    }

    /// Any convex moving average stays within the range of its samples. A 1 ms
    /// tolerance allows integer rounding in a correct implementation.
    #[test]
    fn rtt_ewma_stays_within_the_observed_range(
        rtts in prop::collection::vec(1u64..10_000, 1..40)
    ) {
        let seq: Vec<ProbeOutcome> = rtts.iter().map(|&ms| ok(ms)).collect();
        let (h, _, _) = run(&seq, &HealthConfig::default());
        let ewma = h.rtt_ewma.expect("rtt_ewma must exist after successful probes");

        let lo = Duration::from_millis(*rtts.iter().min().expect("non-empty"));
        let hi = Duration::from_millis(*rtts.iter().max().expect("non-empty"));
        let tol = Duration::from_millis(1);
        prop_assert!(
            ewma + tol >= lo && ewma <= hi + tol,
            "ewma {:?} outside observed range [{:?}, {:?}]", ewma, lo, hi
        );
    }
}
