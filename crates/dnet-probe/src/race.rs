//! Racing profiles: one probe per profile, all at once, until the winner rule decides.
//!
//! The rule itself is `dnet_core::probe::ProbeRace` (usable throughput, Tier 1 preference with a
//! short grace, a 15 s deadline). This module only supplies the concurrency: it starts every
//! probe, feeds results in as they arrive with the time they arrived, asks the rule what to do
//! after each one, and stops the rest the moment it has an answer.
//!
//! **Cancelling losers matters.** Each real probe is a core process. Aborting a probe's task drops
//! its future, which drops the process handle, and the supervisor spawns every core with
//! `kill_on_drop`, so a lost race never leaves a core running.
//!
//! A probe that panics, or never answers, is simply a probe with no result: the deadline turns
//! it into a failure and the race still ends.

use std::future::Future;
use std::time::Duration;

use dnet_core::ids::ProfileId;
use dnet_core::probe::{ProbeRace, ProfileProbe, RaceDecision};
use dnet_core::profile::ConnectionProfile;
use tokio::task::JoinSet;

/// How often the race re-evaluates when no result has arrived, so that the grace period and the
/// deadline fire on time even in silence.
const TICK: Duration = Duration::from_millis(50);

/// What the race concluded and what it saw on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceReport {
    pub decision: RaceDecision,
    /// The probes that reported before the race ended, in arrival order, with when they did
    /// (time since the race started).
    pub results: Vec<(ProfileId, ProfileProbe, Duration)>,
}

/// Race `profiles`. `probe` starts one profile's probe; it is called once per profile.
pub async fn race_with<F, Fut>(profiles: &[ConnectionProfile], probe: F) -> RaceReport
where
    F: Fn(ProfileId) -> Fut,
    Fut: Future<Output = ProfileProbe> + Send + 'static,
{
    let start = tokio::time::Instant::now();
    let mut race = ProbeRace::start(profiles);
    // Unbounded is fine: at most one message per profile is ever sent.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    // A `JoinSet` aborts every task it still holds when it is dropped, so dropping this future (a
    // timeout, a user cancel, shutdown) stops the probes and, through them, their core processes.
    let mut tasks = JoinSet::new();
    for profile in profiles {
        let id = profile.id().clone();
        let running = probe(id.clone());
        let tx = tx.clone();
        tasks.spawn(async move {
            let outcome = running.await;
            let _ = tx.send((id, outcome, start.elapsed()));
        });
    }
    // Only the tasks hold senders now, so the channel closes when every probe has finished or died.
    drop(tx);

    let mut rx = Some(rx);
    let mut results = Vec::new();
    let decision = loop {
        // Count everything already queued before deciding, so a result that arrived together with
        // a tick is not lost to it.
        absorb_queued(&mut rx, &mut race, &mut results, start);
        let decision = race.decide(start.elapsed());
        if decision != RaceDecision::Pending {
            break decision;
        }
        match rx.as_mut() {
            Some(receiver) => tokio::select! {
                message = receiver.recv() => match message {
                    Some((id, outcome, at)) => {
                        race.record(&id, outcome, at);
                        results.push((id, outcome, at));
                    }
                    None => close(&mut rx, &mut race, start),
                },
                _ = tokio::time::sleep(TICK) => {}
            },
            None => tokio::time::sleep(TICK).await,
        }
    };

    // Losers are still running real cores. Abort them and wait until their futures have been
    // dropped, which drops the process handles, which kill their cores, so that nothing is left
    // running when this returns.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    RaceReport { decision, results }
}

type Reports = Vec<(ProfileId, ProfileProbe, Duration)>;
type Receiver = tokio::sync::mpsc::UnboundedReceiver<(ProfileId, ProfileProbe, Duration)>;

/// Record every result already waiting in the channel. If the channel turns out to be closed, no
/// probe can report any more.
fn absorb_queued(
    rx: &mut Option<Receiver>,
    race: &mut ProbeRace,
    results: &mut Reports,
    start: tokio::time::Instant,
) {
    use tokio::sync::mpsc::error::TryRecvError;
    let Some(receiver) = rx.as_mut() else {
        return;
    };
    loop {
        match receiver.try_recv() {
            Ok((id, outcome, at)) => {
                race.record(&id, outcome, at);
                results.push((id, outcome, at));
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                close(rx, race, start);
                return;
            }
        }
    }
}

/// Every probe has finished or died. Any that never reported never will, so fail them now: the
/// race can then end immediately instead of idling until the deadline.
fn close(rx: &mut Option<Receiver>, race: &mut ProbeRace, start: tokio::time::Instant) {
    *rx = None;
    race.fail_pending(start.elapsed());
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::probe::{Unusable, Verdict, PROBE_DEADLINE};
    use dnet_core::profile::{ProfileKind, ProfileParams};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::time::{sleep, Instant};

    fn profile(id: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new(id), kind, ProfileParams::new())
    }

    fn good() -> ProfileProbe {
        ProfileProbe::Transferred {
            bytes: 1_000_000,
            elapsed: Duration::from_secs(1),
        }
    }

    fn two() -> [ConnectionProfile; 2] {
        [
            profile("a", ProfileKind::AmneziaWg),
            profile("b", ProfileKind::VlessReality),
        ]
    }

    fn selected(report: &RaceReport) -> Option<&str> {
        match &report.decision {
            RaceDecision::Selected { profile, .. } => Some(profile.as_str()),
            _ => None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_usable_profile_wins_and_the_slower_one_is_stopped() {
        let slow_finished = Arc::new(AtomicBool::new(false));
        let flag = slow_finished.clone();
        let started = Instant::now();
        let report = race_with(&two(), move |id| {
            let flag = flag.clone();
            async move {
                if id.as_str() == "a" {
                    sleep(Duration::from_secs(8)).await;
                    flag.store(true, Ordering::SeqCst);
                } else {
                    sleep(Duration::from_secs(1)).await;
                }
                good()
            }
        })
        .await;
        assert_eq!(selected(&report), Some("b"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "decided as soon as b reported"
        );
        // Let any (wrongly) surviving task run to completion.
        sleep(Duration::from_secs(20)).await;
        assert!(
            !slow_finished.load(Ordering::SeqCst),
            "the losing probe must be cancelled"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn when_every_probe_fails_the_race_ends_without_waiting_for_the_deadline() {
        let started = Instant::now();
        let report = race_with(&two(), |id| async move {
            sleep(Duration::from_secs(if id.as_str() == "a" { 1 } else { 2 })).await;
            ProfileProbe::HandshakeFailed
        })
        .await;
        assert_eq!(report.decision, RaceDecision::NoneUsable);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(report.results.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_probes_are_failed_at_the_deadline() {
        let started = Instant::now();
        let report = race_with(&two(), |_| async {
            sleep(Duration::from_secs(1000)).await;
            good()
        })
        .await;
        assert_eq!(report.decision, RaceDecision::NoneUsable);
        let took = started.elapsed();
        assert!(
            took >= PROBE_DEADLINE && took < PROBE_DEADLINE + Duration::from_millis(200),
            "{took:?}"
        );
        assert!(report.results.is_empty());
    }

    /// HV-12 through the whole stack: the throttled profile is reported, never selected.
    #[tokio::test(start_paused = true)]
    async fn a_throttled_profile_is_recorded_but_does_not_win() {
        let report = race_with(&two(), |id| async move {
            if id.as_str() == "a" {
                sleep(Duration::from_secs(1)).await;
                ProfileProbe::Transferred {
                    bytes: 1024 * 1024,
                    elapsed: Duration::from_secs(60),
                }
            } else {
                sleep(Duration::from_secs(3)).await;
                good()
            }
        })
        .await;
        assert_eq!(selected(&report), Some("b"));
        let (id, probe, _) = &report.results[0];
        assert_eq!(id.as_str(), "a");
        assert_eq!(
            dnet_core::probe::judge(*probe),
            Verdict::Unusable(Unusable::TooSlow)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_that_panics_does_not_stop_the_race() {
        let report = race_with(&two(), |id| async move {
            if id.as_str() == "a" {
                panic!("a probe blew up");
            }
            sleep(Duration::from_secs(1)).await;
            good()
        })
        .await;
        assert_eq!(selected(&report), Some("b"));
    }

    #[tokio::test(start_paused = true)]
    async fn results_carry_the_time_they_arrived() {
        let report = race_with(&two(), |id| async move {
            sleep(Duration::from_secs(if id.as_str() == "a" { 1 } else { 2 })).await;
            ProfileProbe::HandshakeOnly
        })
        .await;
        let times: Vec<_> = report
            .results
            .iter()
            .map(|(id, _, at)| (id.as_str(), *at))
            .collect();
        assert_eq!(times[0].0, "a");
        assert!(times[0].1 >= Duration::from_secs(1) && times[0].1 < Duration::from_millis(1200));
        assert_eq!(times[1].0, "b");
        assert!(times[1].1 >= Duration::from_secs(2));
    }

    /// The caller may drop the race (a timeout, a user cancel, shutdown). The probes are real core
    /// processes, so they must stop with it, not run on until their own timeouts.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_race_stops_the_probes() {
        let finished = Arc::new(AtomicBool::new(false));
        let flag = finished.clone();
        let profiles = two();
        let race = race_with(&profiles, move |_| {
            let flag = flag.clone();
            async move {
                sleep(Duration::from_secs(30)).await;
                flag.store(true, Ordering::SeqCst);
                good()
            }
        });
        // The timeout drops the race future after 2 s.
        assert!(tokio::time::timeout(Duration::from_secs(2), race)
            .await
            .is_err());
        sleep(Duration::from_secs(120)).await;
        assert!(
            !finished.load(Ordering::SeqCst),
            "a probe outlived the race that started it"
        );
    }

    /// When every probe has died, nothing more can arrive, so the race ends at once.
    #[tokio::test(start_paused = true)]
    async fn when_every_probe_dies_the_race_ends_at_once_not_at_the_deadline() {
        let started = Instant::now();
        let report = race_with(&two(), |_| async {
            panic!("the probe blew up");
            #[allow(unreachable_code)]
            good()
        })
        .await;
        assert_eq!(report.decision, RaceDecision::NoneUsable);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited {:?}",
            started.elapsed()
        );
    }

    /// A result that is already queued when the clock ticks must be counted first: otherwise a
    /// Tier 2 profile can be chosen over a Tier 1 one that had already reported.
    #[tokio::test(start_paused = true)]
    async fn a_result_that_arrived_with_the_tick_is_counted_before_deciding() {
        let report = race_with(&two(), |id| async move {
            // "b" reports exactly on a tick boundary, with "a" failing at the same instant.
            sleep(Duration::from_millis(100)).await;
            if id.as_str() == "a" {
                ProfileProbe::HandshakeFailed
            } else {
                good()
            }
        })
        .await;
        assert_eq!(selected(&report), Some("b"));
        assert_eq!(report.results.len(), 2, "both reports were seen");
    }

    #[tokio::test(start_paused = true)]
    async fn no_profiles_means_nothing_usable_at_once() {
        let started = Instant::now();
        let report = race_with(&[], |_| async { good() }).await;
        assert_eq!(report.decision, RaceDecision::NoneUsable);
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
