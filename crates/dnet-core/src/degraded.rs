//! T084 — honest degradation reporting (FR-019, US3-5, SC-007).
//!
//! The failover machine (`failover.rs`) moves the connection when a better path exists. This module
//! is for the other case: the carrying path is poor and **no move is possible**. Saying nothing
//! would let the interface keep showing "connected", which is true and misleading; saying "moved"
//! would be false. The user is told what is actually the case: the connection is on a poor path, and
//! why it is staying there.
//!
//! # What is reported, and when
//!
//! - **Degraded**, once the carrying path has stayed below `Good` for as long as the machine itself
//!   waits before leaving a path (`degrade_for`). The report therefore means "the machine would have
//!   moved by now if it could": a brief dip is never announced, and a path that is poor for a moment
//!   during a move is not either. It names *why* the connection is staying ([`NoMove`]).
//! - **Recovered**, once the carrying path has stayed `Good` for `recover_for`, and only after a
//!   degradation was reported. A report is never retracted on one good reading, and "recovered" is
//!   never claimed without a prior "degraded".
//! - **Nothing** while the carrying path is unmeasured: no evidence either way, so the last report
//!   stands and no new claim is made. A path that has gone quiet is not "recovered".
//!
//! A report is repeated only when it says something new: the path changed, the reason for staying
//! changed, or the path got worse (`Poor` to `Unusable`). An improvement from `Unusable` to `Poor`
//! is not re-announced; "recovered" is the only good news.
//!
//! Pure logic: no clock, no I/O.

use std::time::{Duration, Instant};

use crate::ids::InterfaceId;
use crate::quality::QualityBand;

/// Why the connection is staying on a poor carrying path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoMove {
    /// There is no other usable path: nothing to switch to.
    OnlyPath,
    /// Other paths exist, but none is better.
    NoBetterPath,
    /// A better path exists but has not yet proven itself (measured, and for a good one, stable).
    Proving,
    /// A move was made moments ago and the machine waits before another (no flapping, FR-018).
    Dwell,
    /// The limit on moves in the recent window is used up (SC-007).
    Budget,
}

/// The carrying path is poor and the connection is staying on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Degradation {
    pub path: InterfaceId,
    /// `Poor` or `Unusable`; never `Good`.
    pub band: QualityBand,
    pub staying: NoMove,
}

/// A change in what the user should be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Degraded(Degradation),
    /// The carrying path is good again, and has been for long enough to say so.
    Recovered {
        path: InterfaceId,
    },
}

/// One look at the carrying path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    /// The path carrying traffic, if any.
    pub carrying: Option<InterfaceId>,
    /// Its quality band, or `None` when it has not been measured recently enough to say.
    pub band: Option<QualityBand>,
    /// What the machine would give as its reason for not moving, if asked now.
    pub staying: NoMove,
}

/// Remembers what has been reported, and how long the carrying path has been poor or good.
#[derive(Debug, Clone, Default)]
pub struct DegradationReporter {
    carrying: Option<InterfaceId>,
    poor_since: Option<Instant>,
    good_since: Option<Instant>,
    reported: Option<Degradation>,
}

impl DegradationReporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The degradation that has been reported and not yet recovered from, if any.
    pub fn current(&self) -> Option<Degradation> {
        self.reported
    }

    /// Look at the carrying path at `now`. Returns what changed since the last look, if anything.
    #[must_use]
    pub fn observe(
        &mut self,
        look: Look,
        now: Instant,
        degrade_for: Duration,
        recover_for: Duration,
    ) -> Option<Change> {
        // A different carrying path is a different story: its clocks start from nothing. What was
        // reported about the old one stands until the new one proves itself good (or is reported
        // poor in its own right), because moving off a poor path does not by itself make the
        // connection good.
        if look.carrying != self.carrying {
            self.carrying = look.carrying;
            self.poor_since = None;
            self.good_since = None;
        }
        let Some(path) = look.carrying else {
            // Every path is gone. That is reported as a failure, not as a recovery.
            self.reported = None;
            return None;
        };
        let held = |since: Instant, long: Duration| now.saturating_duration_since(since) >= long;

        // No measurement is no evidence: neither clock runs, and nothing is claimed.
        let band = look.band?;

        if band == QualityBand::Good {
            self.poor_since = None;
            let since = *self.good_since.get_or_insert(now);
            if self.reported.is_some() && held(since, recover_for) {
                self.reported = None;
                return Some(Change::Recovered { path });
            }
            return None;
        }

        self.good_since = None;
        let since = *self.poor_since.get_or_insert(now);
        if !held(since, degrade_for) {
            return None;
        }
        let now_degraded = Degradation {
            path,
            band,
            staying: look.staying,
        };
        let news = match self.reported {
            None => true,
            Some(before) => {
                before.path != now_degraded.path
                    || before.staying != now_degraded.staying
                    || (band == QualityBand::Unusable && before.band != QualityBand::Unusable)
            }
        };
        // The current band is kept up to date even when it is not worth saying again.
        self.reported = Some(now_degraded);
        news.then_some(Change::Degraded(now_degraded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEGRADE: Duration = Duration::from_secs(10);
    const RECOVER: Duration = Duration::from_secs(10);

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }

    struct Clock(Instant);
    impl Clock {
        fn new() -> Self {
            Clock(Instant::now())
        }
        fn at(&self, secs: u64) -> Instant {
            self.0 + Duration::from_secs(secs)
        }
    }

    fn look(path: u64, band: Option<QualityBand>, staying: NoMove) -> Look {
        Look {
            carrying: Some(id(path)),
            band,
            staying,
        }
    }

    fn see(r: &mut DegradationReporter, l: Look, now: Instant) -> Option<Change> {
        r.observe(l, now, DEGRADE, RECOVER)
    }

    fn degraded(path: u64, band: QualityBand, staying: NoMove) -> Option<Change> {
        Some(Change::Degraded(Degradation {
            path: id(path),
            band,
            staying,
        }))
    }

    #[test]
    fn a_path_that_is_good_from_the_start_reports_nothing() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        for s in 0..60 {
            assert_eq!(
                see(
                    &mut r,
                    look(1, Some(QualityBand::Good), NoMove::OnlyPath),
                    c.at(s)
                ),
                None
            );
        }
        assert_eq!(r.current(), None);
    }

    #[test]
    fn a_dip_shorter_than_the_machines_own_patience_is_not_announced() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        for s in 0..9 {
            assert_eq!(
                see(
                    &mut r,
                    look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
                    c.at(s)
                ),
                None,
                "second {s}"
            );
        }
    }

    #[test]
    fn a_path_poor_for_the_whole_wait_is_announced_with_its_reason() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        assert_eq!(see(&mut r, poor, c.at(0)), None);
        assert_eq!(
            see(&mut r, poor, c.at(10)),
            degraded(1, QualityBand::Poor, NoMove::OnlyPath)
        );
        assert_eq!(r.current().map(|d| d.staying), Some(NoMove::OnlyPath));
    }

    #[test]
    fn the_same_report_is_not_repeated() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let _ = see(&mut r, poor, c.at(0));
        assert!(see(&mut r, poor, c.at(10)).is_some());
        for s in 11..60 {
            assert_eq!(see(&mut r, poor, c.at(s)), None, "second {s}");
        }
    }

    #[test]
    fn a_change_of_reason_is_announced_again() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let _ = see(
            &mut r,
            look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
            c.at(0),
        );
        let _ = see(
            &mut r,
            look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
            c.at(10),
        );
        // A second network appears, but it is no better.
        assert_eq!(
            see(
                &mut r,
                look(1, Some(QualityBand::Poor), NoMove::NoBetterPath),
                c.at(11)
            ),
            degraded(1, QualityBand::Poor, NoMove::NoBetterPath)
        );
    }

    #[test]
    fn getting_worse_is_announced_and_getting_better_is_not() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let _ = see(
            &mut r,
            look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
            c.at(0),
        );
        let _ = see(
            &mut r,
            look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
            c.at(10),
        );
        assert_eq!(
            see(
                &mut r,
                look(1, Some(QualityBand::Unusable), NoMove::OnlyPath),
                c.at(11)
            ),
            degraded(1, QualityBand::Unusable, NoMove::OnlyPath)
        );
        assert_eq!(
            see(
                &mut r,
                look(1, Some(QualityBand::Poor), NoMove::OnlyPath),
                c.at(12)
            ),
            None,
            "an improvement that is still poor is not news"
        );
        assert_eq!(
            r.current().map(|d| d.band),
            Some(QualityBand::Poor),
            "but the current band is kept up to date"
        );
    }

    #[test]
    fn a_good_moment_does_not_retract_a_report() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let good = look(1, Some(QualityBand::Good), NoMove::OnlyPath);
        let _ = see(&mut r, poor, c.at(0));
        let _ = see(&mut r, poor, c.at(10));
        for s in 11..20 {
            assert_eq!(see(&mut r, good, c.at(s)), None, "second {s}");
        }
        assert!(r.current().is_some(), "still reported");
        // A relapse starts the recovery clock over.
        assert_eq!(see(&mut r, poor, c.at(20)), None);
        for s in 21..30 {
            assert_eq!(see(&mut r, good, c.at(s)), None, "second {s}");
        }
        assert!(r.current().is_some());
    }

    #[test]
    fn staying_good_for_the_whole_wait_recovers_once() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let good = look(1, Some(QualityBand::Good), NoMove::OnlyPath);
        let _ = see(&mut r, poor, c.at(0));
        let _ = see(&mut r, poor, c.at(10));
        assert_eq!(see(&mut r, good, c.at(11)), None);
        assert_eq!(
            see(&mut r, good, c.at(21)),
            Some(Change::Recovered { path: id(1) })
        );
        assert_eq!(r.current(), None);
        assert_eq!(see(&mut r, good, c.at(40)), None, "said once");
    }

    #[test]
    fn nothing_measured_makes_no_claim_either_way() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let silent = look(1, None, NoMove::OnlyPath);
        // Silence does not start a degradation ...
        for s in 0..30 {
            assert_eq!(see(&mut r, silent, c.at(s)), None);
        }
        // ... and does not end one.
        let _ = see(&mut r, poor, c.at(30));
        assert!(see(&mut r, poor, c.at(40)).is_some());
        for s in 41..100 {
            assert_eq!(see(&mut r, silent, c.at(s)), None, "second {s}");
        }
        assert!(r.current().is_some(), "a path gone quiet is not recovered");
    }

    #[test]
    fn silence_in_the_middle_does_not_count_towards_either_clock() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let silent = look(1, None, NoMove::OnlyPath);
        let _ = see(&mut r, poor, c.at(0));
        let _ = see(&mut r, silent, c.at(5));
        // The poor clock keeps running through silence: the path was poor, then unknown, not good.
        assert!(see(&mut r, poor, c.at(10)).is_some());
    }

    #[test]
    fn a_new_carrying_path_starts_its_own_clocks() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor1 = look(1, Some(QualityBand::Poor), NoMove::NoBetterPath);
        let _ = see(&mut r, poor1, c.at(0));
        assert!(see(&mut r, poor1, c.at(10)).is_some());
        // The connection moves to path 2, which is also poor: it must stay poor for the whole wait
        // before being announced in its own right.
        let poor2 = look(2, Some(QualityBand::Poor), NoMove::OnlyPath);
        assert_eq!(see(&mut r, poor2, c.at(11)), None);
        assert_eq!(see(&mut r, poor2, c.at(20)), None);
        assert_eq!(
            see(&mut r, poor2, c.at(21)),
            degraded(2, QualityBand::Poor, NoMove::OnlyPath)
        );
    }

    #[test]
    fn a_move_to_a_good_path_recovers_after_the_wait_not_at_once() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor1 = look(1, Some(QualityBand::Poor), NoMove::Proving);
        let _ = see(&mut r, poor1, c.at(0));
        assert!(see(&mut r, poor1, c.at(10)).is_some());
        let good2 = look(2, Some(QualityBand::Good), NoMove::OnlyPath);
        assert_eq!(see(&mut r, good2, c.at(11)), None);
        assert_eq!(see(&mut r, good2, c.at(20)), None);
        assert_eq!(
            see(&mut r, good2, c.at(21)),
            Some(Change::Recovered { path: id(2) })
        );
    }

    #[test]
    fn with_nothing_carrying_the_slate_is_wiped_without_a_word() {
        let c = Clock::new();
        let mut r = DegradationReporter::new();
        let poor = look(1, Some(QualityBand::Poor), NoMove::OnlyPath);
        let _ = see(&mut r, poor, c.at(0));
        assert!(see(&mut r, poor, c.at(10)).is_some());
        let none = Look {
            carrying: None,
            band: None,
            staying: NoMove::OnlyPath,
        };
        // Losing every path is reported by the failure machinery, not as a recovery.
        assert_eq!(see(&mut r, none, c.at(11)), None);
        assert_eq!(r.current(), None);
    }
}
