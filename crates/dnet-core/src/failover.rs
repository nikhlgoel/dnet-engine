//! T082 — which path carries traffic, and when that changes (FR-016, FR-017, FR-018, SC-007).
//!
//! Pure logic, like `health.rs`: the caller passes in the paths (with their smoothed quality, see
//! `quality.rs`) and the time, and gets back a new state and a [`Decision`]. Nothing here touches
//! the network. Acting on a `Move` (rewrite the host route, then rebind the tunnel) is T083.
//!
//! # Two kinds of change, handled differently
//!
//! - **Forced.** The carrying path's link is gone (its role is `Unusable`, or it vanished from the
//!   list). Nothing can be carried over it, so the move is immediate and ignores every limit below.
//!   A lost link is a fact, not a fluctuation.
//! - **Voluntary.** The carrying path still works, but a better one exists. Moving breaks Tier 2
//!   connections and costs a rebind even on Tier 1, so it has to be worth it and has to be sure:
//!   - the carrying path must have stayed below `Good` for `degrade_for` (or been `Unusable` for
//!     the shorter `unusable_for`), never on one reading;
//!   - the path to move to must have been `Good` for `stable_for` without a break, which is also
//!     what "recovers and remains stable" (FR-017) means for going back to a preferred path;
//!   - at least `min_dwell` must have passed since the last move;
//!   - and no more than `max_moves` moves may have happened in the last `window`. This is SC-007
//!     ("no more than 4 times in 10 minutes") enforced directly, so it holds however the quality
//!     fluctuates, not only for the fluctuations somebody thought to test.
//!
//! A voluntary move that the budget or the dwell refuses is not queued: the machine stays, and asks
//! again on the next evaluation.
//!
//! Limits, stated rather than hidden: a path whose link is up but which is dead upstream is
//! `Unusable` by quality, which is voluntary, so after four moves in ten minutes the machine stays
//! on it until the budget frees. That is the price of the cap; a flapping network is exactly what
//! SC-007 exists to keep from flapping the connection.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::ids::InterfaceId;
use crate::path::{NetworkPath, PathRole};
use crate::quality::{QualityBand, QualityThresholds};

/// How much less loss (an absolute fraction) a poor path must show over a poor carrying path to be
/// worth a move: below this the difference is noise, and a move costs more than it gains.
const SAME_BAND_MARGIN: f64 = 0.15;

/// Tunable limits. The defaults are for campus and public Wi-Fi.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FailoverConfig {
    pub thresholds: QualityThresholds,
    /// The carrying path must stay below `Good` this long before it is left.
    pub degrade_for: Duration,
    /// Shorter, for a carrying path that is `Unusable`.
    pub unusable_for: Duration,
    /// A path must stay `Good` this long, unbroken, before it is moved to (or back to).
    pub stable_for: Duration,
    /// Minimum time between a move and the next voluntary one.
    pub min_dwell: Duration,
    /// SC-007: at most this many moves in `window`, counting forced ones, which block further
    /// voluntary moves but are never blocked themselves.
    pub max_moves: usize,
    pub window: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            thresholds: QualityThresholds::default(),
            degrade_for: Duration::from_secs(10),
            unusable_for: Duration::from_secs(4),
            stable_for: Duration::from_secs(30),
            min_dwell: Duration::from_secs(120),
            max_moves: 4,
            window: Duration::from_secs(600),
        }
    }
}

/// Why the carrying path changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveReason {
    /// Nothing was carrying and a path could be chosen: the first choice, or the first one after
    /// every path had been lost. Not counted against the budget: it changes nothing that was
    /// carrying traffic.
    Acquired,
    /// The carrying path's link is gone.
    Lost,
    /// The carrying path stayed poor and a better one was ready.
    Degraded,
    /// A more preferred path recovered and stayed stable (FR-017).
    Preferred,
}

/// What to do about the carrying path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Keep the carrying path as it is. Only returned while a path is carrying.
    Stay,
    /// Carry over `to` from now on.
    Move {
        from: Option<InterfaceId>,
        to: InterfaceId,
        reason: MoveReason,
    },
    /// No path can carry anything. The caller fails closed (`posture.rs`); this never means "send
    /// it direct".
    NoPath,
}

/// What the machine remembers between evaluations.
#[derive(Debug, Clone, Default)]
pub struct FailoverState {
    carrying: Option<InterfaceId>,
    moved_at: Option<Instant>,
    /// Since when the carrying path has been below `Good`, without a break.
    below_good_since: Option<Instant>,
    /// Since when the carrying path has been `Unusable`, without a break.
    unusable_since: Option<Instant>,
    /// Since when each usable path has been `Good`, without a break.
    good_since: HashMap<InterfaceId, Instant>,
    /// When the recent moves happened (oldest first), for the budget.
    moves: VecDeque<Instant>,
}

impl FailoverState {
    /// Nothing carrying yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a path that is already carrying, such as after the service restarts or when a
    /// tunnel was just started on it. Adopting a path is not a move, so it starts no dwell: a path
    /// found to be dead straight away should not have to be kept for two minutes. (`_now` is kept
    /// so callers state when they adopted it; nothing depends on it.)
    pub fn carrying_on(path: InterfaceId, _now: Instant) -> Self {
        Self {
            carrying: Some(path),
            ..Self::default()
        }
    }

    /// The path carrying traffic now, if any.
    pub fn carrying(&self) -> Option<InterfaceId> {
        self.carrying
    }

    /// Look at the paths at `now` and decide. The returned state replaces this one.
    #[must_use]
    pub fn evaluate(
        &self,
        paths: &[NetworkPath],
        now: Instant,
        cfg: &FailoverConfig,
    ) -> (FailoverState, Decision) {
        let mut next = self.clone();
        let band_of = |p: &NetworkPath| p.quality.band(&cfg.thresholds);
        let usable = |p: &NetworkPath| p.role != PathRole::Unusable;

        // How long each path has been continuously `Good` *and measured*. A path that is down, or
        // not `Good`, starts over when it comes back: stability is unbroken time, not total time.
        // A path nobody has measured reads as `Good` but has proven nothing, so its clock does not
        // run until the first sample.
        next.good_since
            .retain(|id, _| paths.iter().any(|p| p.interface_id == *id && usable(p)));
        for p in paths {
            if usable(p) && band_of(p) == QualityBand::Good && p.quality.is_measured() {
                next.good_since.entry(p.interface_id).or_insert(now);
            } else {
                next.good_since.remove(&p.interface_id);
            }
        }
        next.moves
            .retain(|at| now.saturating_duration_since(*at) < cfg.window);

        let carrying_path = self
            .carrying
            .and_then(|id| paths.iter().find(|p| p.interface_id == id))
            .filter(|p| usable(p));

        // Forced: nothing is carrying, or the link under it is gone.
        let Some(current) = carrying_path else {
            let lost = self.carrying.is_some();
            return match best(paths, |_| true, usable, band_of) {
                None => {
                    next.carrying = None;
                    next.reset_timers();
                    (next, Decision::NoPath)
                }
                Some(to) => {
                    let reason = if lost {
                        MoveReason::Lost
                    } else {
                        MoveReason::Acquired
                    };
                    next.moved_to(to.interface_id, now, lost);
                    (
                        next,
                        Decision::Move {
                            from: self.carrying,
                            to: to.interface_id,
                            reason,
                        },
                    )
                }
            };
        };

        // Voluntary. First how long the carrying path has been bad.
        let band = band_of(current);
        next.below_good_since =
            (band < QualityBand::Good).then(|| self.below_good_since.unwrap_or(now));
        next.unusable_since =
            (band == QualityBand::Unusable).then(|| self.unusable_since.unwrap_or(now));

        let dwelled = self
            .moved_at
            .is_none_or(|at| now.saturating_duration_since(at) >= cfg.min_dwell);
        let in_budget = next.moves.len() < cfg.max_moves;
        if !(dwelled && in_budget) {
            return (next, Decision::Stay);
        }
        let held = |since: Option<Instant>, long: Duration| {
            since.is_some_and(|s| now.saturating_duration_since(s) >= long)
        };
        let stable = |p: &NetworkPath| {
            band_of(p) == QualityBand::Good
                && next
                    .good_since
                    .get(&p.interface_id)
                    .is_some_and(|s| now.saturating_duration_since(*s) >= cfg.stable_for)
        };

        // Leave a path that stays bad.
        let urgent = band == QualityBand::Unusable && held(next.unusable_since, cfg.unusable_for);
        let sustained = urgent || held(next.below_good_since, cfg.degrade_for);
        if band < QualityBand::Good && sustained {
            // A better path, and a proven one. Better: a higher band, or, among poor paths (as on
            // a weak connection, where nothing is good), clearly less lossy. Proven: a good path has
            // been good and measured for `stable_for`; a poor one has at least been measured. When
            // the carrying path is `Unusable`, waiting for proof costs more than a gamble does.
            let better = |p: &NetworkPath| {
                band_of(p) > band
                    || (band == QualityBand::Poor
                        && band_of(p) == QualityBand::Poor
                        && p.quality.is_measured()
                        && p.quality.loss_ewma + SAME_BAND_MARGIN <= current.quality.loss_ewma)
            };
            let proven = |p: &NetworkPath| {
                if band_of(p) == QualityBand::Good {
                    stable(p)
                } else {
                    p.quality.is_measured()
                }
            };
            let ready = |p: &NetworkPath| {
                p.interface_id != current.interface_id && better(p) && (urgent || proven(p))
            };
            if let Some(to) = best(paths, ready, usable, band_of) {
                let to = to.interface_id;
                next.moved_to(to, now, true);
                return (
                    next,
                    Decision::Move {
                        from: Some(current.interface_id),
                        to,
                        reason: MoveReason::Degraded,
                    },
                );
            }
        }

        // Go back to (or on to) a path the user prefers, once it has proven itself.
        if band == QualityBand::Good {
            let preferred = |p: &NetworkPath| {
                p.interface_id != current.interface_id
                    && p.preference > current.preference
                    && stable(p)
            };
            if let Some(to) = best(paths, preferred, usable, band_of) {
                let to = to.interface_id;
                next.moved_to(to, now, true);
                return (
                    next,
                    Decision::Move {
                        from: Some(current.interface_id),
                        to,
                        reason: MoveReason::Preferred,
                    },
                );
            }
        }
        (next, Decision::Stay)
    }

    fn reset_timers(&mut self) {
        self.moved_at = None;
        self.below_good_since = None;
        self.unusable_since = None;
    }

    /// Record a move to `to`. A move that replaced something carrying traffic counts against the
    /// budget and starts the dwell; acquiring a first path does neither, because it disturbs
    /// nothing: the dwell and the budget exist to stop an established tunnel from flapping, and a
    /// first choice that turns out to be dead should be left as soon as the evidence is in.
    fn moved_to(&mut self, to: InterfaceId, now: Instant, counts: bool) {
        self.carrying = Some(to);
        self.below_good_since = None;
        self.unusable_since = None;
        if counts {
            self.moved_at = Some(now);
            self.moves.push_back(now);
        }
    }
}

/// The best usable path among those `eligible`: best band, then the user's preference, then lower
/// round-trip time, then lower loss, then the order given, so the result is deterministic.
fn best(
    paths: &[NetworkPath],
    eligible: impl Fn(&NetworkPath) -> bool,
    usable: impl Fn(&NetworkPath) -> bool,
    band_of: impl Fn(&NetworkPath) -> QualityBand,
) -> Option<&NetworkPath> {
    let rtt = |p: &NetworkPath| p.quality.rtt_ewma.unwrap_or(Duration::MAX);
    paths
        .iter()
        .filter(|p| usable(p) && eligible(p))
        // `min_by` keeps the first of equals, which is the order given.
        .min_by(|a, b| {
            band_of(b)
                .cmp(&band_of(a))
                .then(b.preference.cmp(&a.preference))
                .then(rtt(a).cmp(&rtt(b)))
                .then(a.quality.loss_ewma.total_cmp(&b.quality.loss_ewma))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::{PathKind, PathQuality};
    use crate::quality::PathSample;

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }

    /// A path with a given smoothed loss and round-trip time.
    fn path(n: u64, preference: i32, loss: f64, rtt_ms: u64) -> NetworkPath {
        NetworkPath {
            interface_id: id(n),
            kind: PathKind::Wifi,
            gateway: None,
            quality: PathQuality {
                loss_ewma: loss,
                rtt_ewma: Some(Duration::from_millis(rtt_ms)),
                jitter_ewma: None,
            },
            role: PathRole::Standby,
            preference,
        }
    }

    fn good(n: u64, preference: i32) -> NetworkPath {
        path(n, preference, 0.0, 40)
    }
    fn poor(n: u64, preference: i32) -> NetworkPath {
        path(n, preference, 0.3, 40)
    }
    fn unusable(n: u64, preference: i32) -> NetworkPath {
        path(n, preference, 0.8, 40)
    }
    fn down(n: u64, preference: i32) -> NetworkPath {
        NetworkPath {
            role: PathRole::Unusable,
            ..good(n, preference)
        }
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

    fn cfg() -> FailoverConfig {
        FailoverConfig::default()
    }

    /// Evaluate and keep the state, returning the decision.
    fn step(state: &mut FailoverState, paths: &[NetworkPath], now: Instant) -> Decision {
        let (next, decision) = state.evaluate(paths, now, &cfg());
        *state = next;
        decision
    }

    fn moved(to: u64, reason: MoveReason, from: Option<u64>) -> Decision {
        Decision::Move {
            from: from.map(id),
            to: id(to),
            reason,
        }
    }

    // ------------------------------------------------------------------ choosing a first path

    #[test]
    fn with_nothing_carrying_the_best_path_is_acquired() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        let d = step(&mut s, &[poor(1, 0), good(2, 0)], c.at(0));
        assert_eq!(d, moved(2, MoveReason::Acquired, None));
        assert_eq!(s.carrying(), Some(id(2)));
    }

    #[test]
    fn a_good_path_beats_a_preferred_poor_one_when_choosing() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        let d = step(&mut s, &[poor(1, 10), good(2, 0)], c.at(0));
        assert_eq!(d, moved(2, MoveReason::Acquired, None));
    }

    #[test]
    fn among_equal_bands_the_users_preference_wins_then_the_faster_path() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        assert_eq!(
            step(&mut s, &[good(1, 0), good(2, 5)], c.at(0)),
            moved(2, MoveReason::Acquired, None)
        );
        let mut s = FailoverState::new();
        let slow = path(1, 0, 0.0, 90);
        let fast = path(2, 0, 0.0, 30);
        assert_eq!(
            step(&mut s, &[slow, fast], c.at(0)),
            moved(2, MoveReason::Acquired, None)
        );
    }

    #[test]
    fn with_everything_equal_the_first_path_given_wins() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        assert_eq!(
            step(&mut s, &[good(7, 0), good(3, 0)], c.at(0)),
            moved(7, MoveReason::Acquired, None)
        );
    }

    #[test]
    fn acquiring_does_not_use_up_the_move_budget() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        step(&mut s, &[good(1, 0)], c.at(0));
        assert!(s.moves.is_empty());
    }

    #[test]
    fn with_no_usable_path_there_is_no_path() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        assert_eq!(
            step(&mut s, &[down(1, 0), down(2, 0)], c.at(0)),
            Decision::NoPath
        );
        assert_eq!(s.carrying(), None);
        assert_eq!(step(&mut s, &[], c.at(1)), Decision::NoPath);
    }

    #[test]
    fn a_path_comes_back_after_no_path_and_is_acquired_again() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        assert_eq!(step(&mut s, &[down(1, 0)], c.at(10)), Decision::NoPath);
        assert_eq!(
            step(&mut s, &[good(1, 0)], c.at(20)),
            moved(1, MoveReason::Acquired, None)
        );
    }

    // ------------------------------------------------------------------ a lost link: forced

    #[test]
    fn a_lost_link_moves_at_once_to_the_best_alternative() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let d = step(&mut s, &[down(1, 0), good(2, 0)], c.at(1));
        assert_eq!(d, moved(2, MoveReason::Lost, Some(1)));
    }

    #[test]
    fn a_path_that_vanishes_from_the_list_counts_as_lost() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let d = step(&mut s, &[good(2, 0)], c.at(1));
        assert_eq!(d, moved(2, MoveReason::Lost, Some(1)));
    }

    #[test]
    fn a_lost_link_ignores_the_dwell_and_the_exhausted_budget() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        // Four moves already spent in the window, and the last was a second ago.
        s.moves = VecDeque::from([c.at(100), c.at(101), c.at(102), c.at(103)]);
        s.moved_at = Some(c.at(103));
        let d = step(&mut s, &[down(1, 0), good(2, 0)], c.at(104));
        assert_eq!(d, moved(2, MoveReason::Lost, Some(1)));
    }

    #[test]
    fn a_lost_link_with_only_a_poor_alternative_still_moves_to_it() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let d = step(&mut s, &[down(1, 0), poor(2, 0)], c.at(1));
        assert_eq!(d, moved(2, MoveReason::Lost, Some(1)));
    }

    #[test]
    fn forced_moves_use_up_the_budget_for_voluntary_ones() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        step(&mut s, &[down(1, 0), good(2, 0)], c.at(10));
        assert_eq!(s.moves.len(), 1);
    }

    // ------------------------------------------------------------------ leaving a bad path

    #[test]
    fn a_path_that_dips_below_good_is_not_left_until_it_stays_there() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        // The alternative has been good for a long time; the carrying path goes poor at t=200.
        step(&mut s, &[good(1, 0), good(2, 0)], c.at(150));
        assert_eq!(
            step(&mut s, &[good(1, 0), good(2, 0)], c.at(199)),
            Decision::Stay
        );
        let both = [poor(1, 0), good(2, 0)];
        assert_eq!(
            step(&mut s, &both, c.at(200)),
            Decision::Stay,
            "the dip begins"
        );
        assert_eq!(
            step(&mut s, &both, c.at(209)),
            Decision::Stay,
            "9 s is not sustained"
        );
        assert_eq!(
            step(&mut s, &both, c.at(210)),
            moved(2, MoveReason::Degraded, Some(1)),
            "10 s is"
        );
    }

    #[test]
    fn a_dip_that_recovers_resets_the_clock() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        step(&mut s, &[good(1, 0), good(2, 0)], c.at(100));
        step(&mut s, &[poor(1, 0), good(2, 0)], c.at(201));
        step(&mut s, &[good(1, 0), good(2, 0)], c.at(208));
        // Poor again: ten seconds counted from here, not from t=201.
        step(&mut s, &[poor(1, 0), good(2, 0)], c.at(209));
        assert_eq!(
            step(&mut s, &[poor(1, 0), good(2, 0)], c.at(215)),
            Decision::Stay
        );
        assert_eq!(
            step(&mut s, &[poor(1, 0), good(2, 0)], c.at(219)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    #[test]
    fn a_poor_path_with_no_better_alternative_is_kept() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        for t in [200, 300, 400, 900] {
            let d = step(&mut s, &[poor(1, 0), poor(2, 0)], c.at(t));
            assert_eq!(d, Decision::Stay, "t={t}");
        }
    }

    #[test]
    fn a_poor_path_alone_is_kept_and_nothing_is_claimed() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        assert_eq!(step(&mut s, &[poor(1, 0)], c.at(500)), Decision::Stay);
        assert_eq!(s.carrying(), Some(id(1)));
    }

    #[test]
    fn a_new_alternative_must_prove_itself_before_a_poor_path_is_left() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        // Carrying is poor from t=200. The alternative turns up good at t=205.
        step(&mut s, &[poor(1, 0)], c.at(200));
        step(&mut s, &[poor(1, 0), good(2, 0)], c.at(205));
        assert_eq!(
            step(&mut s, &[poor(1, 0), good(2, 0)], c.at(234)),
            Decision::Stay,
            "29 s of good is not stable"
        );
        assert_eq!(
            step(&mut s, &[poor(1, 0), good(2, 0)], c.at(235)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    #[test]
    fn an_alternative_that_flaps_never_becomes_stable() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        step(&mut s, &[poor(1, 0)], c.at(200));
        for t in 205..400 {
            // Good for 20 s, then poor for a moment, over and over.
            let alt = if t % 25 < 20 { good(2, 0) } else { poor(2, 0) };
            assert_eq!(
                step(&mut s, &[poor(1, 0), alt], c.at(t)),
                Decision::Stay,
                "t={t}"
            );
        }
    }

    #[test]
    fn an_unusable_path_is_left_sooner_and_for_any_better_path() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [unusable(1, 0), poor(2, 0)];
        step(&mut s, &paths, c.at(200));
        assert_eq!(step(&mut s, &paths, c.at(203)), Decision::Stay);
        assert_eq!(
            step(&mut s, &paths, c.at(204)),
            moved(2, MoveReason::Degraded, Some(1)),
            "4 s unusable, and a poor path that works is better; no 30 s proof is asked of it"
        );
    }

    #[test]
    fn leaving_a_poor_path_never_picks_something_no_better() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [poor(1, 0), unusable(2, 9)];
        step(&mut s, &paths, c.at(200));
        assert_eq!(step(&mut s, &paths, c.at(260)), Decision::Stay);
    }

    // ------------------------------------------------------------------ evidence

    /// A path the system lists and nothing has measured.
    fn fresh(n: u64, preference: i32) -> NetworkPath {
        NetworkPath {
            quality: PathQuality::unmeasured(),
            ..good(n, preference)
        }
    }

    /// Nothing says an unmeasured path is bad, so it reads as good; but that is not evidence, and
    /// a voluntary move needs evidence. Staying on a poor path is the lesser risk than moving to
    /// one nobody has ever seen carry anything.
    #[test]
    fn a_path_nobody_has_measured_is_never_moved_to_voluntarily() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [poor(1, 0), fresh(2, 0)];
        for t in [200, 210, 300, 600, 1000, 5000] {
            assert_eq!(step(&mut s, &paths, c.at(t)), Decision::Stay, "t={t}");
        }
    }

    #[test]
    fn a_path_nobody_has_measured_is_still_taken_when_the_carrying_link_is_lost() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        assert_eq!(
            step(&mut s, &[down(1, 0), fresh(2, 0)], c.at(1)),
            moved(2, MoveReason::Lost, Some(1)),
            "with the link gone there is nothing to stay on"
        );
    }

    #[test]
    fn a_path_nobody_has_measured_is_taken_when_the_carrying_one_is_unusable() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [unusable(1, 0), fresh(2, 0)];
        step(&mut s, &paths, c.at(200));
        assert_eq!(
            step(&mut s, &paths, c.at(204)),
            moved(2, MoveReason::Degraded, Some(1)),
            "a dead path is worth a gamble; a merely poor one is not"
        );
    }

    /// Thirty seconds of "good" is thirty seconds of *measured* good: a path seen for an hour
    /// without a single sample has proven nothing, and its clock starts at the first sample.
    #[test]
    fn the_stability_proof_counts_from_the_first_measurement_not_from_when_the_path_appeared() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        step(&mut s, &[poor(1, 0), fresh(2, 0)], c.at(200));
        step(&mut s, &[poor(1, 0), fresh(2, 0)], c.at(299));
        // First measurement of path 2 at t=300.
        let measured = [poor(1, 0), good(2, 0)];
        assert_eq!(step(&mut s, &measured, c.at(300)), Decision::Stay);
        assert_eq!(step(&mut s, &measured, c.at(329)), Decision::Stay);
        assert_eq!(
            step(&mut s, &measured, c.at(330)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    // ------------------------------------------------------------------ weak conditions

    /// When every path is poor, as on a weak connection, "no better band" must not mean "stay on
    /// the worst of them".
    #[test]
    fn among_poor_paths_a_clearly_better_one_is_moved_to() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [path(1, 0, 0.45, 40), path(2, 0, 0.20, 40)];
        step(&mut s, &paths, c.at(200));
        assert_eq!(
            step(&mut s, &paths, c.at(209)),
            Decision::Stay,
            "not sustained yet"
        );
        assert_eq!(
            step(&mut s, &paths, c.at(210)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    #[test]
    fn among_poor_paths_one_only_slightly_better_is_not_worth_a_move() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [path(1, 0, 0.45, 40), path(2, 0, 0.40, 40)];
        for t in [200, 300, 600, 3000] {
            assert_eq!(step(&mut s, &paths, c.at(t)), Decision::Stay, "t={t}");
        }
    }

    #[test]
    fn among_poor_paths_an_unmeasured_one_is_not_assumed_better() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [path(1, 0, 0.45, 40), fresh(2, 0)];
        for t in [200, 300, 3000] {
            assert_eq!(step(&mut s, &paths, c.at(t)), Decision::Stay, "t={t}");
        }
    }

    // ------------------------------------------------------------------ going back (FR-017)

    #[test]
    fn a_preferred_path_that_recovers_is_returned_to_only_once_stable() {
        let c = Clock::new();
        // On path 2 (preference 0) since t=0; path 1 (preference 5) comes good at t=300.
        let mut s = FailoverState::carrying_on(id(2), c.at(0));
        let now_good = [good(1, 5), good(2, 0)];
        step(&mut s, &[poor(1, 5), good(2, 0)], c.at(299));
        assert_eq!(step(&mut s, &now_good, c.at(300)), Decision::Stay);
        assert_eq!(step(&mut s, &now_good, c.at(329)), Decision::Stay);
        assert_eq!(
            step(&mut s, &now_good, c.at(330)),
            moved(1, MoveReason::Preferred, Some(2))
        );
    }

    #[test]
    fn a_preferred_path_that_wobbles_while_recovering_starts_its_proof_again() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(2), c.at(0));
        let now_good = [good(1, 5), good(2, 0)];
        step(&mut s, &now_good, c.at(300));
        step(&mut s, &now_good, c.at(320));
        step(&mut s, &[poor(1, 5), good(2, 0)], c.at(321));
        assert_eq!(step(&mut s, &now_good, c.at(322)), Decision::Stay);
        assert_eq!(step(&mut s, &now_good, c.at(340)), Decision::Stay);
        assert_eq!(
            step(&mut s, &now_good, c.at(352)),
            moved(1, MoveReason::Preferred, Some(2))
        );
    }

    #[test]
    fn a_path_is_not_left_for_one_the_user_likes_equally_or_less() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        for t in [200, 400, 800] {
            let d = step(&mut s, &[good(1, 5), good(2, 5), good(3, 1)], c.at(t));
            assert_eq!(d, Decision::Stay, "t={t}");
        }
    }

    #[test]
    fn a_preferred_path_that_is_itself_poor_is_not_returned_to() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(2), c.at(0));
        for t in [200, 300, 400] {
            assert_eq!(
                step(&mut s, &[poor(1, 5), good(2, 0)], c.at(t)),
                Decision::Stay
            );
        }
    }

    // ------------------------------------------------------------------ limits (SC-007)

    #[test]
    fn after_a_move_nothing_voluntary_happens_until_the_dwell_has_passed() {
        let c = Clock::new();
        // Path 1 is lost at t=1000 and the machine moves to 2, which goes poor straight away while
        // 3 has been good all along. The move starts the dwell.
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [poor(2, 0), good(3, 0)];
        assert_eq!(
            step(&mut s, &[down(1, 0), good(2, 0), good(3, 0)], c.at(1000)),
            moved(2, MoveReason::Lost, Some(1))
        );
        step(&mut s, &paths, c.at(1001));
        assert_eq!(
            step(&mut s, &paths, c.at(1100)),
            Decision::Stay,
            "still dwelling"
        );
        assert_eq!(step(&mut s, &paths, c.at(1119)), Decision::Stay);
        assert_eq!(
            step(&mut s, &paths, c.at(1120)),
            moved(3, MoveReason::Degraded, Some(2))
        );
    }

    /// Acquiring a first path disturbs nothing, so it owes no dwell and uses no budget: a first
    /// choice that proves dead is left as soon as the evidence is in.
    #[test]
    fn a_first_choice_that_proves_dead_is_left_without_waiting_out_a_dwell() {
        let c = Clock::new();
        let mut s = FailoverState::new();
        assert_eq!(
            step(&mut s, &[good(1, 0), good(2, 0)], c.at(0)),
            moved(1, MoveReason::Acquired, None)
        );
        let paths = [unusable(1, 0), poor(2, 0)];
        step(&mut s, &paths, c.at(1));
        assert_eq!(
            step(&mut s, &paths, c.at(5)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    #[test]
    fn a_path_adopted_while_running_owes_no_dwell_either() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        let paths = [unusable(1, 0), poor(2, 0)];
        step(&mut s, &paths, c.at(1));
        assert_eq!(
            step(&mut s, &paths, c.at(5)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    #[test]
    fn the_budget_refuses_a_fifth_voluntary_move_in_ten_minutes() {
        let c = Clock::new();
        let mut s = FailoverState::carrying_on(id(1), c.at(0));
        // Four moves already spent, the last long enough ago to be past the dwell.
        s.moves = VecDeque::from([c.at(100), c.at(200), c.at(300), c.at(400)]);
        s.moved_at = Some(c.at(400));
        let paths = [poor(1, 0), good(2, 0)];
        step(&mut s, &paths, c.at(540));
        assert_eq!(
            step(&mut s, &paths, c.at(590)),
            Decision::Stay,
            "dwell is over but four moves are inside the window"
        );
        // At t=700 the move from t=100 has left the window.
        assert_eq!(
            step(&mut s, &paths, c.at(700)),
            moved(2, MoveReason::Degraded, Some(1))
        );
    }

    /// SC-007 as a property: whatever the qualities do, no ten minutes hold more than four moves.
    /// Two paths whose qualities swap every few seconds, for several swap periods, with the real
    /// smoothing in the loop.
    #[test]
    fn fluctuating_quality_never_causes_more_than_four_moves_in_ten_minutes() {
        for period in [2u64, 3, 5, 7, 11, 17, 29, 41, 60] {
            let c = Clock::new();
            let cfg = cfg();
            let mut state = FailoverState::new();
            let mut quality = [PathQuality::unmeasured(), PathQuality::unmeasured()];
            let mut moves: Vec<u64> = Vec::new();
            for t in 0..3600u64 {
                // Path A is bad in even periods, path B in odd ones: one of them always is.
                let a_bad = (t / period) % 2 == 0;
                let sample = |bad: bool| {
                    if bad {
                        PathSample::Lost
                    } else {
                        PathSample::Answered {
                            rtt: Duration::from_millis(40),
                        }
                    }
                };
                quality[0] = quality[0].observe(sample(a_bad));
                quality[1] = quality[1].observe(sample(!a_bad));
                let paths = [
                    NetworkPath {
                        quality: quality[0].clone(),
                        ..good(1, 0)
                    },
                    NetworkPath {
                        quality: quality[1].clone(),
                        ..good(2, 0)
                    },
                ];
                let (next, decision) = state.evaluate(&paths, c.at(t), &cfg);
                state = next;
                if let Decision::Move { reason, .. } = decision {
                    if reason != MoveReason::Acquired {
                        moves.push(t);
                    }
                }
            }
            for (i, start) in moves.iter().enumerate() {
                let inside = moves[i..].iter().take_while(|m| **m - start < 600).count();
                assert!(
                    inside <= 4,
                    "period {period}: {inside} moves from t={start}: {moves:?}"
                );
            }
        }
    }
}
