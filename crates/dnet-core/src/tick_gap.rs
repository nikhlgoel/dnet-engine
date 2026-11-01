//! T162 — noticing that the machine was frozen (`docs/research/2026-10-31-solutions.md` section 6).
//!
//! A laptop that sleeps does not always say so: on Modern Standby the old suspend messages are not a
//! reliable signal. What cannot be hidden is time. A service that ticks every second and finds that
//! one tick came many seconds late knows the machine was not running in between, whatever the system
//! told it. After such a gap every measurement about the network is stale, so the connection must
//! look again before it claims to be fine.
//!
//! Pure: no clock is read here. The caller gives the two readings it has, and the detector says
//! whether the time between ticks was longer than a tick can be.
//!
//! **Two clocks, because either can be wrong.** A monotonic clock may or may not count time spent
//! asleep, depending on the system; the wall clock does, but a person or the network can set it. So a
//! gap is reported when *either* shows one. A wall clock set forward is a false alarm, and its cost is
//! one extra look at the network; a gap that goes unnoticed costs a connection that claims to be up
//! and is not, so the detector errs toward noticing. A clock that goes **backward** is never a gap.

use std::time::Duration;

/// How much later than scheduled a tick may be before the machine is taken to have been frozen. A
/// busy machine can delay a tick by a moment; it cannot delay one by this much for any ordinary
/// reason.
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(5);

/// A stretch of time during which the machine was not running, as far as the detector can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// How much longer than scheduled the tick took (never zero).
    pub late_by: Duration,
}

/// Watches the spacing of ticks that are meant to come every `period`.
#[derive(Debug, Clone)]
pub struct TickGap {
    period: Duration,
    tolerance: Duration,
    last: Option<Reading>,
}

#[derive(Debug, Clone, Copy)]
struct Reading {
    monotonic: Duration,
    wall: Duration,
}

impl TickGap {
    pub fn new(period: Duration, tolerance: Duration) -> Self {
        Self {
            period,
            tolerance,
            last: None,
        }
    }

    /// Record a tick. `monotonic` and `wall` are readings of the two clocks as time since any fixed
    /// point (their origins do not matter, only the differences). Returns the gap if the time since
    /// the previous tick was longer than `period + tolerance` on either clock. The first tick has
    /// nothing to compare with and never reports one.
    pub fn tick(&mut self, monotonic: Duration, wall: Duration) -> Option<Gap> {
        let now = Reading { monotonic, wall };
        let previous = self.last.replace(now)?;
        // `saturating_sub`: a clock that went backward gives zero, which is no gap.
        let elapsed = now
            .monotonic
            .saturating_sub(previous.monotonic)
            .max(now.wall.saturating_sub(previous.wall));
        let allowed = self.period.saturating_add(self.tolerance);
        (elapsed > allowed).then(|| Gap {
            late_by: elapsed.saturating_sub(self.period),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn detector() -> TickGap {
        TickGap::new(SECOND, DEFAULT_TOLERANCE)
    }

    #[test]
    fn steady_ticks_are_no_gap() {
        let mut gap = detector();
        for n in 0..100 {
            assert_eq!(gap.tick(secs(n), secs(1_000 + n)), None, "tick {n}");
        }
    }

    #[test]
    fn the_first_tick_has_nothing_to_compare_with() {
        assert_eq!(detector().tick(secs(500), secs(9_999)), None);
    }

    #[test]
    fn a_tick_that_is_a_little_late_is_not_a_gap() {
        let mut gap = detector();
        gap.tick(secs(0), secs(0));
        // 1 s period + 5 s tolerance: exactly 6 s is still on time.
        assert_eq!(gap.tick(secs(6), secs(6)), None);
        // A busy machine delaying one tick by three seconds is not a sleep.
        assert_eq!(gap.tick(secs(9), secs(9)), None);
    }

    #[test]
    fn a_long_silence_on_both_clocks_is_a_gap_and_says_how_late() {
        let mut gap = detector();
        gap.tick(secs(0), secs(0));
        let found = gap.tick(secs(600), secs(600)).expect("a ten-minute freeze");
        assert_eq!(found.late_by, secs(599));
    }

    /// The monotonic clock may not count the time asleep; the wall clock does. Either is enough.
    #[test]
    fn a_sleep_the_monotonic_clock_did_not_count_is_seen_by_the_wall_clock() {
        let mut gap = detector();
        gap.tick(secs(10), secs(1_000));
        let found = gap
            .tick(secs(11), secs(1_000 + 1_800))
            .expect("half an hour asleep");
        assert_eq!(found.late_by, secs(1_799));
    }

    #[test]
    fn a_wall_clock_that_stood_still_does_not_hide_a_gap_the_monotonic_clock_saw() {
        let mut gap = detector();
        gap.tick(secs(0), secs(1_000));
        assert!(gap.tick(secs(120), secs(1_000)).is_some());
    }

    /// Setting the clock back (a person, a time sync) is never a gap, and does not break the next tick.
    #[test]
    fn a_clock_set_backward_is_not_a_gap() {
        let mut gap = detector();
        gap.tick(secs(100), secs(5_000));
        assert_eq!(gap.tick(secs(101), secs(1_000)), None);
        // And afterwards the spacing is judged from the new reading.
        assert_eq!(gap.tick(secs(102), secs(1_001)), None);
        assert!(gap.tick(secs(200), secs(1_099)).is_some());
    }

    #[test]
    fn a_gap_is_reported_once_and_the_next_tick_is_judged_afresh() {
        let mut gap = detector();
        gap.tick(secs(0), secs(0));
        assert!(gap.tick(secs(300), secs(300)).is_some());
        assert_eq!(gap.tick(secs(301), secs(301)), None);
        assert_eq!(gap.tick(secs(302), secs(302)), None);
    }

    #[test]
    fn the_tolerance_is_the_line_between_busy_and_frozen() {
        let mut tight = TickGap::new(SECOND, secs(1));
        tight.tick(secs(0), secs(0));
        assert_eq!(
            tight.tick(secs(2), secs(2)),
            None,
            "2 s = period + tolerance"
        );
        assert!(tight.tick(secs(5), secs(5)).is_some(), "3 s late");
    }

    #[test]
    fn readings_at_the_extremes_do_not_overflow() {
        let mut gap = TickGap::new(Duration::MAX, Duration::MAX);
        gap.tick(Duration::ZERO, Duration::ZERO);
        assert_eq!(gap.tick(Duration::MAX, Duration::MAX), None);
        let mut gap = detector();
        gap.tick(Duration::ZERO, Duration::ZERO);
        assert!(gap.tick(Duration::MAX, Duration::MAX).is_some());
    }
}
