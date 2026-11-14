// SPDX-License-Identifier: GPL-3.0-or-later
//! T182 — a transport process that exits on its own is started again, a few times, before anyone calls a profile
//! blocked.
//!
//! A program that stops by itself is a crash, not a censor: nothing on the network told it to. Treating it as a
//! block (the way a run of failed live checks is) would cost the retry wait of `reprobe.rs` (a minute, growing to a
//! quarter of an hour) and, with no other profile left, a failed connection, for what a restart usually fixes. But
//! a program that keeps exiting is not fixed by restarting it forever, so after [`RESTARTS_ALLOWED`] exits inside
//! [`CRASH_WINDOW`] the next one is judged as a block, and the engine takes the same road it takes for a profile
//! that stopped carrying traffic: stop, fail closed, try what is left.
//!
//! Pure: the clock is passed in, so every edge is tested without waiting.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many times in a row a transport process that exited on its own is started again, within [`CRASH_WINDOW`].
pub const RESTARTS_ALLOWED: usize = 2;

/// How long an exit counts against the budget. An exit exactly this old no longer does.
pub const CRASH_WINDOW: Duration = Duration::from_secs(300);

/// What to do about one exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashDecision {
    /// Start it again. `attempt` is which restart this is, counting from 1.
    Restart { attempt: usize },
    /// It has exited too often: treat the profile as blocked. `exits` is how many exits fell inside the window.
    GiveUp { exits: usize },
}

/// The exits of the current connection, newest last. Never longer than it needs to be to tell the two answers
/// apart, so a process that exits every second for a day costs no memory.
#[derive(Debug, Clone, Default)]
pub struct CrashTracker {
    exits: VecDeque<Instant>,
}

impl CrashTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Note an exit at `now` and say what to do about it.
    pub fn record(&mut self, now: Instant) -> CrashDecision {
        while let Some(&oldest) = self.exits.front() {
            if now.saturating_duration_since(oldest) >= CRASH_WINDOW {
                self.exits.pop_front();
            } else {
                break;
            }
        }
        self.exits.push_back(now);
        while self.exits.len() > RESTARTS_ALLOWED + 1 {
            self.exits.pop_front();
        }
        let exits = self.exits.len();
        if exits <= RESTARTS_ALLOWED {
            CrashDecision::Restart { attempt: exits }
        } else {
            CrashDecision::GiveUp { exits }
        }
    }

    /// Forget every exit: a new connection starts with a clean budget.
    pub fn reset(&mut self) {
        self.exits.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn the_first_two_exits_are_restarted_and_the_third_in_the_window_gives_up() {
        let t0 = Instant::now();
        let mut tracker = CrashTracker::new();
        assert_eq!(
            tracker.record(at(t0, 0)),
            CrashDecision::Restart { attempt: 1 }
        );
        assert_eq!(
            tracker.record(at(t0, 1)),
            CrashDecision::Restart { attempt: 2 }
        );
        assert_eq!(
            tracker.record(at(t0, 2)),
            CrashDecision::GiveUp { exits: 3 }
        );
    }

    #[test]
    fn an_exit_exactly_one_window_old_no_longer_counts_and_one_second_younger_does() {
        let t0 = Instant::now();
        let window = CRASH_WINDOW.as_secs();

        let mut tracker = CrashTracker::new();
        tracker.record(at(t0, 0));
        tracker.record(at(t0, 100));
        assert_eq!(
            tracker.record(at(t0, window)),
            CrashDecision::Restart { attempt: 2 },
            "the exit at 0 is exactly one window old and has left it"
        );

        let mut tracker = CrashTracker::new();
        tracker.record(at(t0, 0));
        tracker.record(at(t0, 100));
        assert_eq!(
            tracker.record(at(t0, window - 1)),
            CrashDecision::GiveUp { exits: 3 },
            "one second younger, it still counts"
        );
    }

    #[test]
    fn a_calm_stretch_gives_the_budget_back() {
        let t0 = Instant::now();
        let mut tracker = CrashTracker::new();
        for s in [0, 1, 2] {
            tracker.record(at(t0, s));
        }
        assert_eq!(
            tracker.record(at(t0, 2 + CRASH_WINDOW.as_secs())),
            CrashDecision::Restart { attempt: 1 },
            "everything before has left the window"
        );
    }

    #[test]
    fn a_new_connection_starts_with_a_clean_budget() {
        let t0 = Instant::now();
        let mut tracker = CrashTracker::new();
        tracker.record(at(t0, 0));
        tracker.record(at(t0, 1));
        tracker.reset();
        assert_eq!(
            tracker.record(at(t0, 2)),
            CrashDecision::Restart { attempt: 1 }
        );
    }

    #[test]
    fn a_process_that_exits_every_second_costs_no_memory_and_is_always_given_up_on() {
        let t0 = Instant::now();
        let mut tracker = CrashTracker::new();
        for s in 0..100_000 {
            let decision = tracker.record(at(t0, s));
            if s >= RESTARTS_ALLOWED as u64 {
                assert!(
                    matches!(decision, CrashDecision::GiveUp { .. }),
                    "second {s}"
                );
            }
            assert!(tracker.exits.len() <= RESTARTS_ALLOWED + 1);
        }
    }

    #[test]
    fn a_clock_that_runs_backwards_cannot_make_an_old_exit_vanish() {
        let t0 = at(Instant::now(), 1_000);
        let mut tracker = CrashTracker::new();
        tracker.record(t0);
        tracker.record(t0);
        // Earlier than both: the gap saturates to zero, so both still count.
        let earlier = t0 - Duration::from_secs(500);
        assert_eq!(tracker.record(earlier), CrashDecision::GiveUp { exits: 3 });
    }
}
