//! T060 — noticing that the active profile has been blocked, and what to try next
//! (FR-005, SC-004).
//!
//! While connected, the daemon checks the carrying profile periodically by moving a little
//! traffic through it. [`BlockDetector`] turns those checks into a decision:
//!
//! - One failure is a hiccup. [`BLOCK_AFTER`] failures **in a row** is a block; any success in
//!   between starts the count again, so a flaky link is not mistaken for a block.
//! - A block is reported exactly once, so the caller raises one `ProfileBlocked` event and
//!   starts one recovery, not one per sample.
//!
//! [`plan_reprobe`] then lists what to try, and says so plainly when nothing is left, which the
//! caller reports as `AllProfilesBlocked` rather than looping. Recovery has to finish within
//! [`RECOVERY_BUDGET`] (SC-004), which the caller uses to bound its own attempts.

use std::time::Duration;

use crate::ids::ProfileId;
use crate::profile::{ConnectionProfile, Viability};

/// Consecutive failed live checks that make a block.
pub const BLOCK_AFTER: u32 = 3;
/// Traffic must be flowing again within this long of a block being noticed (SC-004).
pub const RECOVERY_BUDGET: Duration = Duration::from_secs(30);
/// First wait before a blocked profile is tried again.
pub const RETRY_BASE: Duration = Duration::from_secs(60);
/// The longest wait between attempts on a blocked profile.
pub const RETRY_CAP: Duration = Duration::from_secs(900);

/// The result of one live check of the carrying profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCheck {
    Passed,
    Failed,
}

/// What a live check means for the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// Working, or not yet enough failures to say otherwise.
    Fine,
    /// `failures` in a row, short of a block.
    Suspect { failures: u32 },
    /// The profile is blocked. Returned once, on the check that crosses the line.
    Blocked { failures: u32 },
    /// A block was already reported and the profile has not passed since. Nothing new to do.
    AlreadyBlocked,
}

/// Watches the carrying profile.
#[derive(Debug, Clone, Default)]
pub struct BlockDetector {
    failures: u32,
    reported: bool,
}

impl BlockDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one live check.
    pub fn observe(&mut self, check: LiveCheck) -> Detection {
        match check {
            LiveCheck::Passed => {
                *self = Self::default();
                Detection::Fine
            }
            LiveCheck::Failed => {
                self.failures = self.failures.saturating_add(1);
                if self.reported {
                    Detection::AlreadyBlocked
                } else if self.failures >= BLOCK_AFTER {
                    self.reported = true;
                    Detection::Blocked {
                        failures: self.failures,
                    }
                } else {
                    Detection::Suspect {
                        failures: self.failures,
                    }
                }
            }
        }
    }

    /// Start over, for a newly selected profile.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// What to try after a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReprobePlan {
    /// Try these profiles, in this order, in parallel as a probe race.
    Try(Vec<ProfileId>),
    /// Nothing else to try: every profile is blocked.
    AllBlocked,
}

/// Plan the recovery after `blocked` stopped working. Profiles already known to be blocked are
/// not retried here; they wait out [`retry_delay`] first. Candidates are ordered best tier first,
/// then in the order given.
pub fn plan_reprobe(profiles: &[ConnectionProfile], blocked: &ProfileId) -> ReprobePlan {
    let mut candidates: Vec<&ConnectionProfile> = profiles
        .iter()
        .filter(|p| p.id() != blocked)
        .filter(|p| !matches!(p.viability(), Viability::Blocked { .. }))
        .collect();
    // Stable: equal tiers keep the given order.
    candidates.sort_by_key(|p| p.tier());
    if candidates.is_empty() {
        ReprobePlan::AllBlocked
    } else {
        ReprobePlan::Try(candidates.iter().map(|p| p.id().clone()).collect())
    }
}

/// How long to wait before retrying a profile that has been blocked `attempt` times already
/// (0 for the first retry): doubling from [`RETRY_BASE`], capped at [`RETRY_CAP`].
pub fn retry_delay(attempt: u32) -> Duration {
    // 2^16 already exceeds the cap many times over, and the clamp keeps the shift in range.
    (RETRY_BASE * 2u32.pow(attempt.min(16))).min(RETRY_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ProfileKind, ProfileParams};
    use crate::tier::SurvivalMeasurement;
    use std::time::Instant;

    fn id(s: &str) -> ProfileId {
        ProfileId::new(s)
    }

    fn profile(name: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(id(name), kind, ProfileParams::new())
    }

    fn tier1(name: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::measured(
            id(name),
            kind,
            ProfileParams::new(),
            SurvivalMeasurement::Survived,
        )
    }

    // ------------------------------------------------------------- detector

    #[test]
    fn passing_checks_are_fine() {
        let mut d = BlockDetector::new();
        for _ in 0..10 {
            assert_eq!(d.observe(LiveCheck::Passed), Detection::Fine);
        }
    }

    #[test]
    fn failures_below_the_threshold_are_only_suspect() {
        let mut d = BlockDetector::new();
        assert_eq!(
            d.observe(LiveCheck::Failed),
            Detection::Suspect { failures: 1 }
        );
        assert_eq!(
            d.observe(LiveCheck::Failed),
            Detection::Suspect { failures: 2 }
        );
    }

    #[test]
    fn the_nth_consecutive_failure_is_a_block() {
        let mut d = BlockDetector::new();
        for _ in 0..BLOCK_AFTER - 1 {
            d.observe(LiveCheck::Failed);
        }
        assert_eq!(
            d.observe(LiveCheck::Failed),
            Detection::Blocked {
                failures: BLOCK_AFTER
            }
        );
    }

    /// A flaky link must not look like a block.
    #[test]
    fn a_success_in_between_restarts_the_count() {
        let mut d = BlockDetector::new();
        for _ in 0..50 {
            d.observe(LiveCheck::Failed);
            d.observe(LiveCheck::Failed);
            assert_eq!(d.observe(LiveCheck::Passed), Detection::Fine);
        }
    }

    #[test]
    fn a_block_is_reported_once() {
        let mut d = BlockDetector::new();
        for _ in 0..BLOCK_AFTER {
            d.observe(LiveCheck::Failed);
        }
        for _ in 0..5 {
            assert_eq!(
                d.observe(LiveCheck::Failed),
                Detection::AlreadyBlocked,
                "further failures must not re-raise the block"
            );
        }
    }

    /// If the same profile starts working again before it is replaced, it is watched afresh.
    #[test]
    fn a_success_after_a_reported_block_clears_it() {
        let mut d = BlockDetector::new();
        for _ in 0..BLOCK_AFTER {
            d.observe(LiveCheck::Failed);
        }
        assert_eq!(d.observe(LiveCheck::Passed), Detection::Fine);
        for _ in 0..BLOCK_AFTER - 1 {
            d.observe(LiveCheck::Failed);
        }
        assert!(matches!(
            d.observe(LiveCheck::Failed),
            Detection::Blocked { .. }
        ));
    }

    #[test]
    fn reset_clears_a_reported_block_for_the_next_profile() {
        let mut d = BlockDetector::new();
        for _ in 0..BLOCK_AFTER {
            d.observe(LiveCheck::Failed);
        }
        d.reset();
        for _ in 0..BLOCK_AFTER - 1 {
            d.observe(LiveCheck::Failed);
        }
        assert!(matches!(
            d.observe(LiveCheck::Failed),
            Detection::Blocked { .. }
        ));
    }

    // ----------------------------------------------------------------- plan

    #[test]
    fn the_plan_excludes_the_blocked_profile_and_known_blocked_ones() {
        let mut known_blocked = profile("reality", ProfileKind::VlessReality);
        known_blocked.mark_blocked(Instant::now(), "reset");
        let profiles = [
            profile("awg", ProfileKind::AmneziaWg),
            profile("hy2", ProfileKind::Hysteria2),
            known_blocked,
        ];
        assert_eq!(
            plan_reprobe(&profiles, &id("awg")),
            ReprobePlan::Try(vec![id("hy2")])
        );
    }

    #[test]
    fn the_plan_orders_tier1_first_then_the_given_order() {
        let profiles = [
            profile("awg", ProfileKind::AmneziaWg),
            profile("reality", ProfileKind::VlessReality),
            tier1("hy2", ProfileKind::Hysteria2),
            profile("other", ProfileKind::AmneziaWg),
        ];
        assert_eq!(
            plan_reprobe(&profiles, &id("awg")),
            ReprobePlan::Try(vec![id("hy2"), id("reality"), id("other")])
        );
    }

    #[test]
    fn with_nothing_left_to_try_everything_is_blocked() {
        let mut other = profile("reality", ProfileKind::VlessReality);
        other.mark_blocked(Instant::now(), "reset");
        let profiles = [profile("awg", ProfileKind::AmneziaWg), other];
        assert_eq!(plan_reprobe(&profiles, &id("awg")), ReprobePlan::AllBlocked);
        assert_eq!(plan_reprobe(&[], &id("awg")), ReprobePlan::AllBlocked);
    }

    // -------------------------------------------------------------- backoff

    #[test]
    fn retries_double_from_the_base_and_stop_at_the_cap() {
        assert_eq!(retry_delay(0), RETRY_BASE);
        assert_eq!(retry_delay(1), RETRY_BASE * 2);
        assert_eq!(retry_delay(2), RETRY_BASE * 4);
        assert_eq!(
            retry_delay(4),
            RETRY_CAP,
            "60 s * 16 = 960 s is capped at 900 s"
        );
        assert_eq!(
            retry_delay(100),
            RETRY_CAP,
            "a huge attempt count does not overflow"
        );
        assert_eq!(retry_delay(u32::MAX), RETRY_CAP);
    }

    #[test]
    fn the_recovery_budget_is_the_documented_30_seconds() {
        assert_eq!(RECOVERY_BUDGET, Duration::from_secs(30));
    }
}
