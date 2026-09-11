//! T044 — bounded, jittered restart backoff (SUP-02, SUP-03).
//!
//! Restart-on-exit must not loop forever: the backoff has a ceiling and an attempt
//! limit, and once the limit is exceeded supervision gives up and reports
//! `CoreFailedPersistently` (SUP-T1). The policy is a pure function of the attempt
//! number, so it is fully testable without spawning anything.

use std::time::Duration;

/// What to do after a core exits unexpectedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    /// Wait this long, then restart.
    RetryAfter(Duration),
    /// The attempt limit is exceeded; stop restarting and fail persistently.
    GiveUp,
}

/// Exponential backoff with a ceiling and a hard attempt limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    base: Duration,
    ceiling: Duration,
    max_attempts: u32,
}

impl RestartPolicy {
    /// A policy with an explicit base delay, ceiling, and attempt limit.
    pub fn new(base: Duration, ceiling: Duration, max_attempts: u32) -> Self {
        Self {
            base,
            ceiling,
            max_attempts,
        }
    }

    /// The default for supervised cores: 500 ms base, 30 s ceiling, 8 attempts.
    pub fn for_cores() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30), 8)
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Decide what to do for the given 1-based restart `attempt`.
    ///
    /// `jitter` in `[0.0, 1.0]` scales the delay by equal jitter — the delay lands in
    /// `[capped/2, capped]`, so it is never zero and never exceeds the ceiling. Passing
    /// the jitter in keeps the decision deterministic and testable; the caller supplies
    /// a random value in production.
    pub fn decide(&self, attempt: u32, jitter: f64) -> RestartDecision {
        if attempt == 0 || attempt > self.max_attempts {
            return RestartDecision::GiveUp;
        }
        let capped = self.capped_delay(attempt);
        let jitter = jitter.clamp(0.0, 1.0);
        let scaled = capped.mul_f64(0.5 + 0.5 * jitter);
        RestartDecision::RetryAfter(scaled.min(capped))
    }

    /// `base * 2^(attempt-1)`, saturated at the ceiling. The shift is bounded because
    /// `attempt <= max_attempts`, so the exponent stays small.
    fn capped_delay(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(20);
        let factor = 1u64 << shift;
        let millis = (self.base.as_millis() as u64).saturating_mul(factor);
        Duration::from_millis(millis).min(self.ceiling)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_up_once_the_attempt_limit_is_exceeded() {
        let policy = RestartPolicy::new(Duration::from_millis(100), Duration::from_secs(10), 5);
        for attempt in 1..=5 {
            assert!(matches!(
                policy.decide(attempt, 1.0),
                RestartDecision::RetryAfter(_)
            ));
        }
        assert_eq!(policy.decide(6, 1.0), RestartDecision::GiveUp);
        assert_eq!(policy.decide(0, 1.0), RestartDecision::GiveUp);
    }

    #[test]
    fn delay_grows_but_never_exceeds_the_ceiling() {
        let policy = RestartPolicy::new(Duration::from_millis(500), Duration::from_secs(4), 10);
        // Full jitter (1.0) yields the capped delay exactly.
        let d1 = match policy.decide(1, 1.0) {
            RestartDecision::RetryAfter(d) => d,
            _ => panic!(),
        };
        let d3 = match policy.decide(3, 1.0) {
            RestartDecision::RetryAfter(d) => d,
            _ => panic!(),
        };
        assert_eq!(d1, Duration::from_millis(500));
        assert_eq!(d3, Duration::from_millis(2000));
        // By attempt 5 the raw delay (8s) is past the 4s ceiling.
        let d5 = match policy.decide(5, 1.0) {
            RestartDecision::RetryAfter(d) => d,
            _ => panic!(),
        };
        assert_eq!(d5, Duration::from_secs(4));
    }

    #[test]
    fn equal_jitter_keeps_the_delay_in_the_lower_half() {
        let policy = RestartPolicy::new(Duration::from_millis(1000), Duration::from_secs(60), 8);
        // jitter 0.0 -> half the capped delay, never zero.
        assert_eq!(
            policy.decide(1, 0.0),
            RestartDecision::RetryAfter(Duration::from_millis(500))
        );
    }
}
