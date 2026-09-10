//! `EndpointHealth` state machine (data-model §1.1).
//!
//! Pure logic: callers pass in the probe outcome and the time, and this module does
//! no I/O. Transitions return a new value rather than mutating in place.
//!
//! ```text
//!                     probe ok (rtt<250ms, no loss)
//! Unknown ────────────────────────────────────────────▶ Healthy
//!    │                                                    │  ▲
//!    │ probe fail (immediately)                           │  │ 3 good probes
//!    ▼                                                    ▼  │
//! Unreachable ◀── N consecutive failures ──────── Degraded ──┘
//!    │                                             ▲
//!    └── probe ok ──▶ Healthy   (recovery)         │ 2 probes rtt>250ms OR loss
//! ```
//!
//! Smoothing constants are the standard TCP values (RFC 6298 / Jacobson-Karels):
//! `α = 1/8` for the RTT estimate, `β = 1/4` for the RTT variance.

use std::time::{Duration, Instant};

/// Default number of consecutive failed probes before an endpoint is `Unreachable`.
pub const DEFAULT_UNREACHABLE_AFTER: u32 = 3;

/// A successful probe slower than this, or reporting loss, counts as bad quality.
pub const DEGRADED_RTT_THRESHOLD: Duration = Duration::from_millis(250);

/// Consecutive bad-quality probes that move `Healthy → Degraded`.
pub const DEGRADED_AFTER_BAD: u32 = 2;

/// Consecutive good-quality probes that move `Degraded → Healthy`.
pub const HEALTHY_AFTER_GOOD: u32 = 3;

/// EWMA weight for the smoothed RTT estimate (`SRTT`).
pub const RTT_EWMA_ALPHA: f64 = 0.125;

/// EWMA weight for the smoothed RTT variance (`RTTVAR`).
pub const RTTVAR_EWMA_BETA: f64 = 0.25;

/// Observable health of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Not yet probed.
    Unknown,
    /// Answering probes promptly and without loss.
    Healthy,
    /// Answering, but slowly or with loss.
    Degraded,
    /// Failed `N` consecutive probes, or failed its first probe from `Unknown`.
    /// Never terminal (FR-012, US4-3).
    Unreachable,
}

/// Result of one health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The endpoint answered after `rtt`. `loss` is true if the probe observed packet
    /// loss (e.g. a retransmit) even though it ultimately succeeded.
    Ok {
        /// Measured round-trip time.
        rtt: Duration,
        /// Whether the probe observed packet loss.
        loss: bool,
    },
    /// The endpoint did not answer.
    Failed,
}

impl ProbeOutcome {
    /// A good-quality success: fast and lossless.
    fn is_good_quality(&self) -> bool {
        matches!(self, ProbeOutcome::Ok { rtt, loss } if *rtt < DEGRADED_RTT_THRESHOLD && !*loss)
    }
}

/// Tunable thresholds for health evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// Consecutive failures that mark an endpoint `Unreachable`.
    pub unreachable_after: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            unreachable_after: DEFAULT_UNREACHABLE_AFTER,
        }
    }
}

/// Health of one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealth {
    pub state: HealthState,
    pub last_probe: Option<Instant>,
    pub consecutive_failures: u32,
    /// Successful-but-slow/lossy probes in a row; drives `Healthy → Degraded`.
    pub consecutive_bad_quality: u32,
    /// Fast, lossless probes in a row; drives `Degraded → Healthy`.
    pub consecutive_good_quality: u32,
    /// Smoothed round-trip time; feeds selection among healthy endpoints.
    pub rtt_ewma: Option<Duration>,
    /// Smoothed round-trip-time variance; reserved for future RTO/quality scoring.
    pub rttvar_ewma: Option<Duration>,
}

/// The result of applying one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// Health after the probe.
    pub next: EndpointHealth,
    /// `true` only on the probe that moves the endpoint **into** `Unreachable`.
    ///
    /// On the active endpoint this raises a `ConnectionEvent`, so the user is told
    /// rather than migrated silently (data-model §1.1, FR-012).
    pub became_unreachable: bool,
}

impl EndpointHealth {
    /// A never-probed endpoint.
    pub fn new() -> Self {
        Self {
            state: HealthState::Unknown,
            last_probe: None,
            consecutive_failures: 0,
            consecutive_bad_quality: 0,
            consecutive_good_quality: 0,
            rtt_ewma: None,
            rttvar_ewma: None,
        }
    }

    /// Apply one probe outcome observed at `at`, returning the resulting health.
    #[must_use]
    pub fn on_probe(&self, outcome: ProbeOutcome, at: Instant, cfg: &HealthConfig) -> Transition {
        let prev = self.state;
        let mut next = self.clone();
        next.last_probe = Some(at);

        match outcome {
            ProbeOutcome::Failed => {
                next.consecutive_failures = self.consecutive_failures.saturating_add(1);
                // A failure is not a quality sample and measures no round trip.
                next.consecutive_bad_quality = 0;
                next.consecutive_good_quality = 0;
                // Unreachable on: the first failure from Unknown, the Nth consecutive
                // failure, or a failure while already Unreachable. Otherwise (Healthy
                // or Degraded, below threshold) the state is unchanged.
                let now_unreachable = prev == HealthState::Unknown
                    || prev == HealthState::Unreachable
                    || next.consecutive_failures >= cfg.unreachable_after;
                next.state = if now_unreachable {
                    HealthState::Unreachable
                } else {
                    prev
                };
            }
            ProbeOutcome::Ok { rtt, .. } => {
                next.consecutive_failures = 0;
                next.update_rtt(rtt);
                if outcome.is_good_quality() {
                    next.consecutive_good_quality = self.consecutive_good_quality.saturating_add(1);
                    next.consecutive_bad_quality = 0;
                } else {
                    next.consecutive_bad_quality = self.consecutive_bad_quality.saturating_add(1);
                    next.consecutive_good_quality = 0;
                }
                next.state = next.state_after_success(prev);
            }
        }

        let became_unreachable =
            prev != HealthState::Unreachable && next.state == HealthState::Unreachable;
        Transition {
            next,
            became_unreachable,
        }
    }

    /// State after a successful probe, given the previous state and the freshly
    /// updated quality counters on `self`.
    fn state_after_success(&self, prev: HealthState) -> HealthState {
        match prev {
            // First contact or recovery: land in Healthy, unless this very probe is the
            // second consecutive bad-quality one (which cannot happen from Unreachable,
            // whose counters were just reset, but is handled uniformly here).
            HealthState::Unknown | HealthState::Unreachable | HealthState::Healthy => {
                if self.consecutive_bad_quality >= DEGRADED_AFTER_BAD {
                    HealthState::Degraded
                } else {
                    HealthState::Healthy
                }
            }
            HealthState::Degraded => {
                if self.consecutive_good_quality >= HEALTHY_AFTER_GOOD {
                    HealthState::Healthy
                } else {
                    HealthState::Degraded
                }
            }
        }
    }

    /// Update the smoothed RTT and its variance with one measured sample.
    ///
    /// First sample seeds the estimators as RFC 6298 specifies (`SRTT = R`,
    /// `RTTVAR = R/2`); later samples use the α/β EWMA recurrences. A failed probe
    /// never calls this — it measured no round trip.
    fn update_rtt(&mut self, sample: Duration) {
        let r = sample.as_secs_f64();
        match self.rtt_ewma {
            None => {
                self.rtt_ewma = Some(sample);
                self.rttvar_ewma = Some(sample / 2);
            }
            Some(srtt) => {
                let srtt = srtt.as_secs_f64();
                let rttvar = self.rttvar_ewma.map(|v| v.as_secs_f64()).unwrap_or(0.0);
                let new_rttvar =
                    (1.0 - RTTVAR_EWMA_BETA) * rttvar + RTTVAR_EWMA_BETA * (srtt - r).abs();
                let new_srtt = (1.0 - RTT_EWMA_ALPHA) * srtt + RTT_EWMA_ALPHA * r;
                self.rtt_ewma = Some(Duration::from_secs_f64(new_srtt.max(0.0)));
                self.rttvar_ewma = Some(Duration::from_secs_f64(new_rttvar.max(0.0)));
            }
        }
    }
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self::new()
    }
}
