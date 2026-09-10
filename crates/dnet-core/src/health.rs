//! `EndpointHealth` state machine (data-model §1.1).
//!
//! Pure logic: callers pass in the probe outcome and the time, and this module does
//! no I/O. Transitions return a new value rather than mutating in place.
//!
//! ```text
//! Unknown ──probe ok──▶ Healthy ──consecutive failures ≥ N──▶ Unreachable
//!                          ▲                                       │
//!                          └───────────────probe ok────────────────┘
//! ```

use std::time::{Duration, Instant};

/// Default number of consecutive failed probes before an endpoint is `Unreachable`.
pub const DEFAULT_UNREACHABLE_AFTER: u32 = 3;

/// Observable health of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Not yet probed.
    Unknown,
    /// Answering probes.
    Healthy,
    /// Listed in the data model; its entry and exit are not yet specified.
    Degraded,
    /// Failed `N` consecutive probes. Never terminal (FR-012, US4-3).
    Unreachable,
}

/// Result of one health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The endpoint answered after `rtt`.
    Ok {
        /// Measured round-trip time.
        rtt: Duration,
    },
    /// The endpoint did not answer.
    Failed,
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
    /// Smoothed round-trip time; feeds selection among healthy endpoints.
    pub rtt_ewma: Option<Duration>,
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
            rtt_ewma: None,
        }
    }

    /// Apply one probe outcome observed at `at`.
    #[must_use]
    pub fn on_probe(
        &self,
        _outcome: ProbeOutcome,
        _at: Instant,
        _cfg: &HealthConfig,
    ) -> Transition {
        todo!("T025: implement EndpointHealth transitions")
    }
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self::new()
    }
}
