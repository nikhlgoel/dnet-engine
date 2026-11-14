// SPDX-License-Identifier: GPL-3.0-or-later
//! T144 — what the interface needs to show about the networks and the session, and nothing it would
//! have to invent.
//!
//! Two small, pure pieces:
//!
//! - [`PathHistory`]: the last few readings of each network, for a trace and for "what is normal
//!   here". A reading is a latency, or a loss. Nothing is made up to fill a gap: a lost probe is a
//!   gap in the trace, and a typical range is given only once there are enough answers to mean
//!   something.
//! - [`SessionStats`]: counters of what the product *did* during a connection, taken from the events
//!   the engine already records. They are counts of facts, never a comparison with "not using the
//!   product": that would need a measurement nobody has made (Principle VI).
//!
//! What is deliberately absent: a drop counter and an "interruption" length. Nothing in the engine
//! measures when traffic stopped flowing, so neither can be reported without guessing. What can be
//! said truthfully is how often the network changed under a Tier 2 profile (which breaks established
//! connections by the profile's own terms) and how long the path was *poor* (`Degraded` to
//! `Recovered`).
//!
//! Pure logic: no clock, no I/O.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::degraded::Degradation;
use crate::ids::InterfaceId;
use crate::path::{PathKind, PathRole};
use crate::quality::{PathSample, QualityBand};
use crate::session::ConnectionEvent;
use crate::tier::FailoverTier;

/// Readings kept per network: ten minutes at the carrying path's probe interval.
pub const HISTORY_LEN: usize = 60;

/// Readings in a trace.
pub const TRACE_LEN: usize = 40;

/// Answers needed before a typical range is offered. Fewer says nothing about what is normal.
pub const MIN_FOR_TYPICAL: usize = 8;

/// One reading of a network.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Reading {
    /// Answered after this many milliseconds.
    Rtt(f32),
    Lost,
}

/// The recent readings of each network.
#[derive(Debug, Clone, Default)]
pub struct PathHistory {
    readings: HashMap<InterfaceId, VecDeque<Reading>>,
}

impl PathHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reading of `path`.
    pub fn record(&mut self, path: InterfaceId, sample: PathSample) {
        let reading = match sample {
            PathSample::Answered { rtt } => Reading::Rtt(rtt.as_secs_f32() * 1000.0),
            PathSample::Lost => Reading::Lost,
        };
        let ring = self.readings.entry(path).or_default();
        if ring.len() == HISTORY_LEN {
            ring.pop_front();
        }
        ring.push_back(reading);
    }

    /// Forget every network that is not in `keep`: one that has gone has no history worth showing,
    /// and one that comes back starts afresh.
    pub fn retain(&mut self, keep: impl Fn(InterfaceId) -> bool) {
        self.readings.retain(|id, _| keep(*id));
    }

    /// The last [`TRACE_LEN`] readings, oldest first: milliseconds, or `None` for a probe that was
    /// lost.
    pub fn trace(&self, path: InterfaceId) -> Vec<Option<f32>> {
        let Some(ring) = self.readings.get(&path) else {
            return Vec::new();
        };
        let skip = ring.len().saturating_sub(TRACE_LEN);
        ring.iter()
            .skip(skip)
            .map(|r| match r {
                Reading::Rtt(ms) => Some(*ms),
                Reading::Lost => None,
            })
            .collect()
    }

    /// What is normal for this network: the 10th and 90th percentile of the answered latencies kept,
    /// in milliseconds. `None` until [`MIN_FOR_TYPICAL`] answers have been seen.
    pub fn typical(&self, path: InterfaceId) -> Option<(f32, f32)> {
        let mut answered: Vec<f32> = self
            .readings
            .get(&path)?
            .iter()
            .filter_map(|r| match r {
                Reading::Rtt(ms) => Some(*ms),
                Reading::Lost => None,
            })
            .collect();
        if answered.len() < MIN_FOR_TYPICAL {
            return None;
        }
        answered.sort_by(f32::total_cmp);
        let at = |q: f32| answered[((answered.len() - 1) as f32 * q).round() as usize];
        Some((at(0.1), at(0.9)))
    }
}

/// One network, as the interface shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct PathView {
    pub id: InterfaceId,
    pub kind: PathKind,
    /// What the system calls it (for Wi-Fi, the network name), when the caller knows. The monitor
    /// does not: it knows interfaces, not names, and leaves this `None` for the daemon to fill.
    pub name: Option<String>,
    pub role: PathRole,
    /// Whether there is a recent measurement at all. Without one, `band`, `rtt`, `jitter` and `loss`
    /// are not to be read as "fine".
    pub measured: bool,
    pub band: Option<QualityBand>,
    pub rtt: Option<Duration>,
    pub jitter: Option<Duration>,
    pub loss: Option<f64>,
    pub trace_ms: Vec<Option<f32>>,
    pub typical_ms: Option<(f32, f32)>,
}

/// The networks, and whether the connection is on a poor one with no way out.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PathsSnapshot {
    pub paths: Vec<PathView>,
    pub degradation: Option<Degradation>,
}

/// Counters of what happened during a connection, from the events recorded.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    started: Option<Instant>,
    /// Times the carrying network changed after the first one was found.
    network_changes: u32,
    /// Of those, the ones under a Tier 2 profile, which breaks established connections.
    changes_that_drop_connections: u32,
    /// Times another connection method took over after the first was chosen.
    method_switches: u32,
    endpoint_switches: u32,
    selected_once: bool,
    degraded_periods: u32,
    degraded_since: Option<Instant>,
    longest_degraded: Duration,
}

/// What [`SessionStats::summary`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSummary {
    pub connected_for: Duration,
    pub network_changes: u32,
    pub changes_that_drop_connections: u32,
    pub method_switches: u32,
    pub endpoint_switches: u32,
    pub degraded_periods: u32,
    /// The longest time the carrying network was poor with no way out, including one still going on.
    pub longest_degraded: Duration,
}

impl SessionStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// A connection came up: start counting from nothing.
    pub fn begin(&mut self, now: Instant) {
        *self = Self {
            started: Some(now),
            ..Self::default()
        };
    }

    /// The connection ended: nothing is connected, so nothing is counted until the next one.
    pub fn end(&mut self) {
        *self = Self::default();
    }

    /// Whether a connection is being counted.
    pub fn active(&self) -> bool {
        self.started.is_some()
    }

    /// Take one recorded event into account. Events outside a counted connection are ignored.
    pub fn record(&mut self, event: &ConnectionEvent, now: Instant) {
        if self.started.is_none() {
            return;
        }
        match event {
            // The first path found is not a change; every later one is.
            ConnectionEvent::PathChanged {
                from: Some(_),
                tier_at_time,
                ..
            } => {
                self.network_changes += 1;
                if *tier_at_time == FailoverTier::Tier2 {
                    self.changes_that_drop_connections += 1;
                }
            }
            // The first method chosen is the choice; later ones are switches.
            ConnectionEvent::ProfileSelected { .. } => {
                if self.selected_once {
                    self.method_switches += 1;
                }
                self.selected_once = true;
            }
            ConnectionEvent::EndpointMigrated { .. } => self.endpoint_switches += 1,
            // A repeated `Degraded` (another reason, or worse) is the same period.
            ConnectionEvent::Degraded { .. } => {
                if self.degraded_since.is_none() {
                    self.degraded_since = Some(now);
                    self.degraded_periods += 1;
                }
            }
            ConnectionEvent::Recovered { .. } => {
                if let Some(since) = self.degraded_since.take() {
                    let lasted = now.saturating_duration_since(since);
                    self.longest_degraded = self.longest_degraded.max(lasted);
                }
            }
            _ => {}
        }
    }

    /// The counters as they stand at `now`; `None` when no connection is being counted.
    pub fn summary(&self, now: Instant) -> Option<StatsSummary> {
        let started = self.started?;
        let ongoing = self
            .degraded_since
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        Some(StatsSummary {
            connected_for: now.saturating_duration_since(started),
            network_changes: self.network_changes,
            changes_that_drop_connections: self.changes_that_drop_connections,
            method_switches: self.method_switches,
            endpoint_switches: self.endpoint_switches,
            degraded_periods: self.degraded_periods,
            longest_degraded: self.longest_degraded.max(ongoing),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::degraded::NoMove;
    use crate::ids::{EndpointId, ProfileId};

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }
    fn answered(ms: u64) -> PathSample {
        PathSample::Answered {
            rtt: Duration::from_millis(ms),
        }
    }

    // ------------------------------------------------------------------ history

    #[test]
    fn a_network_never_seen_has_no_trace_and_nothing_typical() {
        let h = PathHistory::new();
        assert_eq!(h.trace(id(1)), Vec::<Option<f32>>::new());
        assert_eq!(h.typical(id(1)), None);
    }

    #[test]
    fn a_lost_probe_is_a_gap_in_the_trace_not_a_number() {
        let mut h = PathHistory::new();
        h.record(id(1), answered(40));
        h.record(id(1), PathSample::Lost);
        h.record(id(1), answered(44));
        assert_eq!(h.trace(id(1)), [Some(40.0), None, Some(44.0)]);
    }

    #[test]
    fn the_trace_is_the_most_recent_readings_oldest_first_and_bounded() {
        let mut h = PathHistory::new();
        for n in 0..100u64 {
            h.record(id(1), answered(n));
        }
        let trace = h.trace(id(1));
        assert_eq!(trace.len(), TRACE_LEN);
        assert_eq!(trace.first(), Some(&Some(60.0)));
        assert_eq!(trace.last(), Some(&Some(99.0)));
    }

    #[test]
    fn history_is_kept_per_network() {
        let mut h = PathHistory::new();
        h.record(id(1), answered(10));
        h.record(id(2), answered(90));
        assert_eq!(h.trace(id(1)), [Some(10.0)]);
        assert_eq!(h.trace(id(2)), [Some(90.0)]);
    }

    #[test]
    fn nothing_is_called_typical_on_too_few_answers() {
        let mut h = PathHistory::new();
        for _ in 0..MIN_FOR_TYPICAL - 1 {
            h.record(id(1), answered(40));
        }
        assert_eq!(h.typical(id(1)), None);
        h.record(id(1), answered(40));
        assert_eq!(h.typical(id(1)), Some((40.0, 40.0)));
    }

    #[test]
    fn losses_do_not_count_towards_what_is_typical() {
        let mut h = PathHistory::new();
        for _ in 0..MIN_FOR_TYPICAL - 1 {
            h.record(id(1), answered(40));
        }
        for _ in 0..20 {
            h.record(id(1), PathSample::Lost);
        }
        assert_eq!(h.typical(id(1)), None, "seven answers are still seven");
    }

    #[test]
    fn typical_is_the_middle_eighty_percent() {
        let mut h = PathHistory::new();
        // 41 readings, 0..=40 ms: the 10th percentile is 4 ms, the 90th 36 ms.
        for ms in 0..=40u64 {
            h.record(id(1), answered(ms));
        }
        assert_eq!(h.typical(id(1)), Some((4.0, 36.0)));
    }

    #[test]
    fn an_outlier_does_not_widen_what_is_typical() {
        let mut h = PathHistory::new();
        for _ in 0..30 {
            h.record(id(1), answered(40));
        }
        h.record(id(1), answered(5000));
        assert_eq!(h.typical(id(1)), Some((40.0, 40.0)));
    }

    #[test]
    fn a_network_that_is_gone_is_forgotten_and_one_that_stays_is_not() {
        let mut h = PathHistory::new();
        h.record(id(1), answered(10));
        h.record(id(2), answered(20));
        h.retain(|path| path == id(2));
        assert_eq!(h.trace(id(1)), Vec::<Option<f32>>::new());
        assert_eq!(h.trace(id(2)), [Some(20.0)]);
    }

    // ------------------------------------------------------------------ session counters

    fn clock() -> Instant {
        Instant::now()
    }
    fn secs(base: Instant, n: u64) -> Instant {
        base + Duration::from_secs(n)
    }
    fn changed(from: Option<u64>, tier: FailoverTier) -> ConnectionEvent {
        ConnectionEvent::PathChanged {
            from: from.map(id),
            to: id(9),
            tier_at_time: tier,
        }
    }
    fn selected() -> ConnectionEvent {
        ConnectionEvent::ProfileSelected {
            profile: ProfileId::new("hy2-default"),
            because: "fastest".into(),
        }
    }
    fn degraded() -> ConnectionEvent {
        ConnectionEvent::Degraded {
            path: id(1),
            band: QualityBand::Poor,
            staying: NoMove::OnlyPath,
        }
    }
    fn recovered() -> ConnectionEvent {
        ConnectionEvent::Recovered { path: id(1) }
    }

    #[test]
    fn nothing_is_counted_when_nothing_is_connected() {
        let t = clock();
        let mut s = SessionStats::new();
        s.record(&changed(Some(1), FailoverTier::Tier2), t);
        assert_eq!(s.summary(t), None);
        assert!(!s.active());
    }

    #[test]
    fn a_new_connection_starts_from_nothing() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&changed(Some(1), FailoverTier::Tier2), secs(t, 5));
        s.end();
        s.begin(secs(t, 100));
        let summary = s.summary(secs(t, 130)).unwrap();
        assert_eq!(summary.network_changes, 0);
        assert_eq!(summary.connected_for, Duration::from_secs(30));
    }

    #[test]
    fn the_first_path_found_is_not_a_change_but_later_ones_are() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&changed(None, FailoverTier::Tier2), secs(t, 1));
        assert_eq!(s.summary(t).unwrap().network_changes, 0);
        s.record(&changed(Some(9), FailoverTier::Tier2), secs(t, 2));
        s.record(&changed(Some(9), FailoverTier::Tier1), secs(t, 3));
        let summary = s.summary(secs(t, 4)).unwrap();
        assert_eq!(summary.network_changes, 2);
        assert_eq!(
            summary.changes_that_drop_connections, 1,
            "only the Tier 2 change breaks established connections"
        );
    }

    #[test]
    fn the_first_method_chosen_is_not_a_switch_but_later_ones_are() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&selected(), t);
        assert_eq!(s.summary(t).unwrap().method_switches, 0);
        s.record(&selected(), secs(t, 60));
        assert_eq!(s.summary(secs(t, 61)).unwrap().method_switches, 1);
    }

    #[test]
    fn endpoint_migrations_are_counted() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(
            &ConnectionEvent::EndpointMigrated {
                from: EndpointId::new(),
                to: EndpointId::new(),
                because: "stopped answering".into(),
            },
            t,
        );
        assert_eq!(s.summary(t).unwrap().endpoint_switches, 1);
    }

    #[test]
    fn a_poor_period_is_counted_once_however_often_it_is_restated() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&degraded(), secs(t, 10));
        s.record(&degraded(), secs(t, 20)); // another reason, or worse: the same period
        s.record(&recovered(), secs(t, 70));
        let summary = s.summary(secs(t, 80)).unwrap();
        assert_eq!(summary.degraded_periods, 1);
        assert_eq!(summary.longest_degraded, Duration::from_secs(60));
    }

    #[test]
    fn the_longest_poor_period_is_kept_and_a_shorter_one_does_not_replace_it() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&degraded(), secs(t, 0));
        s.record(&recovered(), secs(t, 100));
        s.record(&degraded(), secs(t, 200));
        s.record(&recovered(), secs(t, 230));
        let summary = s.summary(secs(t, 300)).unwrap();
        assert_eq!(summary.degraded_periods, 2);
        assert_eq!(summary.longest_degraded, Duration::from_secs(100));
    }

    #[test]
    fn a_poor_period_still_going_on_counts_towards_the_longest() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&degraded(), secs(t, 10));
        assert_eq!(
            s.summary(secs(t, 50)).unwrap().longest_degraded,
            Duration::from_secs(40)
        );
    }

    #[test]
    fn a_recovery_without_a_poor_period_changes_nothing() {
        let t = clock();
        let mut s = SessionStats::new();
        s.begin(t);
        s.record(&recovered(), secs(t, 5));
        let summary = s.summary(secs(t, 6)).unwrap();
        assert_eq!(summary.degraded_periods, 0);
        assert_eq!(summary.longest_degraded, Duration::ZERO);
    }
}
