//! T144 — what the service knows about the networks and the session, held for the control pipe to
//! answer `GetPaths` and `GetStats` with.
//!
//! Two writers and one reader:
//!
//! - The network-watch loop (one per connection attempt) publishes the latest [`PathsSnapshot`] and
//!   clears it when it ends.
//! - The orchestrator counts the session's events.
//! - The control pipe reads both.
//!
//! **A stale attempt never touches a newer one's data.** Every write carries the number of the
//! attempt that made it, and the store keeps the highest it has seen: a loop that is slow to stop
//! cannot overwrite what its successor published, and cannot clear it on the way out.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use dnet_core::session::ConnectionEvent;
use dnet_core::telemetry::{PathsSnapshot, SessionStats, StatsSummary};

#[derive(Default)]
struct Inner {
    /// The newest attempt that has written paths.
    attempt: u64,
    paths: Option<PathsSnapshot>,
    stats: SessionStats,
}

/// Shared between the watch loop, the orchestrator and the control pipe.
#[derive(Clone, Default)]
pub struct Telemetry {
    inner: Arc<Mutex<Inner>>,
}

impl Telemetry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The latest networks, from attempt `attempt`. Ignored if a newer attempt has written.
    pub fn publish_paths(&self, attempt: u64, snapshot: PathsSnapshot) {
        let mut inner = self.lock();
        if attempt < inner.attempt {
            return;
        }
        inner.attempt = attempt;
        inner.paths = Some(snapshot);
    }

    /// The loop of `attempt` has ended: its networks are no longer being watched. Ignored if a newer
    /// attempt has written since.
    pub fn clear_paths(&self, attempt: u64) {
        let mut inner = self.lock();
        if attempt >= inner.attempt {
            inner.attempt = attempt;
            inner.paths = None;
        }
    }

    /// The networks being watched, or `None` when nothing is.
    pub fn paths(&self) -> Option<PathsSnapshot> {
        self.lock().paths.clone()
    }

    /// A connection came up.
    pub fn begin_session(&self, now: Instant) {
        self.lock().stats.begin(now);
    }

    /// The connection ended.
    pub fn end_session(&self) {
        self.lock().stats.end();
    }

    /// Count one recorded event.
    pub fn record(&self, event: &ConnectionEvent, now: Instant) {
        self.lock().stats.record(event, now);
    }

    /// The session's counters, or `None` when nothing is connected.
    pub fn stats(&self, now: Instant) -> Option<StatsSummary> {
        self.lock().stats.summary(now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dnet_core::ids::InterfaceId;
    use dnet_core::session::ConnectionEvent;
    use dnet_core::telemetry::PathView;
    use dnet_core::tier::FailoverTier;

    use super::*;

    fn snapshot(id: u64) -> PathsSnapshot {
        PathsSnapshot {
            paths: vec![PathView {
                id: InterfaceId::new(id),
                kind: dnet_core::path::PathKind::Wifi,
                name: None,
                role: dnet_core::path::PathRole::Carrying,
                measured: false,
                band: None,
                rtt: None,
                jitter: None,
                loss: None,
                trace_ms: Vec::new(),
                typical_ms: None,
            }],
            degradation: None,
        }
    }

    fn carrying(t: &Telemetry) -> Option<u64> {
        t.paths().map(|s| s.paths[0].id.luid())
    }

    #[test]
    fn nothing_is_known_until_something_publishes() {
        let t = Telemetry::new();
        assert_eq!(t.paths(), None);
        assert_eq!(t.stats(Instant::now()), None);
    }

    #[test]
    fn what_is_published_is_what_is_read_and_clearing_removes_it() {
        let t = Telemetry::new();
        t.publish_paths(1, snapshot(7));
        assert_eq!(carrying(&t), Some(7));
        t.publish_paths(1, snapshot(8));
        assert_eq!(carrying(&t), Some(8), "the same attempt may update");
        t.clear_paths(1);
        assert_eq!(t.paths(), None);
    }

    #[test]
    fn an_older_attempt_cannot_overwrite_a_newer_one() {
        let t = Telemetry::new();
        t.publish_paths(2, snapshot(20));
        t.publish_paths(1, snapshot(10));
        assert_eq!(carrying(&t), Some(20));
    }

    #[test]
    fn an_older_attempt_cannot_clear_what_a_newer_one_published() {
        let t = Telemetry::new();
        t.publish_paths(1, snapshot(10));
        t.publish_paths(2, snapshot(20));
        t.clear_paths(1); // the old loop, slow to stop, finishing now
        assert_eq!(carrying(&t), Some(20));
    }

    #[test]
    fn a_newer_attempt_clearing_is_honoured_and_a_late_older_publish_is_still_ignored() {
        let t = Telemetry::new();
        t.publish_paths(1, snapshot(10));
        t.clear_paths(2);
        assert_eq!(t.paths(), None);
        t.publish_paths(1, snapshot(10));
        assert_eq!(t.paths(), None, "attempt 1 is over");
    }

    #[test]
    fn the_session_is_counted_from_its_beginning_to_its_end() {
        let t = Telemetry::new();
        let start = Instant::now();
        t.begin_session(start);
        t.record(
            &ConnectionEvent::PathChanged {
                from: Some(InterfaceId::new(1)),
                to: InterfaceId::new(2),
                tier_at_time: FailoverTier::Tier2,
            },
            start + Duration::from_secs(5),
        );
        let s = t.stats(start + Duration::from_secs(60)).unwrap();
        assert_eq!(s.network_changes, 1);
        assert_eq!(s.connected_for, Duration::from_secs(60));
        t.end_session();
        assert_eq!(t.stats(start + Duration::from_secs(61)), None);
    }

    #[test]
    fn a_poisoned_lock_does_not_take_the_control_pipe_with_it() {
        let t = Telemetry::new();
        let poisoner = t.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.inner.lock().unwrap();
            panic!("a writer died holding the lock");
        })
        .join();
        t.publish_paths(1, snapshot(7));
        assert_eq!(carrying(&t), Some(7));
    }
}
