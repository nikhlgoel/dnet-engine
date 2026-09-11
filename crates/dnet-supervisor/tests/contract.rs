//! T042 — supervision contract tests (SUP-T1…SUP-T4).
//!
//! Ordering is asserted with a recording fake `CoreRuntime`, exactly as the contract
//! requires ("asserted by ordering, not by timing"). The same orderings are driven for
//! real by `WindowsCoreRuntime`; its OS effects are exercised by the crate's `process`
//! and `orphans` tests and by SPIKE-R4.
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §3.1.

use std::cell::RefCell;
use std::time::Duration;

use dnet_core::profile::CoreBinding;
use dnet_supervisor::child::{await_ready, ReadyError};
use dnet_supervisor::reap::start_cores;
use dnet_supervisor::restart::{RestartDecision, RestartPolicy};
use dnet_supervisor::shutdown::shutdown_all;
use dnet_supervisor::{CoreRuntime, SupervisorError};

/// Records every side effect in order, so tests can assert the sequence.
#[derive(Default)]
struct RecordingRuntime {
    actions: RefCell<Vec<String>>,
    fail_kill: bool,
}

impl RecordingRuntime {
    fn log(&self, action: impl Into<String>) {
        self.actions.borrow_mut().push(action.into());
    }
    fn actions(&self) -> Vec<String> {
        self.actions.borrow().clone()
    }
    fn position(&self, action: &str) -> usize {
        self.actions()
            .iter()
            .position(|a| a == action)
            .unwrap_or_else(|| panic!("{action} never happened: {:?}", self.actions()))
    }
}

impl CoreRuntime for RecordingRuntime {
    async fn reap_orphans(&self) -> Result<(), SupervisorError> {
        self.log("reap_orphans");
        Ok(())
    }
    async fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        self.log(format!("spawn_core:{core:?}"));
        Ok(())
    }
    async fn await_adapter(&self) -> Result<(), SupervisorError> {
        self.log("await_adapter");
        Ok(())
    }
    async fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        self.log(format!("kill_core:{core:?}"));
        if self.fail_kill {
            return Err(SupervisorError::Runtime("kill failed".into()));
        }
        Ok(())
    }
    async fn replay_undo(&self) -> Result<(), SupervisorError> {
        self.log("replay_undo");
        Ok(())
    }
}

// ---------------------------------------------------------------- SUP-T1

/// A core exiting repeatedly reaches `CoreFailedPersistently` within the attempt limit
/// and stops being restarted (does not loop forever).
#[test]
fn sup_t1_repeated_exit_reaches_failed_persistently_within_the_limit() {
    let policy = RestartPolicy::for_cores();
    let mut attempts = 0u32;
    let mut gave_up = false;
    for attempt in 1..=1000 {
        match policy.decide(attempt, 1.0) {
            RestartDecision::RetryAfter(_) => attempts += 1,
            RestartDecision::GiveUp => {
                gave_up = true;
                break;
            }
        }
    }
    assert!(gave_up, "supervision must give up, not loop forever");
    assert_eq!(attempts, policy.max_attempts());

    let err = SupervisorError::CoreFailedPersistently(CoreBinding::PrimaryCore);
    assert_eq!(
        err.to_string(),
        "core PrimaryCore failed persistently and will not be restarted"
    );
}

// ---------------------------------------------------------------- SUP-T2

/// Teardown terminates both cores and replays undo, with cores killed before the undo
/// replay so a live core cannot re-add a route the replay removed.
#[tokio::test]
async fn sup_t2_shutdown_kills_both_cores_then_replays_undo() {
    let rt = RecordingRuntime::default();
    shutdown_all(&rt).await.unwrap();
    assert_eq!(
        rt.actions(),
        [
            "kill_core:PrimaryCore",
            "kill_core:AmneziaWgCore",
            "replay_undo"
        ]
    );
}

#[tokio::test]
async fn sup_t2_undo_replay_runs_even_if_a_kill_fails() {
    let rt = RecordingRuntime {
        fail_kill: true,
        ..RecordingRuntime::default()
    };
    assert!(
        shutdown_all(&rt).await.is_err(),
        "a failed kill is still surfaced"
    );
    assert!(rt.actions().contains(&"replay_undo".to_string()));
}

// ---------------------------------------------------------------- SUP-T3

/// Orphans are reaped before anything is spawned, and the adapter exists before the
/// primary core (which binds to it) is spawned.
#[tokio::test]
async fn sup_t3_orphans_are_reaped_before_anything_is_spawned() {
    let rt = RecordingRuntime::default();
    start_cores(&rt).await.unwrap();
    assert_eq!(
        rt.actions(),
        [
            "reap_orphans",
            "spawn_core:AmneziaWgCore",
            "await_adapter",
            "spawn_core:PrimaryCore"
        ]
    );
    assert!(rt.position("reap_orphans") < rt.position("spawn_core:AmneziaWgCore"));
    assert!(rt.position("await_adapter") < rt.position("spawn_core:PrimaryCore"));
}

// ---------------------------------------------------------------- SUP-T4

/// A core that never signals ready is failed at the timeout, not awaited.
#[tokio::test(start_paused = true)]
async fn sup_t4_a_never_ready_core_is_failed_at_the_timeout() {
    let never = std::future::pending::<bool>();
    let result = await_ready(never, Duration::from_secs(10)).await;
    assert_eq!(result, Err(ReadyError::Timeout(Duration::from_secs(10))));
}
