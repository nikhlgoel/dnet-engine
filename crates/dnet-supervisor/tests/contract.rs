//! T042 — supervision contract tests (SUP-T1…SUP-T4).
//!
//! Ordering is asserted with a recording fake `CoreRuntime`, exactly as the contract
//! requires ("asserted by ordering, not by timing").
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
}

impl RecordingRuntime {
    fn log(&self, action: impl Into<String>) {
        self.actions.borrow_mut().push(action.into());
    }
    fn actions(&self) -> Vec<String> {
        self.actions.borrow().clone()
    }
}

impl CoreRuntime for RecordingRuntime {
    fn reap_orphans(&self) -> Result<(), SupervisorError> {
        self.log("reap_orphans");
        Ok(())
    }
    fn create_adapter(&self) -> Result<(), SupervisorError> {
        self.log("create_adapter");
        Ok(())
    }
    fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        self.log(format!("spawn_core:{core:?}"));
        Ok(())
    }
    fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        self.log(format!("kill_core:{core:?}"));
        Ok(())
    }
    fn replay_undo(&self) -> Result<(), SupervisorError> {
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
    // Drive the restart loop for a core that always exits immediately.
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

    // Giving up maps to the distinguishable persistent-failure error.
    let err = SupervisorError::CoreFailedPersistently(CoreBinding::PrimaryCore);
    assert_eq!(
        err.to_string(),
        "core PrimaryCore failed persistently and will not be restarted"
    );
}

// ---------------------------------------------------------------- SUP-T2

/// Teardown terminates both cores and replays undo, with cores killed before the undo
/// replay so a live core cannot re-add a route the replay removed. Verifies the SC-016
/// teardown guarantee at the unit level (full crash-restart recovery is T038).
#[test]
fn sup_t2_shutdown_kills_both_cores_then_replays_undo() {
    let rt = RecordingRuntime::default();
    shutdown_all(&rt).unwrap();
    let actions = rt.actions();

    assert!(actions.contains(&"kill_core:PrimaryCore".to_string()));
    assert!(actions.contains(&"kill_core:AmneziaWgCore".to_string()));

    let last_kill = actions
        .iter()
        .rposition(|a| a.starts_with("kill_core:"))
        .unwrap();
    let replay = actions.iter().position(|a| a == "replay_undo").unwrap();
    assert!(
        last_kill < replay,
        "both cores must be killed before undo replay: {actions:?}"
    );
}

#[test]
fn sup_t2_undo_replay_runs_even_if_a_kill_fails() {
    struct KillFailsRuntime {
        inner: RecordingRuntime,
    }
    impl CoreRuntime for KillFailsRuntime {
        fn reap_orphans(&self) -> Result<(), SupervisorError> {
            self.inner.reap_orphans()
        }
        fn create_adapter(&self) -> Result<(), SupervisorError> {
            self.inner.create_adapter()
        }
        fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
            self.inner.spawn_core(core)
        }
        fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
            self.inner.log(format!("kill_core:{core:?}"));
            Err(SupervisorError::Runtime("kill failed".into()))
        }
        fn replay_undo(&self) -> Result<(), SupervisorError> {
            self.inner.replay_undo()
        }
    }
    let rt = KillFailsRuntime {
        inner: RecordingRuntime::default(),
    };
    let result = shutdown_all(&rt);
    assert!(result.is_err(), "a failed kill is still surfaced");
    // But restoration ran regardless.
    assert!(rt.inner.actions().contains(&"replay_undo".to_string()));
}

// ---------------------------------------------------------------- SUP-T3

/// Orphaned cores from a simulated prior crash are reaped at start, before any new
/// adapter is created.
#[test]
fn sup_t3_orphans_are_reaped_before_the_adapter_is_created() {
    let rt = RecordingRuntime::default();
    start_cores(&rt).unwrap();
    let actions = rt.actions();

    let reap = actions.iter().position(|a| a == "reap_orphans").unwrap();
    let adapter = actions.iter().position(|a| a == "create_adapter").unwrap();
    assert!(
        reap < adapter,
        "orphans must be reaped before the adapter is created: {actions:?}"
    );
    // The AmneziaWG adapter exists before the primary core binds to it (AW-01).
    let adapter_pos = adapter;
    let primary = actions
        .iter()
        .position(|a| a == "spawn_core:PrimaryCore")
        .unwrap();
    assert!(adapter_pos < primary);
}

// ---------------------------------------------------------------- SUP-T4

/// A core that never signals ready is failed at the timeout, not awaited. (Exercised in
/// the crate's own `child` unit tests; re-asserted here at the contract boundary.)
#[tokio::test(start_paused = true)]
async fn sup_t4_a_never_ready_core_is_failed_at_the_timeout() {
    let never = std::future::pending::<bool>();
    let result = await_ready(never, Duration::from_secs(10)).await;
    assert_eq!(result, Err(ReadyError::Timeout(Duration::from_secs(10))));
}
