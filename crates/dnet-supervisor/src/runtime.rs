// SPDX-License-Identifier: GPL-3.0-or-later
//! The side-effect seam supervision drives.
//!
//! Startup and shutdown are sequences of privileged side effects whose *order* is
//! safety-critical. Expressing them against this trait lets a recording fake assert the
//! order in a unit test (contract §3.1), while `windows_runtime::WindowsCoreRuntime`
//! performs the real process operations.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;

/// What a runtime can say about one core right now (T170). The live map reads it; nothing here changes a core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreHealth {
    /// The runtime has nothing to say: the core was never started, was stopped on purpose, or the runtime
    /// cannot tell. It is never shown as fine.
    Unknown,
    /// Started and, as of this reading, still running.
    Running,
    /// It ended without being stopped. `code` is its exit code, when the system gave one.
    Exited { code: Option<i32> },
}

/// The privileged operations supervision performs, in the order it performs them.
///
/// Async because spawning waits for readiness and killing waits for exit. Used only
/// through generics (never `dyn`), so the `async_fn_in_trait` auto-trait caveat does not
/// apply.
#[allow(async_fn_in_trait)]
pub trait CoreRuntime {
    /// Kill any cores left running by a previously-crashed `dnetd` (SUP-05). Must run
    /// before anything new is spawned — a stale AmneziaWG core would still own the
    /// adapter name and its UAPI pipe.
    async fn reap_orphans(&self) -> Result<(), SupervisorError>;

    /// Spawn a supervised core and wait for it to become ready (SUP-01, SUP-06).
    async fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError>;

    /// Wait until the AmneziaWG adapter exists. The AmneziaWG core creates the adapter
    /// itself on start (verified against the pinned core's `main_windows.go`), and the
    /// primary core's outbound binds to it, so this gates the primary core's spawn
    /// (AW-01).
    async fn await_adapter(&self) -> Result<(), SupervisorError>;

    /// Terminate a supervised core.
    async fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError>;

    /// The process id of a running core, if this runtime knows it. The default knows none, which makes a check
    /// that needs it (confirming who listens on the core's control port) refuse instead of guess.
    async fn core_pid(&self, _core: CoreBinding) -> Option<u32> {
        None
    }

    /// Whether a core is running now, read without waiting. The default says nothing (`Unknown`), so a runtime
    /// that cannot tell makes the map leave the core out instead of showing it as fine.
    async fn core_health(&self, _core: CoreBinding) -> CoreHealth {
        CoreHealth::Unknown
    }

    /// Replay every outstanding undo record, restoring routing/DNS/adapter state
    /// (SUP-04, data-model §Cross-cutting 1).
    async fn replay_undo(&self) -> Result<(), SupervisorError>;
}

#[cfg(test)]
mod default_tests {
    use super::*;

    /// A runtime that overrides nothing optional.
    struct Bare;

    impl CoreRuntime for Bare {
        async fn reap_orphans(&self) -> Result<(), SupervisorError> {
            Ok(())
        }
        async fn spawn_core(&self, _: CoreBinding) -> Result<(), SupervisorError> {
            Ok(())
        }
        async fn await_adapter(&self) -> Result<(), SupervisorError> {
            Ok(())
        }
        async fn kill_core(&self, _: CoreBinding) -> Result<(), SupervisorError> {
            Ok(())
        }
        async fn replay_undo(&self) -> Result<(), SupervisorError> {
            Ok(())
        }
    }

    /// A runtime that does not know a core's process id says so, which makes the check that needs it refuse
    /// and not guess: a made-up id would let the wrong program receive the control secret.
    #[tokio::test]
    async fn a_runtime_that_does_not_know_a_process_id_gives_none_for_every_core() {
        for core in [CoreBinding::PrimaryCore, CoreBinding::AmneziaWgCore] {
            assert_eq!(Bare.core_pid(core).await, None);
        }
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_tell_says_unknown_and_never_fine() {
        for core in [CoreBinding::PrimaryCore, CoreBinding::AmneziaWgCore] {
            assert_eq!(Bare.core_health(core).await, CoreHealth::Unknown);
        }
    }
}
