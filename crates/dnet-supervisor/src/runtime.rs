//! The side-effect seam supervision drives.
//!
//! Startup and shutdown are sequences of privileged side effects whose *order* is
//! safety-critical. Expressing them against this trait lets a recording fake assert the
//! order in a unit test (contract §3.1), while `windows_runtime::WindowsCoreRuntime`
//! performs the real process operations.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;

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

    /// Replay every outstanding undo record, restoring routing/DNS/adapter state
    /// (SUP-04, data-model §Cross-cutting 1).
    async fn replay_undo(&self) -> Result<(), SupervisorError>;
}
