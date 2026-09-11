//! The side-effect seam supervision drives.
//!
//! Startup and shutdown are sequences of privileged side effects whose *order* is
//! safety-critical. Expressing them against this trait lets a recording fake assert the
//! order in a unit test (contract §3.1), while the real implementation in `dnetd`
//! performs the actual process and netstate operations.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;

/// The privileged operations supervision performs, in the order it performs them.
pub trait CoreRuntime {
    /// Kill any cores left running by a previously-crashed `dnetd` (SUP-05). Must run
    /// before any new adapter is created.
    fn reap_orphans(&self) -> Result<(), SupervisorError>;

    /// Create the AmneziaWG adapter. The primary core's outbound is later bound to it,
    /// so it must exist first (AW-01).
    fn create_adapter(&self) -> Result<(), SupervisorError>;

    /// Spawn a supervised core as a child process.
    fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError>;

    /// Terminate a supervised core.
    fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError>;

    /// Replay every outstanding undo record, restoring routing/DNS/adapter state
    /// (SUP-04, data-model §Cross-cutting 1).
    fn replay_undo(&self) -> Result<(), SupervisorError>;
}
