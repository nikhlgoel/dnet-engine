//! Supervision errors.

use dnet_core::profile::CoreBinding;

/// A failure in supervising the transport cores.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupervisorError {
    /// A core exited repeatedly and the restart attempt limit was exceeded. Supervision
    /// stops rather than looping forever (SUP-03); this maps to
    /// `FailureCause::CoreFailedPersistently`.
    #[error("core {0:?} failed persistently and will not be restarted")]
    CoreFailedPersistently(CoreBinding),

    /// A runtime side effect (spawn, kill, adapter, undo replay) failed.
    #[error("supervisor runtime operation failed: {0}")]
    Runtime(String),
}
