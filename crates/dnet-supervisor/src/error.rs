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

    /// A core could not be started at all (missing binary, access denied, ...).
    #[error("core {core:?} could not be spawned: {detail}")]
    Spawn { core: CoreBinding, detail: String },

    /// A core did not become ready within its timeout, or exited first (SUP-06).
    #[error("core {core:?} did not become ready: {detail}")]
    NotReady { core: CoreBinding, detail: String },

    /// A runtime side effect (kill, adapter wait, reaping, undo replay) failed.
    #[error("supervisor runtime operation failed: {0}")]
    Runtime(String),
}
