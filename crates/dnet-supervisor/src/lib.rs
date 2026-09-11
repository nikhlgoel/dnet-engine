//! Child process lifecycle for the supervised transport cores.
//!
//! Both cores (primary and AmneziaWG) are spawned as children, restarted with a
//! bounded, jittered backoff, reaped if orphaned by a prior crash, and torn down — with
//! all routing/DNS mutations undone — whenever `dnetd` stops (FR-030, contract §3).
//!
//! The dangerous parts of this are *ordering* facts: orphans must be reaped **before**
//! anything is spawned, the adapter must exist **before** the primary core binds to it,
//! and both cores must be killed **before** undo replay. Those orderings are expressed
//! against the [`CoreRuntime`] seam so a recording fake asserts them, exactly as the
//! contract requires; [`windows_runtime::WindowsCoreRuntime`] performs them for real.
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §3.

pub mod child;
pub mod error;
pub mod orphans;
pub mod process;
pub mod reap;
pub mod restart;
pub mod runtime;
pub mod shutdown;
pub mod windows_runtime;

pub use error::SupervisorError;
pub use restart::{RestartDecision, RestartPolicy};
pub use runtime::CoreRuntime;
