//! Child process lifecycle for the supervised transport cores.
//!
//! Both cores (primary and AmneziaWG) are spawned as children, restarted with a
//! bounded, jittered backoff, reaped if orphaned by a prior crash, and torn down — with
//! all routing/DNS mutations undone — whenever `dnetd` stops (FR-030, contract §3).
//!
//! The dangerous parts of this are *ordering* facts: orphans must be reaped **before** a
//! new adapter is created, and both cores killed **before** undo replay. Those orderings
//! are expressed against the [`CoreRuntime`] seam so they can be asserted by a recording
//! fake, exactly as the contract requires ("asserted by ordering, not by timing"). The
//! real `CoreRuntime` (tokio child processes, the netstate undo log) is wired in `dnetd`.
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §3.

pub mod child;
pub mod error;
pub mod reap;
pub mod restart;
pub mod runtime;
pub mod shutdown;

pub use error::SupervisorError;
pub use restart::{RestartDecision, RestartPolicy};
pub use runtime::CoreRuntime;
