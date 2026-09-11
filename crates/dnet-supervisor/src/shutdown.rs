//! T046 — ordered teardown (SUP-04).
//!
//! Whenever `dnetd` stops for any reason, both cores are terminated and every
//! routing/DNS/adapter mutation is undone. Cores are killed **before** undo replay so a
//! still-running core cannot re-add a route the replay just removed.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;
use crate::runtime::CoreRuntime;

/// Tear everything down: kill both cores, then replay all undo records. Best-effort —
/// a failure to kill one core does not skip undo replay, since leaving routing state
/// mutated is the worse outcome (fail toward restoration).
pub fn shutdown_all<R: CoreRuntime>(rt: &R) -> Result<(), SupervisorError> {
    let primary = rt.kill_core(CoreBinding::PrimaryCore);
    let amnezia = rt.kill_core(CoreBinding::AmneziaWgCore);
    // Undo replay always runs, even if a kill failed.
    rt.replay_undo()?;
    primary?;
    amnezia?;
    Ok(())
}
