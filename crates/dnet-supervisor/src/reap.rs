//! T045 — orphan reaping and ordered startup (SUP-05).
//!
//! A crashed `dnetd` can leave core processes running and adapters half-created. At
//! service start those orphans must be killed **before** a new adapter is created, or a
//! stale core could hold the adapter or the UAPI pipe. The ordering is the contract.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;
use crate::runtime::CoreRuntime;

/// The ordered startup sequence: reap orphans, then create the adapter, then spawn the
/// cores (AmneziaWG first so its adapter exists before the primary core binds to it).
pub fn start_cores<R: CoreRuntime>(rt: &R) -> Result<(), SupervisorError> {
    // SUP-05: orphans die before anything new is created.
    rt.reap_orphans()?;
    rt.create_adapter()?;
    rt.spawn_core(CoreBinding::AmneziaWgCore)?;
    rt.spawn_core(CoreBinding::PrimaryCore)?;
    Ok(())
}
