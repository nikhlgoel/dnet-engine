//! T045 — orphan reaping and ordered startup (SUP-05).
//!
//! A crashed `dnetd` can leave core processes running. At service start those orphans
//! must be killed **before** anything new is spawned, or a stale AmneziaWG core would
//! still hold the adapter name and its UAPI pipe. The ordering is the contract.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;
use crate::runtime::CoreRuntime;

/// The ordered startup sequence:
///
/// 1. reap orphans (SUP-05);
/// 2. spawn the AmneziaWG core, which creates its adapter;
/// 3. wait for that adapter to exist (AW-01);
/// 4. spawn the primary core, whose Profile A outbound binds to the adapter.
pub async fn start_cores<R: CoreRuntime>(rt: &R) -> Result<(), SupervisorError> {
    rt.reap_orphans().await?;
    rt.spawn_core(CoreBinding::AmneziaWgCore).await?;
    rt.await_adapter().await?;
    rt.spawn_core(CoreBinding::PrimaryCore).await?;
    Ok(())
}
