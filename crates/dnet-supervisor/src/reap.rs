//! T045 — orphan reaping and ordered startup (SUP-05).
//!
//! A crashed `dnetd` can leave core processes running. At service start those orphans
//! must be killed **before** anything new is spawned, or a stale AmneziaWG core would
//! still hold the adapter name and its UAPI pipe. The ordering is the contract.

use dnet_core::profile::CoreBinding;

use crate::error::SupervisorError;
use crate::runtime::CoreRuntime;

/// The ordered startup sequence for the profile that will carry traffic. `active` is the core
/// that serves it ([`dnet_core::profile::ProfileKind::core_binding`]).
///
/// 1. reap orphans (SUP-05), always, and for both cores' images;
/// 2. **only for an AmneziaWG profile:** spawn the AmneziaWG core, which creates its adapter,
///    and wait for that adapter to exist (AW-01);
/// 3. spawn the primary core. It owns the capture TUN, FakeIP and the rules for every profile,
///    and for AmneziaWG its outbound binds to the adapter from step 2.
///
/// A profile served by the primary core alone (Hysteria 2, VLESS+REALITY) starts no AmneziaWG
/// core and awaits no adapter: nothing would create one, so waiting would fail every connect.
pub async fn start_cores<R: CoreRuntime>(
    rt: &R,
    active: CoreBinding,
) -> Result<(), SupervisorError> {
    rt.reap_orphans().await?;
    if active == CoreBinding::AmneziaWgCore {
        rt.spawn_core(CoreBinding::AmneziaWgCore).await?;
        rt.await_adapter().await?;
    }
    rt.spawn_core(CoreBinding::PrimaryCore).await?;
    Ok(())
}
