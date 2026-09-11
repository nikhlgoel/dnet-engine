//! T052 — endpoint host route via the physical gateway (AW-02, AW-03, research.md §R4).
//!
//! The endpoint must be reachable **outside** the tunnel, via a host route through the
//! physical gateway. The single most dangerous ordering in the system lives here:
//!
//! - the host route is installed **before** the tunnel starts, and removed **after** it
//!   stops — including after an abnormal stop (AW-02);
//! - on a carrying-path change the route is rewritten to the new gateway **before** the
//!   tunnel is told to rebind (AW-03).
//!
//! Get either order wrong and the tunnel's own packets to the endpoint re-enter the
//! tunnel — the R4 loop, a silent failure that looks like a good handshake with no
//! throughput. The orderings are expressed against the [`TunnelBringup`] seam so they
//! are asserted by call order in a unit test, not by timing; the real installer performs
//! the actual route and adapter operations.

use std::net::IpAddr;

use dnet_config::ActiveEndpointBypass;

use crate::error::NetstateError;

/// A host route: reach `destination` via `gateway` on the physical link. Derived from
/// the same [`ActiveEndpointBypass`] as the config's endpoint bypass rule, so the route
/// table and rule evaluation cannot disagree (data-model §Cross-cutting 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    destination: String,
    gateway: IpAddr,
}

impl HostRoute {
    /// Build the endpoint host route from the shared bypass source and a gateway.
    pub fn for_endpoint(bypass: &ActiveEndpointBypass, gateway: IpAddr) -> Self {
        Self {
            destination: bypass.host().to_string(),
            gateway,
        }
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }

    /// The same route via a different gateway, for a carrying-path change.
    pub fn via(&self, gateway: IpAddr) -> Self {
        Self {
            destination: self.destination.clone(),
            gateway,
        }
    }
}

/// The route/adapter/tunnel operations whose ordering prevents the R4 loop. Implemented
/// for real by the OS installer; a recording fake asserts the order in tests.
pub trait TunnelBringup {
    fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError>;
    fn remove_host_route(&self, route: &HostRoute) -> Result<(), NetstateError>;
    fn rewrite_host_route(&self, from: &HostRoute, to: &HostRoute) -> Result<(), NetstateError>;
    fn start_tunnel(&self) -> Result<(), NetstateError>;
    fn stop_tunnel(&self) -> Result<(), NetstateError>;
    fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError>;
}

/// Bring the tunnel up: install the host route **first**, then start the tunnel (AW-02).
/// If the route install fails, the tunnel is never started.
pub fn bring_up<T: TunnelBringup>(ops: &T, route: &HostRoute) -> Result<(), NetstateError> {
    ops.install_host_route(route)?;
    ops.start_tunnel()
}

/// Tear the tunnel down: stop the tunnel, then remove the host route (AW-03). The route
/// removal runs even if the stop reported an error, so an abnormal stop still leaves no
/// residual host route.
pub fn tear_down<T: TunnelBringup>(ops: &T, route: &HostRoute) -> Result<(), NetstateError> {
    let stopped = ops.stop_tunnel();
    ops.remove_host_route(route)?;
    stopped
}

/// Handle a carrying-path change: rewrite the host route to the new gateway **before**
/// telling the tunnel to rebind (AW-03). A stale gateway route during rebind loops.
pub fn on_carrying_path_change<T: TunnelBringup>(
    ops: &T,
    current: &HostRoute,
    new_gateway: IpAddr,
) -> Result<HostRoute, NetstateError> {
    let updated = current.via(new_gateway);
    ops.rewrite_host_route(current, &updated)?;
    ops.rebind_tunnel(new_gateway)?;
    Ok(updated)
}
