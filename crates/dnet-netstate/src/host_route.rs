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
/// for real by `win_bringup::WindowsTunnelBringup`; a recording fake asserts the order in
/// tests.
///
/// Async because starting, stopping, and rebinding the tunnel are UAPI round-trips. The
/// trait is only ever used through generics (never `dyn`), so the auto-trait-bound
/// limitation the `async_fn_in_trait` lint warns about does not apply.
#[allow(async_fn_in_trait)]
pub trait TunnelBringup {
    async fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError>;
    async fn remove_host_route(&self, route: &HostRoute) -> Result<(), NetstateError>;
    async fn rewrite_host_route(
        &self,
        from: &HostRoute,
        to: &HostRoute,
    ) -> Result<(), NetstateError>;
    async fn start_tunnel(&self) -> Result<(), NetstateError>;
    async fn stop_tunnel(&self) -> Result<(), NetstateError>;
    async fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError>;
}

/// Bring the tunnel up: install the host route **first**, then start the tunnel (AW-02).
/// If the route install fails, the tunnel is never started.
pub async fn bring_up<T: TunnelBringup>(ops: &T, route: &HostRoute) -> Result<(), NetstateError> {
    ops.install_host_route(route).await?;
    ops.start_tunnel().await
}

/// Tear the tunnel down: stop the tunnel, then remove the host route (AW-03). The route
/// removal runs even if the stop reported an error, so an abnormal stop still leaves no
/// residual host route.
pub async fn tear_down<T: TunnelBringup>(ops: &T, route: &HostRoute) -> Result<(), NetstateError> {
    let stopped = ops.stop_tunnel().await;
    ops.remove_host_route(route).await?;
    stopped
}

/// Handle a carrying-path change: rewrite the host route to the new gateway **before**
/// telling the tunnel to rebind (AW-03). A stale gateway route during rebind loops.
pub async fn on_carrying_path_change<T: TunnelBringup>(
    ops: &T,
    current: &HostRoute,
    new_gateway: IpAddr,
) -> Result<HostRoute, NetstateError> {
    let (route, outcome) = move_to_gateway(ops, current, new_gateway).await;
    outcome.map(|()| route)
}

/// [`on_carrying_path_change`] for a caller that has to keep track of the routing table: it also
/// says which route is installed afterwards.
///
/// The two steps can fail separately. If the rewrite fails nothing changed and the route is still
/// `current`. If the rewrite succeeded and the rebind then failed, the table already holds the new
/// route, and a caller that believed the old one would later try to remove a route that is not
/// there and leave the new one behind. So the route returned is always the one installed.
pub async fn move_to_gateway<T: TunnelBringup>(
    ops: &T,
    current: &HostRoute,
    new_gateway: IpAddr,
) -> (HostRoute, Result<(), NetstateError>) {
    let updated = current.via(new_gateway);
    if let Err(error) = ops.rewrite_host_route(current, &updated).await {
        return (current.clone(), Err(error));
    }
    let outcome = ops.rebind_tunnel(new_gateway).await;
    (updated, outcome)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records the order of operations, and can fail either step.
    struct Recorder {
        log: Mutex<Vec<String>>,
        fail_rewrite: bool,
        fail_rebind: bool,
    }

    impl Recorder {
        fn new(fail_rewrite: bool, fail_rebind: bool) -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                fail_rewrite,
                fail_rebind,
            }
        }
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl TunnelBringup for Recorder {
        async fn install_host_route(&self, _: &HostRoute) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn remove_host_route(&self, _: &HostRoute) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn rewrite_host_route(
            &self,
            _: &HostRoute,
            to: &HostRoute,
        ) -> Result<(), NetstateError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("rewrite:{}", to.gateway()));
            if self.fail_rewrite {
                Err(NetstateError::Operation("denied".into()))
            } else {
                Ok(())
            }
        }
        async fn start_tunnel(&self) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn stop_tunnel(&self) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError> {
            self.log.lock().unwrap().push(format!("rebind:{gateway}"));
            if self.fail_rebind {
                Err(NetstateError::Operation("pipe closed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn route(gateway: &str) -> HostRoute {
        let address = dnet_core::endpoint::EndpointAddress::new("203.0.113.10", 51820).unwrap();
        HostRoute::for_endpoint(
            &ActiveEndpointBypass::new(&address),
            gateway.parse().unwrap(),
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn the_route_is_rewritten_before_the_tunnel_is_rebound() {
        let ops = Recorder::new(false, false);
        let (now, outcome) = move_to_gateway(&ops, &route("10.0.0.1"), ip("10.0.0.9")).await;

        assert!(outcome.is_ok());
        assert_eq!(ops.log(), ["rewrite:10.0.0.9", "rebind:10.0.0.9"]);
        assert_eq!(now.gateway(), ip("10.0.0.9"));
    }

    #[tokio::test]
    async fn a_rewrite_that_fails_changes_nothing_and_never_rebinds() {
        let ops = Recorder::new(true, false);
        let (now, outcome) = move_to_gateway(&ops, &route("10.0.0.1"), ip("10.0.0.9")).await;

        assert!(outcome.is_err());
        assert_eq!(
            ops.log(),
            ["rewrite:10.0.0.9"],
            "no rebind against a stale route"
        );
        assert_eq!(
            now.gateway(),
            ip("10.0.0.1"),
            "the table still holds the old route"
        );
    }

    /// The gap this function exists to close: the table already has the new route.
    #[tokio::test]
    async fn a_rebind_that_fails_still_reports_the_route_that_is_now_installed() {
        let ops = Recorder::new(false, true);
        let (now, outcome) = move_to_gateway(&ops, &route("10.0.0.1"), ip("10.0.0.9")).await;

        assert!(outcome.is_err());
        assert_eq!(now.gateway(), ip("10.0.0.9"), "the rewrite had succeeded");
    }

    #[tokio::test]
    async fn the_older_helper_still_returns_the_new_route_or_the_error() {
        let ok = Recorder::new(false, false);
        let updated = on_carrying_path_change(&ok, &route("10.0.0.1"), ip("10.0.0.9"))
            .await
            .unwrap();
        assert_eq!(updated.gateway(), ip("10.0.0.9"));

        let bad = Recorder::new(false, true);
        assert!(
            on_carrying_path_change(&bad, &route("10.0.0.1"), ip("10.0.0.9"))
                .await
                .is_err()
        );
    }
}
