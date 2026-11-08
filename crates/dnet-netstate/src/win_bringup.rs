//! The real `TunnelBringup`: routes via the IP Helper API, tunnel control via UAPI.
//!
//! - **host route** — `WindowsRouteInstaller` (`CreateIpForwardEntry2`, owned rows only,
//!   each recorded in the undo registry before it is created)
//! - **start tunnel** — assign the tunnel address and adapter route, then one UAPI
//!   `set` carrying private key + obfuscation + peer together (AW-04). Handshakes begin
//!   the moment the peer exists, which is why `bring_up` installs the host route first.
//! - **stop tunnel** — UAPI `replace_peers=true`: no peer, no traffic to the endpoint.
//! - **rebind** — UAPI `update_only` endpoint re-set, after the route rewrite (AW-03).
//!
//! Errors from the config layer are secret-free by construction, so they are safe to
//! carry into `NetstateError`.

#![cfg(windows)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dnet_config::amneziawg::{
    build_rebind, build_remove_peers, build_set_device, ObfuscationParams, PeerConfig, PrivateKey,
};
use dnet_config::uapi_pipe;

use crate::adapter;
use crate::error::NetstateError;
use crate::host_route::{HostRoute, TunnelBringup};
use crate::undo::UndoRegistry;
use crate::win_route::WindowsRouteInstaller;

/// How long a single UAPI operation may take before it is treated as failed.
pub const UAPI_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything needed to bring Profile A's tunnel up on a real adapter.
pub struct TunnelSpec {
    /// The AmneziaWG adapter alias (also the UAPI pipe leaf).
    pub adapter: String,
    /// The tunnel-side address of this client and its prefix length.
    pub address: IpAddr,
    pub prefix_len: u8,
    pub private_key: PrivateKey,
    pub obfuscation: ObfuscationParams,
    /// The endpoint peer. `endpoint` must be an `IP:port` literal.
    pub peer: PeerConfig,
}

/// The production `TunnelBringup` for Profile A.
pub struct WindowsTunnelBringup {
    spec: TunnelSpec,
    routes: WindowsRouteInstaller,
}

impl WindowsTunnelBringup {
    pub fn new(spec: TunnelSpec, undo: Arc<UndoRegistry>) -> Self {
        Self {
            spec,
            routes: WindowsRouteInstaller::new(undo),
        }
    }

    pub fn routes(&self) -> &WindowsRouteInstaller {
        &self.routes
    }

    fn pipe(&self) -> String {
        uapi_pipe::pipe_path(&self.spec.adapter)
    }
}

fn op<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> NetstateError + '_ {
    move |e| NetstateError::Operation(format!("{what}: {e}"))
}

impl TunnelBringup for WindowsTunnelBringup {
    async fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError> {
        let addrs = self.routes.install(route)?;
        tracing::info!(?addrs, gateway = %route.gateway(), "endpoint host route installed");
        Ok(())
    }

    async fn remove_host_route(&self, route: &HostRoute) -> Result<(), NetstateError> {
        self.routes.remove(route)?;
        tracing::info!("endpoint host route removed");
        Ok(())
    }

    async fn rewrite_host_route(
        &self,
        from: &HostRoute,
        to: &HostRoute,
    ) -> Result<(), NetstateError> {
        self.routes.rewrite(from, to)?;
        tracing::info!(from = %from.gateway(), to = %to.gateway(), "endpoint host route rewritten");
        Ok(())
    }

    async fn start_tunnel(&self) -> Result<(), NetstateError> {
        let spec = &self.spec;
        adapter::assign_address(&spec.adapter, spec.address, spec.prefix_len)?;
        adapter::add_adapter_default_route(&spec.adapter, spec.address.is_ipv4())?;

        let request = build_set_device(&spec.private_key, &spec.obfuscation, &spec.peer)
            .map_err(op("building the peer transaction"))?;
        uapi_pipe::set(&self.pipe(), &request, UAPI_TIMEOUT)
            .await
            .map_err(op("configuring the peer"))?;
        tracing::info!(adapter = %spec.adapter, "tunnel peer configured");
        Ok(())
    }

    async fn stop_tunnel(&self) -> Result<(), NetstateError> {
        uapi_pipe::set(&self.pipe(), &build_remove_peers(), UAPI_TIMEOUT)
            .await
            .map_err(op("removing the peer"))?;
        tracing::info!("tunnel peer removed");
        Ok(())
    }

    async fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError> {
        let request = build_rebind(&self.spec.peer.public_key, &self.spec.peer.endpoint)
            .map_err(op("building the rebind"))?;
        uapi_pipe::set(&self.pipe(), &request, UAPI_TIMEOUT)
            .await
            .map_err(op("rebinding the peer"))?;
        tracing::info!(%gateway, "tunnel rebound after path change");
        Ok(())
    }
}

/// The production bring-up against an adapter that does not exist. Nothing real is configured: the adapter
/// and its control pipe are absent, so every step that needs them must fail, say which step it was, and
/// leave the routing table alone. That is what a service sees when the adapter never appeared.
#[cfg(test)]
mod absent_adapter_tests {
    use std::time::Instant;

    use dnet_config::amneziawg::{ObfuscationParams, PeerConfig, PrivateKey};

    use super::*;
    use crate::undo::MemoryStore;
    use dnet_config::ActiveEndpointBypass;
    use dnet_core::endpoint::EndpointAddress;

    const ADAPTER: &str = "dnet-absent-adapter-5b1c";

    fn bringup(address: IpAddr) -> WindowsTunnelBringup {
        let undo = Arc::new(UndoRegistry::open(Box::new(MemoryStore::new())).unwrap());
        WindowsTunnelBringup::new(
            TunnelSpec {
                adapter: ADAPTER.to_owned(),
                address,
                prefix_len: 32,
                private_key: PrivateKey::new("00".repeat(32)),
                obfuscation: ObfuscationParams {
                    jc: 4,
                    jmin: 40,
                    jmax: 70,
                    s1: 15,
                    s2: 23,
                    h1: 1_000_000_001,
                    h2: 1_000_000_002,
                    h3: 1_000_000_003,
                    h4: 1_000_000_004,
                },
                peer: PeerConfig {
                    public_key: "11".repeat(32),
                    endpoint: "203.0.113.10:51820".to_owned(),
                    allowed_ips: vec!["0.0.0.0/0".to_owned()],
                    persistent_keepalive: Some(25),
                },
            },
            undo,
        )
    }

    fn v4() -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2))
    }

    fn route(gateway: &str) -> HostRoute {
        let address = EndpointAddress::new("203.0.113.10", 51820).unwrap();
        HostRoute::for_endpoint(
            &ActiveEndpointBypass::new(&address),
            gateway.parse().unwrap(),
        )
    }

    #[test]
    fn the_control_pipe_is_the_one_named_for_the_adapter() {
        let pipe = bringup(v4()).pipe();
        assert_eq!(pipe, uapi_pipe::pipe_path(ADAPTER));
        assert!(pipe.contains(ADAPTER), "{pipe}");
        assert!(!pipe.is_empty());
        assert_ne!(pipe, "xyzzy");
    }

    #[tokio::test]
    async fn starting_on_an_adapter_that_is_not_there_fails_before_any_peer_is_configured() {
        for address in [v4(), IpAddr::V6("fd00::2".parse().unwrap())] {
            let error = bringup(address)
                .start_tunnel()
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("not found"), "{error}");
            assert!(error.contains(ADAPTER), "{error}");
        }
    }

    #[tokio::test]
    async fn stopping_when_the_control_pipe_is_gone_fails_saying_what_could_not_be_done() {
        let started = Instant::now();
        let error = bringup(v4()).stop_tunnel().await.unwrap_err().to_string();
        assert!(error.contains("removing the peer"), "{error}");
        assert!(
            started.elapsed() < UAPI_TIMEOUT + Duration::from_secs(3),
            "it gave up within its own limit, not after it"
        );
    }

    #[tokio::test]
    async fn rebinding_when_the_control_pipe_is_gone_fails_saying_what_could_not_be_done() {
        let error = bringup(v4())
            .rebind_tunnel("192.168.1.1".parse().unwrap())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("rebinding the peer"), "{error}");
    }

    #[tokio::test]
    async fn removing_a_route_that_was_never_installed_is_success() {
        bringup(v4())
            .remove_host_route(&route("192.168.1.1"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rewriting_a_route_to_itself_is_success_and_installs_nothing() {
        let ops = bringup(v4());
        let r = route("192.168.1.1");
        ops.rewrite_host_route(&r, &r.clone()).await.unwrap();
        assert!(!ops.routes().owns(&r));
    }

    #[tokio::test]
    async fn a_fresh_bring_up_owns_no_route() {
        let ops = bringup(v4());
        assert!(!ops.routes().owns(&route("192.168.1.1")));
    }

    #[test]
    fn the_error_helper_says_what_was_being_done_and_why_it_failed() {
        let error = op("configuring the peer")("the pipe closed").to_string();
        assert!(error.contains("configuring the peer"), "{error}");
        assert!(error.contains("the pipe closed"), "{error}");
    }
}
