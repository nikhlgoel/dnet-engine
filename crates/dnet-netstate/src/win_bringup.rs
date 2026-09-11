//! The real `TunnelBringup`: routes via the IP Helper API, tunnel control via UAPI.
//!
//! - **host route** — `WindowsRouteInstaller` (`CreateIpForwardEntry2`, owned rows only)
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
use std::time::Duration;

use dnet_config::amneziawg::{
    build_rebind, build_remove_peers, build_set_device, ObfuscationParams, PeerConfig, PrivateKey,
};
use dnet_config::uapi_pipe;

use crate::adapter;
use crate::error::NetstateError;
use crate::host_route::{HostRoute, TunnelBringup};
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
    pub fn new(spec: TunnelSpec) -> Self {
        Self {
            spec,
            routes: WindowsRouteInstaller::new(),
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
