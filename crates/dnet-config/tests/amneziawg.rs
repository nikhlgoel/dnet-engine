//! T041 — AmneziaWG configuration contract tests (AWG-01…AWG-06).
//!
//! AWG-01 (no gateway -> NoUsablePath) is the primary loop prevention and lives in
//! `dnet-core`. AWG-02..04 (host-route ordering) are asserted by call order against the
//! `dnet-netstate` bring-up seam. AWG-05/06 (single-transaction obfuscation, no key
//! leak) are asserted on the generated UAPI request.
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md` §2.2.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

use dnet_config::amneziawg::{build_set_device, ObfuscationParams, PeerConfig, PrivateKey};
use dnet_config::ActiveEndpointBypass;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::InterfaceId;
use dnet_core::path::{NetworkPath, PathKind, PathQuality, PathRole};
use dnet_core::profile_start::gateway_for_profile_a;
use dnet_core::session::FailureCause;
use dnet_netstate::host_route::{
    bring_up, on_carrying_path_change, tear_down, HostRoute, TunnelBringup,
};
use dnet_netstate::NetstateError;

// ---------------------------------------------------------------- AWG-01

fn path(gateway: Option<IpAddr>) -> NetworkPath {
    NetworkPath {
        interface_id: InterfaceId::new(1),
        kind: PathKind::Wifi,
        gateway,
        quality: PathQuality::unmeasured(),
        role: PathRole::Carrying,
        preference: 0,
    }
}

#[tokio::test]
async fn awg_01_no_gateway_fails_with_no_usable_path_and_starts_no_tunnel() {
    // With no gateway, the start guard refuses before any bring-up call is made.
    assert_eq!(
        gateway_for_profile_a(&path(None)),
        Err(FailureCause::NoUsablePath)
    );

    // And a caller that (correctly) checks the guard first never reaches bring_up.
    let rt = Recording::default();
    if let Ok(gw) = gateway_for_profile_a(&path(None)) {
        bring_up(&rt, &route_via(gw)).await.unwrap();
    }
    assert!(
        rt.actions().is_empty(),
        "no tunnel or route operation may run without a gateway"
    );
}

// ---------------------------------------------------------------- AWG-02..04

#[derive(Default)]
struct Recording {
    actions: RefCell<Vec<String>>,
    fail_stop: bool,
}

impl Recording {
    fn log(&self, s: impl Into<String>) {
        self.actions.borrow_mut().push(s.into());
    }
    fn actions(&self) -> Vec<String> {
        self.actions.borrow().clone()
    }
}

impl TunnelBringup for Recording {
    async fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError> {
        self.log(format!("install_route:{}", route.gateway()));
        Ok(())
    }
    async fn remove_host_route(&self, _route: &HostRoute) -> Result<(), NetstateError> {
        self.log("remove_route");
        Ok(())
    }
    async fn rewrite_host_route(
        &self,
        _from: &HostRoute,
        to: &HostRoute,
    ) -> Result<(), NetstateError> {
        self.log(format!("rewrite_route:{}", to.gateway()));
        Ok(())
    }
    async fn start_tunnel(&self) -> Result<(), NetstateError> {
        self.log("start_tunnel");
        Ok(())
    }
    async fn stop_tunnel(&self) -> Result<(), NetstateError> {
        self.log("stop_tunnel");
        if self.fail_stop {
            return Err(NetstateError::Operation("abnormal stop".into()));
        }
        Ok(())
    }
    async fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError> {
        self.log(format!("rebind_tunnel:{gateway}"));
        Ok(())
    }
}

fn route_via(gateway: IpAddr) -> HostRoute {
    let bypass = ActiveEndpointBypass::new(&EndpointAddress::new("203.0.113.9", 51820).unwrap());
    HostRoute::for_endpoint(&bypass, gateway)
}

fn route() -> HostRoute {
    route_via(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
}

#[tokio::test]
async fn awg_02_host_route_is_installed_before_the_tunnel_starts() {
    let rt = Recording::default();
    bring_up(&rt, &route()).await.unwrap();
    assert_eq!(rt.actions(), ["install_route:192.168.1.1", "start_tunnel"]);
}

#[tokio::test]
async fn awg_03_host_route_is_removed_after_the_tunnel_stops() {
    let rt = Recording::default();
    tear_down(&rt, &route()).await.unwrap();
    assert_eq!(rt.actions(), ["stop_tunnel", "remove_route"]);
}

#[tokio::test]
async fn awg_03_route_is_removed_even_after_an_abnormal_stop() {
    let rt = Recording {
        fail_stop: true,
        ..Recording::default()
    };
    assert!(
        tear_down(&rt, &route()).await.is_err(),
        "the stop error surfaces"
    );
    assert_eq!(
        rt.actions(),
        ["stop_tunnel", "remove_route"],
        "an abnormal stop must still remove the host route"
    );
}

#[tokio::test]
async fn awg_04_path_change_rewrites_route_before_rebinding() {
    let rt = Recording::default();
    let new_gw = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let updated = on_carrying_path_change(&rt, &route(), new_gw)
        .await
        .unwrap();
    assert_eq!(
        rt.actions(),
        ["rewrite_route:10.0.0.1", "rebind_tunnel:10.0.0.1"]
    );
    assert_eq!(updated.gateway(), new_gw);
}

// ---------------------------------------------------------------- AWG-05 / AWG-06

fn obf() -> ObfuscationParams {
    ObfuscationParams {
        jc: 4,
        jmin: 40,
        jmax: 70,
        s1: 15,
        s2: 20,
        h1: 1,
        h2: 2,
        h3: 3,
        h4: 4,
    }
}

fn peer() -> PeerConfig {
    PeerConfig {
        public_key: "PEERPUB".into(),
        endpoint: "203.0.113.9:51820".into(),
        allowed_ips: vec!["0.0.0.0/0".into()],
        persistent_keepalive: Some(25),
    }
}

#[test]
fn awg_05_peer_and_obfuscation_are_one_transaction() {
    let req = build_set_device(&PrivateKey::new("SECRET"), &obf(), &peer()).unwrap();
    assert!(req.has_key("public_key"));
    for key in ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"] {
        assert!(
            req.has_key(key),
            "obfuscation param {key} missing from the peer transaction"
        );
    }
}

#[test]
fn awg_06_no_private_key_in_any_loggable_rendering() {
    let secret = "PRIVATEKEYMATERIAL";
    let req = build_set_device(&PrivateKey::new(secret), &obf(), &peer()).unwrap();

    // The redacted rendering and the Debug form (what would reach a log) never carry it.
    assert!(!req.redacted().contains(secret));
    assert!(!format!("{req:?}").contains(secret));
    // Only the framed operation sent to the pipe carries it.
    assert!(req.to_set_operation().contains(secret));
}
