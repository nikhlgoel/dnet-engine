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

#[test]
fn awg_01_no_gateway_fails_with_no_usable_path_and_starts_no_tunnel() {
    // With no gateway, the start guard refuses before any bring-up call is made.
    let result = gateway_for_profile_a(&path(None));
    assert_eq!(result, Err(FailureCause::NoUsablePath));

    // And a caller that (correctly) checks the guard first never reaches bring_up.
    let rt = Recording::default();
    if let Ok(gw) = gateway_for_profile_a(&path(None)) {
        let bypass = ActiveEndpointBypass::new(&EndpointAddress::new("edge.example", 443).unwrap());
        let route = HostRoute::for_endpoint(&bypass, gw);
        bring_up(&rt, &route).unwrap();
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
    fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError> {
        self.log(format!("install_route:{}", route.gateway()));
        Ok(())
    }
    fn remove_host_route(&self, _route: &HostRoute) -> Result<(), NetstateError> {
        self.log("remove_route");
        Ok(())
    }
    fn rewrite_host_route(&self, _from: &HostRoute, to: &HostRoute) -> Result<(), NetstateError> {
        self.log(format!("rewrite_route:{}", to.gateway()));
        Ok(())
    }
    fn start_tunnel(&self) -> Result<(), NetstateError> {
        self.log("start_tunnel");
        Ok(())
    }
    fn stop_tunnel(&self) -> Result<(), NetstateError> {
        self.log("stop_tunnel");
        Ok(())
    }
    fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError> {
        self.log(format!("rebind_tunnel:{gateway}"));
        Ok(())
    }
}

fn route() -> HostRoute {
    let bypass = ActiveEndpointBypass::new(&EndpointAddress::new("edge.example", 443).unwrap());
    HostRoute::for_endpoint(&bypass, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
}

#[test]
fn awg_02_host_route_is_installed_before_the_tunnel_starts() {
    let rt = Recording::default();
    bring_up(&rt, &route()).unwrap();
    assert_eq!(
        rt.actions(),
        vec![
            "install_route:192.168.1.1".to_string(),
            "start_tunnel".to_string()
        ]
    );
}

#[test]
fn awg_03_host_route_is_removed_after_the_tunnel_stops() {
    let rt = Recording::default();
    tear_down(&rt, &route()).unwrap();
    let actions = rt.actions();
    let stop = actions.iter().position(|a| a == "stop_tunnel").unwrap();
    let remove = actions.iter().position(|a| a == "remove_route").unwrap();
    assert!(
        stop < remove,
        "route removed only after tunnel stop: {actions:?}"
    );
}

#[test]
fn awg_03_route_is_removed_even_after_an_abnormal_stop() {
    struct StopFails(Recording);
    impl TunnelBringup for StopFails {
        fn install_host_route(&self, r: &HostRoute) -> Result<(), NetstateError> {
            self.0.install_host_route(r)
        }
        fn remove_host_route(&self, r: &HostRoute) -> Result<(), NetstateError> {
            self.0.remove_host_route(r)
        }
        fn rewrite_host_route(&self, a: &HostRoute, b: &HostRoute) -> Result<(), NetstateError> {
            self.0.rewrite_host_route(a, b)
        }
        fn start_tunnel(&self) -> Result<(), NetstateError> {
            self.0.start_tunnel()
        }
        fn stop_tunnel(&self) -> Result<(), NetstateError> {
            self.0.log("stop_tunnel");
            Err(NetstateError::Operation("abnormal stop".into()))
        }
        fn rebind_tunnel(&self, gw: IpAddr) -> Result<(), NetstateError> {
            self.0.rebind_tunnel(gw)
        }
    }
    let rt = StopFails(Recording::default());
    let _ = tear_down(&rt, &route());
    assert!(
        rt.0.actions().contains(&"remove_route".to_string()),
        "an abnormal stop must still remove the host route"
    );
}

#[test]
fn awg_04_path_change_rewrites_route_before_rebinding() {
    let rt = Recording::default();
    let new_gw = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    on_carrying_path_change(&rt, &route(), new_gw).unwrap();
    assert_eq!(
        rt.actions(),
        vec![
            "rewrite_route:10.0.0.1".to_string(),
            "rebind_tunnel:10.0.0.1".to_string()
        ]
    );
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
        endpoint: "edge.example:51820".into(),
        allowed_ips: vec!["0.0.0.0/0".into()],
        persistent_keepalive: Some(25),
    }
}

#[test]
fn awg_05_peer_and_obfuscation_are_one_transaction() {
    let req = build_set_device(&PrivateKey::new("SECRET"), &obf(), &peer()).unwrap();
    // The peer and every obfuscation parameter are present in the single request.
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
    // Only the wire form sent to the pipe carries it.
    assert!(req.to_wire().contains(secret));
}
