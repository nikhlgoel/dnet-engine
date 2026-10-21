//! T138 — the Windows machine behind the network watch.
//!
//! `netwatch` is the loop; this is what it stands on. Everything here is a thin step over a piece
//! that is tested where it lives: `dnet_netstate::notify` (what changed, already settled),
//! `paths` (what the machine's ways out are), `echo` and `probe` (what a measurement saw), and
//! `Tunnels::carry_over` (moving the tunnel, route first). What is left is choosing among them.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use dnet_core::ids::InterfaceId;
use dnet_core::path::{NetworkPath, PathRole};
use dnet_core::probe_plan::{Observation, Strategy};
use dnet_core::profile::Carrier;
use dnet_core::quality::PathSample;
use dnet_netstate::notify::{settled, ChangeSource, LONGEST, QUIET};
use dnet_netstate::win_route::best_route_to;
use dnet_netstate::{echo, paths, probe};
use tokio::sync::mpsc;

use crate::effects::WindowsHost;
use crate::netwatch::{NetworkWatch, PathProber, ProbeTarget};
use crate::tunnel::Tunnels;

/// How long an echo to a gateway waits.
const GATEWAY_ECHO_TIMEOUT: Duration = Duration::from_secs(2);

/// What is known about the tunnel being watched, captured when it was started.
#[derive(Debug, Clone)]
pub struct WatchSetup {
    pub carrier: Carrier,
    /// Whether the tunnel's path is ours to steer (AmneziaWG); see `netwatch`.
    pub steer: bool,
    /// The endpoint's address, when it is an IPv4 literal.
    pub endpoint_ip: Option<Ipv4Addr>,
    /// The endpoint's TCP port, when it serves one, to aim a probe at.
    pub endpoint_tcp: Option<SocketAddrV4>,
}

pub struct WindowsWatch {
    setup: WatchSetup,
    tunnels: Arc<Tunnels<WindowsHost>>,
    changes: mpsc::Receiver<()>,
}

impl WindowsWatch {
    /// Start listening for changes of the network. If the system will not take the subscription
    /// the watch still works: the loop reads the paths on a slow timer as well, and a source that
    /// has ended is not an error to it.
    pub fn start(setup: WatchSetup, tunnels: Arc<Tunnels<WindowsHost>>) -> Self {
        let (tx, changes) = mpsc::channel(1);
        match ChangeSource::start() {
            Ok((source, mut raw)) => {
                // `settled` is not cancel-safe (it counts events as it goes), so it runs here, on
                // a task of its own, and the loop receives a plain channel that is.
                tokio::spawn(async move {
                    let _source = source;
                    loop {
                        tokio::select! {
                            () = tx.closed() => break,
                            burst = settled(&mut raw, QUIET, LONGEST) => match burst {
                                Some(_) => { let _ = tx.try_send(()); }
                                None => break,
                            },
                        }
                    }
                });
            }
            Err(error) => {
                tracing::warn!(%error, "the system would not report network changes; the paths are read on a timer instead");
            }
        }
        Self {
            setup,
            tunnels,
            changes,
        }
    }
}

impl NetworkWatch for WindowsWatch {
    type Prober = WindowsProber;

    fn prober(&self) -> WindowsProber {
        WindowsProber {
            endpoint_tcp: self.setup.endpoint_tcp,
        }
    }

    fn changes(&mut self) -> impl std::future::Future<Output = Option<()>> + Send {
        self.changes.recv()
    }

    fn paths(&mut self) -> Result<Vec<NetworkPath>, String> {
        paths::current().map_err(|e| e.to_string())
    }

    /// The adapter the tunnel leaves through: the one the system would use to reach the endpoint
    /// (the endpoint is kept out of the tunnel, so this is a physical adapter). If that is not a
    /// path we know, the best usable path is the closest guess.
    fn carrying_now(&mut self, known: &[NetworkPath]) -> Option<InterfaceId> {
        let routed = self
            .setup
            .endpoint_ip
            .and_then(|ip| best_route_to(IpAddr::V4(ip)).ok())
            .map(|route| InterfaceId::new(route.interface_luid));
        choose_carrying(routed, known)
    }

    fn carrier(&self) -> Carrier {
        self.setup.carrier
    }

    fn endpoint_tcp(&self) -> bool {
        self.setup.endpoint_tcp.is_some()
    }

    fn can_steer(&self) -> bool {
        self.setup.steer
    }

    fn needs_gateway(&self) -> bool {
        self.setup.steer
    }

    fn carry_over(
        &mut self,
        to: &NetworkPath,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let tunnels = Arc::clone(&self.tunnels);
        let gateway = to.gateway;
        async move {
            let gateway = gateway.ok_or_else(|| "the path has no gateway".to_owned())?;
            tunnels.carry_over(gateway).await.map_err(|e| e.to_string())
        }
    }
}

/// Which adapter the tunnel is on, given the adapter the system routes the endpoint through (if it
/// said) and the paths known. The routed adapter wins when it is a usable path we know. Otherwise
/// (the system names the tunnel's own adapter, or a virtual one, or nothing) the best usable path
/// is the closest guess: `known` is ordered best route first.
fn choose_carrying(routed: Option<InterfaceId>, known: &[NetworkPath]) -> Option<InterfaceId> {
    let usable = |p: &&NetworkPath| p.role != PathRole::Unusable;
    routed
        .filter(|id| known.iter().filter(usable).any(|p| p.interface_id == *id))
        .or_else(|| known.iter().find(usable).map(|p| p.interface_id))
}

/// Runs the measurements of the watch on this machine.
#[derive(Clone)]
pub struct WindowsProber {
    endpoint_tcp: Option<SocketAddrV4>,
}

impl PathProber for WindowsProber {
    async fn observe(&self, target: ProbeTarget, strategy: Strategy) -> Option<Observation> {
        match strategy {
            Strategy::Endpoint => {
                let endpoint = self.endpoint_tcp?;
                match probe::probe_tcp(target.interface.luid(), endpoint, probe::CONNECT_TIMEOUT)
                    .await
                {
                    Ok(PathSample::Answered { rtt }) => Some(Observation::Answered(rtt)),
                    Ok(PathSample::Lost) => Some(Observation::Silent),
                    // Could not be set up: not a measurement of the path.
                    Err(_) => None,
                }
            }
            Strategy::Gateway => {
                let gateway = target.gateway?;
                echo::echo_gateway(gateway, GATEWAY_ECHO_TIMEOUT).await.ok()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use dnet_core::path::{PathKind, PathQuality};

    use super::*;

    fn path(n: u64, up: bool) -> NetworkPath {
        NetworkPath {
            interface_id: InterfaceId::new(n),
            kind: PathKind::Wifi,
            gateway: None,
            quality: PathQuality::unmeasured(),
            role: if up {
                PathRole::Standby
            } else {
                PathRole::Unusable
            },
            preference: 0,
        }
    }

    fn id(n: u64) -> Option<InterfaceId> {
        Some(InterfaceId::new(n))
    }

    #[test]
    fn the_adapter_the_endpoint_is_routed_through_is_the_one_carrying() {
        assert_eq!(
            choose_carrying(id(2), &[path(1, true), path(2, true)]),
            id(2)
        );
    }

    #[test]
    fn a_routed_adapter_that_is_not_a_known_path_falls_back_to_the_best_usable_one() {
        // The system names an adapter that is no way out (the tunnel itself, a virtual switch).
        assert_eq!(
            choose_carrying(id(99), &[path(1, true), path(2, true)]),
            id(1)
        );
    }

    #[test]
    fn a_routed_adapter_that_is_down_is_not_believed() {
        assert_eq!(
            choose_carrying(id(1), &[path(1, false), path(2, true)]),
            id(2)
        );
    }

    #[test]
    fn with_no_answer_from_the_system_the_best_usable_path_is_the_guess() {
        assert_eq!(
            choose_carrying(None, &[path(3, false), path(2, true)]),
            id(2)
        );
    }

    #[test]
    fn with_nothing_usable_nothing_is_carrying() {
        assert_eq!(choose_carrying(id(1), &[path(1, false)]), None);
        assert_eq!(choose_carrying(None, &[]), None);
    }
}
