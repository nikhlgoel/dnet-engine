//! T052 (OS half) — real endpoint host routes via `CreateIpForwardEntry2`.
//!
//! Installs a `/32` (or `/128`) route to each resolved endpoint address through the
//! physical gateway, on the interface that actually reaches that gateway. The installer
//! owns exactly the routes it created and deletes only those: a pre-existing identical
//! route is left alone, never removed on teardown.
//!
//! Every route is created through the undo registry (T037), so its reversal is on disk
//! before the route exists, and removal runs the same [`WindowsUndoExecutor`] that crash
//! replay does.

#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2,
    GetIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_INET,
};

use crate::error::NetstateError;
use crate::host_route::HostRoute;
use crate::undo::{Mutation, UndoExecutor, UndoId, UndoRecord, UndoRegistry};

/// A TEST-NET-2 address (RFC 5737): never assigned, so the best route to it is the
/// machine's default route.
const DEFAULT_ROUTE_PROBE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

fn win32(status: WIN32_ERROR, what: &str) -> Result<(), NetstateError> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(NetstateError::Operation(format!(
            "{what} failed (win32 error {})",
            status.0
        )))
    }
}

/// Convert an address to the `SOCKADDR_INET` the IP Helper API takes.
pub fn to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                // S_addr is the address in network byte order as it sits in memory.
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            sa.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..SOCKADDR_IN6::default()
            };
        }
    }
    sa
}

/// Read an address back out of a `SOCKADDR_INET`. `None` for an unknown family.
pub fn from_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` overlays the family field of both union members, and the
    // member read below is selected by that family.
    unsafe {
        match sa.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// The route the OS would use to reach a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BestRoute {
    pub interface_index: u32,
    /// The interface's LUID, which unlike the index is stable across restarts.
    pub interface_luid: u64,
    /// Prefix length of the matched route: `0` means the default route.
    pub prefix_len: u8,
    /// The next hop, or `None` when the destination is on-link.
    pub next_hop: Option<IpAddr>,
}

/// Ask the OS for its best route to `dest`.
pub fn best_route_to(dest: IpAddr) -> Result<BestRoute, NetstateError> {
    let target = to_sockaddr_inet(dest);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: all pointers reference live locals for the duration of the call.
    let status = unsafe { GetBestRoute2(None, 0, None, &target, 0, &mut row, &mut source) };
    win32(status, "GetBestRoute2")?;
    let next_hop = from_sockaddr_inet(&row.NextHop).filter(|ip| !ip.is_unspecified());
    Ok(BestRoute {
        interface_index: row.InterfaceIndex,
        // SAFETY: NET_LUID_LH is a union over a u64; every bit pattern is a valid u64.
        interface_luid: unsafe { row.InterfaceLuid.Value },
        prefix_len: row.DestinationPrefix.PrefixLength,
        next_hop,
    })
}

/// The physical default gateway, read **before** any TUN exists (afterwards the best
/// route to an arbitrary address is the TUN itself).
pub fn default_gateway() -> Result<IpAddr, NetstateError> {
    let route = best_route_to(IpAddr::V4(DEFAULT_ROUTE_PROBE))?;
    match (route.prefix_len, route.next_hop) {
        (0, Some(gw)) => Ok(gw),
        _ => Err(NetstateError::Operation(
            "no IPv4 default route with a gateway (no usable path)".into(),
        )),
    }
}

/// Resolve a route destination to addresses of the gateway's family. An IP literal is
/// used as-is; a hostname is resolved through the OS — which is only correct **before**
/// the TUN is up, since afterwards the answer would be a FakeIP address.
pub fn resolve_destination(host: &str, gateway: IpAddr) -> Result<Vec<IpAddr>, NetstateError> {
    let candidates: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => (host, 0)
            .to_socket_addrs()
            .map_err(|e| NetstateError::Operation(format!("resolving endpoint failed: {e}")))?
            .map(|sa| sa.ip())
            .collect(),
    };
    let matching: Vec<IpAddr> = candidates
        .into_iter()
        .filter(|ip| ip.is_ipv4() == gateway.is_ipv4())
        .collect();
    if matching.is_empty() {
        return Err(NetstateError::Operation(
            "endpoint has no address in the gateway's address family".into(),
        ));
    }
    Ok(matching)
}

/// A host-route row: `dest/32|128` via `next_hop` on the interface with this LUID.
fn route_row(interface_luid: u64, dest: IpAddr, next_hop: IpAddr) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH {
        Value: interface_luid,
    };
    row.DestinationPrefix.Prefix = to_sockaddr_inet(dest);
    row.DestinationPrefix.PrefixLength = if dest.is_ipv4() { 32 } else { 128 };
    row.NextHop = to_sockaddr_inet(next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Whether a route with this row's key (interface, prefix, next hop) exists.
fn route_exists(row: &MIB_IPFORWARD_ROW2) -> bool {
    let mut probe = *row;
    // SAFETY: `probe` is an initialised row whose key fields are set; the call fills the rest.
    unsafe { GetIpForwardEntry2(&mut probe) }.is_ok()
}

/// Whether an interface with this LUID currently exists. Read-only and unprivileged.
pub fn interface_exists(interface_luid: u64) -> bool {
    let luid = NET_LUID_LH {
        Value: interface_luid,
    };
    let mut index = 0u32;
    // SAFETY: both pointers reference live locals for the duration of the call.
    unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) }.is_ok()
}

/// Reverses undo records on the real routing table. Used both for normal teardown and for
/// replay after a crash.
pub struct WindowsUndoExecutor;

impl UndoExecutor for WindowsUndoExecutor {
    fn reverse(&self, record: &UndoRecord) -> Result<(), NetstateError> {
        match record {
            UndoRecord::HostRoute {
                interface_luid,
                destination,
                next_hop,
            } => {
                // A route cannot outlive its interface, so a vanished interface (an unplugged
                // tether, a removed adapter) means the route is already gone.
                if !interface_exists(*interface_luid) {
                    return Ok(());
                }
                let row = route_row(*interface_luid, *destination, *next_hop);
                // SAFETY: `row` is fully initialised by `route_row`.
                let status = unsafe { DeleteIpForwardEntry2(&row) };
                // Gone already, or its interface is: either way nothing of ours remains.
                if status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND {
                    return Ok(());
                }
                win32(status, "DeleteIpForwardEntry2")
            }
        }
    }
}

struct OwnedRoute {
    destination: String,
    gateway: IpAddr,
    id: UndoId,
}

/// Installs and removes endpoint host routes, owning exactly what it created.
pub struct WindowsRouteInstaller {
    undo: Arc<UndoRegistry>,
    owned: Mutex<Vec<OwnedRoute>>,
}

impl WindowsRouteInstaller {
    pub fn new(undo: Arc<UndoRegistry>) -> Self {
        Self {
            undo,
            owned: Mutex::new(Vec::new()),
        }
    }

    /// Install the host route to every resolved address of the route's destination.
    /// Returns the addresses now routed via the gateway.
    pub fn install(&self, route: &HostRoute) -> Result<Vec<IpAddr>, NetstateError> {
        let addrs = resolve_destination(route.destination(), route.gateway())?;
        // The interface is the one the OS uses to reach the *gateway* — the physical link.
        // Querying the gateway (on-link) rather than the endpoint is deliberate: once a TUN
        // exists, the best route to the endpoint would be the TUN.
        let via = best_route_to(route.gateway())?;
        let mut owned = self.owned.lock().expect("route ownership mutex poisoned");
        for &dest in &addrs {
            let row = route_row(via.interface_luid, dest, route.gateway());
            // Checked before registering, so a route someone else owns never gets an undo
            // record that a crash could leave behind to delete it.
            if route_exists(&row) {
                tracing::warn!(%dest, "endpoint host route already present; not taking ownership");
                continue;
            }
            let record = UndoRecord::HostRoute {
                interface_luid: via.interface_luid,
                destination: dest,
                next_hop: route.gateway(),
            };
            let id = self.undo.apply(record, || {
                // SAFETY: `row` is fully initialised by `route_row`.
                let status = unsafe { CreateIpForwardEntry2(&row) };
                if status == ERROR_OBJECT_ALREADY_EXISTS {
                    // Created by someone else since the check: use it, never delete it.
                    tracing::warn!(%dest, "endpoint host route appeared concurrently; not taking ownership");
                    return Ok(Mutation::AlreadyPresent);
                }
                win32(status, "CreateIpForwardEntry2").map(|()| Mutation::Applied)
            })?;
            if let Some(id) = id {
                owned.push(OwnedRoute {
                    destination: route.destination().to_string(),
                    gateway: route.gateway(),
                    id,
                });
            }
        }
        Ok(addrs)
    }

    /// Remove the host routes this installer created for `route`. Idempotent: a route
    /// already gone is not an error. A route that cannot be removed stays owned, and its
    /// undo record stays on disk for replay.
    pub fn remove(&self, route: &HostRoute) -> Result<(), NetstateError> {
        let mut owned = self.owned.lock().expect("route ownership mutex poisoned");
        let mut first_error = None;
        owned.retain(|r| {
            if r.destination != route.destination() || r.gateway != route.gateway() {
                return true;
            }
            match self.undo.undo(r.id, &WindowsUndoExecutor) {
                Ok(()) => false,
                Err(e) => {
                    first_error.get_or_insert(e);
                    true
                }
            }
        });
        match first_error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Point the host route at a new gateway: install the new route first, then remove
    /// the old one, so there is no instant with no host route at all.
    pub fn rewrite(&self, from: &HostRoute, to: &HostRoute) -> Result<(), NetstateError> {
        if from == to {
            return Ok(());
        }
        self.install(to)?;
        self.remove(from)
    }

    /// Whether this installer currently owns a route for `route`.
    pub fn owns(&self, route: &HostRoute) -> bool {
        self.owned
            .lock()
            .expect("route ownership mutex poisoned")
            .iter()
            .any(|r| r.destination == route.destination() && r.gateway == route.gateway())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::undo::MemoryStore;
    use dnet_config::ActiveEndpointBypass;
    use dnet_core::endpoint::EndpointAddress;

    #[test]
    fn sockaddr_round_trips_both_families() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            IpAddr::V6("2001:db8::9".parse().unwrap()),
        ] {
            assert_eq!(from_sockaddr_inet(&to_sockaddr_inet(ip)), Some(ip));
        }
    }

    #[test]
    fn ipv4_is_stored_in_network_byte_order() {
        let sa = to_sockaddr_inet(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        // SAFETY: written as the IPv4 member above.
        let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
        assert_eq!(raw.to_ne_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn destination_filtering_keeps_only_the_gateway_family() {
        let gw4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            resolve_destination("203.0.113.9", gw4).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
        );
        assert!(resolve_destination("2001:db8::9", gw4).is_err());
    }

    #[test]
    fn best_route_query_succeeds_for_loopback() {
        // Read-only and unprivileged: every machine has a route to its loopback.
        let route = best_route_to(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert_ne!(route.interface_luid, 0);
    }

    fn test_route(last_octet: u8, gateway: IpAddr) -> HostRoute {
        let host = format!("203.0.113.{last_octet}");
        let bypass = ActiveEndpointBypass::new(&EndpointAddress::new(host, 1).unwrap());
        HostRoute::for_endpoint(&bypass, gateway)
    }

    /// Installs and removes a real route to an unassigned TEST-NET-3 address via the
    /// current default gateway, then confirms the OS picks it.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn a_real_host_route_is_installed_preferred_and_removed() {
        let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
        let dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        let route = test_route(77, gateway);
        let store = MemoryStore::new();
        let registry = Arc::new(UndoRegistry::open(Box::new(store.clone())).unwrap());
        let installer = WindowsRouteInstaller::new(registry.clone());

        installer.install(&route).unwrap();
        let chosen = best_route_to(dest).unwrap();
        assert_eq!(
            chosen.prefix_len, 32,
            "the /32 host route must be preferred"
        );
        assert_eq!(chosen.next_hop, Some(gateway));
        assert_eq!(
            registry.outstanding().len(),
            1,
            "the route's undo must be recorded"
        );

        installer.remove(&route).unwrap();
        assert!(!installer.owns(&route));
        assert!(registry.outstanding().is_empty());
        assert_ne!(best_route_to(dest).unwrap().prefix_len, 32);
    }

    /// SC-016 for routes: a run that dies without teardown leaves a journal, and a fresh
    /// registry over that journal removes the route.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn a_route_left_by_a_crashed_run_is_removed_by_replay() {
        use crate::undo_file::FileStore;

        let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
        let dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 78));
        let root = tempfile::tempdir().unwrap();
        let journal = root.path().join("state").join("undo.json");

        {
            let registry =
                Arc::new(UndoRegistry::open(Box::new(FileStore::new(&journal))).unwrap());
            let installer = WindowsRouteInstaller::new(registry);
            installer.install(&test_route(78, gateway)).unwrap();
            assert_eq!(best_route_to(dest).unwrap().prefix_len, 32);
            // Dropped without `remove`: the process died.
        }
        assert_eq!(
            best_route_to(dest).unwrap().prefix_len,
            32,
            "nothing restored it yet"
        );

        let restarted = UndoRegistry::open(Box::new(FileStore::new(&journal))).unwrap();
        let report = restarted.replay(&WindowsUndoExecutor).unwrap();

        assert_eq!((report.restored, report.failed.len()), (1, 0));
        assert!(restarted.outstanding().is_empty());
        assert_ne!(best_route_to(dest).unwrap().prefix_len, 32);
    }

    /// A pre-existing identical route is used but never recorded, so neither teardown nor
    /// replay can remove it.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn a_pre_existing_route_is_never_recorded_or_removed() {
        let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
        let dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 79));
        let theirs = WindowsRouteInstaller::new(Arc::new(
            UndoRegistry::open(Box::new(MemoryStore::new())).unwrap(),
        ));
        theirs.install(&test_route(79, gateway)).unwrap();

        let registry = Arc::new(UndoRegistry::open(Box::new(MemoryStore::new())).unwrap());
        let ours = WindowsRouteInstaller::new(registry.clone());
        ours.install(&test_route(79, gateway)).unwrap();
        assert!(registry.outstanding().is_empty());
        ours.remove(&test_route(79, gateway)).unwrap();
        assert_eq!(
            best_route_to(dest).unwrap().prefix_len,
            32,
            "not ours to remove"
        );

        theirs.remove(&test_route(79, gateway)).unwrap();
        assert_ne!(best_route_to(dest).unwrap().prefix_len, 32);
    }

    /// An interface that no longer exists took its routes with it. Runs unelevated because
    /// the routing table is never touched: without the interface check this would be a
    /// delete attempt, which an unprivileged caller is denied.
    #[test]
    fn reversing_a_route_on_a_vanished_interface_succeeds_without_touching_routes() {
        assert!(!interface_exists(0x0006_0000_0000_7f3a));
        let record = UndoRecord::HostRoute {
            interface_luid: 0x0006_0000_0000_7f3a,
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        };
        WindowsUndoExecutor.reverse(&record).unwrap();
    }

    #[test]
    fn a_present_interface_exists() {
        let luid = best_route_to(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .unwrap()
            .interface_luid;
        assert!(interface_exists(luid));
    }

    /// Reversal is idempotent: deleting a route that is already gone, on an interface that
    /// still exists, is success.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn reversing_a_route_that_is_already_gone_succeeds() {
        let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
        let record = UndoRecord::HostRoute {
            interface_luid: best_route_to(gateway).unwrap().interface_luid,
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)),
            next_hop: gateway,
        };
        WindowsUndoExecutor.reverse(&record).unwrap();
    }
}
