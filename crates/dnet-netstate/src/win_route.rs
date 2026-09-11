//! T052 (OS half) — real endpoint host routes via `CreateIpForwardEntry2`.
//!
//! Installs a `/32` (or `/128`) route to each resolved endpoint address through the
//! physical gateway, on the interface that actually reaches that gateway. The installer
//! records exactly the rows it created and deletes only those: a pre-existing identical
//! route is left alone, never removed on teardown.

#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Mutex;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_INET,
};

use crate::error::NetstateError;
use crate::host_route::HostRoute;

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

/// Build the host-route row: `dest/32|128` via `gateway` on the interface that reaches it.
fn host_route_row(dest: IpAddr, gateway: IpAddr) -> Result<MIB_IPFORWARD_ROW2, NetstateError> {
    // The interface is the one the OS uses to reach the *gateway* — the physical link.
    // Querying the gateway (on-link) rather than the endpoint is deliberate: once a TUN
    // exists, the best route to the endpoint would be the TUN.
    let via = best_route_to(gateway)?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = via.interface_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(dest);
    row.DestinationPrefix.PrefixLength = if dest.is_ipv4() { 32 } else { 128 };
    row.NextHop = to_sockaddr_inet(gateway);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    Ok(row)
}

struct OwnedRoute {
    destination: String,
    gateway: IpAddr,
    row: MIB_IPFORWARD_ROW2,
}

// SAFETY: MIB_IPFORWARD_ROW2 is plain data (integers and unions of integers) with no
// pointers or thread affinity.
unsafe impl Send for OwnedRoute {}

/// Installs and removes endpoint host routes, owning exactly what it created.
#[derive(Default)]
pub struct WindowsRouteInstaller {
    owned: Mutex<Vec<OwnedRoute>>,
}

impl WindowsRouteInstaller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the host route to every resolved address of the route's destination.
    /// Returns the addresses now routed via the gateway.
    pub fn install(&self, route: &HostRoute) -> Result<Vec<IpAddr>, NetstateError> {
        let addrs = resolve_destination(route.destination(), route.gateway())?;
        let mut owned = self.owned.lock().expect("route ownership mutex poisoned");
        for &dest in &addrs {
            let row = host_route_row(dest, route.gateway())?;
            // SAFETY: `row` is fully initialised above.
            let status = unsafe { CreateIpForwardEntry2(&row) };
            if status == ERROR_OBJECT_ALREADY_EXISTS {
                // An identical route already exists and is not ours: use it, never delete.
                tracing::warn!(%dest, "endpoint host route already present; not taking ownership");
                continue;
            }
            win32(status, "CreateIpForwardEntry2")?;
            owned.push(OwnedRoute {
                destination: route.destination().to_string(),
                gateway: route.gateway(),
                row,
            });
        }
        Ok(addrs)
    }

    /// Remove the host routes this installer created for `route`. Idempotent: a route
    /// already gone is not an error.
    pub fn remove(&self, route: &HostRoute) -> Result<(), NetstateError> {
        let mut owned = self.owned.lock().expect("route ownership mutex poisoned");
        let mut first_error = None;
        owned.retain(|r| {
            if r.destination != route.destination() || r.gateway != route.gateway() {
                return true;
            }
            // SAFETY: `row` is the exact row passed to CreateIpForwardEntry2.
            let status = unsafe { DeleteIpForwardEntry2(&r.row) };
            if status.is_ok() || status == ERROR_NOT_FOUND {
                false
            } else {
                first_error.get_or_insert(status);
                true
            }
        });
        match first_error {
            None => Ok(()),
            Some(status) => win32(status, "DeleteIpForwardEntry2"),
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
        assert!(best_route_to(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    }

    /// Installs and removes a real route to an unassigned TEST-NET-3 address via the
    /// current default gateway, then confirms the OS picks it.
    #[test]
    #[ignore = "requires an elevated Administrator (run: cargo test -p dnet-netstate -- --ignored)"]
    fn a_real_host_route_is_installed_preferred_and_removed() {
        let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
        let dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        let bypass = ActiveEndpointBypass::new(&EndpointAddress::new("203.0.113.77", 1).unwrap());
        let route = HostRoute::for_endpoint(&bypass, gateway);
        let installer = WindowsRouteInstaller::new();

        installer.install(&route).unwrap();
        let chosen = best_route_to(dest).unwrap();
        assert_eq!(
            chosen.prefix_len, 32,
            "the /32 host route must be preferred"
        );
        assert_eq!(chosen.next_hop, Some(gateway));

        installer.remove(&route).unwrap();
        assert!(!installer.owns(&route));
        assert_ne!(best_route_to(dest).unwrap().prefix_len, 32);
    }
}
