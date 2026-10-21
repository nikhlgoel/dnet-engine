//! T080 — the machine's real ways out, as the failover logic sees them (data-model §3).
//!
//! `notify` says that something changed; this says what the machine looks like now, as a list of
//! [`NetworkPath`]. Reading the operating system is Windows-only ([`current`]); deciding what counts
//! as a way out is [`project`], pure and tested on plain data.
//!
//! **What counts as a path.** A physical network adapter that is up and has an IPv4 default route
//! (endpoints are IPv4 literals, so an adapter with only an IPv6 route cannot carry one):
//!
//! - Virtual adapters are not ways out: the Hyper-V and WSL switches, VMware and VPN adapters, and
//!   above all this product's own tunnel adapters. A tunnel counted as a way out is the routing loop
//!   (R4) in its purest form, so adapters named `dnet-…` are excluded even if one were ever flagged
//!   as hardware.
//! - A hardware adapter that is down, or up with no default route, is listed as `Unusable` rather
//!   than left out: to the failover logic a path that was there and is not is a lost link, and a
//!   path that simply vanished from the list reads the same way.
//! - A default route with no gateway (mobile broadband routes on-link) is a usable path that
//!   cannot carry the AmneziaWG profile; `gateway` is `None`, as `NetworkPath` says it must be.
//!
//! **Default preference by kind**, because failover returns to a preferred path only when one is
//! strictly preferred: wired over Wi-Fi over cellular, the last because it costs data. It is a
//! default until the user can set their own.

use std::net::{IpAddr, Ipv4Addr};

use dnet_core::ids::InterfaceId;
use dnet_core::path::{NetworkPath, PathKind, PathQuality, PathRole};

/// Interface types (`IF_TYPE_*`) this module distinguishes.
mod if_type {
    pub const ETHERNET: u32 = 6;
    pub const IEEE80211: u32 = 71;
    pub const WWANPP: u32 = 243;
    pub const WWANPP2: u32 = 244;
}

/// The prefix of the names of this product's own adapters.
const OWN_ADAPTER_PREFIX: &str = "dnet-";

/// One network interface as the operating system reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInterface {
    pub luid: u64,
    pub name: String,
    pub if_type: u32,
    /// A physical adapter, as opposed to a virtual one.
    pub hardware: bool,
    pub up: bool,
}

/// An IPv4 default route (`0.0.0.0/0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDefaultRoute {
    pub luid: u64,
    /// `None` for an on-link route (next hop `0.0.0.0`).
    pub gateway: Option<Ipv4Addr>,
    /// The route's own metric plus its interface's: what the system compares.
    pub metric: u32,
}

fn kind_of(if_type: u32) -> PathKind {
    match if_type {
        if_type::IEEE80211 => PathKind::Wifi,
        if_type::ETHERNET => PathKind::Ethernet,
        if_type::WWANPP | if_type::WWANPP2 => PathKind::Cellular,
        _ => PathKind::Other,
    }
}

/// The default preference of a kind: higher wins.
fn default_preference(kind: PathKind) -> i32 {
    match kind {
        PathKind::Ethernet => 20,
        PathKind::Wifi => 10,
        PathKind::Cellular | PathKind::Other => 0,
    }
}

/// Turn what the operating system reported into paths, best route first.
pub fn project(interfaces: &[RawInterface], routes: &[RawDefaultRoute]) -> Vec<NetworkPath> {
    let mut paths: Vec<(u32, NetworkPath)> = interfaces
        .iter()
        .filter(|i| i.hardware && !i.name.to_ascii_lowercase().starts_with(OWN_ADAPTER_PREFIX))
        .map(|i| {
            // The best (lowest metric) default route of this interface.
            let route = routes
                .iter()
                .filter(|r| r.luid == i.luid)
                .min_by_key(|r| r.metric);
            let kind = kind_of(i.if_type);
            let usable = i.up && route.is_some();
            let path = NetworkPath {
                interface_id: InterfaceId::new(i.luid),
                kind,
                gateway: route.and_then(|r| r.gateway).map(IpAddr::V4),
                quality: PathQuality::unmeasured(),
                role: if usable {
                    PathRole::Standby
                } else {
                    PathRole::Unusable
                },
                preference: default_preference(kind),
            };
            (route.map_or(u32::MAX, |r| r.metric), path)
        })
        .collect();
    // The system's own order of preference first; usable before not; the interface id last so the
    // result is the same every time.
    paths.sort_by_key(|(metric, p)| (p.role == PathRole::Unusable, *metric, p.interface_id.luid()));
    paths.into_iter().map(|(_, p)| p).collect()
}

#[cfg(windows)]
pub use windows_reader::{current, read};

#[cfg(windows)]
mod windows_reader {
    use std::net::Ipv4Addr;

    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, GetIpForwardTable2, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    use super::{project, RawDefaultRoute, RawInterface};
    use crate::error::NetstateError;
    use dnet_core::path::NetworkPath;

    /// `IfOperStatusUp`.
    const OPER_STATUS_UP: i32 = 1;
    /// `HardwareInterface`, bit 0 of `InterfaceAndOperStatusFlags`.
    const HARDWARE_BIT: u8 = 0b1;

    fn alias(raw: &[u16]) -> String {
        let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
        String::from_utf16_lossy(&raw[..end])
    }

    /// The interfaces and IPv4 default routes, exactly as the system reports them.
    pub fn read() -> Result<(Vec<RawInterface>, Vec<RawDefaultRoute>), NetstateError> {
        let mut interfaces = Vec::new();
        let mut routes = Vec::new();

        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        // SAFETY: `table` is a valid out-pointer; on success it owns a table freed below.
        let status = unsafe { GetIfTable2(&mut table) };
        if status != NO_ERROR || table.is_null() {
            return Err(NetstateError::Operation(format!(
                "could not list network interfaces (error {})",
                status.0
            )));
        }
        // SAFETY: `table` is non-null and holds `NumEntries` rows after the header.
        unsafe {
            let rows =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for row in rows {
                interfaces.push(RawInterface {
                    luid: row.InterfaceLuid.Value,
                    name: alias(&row.Alias),
                    if_type: row.Type,
                    hardware: row.InterfaceAndOperStatusFlags._bitfield & HARDWARE_BIT != 0,
                    up: row.OperStatus.0 == OPER_STATUS_UP,
                });
            }
            FreeMibTable(table as *const _);
        }

        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: as above.
        let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
        if status != NO_ERROR || table.is_null() {
            return Err(NetstateError::Operation(format!(
                "could not list routes (error {})",
                status.0
            )));
        }
        // SAFETY: `table` is non-null and holds `NumEntries` rows after the header.
        unsafe {
            let rows =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for row in rows {
                let prefix = &row.DestinationPrefix;
                if prefix.PrefixLength != 0 || prefix.Prefix.Ipv4.sin_addr.S_un.S_addr != 0 {
                    continue;
                }
                let hop = u32::from_be(row.NextHop.Ipv4.sin_addr.S_un.S_addr);
                routes.push(RawDefaultRoute {
                    luid: row.InterfaceLuid.Value,
                    gateway: (hop != 0).then(|| Ipv4Addr::from(hop)),
                    // Route metric only; the interface metric is added by the system when it
                    // picks, and ordering by the route's own is enough to rank ones that exist.
                    metric: row.Metric,
                });
            }
            FreeMibTable(table as *const _);
        }
        Ok((interfaces, routes))
    }

    /// The machine's paths right now.
    pub fn current() -> Result<Vec<NetworkPath>, NetstateError> {
        let (interfaces, routes) = read()?;
        Ok(project(&interfaces, &routes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(luid: u64, name: &str, if_type: u32) -> RawInterface {
        RawInterface {
            luid,
            name: name.into(),
            if_type,
            hardware: true,
            up: true,
        }
    }

    fn route(luid: u64, gateway: Option<[u8; 4]>, metric: u32) -> RawDefaultRoute {
        RawDefaultRoute {
            luid,
            gateway: gateway.map(Ipv4Addr::from),
            metric,
        }
    }

    fn only(paths: Vec<NetworkPath>) -> NetworkPath {
        assert_eq!(paths.len(), 1, "{paths:?}");
        paths.into_iter().next().unwrap()
    }

    #[test]
    fn a_wifi_adapter_with_a_gateway_is_a_standby_wifi_path() {
        let p = only(project(
            &[nic(1, "Wi-Fi", if_type::IEEE80211)],
            &[route(1, Some([192, 168, 1, 1]), 25)],
        ));
        assert_eq!(p.kind, PathKind::Wifi);
        assert_eq!(p.role, PathRole::Standby);
        assert_eq!(p.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(p.interface_id, InterfaceId::new(1));
        assert_eq!(p.quality, PathQuality::unmeasured());
    }

    #[test]
    fn wired_is_preferred_over_wifi_over_cellular_by_default() {
        let paths = project(
            &[
                nic(1, "Wi-Fi", if_type::IEEE80211),
                nic(2, "Ethernet", if_type::ETHERNET),
                nic(3, "Cellular", if_type::WWANPP2),
            ],
            &[
                route(1, Some([10, 0, 0, 1]), 25),
                route(2, Some([10, 1, 0, 1]), 25),
                route(3, None, 25),
            ],
        );
        let preference = |kind| paths.iter().find(|p| p.kind == kind).unwrap().preference;
        assert!(preference(PathKind::Ethernet) > preference(PathKind::Wifi));
        assert!(preference(PathKind::Wifi) > preference(PathKind::Cellular));
    }

    #[test]
    fn an_on_link_default_route_is_a_usable_path_without_a_gateway() {
        let p = only(project(
            &[nic(3, "Cellular", if_type::WWANPP)],
            &[route(3, None, 50)],
        ));
        assert_eq!(p.kind, PathKind::Cellular);
        assert_eq!(p.role, PathRole::Standby);
        assert_eq!(p.gateway, None);
        assert!(
            !p.can_carry_profile_a(),
            "no gateway, so not the AmneziaWG profile"
        );
    }

    #[test]
    fn an_up_adapter_with_no_default_route_is_listed_as_unusable() {
        let p = only(project(&[nic(1, "Wi-Fi", if_type::IEEE80211)], &[]));
        assert_eq!(p.role, PathRole::Unusable);
        assert_eq!(p.gateway, None);
    }

    #[test]
    fn an_adapter_that_is_down_is_unusable_even_with_a_stale_route() {
        let mut down = nic(1, "Ethernet", if_type::ETHERNET);
        down.up = false;
        let p = only(project(&[down], &[route(1, Some([10, 0, 0, 1]), 25)]));
        assert_eq!(p.role, PathRole::Unusable);
    }

    #[test]
    fn virtual_adapters_are_not_ways_out() {
        let mut vmware = nic(5, "VMware Network Adapter VMnet8", if_type::ETHERNET);
        vmware.hardware = false;
        let mut wsl = nic(6, "vEthernet (WSL)", if_type::ETHERNET);
        wsl.hardware = false;
        let paths = project(
            &[vmware, wsl],
            &[
                route(5, Some([192, 168, 5, 1]), 5),
                route(6, Some([172, 17, 0, 1]), 5),
            ],
        );
        assert!(paths.is_empty(), "{paths:?}");
    }

    /// A tunnel counted as a way out is the routing loop. Excluded by name too, so that a flag the
    /// system got wrong cannot put one in the list.
    #[test]
    fn this_products_own_adapters_are_never_ways_out_even_if_flagged_as_hardware() {
        let paths = project(
            &[
                nic(7, "dnet-tun0", if_type::ETHERNET),
                nic(8, "DNET-AWG0", if_type::ETHERNET),
            ],
            &[
                route(7, Some([10, 66, 0, 1]), 1),
                route(8, Some([10, 66, 0, 1]), 1),
            ],
        );
        assert!(paths.is_empty(), "{paths:?}");
    }

    #[test]
    fn a_hardware_adapter_of_an_unknown_type_is_still_a_path() {
        let p = only(project(
            &[nic(9, "Dial-up", 23)],
            &[route(9, Some([1, 1, 1, 1]), 10)],
        ));
        assert_eq!(p.kind, PathKind::Other);
        assert_eq!(p.role, PathRole::Standby);
    }

    #[test]
    fn an_interface_with_two_default_routes_uses_the_one_with_the_lower_metric() {
        let p = only(project(
            &[nic(1, "Wi-Fi", if_type::IEEE80211)],
            &[
                route(1, Some([10, 0, 0, 254]), 400),
                route(1, Some([10, 0, 0, 1]), 25),
            ],
        ));
        assert_eq!(p.gateway, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn a_route_belonging_to_another_interface_is_not_borrowed() {
        let paths = project(
            &[
                nic(1, "Wi-Fi", if_type::IEEE80211),
                nic(2, "Ethernet", if_type::ETHERNET),
            ],
            &[route(2, Some([10, 1, 0, 1]), 25)],
        );
        let wifi = paths.iter().find(|p| p.kind == PathKind::Wifi).unwrap();
        assert_eq!(wifi.role, PathRole::Unusable);
        assert_eq!(wifi.gateway, None);
    }

    #[test]
    fn usable_paths_come_first_best_route_first() {
        let mut down = nic(3, "Cellular", if_type::WWANPP);
        down.up = false;
        let paths = project(
            &[
                down,
                nic(1, "Wi-Fi", if_type::IEEE80211),
                nic(2, "Ethernet", if_type::ETHERNET),
            ],
            &[
                route(1, Some([10, 0, 0, 1]), 50),
                route(2, Some([10, 1, 0, 1]), 25),
            ],
        );
        let order: Vec<u64> = paths.iter().map(|p| p.interface_id.luid()).collect();
        assert_eq!(
            order,
            [2, 1, 3],
            "ethernet (25), wifi (50), then the one that is down"
        );
    }

    #[test]
    fn the_same_input_always_gives_the_same_order() {
        let interfaces = [
            nic(4, "A", if_type::ETHERNET),
            nic(2, "B", if_type::ETHERNET),
            nic(3, "C", if_type::ETHERNET),
        ];
        let routes = [
            route(4, Some([1, 0, 0, 1]), 25),
            route(2, Some([2, 0, 0, 1]), 25),
            route(3, Some([3, 0, 0, 1]), 25),
        ];
        let once = project(&interfaces, &routes);
        let mut reversed = interfaces.to_vec();
        reversed.reverse();
        assert_eq!(
            once,
            project(&reversed, &routes),
            "ties are broken by interface id"
        );
    }

    #[test]
    fn nothing_in_nothing_out() {
        assert!(project(&[], &[]).is_empty());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// Reads this machine's real network. Whatever it holds, the rules must: no virtual or
    /// product-owned adapter is listed, and a usable path is an adapter that is up.
    #[test]
    fn this_machines_paths_obey_the_rules() {
        let (interfaces, routes) = read().expect("reading the network needs no elevation");
        let paths = project(&interfaces, &routes);

        for path in &paths {
            let raw = interfaces
                .iter()
                .find(|i| i.luid == path.interface_id.luid())
                .expect("a path comes from an interface");
            assert!(raw.hardware, "{} is not a physical adapter", raw.name);
            assert!(
                !raw.name.to_ascii_lowercase().starts_with("dnet-"),
                "{}",
                raw.name
            );
            // A usable path is an adapter that is up. The reverse does not hold: an adapter can
            // still have its default route while it is not up (it was seen, associating), and
            // that moment is exactly when a test of "a gateway means usable" would fail.
            if path.role == PathRole::Standby {
                assert!(raw.up, "{} is listed usable while not up", raw.name);
            }
        }
        // Standby paths sort before unusable ones.
        let first_unusable = paths.iter().position(|p| p.role == PathRole::Unusable);
        if let Some(i) = first_unusable {
            assert!(paths[i..].iter().all(|p| p.role == PathRole::Unusable));
        }
    }
}
