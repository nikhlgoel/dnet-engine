// SPDX-License-Identifier: GPL-3.0-or-later
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

/// `IfOperStatusUp`.
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows; tested everywhere
const OPER_STATUS_UP: i32 = 1;
/// `HardwareInterface`, bit 0 of `InterfaceAndOperStatusFlags`.
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows; tested everywhere
const HARDWARE_BIT: u8 = 0b1;

/// The alias of an interface as the system stores it: UTF-16, ended by the first NUL (or full). Anything
/// that is not valid UTF-16 is replaced, never trusted.
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows; tested everywhere
pub(crate) fn alias_text(raw: &[u16]) -> String {
    let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
    String::from_utf16_lossy(&raw[..end])
}

/// One row of the interface table as plain facts: `flags` is the system's bit field (bit 0 set means a
/// physical adapter) and `oper_status` its operational status (1 means up, and nothing else does).
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows; tested everywhere
pub(crate) fn raw_interface(
    luid: u64,
    alias: &[u16],
    if_type: u32,
    flags: u8,
    oper_status: i32,
) -> RawInterface {
    RawInterface {
        luid,
        name: alias_text(alias),
        if_type,
        hardware: flags & HARDWARE_BIT != 0,
        up: oper_status == OPER_STATUS_UP,
    }
}

/// One row of the IPv4 route table, kept only if it is a default route (`0.0.0.0/0`): a prefix length
/// of zero **and** an all-zero destination. `next_hop_network_order` is the address as the system
/// stores it (network byte order); a next hop of `0.0.0.0` means on-link, with no gateway.
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows; tested everywhere
pub(crate) fn raw_default_route(
    prefix_length: u8,
    destination_network_order: u32,
    next_hop_network_order: u32,
    luid: u64,
    metric: u32,
) -> Option<RawDefaultRoute> {
    if prefix_length != 0 || destination_network_order != 0 {
        return None;
    }
    let hop = u32::from_be(next_hop_network_order);
    Some(RawDefaultRoute {
        luid,
        gateway: (hop != 0).then(|| Ipv4Addr::from(hop)),
        // Route metric only; the interface metric is added by the system when it picks, and ordering
        // by the route's own is enough to rank ones that exist.
        metric,
    })
}

#[cfg(windows)]
pub use windows_reader::{current, read};

#[cfg(windows)]
mod windows_reader {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, GetIpForwardTable2, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    use super::{project, raw_default_route, raw_interface, RawDefaultRoute, RawInterface};
    use crate::error::NetstateError;
    use dnet_core::path::NetworkPath;

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
                interfaces.push(raw_interface(
                    row.InterfaceLuid.Value,
                    &row.Alias,
                    row.Type,
                    row.InterfaceAndOperStatusFlags._bitfield,
                    row.OperStatus.0,
                ));
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
                routes.extend(raw_default_route(
                    prefix.PrefixLength,
                    prefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                    row.NextHop.Ipv4.sin_addr.S_un.S_addr,
                    row.InterfaceLuid.Value,
                    row.Metric,
                ));
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

/// The decoding of raw table rows (what the system's tables hold, bit for bit) into plain facts. These are
/// the same rules whether the machine is a laptop, a server or a virtual machine, and they decide what the
/// failover logic believes about the network, so every bit and edge is tried.
#[cfg(test)]
mod decode_tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A fixed-size alias buffer as the system keeps it: the text, then NULs.
    fn padded(text: &str, size: usize) -> Vec<u16> {
        let mut buffer = wide(text);
        buffer.resize(size, 0);
        buffer
    }

    // ---------------------------------------------------------------- the alias

    #[test]
    fn an_alias_ends_at_the_first_nul() {
        assert_eq!(alias_text(&padded("Wi-Fi", 257)), "Wi-Fi");
    }

    #[test]
    fn an_alias_that_fills_the_buffer_has_no_nul_to_end_it() {
        assert_eq!(alias_text(&wide("Ethernet")), "Ethernet");
    }

    #[test]
    fn an_empty_buffer_and_an_all_nul_buffer_are_an_empty_alias() {
        assert_eq!(alias_text(&[]), "");
        assert_eq!(alias_text(&[0, 0, 0]), "");
    }

    #[test]
    fn anything_after_the_first_nul_is_never_part_of_the_alias() {
        let mut buffer = wide("Wi-Fi");
        buffer.push(0);
        buffer.extend(wide("hidden"));
        assert_eq!(alias_text(&buffer), "Wi-Fi");
    }

    #[test]
    fn an_alias_in_another_script_is_read_whole() {
        for name in [
            "Ethernet 2",
            "Беспроводная сеть",
            "無線LAN",
            "واي فاي",
            "Wi‑Fi",
        ] {
            assert_eq!(alias_text(&padded(name, 300)), name);
        }
    }

    #[test]
    fn broken_utf16_is_replaced_and_never_trusted() {
        // A lone surrogate is not text.
        let shown = alias_text(&[0x0057, 0xD800, 0x0069, 0]);
        assert_eq!(shown, "W\u{FFFD}i");
    }

    // ---------------------------------------------------------------- an interface row

    #[test]
    fn bit_zero_of_the_flags_alone_makes_an_adapter_hardware() {
        for flags in 0u8..=255 {
            let row = raw_interface(1, &wide("a"), 6, flags, 1);
            assert_eq!(row.hardware, flags & 1 == 1, "flags {flags:#010b}");
        }
    }

    #[test]
    fn only_an_operational_status_of_one_is_up() {
        for status in -3i32..=12 {
            let row = raw_interface(1, &wide("a"), 6, 1, status);
            assert_eq!(row.up, status == 1, "status {status}");
        }
        assert!(!raw_interface(1, &wide("a"), 6, 1, i32::MAX).up);
        assert!(!raw_interface(1, &wide("a"), 6, 1, i32::MIN).up);
    }

    #[test]
    fn hardware_and_up_do_not_depend_on_each_other() {
        let a = raw_interface(1, &wide("a"), 6, 1, 2);
        assert!(a.hardware && !a.up);
        let b = raw_interface(1, &wide("a"), 6, 0, 1);
        assert!(!b.hardware && b.up);
    }

    #[test]
    fn the_row_keeps_the_identity_the_name_and_the_type_it_was_given() {
        let row = raw_interface(0xDEAD_BEEF_0000_0001, &padded("Wi-Fi", 8), 71, 1, 1);
        assert_eq!(row.luid, 0xDEAD_BEEF_0000_0001);
        assert_eq!(row.name, "Wi-Fi");
        assert_eq!(row.if_type, 71);
    }

    #[test]
    fn an_interface_with_an_unknown_type_is_still_a_row() {
        let row = raw_interface(7, &wide("x"), 9999, 1, 1);
        assert_eq!(row.if_type, 9999);
    }

    // ---------------------------------------------------------------- a route row

    /// The system stores an address in network byte order: 192.168.1.1 is the bytes c0 a8 01 01, which a
    /// little-endian machine reads as the number 0x0101a8c0.
    fn network_order(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_ne_bytes([a, b, c, d])
    }

    #[test]
    fn a_default_route_with_a_gateway_is_kept_with_that_gateway() {
        let route = raw_default_route(0, 0, network_order(192, 168, 1, 1), 5, 25).unwrap();
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.luid, 5);
        assert_eq!(route.metric, 25);
    }

    #[test]
    fn a_default_route_with_no_next_hop_is_on_link_and_has_no_gateway() {
        let route = raw_default_route(0, 0, 0, 5, 25).unwrap();
        assert_eq!(route.gateway, None);
    }

    #[test]
    fn any_nonzero_prefix_length_is_not_a_default_route() {
        for length in 1u8..=255 {
            assert!(
                raw_default_route(length, 0, network_order(10, 0, 0, 1), 1, 1).is_none(),
                "/{length}"
            );
        }
    }

    #[test]
    fn any_nonzero_destination_is_not_a_default_route_even_with_a_zero_length() {
        for destination in [1u32, 0x0100_0000, 0x0000_0100, 0xFFFF_FFFF, 0x7F00_0001] {
            assert!(
                raw_default_route(0, destination, network_order(10, 0, 0, 1), 1, 1).is_none(),
                "{destination:#x}"
            );
        }
    }

    #[test]
    fn each_octet_of_the_gateway_comes_out_in_its_own_place() {
        for (a, b, c, d) in [
            (1, 2, 3, 4),
            (10, 0, 0, 1),
            (172, 16, 254, 1),
            (255, 255, 255, 254),
            (0, 0, 0, 1),
            (1, 0, 0, 0),
        ] {
            let route = raw_default_route(0, 0, network_order(a, b, c, d), 1, 1).unwrap();
            assert_eq!(
                route.gateway,
                Some(Ipv4Addr::new(a, b, c, d)),
                "{a}.{b}.{c}.{d}"
            );
        }
    }

    #[test]
    fn the_metric_is_the_routes_own_whatever_its_size() {
        for metric in [0u32, 1, 25, 5000, u32::MAX] {
            let route = raw_default_route(0, 0, 0, 1, metric).unwrap();
            assert_eq!(route.metric, metric);
        }
    }

    #[test]
    fn the_route_belongs_to_the_interface_it_names() {
        let route = raw_default_route(0, 0, 0, u64::MAX, 1).unwrap();
        assert_eq!(route.luid, u64::MAX);
    }

    // ---------------------------------------------------------------- what the decoders feed

    /// The whole chain on a laptop's plain situation: Wi-Fi up with a default route, Ethernet down.
    #[test]
    fn decoded_rows_become_one_usable_path_and_one_unusable() {
        let interfaces = [
            raw_interface(1, &padded("Wi-Fi", 257), 71, 1, 1),
            raw_interface(2, &padded("Ethernet", 257), 6, 1, 2),
        ];
        let routes: Vec<RawDefaultRoute> = [
            raw_default_route(0, 0, network_order(192, 168, 1, 1), 1, 50),
            raw_default_route(24, network_order(192, 168, 1, 0), 0, 1, 281),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert_eq!(routes.len(), 1, "the /24 is not a default route");
        let paths = project(&interfaces, &routes);
        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.role != PathRole::Unusable)
                .count(),
            1
        );
    }
}

#[cfg(all(test, windows))]
mod current_tests {
    use super::*;

    /// The machine's paths are the projection of the interface and route tables, nothing added or dropped.
    #[test]
    fn the_current_paths_are_the_projection_of_the_tables_the_system_reports() {
        let (interfaces, routes) = read().unwrap();
        let expected = project(&interfaces, &routes);
        let actual = current().unwrap();
        // The tables are read twice a moment apart; an interface coming or going in between is the only
        // way these differ, and then the identities of the paths still overlap.
        if actual != expected {
            let ids = |paths: &[NetworkPath]| -> Vec<u64> {
                let mut v: Vec<u64> = paths.iter().map(|p| p.interface_id.luid()).collect();
                v.sort_unstable();
                v
            };
            let (a, e) = (ids(&actual), ids(&expected));
            assert!(
                a.iter().any(|id| e.contains(id)) || a.is_empty() == e.is_empty(),
                "{a:?} vs {e:?}"
            );
        }
    }

    #[test]
    fn reading_the_tables_gives_the_loopback_interface() {
        let (interfaces, _) = read().unwrap();
        assert!(
            interfaces
                .iter()
                .any(|i| i.name.to_ascii_lowercase().contains("loopback")),
            "every machine lists its loopback interface"
        );
    }
}
