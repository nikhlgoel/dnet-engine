//! AmneziaWG adapter address and route setup.
//!
//! The pinned AmneziaWG core creates its adapter but does not assign it an address or
//! routes (verified: `main_windows.go` only calls `CreateTUN` and `UAPIListen`). The
//! primary core's Profile A outbound binds to that adapter (CC-07), and a bound socket
//! needs a source address on it and a route out of it — so `dnetd` assigns the tunnel
//! address and an on-link default route scoped to the adapter.
//!
//! The adapter route has a deliberately high metric: ordinary traffic keeps preferring
//! the TUN's more-specific routes and the physical default route, and the adapter route
//! is selected only by sockets explicitly bound to the adapter. Both vanish with the
//! adapter when the core exits, so there is nothing to undo separately.

#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{IpDadStatePreferred, MIB_IPPROTO_NETMGMT};

use crate::error::NetstateError;
use crate::win_route::to_sockaddr_inet;

/// Metric for the adapter-scoped default route: high enough that only sockets bound to
/// the adapter ever select it.
pub const ADAPTER_ROUTE_METRIC: u32 = 5000;

/// The LUID of the interface with this alias, or an error if it does not exist (yet).
pub fn interface_luid(alias: &str) -> Result<NET_LUID_LH, NetstateError> {
    // The system reads the alias up to its first NUL, so an alias carrying one would name a different
    // adapter than the text says, and an empty one names none. Neither is looked up.
    if alias.is_empty() || alias.contains('\0') {
        return Err(NetstateError::Operation(format!(
            "interface {alias:?} not found (it is not a usable name)"
        )));
    }
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `luid` is a valid out-ptr.
    let status = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
    if status.is_err() {
        return Err(NetstateError::Operation(format!(
            "interface {alias:?} not found (win32 error {})",
            status.0
        )));
    }
    // SAFETY: reading the `Value` view of the LUID union, which every view shares.
    if unsafe { luid.Value } == 0 {
        // A success that names no interface is not an interface: nothing may be built on it.
        return Err(NetstateError::Operation(format!(
            "interface {alias:?} not found (the system gave no identity for it)"
        )));
    }
    Ok(luid)
}

/// The 64-bit identity of the interface with this alias (its LUID), for code that names an adapter by number.
pub fn interface_luid_value(alias: &str) -> Result<u64, NetstateError> {
    let luid = interface_luid(alias)?;
    // SAFETY: reading the `Value` view of the LUID union, which every view shares.
    Ok(unsafe { luid.Value })
}

/// Assign `address/prefix_len` to the adapter. Already-assigned is success.
pub fn assign_address(alias: &str, address: IpAddr, prefix_len: u8) -> Result<(), NetstateError> {
    let luid = interface_luid(alias)?;
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a valid, writable MIB_UNICASTIPADDRESS_ROW.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.Address = to_sockaddr_inet(address);
    row.OnLinkPrefixLength = prefix_len;
    // Skip duplicate-address detection's tentative phase on a point-to-point tunnel.
    row.DadState = IpDadStatePreferred;
    // SAFETY: `row` is fully initialised above.
    let status = unsafe { CreateUnicastIpAddressEntry(&row) };
    if status.is_ok() || status == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(NetstateError::Operation(format!(
            "assigning the tunnel address failed (win32 error {})",
            status.0
        )))
    }
}

/// Add an on-link default route for the address family, scoped to the adapter.
pub fn add_adapter_default_route(alias: &str, ipv4: bool) -> Result<(), NetstateError> {
    let luid = interface_luid(alias)?;
    let unspecified = if ipv4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(unspecified);
    row.DestinationPrefix.PrefixLength = 0;
    // On-link: the next hop is the unspecified address.
    row.NextHop = to_sockaddr_inet(unspecified);
    row.Metric = ADAPTER_ROUTE_METRIC;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    // SAFETY: `row` is fully initialised above.
    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status.is_ok() || status == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(NetstateError::Operation(format!(
            "adding the adapter route failed (win32 error {})",
            status.0
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_interface_is_a_clear_error_not_a_panic() {
        match interface_luid("dnet-no-such-adapter-7f3a") {
            Err(err) => assert!(err.to_string().contains("not found")),
            Ok(_) => panic!("a nonexistent adapter must not resolve"),
        }
    }

    #[test]
    fn the_loopback_interface_resolves() {
        // Every Windows install has this alias; unprivileged and read-only.
        assert!(interface_luid("Loopback Pseudo-Interface 1").is_ok());
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    const LOOPBACK: &str = "Loopback Pseudo-Interface 1";

    /// The error text for an alias that must not resolve (the identity type has no `Debug`).
    fn refusal(alias: &str) -> String {
        match interface_luid(alias) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("{alias:?} must not resolve"),
        }
    }

    fn luid_value(luid: NET_LUID_LH) -> u64 {
        // SAFETY: reading the `Value` view of the LUID union, which every view shares.
        unsafe { luid.Value }
    }

    /// The Windows call reads the alias up to the first NUL, so an alias carrying one would name a
    /// different adapter than the text says. It is refused instead.
    #[test]
    fn an_alias_with_a_nul_in_it_does_not_resolve_to_the_part_before_it() {
        let smuggled = format!("{LOOPBACK}\0anything");
        let error = refusal(&smuggled);
        assert!(error.contains("not found"), "{error}");
    }

    #[test]
    fn a_nul_at_the_start_is_refused_too() {
        assert!(interface_luid("\0").is_err());
        assert!(interface_luid(&format!("\0{LOOPBACK}")).is_err());
    }

    #[test]
    fn an_empty_alias_is_an_error() {
        assert!(interface_luid("").is_err());
    }

    #[test]
    fn a_very_long_alias_is_an_error_not_a_crash() {
        assert!(interface_luid(&"a".repeat(10_000)).is_err());
        assert!(interface_luid(&"é".repeat(5_000)).is_err());
    }

    #[test]
    fn aliases_in_other_scripts_that_do_not_exist_are_errors() {
        for alias in ["Ethernet 🛰", "واي فاي", "无线网络", "ᚠᚢᚦ", "\u{202e}Wi-Fi"]
        {
            assert!(interface_luid(alias).is_err(), "{alias:?}");
        }
    }

    #[test]
    fn the_error_names_the_alias_so_it_can_be_found_in_a_log() {
        let error = refusal("dnet-no-such-adapter-1c2d");
        assert!(error.contains("dnet-no-such-adapter-1c2d"), "{error}");
        assert!(error.contains("win32 error"), "{error}");
    }

    #[test]
    fn a_hostile_alias_is_shown_escaped_in_the_error() {
        let error = refusal("bad\nname\u{1b}[31m");
        assert!(!error.contains('\n'), "{error:?}");
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }

    #[test]
    fn the_same_adapter_gives_the_same_identity_every_time() {
        let first = luid_value(interface_luid(LOOPBACK).unwrap());
        let second = luid_value(interface_luid(LOOPBACK).unwrap());
        assert_eq!(first, second);
        assert_ne!(first, 0);
    }

    #[test]
    fn an_alias_is_matched_without_regard_to_case() {
        let exact = luid_value(interface_luid(LOOPBACK).unwrap());
        let lower = luid_value(interface_luid(&LOOPBACK.to_lowercase()).unwrap());
        let upper = luid_value(interface_luid(&LOOPBACK.to_uppercase()).unwrap());
        assert_eq!(exact, lower);
        assert_eq!(exact, upper);
    }

    #[test]
    fn an_alias_with_extra_spaces_is_a_different_alias() {
        assert!(interface_luid(&format!(" {LOOPBACK}")).is_err());
        assert!(interface_luid(&format!("{LOOPBACK} ")).is_err());
    }

    /// Nothing is changed when the adapter is not there: the lookup fails before any row is built.
    #[test]
    fn assigning_an_address_to_a_missing_adapter_fails_and_names_it() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let error = assign_address("dnet-no-such-adapter-9e8f", address, 32).unwrap_err();
            assert!(error.to_string().contains("not found"), "{error}");
        }
    }

    #[test]
    fn a_default_route_for_a_missing_adapter_fails_for_both_families() {
        for ipv4 in [true, false] {
            let error = add_adapter_default_route("dnet-no-such-adapter-9e8f", ipv4).unwrap_err();
            assert!(
                error.to_string().contains("not found"),
                "ipv4={ipv4}: {error}"
            );
        }
    }

    #[test]
    fn an_address_for_an_alias_with_a_nul_is_refused_before_anything_is_built() {
        let alias = format!("{LOOPBACK}\0x");
        assert!(assign_address(&alias, IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)), 32).is_err());
        assert!(add_adapter_default_route(&alias, true).is_err());
    }

    /// The adapter route must lose to every ordinary route, or it would carry ordinary traffic.
    /// Checked when the program is built: an ordinary route's metric is in the tens, so 1000 or more
    /// can never win against one.
    const _: () = assert!(ADAPTER_ROUTE_METRIC >= 1000);

    #[test]
    fn the_adapter_route_metric_is_the_documented_value() {
        assert_eq!(ADAPTER_ROUTE_METRIC, 5000);
    }
}
