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
    Ok(luid)
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
