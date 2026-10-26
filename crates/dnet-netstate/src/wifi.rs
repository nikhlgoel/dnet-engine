//! T144 — the name of the Wi-Fi network each wireless adapter is connected to.
//!
//! The rest of `dnet-netstate` knows adapters (by LUID), not networks: an adapter is a way out, and
//! which access point it is joined to is a separate fact that only the system's WLAN service holds.
//! The interface shows "Hostel-5G", not "interface 12884901888", so this asks the WLAN service.
//!
//! - **Read-only and local.** It queries the machine's own state. Nothing is sent anywhere and no
//!   privilege is needed.
//! - **The name is untrusted text.** Whoever runs the access point chose it; it may hold control or
//!   direction-changing characters, invalid UTF-8, or anything at all within 32 bytes. This module
//!   turns the bytes into text (lossily) and nothing more: removing what must not reach a screen is
//!   done where the name is sent, so there is one rule for it (`dnet_ipc::netview::clean_name`).
//! - **A name can reveal where a person is.** It is shown only in the local window, and the
//!   diagnostics bundle leaves it out by default (T112).
//! - **Windows 11 may refuse.** Recent builds answer "access denied" to this query until the user
//!   turns on location access for desktop apps (Settings, Privacy & security, Location), because a
//!   network name can reveal where they are. That is the user's choice and is not worked around: the
//!   answer is "no names", and the interface shows the network by its kind. Whether the service
//!   (which runs as SYSTEM, in no user session) is refused too is to be seen on a real machine.
//! - **Any failure is "no names".** No Wi-Fi adapter, a service that is not running, a refusal: the
//!   answer is an empty map, and the interface shows the network by its kind instead. A name that
//!   could not be read must never stop the connection being watched.

use std::collections::HashMap;

use dnet_core::ids::InterfaceId;

/// The most bytes an SSID can have (IEEE 802.11).
pub const MAX_SSID_BYTES: usize = 32;

/// Turn the SSID the system reports into text: the first `len` bytes (never more than
/// [`MAX_SSID_BYTES`], never more than were given), decoded as UTF-8 with anything invalid replaced.
/// `None` for an empty name: a hidden network has none to show.
pub fn ssid_text(bytes: &[u8], len: usize) -> Option<String> {
    let len = len.min(MAX_SSID_BYTES).min(bytes.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

/// The Wi-Fi network each connected wireless adapter is on, by adapter. Empty when there is none, or
/// when the system would not say.
pub fn connected_networks() -> HashMap<InterfaceId, String> {
    #[cfg(windows)]
    {
        windows_impl::connected_networks()
    }
    #[cfg(not(windows))]
    {
        HashMap::new()
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::collections::HashMap;
    use std::ffi::c_void;

    use dnet_core::ids::InterfaceId;
    use windows::Win32::Foundation::{HANDLE, NO_ERROR, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceGuidToLuid;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::NetworkManagement::WiFi::{
        wlan_interface_state_connected, wlan_intf_opcode_current_connection, WlanCloseHandle,
        WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface,
        WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
    };

    use super::ssid_text;

    /// The WLAN client version that exists on every Windows from Vista on.
    const CLIENT_VERSION: u32 = 2;

    /// Closes the WLAN handle, and frees what the service allocated, whatever happens in between.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `WlanOpenHandle` and is closed once.
            unsafe {
                let _ = WlanCloseHandle(self.0, None);
            }
        }
    }

    /// Memory the WLAN service allocated for us, freed on drop.
    struct Allocation(*mut c_void);

    impl Drop for Allocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the WLAN service and freed exactly once, with its own free.
                unsafe { WlanFreeMemory(self.0) };
            }
        }
    }

    pub fn connected_networks() -> HashMap<InterfaceId, String> {
        read().unwrap_or_default()
    }

    fn read() -> Option<HashMap<InterfaceId, String>> {
        let mut negotiated = 0u32;
        let mut raw = HANDLE::default();
        // SAFETY: both out-pointers are valid for the call; the handle is closed by `Handle`.
        let status = unsafe { WlanOpenHandle(CLIENT_VERSION, None, &mut negotiated, &mut raw) };
        if WIN32_ERROR(status) != NO_ERROR {
            return None; // no WLAN service: no Wi-Fi to name
        }
        let client = Handle(raw);

        let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        // SAFETY: a valid handle and out-pointer; the list is freed by `Allocation`.
        let status = unsafe { WlanEnumInterfaces(client.0, None, &mut list) };
        let list_guard = Allocation(list.cast());
        if WIN32_ERROR(status) != NO_ERROR || list.is_null() {
            return None;
        }

        let mut names = HashMap::new();
        // SAFETY: the list is valid until `list_guard` drops, and `dwNumberOfItems` entries follow
        // its header; the slice is built from exactly that.
        let interfaces = unsafe {
            std::slice::from_raw_parts(
                (*list).InterfaceInfo.as_ptr(),
                (*list).dwNumberOfItems as usize,
            )
        };
        for interface in interfaces {
            if interface.isState != wlan_interface_state_connected {
                continue;
            }
            let mut size = 0u32;
            let mut data: *mut c_void = std::ptr::null_mut();
            // SAFETY: valid handle, a GUID that came from the enumeration, and out-pointers; the
            // data is freed by `Allocation`.
            let status = unsafe {
                WlanQueryInterface(
                    client.0,
                    &interface.InterfaceGuid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut size,
                    &mut data,
                    None,
                )
            };
            let data_guard = Allocation(data);
            if WIN32_ERROR(status) != NO_ERROR
                || data.is_null()
                || (size as usize) < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>()
            {
                // Windows 11 answers "access denied" (5) until the user allows location access,
                // because a network name can reveal where they are. That is theirs to decide, so it
                // is not worked around: the interface shows the network by its kind instead.
                tracing::debug!(code = status, "the system would not name the Wi-Fi network");
                continue;
            }
            // SAFETY: the service returned at least the size of the attributes, and it stays valid
            // until `data_guard` drops.
            let attributes = unsafe { &*(data as *const WLAN_CONNECTION_ATTRIBUTES) };
            let ssid = &attributes.wlanAssociationAttributes.dot11Ssid;
            let Some(name) = ssid_text(&ssid.ucSSID, ssid.uSSIDLength as usize) else {
                drop(data_guard);
                continue;
            };
            drop(data_guard);

            let mut luid = NET_LUID_LH::default();
            // SAFETY: a GUID from the enumeration and a valid out-pointer.
            let status = unsafe { ConvertInterfaceGuidToLuid(&interface.InterfaceGuid, &mut luid) };
            if status != NO_ERROR {
                continue;
            }
            // SAFETY: reading the `Value` view of the LUID union, which every view shares.
            let value = unsafe { luid.Value };
            names.insert(InterfaceId::new(value), name);
        }
        drop(list_guard);
        Some(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(name: &[u8]) -> [u8; MAX_SSID_BYTES] {
        let mut out = [0u8; MAX_SSID_BYTES];
        out[..name.len()].copy_from_slice(name);
        out
    }

    #[test]
    fn a_name_is_the_bytes_the_system_says_it_has() {
        let raw = padded(b"Hostel-5G");
        assert_eq!(ssid_text(&raw, 9).as_deref(), Some("Hostel-5G"));
    }

    #[test]
    fn the_padding_after_the_length_is_not_part_of_the_name() {
        let mut raw = padded(b"Cafe");
        raw[10] = b'X'; // garbage beyond the length the system gave
        assert_eq!(ssid_text(&raw, 4).as_deref(), Some("Cafe"));
    }

    #[test]
    fn a_hidden_network_has_no_name() {
        assert_eq!(ssid_text(&padded(b""), 0), None);
    }

    #[test]
    fn a_length_longer_than_the_data_or_the_standard_never_reads_past_either() {
        let raw = padded(b"abc");
        assert_eq!(ssid_text(&raw, 1000).map(|s| s.len()), Some(MAX_SSID_BYTES));
        assert_eq!(ssid_text(b"ab", 1000).as_deref(), Some("ab"));
        assert_eq!(ssid_text(&[], 5), None);
    }

    #[test]
    fn a_name_is_never_longer_than_the_standard_allows_whatever_the_buffer() {
        // A buffer longer than an SSID can be, with a length that claims all of it: the standard's
        // limit holds, not the caller's claim.
        let long = [b'a'; 64];
        assert_eq!(ssid_text(&long, 64).map(|s| s.len()), Some(MAX_SSID_BYTES));
    }

    #[test]
    fn bytes_that_are_not_text_are_replaced_not_trusted() {
        let raw = padded(&[b'A', 0xff, 0xfe, b'B']);
        let name = ssid_text(&raw, 4).unwrap();
        assert!(name.starts_with('A') && name.ends_with('B'));
        assert!(name.contains('\u{fffd}'));
    }

    #[test]
    fn a_name_with_control_characters_is_returned_as_is_for_the_sender_to_clean() {
        // One rule for what may reach a screen lives where names are sent (`netview::clean_name`).
        let raw = padded(b"a\x1b[31mb");
        assert_eq!(ssid_text(&raw, 7).as_deref(), Some("a\u{1b}[31mb"));
    }

    #[test]
    fn asking_the_system_never_fails_the_caller() {
        // Whatever this machine has (Wi-Fi, none, a stopped WLAN service), the answer is a map, and
        // every name in it is for an adapter id the system gave.
        let names = connected_networks();
        for (id, name) in &names {
            assert!(id.luid() != 0);
            assert!(name.chars().count() <= MAX_SSID_BYTES);
        }
    }
}
