// SPDX-License-Identifier: GPL-3.0-or-later
//! T165 — prints what the system says each network adapter costs: metered, near its limit, roaming. Read-only.
//!
//!     cargo run -p dnet-netstate --example link_costs

#[cfg(not(windows))]
fn main() {
    eprintln!("link_costs runs on Windows only");
}

#[cfg(windows)]
fn main() {
    use dnet_netstate::cost::link_facts_for_index;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 0u32;
    // SAFETY: the first call only asks how much room is needed.
    unsafe { GetAdaptersAddresses(0, flags, None, None, &mut size) };
    let mut buffer = vec![0u8; size as usize];
    let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: `buffer` has the size the first call asked for and outlives the walk below.
    let status = unsafe { GetAdaptersAddresses(0, flags, None, Some(first), &mut size) };
    if status != 0 {
        eprintln!("the adapter list could not be read ({status})");
        return;
    }
    let mut at = first;
    while !at.is_null() {
        // SAFETY: a node of the list the system just wrote into `buffer`.
        let adapter = unsafe { &*at };
        let name = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        let facts = link_facts_for_index(unsafe { adapter.Anonymous1.Anonymous.IfIndex });
        println!("{name:<34} {facts:?} metered={}", facts.is_metered());
        at = adapter.Next;
    }
}
