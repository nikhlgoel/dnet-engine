//! T144 — print the Wi-Fi network each wireless adapter is connected to, as the service would.
//!
//! Read-only and local: it asks the system's WLAN service and prints the answer, one adapter per
//! line (`<adapter id>  <name>`). No privilege is needed and nothing is sent anywhere. A name can
//! reveal where you are, so treat the output as personal.
//!
//! ```text
//! cargo run -p dnet-netstate --example wifi_names
//! ```

fn main() {
    // The link facts (T165) need no name: they are printed even when the system will not say the name.
    let mut links: Vec<_> = dnet_netstate::wifi::connected_links().into_iter().collect();
    links.sort_by_key(|(id, _)| id.luid());
    for (id, facts) in links {
        println!(
            "{}  {}  receive {:?} Mbit/s, transmit {:?} Mbit/s, signal {:?}%",
            id.luid(),
            facts.generation.label(),
            facts.receive_mbps,
            facts.transmit_mbps,
            facts.signal_percent
        );
    }
    let names = dnet_netstate::wifi::connected_networks();
    if names.is_empty() {
        println!("no connected Wi-Fi network was reported (no Wi-Fi adapter, or not connected)");
        return;
    }
    let mut rows: Vec<_> = names.into_iter().collect();
    rows.sort_by_key(|(id, _)| id.luid());
    for (id, name) in rows {
        println!("{}  {}", id.luid(), name);
    }
}
