//! T134, T136 — measure each usable network path: the first hop, and optionally your own endpoint.
//!
//! Read-only. For every usable physical adapter it sends one echo to that adapter's gateway, and,
//! if you give an address, times one TCP connection to it pinned to leave through that adapter.
//! Use an endpoint you control. Nothing is chosen for you.
//!
//!     cargo run -p dnet-netstate --example probe_path
//!     cargo run -p dnet-netstate --example probe_path -- 198.51.100.7:443

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use std::net::{IpAddr, SocketAddrV4};
    use std::time::Duration;

    use dnet_core::path::PathRole;
    use dnet_core::probe_plan::Observation;
    use dnet_core::quality::PathSample;
    use dnet_netstate::{echo, paths, probe};

    let target: Option<SocketAddrV4> = match std::env::args().nth(1) {
        None => None,
        Some(arg) => Some(arg.parse().map_err(|_| {
            anyhow::anyhow!("'{arg}' is not an IPv4 address and port, like 198.51.100.7:443")
        })?),
    };

    let paths = paths::current()?;
    if paths.is_empty() {
        println!("no physical network adapters found");
    }
    for path in &paths {
        let name = format!("{:?} (interface {})", path.kind, path.interface_id.luid());
        if path.role == PathRole::Unusable {
            println!("{name}: not usable, not probed");
            continue;
        }
        match path.gateway {
            Some(IpAddr::V4(gateway)) => {
                match echo::echo_gateway(gateway, Duration::from_secs(2)).await {
                    Ok(Observation::Answered(rtt)) => {
                        println!(
                            "{name}: gateway {gateway} answered in {} ms",
                            rtt.as_millis()
                        );
                    }
                    Ok(Observation::Silent) => println!(
                        "{name}: gateway {gateway} did not answer (many gateways ignore echoes)"
                    ),
                    Err(e) => println!("{name}: could not echo the gateway ({e})"),
                }
            }
            _ => println!("{name}: no gateway to echo"),
        }
        if let Some(target) = target {
            match probe::probe_tcp(path.interface_id.luid(), target, probe::CONNECT_TIMEOUT).await {
                Ok(PathSample::Answered { rtt }) => {
                    println!("{name}: {target} answered in {} ms", rtt.as_millis());
                }
                Ok(PathSample::Lost) => println!("{name}: {target} gave no answer"),
                Err(e) => println!("{name}: could not probe {target} ({e})"),
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_path reads the Windows network and runs on Windows only");
}
