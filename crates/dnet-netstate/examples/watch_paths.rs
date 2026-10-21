//! T080 — print the machine's paths now, and again after each change to the network.
//!
//! Read-only: it changes nothing. Run it, then switch Wi-Fi off and on, plug in a cable, or
//! tether a phone, and watch the list follow. Ctrl+C ends it.
//!
//!     cargo run -p dnet-netstate --example watch_paths

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use dnet_netstate::notify::{settled, ChangeSource, LONGEST, QUIET};
    use dnet_netstate::paths;

    fn show(why: &str, paths: &[dnet_core::path::NetworkPath]) {
        println!("--- {why}: {} path(s)", paths.len());
        for p in paths {
            println!(
                "  interface {:>20}  {:<9?} {:<9?} gateway {:<15} preference {}",
                p.interface_id.luid(),
                p.kind,
                p.role,
                p.gateway.map_or("(none)".to_string(), |g| g.to_string()),
                p.preference
            );
        }
    }

    let (_source, mut changes) = ChangeSource::start()?;
    show("now", &paths::current()?);
    println!("watching; change the network, or press Ctrl+C to stop");
    loop {
        tokio::select! {
            burst = settled(&mut changes, QUIET, LONGEST) => {
                let Some(burst) = burst else { break };
                let why = format!(
                    "changed ({} event(s){})",
                    burst.events,
                    if burst.cut_off { ", still changing" } else { "" }
                );
                show(&why, &paths::current()?);
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("watch_paths reads the Windows network and runs on Windows only");
}
