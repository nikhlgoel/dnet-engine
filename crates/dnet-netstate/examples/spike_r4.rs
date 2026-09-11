//! SPIKE-R4 runner (T055): Profile A end-to-end on the **real** OS seams.
//!
//! Drives exactly the production sequence — `start_cores` (reap → AmneziaWG → adapter
//! → primary core) then `bring_up` (host route → peer) — against
//! `WindowsCoreRuntime` and `WindowsTunnelBringup`, pulls bytes through the tunnel, and
//! tears everything down. It is driven by `testing/spike-r4/Invoke-SpikeR4.ps1`, which
//! owns the packet-count measurement and the verdict.
//!
//! Modes:
//! - `pass`    — the production sequence.
//! - `control` — identical, but the endpoint host route is **deliberately withheld**.
//!   This is the negative control: it must produce re-entry, or the measurement cannot
//!   tell a loop from no loop and the spike result is invalid.
//!
//! Checkpoints (file handshakes in the run directory) let the wrapper start packet
//! capture after the adapters exist — capture does not attach to adapters created
//! after it starts — and snapshot counters before teardown removes them.
//!
//! Requires: an elevated Administrator, the two cores staged by the wrapper (with the
//! AmneziaWG core's adapter driver DLL beside it), and a harness endpoint reachable only
//! via the default gateway.

#[cfg(not(windows))]
fn main() {
    eprintln!("spike_r4 runs on Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    win::main()
}

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::net::{IpAddr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use dnet_config::amneziawg::{ObfuscationParams, PeerConfig, PrivateKey};
    use dnet_config::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
    use dnet_config::{write, ActiveEndpointBypass};
    use dnet_core::endpoint::EndpointAddress;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::{ConnectionProfile, CoreBinding, ProfileKind, ProfileParams};
    use dnet_core::rule::builtin_rules;
    use dnet_netstate::host_route::{
        bring_up, on_carrying_path_change, tear_down, HostRoute, TunnelBringup,
    };
    use dnet_netstate::win_bringup::{TunnelSpec, WindowsTunnelBringup};
    use dnet_netstate::win_route::{best_route_to, default_gateway};
    use dnet_netstate::NetstateError;
    use dnet_supervisor::process::CoreCommand;
    use dnet_supervisor::reap::start_cores;
    use dnet_supervisor::shutdown::shutdown_all;
    use dnet_supervisor::windows_runtime::WindowsCoreRuntime;

    const ADAPTER: &str = "dnet-awg0";
    const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(180);

    /// The endpoint container's `awg-client.json`.
    #[derive(Deserialize)]
    struct ClientParams {
        client_private_key_hex: String,
        server_public_key_hex: String,
        client_address: IpAddr,
        prefix_len: u8,
        listen_port: u16,
        origin_url: String,
        obfuscation: Obfuscation,
    }

    #[derive(Deserialize)]
    struct Obfuscation {
        jc: u32,
        jmin: u32,
        jmax: u32,
        s1: u32,
        s2: u32,
        h1: u32,
        h2: u32,
        h3: u32,
        h4: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        Pass,
        Control,
    }

    struct Args {
        params: PathBuf,
        endpoint: IpAddr,
        awg_exe: PathBuf,
        primary_exe: PathBuf,
        run_dir: PathBuf,
        mode: Mode,
        bytes: u64,
        alt_gateway: Option<IpAddr>,
        report: PathBuf,
    }

    #[derive(Serialize, Default)]
    struct Transfer {
        ok: bool,
        bytes: u64,
        seconds: f64,
        mbps: f64,
        error: Option<String>,
    }

    #[derive(Serialize)]
    struct Report {
        mode: Mode,
        endpoint: IpAddr,
        gateway: IpAddr,
        host_route_installed: bool,
        transfer: Transfer,
        path_change: Option<Transfer>,
        teardown_ok: bool,
        error: Option<String>,
    }

    fn parse_args() -> Result<Args> {
        let mut it = std::env::args().skip(1);
        let (mut params, mut endpoint, mut run_dir, mut report) = (None, None, None, None);
        let (mut awg_exe, mut primary_exe) = (None, None);
        let (mut mode, mut bytes, mut alt_gateway) = (Mode::Pass, 20_000_000u64, None);
        while let Some(flag) = it.next() {
            let mut val = || it.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--params" => params = Some(PathBuf::from(val()?)),
                "--endpoint" => {
                    endpoint = Some(val()?.parse().context("--endpoint must be an IP")?)
                }
                "--awg-exe" => awg_exe = Some(PathBuf::from(val()?)),
                "--primary-exe" => primary_exe = Some(PathBuf::from(val()?)),
                "--run-dir" => run_dir = Some(PathBuf::from(val()?)),
                "--report" => report = Some(PathBuf::from(val()?)),
                "--bytes" => bytes = val()?.parse()?,
                "--alt-gateway" => alt_gateway = Some(val()?.parse()?),
                "--mode" => {
                    mode = match val()?.as_str() {
                        "pass" => Mode::Pass,
                        "control" => Mode::Control,
                        other => bail!("unknown mode {other:?}"),
                    }
                }
                other => bail!("unknown argument {other:?}"),
            }
        }
        Ok(Args {
            params: params.context("--params is required")?,
            endpoint: endpoint.context("--endpoint is required")?,
            awg_exe: awg_exe.context("--awg-exe is required")?,
            primary_exe: primary_exe.context("--primary-exe is required")?,
            run_dir: run_dir.context("--run-dir is required")?,
            report: report.context("--report is required")?,
            mode,
            bytes,
            alt_gateway,
        })
    }

    /// Signal the wrapper and wait for it to answer (`<name>.ready` -> `<name>.go`).
    async fn checkpoint(run_dir: &Path, mode: Mode, name: &str) -> Result<()> {
        let tag = serde_json::to_value(mode)?
            .as_str()
            .unwrap_or("run")
            .to_string();
        let ready = run_dir.join(format!("{tag}.{name}.ready"));
        let go = run_dir.join(format!("{tag}.{name}.go"));
        let _ = std::fs::remove_file(&go);
        std::fs::write(&ready, b"")?;
        tracing::info!(checkpoint = name, "waiting for the wrapper");
        let deadline = Instant::now() + CHECKPOINT_TIMEOUT;
        while !go.exists() {
            if Instant::now() > deadline {
                bail!("wrapper never released checkpoint {name}");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// GET `/bytes/<n>` from the origin through whatever route the OS picks (the TUN).
    async fn transfer(origin: &str, bytes: u64) -> Transfer {
        let attempt = async {
            let host = origin.trim_start_matches("http://");
            let addr: SocketAddr = host.parse().context("origin must be http://IP:port")?;
            let started = Instant::now();
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            let request = format!("GET /bytes/{bytes} HTTP/1.0\r\nHost: {host}\r\n\r\n");
            stream.write_all(request.as_bytes()).await?;
            let mut buf = Vec::with_capacity(bytes as usize + 512);
            stream.read_to_end(&mut buf).await?;
            let body = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| buf.len() - i - 4)
                .unwrap_or(0) as u64;
            let seconds = started.elapsed().as_secs_f64();
            anyhow::Ok(Transfer {
                ok: body == bytes,
                bytes: body,
                seconds,
                mbps: (body as f64 * 8.0) / seconds.max(1e-9) / 1_000_000.0,
                error: (body != bytes).then(|| format!("short body: {body} of {bytes}")),
            })
        };
        // A loop presents as a completed handshake with zero throughput, so a stalled
        // transfer is a result, not a hang.
        match tokio::time::timeout(Duration::from_secs(90), attempt).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => Transfer {
                error: Some(e.to_string()),
                ..Transfer::default()
            },
            Err(_) => Transfer {
                error: Some("transfer stalled for 90s".into()),
                ..Transfer::default()
            },
        }
    }

    /// Retry the first transfer while the handshake completes.
    async fn transfer_after_handshake(origin: &str, bytes: u64) -> Transfer {
        let mut last = Transfer::default();
        for _ in 0..5 {
            last = transfer(origin, bytes).await;
            if last.ok {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        last
    }

    /// The negative control: every operation is real except the host route, which is
    /// withheld. This is the configuration that must loop.
    struct WithheldHostRoute<'a>(&'a WindowsTunnelBringup);

    impl TunnelBringup for WithheldHostRoute<'_> {
        async fn install_host_route(&self, _route: &HostRoute) -> Result<(), NetstateError> {
            tracing::warn!("CONTROL: endpoint host route deliberately withheld");
            Ok(())
        }
        async fn remove_host_route(&self, _route: &HostRoute) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn rewrite_host_route(
            &self,
            _: &HostRoute,
            _: &HostRoute,
        ) -> Result<(), NetstateError> {
            Ok(())
        }
        async fn start_tunnel(&self) -> Result<(), NetstateError> {
            self.0.start_tunnel().await
        }
        async fn stop_tunnel(&self) -> Result<(), NetstateError> {
            self.0.stop_tunnel().await
        }
        async fn rebind_tunnel(&self, gateway: IpAddr) -> Result<(), NetstateError> {
            self.0.rebind_tunnel(gateway).await
        }
    }

    async fn run(args: &Args) -> Result<Report> {
        // Preflight: the spike is only meaningful if the endpoint is reached through the
        // default gateway. Loopback or on-link endpoints never enter the TUN, so they would
        // pass vacuously.
        let gateway = default_gateway().context("reading the physical default gateway")?;
        let to_endpoint = best_route_to(args.endpoint)?;
        if to_endpoint.prefix_len != 0 || to_endpoint.next_hop != Some(gateway) {
            bail!(
                "VACUOUS TOPOLOGY: {} is not reached via the default gateway {gateway} \
                 (matched /{} next hop {:?}); a loop cannot form, so R4 cannot be tested",
                args.endpoint,
                to_endpoint.prefix_len,
                to_endpoint.next_hop
            );
        }

        let params: ClientParams = serde_json::from_slice(
            &std::fs::read(&args.params)
                .with_context(|| format!("reading {}", args.params.display()))?,
        )?;
        // Staged by the wrapper into private per-run directories: orphan reaping matches
        // these exact paths, so a spike never touches cores belonging to anything else.
        let (awg_exe, primary_exe) = (args.awg_exe.clone(), args.primary_exe.clone());
        for exe in [&awg_exe, &primary_exe] {
            if !exe.is_file() {
                bail!("staged core missing: {}", exe.display());
            }
        }

        // The endpoint is an IP literal everywhere: host route, config bypass, and UAPI.
        let endpoint_addr = EndpointAddress::new(args.endpoint.to_string(), params.listen_port)?;
        let bypass = ActiveEndpointBypass::new(&endpoint_addr);
        let rules = builtin_rules(Some(&endpoint_addr));
        let profile = ConnectionProfile::new(
            ProfileId::new("spike-r4"),
            ProfileKind::AmneziaWg,
            ProfileParams::new(),
        );
        let config = generate_primary_core_config(PrimaryCoreInput {
            active_profile: &profile,
            endpoint_bypass: &bypass,
            rules: &rules,
            amneziawg_adapter: Some(ADAPTER),
        })?;
        let config_path = write::write_restricted(
            &args.run_dir.join("config"),
            "primary-core.json",
            to_json(&config).as_bytes(),
        )
        .context("writing the restricted primary-core config")?;

        let runtime = WindowsCoreRuntime::new(
            CoreCommand {
                core: CoreBinding::PrimaryCore,
                program: primary_exe.clone(),
                args: vec![
                    OsString::from("run"),
                    OsString::from("-c"),
                    config_path.into_os_string(),
                    OsString::from("-D"),
                    args.run_dir.join("primary").into_os_string(),
                    OsString::from("--disable-color"),
                ],
                working_dir: Some(args.run_dir.join("primary")),
                ready_marker: Some("started".into()),
                ready_timeout: Duration::from_secs(30),
            },
            CoreCommand {
                core: CoreBinding::AmneziaWgCore,
                program: awg_exe.clone(),
                args: vec![OsString::from(ADAPTER)],
                working_dir: awg_exe.parent().map(Path::to_path_buf),
                ready_marker: None, // readiness = the UAPI pipe appearing
                ready_timeout: Duration::from_secs(5),
            },
            ADAPTER,
            Duration::from_secs(30),
            // Routes are removed by tear_down and the adapter's own address and route
            // vanish with it, so there is nothing further to restore in the spike.
            Box::new(|| Ok(())),
        );

        let tunnel = WindowsTunnelBringup::new(TunnelSpec {
            adapter: ADAPTER.into(),
            address: params.client_address,
            prefix_len: params.prefix_len,
            private_key: PrivateKey::new(params.client_private_key_hex),
            obfuscation: ObfuscationParams {
                jc: params.obfuscation.jc,
                jmin: params.obfuscation.jmin,
                jmax: params.obfuscation.jmax,
                s1: params.obfuscation.s1,
                s2: params.obfuscation.s2,
                h1: params.obfuscation.h1,
                h2: params.obfuscation.h2,
                h3: params.obfuscation.h3,
                h4: params.obfuscation.h4,
            },
            peer: PeerConfig {
                public_key: params.server_public_key_hex,
                endpoint: SocketAddr::new(args.endpoint, params.listen_port).to_string(),
                allowed_ips: vec!["0.0.0.0/0".into()],
                persistent_keepalive: Some(25),
            },
        });
        let route = HostRoute::for_endpoint(&bypass, gateway);

        let mut report = Report {
            mode: args.mode,
            endpoint: args.endpoint,
            gateway,
            host_route_installed: false,
            transfer: Transfer::default(),
            path_change: None,
            teardown_ok: false,
            error: None,
        };

        let outcome = async {
            start_cores(&runtime).await?;
            // Adapters now exist and no peer is configured: nothing flows yet.
            checkpoint(&args.run_dir, args.mode, "cores-up").await?;

            match args.mode {
                Mode::Pass => bring_up(&tunnel, &route).await?,
                Mode::Control => bring_up(&WithheldHostRoute(&tunnel), &route).await?,
            }
            report.host_route_installed = tunnel.routes().owns(&route);
            report.transfer = transfer_after_handshake(&params.origin_url, args.bytes).await;

            if let (Mode::Pass, Some(alt)) = (args.mode, args.alt_gateway) {
                on_carrying_path_change(&tunnel, &route, alt).await?;
                report.path_change =
                    Some(transfer_after_handshake(&params.origin_url, args.bytes).await);
            }
            checkpoint(&args.run_dir, args.mode, "measured").await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = &outcome {
            report.error = Some(format!("{e:#}"));
        }

        // Teardown always runs: peer, host route(s), then both cores.
        let current_route = match (args.mode, args.alt_gateway, &report.path_change) {
            (Mode::Pass, Some(alt), Some(_)) => route.via(alt),
            _ => route.clone(),
        };
        let tunnel_down = match args.mode {
            Mode::Pass => tear_down(&tunnel, &current_route).await,
            Mode::Control => tear_down(&WithheldHostRoute(&tunnel), &current_route).await,
        };
        // Defensive: whichever gateway was current, remove anything this run still owns.
        let _ = tunnel.routes().remove(&route);
        let cores_down = shutdown_all(&runtime).await;
        report.teardown_ok =
            tunnel_down.is_ok() && cores_down.is_ok() && !tunnel.routes().owns(&route);
        if let Err(e) = tunnel_down {
            tracing::error!(error = %e, "tunnel teardown failed");
        }
        if let Err(e) = cores_down {
            tracing::error!(error = %e, "core shutdown failed");
        }
        Ok(report)
    }

    pub fn main() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_writer(std::io::stderr)
            .init();
        let args = parse_args()?;
        std::fs::create_dir_all(&args.run_dir)?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(run(&args))?;
        std::fs::write(&args.report, serde_json::to_vec_pretty(&report)?)?;
        println!("{}", serde_json::to_string(&report)?);
        Ok(())
    }
}
