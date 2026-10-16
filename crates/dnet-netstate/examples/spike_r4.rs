//! SPIKE-R4 runner (T055): one profile end-to-end on the **real** OS seams.
//!
//! Profiles (`--profile`):
//! - `a` (default) — AmneziaWG. Drives exactly the production sequence: `start_cores`
//!   (reap → AmneziaWG → adapter → primary core) then `bring_up` (host route → peer).
//! - `hy2` — Hysteria 2. The primary core alone: `start_cores` starts no AmneziaWG core, there
//!   is no host route, and the loop guard is the core's own `auto_detect_interface`.
//!
//! Either way it runs against `WindowsCoreRuntime`, pulls bytes through the tunnel, and tears
//! everything down. It is driven by `testing/spike-r4/Invoke-SpikeR4.ps1`, which owns the
//! packet-count measurement and the verdict.
//!
//! Modes:
//! - `pass`    — the production sequence.
//! - `control` — identical, but the loop guard is **deliberately withheld**: the endpoint host
//!   route for `a`, `auto_detect_interface` for `hy2`. This is the negative control: it must
//!   produce re-entry, or the measurement cannot tell a loop from no loop and the spike
//!   result is invalid.
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

/// The parts of the runner with no OS dependency, so they build and are unit-tested anywhere.
// Off Windows only the tests use them (the runner itself is Windows-only), which would otherwise
// trip `-D warnings` on a Linux host.
#[cfg_attr(not(windows), allow(dead_code))]
mod pure {
    use std::net::IpAddr;

    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    use dnet_config::hysteria2::{
        Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs,
        Hysteria2Settings, Hysteria2Transport,
    };
    use dnet_config::primary::{
        generate_primary_core_config, to_json, PrimaryCoreInput, PrimaryTransport,
    };
    use dnet_config::secret::Secret;
    use dnet_config::tls::ServerTrust;
    use dnet_config::ActiveEndpointBypass;
    use dnet_core::builtin_rules::builtin_rules;
    use dnet_core::endpoint::EndpointAddress;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};

    /// Which transport a run exercises.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ProfileArg {
        /// AmneziaWG: two cores, an adapter of its own, and the endpoint host route.
        A,
        /// Hysteria 2: the primary core alone, guarded by `auto_detect_interface`.
        Hy2,
    }

    pub fn parse_profile(value: &str) -> Result<ProfileArg> {
        match value {
            "a" => Ok(ProfileArg::A),
            "hy2" => Ok(ProfileArg::Hy2),
            other => bail!("unknown profile {other:?}; expected `a` or `hy2`"),
        }
    }

    /// The endpoint container's `hy2-client.json`. Test keys only. Unknown fields are refused,
    /// so a change on the server side cannot be silently ignored here.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Hy2Params {
        pub server_port: u16,
        pub server_name: String,
        /// SHA-256 of the server certificate's DER SubjectPublicKeyInfo, as 64 hex characters.
        pub spki_sha256_hex: String,
        pub auth_password: String,
        pub obfs_password: String,
        pub origin_url: String,
    }

    impl Hy2Params {
        pub fn parse(bytes: &[u8]) -> Result<Self> {
            serde_json::from_slice(bytes).context("reading the Hysteria 2 client parameters")
        }

        pub fn spki_sha256(&self) -> Result<[u8; 32]> {
            let hex = self.spki_sha256_hex.as_str();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("spki_sha256_hex must be exactly 64 hex characters");
            }
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
            }
            Ok(out)
        }
    }

    /// The negative control for Hysteria 2. Takes the **production** configuration and removes
    /// the loop guard under test, so that the control is the pass configuration minus one thing
    /// and nothing else. It must loop; if it does not, the measurement cannot see loops and
    /// the spike is INVALID.
    ///
    /// Only `route.auto_detect_interface` is turned off, and written as an explicit `false`
    /// even if the field was absent. The endpoint bypass rule is left alone: it catches traffic
    /// other applications send to the endpoint, not the core's own sockets, so removing it
    /// would confound the result rather than test the guard.
    pub fn withhold_loop_guard(config: &mut Value) {
        config["route"]["auto_detect_interface"] = Value::Bool(false);
    }

    /// The primary-core configuration for a Hysteria 2 run, as JSON. `control` withholds the
    /// loop guard via [`withhold_loop_guard`].
    pub fn hy2_primary_config(
        endpoint: IpAddr,
        params: &Hy2Params,
        control: bool,
    ) -> Result<String> {
        let address = EndpointAddress::new(endpoint.to_string(), params.server_port)?;
        let bypass = ActiveEndpointBypass::new(&address);
        let rules = builtin_rules(Some(&address));
        let transport = Hysteria2Transport {
            settings: Hysteria2Settings {
                client: Hysteria2ClientParams::default(),
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: params.server_name.clone(),
                        spki_sha256: params.spki_sha256()?,
                    },
                },
            },
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(params.auth_password.clone()),
                obfs_password: Secret::new(params.obfs_password.clone()),
            },
        };
        let profile = ConnectionProfile::new(
            ProfileId::new("spike-r4-hy2"),
            ProfileKind::Hysteria2,
            ProfileParams::new(),
        );
        let config = generate_primary_core_config(PrimaryCoreInput {
            active_profile: &profile,
            endpoint_bypass: &bypass,
            rules: &rules,
            amneziawg_adapter: None,
            primary_transport: Some(PrimaryTransport::Hysteria2(&transport)),
        })?;
        let mut value: Value = serde_json::from_str(&to_json(&config))?;
        if control {
            withhold_loop_guard(&mut value);
        }
        Ok(serde_json::to_string_pretty(&value)?)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use serde_json::{json, Value};

    use super::pure::*;

    /// TEST-NET-2: never routable, so it cannot collide with a real endpoint.
    const ENDPOINT: &str = "198.51.100.7";

    const PARAMS: &str = r#"{
        "server_port": 44443,
        "server_name": "hy2.harness.test",
        "spki_sha256_hex": "0707070707070707070707070707070707070707070707070707070707070707",
        "auth_password": "test-only-auth",
        "obfs_password": "test-only-obfs",
        "origin_url": "http://203.0.113.80:8080"
    }"#;

    fn params() -> Hy2Params {
        Hy2Params::parse(PARAMS.as_bytes()).expect("the sample parameters are valid")
    }

    fn config(control: bool) -> Value {
        let endpoint: IpAddr = ENDPOINT.parse().unwrap();
        let text = hy2_primary_config(endpoint, &params(), control).expect("generation");
        serde_json::from_str(&text).expect("the generator emits JSON")
    }

    #[test]
    fn the_profile_argument_accepts_a_and_hy2_only() {
        assert_eq!(parse_profile("a").unwrap(), ProfileArg::A);
        assert_eq!(parse_profile("hy2").unwrap(), ProfileArg::Hy2);
        for bad in ["", "A", "HY2", "hysteria2", "reality"] {
            assert!(parse_profile(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_server_contract_parses() {
        let p = params();
        assert_eq!(p.server_port, 44443);
        assert_eq!(p.server_name, "hy2.harness.test");
        assert_eq!(p.spki_sha256().unwrap(), [7u8; 32]);
        assert_eq!(p.origin_url, "http://203.0.113.80:8080");
    }

    #[test]
    fn an_unknown_field_or_a_malformed_pin_is_refused() {
        let extra = PARAMS.replace("\"origin_url\"", "\"surprise\": 1, \"origin_url\"");
        assert!(Hy2Params::parse(extra.as_bytes()).is_err());

        for bad in ["", "07", &"zz".repeat(32), &"07".repeat(33)] {
            let mut p = params();
            p.spki_sha256_hex = bad.to_string();
            assert!(p.spki_sha256().is_err(), "{bad:?} must be refused");
        }
    }

    /// The control is only meaningful if the production configuration really carries the
    /// guard it withholds. If the generator ever stopped emitting it, the control would equal
    /// the pass configuration and the instrument would be blind.
    #[test]
    fn the_pass_config_carries_the_guard_and_the_pinned_hysteria2_outbound() {
        let v = config(false);
        assert_eq!(v["route"]["auto_detect_interface"], true);

        let proxy = &v["outbounds"][0];
        assert_eq!(proxy["type"], "hysteria2");
        assert_eq!(proxy["server"], ENDPOINT);
        assert_eq!(proxy["server_port"], 44443);
        assert_eq!(proxy["obfs"]["type"], "salamander");
        assert_eq!(proxy["tls"]["server_name"], "hy2.harness.test");
        // Standard base64 of 32 bytes of 0x07.
        let pin = format!("{}Bwc=", "BwcH".repeat(10));
        assert_eq!(proxy["tls"]["certificate_public_key_sha256"], json!([pin]));
    }

    #[test]
    fn the_control_turns_the_guard_off() {
        assert_eq!(config(true)["route"]["auto_detect_interface"], false);

        let mut bare = json!({ "route": { "auto_detect_interface": true } });
        withhold_loop_guard(&mut bare);
        assert_eq!(bare["route"]["auto_detect_interface"], false);
    }

    /// The control must still tunnel exactly like the pass run: same TUN, same outbounds,
    /// same DNS, same final route. Otherwise a missing loop could be blamed on a broken control.
    #[test]
    fn the_control_still_tunnels_like_the_pass_run() {
        let (pass, control) = (config(false), config(true));
        for key in ["inbounds", "outbounds", "dns"] {
            assert_eq!(control[key], pass[key], "{key} must not change");
        }
        assert_eq!(control["route"]["final"], pass["route"]["final"]);
    }
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

    use super::pure::{hy2_primary_config, parse_profile, Hy2Params, ProfileArg};

    use dnet_config::amneziawg::{ObfuscationParams, PeerConfig, PrivateKey};
    use dnet_config::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
    use dnet_config::{write, ActiveEndpointBypass};
    use dnet_core::builtin_rules::builtin_rules;
    use dnet_core::endpoint::EndpointAddress;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::{ConnectionProfile, CoreBinding, ProfileKind, ProfileParams};
    use dnet_netstate::host_route::{
        bring_up, on_carrying_path_change, tear_down, HostRoute, TunnelBringup,
    };
    use dnet_netstate::undo::UndoRegistry;
    use dnet_netstate::undo_file::FileStore;
    use dnet_netstate::win_bringup::{TunnelSpec, WindowsTunnelBringup};
    use dnet_netstate::win_route::{best_route_to, default_gateway, WindowsUndoExecutor};
    use dnet_netstate::NetstateError;
    use dnet_supervisor::error::SupervisorError;
    use dnet_supervisor::process::CoreCommand;
    use dnet_supervisor::reap::start_cores;
    use dnet_supervisor::shutdown::shutdown_all;
    use dnet_supervisor::windows_runtime::{UndoHook, WindowsCoreRuntime};
    use std::sync::Arc;

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
        profile: ProfileArg,
        params: PathBuf,
        endpoint: IpAddr,
        /// Required for Profile A only; Hysteria 2 runs no AmneziaWG core.
        awg_exe: Option<PathBuf>,
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
        profile: ProfileArg,
        mode: Mode,
        endpoint: IpAddr,
        gateway: IpAddr,
        host_route_installed: bool,
        /// Whether the guard that keeps the tunnel's own packets off the TUN was in force: the
        /// endpoint host route for Profile A, `auto_detect_interface` for Hysteria 2. True in a
        /// pass run and false in the control. The wrapper reads this, not `host_route_installed`,
        /// so one verdict rule serves both profiles.
        loop_guard_in_force: bool,
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
        let mut profile = ProfileArg::A;
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
                "--profile" => profile = parse_profile(&val()?)?,
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
        if profile == ProfileArg::A && awg_exe.is_none() {
            bail!("--awg-exe is required for --profile a");
        }
        if profile == ProfileArg::Hy2 && alt_gateway.is_some() {
            bail!("--alt-gateway applies to the Profile A host-route rewrite only");
        }
        Ok(Args {
            profile,
            params: params.context("--params is required")?,
            endpoint: endpoint.context("--endpoint is required")?,
            awg_exe,
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

    /// Preflight: the spike is only meaningful if the endpoint is reached through the default
    /// gateway. Loopback or on-link endpoints never enter the TUN, so they would pass vacuously.
    /// Returns that gateway.
    fn preflight(args: &Args) -> Result<IpAddr> {
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
        Ok(gateway)
    }

    /// Restoration state for this run. Anything an earlier, crashed run left is reversed before
    /// this run touches the routing table.
    fn open_undo(args: &Args) -> Result<Arc<UndoRegistry>> {
        let undo = Arc::new(
            UndoRegistry::open(Box::new(FileStore::new(
                args.run_dir.join("state").join("undo.json"),
            )))
            .context("opening the undo journal")?,
        );
        let leftover = undo.replay(&WindowsUndoExecutor)?;
        if leftover.restored > 0 || !leftover.failed.is_empty() {
            tracing::warn!(?leftover, "reversed state left by an earlier run");
        }
        if !leftover.failed.is_empty() {
            bail!("state left by an earlier run could not be restored: {leftover:?}");
        }
        Ok(undo)
    }

    /// How to launch the primary core against a generated configuration.
    fn primary_core_command(exe: &Path, config: PathBuf, run_dir: &Path) -> CoreCommand {
        CoreCommand {
            core: CoreBinding::PrimaryCore,
            program: exe.to_path_buf(),
            args: vec![
                OsString::from("run"),
                OsString::from("-c"),
                config.into_os_string(),
                OsString::from("-D"),
                run_dir.join("primary").into_os_string(),
                OsString::from("--disable-color"),
            ],
            working_dir: Some(run_dir.join("primary")),
            ready_marker: Some("started".into()),
            ready_timeout: Duration::from_secs(30),
        }
    }

    /// Replays whatever teardown could not remove. The AmneziaWG adapter's own address and route
    /// vanish with the adapter, so they are never recorded.
    fn undo_hook(undo: Arc<UndoRegistry>) -> UndoHook {
        Box::new(move || match undo.replay(&WindowsUndoExecutor) {
            Ok(report) if report.failed.is_empty() => Ok(()),
            Ok(report) => Err(SupervisorError::Runtime(format!(
                "undo replay left {} record(s)",
                report.failed.len()
            ))),
            Err(e) => Err(SupervisorError::Runtime(e.to_string())),
        })
    }

    async fn run(args: &Args) -> Result<Report> {
        match args.profile {
            ProfileArg::A => run_profile_a(args).await,
            ProfileArg::Hy2 => run_hy2(args).await,
        }
    }

    /// Profile B (Hysteria 2): the primary core alone. There is no second adapter and no host
    /// route. The guard against the loop is the core's own `auto_detect_interface`, which binds
    /// its outbound sockets to the physical NIC; the control withholds exactly that.
    async fn run_hy2(args: &Args) -> Result<Report> {
        let gateway = preflight(args)?;
        let undo = open_undo(args)?;

        let params = Hy2Params::parse(
            &std::fs::read(&args.params)
                .with_context(|| format!("reading {}", args.params.display()))?,
        )?;
        let primary_exe = args.primary_exe.clone();
        if !primary_exe.is_file() {
            bail!("staged core missing: {}", primary_exe.display());
        }

        let config_json = hy2_primary_config(args.endpoint, &params, args.mode == Mode::Control)?;
        let config_path = write::write_restricted(
            &args.run_dir.join("config"),
            "primary-core.json",
            config_json.as_bytes(),
        )
        .context("writing the restricted primary-core config")?;

        // No AmneziaWG core runs for this profile, but the runtime still names one. It is never
        // spawned (`start_cores` starts only the primary core for this profile), so a path that
        // does not exist is enough.
        let unused_awg = args
            .awg_exe
            .clone()
            .unwrap_or_else(|| args.run_dir.join("amneziawg-go-unused.exe"));
        let runtime = WindowsCoreRuntime::new(
            primary_core_command(&primary_exe, config_path, &args.run_dir),
            CoreCommand {
                core: CoreBinding::AmneziaWgCore,
                program: unused_awg,
                args: Vec::new(),
                working_dir: None,
                ready_marker: None,
                ready_timeout: Duration::from_secs(5),
            },
            ADAPTER,
            Duration::from_secs(30),
            undo_hook(undo.clone()),
        );

        let mut report = Report {
            profile: ProfileArg::Hy2,
            mode: args.mode,
            endpoint: args.endpoint,
            gateway,
            host_route_installed: false,
            loop_guard_in_force: args.mode == Mode::Pass,
            transfer: Transfer::default(),
            path_change: None,
            teardown_ok: false,
            error: None,
        };

        let outcome = async {
            start_cores(&runtime, CoreBinding::PrimaryCore).await?;
            // The TUN exists and no Hysteria 2 session has been opened yet: the outbound dials
            // lazily, so nothing has been sent to the endpoint.
            checkpoint(&args.run_dir, args.mode, "cores-up").await?;
            report.transfer = transfer_after_handshake(&params.origin_url, args.bytes).await;
            checkpoint(&args.run_dir, args.mode, "measured").await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = &outcome {
            report.error = Some(format!("{e:#}"));
        }

        let cores_down = shutdown_all(&runtime).await;
        report.teardown_ok = cores_down.is_ok() && undo.outstanding().is_empty();
        if let Err(e) = cores_down {
            tracing::error!(error = %e, "core shutdown failed");
        }
        Ok(report)
    }

    async fn run_profile_a(args: &Args) -> Result<Report> {
        let gateway = preflight(args)?;
        let undo = open_undo(args)?;

        let params: ClientParams = serde_json::from_slice(
            &std::fs::read(&args.params)
                .with_context(|| format!("reading {}", args.params.display()))?,
        )?;
        // Staged by the wrapper into private per-run directories: orphan reaping matches
        // these exact paths, so a spike never touches cores belonging to anything else.
        let awg_exe = args
            .awg_exe
            .clone()
            .context("--awg-exe is required for --profile a")?;
        let primary_exe = args.primary_exe.clone();
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
            primary_transport: None,
        })?;
        let config_path = write::write_restricted(
            &args.run_dir.join("config"),
            "primary-core.json",
            to_json(&config).as_bytes(),
        )
        .context("writing the restricted primary-core config")?;

        let runtime = WindowsCoreRuntime::new(
            primary_core_command(&primary_exe, config_path, &args.run_dir),
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
            undo_hook(undo.clone()),
        );

        let tunnel = WindowsTunnelBringup::new(
            TunnelSpec {
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
            },
            undo.clone(),
        );
        let route = HostRoute::for_endpoint(&bypass, gateway);

        let mut report = Report {
            profile: ProfileArg::A,
            mode: args.mode,
            endpoint: args.endpoint,
            gateway,
            host_route_installed: false,
            loop_guard_in_force: false,
            transfer: Transfer::default(),
            path_change: None,
            teardown_ok: false,
            error: None,
        };

        let outcome = async {
            start_cores(&runtime, CoreBinding::AmneziaWgCore).await?;
            // Adapters now exist and no peer is configured: nothing flows yet.
            checkpoint(&args.run_dir, args.mode, "cores-up").await?;

            match args.mode {
                Mode::Pass => bring_up(&tunnel, &route).await?,
                Mode::Control => bring_up(&WithheldHostRoute(&tunnel), &route).await?,
            }
            report.host_route_installed = tunnel.routes().owns(&route);
            report.loop_guard_in_force = report.host_route_installed;
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
        report.teardown_ok = tunnel_down.is_ok()
            && cores_down.is_ok()
            && !tunnel.routes().owns(&route)
            && undo.outstanding().is_empty();
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
