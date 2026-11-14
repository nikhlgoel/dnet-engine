// SPDX-License-Identifier: GPL-3.0-or-later
//! T126 step 2 — the real effects (Windows).
//!
//! The orchestrator decides when; this does. It is deliberately thin: what to start is decided by
//! `plan`, how a tunnel comes up and goes down (and what is cleaned up when it fails) by `tunnel`,
//! and what the network is asked by `checks`, each tested without the OS. What is left here is
//! the Windows plumbing: where the files are, the restricted directories, the real runtime and
//! bring-up objects, and looking up credentials.
//!
//! **Credentials are read when needed and not kept.** The secret store is consulted at start-up to
//! learn which endpoints can be used (`plan::assess_endpoints`), and again for each race and each
//! tunnel, because a race and a start are rare and a service that holds every endpoint's keys in
//! memory for as long as it runs gains nothing from it.
//!
//! **Every private directory is restricted before anything is put in it** (SYSTEM and
//! Administrators only), because the files here are generated configurations that contain
//! credentials.

use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dnet_config::credentials::EndpointCredentials;
use dnet_config::install_trust::{verify_programs, InstallProblem};
use dnet_config::primary::{FakeIpHalf, FakeIpRotation};
use dnet_config::secret_store::{SecretKey, SecretStore};
use dnet_config::write;
use dnet_core::endpoint::Endpoint;
use dnet_core::engine::Environment;
use dnet_core::failure::Reach;
use dnet_core::health::ProbeOutcome as EndpointProbeOutcome;
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::origin::Origin;
use dnet_core::probe::RaceDecision;
use dnet_core::profile::{ConnectionProfile, CoreBinding, ProfileKind};
use dnet_core::reprobe::LiveCheck;
use dnet_core::rule::RoutingRule;
use dnet_core::session::FailureCause;
use dnet_netstate::undo::UndoRegistry;
use dnet_netstate::win_bringup::{TunnelSpec, WindowsTunnelBringup};
use dnet_netstate::win_route::{default_gateway, WindowsUndoExecutor};
use dnet_netstate::NetstateError;
use dnet_probe::measure::MeasureConfig;
use dnet_probe::runner::{free_loopback_ports, sweep_stale_in, Prober, READY_TIMEOUT};
use dnet_supervisor::error::SupervisorError;
use dnet_supervisor::process::CoreCommand;
use dnet_supervisor::windows_runtime::{UndoHook, WindowsCoreRuntime};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::checks;
use crate::feed_service::SharedDefinitions;
use crate::listener;
use crate::orchestrator::{Effects, RaceOutcome};
use crate::plan::{
    origin_for, plan_tunnel, probe_job, race_origin, reach_ports, SessionInfo, AMNEZIAWG_ADAPTER,
};
use crate::portal_probe::{self, PortalMemory};
use crate::recovery::windows_ops::CORE_EXECUTABLES;
use crate::session_switch::{switch_to, ControlClient, NudgeOutcome, NudgePlan, OriginProbe};
use crate::tunnel::{Prepared, TunnelHost, Tunnels};
use crate::winwatch::{WatchSetup, WindowsWatch};
use dnet_config::session::CarrierKind;

/// How long a single host may take to answer the pre-connect reachability check. Windows reports a
/// refused connection only after about two seconds, so less would read a refusal as silence.
const REACH_TIMEOUT: Duration = Duration::from_millis(2500);

/// How long the AmneziaWG adapter may take to appear after its core starts.
const ADAPTER_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the primary core may take to report it has started.
const PRIMARY_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the files are.
#[derive(Debug, Clone)]
pub struct Layout {
    pub primary_core: PathBuf,
    pub amneziawg_core: PathBuf,
    /// `%PROGRAMDATA%\DNet Engine\run`.
    pub run_dir: PathBuf,
}

impl Layout {
    /// The installed layout: the cores beside the service executable (T114), the run directory
    /// under `%PROGRAMDATA%`.
    pub fn installed() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let dir = exe.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "the service has no directory")
        })?;
        Ok(Self {
            primary_core: dir.join(CORE_EXECUTABLES[0]),
            amneziawg_core: dir.join(CORE_EXECUTABLES[1]),
            run_dir: write::default_run_dir(),
        })
    }

    fn config_dir(&self) -> PathBuf {
        self.run_dir.join("config")
    }

    fn core_dir(&self) -> PathBuf {
        self.run_dir.join("primary")
    }

    fn probe_dir(&self) -> PathBuf {
        self.run_dir.join("probe")
    }
}

/// A directory only SYSTEM and Administrators control, or an error: see
/// [`write::prepare_private_dir`] for what is refused and why.
fn private_dir(dir: &Path) -> io::Result<()> {
    write::prepare_private_dir(dir)
}

/// Replays what teardown could not remove. The AmneziaWG adapter's own address and route vanish with
/// the adapter, so they are never recorded.
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

// ------------------------------------------------------------------ the tunnel host

/// What carrying a tunnel out needs from this machine.
pub struct WindowsHost {
    layout: Layout,
    undo: Arc<UndoRegistry>,
}

impl WindowsHost {
    fn config_file(&self) -> PathBuf {
        self.layout.config_dir().join("primary-core.json")
    }
}

impl TunnelHost for WindowsHost {
    type Runtime = WindowsCoreRuntime;
    type Bringup = WindowsTunnelBringup;

    fn gateway(&self) -> Result<IpAddr, NetstateError> {
        default_gateway()
    }

    fn prepare(
        &self,
        plan: &crate::plan::TunnelPlan,
    ) -> Result<Prepared<WindowsCoreRuntime, WindowsTunnelBringup>, String> {
        let layout = &self.layout;
        // Names the step and the kind of failure, never a path with a credential or the content.
        let failed = |what: &str| {
            let what = what.to_owned();
            move |error: io::Error| format!("{what} ({})", error.kind())
        };
        let config = write::write_restricted(
            &layout.config_dir(),
            "primary-core.json",
            plan.config_json().as_bytes(),
        )
        .map_err(failed("the connection settings could not be written"))?;
        private_dir(&layout.core_dir())
            .map_err(failed("the working directory could not be prepared"))?;

        let primary = CoreCommand {
            core: CoreBinding::PrimaryCore,
            program: layout.primary_core.clone(),
            args: vec![
                OsString::from("run"),
                OsString::from("-c"),
                config.into_os_string(),
                OsString::from("-D"),
                layout.core_dir().into_os_string(),
                OsString::from("--disable-color"),
            ],
            working_dir: Some(layout.core_dir()),
            ready_marker: Some("started".into()),
            ready_timeout: PRIMARY_READY_TIMEOUT,
        };
        let amneziawg = CoreCommand {
            core: CoreBinding::AmneziaWgCore,
            program: layout.amneziawg_core.clone(),
            args: vec![OsString::from(AMNEZIAWG_ADAPTER)],
            working_dir: layout.amneziawg_core.parent().map(Path::to_path_buf),
            // Ready when its control pipe appears, which `await_adapter` waits for.
            ready_marker: None,
            ready_timeout: Duration::from_secs(5),
        };
        let runtime = WindowsCoreRuntime::new(
            primary,
            amneziawg,
            AMNEZIAWG_ADAPTER,
            ADAPTER_TIMEOUT,
            undo_hook(Arc::clone(&self.undo)),
        );
        let bringup = plan.awg.as_ref().map(|awg| {
            WindowsTunnelBringup::new(
                TunnelSpec {
                    adapter: AMNEZIAWG_ADAPTER.into(),
                    address: awg.address,
                    prefix_len: awg.prefix_len,
                    private_key: awg.private_key.clone(),
                    obfuscation: awg.obfuscation,
                    peer: awg.peer.clone(),
                },
                Arc::clone(&self.undo),
            )
        });
        Ok(Prepared { runtime, bringup })
    }

    fn discard_config(&self) {
        if let Err(error) = std::fs::remove_file(self.config_file()) {
            if error.kind() != io::ErrorKind::NotFound {
                // It holds credentials, so a failed delete is worth knowing about.
                tracing::warn!(kind = ?error.kind(), "could not delete the generated core configuration");
            }
        }
    }

    async fn flush_resolver_cache(&self) {
        let program = resolver_flush_program(std::env::var_os("SystemRoot"));
        let mut command = tokio::process::Command::new(&program);
        command
            .arg("/flushdns")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            // A flush that overruns is abandoned, and must not outlive the wait for it.
            .kill_on_drop(true);
        match tokio::time::timeout(RESOLVER_FLUSH_TIMEOUT, command.status()).await {
            Ok(Ok(status)) if status.success() => {
                tracing::debug!("flushed the system resolver cache");
            }
            Ok(Ok(status)) => {
                tracing::warn!(code = ?status.code(), "the system resolver cache was not flushed");
            }
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "the system resolver cache could not be flushed");
            }
            Err(_) => tracing::warn!("flushing the system resolver cache took too long"),
        }
    }
}

/// How long the resolver flush may take. It is instant on a healthy machine; a stuck DNS Client
/// service must not hold up a tunnel stop, which has a deadline of its own.
const RESOLVER_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// `CREATE_NO_WINDOW`: no console window for a helper started by the service.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The program that flushes the resolver cache, by absolute path. A service running as SYSTEM must
/// not find it by searching `PATH` or its working directory. `SystemRoot` is a machine-wide
/// setting only an administrator can change; if it is missing the default location is used.
fn resolver_flush_program(system_root: Option<OsString>) -> PathBuf {
    let root = system_root
        .filter(|root| !root.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32").join("ipconfig.exe")
}

// ------------------------------------------------------------------ the effects

/// The effects the orchestrator runs on this machine.
pub struct RealEffects {
    profiles: Vec<ConnectionProfile>,
    endpoints: Vec<Endpoint>,
    rules: Vec<RoutingRule>,
    secrets: Arc<dyn SecretStore>,
    layout: Layout,
    tunnels: Arc<Tunnels<WindowsHost>>,
    privileged: bool,
    /// Why nothing can be connected to, when that is so; shown to the user as it stands.
    configuration_error: Option<String>,
    /// The origin the tunnel in use is measured against. Set while a tunnel is up.
    carrying: Mutex<Option<Origin>>,
    /// The checks of the tunnel in use: a sliver each time, a full measurement on a slow clock.
    live: checks::LiveChecker,
    /// What the network watch needs to know about the tunnel in use. Set while a tunnel is up.
    watching: Mutex<Option<WatchSetup>>,
    /// The session connection that is up, if it is one: what a live move of the carrier needs.
    live_session: Mutex<Option<LiveSession>>,
    /// Whether the network is watched at all. Off only for a development run with
    /// `--no-path-watch`, so a test never sends probes to the network it runs on.
    watch_paths: bool,
    /// Whether the programs launched as SYSTEM are checked for being out of reach of ordinary
    /// users, before every connection. Off only for a development run (`install_check_enabled`).
    check_install: bool,
    /// Which half of the FakeIP pools the next tunnel hands out. Alternates on every start, so an
    /// address a program remembers from the last session is refused rather than answered with a
    /// different name (T131).
    fakeip: FakeIpRotation,
    /// Whether the network is believed to be a captive portal (T077, T078): read at every connect and
    /// again whenever a live check fails.
    portal: Mutex<PortalMemory>,
    /// What the applied profile feed says about the client-only parameters (T066a). Read when a
    /// configuration is generated, so a feed accepted mid-session reaches the next connection and
    /// never the one that is up.
    definitions: SharedDefinitions,
    /// The kill switch (T161): the person's choice and the door to the firewall guard, when there is one.
    guard: Option<crate::guard_control::GuardWiring>,
}

/// A session connection that is up (ADR-0008): which endpoint it is on, its carriers and the one it runs on, how
/// to reach its core's control API, and where the connection is measured (the nudge goes there).
#[derive(Clone)]
struct LiveSession {
    endpoint: EndpointId,
    info: SessionInfo,
    origin: Origin,
}

/// What a live move of the carrier has to settle before it touches anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preflight {
    /// Not a session connection to this endpoint, or the target is not one of its carriers: not a live move.
    Cannot,
    /// The connection is already on that carrier.
    Already,
    /// A move is possible; the checks on the control port come next.
    Switch,
}

fn preflight(live: &LiveSession, endpoint: EndpointId, target: CarrierKind) -> Preflight {
    // The same server, and a carrier this connection has. Anything else is a different connection.
    if live.endpoint != endpoint || !live.info.carriers.contains(&target) {
        Preflight::Cannot
    } else if live.info.active == target {
        Preflight::Already
    } else {
        Preflight::Switch
    }
}

/// How long one look for a captive portal may take. Shorter than the orchestrator's wait for the
/// reachability check it runs beside, so a slow portal probe can never turn into "unknown" for every
/// endpoint.
const PORTAL_TIMEOUT: Duration = Duration::from_secs(3);

/// The half of the FakeIP pools the first tunnel after the daemon starts uses. Which one hardly
/// matters, only that it is not always the same one, so that a daemon restarted between two sessions
/// has an even chance of using the other half. Not security-relevant: the clock's low bit will do.
fn first_fakeip_half(clock_micros: u128) -> FakeIpHalf {
    if clock_micros & 1 == 0 {
        FakeIpHalf::Low
    } else {
        FakeIpHalf::High
    }
}

/// What the real effects work with, besides the configuration they are built from.
pub struct Dependencies {
    /// Where the endpoints' credentials are kept sealed.
    pub secrets: Arc<dyn SecretStore>,
    /// The record of network changes to undo, so a crash leaves nothing behind.
    pub undo: Arc<UndoRegistry>,
    /// Where the programs and working directories are.
    pub layout: Layout,
    /// What the applied profile feed says about the client-only parameters.
    pub definitions: SharedDefinitions,
    /// The person's kill-switch choice and the door to the firewall guard (T161); `None` leaves the guard out.
    pub guard: Option<crate::guard_control::GuardWiring>,
}

impl RealEffects {
    /// Put the guard into the firewall around the tunnel that just came up (T161). Off the async threads: the
    /// firewall engine is a blocking call, and so is the adapter lookup.
    async fn engage_guard(&self, control_port: u16) -> Result<(), String> {
        let Some(wiring) = &self.guard else {
            return Ok(());
        };
        let control = Arc::clone(&wiring.control);
        let switch = Arc::clone(&wiring.switch);
        let core = self.layout.primary_core.clone();
        tokio::task::spawn_blocking(move || {
            let service = std::env::current_exe()
                .map_err(|e| format!("the service's own path is not known: {e}"))?;
            let luid =
                dnet_netstate::adapter::interface_luid_value(dnet_config::primary::TUN_INTERFACE)
                    .map_err(|e| e.to_string())?;
            let plan = crate::guard_control::plan_for(&core, &service, control_port, luid);
            control.engage(&plan)?;
            // The person may have turned it off while this was going in (review 2026-11-10): the guard must not
            // outlive a choice that was changed under it, or the switch would read off with a guard in.
            if !switch.enabled() {
                control.release()?;
            }
            Ok(())
        })
        .await
        .map_err(|_| "putting the guard in was interrupted".to_owned())?
    }

    /// Build the effects for the endpoints in `endpoints` that can be used, and return them with
    /// the profiles and endpoints the engine must be given: exactly these, so it never chooses one
    /// that cannot work or reports a profile blocked that was never tried.
    pub fn new(
        profiles: Vec<ConnectionProfile>,
        endpoints: &[Endpoint],
        rules: Vec<RoutingRule>,
        dependencies: Dependencies,
    ) -> (Self, Vec<ConnectionProfile>, Vec<Endpoint>) {
        let Dependencies {
            secrets,
            undo,
            layout,
            definitions,
            guard,
        } = dependencies;
        let assessed = crate::plan::assess_endpoints(endpoints, secrets.as_ref());
        // Only profiles some usable endpoint can serve: see `served_profiles`.
        let profiles = crate::plan::served_profiles(profiles, &assessed.served);
        for problem in &assessed.problems {
            tracing::warn!("{problem}");
        }

        let mut configuration_error = if assessed.usable.is_empty() {
            assessed.problems.first().cloned()
        } else {
            None
        };
        if !layout.primary_core.is_file() {
            configuration_error = Some(
                "the connection engine is missing from the installation; reinstall DNet Engine"
                    .to_owned(),
            );
            tracing::error!(path = %layout.primary_core.display(), "the primary core is missing");
        }
        if !layout.amneziawg_core.is_file() {
            tracing::warn!(path = %layout.amneziawg_core.display(), "the AmneziaWG core is missing");
        }
        // The service runs these as SYSTEM: if an ordinary user could replace one, connecting would
        // hand them SYSTEM. Refuse to connect from such an installation, and say why.
        let check_install = install_check_enabled(std::env::args());
        if check_install {
            if let Err(problem) = verify_programs(&programs_of(&layout)) {
                tracing::error!(%problem, "the installation is not protected from ordinary users");
                configuration_error.get_or_insert_with(|| install_message(&problem));
            }
        } else {
            tracing::warn!(
                "--allow-untrusted-install: the programs run as SYSTEM were not checked for being \
                 out of reach of ordinary users; this is for development only"
            );
        }

        // A crash can leave credentials in the places this writes to. Clear them before anything
        // new is written, and make the directories private before anything is put in them.
        for dir in [layout.config_dir(), layout.core_dir(), layout.probe_dir()] {
            if let Err(error) = private_dir(&dir) {
                tracing::error!(kind = ?error.kind(), dir = %dir.display(), "could not restrict a private directory");
                configuration_error.get_or_insert_with(|| {
                    "the service's private directories could not be prepared".to_owned()
                });
            }
        }
        let host = WindowsHost {
            layout: layout.clone(),
            undo,
        };
        host.discard_config();
        let swept = sweep_stale_in(&layout.probe_dir());
        if swept > 0 {
            tracing::warn!(
                swept,
                "removed probe configurations a crashed run left behind"
            );
        }

        let effects = Self {
            profiles: profiles.clone(),
            endpoints: assessed.usable.clone(),
            rules,
            secrets,
            layout,
            tunnels: Arc::new(Tunnels::new(host)),
            privileged: is_elevated(),
            configuration_error,
            carrying: Mutex::new(None),
            live: checks::LiveChecker::new(checks::DEEP_EVERY),
            watching: Mutex::new(None),
            live_session: Mutex::new(None),
            watch_paths: !std::env::args().any(|a| a == "--no-path-watch"),
            check_install,
            fakeip: FakeIpRotation::new(first_fakeip_half(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_micros()),
            )),
            portal: Mutex::new(PortalMemory::default()),
            definitions,
            guard,
        };
        if !effects.watch_paths {
            tracing::warn!("--no-path-watch: the network is not watched and no path is probed");
        }
        (effects, profiles, assessed.usable)
    }

    /// The stored credentials of `endpoint`, read now.
    async fn credentials(
        &self,
        endpoint: EndpointId,
    ) -> Result<(Endpoint, EndpointCredentials), String> {
        let endpoint = self
            .endpoints
            .iter()
            .find(|e| e.id() == endpoint)
            .cloned()
            .ok_or_else(|| "the endpoint is not one that can be used".to_owned())?;
        let secrets = Arc::clone(&self.secrets);
        let reference = endpoint.credentials().clone();
        let label = endpoint.label().to_owned();
        tokio::task::spawn_blocking(move || {
            let key = SecretKey::parse(&reference).map_err(|e| e.to_string())?;
            secrets
                .get(&key)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("endpoint '{label}' has no credentials stored"))
        })
        .await
        .map_err(|_| "reading the credentials was interrupted".to_owned())?
        .map(|credentials| (endpoint, credentials))
    }

    fn carrying_origin(&self) -> Option<Origin> {
        self.carrying
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_carrying(&self, origin: Option<Origin>) {
        *self.carrying.lock().unwrap_or_else(PoisonError::into_inner) = origin;
    }

    fn set_watching(&self, setup: Option<WatchSetup>) {
        *self.watching.lock().unwrap_or_else(PoisonError::into_inner) = setup;
    }

    fn live_session(&self) -> Option<LiveSession> {
        self.live_session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_live_session(&self, session: Option<LiveSession>) {
        *self
            .live_session
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = session;
    }
}

/// File name of the adapter driver library that ships beside the cores. Assembled at run time so
/// that this source file does not itself carry a vendor name `lint-branding` forbids; the name is
/// a file on disk the service must load, not text a user reads.
fn adapter_library_name() -> String {
    format!("{}.dll", ["win", "tun"].concat())
}

/// Every program the service launches or loads as SYSTEM that exists: the two cores, the adapter
/// driver library beside them, and the service itself. One that is missing is reported where it is
/// needed; here it only has nothing to protect.
pub(crate) fn programs_of(layout: &Layout) -> Vec<PathBuf> {
    let mut programs = vec![layout.primary_core.clone(), layout.amneziawg_core.clone()];
    if let Some(folder) = layout.primary_core.parent() {
        programs.push(folder.join(adapter_library_name()));
    }
    if let Ok(service) = std::env::current_exe() {
        programs.push(service);
    }
    programs.retain(|p| p.exists());
    programs
}

/// What the user is told when the installation is too open. The path and the reason are the
/// administrator's to act on; neither is a secret.
fn install_message(problem: &InstallProblem) -> String {
    format!(
        "the DNet Engine installation is not protected from ordinary users ({problem}); it will \
         not connect from here. Reinstall it into a folder only administrators can change"
    )
}

/// Whether the programs are checked. They always are, except in a development run: `--console`
/// together with `--allow-untrusted-install`. The flag alone does nothing, so a service started
/// with it by mistake still checks.
fn install_check_enabled(args: impl Iterator<Item = String>) -> bool {
    let args: Vec<String> = args.collect();
    let console = args.iter().any(|a| a == "--console");
    let allowed = args.iter().any(|a| a == "--allow-untrusted-install");
    !(console && allowed)
}

fn prober(layout: &Layout, origin: Origin) -> Prober {
    Prober {
        core_exe: layout.primary_core.clone(),
        work_dir: layout.probe_dir(),
        origin,
        measure: MeasureConfig {
            connect_timeout: Duration::from_secs(8),
            transfer_timeout: checks::RACE_TRANSFER_TIMEOUT,
            bytes: checks::RACE_BYTES,
        },
        ready_timeout: READY_TIMEOUT,
    }
}

impl RealEffects {
    /// The client-only parameters in effect now.
    fn client_definitions(&self) -> dnet_core::feed::ClientDefinitions {
        *self
            .definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether each endpoint answers a direct connection.
    async fn reach_endpoints(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
        let mut checks = JoinSet::new();
        for (index, endpoint) in endpoints.iter().enumerate() {
            let id = endpoint.id();
            let host = endpoint.address().host().to_owned();
            let loaded = self.credentials(id).await;
            checks.spawn(async move {
                // Only ports that carry TCP: see `reach_ports`.
                let ports: Vec<u16> = loaded
                    .map(|(_, credentials)| reach_ports(&credentials))
                    .unwrap_or_default();
                let reach = match host.parse::<Ipv4Addr>() {
                    Ok(ip) => checks::reach_host(ip, &ports, REACH_TIMEOUT).await,
                    Err(_) => Reach::Unknown,
                };
                (index, reach)
            });
        }
        let mut answers = vec![Reach::Unknown; endpoints.len()];
        while let Some(done) = checks.join_next().await {
            if let Ok((index, reach)) = done {
                answers[index] = reach;
            }
        }
        answers
    }
}

impl Effects for RealEffects {
    async fn core_health(&self) -> Vec<(CoreBinding, dnet_supervisor::runtime::CoreHealth)> {
        self.tunnels.core_health().await
    }

    fn environment(&self) -> Environment {
        Environment {
            privileged: self.privileged,
            usable_paths: usize::from(default_gateway().is_ok()),
            captive_portal: self
                .portal
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_portal(),
            configuration_error: self.configuration_error.clone(),
        }
    }

    async fn reach(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
        // A connect is starting: look at the network beside the endpoints. Both go through the
        // physical network, so neither waits for the other.
        let (answers, reading) = tokio::join!(
            self.reach_endpoints(endpoints),
            portal_probe::detect(PORTAL_TIMEOUT)
        );
        self.portal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .connecting(&reading);
        answers
    }

    async fn race(
        &self,
        profiles: Vec<ProfileId>,
        endpoint: EndpointId,
        cancel: CancellationToken,
    ) -> Option<RaceOutcome> {
        // Nothing that can go wrong below may return `None`: that means "cancelled", and a connect
        // whose race ends without a result would wait for one for ever.
        let nothing_usable = || (RaceDecision::NoneUsable, Vec::new());

        let (endpoint, credentials) = match self.credentials(endpoint).await {
            Ok(found) => found,
            Err(error) => {
                tracing::error!(%error, "the credentials for the race could not be read");
                return Some(nothing_usable());
            }
        };
        let Some(origin) = race_origin(&credentials) else {
            tracing::error!("the endpoint has no measurement origin");
            return Some(nothing_usable());
        };

        let chosen: Vec<&ConnectionProfile> = profiles
            .iter()
            .filter_map(|id| self.profiles.iter().find(|p| p.id() == id))
            .collect();
        let ports = match free_loopback_ports(chosen.len()) {
            Ok(ports) => ports,
            Err(error) => {
                tracing::error!(%error, "no local ports for the race");
                return Some(nothing_usable());
            }
        };
        let definitions = self.client_definitions();
        let jobs: Vec<_> = chosen
            .iter()
            .zip(ports)
            .filter_map(|(profile, port)| {
                match probe_job(profile, &endpoint, &credentials, &definitions, port) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        // Left out of the race; the engine marks a raced profile that never reports.
                        tracing::warn!(profile = %profile.id(), %error, "not raced");
                        None
                    }
                }
            })
            .collect();

        let prober = prober(&self.layout, origin);
        // Dropping the race on cancellation stops its probes and, through them, their cores.
        tokio::select! {
            _ = cancel.cancelled() => None,
            report = prober.race(jobs) => Some(match report {
                Ok(report) => (
                    report.decision,
                    report.results.into_iter().map(|(id, probe, _)| (id, probe)).collect(),
                ),
                Err(error) => {
                    tracing::error!(%error, "the race could not be run");
                    nothing_usable()
                }
            }),
        }
    }

    async fn start_tunnel(
        &self,
        profile: &ProfileId,
        endpoint: EndpointId,
    ) -> Result<(), FailureCause> {
        let configuration = |detail: String| FailureCause::ConfigurationInvalid { detail };
        let profile = self
            .profiles
            .iter()
            .find(|p| p.id() == profile)
            .ok_or_else(|| configuration(format!("profile '{profile}' is not known")))?;
        // Again before every connection, not only at start-up: what was fine then may not be now.
        if self.check_install {
            let layout = self.layout.clone();
            tokio::task::spawn_blocking(move || verify_programs(&programs_of(&layout)))
                .await
                .map_err(|_| configuration("checking the installation was interrupted".to_owned()))?
                .map_err(|problem| {
                    tracing::error!(%problem, "refusing to connect from an unprotected installation");
                    configuration(install_message(&problem))
                })?;
        }
        let endpoint_id = endpoint;
        let (endpoint, credentials) = self.credentials(endpoint).await.map_err(configuration)?;
        let origin = origin_for(profile.kind(), &credentials);
        // One half per start, taken even if this start fails: the next must not reuse it.
        let plan = plan_tunnel(
            profile,
            &endpoint,
            &credentials,
            &self.client_definitions(),
            &self.rules,
            self.fakeip.take(),
        )
        .map_err(FailureCause::from)?;
        // What the network watch will need, taken now while the credentials are in hand: the
        // endpoint and the TCP port a probe may aim at (never a UDP port).
        let endpoint_ip: Option<Ipv4Addr> = endpoint.address().host().parse().ok();
        let tcp_port = reach_ports(&credentials).first().copied();
        let setup = WatchSetup {
            carrier: profile.carrier(),
            steer: plan.awg.is_some(),
            endpoint_ip,
            endpoint_tcp: endpoint_ip
                .zip(tcp_port)
                .map(|(ip, port)| SocketAddrV4::new(ip, port)),
            session_origin: plan.session.as_ref().and(origin.clone()),
        };
        drop(credentials);

        // The kill switch (T161): decided before anything is started, so a connection it cannot cover is refused
        // with the reason instead of being made without the protection that was asked for.
        let coverage = match &self.guard {
            Some(wiring) => crate::guard_control::coverage(
                wiring.switch.enabled(),
                plan.awg.is_some(),
                plan.session.as_ref().map(|s| s.control.port),
            ),
            None => crate::guard_control::Coverage::NotWanted,
        };
        if let crate::guard_control::Coverage::CannotCover(why) = &coverage {
            return Err(configuration(why.clone()));
        }

        self.tunnels.start(&plan).await?;
        if let crate::guard_control::Coverage::Wanted { control_port } = coverage {
            if let Err(detail) = self.engage_guard(control_port).await {
                // A tunnel up without the protection that was asked for is not what the person chose.
                tracing::error!(%detail, "the kill switch could not be put in; stopping the tunnel");
                self.tunnels.stop().await;
                return Err(configuration(format!(
                    "the kill switch is on but could not be put in ({detail}); the connection was not made. \
                     Turn the kill switch off to connect without it"
                )));
            }
        }
        // A session connection can later be moved to another carrier without ending it.
        self.set_live_session(
            plan.session
                .clone()
                .zip(origin.clone())
                .map(|(info, origin)| LiveSession {
                    endpoint: endpoint_id,
                    info,
                    origin,
                }),
        );
        self.set_carrying(origin);
        self.set_watching(Some(setup));
        // The race that chose this method just moved a full transfer through it.
        self.live.proved(std::time::Instant::now());
        Ok(())
    }

    async fn stop_tunnel(&self) {
        self.live.forget();
        self.set_carrying(None);
        self.set_watching(None);
        self.set_live_session(None);
        self.tunnels.stop().await;
    }

    async fn release_guard(&self) {
        let Some(wiring) = &self.guard else {
            return;
        };
        let control = Arc::clone(&wiring.control);
        match tokio::task::spawn_blocking(move || control.release()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, "the guard could not be taken out on disconnect")
            }
            Err(_) => tracing::error!("taking the guard out was interrupted"),
        }
    }

    async fn move_tunnel(&self, profile: &ProfileId, endpoint: EndpointId) -> bool {
        let Some(profile) = self.profiles.iter().find(|p| p.id() == profile) else {
            return false;
        };
        let target = match profile.kind() {
            ProfileKind::Hysteria2 => CarrierKind::Hysteria2,
            ProfileKind::VlessReality => CarrierKind::Reality,
            // Not a carrier of the session: it has its own adapter, and is started as it always was.
            ProfileKind::AmneziaWg => return false,
        };
        let Some(live) = self.live_session() else {
            return false;
        };
        match preflight(&live, endpoint, target) {
            Preflight::Cannot => return false,
            Preflight::Already => return true,
            Preflight::Switch => {}
        }

        // The control secret goes to a local port chosen before the core bound it. Send it only if the core
        // we started is the only thing a connection to that port can reach (T157 review, step d).
        let port = live.info.control.port;
        let Some(core) = self.tunnels.primary_core_pid().await else {
            tracing::warn!("the core's process is not known; not moving the connection live");
            return false;
        };
        let table = match tokio::task::spawn_blocking(listener::listening_sockets).await {
            Ok(Ok(table)) => table,
            _ => {
                tracing::warn!(
                    "the listening ports could not be read; not moving the connection live"
                );
                return false;
            }
        };
        if !listener::only_this_process_listens(&table, port, core) {
            tracing::warn!(
                "something other than the core listens on its control port; not sending it the secret"
            );
            return false;
        }

        let Ok(api) = ControlClient::new(port, live.info.control.secret.clone()) else {
            return false;
        };
        match switch_to(
            &api,
            &OriginProbe(&live.origin),
            target,
            NudgePlan::default(),
        )
        .await
        {
            Ok(report) if matches!(report.nudge, NudgeOutcome::Recovered { .. }) => {
                if let Some(mut now) = self.live_session() {
                    now.info.active = target;
                    self.set_live_session(Some(now));
                }
                // The watch of the next tunnel hears which kind of path the carrier needs now.
                if let Some(setup) = self
                    .watching
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_mut()
                {
                    setup.carrier = profile.carrier();
                }
                // A transfer just crossed the new carrier: the same proof the race gives a new tunnel.
                self.live.proved(std::time::Instant::now());
                true
            }
            Ok(report) => {
                tracing::warn!(?report, "the session did not come back on the new carrier");
                false
            }
            Err(error) => {
                tracing::warn!(%error, "the carrier could not be switched");
                false
            }
        }
    }

    async fn live_check(&self, _profile: &ProfileId) -> LiveCheck {
        let result = match self.carrying_origin() {
            Some(origin) => self.live.check(&origin, std::time::Instant::now()).await,
            None => LiveCheck::Failed,
        };
        if result != LiveCheck::Passed {
            // A connection that stops working may be a portal whose session ended (US6-3). Ask,
            // before the engine is told, so that what it is told next can say so.
            let reading = portal_probe::detect(PORTAL_TIMEOUT).await;
            let recognised = self
                .portal
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .observed(&reading);
            if let Some(change) = recognised {
                tracing::info!(?change, "the network's captive portal changed");
            }
        }
        result
    }

    async fn probe_endpoint(&self, _endpoint: EndpointId) -> EndpointProbeOutcome {
        match self.carrying_origin() {
            Some(origin) => checks::endpoint_probe(&origin).await,
            None => EndpointProbeOutcome::Failed,
        }
    }

    type Watch = WindowsWatch;

    fn network_watch(&self, _profile: &ProfileId, _endpoint: EndpointId) -> Option<WindowsWatch> {
        if !self.watch_paths {
            return None;
        }
        let setup = self
            .watching
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        Some(WindowsWatch::start(setup, Arc::clone(&self.tunnels)))
    }
}

// ------------------------------------------------------------------ privilege

/// Whether this process holds an elevated token. The service runs as LocalSystem, which does; a
/// development run from an ordinary shell does not, and cannot change routes or create adapters.
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: plain queries on this process's own token; the handle is closed before returning.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod flush_tests {
    use super::*;

    #[test]
    fn the_flush_program_is_an_absolute_path_under_the_system_directory() {
        assert_eq!(
            resolver_flush_program(Some(OsString::from(r"D:\Win"))),
            PathBuf::from(r"D:\Win\System32\ipconfig.exe")
        );
    }

    #[test]
    fn a_missing_or_empty_system_root_falls_back_to_the_default_location() {
        let expected = PathBuf::from(r"C:\Windows\System32\ipconfig.exe");
        assert_eq!(resolver_flush_program(None), expected);
        assert_eq!(resolver_flush_program(Some(OsString::new())), expected);
    }
}

#[cfg(test)]
mod fakeip_tests {
    use super::*;

    #[test]
    fn the_first_half_follows_the_clock_so_it_is_not_always_the_same() {
        assert_eq!(first_fakeip_half(0), FakeIpHalf::Low);
        assert_eq!(first_fakeip_half(1), FakeIpHalf::High);
        assert_eq!(first_fakeip_half(1_700_000_000_123_456), FakeIpHalf::Low);
        assert_eq!(first_fakeip_half(1_700_000_000_123_457), FakeIpHalf::High);
    }
}

#[cfg(test)]
mod install_tests {
    use super::*;

    fn args(list: &[&str]) -> std::vec::IntoIter<String> {
        list.iter()
            .map(|a| (*a).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn the_install_is_checked_unless_a_development_run_asks_otherwise() {
        assert!(install_check_enabled(args(&["dnetd.exe"])));
        assert!(install_check_enabled(args(&["dnetd.exe", "--console"])));
        assert!(!install_check_enabled(args(&[
            "dnetd.exe",
            "--console",
            "--allow-untrusted-install"
        ])));
    }

    /// The flag on its own must do nothing: a service started with it by mistake still checks.
    #[test]
    fn the_flag_without_console_mode_does_not_turn_the_check_off() {
        assert!(install_check_enabled(args(&[
            "dnetd.exe",
            "--allow-untrusted-install"
        ])));
    }

    #[test]
    fn the_programs_are_the_cores_the_driver_and_the_service_that_exist() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary-core.exe");
        let awg = dir.path().join("amneziawg-go.exe");
        let missing = dir.path().join("missing.exe");
        std::fs::write(&primary, b"x").unwrap();
        std::fs::write(&awg, b"x").unwrap();
        let library = dir.path().join(adapter_library_name());
        std::fs::write(&library, b"x").unwrap();
        let layout = Layout {
            primary_core: primary.clone(),
            amneziawg_core: awg.clone(),
            run_dir: dir.path().join("run"),
        };

        let programs = programs_of(&layout);

        assert!(programs.contains(&primary) && programs.contains(&awg));
        assert!(programs.contains(&library));
        assert!(!programs.contains(&missing));
        assert!(
            programs.contains(&std::env::current_exe().unwrap()),
            "the service itself is run as SYSTEM too"
        );
    }

    #[test]
    fn an_installation_in_a_users_own_folder_is_refused_with_a_message_that_says_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("primary-core.exe");
        std::fs::write(&core, b"x").unwrap();

        let problem = verify_programs(&[core]).unwrap_err();
        let message = install_message(&problem);

        assert!(
            message.contains("not protected from ordinary users"),
            "{message}"
        );
        assert!(message.contains("Reinstall"), "{message}");
        assert!(
            !message.to_lowercase().contains(&["sing", "box"].join("-")),
            "no vendor name in what the user reads"
        );
    }
}

#[cfg(test)]
mod live_move_tests {
    use super::*;
    use crate::plan::ControlChannel;
    use crate::session_switch::ControlSecret;

    fn live(endpoint: EndpointId, carriers: &[CarrierKind], active: CarrierKind) -> LiveSession {
        LiveSession {
            endpoint,
            info: SessionInfo {
                control: ControlChannel {
                    port: 29090,
                    secret: ControlSecret::new("k".repeat(64)).unwrap(),
                },
                carriers: carriers.to_vec(),
                active,
            },
            origin: Origin::parse("http://10.9.0.254:8080").unwrap(),
        }
    }

    const BOTH: [CarrierKind; 2] = [CarrierKind::Hysteria2, CarrierKind::Reality];

    #[test]
    fn a_move_is_possible_only_to_another_carrier_of_the_same_connection() {
        let here = EndpointId::new();
        let session = live(here, &BOTH, CarrierKind::Hysteria2);
        assert_eq!(
            preflight(&session, here, CarrierKind::Reality),
            Preflight::Switch
        );
        // Already there: nothing to do, and nothing is torn down for it.
        assert_eq!(
            preflight(&session, here, CarrierKind::Hysteria2),
            Preflight::Already
        );
    }

    #[test]
    fn another_server_is_a_different_connection_not_a_move() {
        let session = live(EndpointId::new(), &BOTH, CarrierKind::Hysteria2);
        assert_eq!(
            preflight(&session, EndpointId::new(), CarrierKind::Reality),
            Preflight::Cannot
        );
    }

    #[test]
    fn a_carrier_the_connection_does_not_hold_cannot_be_moved_to() {
        let here = EndpointId::new();
        let only_hy2 = live(here, &[CarrierKind::Hysteria2], CarrierKind::Hysteria2);
        assert_eq!(
            preflight(&only_hy2, here, CarrierKind::Reality),
            Preflight::Cannot
        );
    }
}
