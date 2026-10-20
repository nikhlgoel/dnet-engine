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
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dnet_config::credentials::EndpointCredentials;
use dnet_config::secret_store::{SecretKey, SecretStore};
use dnet_config::write;
use dnet_core::endpoint::Endpoint;
use dnet_core::engine::Environment;
use dnet_core::failure::Reach;
use dnet_core::health::ProbeOutcome as EndpointProbeOutcome;
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::origin::Origin;
use dnet_core::probe::RaceDecision;
use dnet_core::profile::{ConnectionProfile, CoreBinding};
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
use crate::orchestrator::{Effects, RaceOutcome};
use crate::plan::{plan_tunnel, probe_job, reach_ports, AMNEZIAWG_ADAPTER};
use crate::recovery::windows_ops::CORE_EXECUTABLES;
use crate::tunnel::{Prepared, TunnelHost, Tunnels};

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
}

// ------------------------------------------------------------------ the effects

/// The effects the orchestrator runs on this machine.
pub struct RealEffects {
    profiles: Vec<ConnectionProfile>,
    endpoints: Vec<Endpoint>,
    rules: Vec<RoutingRule>,
    secrets: Arc<dyn SecretStore>,
    layout: Layout,
    tunnels: Tunnels<WindowsHost>,
    privileged: bool,
    /// Why nothing can be connected to, when that is so; shown to the user as it stands.
    configuration_error: Option<String>,
    /// The origin the tunnel in use is measured against. Set while a tunnel is up.
    carrying: Mutex<Option<Origin>>,
}

impl RealEffects {
    /// Build the effects for the endpoints in `endpoints` that can be used, and return them with
    /// the profiles and endpoints the engine must be given: exactly these, so it never chooses one
    /// that cannot work or reports a profile blocked that was never tried.
    pub fn new(
        profiles: Vec<ConnectionProfile>,
        endpoints: &[Endpoint],
        rules: Vec<RoutingRule>,
        secrets: Arc<dyn SecretStore>,
        undo: Arc<UndoRegistry>,
        layout: Layout,
    ) -> (Self, Vec<ConnectionProfile>, Vec<Endpoint>) {
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
            tunnels: Tunnels::new(host),
            privileged: is_elevated(),
            configuration_error,
            carrying: Mutex::new(None),
        };
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
}

fn prober(layout: &Layout, origin: Origin) -> Prober {
    Prober {
        core_exe: layout.primary_core.clone(),
        work_dir: layout.probe_dir(),
        origin,
        measure: MeasureConfig {
            connect_timeout: Duration::from_secs(8),
            transfer_timeout: Duration::from_secs(12),
            bytes: 512 * 1024,
        },
        ready_timeout: READY_TIMEOUT,
    }
}

impl Effects for RealEffects {
    fn environment(&self) -> Environment {
        Environment {
            privileged: self.privileged,
            usable_paths: usize::from(default_gateway().is_ok()),
            // Not detected yet: nothing here can tell a portal from the network.
            captive_portal: false,
            configuration_error: self.configuration_error.clone(),
        }
    }

    async fn reach(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
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
        let Some(origin) = credentials.measure_origin.clone() else {
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
        let jobs: Vec<_> = chosen
            .iter()
            .zip(ports)
            .filter_map(|(profile, port)| {
                match probe_job(profile, &endpoint, &credentials, port) {
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
        let (endpoint, credentials) = self.credentials(endpoint).await.map_err(configuration)?;
        let origin = credentials.measure_origin.clone();
        let plan = plan_tunnel(profile, &endpoint, &credentials, &self.rules)
            .map_err(FailureCause::from)?;
        drop(credentials);

        self.tunnels.start(&plan).await?;
        self.set_carrying(origin);
        Ok(())
    }

    async fn stop_tunnel(&self) {
        self.set_carrying(None);
        self.tunnels.stop().await;
    }

    async fn live_check(&self, _profile: &ProfileId) -> LiveCheck {
        match self.carrying_origin() {
            Some(origin) => checks::live_check(&origin).await,
            None => LiveCheck::Failed,
        }
    }

    async fn probe_endpoint(&self, _endpoint: EndpointId) -> EndpointProbeOutcome {
        match self.carrying_origin() {
            Some(origin) => checks::endpoint_probe(&origin).await,
            None => EndpointProbeOutcome::Failed,
        }
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
