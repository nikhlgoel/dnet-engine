//! The real prober: one core process per probe, raced.
//!
//! [`Prober::probe_one`] writes a probe configuration (`dnet_config::probe`), spawns the primary
//! core against it, waits for it to say it has started, measures a transfer through its loopback
//! SOCKS port (`measure`), and stops it. [`Prober::race`] does that for several profiles at once
//! and returns the decision.
//!
//! **Credentials on disk.** A probe configuration contains the profile's secrets, so:
//! - it is written to a **randomly named file created exclusively** (`create_new`), so an
//!   attacker cannot predict the name, pre-create it, or redirect it with a link, and an existing
//!   file is never overwritten or deleted;
//! - it is **deleted as soon as the core reports ready** (the core has read it by then), and on
//!   every other path too: failure to spawn, failure to become ready, and cancellation of a lost
//!   race, because a guard removes it when the probe's future is dropped;
//! - [`Prober::sweep_stale`] removes any left behind by a crash, which no guard can cover, and
//!   `dnetd` should call it at start;
//! - `work_dir` must be readable only by the account running the daemon (`dnetd` passes its
//!   restricted run directory).
//!
//! **The proxy is not open.** Each probe's SOCKS inbound demands a random username and password,
//! generated per probe and never logged, so another local process can neither use the proxy as a
//! relay into the user's endpoint nor answer in its place.
//!
//! Every outcome that is not a measured transfer reads as a failed profile; the reason is logged
//! at debug level, never shown raw to the user.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dnet_config::probe::{generate_probe_config, to_json, ProbeInput, SocksAuth};
use dnet_config::secret::Secret;
use dnet_config::{ActiveEndpointBypass, ConfigError, PrimaryTransport};
use dnet_core::ids::ProfileId;
use dnet_core::probe::ProfileProbe;
use dnet_core::profile::{ConnectionProfile, CoreBinding};
use dnet_supervisor::process::{self, CoreCommand};

use crate::measure::{measure_via_proxy, MeasureConfig, Origin};
use crate::race::{race_with, RaceReport};
use crate::socks5::Credentials;

/// How long a probe core may take to print its readiness marker.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a stopped probe core gets to exit.
const KILL_GRACE: Duration = Duration::from_secs(3);

/// One profile to probe, with everything it needs: its configuration, its loopback port and the
/// credentials its proxy demands.
#[derive(Clone)]
pub struct ProbeJob {
    profile: ConnectionProfile,
    /// The probe configuration. Contains credentials, so this type's `Debug` shows none of it.
    config_json: String,
    socks_port: u16,
    credentials: Credentials,
}

impl ProbeJob {
    /// Build a job for `profile` against `endpoint`, with its SOCKS proxy on `socks_port`
    /// (see [`free_loopback_ports`]). Generates the proxy's random credentials and the
    /// configuration that demands them, so the two cannot disagree.
    pub fn new(
        profile: ConnectionProfile,
        endpoint: &ActiveEndpointBypass,
        transport: PrimaryTransport<'_>,
        socks_port: u16,
    ) -> Result<Self, ConfigError> {
        let credentials = Credentials {
            username: random_token(),
            password: random_token(),
        };
        let auth = SocksAuth {
            username: credentials.username.clone(),
            password: Secret::new(credentials.password.clone()),
        };
        let config = generate_probe_config(ProbeInput {
            socks_auth: &auth,
            profile: &profile,
            endpoint,
            transport: Some(transport),
            socks_port,
        })?;
        Ok(Self {
            profile,
            config_json: to_json(&config),
            socks_port,
            credentials,
        })
    }

    pub fn profile(&self) -> &ConnectionProfile {
        &self.profile
    }

    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    #[cfg(test)]
    fn for_tests(id: &str, secret: &str, socks_port: u16) -> Self {
        use dnet_core::profile::{ProfileKind, ProfileParams};
        Self {
            profile: ConnectionProfile::new(
                ProfileId::new(id),
                ProfileKind::Hysteria2,
                ProfileParams::new(),
            ),
            config_json: format!("{{\"password\": \"{secret}\"}}"),
            socks_port,
            credentials: Credentials {
                username: "u-test".into(),
                password: "p-test".into(),
            },
        }
    }
}

impl std::fmt::Debug for ProbeJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeJob")
            .field("profile", self.profile.id())
            .field("socks_port", &self.socks_port)
            .field("config_json", &"<redacted>")
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// A fresh unguessable token: a version-4 UUID, 122 random bits from the OS random source.
fn random_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Why a race could not be started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RaceError {
    /// Two jobs for one profile would share a result slot and a configuration.
    #[error("profile {0} appears twice in the race")]
    DuplicateProfile(ProfileId),
    /// Two probes cannot listen on the same port.
    #[error("two probes were given SOCKS port {0}")]
    DuplicatePort(u16),
}

/// Runs probes. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Prober {
    /// The primary core executable.
    pub core_exe: PathBuf,
    /// Where probe configurations are written. Must be private to the caller.
    pub work_dir: PathBuf,
    pub origin: Origin,
    pub measure: MeasureConfig,
    pub ready_timeout: Duration,
}

/// Deletes a probe configuration when asked, or when dropped, whatever ended the probe.
struct ConfigFile(Option<PathBuf>);

impl ConfigFile {
    fn remove(&mut self) {
        if let Some(path) = self.0.take() {
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    // The file holds credentials, so a failed delete is worth knowing about.
                    tracing::warn!(%error, "could not delete a probe configuration");
                }
            }
        }
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Create `path`, which must not exist, readable only by the owner where the platform allows.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Free loopback TCP ports, `count` of them, all distinct. Every listener is held until all the
/// ports are chosen, so two calls inside one batch cannot be handed the same port. There remains a
/// gap before a core binds its port, which is acceptable for a probe: a collision fails that one
/// probe and the race carries on.
pub fn free_loopback_ports(count: usize) -> std::io::Result<Vec<u16>> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect::<Result<Vec<_>, _>>()?;
    listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()))
        .collect()
}

/// Remove probe configurations a crashed run left in `work_dir`. Returns how many were removed.
/// For a caller that has a directory but no prober yet, such as the daemon at start-up.
pub fn sweep_stale_in(work_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(work_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("probe-") && name.ends_with(".json")
        })
        .filter(|entry| std::fs::remove_file(entry.path()).is_ok())
        .count()
}

impl Prober {
    /// Remove probe configurations a crashed run left behind. Returns how many were removed.
    /// Call it when the daemon starts.
    pub fn sweep_stale(&self) -> usize {
        sweep_stale_in(&self.work_dir)
    }

    /// Probe one profile and report what happened.
    pub async fn probe_one(&self, job: ProbeJob) -> ProfileProbe {
        let name: String = job
            .profile
            .id()
            .as_str()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self.work_dir.join(format!(
            "probe-{name}-{}-{}.json",
            job.socks_port,
            random_token()
        ));

        // `create_new` fails if anything is already there, and the guard is armed only after it
        // succeeds, so a file that was not ours is never touched. From then on the guard removes
        // the file on every path, including this future being dropped.
        let mut file = match create_private(&path) {
            Ok(file) => file,
            Err(error) => {
                tracing::debug!(%error, profile = %job.profile.id(), "could not create the probe config");
                return ProfileProbe::HandshakeFailed;
            }
        };
        let mut config = ConfigFile(Some(path.clone()));
        if let Err(error) = file
            .write_all(job.config_json.as_bytes())
            .and_then(|()| file.flush())
        {
            tracing::debug!(%error, profile = %job.profile.id(), "could not write the probe config");
            return ProfileProbe::HandshakeFailed;
        }
        drop(file);

        let command = CoreCommand {
            core: CoreBinding::PrimaryCore,
            program: self.core_exe.clone(),
            args: vec![
                OsString::from("run"),
                OsString::from("-c"),
                path.into_os_string(),
                OsString::from("--disable-color"),
            ],
            working_dir: Some(self.work_dir.clone()),
            ready_marker: Some("started".into()),
            ready_timeout: self.ready_timeout,
        };
        let mut running = match process::spawn(&command) {
            Ok(running) => running,
            Err(error) => {
                tracing::debug!(%error, profile = %job.profile.id(), "probe core did not spawn");
                return ProfileProbe::HandshakeFailed;
            }
        };
        if let Err(error) = running.wait_ready(self.ready_timeout).await {
            tracing::debug!(%error, profile = %job.profile.id(), "probe core did not become ready");
            let _ = running.kill(KILL_GRACE).await;
            return ProfileProbe::HandshakeFailed;
        }
        // The core has read its configuration. Nothing needs the credentials on disk any longer.
        config.remove();

        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, job.socks_port));
        let outcome =
            measure_via_proxy(proxy, &self.origin, &self.measure, Some(&job.credentials)).await;

        // Report now and stop the core in the background: waiting out its exit would delay the
        // race's decision by up to the kill grace, and skew when this result is timestamped.
        // `kill_on_drop` still covers the runtime shutting down first.
        tokio::spawn(async move {
            let _ = running.kill(KILL_GRACE).await;
        });
        outcome
    }

    /// Race `jobs`: probe every profile at once and decide.
    pub async fn race(&self, jobs: Vec<ProbeJob>) -> Result<RaceReport, RaceError> {
        let mut ids = HashSet::new();
        let mut ports = HashSet::new();
        for job in &jobs {
            if !ids.insert(job.profile.id().clone()) {
                return Err(RaceError::DuplicateProfile(job.profile.id().clone()));
            }
            if !ports.insert(job.socks_port) {
                return Err(RaceError::DuplicatePort(job.socks_port));
            }
        }

        let profiles: Vec<ConnectionProfile> = jobs.iter().map(|j| j.profile.clone()).collect();
        let by_id: Arc<HashMap<_, _>> = Arc::new(
            jobs.into_iter()
                .map(|job| (job.profile.id().clone(), job))
                .collect(),
        );
        let prober = self.clone();
        Ok(race_with(&profiles, move |id| {
            let prober = prober.clone();
            let job = by_id.get(&id).cloned();
            async move {
                match job {
                    Some(job) => prober.probe_one(job).await,
                    None => ProfileProbe::HandshakeFailed,
                }
            }
        })
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::probe::RaceDecision;

    fn prober(dir: &Path, core: &str) -> Prober {
        Prober {
            core_exe: dir.join(core),
            work_dir: dir.to_path_buf(),
            origin: Origin::parse("http://203.0.113.80:8080").unwrap(),
            measure: MeasureConfig {
                connect_timeout: Duration::from_secs(1),
                transfer_timeout: Duration::from_secs(1),
                bytes: 1000,
            },
            ready_timeout: Duration::from_secs(1),
        }
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// The security property: credentials never outlive the probe, even when the core never ran.
    #[tokio::test]
    async fn a_core_that_cannot_be_started_fails_the_probe_and_leaves_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let p = prober(dir.path(), "no-such-core.exe");
        let outcome = p
            .probe_one(ProbeJob::for_tests("hy2", "TOP-SECRET-VALUE", 51999))
            .await;
        assert_eq!(outcome, ProfileProbe::HandshakeFailed);
        assert!(
            leftovers(dir.path()).is_empty(),
            "{:?}",
            leftovers(dir.path())
        );
    }

    /// A planted file at the old, predictable name is neither overwritten nor deleted: the probe
    /// writes to a random name it created exclusively, and only ever removes that.
    #[tokio::test]
    async fn a_pre_existing_file_is_neither_overwritten_nor_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join("probe-hy2-51999.json");
        std::fs::write(&planted, "planted by someone else").unwrap();
        let p = prober(dir.path(), "no-such-core.exe");
        p.probe_one(ProbeJob::for_tests("hy2", "SECRET", 51999))
            .await;
        assert_eq!(
            std::fs::read_to_string(&planted).unwrap(),
            "planted by someone else"
        );
        assert_eq!(leftovers(dir.path()), ["probe-hy2-51999.json"]);
    }

    #[tokio::test]
    async fn an_unwritable_work_dir_fails_the_probe_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = prober(dir.path(), "no-such-core.exe");
        p.work_dir = dir.path().join("does").join("not").join("exist");
        assert_eq!(
            p.probe_one(ProbeJob::for_tests("hy2", "x", 51999)).await,
            ProfileProbe::HandshakeFailed
        );
    }

    /// A lost race drops the probe future mid-flight; the config must still be removed.
    #[tokio::test]
    async fn cancelling_a_probe_removes_its_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.json");
        std::fs::write(&path, "secret").unwrap();
        drop(ConfigFile(Some(path.clone())));
        assert!(!path.exists());
    }

    #[test]
    fn a_config_file_is_removed_once_and_removing_twice_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.json");
        std::fs::write(&path, "secret").unwrap();
        let mut guard = ConfigFile(Some(path.clone()));
        guard.remove();
        assert!(!path.exists());
        guard.remove();
    }

    #[test]
    fn a_batch_of_free_ports_has_no_duplicates() {
        let ports = free_loopback_ports(16).unwrap();
        assert_eq!(ports.len(), 16);
        assert_eq!(ports.iter().collect::<HashSet<_>>().len(), 16);
        assert!(ports.iter().all(|p| *p != 0));
        // They really were free: each can be bound again.
        for port in ports {
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        }
    }

    #[tokio::test]
    async fn racing_profiles_whose_cores_cannot_start_ends_with_nothing_usable() {
        let dir = tempfile::tempdir().unwrap();
        let p = prober(dir.path(), "no-such-core.exe");
        let report = p
            .race(vec![
                ProbeJob::for_tests("a", "s1", 51001),
                ProbeJob::for_tests("b", "s2", 51002),
            ])
            .await
            .unwrap();
        assert_eq!(report.decision, RaceDecision::NoneUsable);
        assert_eq!(report.results.len(), 2);
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn racing_nothing_is_nothing_usable() {
        let dir = tempfile::tempdir().unwrap();
        let report = prober(dir.path(), "x.exe").race(Vec::new()).await.unwrap();
        assert_eq!(report.decision, RaceDecision::NoneUsable);
    }

    /// Two jobs for one profile, or one port, would share a result slot, a config or a listener.
    #[tokio::test]
    async fn duplicate_profiles_or_ports_are_refused_before_anything_runs() {
        let dir = tempfile::tempdir().unwrap();
        let p = prober(dir.path(), "no-such-core.exe");
        assert_eq!(
            p.race(vec![
                ProbeJob::for_tests("a", "s", 51001),
                ProbeJob::for_tests("a", "s", 51002),
            ])
            .await
            .unwrap_err(),
            RaceError::DuplicateProfile(ProfileId::new("a"))
        );
        assert_eq!(
            p.race(vec![
                ProbeJob::for_tests("a", "s", 51001),
                ProbeJob::for_tests("b", "s", 51001),
            ])
            .await
            .unwrap_err(),
            RaceError::DuplicatePort(51001)
        );
        assert!(leftovers(dir.path()).is_empty());
    }

    /// `Debug` is what ends up in logs and panic messages.
    #[test]
    fn a_job_never_shows_its_credentials_when_debug_printed() {
        let job = ProbeJob::for_tests("hy2", "CONFIG-SECRET-VALUE", 51999);
        let shown = format!("{job:?}");
        assert!(shown.contains("hy2") && shown.contains("51999"));
        for secret in ["CONFIG-SECRET-VALUE", "u-test", "p-test"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
    }

    #[test]
    fn stale_probe_configs_are_swept_and_other_files_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "probe-a-1-x.json",
            "probe-b.json",
            "keep.json",
            "probe-c.txt",
        ] {
            std::fs::write(dir.path().join(name), "x").unwrap();
        }
        let p = prober(dir.path(), "x.exe");
        assert_eq!(p.sweep_stale(), 2);
        let mut left = leftovers(dir.path());
        left.sort();
        assert_eq!(left, ["keep.json", "probe-c.txt"]);
        assert_eq!(p.sweep_stale(), 0);
    }

    #[test]
    fn sweeping_a_missing_directory_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = prober(dir.path(), "x.exe");
        p.work_dir = dir.path().join("nope");
        assert_eq!(p.sweep_stale(), 0);
    }

    #[test]
    fn tokens_are_long_and_do_not_repeat() {
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }
}
