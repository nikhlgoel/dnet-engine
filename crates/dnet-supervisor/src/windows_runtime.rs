//! The real `CoreRuntime` on Windows.
//!
//! - **reap** — `orphans::reap` over both supervised binaries' full image paths.
//! - **spawn** — `process::spawn` + readiness wait, holding the handle until killed.
//! - **await adapter** — the AmneziaWG core's UAPI pipe appearing is the adapter-exists
//!   signal (the core opens the pipe only after `CreateTUN` succeeds).
//! - **kill** — terminate and wait, with a grace period.
//! - **undo replay** — delegated to a hook. The undo registry itself is T037; until it
//!   lands, the caller supplies the restoration it owns (e.g. host-route removal).

#![cfg(windows)]

use std::collections::HashMap;
use std::time::Duration;

use dnet_config::uapi_pipe;
use dnet_core::profile::CoreBinding;
use tokio::sync::Mutex;

use crate::error::SupervisorError;
use crate::orphans;
use crate::process::{self, CoreCommand, RunningCore};
use crate::runtime::{CoreHealth, CoreRuntime};

/// How long a killed core gets to exit before the kill is reported as failed.
pub const KILL_GRACE: Duration = Duration::from_secs(10);

/// The restoration hook run by `replay_undo`.
pub type UndoHook = Box<dyn Fn() -> Result<(), SupervisorError> + Send + Sync>;

/// Supervises the two real core processes.
pub struct WindowsCoreRuntime {
    primary: CoreCommand,
    amneziawg: CoreCommand,
    adapter: String,
    adapter_timeout: Duration,
    running: Mutex<HashMap<CoreBinding, RunningCore>>,
    undo: UndoHook,
}

impl WindowsCoreRuntime {
    pub fn new(
        primary: CoreCommand,
        amneziawg: CoreCommand,
        adapter: impl Into<String>,
        adapter_timeout: Duration,
        undo: UndoHook,
    ) -> Self {
        Self {
            primary,
            amneziawg,
            adapter: adapter.into(),
            adapter_timeout,
            running: Mutex::new(HashMap::new()),
            undo,
        }
    }

    fn command(&self, core: CoreBinding) -> &CoreCommand {
        match core {
            CoreBinding::PrimaryCore => &self.primary,
            CoreBinding::AmneziaWgCore => &self.amneziawg,
        }
    }

    /// The process id of a running core, for diagnostics and the spike report.
    pub async fn pid(&self, core: CoreBinding) -> Option<u32> {
        self.running
            .lock()
            .await
            .get(&core)
            .and_then(RunningCore::id)
    }

    /// Whether a supervised core has exited on its own (crash detection).
    pub async fn has_exited(&self, core: CoreBinding) -> bool {
        match self.running.lock().await.get_mut(&core) {
            Some(running) => running.try_exited().is_some(),
            None => true,
        }
    }
}

impl CoreRuntime for WindowsCoreRuntime {
    async fn core_pid(&self, core: CoreBinding) -> Option<u32> {
        self.pid(core).await
    }

    async fn reap_orphans(&self) -> Result<(), SupervisorError> {
        let images = [self.primary.program.clone(), self.amneziawg.program.clone()];
        let reaped = orphans::reap(&images)?;
        if !reaped.is_empty() {
            tracing::warn!(?reaped, "orphaned cores terminated before start");
        }
        Ok(())
    }

    async fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        let command = self.command(core);
        let mut running = process::spawn(command)?;
        running.wait_ready(command.ready_timeout).await?;
        tracing::info!(?core, pid = ?running.id(), "core started");
        self.running.lock().await.insert(core, running);
        Ok(())
    }

    async fn await_adapter(&self) -> Result<(), SupervisorError> {
        let pipe = uapi_pipe::pipe_path(&self.adapter);
        uapi_pipe::wait_for_pipe(&pipe, self.adapter_timeout)
            .await
            .map_err(|e| SupervisorError::NotReady {
                core: CoreBinding::AmneziaWgCore,
                detail: format!("adapter {:?} not available: {e}", self.adapter),
            })?;
        tracing::info!(adapter = %self.adapter, "AmneziaWG adapter is up");
        Ok(())
    }

    async fn core_health(&self, core: CoreBinding) -> CoreHealth {
        match self.running.lock().await.get_mut(&core) {
            None => CoreHealth::Unknown,
            // The core stays in the map after it ends by itself, so the next reading says so too; it is
            // taken out only by `kill_core`, which is a stop on purpose.
            Some(running) => match running.try_exited() {
                Some(status) => CoreHealth::Exited {
                    code: status.code(),
                },
                None => CoreHealth::Running,
            },
        }
    }

    async fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
        let taken = self.running.lock().await.remove(&core);
        match taken {
            Some(mut running) => {
                running.kill(KILL_GRACE).await?;
                tracing::info!(?core, "core stopped");
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn replay_undo(&self) -> Result<(), SupervisorError> {
        (self.undo)()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::*;
    use crate::runtime::CoreHealth;

    fn cmd(script: &str, core: CoreBinding) -> CoreCommand {
        CoreCommand {
            core,
            program: PathBuf::from("cmd.exe"),
            args: ["/c", script].iter().map(OsString::from).collect(),
            working_dir: None,
            ready_marker: None,
            ready_timeout: Duration::from_secs(5),
        }
    }

    fn runtime(primary: &str) -> WindowsCoreRuntime {
        WindowsCoreRuntime::new(
            cmd(primary, CoreBinding::PrimaryCore),
            cmd("exit 0", CoreBinding::AmneziaWgCore),
            "dnet-test",
            Duration::from_secs(1),
            Box::new(|| Ok(())),
        )
    }

    #[tokio::test]
    async fn a_core_that_was_never_started_is_not_spoken_for() {
        let rt = runtime("exit 0");
        assert_eq!(
            rt.core_health(CoreBinding::PrimaryCore).await,
            CoreHealth::Unknown
        );
    }

    #[tokio::test]
    async fn a_running_core_is_running_and_a_stopped_one_is_not_spoken_for() {
        let rt = runtime("ping -n 30 127.0.0.1 > nul");
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        assert_eq!(
            rt.core_health(CoreBinding::PrimaryCore).await,
            CoreHealth::Running
        );
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
        assert_eq!(
            rt.core_health(CoreBinding::PrimaryCore).await,
            CoreHealth::Unknown
        );
    }

    #[tokio::test]
    async fn a_core_that_exits_on_its_own_is_reported_with_its_exit_code() {
        // Alive for about two seconds (so spawning sees it survive, even on a slow machine), then exits with 3.
        let rt = runtime("ping -n 3 127.0.0.1 > nul & exit 3");
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        assert_eq!(
            rt.core_health(CoreBinding::PrimaryCore).await,
            CoreHealth::Running
        );
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(
            rt.core_health(CoreBinding::PrimaryCore).await,
            CoreHealth::Exited { code: Some(3) }
        );
    }
}

/// What the mutation run found the first tests did not pin: the process id the runtime reports, whether it
/// notices an exit, that it reaps what was left behind, and that the adapter wait and the undo replay do
/// what their names say and report what went wrong.
#[cfg(all(test, windows))]
mod pinned_tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use super::*;

    fn cmd(program: &str, script: &str, core: CoreBinding) -> CoreCommand {
        CoreCommand {
            core,
            program: PathBuf::from(program),
            args: ["/c", script].iter().map(OsString::from).collect(),
            working_dir: None,
            ready_marker: None,
            ready_timeout: Duration::from_secs(5),
        }
    }

    fn runtime(primary: &str) -> WindowsCoreRuntime {
        WindowsCoreRuntime::new(
            cmd("cmd.exe", primary, CoreBinding::PrimaryCore),
            cmd(
                "dnet-never-runs-1.exe",
                "exit 0",
                CoreBinding::AmneziaWgCore,
            ),
            "dnet-test-adapter",
            Duration::from_millis(300),
            Box::new(|| Ok(())),
        )
    }

    /// The image name of a running process, from the system's own task list.
    fn image_of(pid: u32) -> String {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .expect("tasklist is part of Windows");
        String::from_utf8_lossy(&out.stdout).to_lowercase()
    }

    // ---------------------------------------------------------------- the process id

    #[tokio::test]
    async fn the_id_reported_is_the_id_of_the_process_that_was_started() {
        let rt = runtime("ping -n 30 127.0.0.1 > nul");
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        let pid = rt
            .pid(CoreBinding::PrimaryCore)
            .await
            .expect("a running core has an id");
        assert!(
            pid > 4,
            "{pid} is not a plausible process id (0 and 4 belong to the system)"
        );
        assert!(
            image_of(pid).contains("cmd.exe"),
            "{pid}: {}",
            image_of(pid)
        );
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
    }

    #[tokio::test]
    async fn the_runtime_trait_gives_the_same_id_as_the_runtime() {
        let rt = runtime("ping -n 30 127.0.0.1 > nul");
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        let direct = rt.pid(CoreBinding::PrimaryCore).await;
        assert!(direct.is_some());
        assert_eq!(
            CoreRuntime::core_pid(&rt, CoreBinding::PrimaryCore).await,
            direct
        );
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
    }

    #[tokio::test]
    async fn a_core_that_was_never_started_or_was_stopped_has_no_id() {
        let rt = runtime("ping -n 30 127.0.0.1 > nul");
        assert_eq!(rt.pid(CoreBinding::PrimaryCore).await, None);
        assert_eq!(
            CoreRuntime::core_pid(&rt, CoreBinding::PrimaryCore).await,
            None
        );
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
        assert_eq!(rt.pid(CoreBinding::PrimaryCore).await, None);
        assert_eq!(
            CoreRuntime::core_pid(&rt, CoreBinding::PrimaryCore).await,
            None
        );
    }

    #[tokio::test]
    async fn each_core_has_its_own_id() {
        let rt = WindowsCoreRuntime::new(
            cmd(
                "cmd.exe",
                "ping -n 30 127.0.0.1 > nul",
                CoreBinding::PrimaryCore,
            ),
            cmd(
                "cmd.exe",
                "ping -n 30 127.0.0.1 > nul",
                CoreBinding::AmneziaWgCore,
            ),
            "dnet-test-adapter",
            Duration::from_millis(300),
            Box::new(|| Ok(())),
        );
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        rt.spawn_core(CoreBinding::AmneziaWgCore).await.unwrap();
        let a = rt.pid(CoreBinding::PrimaryCore).await.unwrap();
        let b = rt.pid(CoreBinding::AmneziaWgCore).await.unwrap();
        assert_ne!(a, b);
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
        assert!(
            rt.pid(CoreBinding::AmneziaWgCore).await.is_some(),
            "stopping one leaves the other"
        );
        rt.kill_core(CoreBinding::AmneziaWgCore).await.unwrap();
    }

    // ---------------------------------------------------------------- noticing an exit

    #[tokio::test]
    async fn a_running_core_has_not_exited_and_an_unknown_one_counts_as_exited() {
        let rt = runtime("ping -n 30 127.0.0.1 > nul");
        assert!(
            rt.has_exited(CoreBinding::PrimaryCore).await,
            "never started"
        );
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        assert!(!rt.has_exited(CoreBinding::PrimaryCore).await, "running");
        rt.kill_core(CoreBinding::PrimaryCore).await.unwrap();
        assert!(
            rt.has_exited(CoreBinding::PrimaryCore).await,
            "stopped on purpose"
        );
    }

    #[tokio::test]
    async fn a_core_that_ends_by_itself_is_noticed() {
        let rt = runtime("ping -n 3 127.0.0.1 > nul & exit 0");
        rt.spawn_core(CoreBinding::PrimaryCore).await.unwrap();
        assert!(!rt.has_exited(CoreBinding::PrimaryCore).await);
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(rt.has_exited(CoreBinding::PrimaryCore).await);
    }

    // ---------------------------------------------------------------- reaping what was left behind

    /// A uniquely named copy of this test binary, started as a sleeper, stands for a core left running by
    /// a service that crashed.
    fn start_orphan(dir: &std::path::Path, tag: &str) -> (PathBuf, std::process::Child) {
        let image = dir.join(format!(
            "dnet-runtime-orphan-{tag}-{}.exe",
            std::process::id()
        ));
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        let child = std::process::Command::new(&image)
            .args([
                "--ignored",
                "--exact",
                "orphans::tests::orphan_probe_sleeper",
            ])
            .env("DNET_ORPHAN_PROBE", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        (image, child)
    }

    #[tokio::test]
    async fn a_core_left_running_by_a_crashed_service_is_ended_before_anything_starts() {
        let dir = tempfile::tempdir().unwrap();
        let (image, mut orphan) = start_orphan(dir.path(), "a");
        let rt = WindowsCoreRuntime::new(
            CoreCommand {
                program: image,
                ..cmd("cmd.exe", "exit 0", CoreBinding::PrimaryCore)
            },
            cmd(
                "dnet-never-runs-2.exe",
                "exit 0",
                CoreBinding::AmneziaWgCore,
            ),
            "dnet-test-adapter",
            Duration::from_millis(300),
            Box::new(|| Ok(())),
        );
        // The process list may lag the start by a moment.
        for _ in 0..50 {
            if orphan.try_wait().unwrap().is_some() {
                panic!("the sleeper ended by itself");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            if crate::orphans::find_by_image(std::slice::from_ref(&rt.primary.program))
                .unwrap()
                .len()
                == 1
            {
                break;
            }
        }
        rt.reap_orphans().await.unwrap();
        let status = orphan.wait().unwrap();
        assert!(!status.success(), "it was ended, not left to finish");
    }

    #[tokio::test]
    async fn reaping_when_nothing_was_left_is_quiet_success() {
        let rt = runtime("exit 0");
        rt.reap_orphans().await.unwrap();
    }

    // ---------------------------------------------------------------- the adapter and the undo

    /// There is no such adapter pipe, so waiting for it fails after the time given, and the failure
    /// names the adapter and the core that needed it.
    #[tokio::test]
    async fn waiting_for_an_adapter_that_never_appears_fails_naming_it() {
        let rt = runtime("exit 0");
        match rt.await_adapter().await {
            Err(SupervisorError::NotReady { core, detail }) => {
                assert_eq!(core, CoreBinding::AmneziaWgCore);
                assert!(detail.contains("dnet-test-adapter"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn the_undo_replay_runs_the_undo_and_hands_back_its_answer() {
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let rt = WindowsCoreRuntime::new(
            cmd("cmd.exe", "exit 0", CoreBinding::PrimaryCore),
            cmd(
                "dnet-never-runs-3.exe",
                "exit 0",
                CoreBinding::AmneziaWgCore,
            ),
            "dnet-test-adapter",
            Duration::from_millis(300),
            Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                Err(SupervisorError::Runtime(
                    "the table would not change".into(),
                ))
            }),
        );
        let error = rt.replay_undo().await.unwrap_err().to_string();
        assert!(error.contains("would not change"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // And again: each replay is a fresh run.
        let _ = rt.replay_undo().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_undo_that_succeeds_is_success_and_still_runs() {
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let rt = WindowsCoreRuntime::new(
            cmd("cmd.exe", "exit 0", CoreBinding::PrimaryCore),
            cmd(
                "dnet-never-runs-4.exe",
                "exit 0",
                CoreBinding::AmneziaWgCore,
            ),
            "dnet-test-adapter",
            Duration::from_millis(300),
            Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        rt.replay_undo().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
