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
