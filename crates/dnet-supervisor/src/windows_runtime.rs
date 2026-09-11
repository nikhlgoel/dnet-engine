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
use crate::runtime::CoreRuntime;

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
