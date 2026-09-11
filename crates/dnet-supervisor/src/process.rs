//! T043 (OS half) — real child spawning with captured stdio and readiness (SUP-01, SUP-06).
//!
//! A core is spawned with stdin closed and stdout/stderr piped. Output is forwarded to
//! `tracing` at debug level for diagnostics and scanned for an optional readiness
//! marker; it is never echoed raw to the user. Readiness is bounded by a timeout, and an
//! early exit is reported distinctly from a timeout (`child::await_ready`).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnet_core::profile::CoreBinding;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::child::{await_ready, ReadyError};
use crate::error::SupervisorError;

/// Windows `CREATE_NO_WINDOW`: the service has no console, and a core must not get one.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How to launch one supervised core.
#[derive(Debug, Clone)]
pub struct CoreCommand {
    pub core: CoreBinding,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub working_dir: Option<PathBuf>,
    /// A substring of an output line that means "ready". `None` means readiness is
    /// established externally (e.g. the AmneziaWG UAPI pipe appearing), so the process
    /// only has to survive the spawn.
    pub ready_marker: Option<String>,
    pub ready_timeout: Duration,
}

/// A running core.
pub struct RunningCore {
    core: CoreBinding,
    child: Child,
    ready: Option<oneshot::Receiver<()>>,
}

type ReadySignal = Arc<Mutex<Option<oneshot::Sender<()>>>>;

/// Forward one output stream to tracing, firing the readiness signal on the marker.
fn forward_output<R>(
    core: CoreBinding,
    stream: &'static str,
    reader: R,
    marker: Option<String>,
    signal: ReadySignal,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(?core, stream, "{line}");
            if marker.as_deref().is_some_and(|m| line.contains(m)) {
                if let Some(tx) = signal.lock().expect("ready signal mutex poisoned").take() {
                    let _ = tx.send(());
                }
            }
        }
    });
}

/// Spawn a core. Readiness is awaited separately with [`RunningCore::wait_ready`].
pub fn spawn(command: &CoreCommand) -> Result<RunningCore, SupervisorError> {
    let mut cmd = Command::new(&command.program);
    cmd.args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A dropped handle must never leave a core running behind dnetd's back.
        .kill_on_drop(true);
    if let Some(dir) = &command.working_dir {
        cmd.current_dir(dir);
    }
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().map_err(|e| SupervisorError::Spawn {
        core: command.core,
        detail: e.to_string(),
    })?;

    let (tx, rx) = oneshot::channel();
    let signal: ReadySignal = Arc::new(Mutex::new(Some(tx)));
    if let Some(stdout) = child.stdout.take() {
        forward_output(
            command.core,
            "stdout",
            stdout,
            command.ready_marker.clone(),
            signal.clone(),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        forward_output(
            command.core,
            "stderr",
            stderr,
            command.ready_marker.clone(),
            signal,
        );
    }

    Ok(RunningCore {
        core: command.core,
        child,
        ready: command.ready_marker.as_ref().map(|_| rx),
    })
}

impl RunningCore {
    pub fn core(&self) -> CoreBinding {
        self.core
    }

    /// The OS process id, while the process is running.
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Wait for the readiness marker, failing on timeout or early exit (SUP-06). With no
    /// marker, only checks that the process has not already exited.
    pub async fn wait_ready(&mut self, timeout: Duration) -> Result<(), SupervisorError> {
        let core = self.core;
        let not_ready = |detail: String| SupervisorError::NotReady { core, detail };

        let Some(ready) = self.ready.take() else {
            return match self.child.try_wait() {
                Ok(Some(status)) => Err(not_ready(format!("exited immediately ({status})"))),
                Ok(None) => Ok(()),
                Err(e) => Err(not_ready(e.to_string())),
            };
        };

        let child = &mut self.child;
        let outcome = async move {
            tokio::select! {
                signalled = ready => signalled.is_ok(),
                _ = child.wait() => false,
            }
        };
        await_ready(outcome, timeout).await.map_err(|e| match e {
            ReadyError::Timeout(t) => not_ready(format!("no readiness signal within {t:?}")),
            ReadyError::Exited => not_ready("exited before signalling ready".into()),
        })
    }

    /// Non-blocking exit check.
    pub fn try_exited(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Terminate the process and wait up to `grace` for it to exit.
    pub async fn kill(&mut self, grace: Duration) -> Result<(), SupervisorError> {
        if self.try_exited().is_some() {
            return Ok(());
        }
        self.child
            .start_kill()
            .map_err(|e| SupervisorError::Runtime(format!("killing {:?}: {e}", self.core)))?;
        match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(SupervisorError::Runtime(format!(
                "waiting for {:?}: {e}",
                self.core
            ))),
            Err(_) => Err(SupervisorError::Runtime(format!(
                "{:?} did not exit within {grace:?} of being killed",
                self.core
            ))),
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// A stand-in core: one PowerShell process running `script`. A single process (not
    /// `cmd /C a && b`) so killing it leaves no grandchild behind.
    fn cmd(script: &str, marker: Option<&str>) -> CoreCommand {
        CoreCommand {
            core: CoreBinding::PrimaryCore,
            program: PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            args: ["-NoProfile", "-NonInteractive", "-Command", script]
                .iter()
                .map(OsString::from)
                .collect(),
            working_dir: None,
            ready_marker: marker.map(str::to_string),
            ready_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn a_readiness_marker_on_stdout_completes_the_wait() {
        let mut core = spawn(&cmd(
            "Write-Output 'core started'; Start-Sleep -Seconds 60",
            Some("started"),
        ))
        .unwrap();
        core.wait_ready(Duration::from_secs(30)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
        assert!(core.try_exited().is_some());
    }

    #[tokio::test]
    async fn an_exit_before_the_marker_is_not_ready_not_a_hang() {
        let mut core = spawn(&cmd("Write-Output 'nope'", Some("started"))).unwrap();
        let err = core.wait_ready(Duration::from_secs(30)).await.unwrap_err();
        assert!(matches!(err, SupervisorError::NotReady { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_silent_core_times_out() {
        let mut core = spawn(&cmd("Start-Sleep -Seconds 60", Some("started"))).unwrap();
        let err = core
            .wait_ready(Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no readiness signal"), "{err}");
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn a_missing_binary_is_a_spawn_error() {
        let mut c = cmd("", None);
        c.program = PathBuf::from(r"C:\definitely\not\here\core.exe");
        assert!(matches!(spawn(&c), Err(SupervisorError::Spawn { .. })));
    }
}
