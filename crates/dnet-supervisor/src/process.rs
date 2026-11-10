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

/// Longest output line kept, in bytes. The rest of a longer line is read and dropped.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Forward one output stream to tracing, firing the readiness signal on the marker.
///
/// The stream is read to its end whatever it holds. A reader that stopped early (at a line that is
/// not UTF-8, say) would leave the pipe to fill, and a core blocked writing to a full pipe stops
/// working while it still looks alive. Lines are cut at [`MAX_LINE_BYTES`] so a core cannot make the
/// service hold an unbounded line, and bytes that are not UTF-8 are replaced, not refused.
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
        let on_line = |bytes: &[u8]| {
            let line = String::from_utf8_lossy(bytes.strip_suffix(b"\r").unwrap_or(bytes));
            // `trace`, not `debug`: what a core prints includes the places the user is connecting
            // to, and `debug` is what gets switched on when something needs diagnosing. Those
            // names must not reach a log by that route (FR-035); asking for `trace` is deliberate.
            tracing::trace!(?core, stream, "{line}");
            if marker.as_deref().is_some_and(|m| line.contains(m)) {
                if let Some(tx) = signal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = tx.send(());
                }
            }
        };
        for_each_line(reader, on_line).await;
    });
}

/// Call `on_line` with each line of `reader` (without its line ending), cut at [`MAX_LINE_BYTES`],
/// until the stream ends or fails. A last line without an ending counts.
async fn for_each_line<R>(reader: R, mut on_line: impl FnMut(&[u8]))
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    while let Ok(buffer) = reader.fill_buf().await {
        if buffer.is_empty() {
            if !line.is_empty() {
                on_line(&line);
            }
            break;
        }
        let end = buffer.iter().position(|&b| b == b'\n');
        let chunk = &buffer[..end.unwrap_or(buffer.len())];
        let room = MAX_LINE_BYTES.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let used = end.map_or(buffer.len(), |i| i + 1);
        reader.consume(used);
        if end.is_some() {
            on_line(&line);
            line.clear();
        }
    }
}

/// Only one process is started at a time, by anything in this crate (the service, and the tests that start stand-ins).
///
/// On Windows a new process inherits every inheritable handle its parent holds at that moment, and the write end of
/// another child's output pipe is one for a short while after it is made. Two spawns at once can therefore hand the
/// second child the first's pipe: the first child's output then never ends while the second lives, and whatever reads
/// it (a task on the runtime's blocking pool) cannot finish. Seen as a test run that hung for as long as a
/// sixty-second stand-in lived (T190, found with gdb: both blocking readers parked in a pipe read, no child left).
/// Starting one at a time closes that window.
pub(crate) fn spawning() -> std::sync::MutexGuard<'static, ()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    let started = {
        let _one_at_a_time = spawning();
        cmd.spawn()
    };
    let mut child = started.map_err(|e| SupervisorError::Spawn {
        core: command.core,
        detail: e.to_string(),
    })?;
    // A core must not outlive the service even if the service is killed or crashes (T163).
    #[cfg(windows)]
    if let Some(process) = child.raw_handle() {
        crate::job::bind_to_service_lifetime(
            windows::Win32::Foundation::HANDLE(process),
            &format!("{:?}", command.core),
        );
    }

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

    /// A spawned core is in the service's job, so the system ends it when the service's process ends.
    #[tokio::test]
    async fn a_spawned_core_is_held_by_the_services_job() {
        let core = spawn(&cmd("Start-Sleep -Seconds 60", None)).unwrap();
        let process = core.child.raw_handle().expect("a running process");
        assert!(crate::job::service_job_holds(
            windows::Win32::Foundation::HANDLE(process)
        ));
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

#[cfg(test)]
mod line_tests {
    use super::*;

    async fn lines_of(input: &[u8]) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        for_each_line(input, |line| seen.push(line.to_vec())).await;
        seen
    }

    #[tokio::test]
    async fn lines_are_split_at_their_endings_and_a_last_unended_line_counts() {
        assert_eq!(
            lines_of(b"one\ntwo\r\nthree").await,
            [b"one".to_vec(), b"two\r".to_vec(), b"three".to_vec()]
        );
        assert!(lines_of(b"").await.is_empty());
    }

    #[tokio::test]
    async fn bytes_that_are_not_utf8_are_passed_on_not_a_reason_to_stop() {
        assert_eq!(
            lines_of(b"\xff\xfe\nnext\n").await,
            [b"\xff\xfe".to_vec(), b"next".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_long_line_is_cut_and_the_next_line_is_whole() {
        let mut input = vec![b'y'; MAX_LINE_BYTES * 3];
        input.extend_from_slice(b"\nafter\n");
        let lines = lines_of(&input).await;
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), MAX_LINE_BYTES);
        assert_eq!(lines[1], b"after");
    }
}

/// The same lifecycle on a Unix shell, so the spawning and output handling are exercised off
/// Windows too (the Linux build is kept clean, and CI's coverage runs on both).
#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    fn sh(script: &str, marker: Option<&str>) -> CoreCommand {
        CoreCommand {
            core: CoreBinding::PrimaryCore,
            program: PathBuf::from("/bin/sh"),
            args: ["-c", script].iter().map(OsString::from).collect(),
            working_dir: None,
            ready_marker: marker.map(str::to_string),
            ready_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn a_readiness_marker_on_stdout_completes_the_wait() {
        let mut core = spawn(&sh("echo 'core started'; sleep 60", Some("started"))).unwrap();
        assert!(core.id().is_some());
        assert_eq!(core.core(), CoreBinding::PrimaryCore);
        core.wait_ready(Duration::from_secs(10)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
        assert!(core.try_exited().is_some());
    }

    #[tokio::test]
    async fn a_readiness_marker_on_stderr_counts_too() {
        let mut core = spawn(&sh("echo 'core started' >&2; sleep 60", Some("started"))).unwrap();
        core.wait_ready(Duration::from_secs(10)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn an_exit_before_the_marker_is_not_ready_not_a_hang() {
        let mut core = spawn(&sh("echo nope", Some("started"))).unwrap();
        let err = core.wait_ready(Duration::from_secs(10)).await.unwrap_err();
        assert!(err.to_string().contains("exited before"), "{err}");
    }

    #[tokio::test]
    async fn a_silent_core_times_out() {
        let mut core = spawn(&sh("sleep 60", Some("started"))).unwrap();
        let err = core
            .wait_ready(Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no readiness signal"), "{err}");
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn without_a_marker_a_running_core_is_ready_and_one_that_exited_is_not() {
        let mut running = spawn(&sh("sleep 60", None)).unwrap();
        running.wait_ready(Duration::from_secs(1)).await.unwrap();
        running.kill(Duration::from_secs(5)).await.unwrap();

        let mut gone = spawn(&sh("exit 3", None)).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while gone.try_exited().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let err = gone.wait_ready(Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("exited immediately"), "{err}");
    }

    #[tokio::test]
    async fn killing_a_core_that_already_exited_is_fine() {
        let mut core = spawn(&sh("exit 0", None)).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn a_missing_binary_is_a_spawn_error() {
        let mut c = sh("", None);
        c.program = PathBuf::from("/definitely/not/here/core");
        assert!(matches!(spawn(&c), Err(SupervisorError::Spawn { .. })));
    }

    #[tokio::test]
    async fn the_working_directory_is_the_one_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = sh("pwd; sleep 60", None);
        c.working_dir = Some(dir.path().to_path_buf());
        c.ready_marker = Some(
            dir.path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        let mut core = spawn(&c).unwrap();
        core.wait_ready(Duration::from_secs(10)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    /// A line that is not UTF-8 is still output. Reading must carry on past it, or the marker
    /// after it is never seen.
    #[tokio::test]
    async fn output_that_is_not_utf8_does_not_hide_the_marker_after_it() {
        let mut core = spawn(&sh(
            r"printf 'bad \377\376 bytes\n'; echo 'core started'; sleep 60",
            Some("started"),
        ))
        .unwrap();
        core.wait_ready(Duration::from_secs(10)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    /// The output is drained for as long as the core runs. A reader that stops leaves the pipe to
    /// fill, and a core blocked writing to a full pipe stops working while it still looks alive.
    #[tokio::test]
    async fn output_is_drained_past_a_bad_line_so_the_core_never_blocks_on_it() {
        // About 1 MB after the bad line: far more than a pipe holds.
        let mut core = spawn(&sh(
            r"printf '\377\n'; i=0; while [ $i -lt 16384 ]; do echo 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; i=$((i+1)); done; echo 'core started'; sleep 60",
            Some("started"),
        ))
        .unwrap();
        core.wait_ready(Duration::from_secs(20)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
    }

    /// A line with no end is cut, not held whole: a core cannot make the service hold an
    /// unbounded line in memory. The marker on the next line is still found.
    #[tokio::test]
    async fn an_endless_line_is_cut_and_reading_carries_on() {
        let mut core = spawn(&sh(
            r"head -c 3000000 /dev/zero | tr '\0' 'y'; echo; echo 'core started'; sleep 60",
            Some("started"),
        ))
        .unwrap();
        core.wait_ready(Duration::from_secs(20)).await.unwrap();
        core.kill(Duration::from_secs(5)).await.unwrap();
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    /// The cap is a documented number, not whatever its arithmetic happens to give.
    #[test]
    fn a_line_is_cut_at_eight_kilobytes() {
        assert_eq!(MAX_LINE_BYTES, 8192);
    }

    #[tokio::test]
    async fn a_line_of_exactly_the_limit_is_kept_whole_and_one_more_byte_is_dropped() {
        for (length, kept) in [
            (8191usize, 8191usize),
            (8192, 8192),
            (8193, 8192),
            (20_000, 8192),
        ] {
            let mut input = vec![b'z'; length];
            input.push(b'\n');
            let mut lines = Vec::new();
            for_each_line(&input[..], |l| lines.push(l.len())).await;
            assert_eq!(lines, [kept], "a line of {length} bytes");
        }
    }
}
