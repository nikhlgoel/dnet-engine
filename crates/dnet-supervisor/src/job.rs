//! T163 — the cores die with the service (audit E11; `docs/research/2026-10-31-solutions.md` section 5).
//!
//! Both cores run as SYSTEM and parse what strangers send them. `kill_on_drop` ends a core when the service
//! drops its handle, but a **crash** of the service, or a kill of its process, leaves the cores running with
//! nothing supervising them (which is why orphans are reaped at the next start). A Windows job object with
//! "kill on job close" closes that gap in the kernel: when the last handle to the job goes, which is when the
//! service's process ends however it ends, the system terminates every process in it.
//!
//! Best effort by design. A core that could not be put in the job (the service itself runs in a job that forbids
//! it, say) still runs, supervised as before, and the failure is logged: a safety net that refused to start the
//! connection would be worse than the gap it covers.

#![cfg(windows)]

use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// A job object whose processes are killed when it is closed.
pub struct KillOnClose {
    handle: HANDLE,
}

// SAFETY: a job handle is a kernel object reference that may be used from any thread.
unsafe impl Send for KillOnClose {}
// SAFETY: the same; the calls made through it are thread-safe kernel calls.
unsafe impl Sync for KillOnClose {}

impl KillOnClose {
    /// A new, empty job that kills its processes when closed.
    pub fn new() -> windows::core::Result<Self> {
        // SAFETY: no security attributes and no name: an anonymous job owned by this process.
        let handle = unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) }?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is a valid extended-limit structure, of the size given, for the class given.
        let set = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if let Err(error) = set {
            // SAFETY: `handle` was just created and is not used again.
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }
        Ok(Self { handle })
    }

    /// Put the process behind `process` in the job. From now on it ends when the job closes.
    pub fn assign(&self, process: HANDLE) -> windows::core::Result<()> {
        // SAFETY: both handles are valid; the caller keeps `process` open for the call.
        unsafe { AssignProcessToJobObject(self.handle, process) }
    }
}

impl Drop for KillOnClose {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and is closed exactly once. Closing the last handle kills the processes.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

/// The service's one job. Made on first use and never closed by the program: the kernel closes it when the
/// process ends, which is the moment the cores must die.
static SERVICE_JOB: OnceLock<Option<KillOnClose>> = OnceLock::new();

/// Put the core behind `process` in the service's job, logging (not failing) if that cannot be done.
pub fn bind_to_service_lifetime(process: HANDLE, what: &str) {
    let job = SERVICE_JOB.get_or_init(|| match KillOnClose::new() {
        Ok(job) => Some(job),
        Err(error) => {
            tracing::warn!(%error, "no job object: the cores will not die with the service");
            None
        }
    });
    if let Some(job) = job {
        if let Err(error) = job.assign(process) {
            tracing::warn!(%error, core = what, "the core could not be put in the service's job");
        }
    }
}

/// Whether the service's job holds `process`. For tests.
#[cfg(test)]
pub(crate) fn service_job_holds(process: HANDLE) -> bool {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::JobObjects::IsProcessInJob;
    let Some(Some(job)) = SERVICE_JOB.get() else {
        return false;
    };
    let mut inside = BOOL(0);
    // SAFETY: both handles are valid and `inside` is a valid out-pointer.
    unsafe { IsProcessInJob(process, job.handle, &mut inside) }.is_ok() && inside.as_bool()
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    /// A process that would run for a minute if nothing ended it.
    fn long_lived() -> Child {
        let _one_at_a_time = crate::process::spawning();
        Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("ping is part of Windows")
    }

    fn handle_of(child: &Child) -> HANDLE {
        HANDLE(child.as_raw_handle())
    }

    fn ended_within(child: &mut Child, limit: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < limit {
            if child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn a_process_in_the_job_ends_when_the_job_closes() {
        let job = KillOnClose::new().unwrap();
        let mut child = long_lived();
        job.assign(handle_of(&child)).unwrap();
        assert!(
            !ended_within(&mut child, Duration::from_millis(300)),
            "it ended before the job was closed"
        );
        drop(job);
        let ended = ended_within(&mut child, Duration::from_secs(5));
        let _ = child.kill();
        assert!(ended, "the process outlived its job");
    }

    /// The control: closing a job that does not hold the process leaves it running, so the test above is
    /// the job's doing and not the process ending by itself.
    #[test]
    fn a_process_that_is_not_in_the_job_is_not_touched_by_it() {
        let job = KillOnClose::new().unwrap();
        let mut child = long_lived();
        drop(job);
        let ended = ended_within(&mut child, Duration::from_millis(800));
        let _ = child.kill();
        assert!(!ended, "a process outside the job was ended");
    }

    #[test]
    fn two_jobs_do_not_affect_each_others_processes() {
        let (a, b) = (KillOnClose::new().unwrap(), KillOnClose::new().unwrap());
        let (mut in_a, mut in_b) = (long_lived(), long_lived());
        a.assign(handle_of(&in_a)).unwrap();
        b.assign(handle_of(&in_b)).unwrap();
        drop(a);
        assert!(ended_within(&mut in_a, Duration::from_secs(5)));
        assert!(
            !ended_within(&mut in_b, Duration::from_millis(500)),
            "closing one job ended the other's process"
        );
        let _ = in_b.kill();
        drop(b);
    }

    #[test]
    fn binding_to_the_service_lifetime_does_not_fail_the_caller_and_does_not_end_the_process() {
        let mut child = long_lived();
        bind_to_service_lifetime(handle_of(&child), "test");
        // The service's job stays open for as long as this test process lives.
        assert!(!ended_within(&mut child, Duration::from_millis(500)));
        let _ = child.kill();
    }
}
