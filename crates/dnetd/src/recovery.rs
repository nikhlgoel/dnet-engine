//! T038 — restoration-on-start recovery (data-model §Cross-cutting 1, FR-029, SC-016).
//!
//! A crash leaves nobody to run the shutdown path, so at every service start `dnetd`
//! restores what a previous run left behind, **before** any core or adapter is created:
//!
//! 1. **Kill orphaned cores** (SUP-05). This must come first for the same reason shutdown
//!    kills cores before undo replay (SUP-04): an orphaned tunnel still sending while its
//!    endpoint host route is removed would loop its own packets back into the tunnel.
//! 2. **Replay the undo journal** (T037), newest record first.
//!
//! **Strict gate.** Only a fully successful recovery yields [`Recovered`], and `Recovered` is
//! the only holder of the undo registry that every routing mutation must go through. A
//! failed recovery therefore cannot initialise a tunnel, and the service refuses every
//! mutating request with the reason. It stays reachable for read-only queries so the user
//! can see why. It never retries on its own: a restart of the service retries.

use std::sync::Arc;

use dnet_netstate::undo::{UndoExecutor, UndoRecord, UndoRegistry};
use dnet_netstate::NetstateError;

/// The side effects recovery performs, in the order it performs them. The real one kills
/// processes and deletes routes; a recording fake asserts the order.
pub trait RecoveryOps {
    /// Kill cores left running by a previous run. Returns how many were killed.
    fn reap_orphan_cores(&self) -> Result<usize, String>;
    /// Open the undo journal, refusing one that is unreadable or untrusted.
    fn open_journal(&self) -> Result<UndoRegistry, NetstateError>;
    /// What reverses journal records.
    fn executor(&self) -> &dyn UndoExecutor;
}

/// Proof that the network state a previous run left has been fully restored.
///
/// Fields are private, so outside this module it can only be obtained from
/// [`recover_at_start`].
pub struct Recovered {
    undo: Arc<UndoRegistry>,
    reaped: usize,
    restored: usize,
    /// A kill-switch guard that a run which died left in the firewall, and that recovery left in on purpose.
    kept_guard: bool,
}

impl Recovered {
    /// The undo registry every routing mutation of this run must go through.
    #[allow(dead_code)] // The connect path (Phases 4-6 in dnetd) is its first caller.
    pub fn undo(&self) -> &Arc<UndoRegistry> {
        &self.undo
    }

    pub fn reaped(&self) -> usize {
        self.reaped
    }

    pub fn restored(&self) -> usize {
        self.restored
    }

    /// Whether a guard the previous run left was kept (the kill switch is on), so the service starts with the
    /// traffic still blocked until the connection is back or the person takes the guard out.
    pub fn kept_guard(&self) -> bool {
        self.kept_guard
    }

    /// A clean recovery over an empty in-memory journal, for tests of other modules.
    #[cfg(test)]
    pub fn clean_for_tests() -> Self {
        let store = dnet_netstate::undo::MemoryStore::new();
        Self {
            undo: Arc::new(UndoRegistry::open(Box::new(store)).expect("memory store opens")),
            reaped: 0,
            restored: 0,
            kept_guard: false,
        }
    }
}

/// Why recovery failed. Every variant keeps the service from connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// A core left by a previous run could not be killed.
    OrphanCores(String),
    /// The journal could not be read or was not trusted, so what needs restoring is unknown.
    JournalUnusable(String),
    /// Some recorded changes could not be reversed and are still in effect.
    Unrestored { remaining: usize, first: String },
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            RecoveryError::OrphanCores(detail) => {
                format!("a tunnel process left by a previous run could not be stopped ({detail})")
            }
            RecoveryError::JournalUnusable(detail) => format!(
                "the record of network changes from a previous run could not be used ({detail})"
            ),
            RecoveryError::Unrestored { remaining, first } => format!(
                "{remaining} network change(s) from a previous run could not be undone ({first})"
            ),
        };
        write!(
            f,
            "{what}. DNet Engine will not connect until they are restored; \
             restart the DNet Engine service to try again"
        )
    }
}

/// Restore what a previous run left, in order. See the module docs. The guard is taken out with the rest.
pub fn recover_at_start(ops: &dyn RecoveryOps) -> Result<Recovered, RecoveryError> {
    recover_at_start_keeping_the_guard(ops, false)
}

/// What the keeping executor reports for the guard's record. Replay treats a record that was not reversed as still
/// outstanding and keeps it in the journal, which is exactly what a guard left in the firewall needs.
const GUARD_KEPT: &str = "the kill-switch guard was left in on purpose";

/// Passes every record to the real executor except the kill-switch guard, which it leaves alone and remembers by
/// reporting it as not reversed: the record never leaves the journal, so no failure or crash at any point can leave a
/// guard in the firewall that nothing knows about (T161 review).
struct KeepingTheGuard<'a> {
    inner: &'a dyn UndoExecutor,
    kept: std::cell::Cell<bool>,
}

impl UndoExecutor for KeepingTheGuard<'_> {
    fn reverse(&self, record: &UndoRecord) -> Result<(), NetstateError> {
        if matches!(record, UndoRecord::GuardFilters { .. }) {
            self.kept.set(true);
            return Err(NetstateError::Operation(GUARD_KEPT.to_owned()));
        }
        self.inner.reverse(record)
    }
}

/// [`recover_at_start`], but with `keep_guard` a kill-switch guard the dead run left in the firewall stays in (T161):
/// that is what a kill switch is for, and the service's own connection logic then replaces it or the person takes it
/// out (`Disconnect`, `ReleaseGuard`, `dnetd release-guard`, uninstall). Every other leftover change is reversed as
/// ever, and a change that cannot be reversed still fails recovery. The kept guard's record is never reversed and so
/// never leaves the journal, so a later recovery that is not keeping it removes the guard.
pub fn recover_at_start_keeping_the_guard(
    ops: &dyn RecoveryOps,
    keep_guard: bool,
) -> Result<Recovered, RecoveryError> {
    let reaped = ops
        .reap_orphan_cores()
        .map_err(RecoveryError::OrphanCores)?;
    let undo = ops
        .open_journal()
        .map_err(|e| RecoveryError::JournalUnusable(e.to_string()))?;
    let keeping = KeepingTheGuard {
        inner: ops.executor(),
        kept: std::cell::Cell::new(false),
    };
    let report = if keep_guard {
        undo.replay(&keeping)
    } else {
        undo.replay(ops.executor())
    }
    .map_err(|e| RecoveryError::JournalUnusable(e.to_string()))?;
    let kept_guard = keep_guard && keeping.kept.get();
    // A guard left in on purpose is not a failure; anything else that could not be reversed still is.
    let failures: Vec<&(_, NetstateError)> = report
        .failed
        .iter()
        .filter(|(_, why)| !matches!(why, NetstateError::Operation(m) if m == GUARD_KEPT))
        .collect();
    if let Some((_, first)) = failures.first() {
        return Err(RecoveryError::Unrestored {
            remaining: failures.len(),
            first: first.to_string(),
        });
    }
    Ok(Recovered {
        undo: Arc::new(undo),
        reaped,
        restored: report.restored,
        kept_guard,
    })
}

/// Run recovery against the real machine and log the outcome. Everything a previous run left is put right,
/// **including the kill-switch guard**: this is what the uninstall runs.
#[cfg(windows)]
pub fn recover_installation() -> Result<Recovered, RecoveryError> {
    run_and_log(false)
}

/// Run the recovery of a service that is starting. Like [`recover_installation`], except that with the kill switch
/// on, a guard the previous run left in the firewall is **kept** (T161): a crash or a reboot must not hand the traffic
/// back, which is the whole point of the switch. The service connects again, which replaces the guard, or the person
/// takes it out.
#[cfg(windows)]
pub fn recover_for_service() -> Result<Recovered, RecoveryError> {
    run_and_log(kill_switch_is_on())
}

/// The person's choice, read the way the service reads it: absent is off, and a record that is there but damaged
/// is on (`killswitch.rs`).
#[cfg(windows)]
fn kill_switch_is_on() -> bool {
    use dnet_config::persist::{default_config_path, TrustedStateFile};

    crate::killswitch::KillSwitch::new(Box::new(TrustedStateFile::new(
        default_config_path().with_file_name("kill-switch.json"),
    )))
    .enabled()
}

#[cfg(windows)]
fn run_and_log(keep_guard: bool) -> Result<Recovered, RecoveryError> {
    let ops = windows_ops::WindowsRecoveryOps::installed();
    let outcome = if keep_guard {
        recover_at_start_keeping_the_guard(&ops, true)
    } else {
        recover_at_start(&ops)
    };
    match &outcome {
        Ok(r) if r.kept_guard() => tracing::warn!(
            reaped = r.reaped(),
            restored = r.restored(),
            "start-up recovery complete; the kill-switch guard a previous run left is still in the firewall, so traffic stays blocked until the connection is back or it is taken out"
        ),
        Ok(r) => tracing::info!(
            reaped = r.reaped(),
            restored = r.restored(),
            "start-up recovery complete"
        ),
        Err(e) => tracing::error!(error = %e, "start-up recovery FAILED; refusing to connect"),
    }
    outcome
}

#[cfg(windows)]
pub mod windows_ops {
    //! The real recovery side effects.

    use std::path::PathBuf;

    use dnet_netstate::undo::{UndoExecutor, UndoRegistry};
    use dnet_netstate::undo_file::{default_journal_path, FileStore};
    use dnet_netstate::win_route::WindowsUndoExecutor;
    use dnet_netstate::NetstateError;
    use dnet_supervisor::orphans;

    use super::RecoveryOps;

    /// The core executables' file names. The installer (T114) places them beside `dnetd`.
    pub const CORE_EXECUTABLES: [&str; 2] = ["primary-core.exe", "amneziawg-go.exe"];

    pub struct WindowsRecoveryOps {
        pub journal: PathBuf,
        /// Full image paths of the cores. Orphans are matched by full path only, so
        /// nothing that merely shares a file name is ever killed.
        pub core_images: Vec<PathBuf>,
    }

    impl WindowsRecoveryOps {
        /// The installed layout: the journal under `%PROGRAMDATA%`, the cores beside
        /// this executable.
        pub fn installed() -> Self {
            let dir = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(PathBuf::from));
            Self {
                journal: default_journal_path(),
                core_images: dir
                    .map(|dir| CORE_EXECUTABLES.iter().map(|name| dir.join(name)).collect())
                    .unwrap_or_default(),
            }
        }
    }

    impl RecoveryOps for WindowsRecoveryOps {
        fn reap_orphan_cores(&self) -> Result<usize, String> {
            if self.core_images.is_empty() {
                return Err("the service's own location could not be determined".into());
            }
            orphans::reap(&self.core_images)
                .map(|pids| pids.len())
                .map_err(|e| e.to_string())
        }

        fn open_journal(&self) -> Result<UndoRegistry, NetstateError> {
            UndoRegistry::open(Box::new(FileStore::new(&self.journal)))
        }

        fn executor(&self) -> &dyn UndoExecutor {
            &WindowsUndoExecutor
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::{recover_at_start, RecoveryError};
        use super::*;

        /// Ops over a journal in `dir`, with core images that exist nowhere, so reaping
        /// finds nothing and never touches a real process.
        fn ops_in(dir: &std::path::Path) -> WindowsRecoveryOps {
            WindowsRecoveryOps {
                journal: dir.join("state").join("undo.json"),
                core_images: CORE_EXECUTABLES.iter().map(|n| dir.join(n)).collect(),
            }
        }

        #[test]
        fn a_journal_anyone_could_have_written_blocks_recovery() {
            let root = tempfile::tempdir().unwrap();
            let ops = ops_in(root.path());
            std::fs::create_dir_all(ops.journal.parent().unwrap()).unwrap();
            std::fs::write(&ops.journal, br#"{"version":1,"next_id":1,"entries":[]}"#).unwrap();
            dnet_config::write::win::apply_protected_dacl(&ops.journal, "D:P(A;;FA;;;WD)").unwrap();

            let err = recover_at_start(&ops).err().expect("recovery must fail");

            assert!(matches!(err, RecoveryError::JournalUnusable(_)), "{err:?}");
        }

        #[test]
        fn with_no_core_running_the_real_ops_report_that_none_was_stopped() {
            let root = tempfile::tempdir().unwrap();
            assert_eq!(ops_in(root.path()).reap_orphan_cores(), Ok(0));
        }

        #[test]
        fn the_real_ops_refuse_to_guess_where_the_cores_are() {
            let ops = WindowsRecoveryOps {
                journal: std::path::PathBuf::from("undo.json"),
                core_images: Vec::new(),
            };
            let error = ops.reap_orphan_cores().unwrap_err();
            assert!(error.contains("could not be determined"), "{error}");
        }

        /// Helper for the test below: a copy of this test binary runs only this test, which sleeps. Without the
        /// variable it returns at once, so ordinary and `--ignored` runs are unaffected.
        #[test]
        #[ignore = "helper spawned by the real ops stop an orphan that is running at a core's own path"]
        fn orphan_probe_sleeper() {
            if std::env::var_os("DNET_RECOVERY_ORPHAN_PROBE").is_some() {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }

        /// A simulated orphan: a copy of this test binary is started at the path recovery was told a core lives at,
        /// and the real ops stop it, by that full path, and say they stopped one.
        #[test]
        fn the_real_ops_stop_an_orphan_running_at_a_cores_own_path_and_count_it() {
            let dir = tempfile::tempdir().unwrap();
            let image = dir
                .path()
                .join(format!("primary-core-probe-{}.exe", std::process::id()));
            std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
            let mut child = std::process::Command::new(&image)
                .args([
                    "--ignored",
                    "--exact",
                    "recovery::windows_ops::tests::orphan_probe_sleeper",
                ])
                .env("DNET_RECOVERY_ORPHAN_PROBE", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            // The process list may lag the spawn slightly.
            std::thread::sleep(std::time::Duration::from_millis(500));
            let ops = WindowsRecoveryOps {
                journal: dir.path().join("undo.json"),
                core_images: vec![image.clone()],
            };
            let mut stopped = 0;
            for _ in 0..40 {
                stopped = ops.reap_orphan_cores().unwrap();
                if stopped > 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            let status = child.wait().unwrap();
            assert_eq!(stopped, 1, "one orphan, stopped by its full path");
            assert!(!status.success(), "it was ended, not left to finish");
        }

        #[test]
        fn the_installed_layout_reaps_cores_beside_the_service() {
            let ops = WindowsRecoveryOps::installed();
            let exe_dir = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf();
            assert_eq!(ops.core_images.len(), 2);
            assert!(ops
                .core_images
                .iter()
                .all(|p| p.parent() == Some(&*exe_dir)));
            assert!(ops.journal.ends_with(r"DNet Engine\state\undo.json"));
        }

        /// SUP-T2 (routes): a run that died with a host route installed leaves nothing
        /// behind once the next start has recovered.
        #[test]
        #[ignore = "requires an elevated Administrator (run: cargo test -p dnetd -- --ignored)"]
        fn a_route_left_by_a_crashed_run_is_restored_at_the_next_start() {
            use std::net::{IpAddr, Ipv4Addr};
            use std::sync::Arc;

            use dnet_config::ActiveEndpointBypass;
            use dnet_core::endpoint::EndpointAddress;
            use dnet_netstate::host_route::HostRoute;
            use dnet_netstate::win_route::{best_route_to, default_gateway, WindowsRouteInstaller};

            let root = tempfile::tempdir().unwrap();
            let ops = ops_in(root.path());
            let gateway = default_gateway().expect("test host needs an IPv4 default gateway");
            let dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 81));
            {
                let registry =
                    Arc::new(UndoRegistry::open(Box::new(FileStore::new(&ops.journal))).unwrap());
                let bypass =
                    ActiveEndpointBypass::new(&EndpointAddress::new("203.0.113.81", 1).unwrap());
                WindowsRouteInstaller::new(registry)
                    .install(&HostRoute::for_endpoint(&bypass, gateway))
                    .unwrap();
                // Dropped without teardown: the service crashed.
            }
            assert_eq!(best_route_to(dest).unwrap().prefix_len, 32);

            let recovered = recover_at_start(&ops).unwrap();

            assert_eq!(recovered.restored(), 1);
            assert!(recovered.undo().outstanding().is_empty());
            assert_ne!(best_route_to(dest).unwrap().prefix_len, 32);
        }

        /// T161: a run that died with the kill-switch guard in the firewall. With the switch on, the next start
        /// leaves the guard in (the traffic stays blocked); the one after that, with the switch off, removes it.
        /// **This changes the firewall**: the lab VM only, never a real computer (ADR-0006 §5a condition 5). A drop
        /// guard takes it out however the test ends.
        #[test]
        #[ignore = "changes the firewall: elevated, in the lab VM only, never on a real computer"]
        fn a_guard_left_by_a_crashed_run_is_kept_at_the_next_start_when_the_switch_is_on_and_removed_when_off(
        ) {
            use std::path::Path;
            use std::sync::Arc;

            use crate::guard_control::{plan_for, GuardControl, WindowsGuard};
            use crate::recovery::recover_at_start_keeping_the_guard;

            struct Cleanup(WindowsGuard);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = self.0.release();
                }
            }

            let root = tempfile::tempdir().unwrap();
            let ops = ops_in(root.path());
            let registry =
                Arc::new(UndoRegistry::open(Box::new(FileStore::new(&ops.journal))).unwrap());
            let guard = Cleanup(WindowsGuard::new(Arc::clone(&registry)));
            guard.0.release().unwrap();

            let service = std::env::current_exe().unwrap();
            let core = Path::new(r"C:\Windows\System32\cmd.exe");
            guard
                .0
                .engage(&plan_for(core, &service, 34_567, 0x0006_0000_0000_0001))
                .unwrap();
            assert!(guard.0.is_in().unwrap());
            // The run dies here: the registry is dropped without releasing anything.
            drop(registry);

            // The next start, with the kill switch on: the guard is still in, and still on the books.
            let kept = recover_at_start_keeping_the_guard(&ops, true).unwrap();
            assert!(kept.kept_guard());
            assert!(guard.0.is_in().unwrap(), "the guard survived the restart");
            assert_eq!(kept.undo().outstanding().len(), 1);
            drop(kept);

            // The start after that, with the switch off: it comes out, and the journal is clean.
            let plain = recover_at_start_keeping_the_guard(&ops, false).unwrap();
            assert!(!plain.kept_guard());
            assert!(!guard.0.is_in().unwrap(), "the guard was removed");
            assert!(plain.undo().outstanding().is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    use dnet_netstate::undo::{MemoryStore, Mutation, UndoRecord};

    fn route(last_octet: u8) -> UndoRecord {
        UndoRecord::HostRoute {
            interface_luid: 17,
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    /// A journal a crashed run left holding these records.
    fn crashed_journal(records: &[UndoRecord]) -> MemoryStore {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();
        for record in records {
            registry
                .apply(record.clone(), || Ok(Mutation::Applied))
                .unwrap();
        }
        store
    }

    #[derive(Default)]
    struct FakeOps {
        log: RefCell<Vec<String>>,
        store: MemoryStore,
        reap_fails: bool,
        /// How many cores the fake says it stopped; one unless a test says otherwise.
        reaps: Option<usize>,
        journal_unusable: bool,
        irreversible: Vec<UndoRecord>,
    }

    impl FakeOps {
        fn with_journal(store: MemoryStore) -> Self {
            Self {
                store,
                ..Self::default()
            }
        }
        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl UndoExecutor for FakeOps {
        fn reverse(&self, record: &UndoRecord) -> Result<(), NetstateError> {
            if self.irreversible.contains(record) {
                self.log.borrow_mut().push("reverse-failed".into());
                return Err(NetstateError::Operation("access denied".into()));
            }
            self.log.borrow_mut().push("reverse".into());
            Ok(())
        }
    }

    impl RecoveryOps for FakeOps {
        fn reap_orphan_cores(&self) -> Result<usize, String> {
            self.log.borrow_mut().push("reap".into());
            if self.reap_fails {
                return Err("could not terminate pid 4242".into());
            }
            Ok(self.reaps.unwrap_or(1))
        }
        fn open_journal(&self) -> Result<UndoRegistry, NetstateError> {
            self.log.borrow_mut().push("open-journal".into());
            if self.journal_unusable {
                return Err(NetstateError::Journal(
                    "refusing undo.json: untrusted".into(),
                ));
            }
            UndoRegistry::open(Box::new(self.store.clone()))
        }
        fn executor(&self) -> &dyn UndoExecutor {
            self
        }
    }

    #[test]
    fn recovery_reports_how_many_cores_were_stopped_as_the_ops_counted_them() {
        for stopped in [0usize, 1, 2, 7] {
            let ops = FakeOps {
                reaps: Some(stopped),
                ..FakeOps::with_journal(crashed_journal(&[route(1)]))
            };
            let recovered = recover_at_start(&ops).unwrap();
            assert_eq!(recovered.reaped(), stopped);
            assert_eq!(recovered.restored(), 1);
        }
    }

    #[test]
    fn orphaned_cores_are_killed_before_any_recorded_change_is_reversed() {
        let ops = FakeOps::with_journal(crashed_journal(&[route(1), route(2)]));

        let recovered = recover_at_start(&ops).unwrap();

        assert_eq!(ops.log(), ["reap", "open-journal", "reverse", "reverse"]);
        assert_eq!((recovered.reaped(), recovered.restored()), (1, 2));
        assert!(recovered.undo().outstanding().is_empty());
        assert!(ops.store.snapshot().unwrap().entries.is_empty());
    }

    // ------------------------------------------------------------ the kill-switch guard across a restart (T161)

    fn guard() -> UndoRecord {
        UndoRecord::GuardFilters {
            provider: dnet_netstate::guard_wfp::PROVIDER_KEY.to_text(),
        }
    }

    /// With the kill switch on, a run that died with the guard in leaves it in: the point of a kill switch is that a
    /// crash does not hand the traffic back. Everything else that run changed is still put right.
    #[test]
    fn a_guard_a_dead_run_left_is_kept_when_the_kill_switch_is_on_and_everything_else_is_restored()
    {
        let ops = FakeOps::with_journal(crashed_journal(&[route(1), guard(), route(2)]));

        let recovered = recover_at_start_keeping_the_guard(&ops, true).unwrap();

        // Two routes reversed; the guard is not.
        assert_eq!(ops.log(), ["reap", "open-journal", "reverse", "reverse"]);
        assert!(recovered.kept_guard());
        // And it is still on the books, so a later recovery that is not keeping it removes it.
        let remaining = recovered.undo().outstanding();
        assert_eq!(remaining.len(), 1, "{remaining:?}");
        assert_eq!(remaining[0].record, guard());
    }

    #[test]
    fn a_guard_a_dead_run_left_is_removed_when_the_kill_switch_is_off() {
        let ops = FakeOps::with_journal(crashed_journal(&[guard(), route(1)]));

        let recovered = recover_at_start_keeping_the_guard(&ops, false).unwrap();

        assert_eq!(ops.log(), ["reap", "open-journal", "reverse", "reverse"]);
        assert!(!recovered.kept_guard());
        assert!(recovered.undo().outstanding().is_empty());
    }

    /// The default recovery (the uninstall's, and every caller that does not say) never keeps it.
    #[test]
    fn plain_recovery_removes_the_guard_too() {
        let ops = FakeOps::with_journal(crashed_journal(&[guard()]));
        let recovered = recover_at_start(&ops).unwrap();
        assert!(!recovered.kept_guard());
        assert_eq!(ops.log(), ["reap", "open-journal", "reverse"]);
        assert!(recovered.undo().outstanding().is_empty());
    }

    #[test]
    fn keeping_the_guard_with_none_left_changes_nothing() {
        let ops = FakeOps::with_journal(crashed_journal(&[route(1)]));
        let recovered = recover_at_start_keeping_the_guard(&ops, true).unwrap();
        assert!(!recovered.kept_guard());
        assert_eq!(recovered.restored(), 1);
        assert!(recovered.undo().outstanding().is_empty());
    }

    /// Keeping the guard never hides a change that could not be undone: recovery still fails, and says which.
    #[test]
    fn a_change_that_cannot_be_reversed_still_fails_recovery_while_the_guard_is_kept() {
        let ops = FakeOps {
            irreversible: vec![route(1)],
            ..FakeOps::with_journal(crashed_journal(&[route(1), guard()]))
        };
        let err = recover_at_start_keeping_the_guard(&ops, true)
            .err()
            .expect("recovery must fail");
        // Only the route that could not be reversed is reported: the guard was left in on purpose, not failed.
        assert!(
            matches!(err, RecoveryError::Unrestored { remaining: 1, .. }),
            "{err:?}"
        );
        // And the guard that is still in the firewall is still on the books, whatever else went wrong: a record that
        // left the journal here would leave a guard nothing knows about (T161 review, high 1).
        let journal = ops.store.snapshot().expect("the journal was saved");
        assert!(
            journal.entries.iter().any(|e| e.record == guard()),
            "{journal:?}"
        );
    }

    /// The journal never loses the guard's record while it is kept, at any moment: it is not reversed, so replay never
    /// drops it, and nothing has to put it back afterwards (T161 review, medium 1: a crash in between).
    #[test]
    fn a_kept_guard_is_never_off_the_journal_even_for_a_moment() {
        let ops = FakeOps::with_journal(crashed_journal(&[guard(), route(1)]));
        let _ = recover_at_start_keeping_the_guard(&ops, true).unwrap();
        let journal = ops.store.snapshot().unwrap();
        assert_eq!(journal.entries.len(), 1);
        assert_eq!(journal.entries[0].record, guard());
        // The id it had before is the id it has after: it was never removed and added again.
        let before = crashed_journal(&[guard(), route(1)]).snapshot().unwrap();
        assert_eq!(journal.entries[0].id, before.entries[0].id);
    }

    #[test]
    fn a_clean_start_recovers_with_nothing_to_restore() {
        let ops = FakeOps::default();
        let recovered = recover_at_start(&ops).unwrap();
        assert_eq!(recovered.restored(), 0);
    }

    #[test]
    fn a_change_that_cannot_be_reversed_fails_recovery_and_stays_recorded() {
        let ops = FakeOps {
            irreversible: vec![route(1)],
            ..FakeOps::with_journal(crashed_journal(&[route(1), route(2)]))
        };

        let err = recover_at_start(&ops).err().expect("recovery must fail");

        assert!(
            matches!(err, RecoveryError::Unrestored { remaining: 1, .. }),
            "{err:?}"
        );
        assert_eq!(
            ops.store.snapshot().unwrap().entries.len(),
            1,
            "kept for the next start"
        );
    }

    #[test]
    fn an_unusable_journal_fails_recovery_without_reversing_anything() {
        let ops = FakeOps {
            journal_unusable: true,
            ..FakeOps::default()
        };

        let err = recover_at_start(&ops).err().expect("recovery must fail");

        assert!(matches!(err, RecoveryError::JournalUnusable(_)), "{err:?}");
        assert!(!ops.log().contains(&"reverse".to_string()));
    }

    #[test]
    fn a_core_that_cannot_be_killed_fails_recovery_before_the_journal_is_touched() {
        let ops = FakeOps {
            reap_fails: true,
            ..FakeOps::with_journal(crashed_journal(&[route(1)]))
        };

        let err = recover_at_start(&ops).err().expect("recovery must fail");

        assert!(matches!(err, RecoveryError::OrphanCores(_)), "{err:?}");
        assert_eq!(ops.log(), ["reap"]);
        assert_eq!(ops.store.snapshot().unwrap().entries.len(), 1);
    }

    #[test]
    fn every_failure_explains_itself_and_says_how_to_retry() {
        for err in [
            RecoveryError::OrphanCores("could not terminate pid 4242".into()),
            RecoveryError::JournalUnusable("untrusted".into()),
            RecoveryError::Unrestored {
                remaining: 2,
                first: "access denied".into(),
            },
        ] {
            let text = err.to_string();
            assert!(text.contains("will not connect"), "{text}");
            assert!(text.contains("restart the DNet Engine service"), "{text}");
        }
    }
}
