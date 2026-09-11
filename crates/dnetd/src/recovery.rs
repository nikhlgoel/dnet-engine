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

use dnet_netstate::undo::{UndoExecutor, UndoRegistry};
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

    /// A clean recovery over an empty in-memory journal, for tests of other modules.
    #[cfg(test)]
    pub fn clean_for_tests() -> Self {
        let store = dnet_netstate::undo::MemoryStore::new();
        Self {
            undo: Arc::new(UndoRegistry::open(Box::new(store)).expect("memory store opens")),
            reaped: 0,
            restored: 0,
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

/// Restore what a previous run left, in order. See the module docs.
pub fn recover_at_start(ops: &dyn RecoveryOps) -> Result<Recovered, RecoveryError> {
    let reaped = ops
        .reap_orphan_cores()
        .map_err(RecoveryError::OrphanCores)?;
    let undo = ops
        .open_journal()
        .map_err(|e| RecoveryError::JournalUnusable(e.to_string()))?;
    let report = undo
        .replay(ops.executor())
        .map_err(|e| RecoveryError::JournalUnusable(e.to_string()))?;
    if let Some((_, first)) = report.failed.first() {
        return Err(RecoveryError::Unrestored {
            remaining: report.failed.len(),
            first: first.to_string(),
        });
    }
    Ok(Recovered {
        undo: Arc::new(undo),
        reaped,
        restored: report.restored,
    })
}

/// Run recovery against the real machine and log the outcome.
#[cfg(windows)]
pub fn recover_installation() -> Result<Recovered, RecoveryError> {
    let outcome = recover_at_start(&windows_ops::WindowsRecoveryOps::installed());
    match &outcome {
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
            Ok(1)
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
    fn orphaned_cores_are_killed_before_any_recorded_change_is_reversed() {
        let ops = FakeOps::with_journal(crashed_journal(&[route(1), route(2)]));

        let recovered = recover_at_start(&ops).unwrap();

        assert_eq!(ops.log(), ["reap", "open-journal", "reverse", "reverse"]);
        assert_eq!((recovered.reaped(), recovered.restored()), (1, 2));
        assert!(recovered.undo().outstanding().is_empty());
        assert!(ops.store.snapshot().unwrap().entries.is_empty());
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
