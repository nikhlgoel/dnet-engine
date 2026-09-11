//! T037 — the undo-record registry (data-model §Cross-cutting 1, FR-029, SC-016).
//!
//! Restoration is owed unconditionally: on disconnect, exit, crash, and uninstall. A crash
//! leaves nobody to run the shutdown path, so every mutation of routing, DNS, or adapter
//! state is recorded **durably, before it is applied** (write-ahead). The record says how
//! to reverse the mutation without any in-memory state, so `dnetd` can replay it at the
//! next service start (T038).
//!
//! - [`UndoRegistry::apply`] is the only way to perform a registered mutation: it persists
//!   the record, and only then runs the mutation. If persisting fails, nothing is mutated.
//! - A normal teardown goes through [`UndoRegistry::undo`], which runs the **same**
//!   [`UndoExecutor`] crash replay uses. The restoration path is therefore exercised on
//!   every disconnect, not only after a crash.
//! - [`UndoRegistry::replay`] reverses outstanding records newest-first and keeps any it
//!   could not reverse, so a later replay can retry.
//!
//! **Not recorded: the AmneziaWG adapter's own address and route.** They belong to an
//! adapter the core creates and that disappears when the core exits; a core left behind by
//! a crash is reaped at start before anything else (SUP-05).

use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::NetstateError;

/// The journal format version this build reads and writes.
pub const JOURNAL_VERSION: u32 = 1;

/// Identifies one outstanding record. Never reused within a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UndoId(u64);

/// How to reverse one mutation, with no dependence on in-memory state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UndoRecord {
    /// Delete the `/32` (or `/128`) route to `destination` via `next_hop` on the interface
    /// with this LUID. The LUID, unlike the interface index, is stable across restarts.
    HostRoute {
        interface_luid: u64,
        destination: IpAddr,
        next_hop: IpAddr,
    },
}

impl UndoRecord {
    /// Reject a record that could not have been written by this service. The journal is
    /// replayed by LocalSystem, so a malformed record is treated as tampering, not skipped.
    pub fn validate(&self) -> Result<(), NetstateError> {
        match self {
            UndoRecord::HostRoute {
                interface_luid,
                destination,
                next_hop,
            } => {
                let invalid =
                    |why: &str| Err(NetstateError::Journal(format!("invalid host route: {why}")));
                if *interface_luid == 0 {
                    return invalid("no interface");
                }
                if destination.is_unspecified() || next_hop.is_unspecified() {
                    return invalid("unspecified address");
                }
                if destination.is_ipv4() != next_hop.is_ipv4() {
                    return invalid("destination and next hop differ in address family");
                }
                Ok(())
            }
        }
    }
}

/// One outstanding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoEntry {
    pub id: UndoId,
    pub record: UndoRecord,
}

/// The persisted journal: outstanding records in the order they were registered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoJournal {
    pub version: u32,
    pub next_id: u64,
    pub entries: Vec<UndoEntry>,
}

impl Default for UndoJournal {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            next_id: 1,
            entries: Vec::new(),
        }
    }
}

impl UndoJournal {
    /// Parse and validate a journal. Anything unexpected is an error, never a partial load.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NetstateError> {
        let journal: Self = serde_json::from_slice(bytes)
            .map_err(|e| NetstateError::Journal(format!("unreadable: {e}")))?;
        if journal.version != JOURNAL_VERSION {
            return Err(NetstateError::Journal(format!(
                "unsupported version {}",
                journal.version
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for entry in &journal.entries {
            entry.record.validate()?;
            if !seen.insert(entry.id) {
                return Err(NetstateError::Journal(format!(
                    "duplicate id {}",
                    entry.id.0
                )));
            }
            if entry.id.0 >= journal.next_id {
                return Err(NetstateError::Journal(format!(
                    "id {} is not below the next id {}",
                    entry.id.0, journal.next_id
                )));
            }
        }
        Ok(journal)
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("the journal contains only serialisable plain data")
    }

    fn without(&self, ids: &[UndoId]) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|e| !ids.contains(&e.id))
                .cloned()
                .collect(),
            ..self.clone()
        }
    }
}

/// Durable storage for the journal.
pub trait UndoStore: Send {
    /// The stored journal, or an empty one if none has been written.
    fn load(&self) -> Result<UndoJournal, NetstateError>;
    /// Replace the stored journal. Must not return until the write is durable.
    fn save(&self, journal: &UndoJournal) -> Result<(), NetstateError>;
}

/// Reverses records. The real one deletes routes; tests record calls.
pub trait UndoExecutor {
    /// Reverse the mutation. Must be idempotent: reversing something already gone is success.
    fn reverse(&self, record: &UndoRecord) -> Result<(), NetstateError>;
}

/// What a mutation reported doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// The mutation changed system state; the registry now owns its reversal.
    Applied,
    /// The target state already existed and was not created by us: nothing to reverse.
    AlreadyPresent,
}

/// The result of a replay.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Records reversed and removed.
    pub restored: usize,
    /// Records whose reversal failed; they stay in the journal.
    pub failed: Vec<(UndoId, NetstateError)>,
}

/// The write-ahead undo registry.
pub struct UndoRegistry {
    inner: Mutex<Inner>,
}

struct Inner {
    store: Box<dyn UndoStore>,
    journal: UndoJournal,
}

impl UndoRegistry {
    /// Open the registry over a store, loading any records a previous run left behind.
    pub fn open(store: Box<dyn UndoStore>) -> Result<Self, NetstateError> {
        let journal = store.load()?;
        Ok(Self {
            inner: Mutex::new(Inner { store, journal }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("undo registry mutex poisoned")
    }

    /// Records not yet reversed, oldest first.
    pub fn outstanding(&self) -> Vec<UndoEntry> {
        self.lock().journal.entries.clone()
    }

    /// Persist `record`, then run `mutation`. Returns the record's id when the mutation
    /// changed state, or `None` when the target already existed (the record is withdrawn).
    /// If the mutation fails, the record is withdrawn and the error returned. If the record
    /// cannot be persisted, the mutation never runs.
    pub fn apply(
        &self,
        record: UndoRecord,
        mutation: impl FnOnce() -> Result<Mutation, NetstateError>,
    ) -> Result<Option<UndoId>, NetstateError> {
        record.validate()?;
        // Held across the mutation, so registered mutations are serialised and the journal
        // order is the order they were applied in.
        let mut inner = self.lock();

        let id = UndoId(inner.journal.next_id);
        let mut registered = inner.journal.clone();
        registered.next_id += 1;
        registered.entries.push(UndoEntry { id, record });
        inner.store.save(&registered)?;
        inner.journal = registered;

        let outcome = mutation();
        if matches!(outcome, Ok(Mutation::Applied)) {
            return Ok(Some(id));
        }

        // Nothing of ours to reverse. If the withdrawal cannot be written, the stale record
        // is dropped from memory anyway and the next successful write removes it on disk.
        let withdrawn = inner.journal.without(&[id]);
        if let Err(e) = inner.store.save(&withdrawn) {
            tracing::error!(error = %e, "withdrawing an unused undo record failed");
        }
        inner.journal = withdrawn;
        outcome.map(|_| None)
    }

    /// Reverse one record now (normal teardown) and remove it. On failure it stays.
    pub fn undo(&self, id: UndoId, executor: &dyn UndoExecutor) -> Result<(), NetstateError> {
        let mut inner = self.lock();
        let entry = inner
            .journal
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| NetstateError::Journal(format!("no outstanding record {}", id.0)))?;
        executor.reverse(&entry.record)?;
        // Reversal is idempotent, so if this write fails the record simply stays and a
        // later replay reverses it again.
        let remaining = inner.journal.without(&[id]);
        inner.store.save(&remaining)?;
        inner.journal = remaining;
        Ok(())
    }

    /// Reverse every outstanding record, newest first. Failures stay in the journal.
    pub fn replay(&self, executor: &dyn UndoExecutor) -> Result<ReplayReport, NetstateError> {
        let mut inner = self.lock();
        let mut report = ReplayReport::default();
        let mut restored = Vec::new();
        for entry in inner.journal.entries.iter().rev() {
            match executor.reverse(&entry.record) {
                Ok(()) => restored.push(entry.id),
                Err(e) => report.failed.push((entry.id, e)),
            }
        }
        report.restored = restored.len();
        if !restored.is_empty() {
            let remaining = inner.journal.without(&restored);
            inner.store.save(&remaining)?;
            inner.journal = remaining;
        }
        Ok(report)
    }
}

/// An in-memory store for tests and for callers that only need ordering, not durability.
#[derive(Clone, Default)]
pub struct MemoryStore {
    journal: std::sync::Arc<Mutex<Option<UndoJournal>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// What is currently stored.
    pub fn snapshot(&self) -> Option<UndoJournal> {
        self.journal.lock().expect("memory store poisoned").clone()
    }
}

impl UndoStore for MemoryStore {
    fn load(&self) -> Result<UndoJournal, NetstateError> {
        Ok(self.snapshot().unwrap_or_default())
    }

    fn save(&self, journal: &UndoJournal) -> Result<(), NetstateError> {
        *self.journal.lock().expect("memory store poisoned") = Some(journal.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn route(last_octet: u8) -> UndoRecord {
        UndoRecord::HostRoute {
            interface_luid: 0x0006_0000_0000_0011,
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    fn stored_records(store: &MemoryStore) -> Vec<UndoRecord> {
        store
            .snapshot()
            .map(|j| j.entries.into_iter().map(|e| e.record).collect())
            .unwrap_or_default()
    }

    /// Records every reversal; fails for the destinations listed in `fail`.
    #[derive(Default)]
    struct Recorder {
        reversed: RefCell<Vec<UndoRecord>>,
        fail: Vec<UndoRecord>,
    }

    impl UndoExecutor for Recorder {
        fn reverse(&self, record: &UndoRecord) -> Result<(), NetstateError> {
            if self.fail.contains(record) {
                return Err(NetstateError::Operation(
                    "simulated reversal failure".into(),
                ));
            }
            self.reversed.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    /// A store whose writes can be made to fail.
    #[derive(Clone, Default)]
    struct FlakyStore {
        inner: MemoryStore,
        failing: Arc<AtomicBool>,
    }

    impl UndoStore for FlakyStore {
        fn load(&self) -> Result<UndoJournal, NetstateError> {
            self.inner.load()
        }
        fn save(&self, journal: &UndoJournal) -> Result<(), NetstateError> {
            if self.failing.load(Ordering::SeqCst) {
                return Err(NetstateError::Journal("simulated write failure".into()));
            }
            self.inner.save(journal)
        }
    }

    #[test]
    fn the_record_is_durable_before_the_mutation_runs() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();

        let id = registry
            .apply(route(1), || {
                assert_eq!(
                    stored_records(&store),
                    vec![route(1)],
                    "the undo record must already be stored when the mutation runs"
                );
                Ok(Mutation::Applied)
            })
            .unwrap();

        assert!(id.is_some());
        assert_eq!(stored_records(&store), vec![route(1)]);
    }

    #[test]
    fn a_record_that_cannot_be_persisted_prevents_the_mutation() {
        let store = FlakyStore::default();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();
        store.failing.store(true, Ordering::SeqCst);

        let mut ran = false;
        let result = registry.apply(route(1), || {
            ran = true;
            Ok(Mutation::Applied)
        });

        assert!(result.is_err());
        assert!(
            !ran,
            "a mutation without a durable undo record must not run"
        );
        assert!(registry.outstanding().is_empty());
    }

    #[test]
    fn a_failed_mutation_withdraws_its_record() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();

        let result = registry.apply(route(1), || Err(NetstateError::Operation("denied".into())));

        assert_eq!(result, Err(NetstateError::Operation("denied".into())));
        assert!(registry.outstanding().is_empty());
        assert!(stored_records(&store).is_empty());
    }

    #[test]
    fn a_pre_existing_target_is_never_owned() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();

        let id = registry
            .apply(route(1), || Ok(Mutation::AlreadyPresent))
            .unwrap();

        assert_eq!(id, None);
        assert!(
            stored_records(&store).is_empty(),
            "someone else's state must not be undone"
        );
    }

    #[test]
    fn undo_reverses_through_the_executor_then_drops_the_record() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();
        let id = registry
            .apply(route(1), || Ok(Mutation::Applied))
            .unwrap()
            .unwrap();
        let executor = Recorder::default();

        registry.undo(id, &executor).unwrap();

        assert_eq!(*executor.reversed.borrow(), vec![route(1)]);
        assert!(stored_records(&store).is_empty());
    }

    #[test]
    fn a_failed_undo_keeps_the_record_for_a_later_replay() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();
        let id = registry
            .apply(route(1), || Ok(Mutation::Applied))
            .unwrap()
            .unwrap();
        let executor = Recorder {
            fail: vec![route(1)],
            ..Recorder::default()
        };

        assert!(registry.undo(id, &executor).is_err());
        assert_eq!(stored_records(&store), vec![route(1)]);
    }

    #[test]
    fn undoing_an_unknown_id_is_an_error() {
        let registry = UndoRegistry::open(Box::new(MemoryStore::new())).unwrap();
        assert!(registry.undo(UndoId(42), &Recorder::default()).is_err());
    }

    #[test]
    fn replay_reverses_newest_first_and_keeps_failures() {
        let store = MemoryStore::new();
        let registry = UndoRegistry::open(Box::new(store.clone())).unwrap();
        for n in 1..=3 {
            registry.apply(route(n), || Ok(Mutation::Applied)).unwrap();
        }
        let executor = Recorder {
            fail: vec![route(2)],
            ..Recorder::default()
        };

        let report = registry.replay(&executor).unwrap();

        assert_eq!(*executor.reversed.borrow(), vec![route(3), route(1)]);
        assert_eq!(report.restored, 2);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(stored_records(&store), vec![route(2)]);
    }

    #[test]
    fn a_new_registry_sees_what_a_crashed_run_left_and_never_reuses_its_ids() {
        let store = MemoryStore::new();
        let crashed = UndoRegistry::open(Box::new(store.clone())).unwrap();
        let old = crashed
            .apply(route(1), || Ok(Mutation::Applied))
            .unwrap()
            .unwrap();
        drop(crashed); // no teardown: the process died

        let restarted = UndoRegistry::open(Box::new(store.clone())).unwrap();
        assert_eq!(
            restarted.outstanding(),
            vec![UndoEntry {
                id: old,
                record: route(1)
            }]
        );
        let new = restarted
            .apply(route(2), || Ok(Mutation::Applied))
            .unwrap()
            .unwrap();
        assert!(new > old);
    }

    #[test]
    fn the_journal_format_is_stable() {
        let journal = UndoJournal {
            version: JOURNAL_VERSION,
            next_id: 8,
            entries: vec![UndoEntry {
                id: UndoId(7),
                record: route(9),
            }],
        };
        let json = String::from_utf8(journal.to_json()).unwrap();
        assert_eq!(
            json,
            r#"{"version":1,"next_id":8,"entries":[{"id":7,"record":{"kind":"host_route","interface_luid":1688849860263953,"destination":"203.0.113.9","next_hop":"192.168.1.1"}}]}"#
        );
        assert_eq!(UndoJournal::from_json(json.as_bytes()).unwrap(), journal);
    }

    #[test]
    fn a_tampered_or_unexpected_journal_is_refused_whole() {
        let good = r#"{"kind":"host_route","interface_luid":17,"destination":"203.0.113.9","next_hop":"192.168.1.1"}"#;
        let journal = |next_id: u64, entries: &str| {
            format!(r#"{{"version":1,"next_id":{next_id},"entries":[{entries}]}}"#)
        };
        let refused = [
            // unknown version
            r#"{"version":2,"next_id":1,"entries":[]}"#.to_string(),
            // unknown record kind
            journal(
                2,
                r#"{"id":1,"record":{"kind":"dns_server","interface_luid":17}}"#,
            ),
            // unknown field
            journal(2, &format!(r#"{{"id":1,"record":{good},"extra":true}}"#)),
            // next hop of the wrong family
            journal(
                2,
                r#"{"id":1,"record":{"kind":"host_route","interface_luid":17,"destination":"203.0.113.9","next_hop":"fe80::1"}}"#,
            ),
            // unspecified destination would be a default route, not a host route
            journal(
                2,
                r#"{"id":1,"record":{"kind":"host_route","interface_luid":17,"destination":"0.0.0.0","next_hop":"192.168.1.1"}}"#,
            ),
            // no interface
            journal(
                2,
                r#"{"id":1,"record":{"kind":"host_route","interface_luid":0,"destination":"203.0.113.9","next_hop":"192.168.1.1"}}"#,
            ),
            // duplicate ids
            journal(
                3,
                &format!(r#"{{"id":1,"record":{good}}},{{"id":1,"record":{good}}}"#),
            ),
            // an id the counter would hand out again
            journal(1, &format!(r#"{{"id":1,"record":{good}}}"#)),
            // not JSON
            "not json".to_string(),
        ];
        for text in refused {
            assert!(
                UndoJournal::from_json(text.as_bytes()).is_err(),
                "must refuse: {text}"
            );
        }
        assert!(UndoJournal::from_json(
            journal(2, &format!(r#"{{"id":1,"record":{good}}}"#)).as_bytes()
        )
        .is_ok());
    }

    #[test]
    fn ipv6_host_routes_validate() {
        let record = UndoRecord::HostRoute {
            interface_luid: 17,
            destination: IpAddr::V6("2001:db8::9".parse().unwrap()),
            next_hop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        };
        assert!(record.validate().is_ok());
    }
}
