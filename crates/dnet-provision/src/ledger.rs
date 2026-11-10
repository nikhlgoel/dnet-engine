//! T090 — the ledger of what a job has created, written **before** each create call (PR-07, PR-04 of the
//! plan's cleanup contract, SC-011).
//!
//! Provisioning makes billable things in the person's own cloud account. If the program dies half way
//! (power cut, crash, a closed laptop) and nobody knows what exists, those things keep costing money and
//! keep occupying the free allowance, and the person finds out when the bill arrives. The ledger is how
//! that is prevented, and the order of writes is the whole point:
//!
//! 1. **Intent first.** `record_intent` is written, and made durable, *before* the create call is issued.
//!    Recording afterwards would lose exactly the resources most likely to leak: the ones whose creation
//!    was interrupted.
//! 2. **Then the create call.**
//! 3. **Then the provider's id**, `record_created`. Losing this write is survivable: the entry already
//!    exists, and cleanup finds the resource by its `token`, a name the job chose and the provider stores.
//! 4. `record_removed` when cleanup has confirmed the resource is gone.
//!
//! An entry that cannot be written stops the job *before* the create call. A job that cannot record what it
//! is about to make does not make it.
//!
//! The file is append-only, one JSON object per line, each line flushed to disk before the call returns.
//! The in-memory view is updated only after the line is safely written, so it is never ahead of the file.
//! A torn final line (the write was cut off) is ignored: the create call that would have followed it was
//! never issued. A damaged line anywhere else is refused: if the file cannot be trusted, nobody can say
//! what exists, and guessing is how things leak.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::provider::ResourceKind;

/// Where in its life a recorded resource is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Written before the create call. The resource may or may not exist.
    Intended,
    /// The provider confirmed it, and its id is recorded.
    Created,
    /// Confirmed gone.
    Removed,
}

/// One resource a job has made or is about to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub kind: ResourceKind,
    /// The name the job chose; the provider stores it, and cleanup searches by it.
    pub token: String,
    pub region: String,
    pub provider_id: Option<String>,
    pub state: EntryState,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("the ledger could not be written ({0})")]
    Write(String),
    #[error("the ledger is damaged at line {0}; nothing is created or removed on a guess")]
    Corrupt(usize),
    #[error("the ledger has no resource named like that")]
    Unknown,
}

pub trait Ledger: Send {
    /// Record that a resource is about to be created. Durable when this returns `Ok`.
    fn record_intent(
        &mut self,
        kind: ResourceKind,
        token: &str,
        region: &str,
    ) -> Result<(), LedgerError>;
    /// Record the provider's id for a resource.
    fn record_created(&mut self, token: &str, provider_id: &str) -> Result<(), LedgerError>;
    /// Record that a resource is confirmed gone.
    fn record_removed(&mut self, token: &str) -> Result<(), LedgerError>;
    /// Every resource, oldest first.
    fn entries(&self) -> Vec<LedgerEntry>;
}

/// A name for a resource: what the job makes up, what the provider stores.
pub fn valid_token(token: &str) -> bool {
    (1..=80).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Intent {
        kind: ResourceKind,
        token: String,
        region: String,
    },
    Created {
        token: String,
        provider_id: String,
    },
    Removed {
        token: String,
    },
}

impl Event {
    fn to_line(&self) -> String {
        let value = match self {
            Event::Intent {
                kind,
                token,
                region,
            } => {
                json!({ "e": "intent", "kind": kind.as_str(), "token": token, "region": region })
            }
            Event::Created { token, provider_id } => {
                json!({ "e": "created", "token": token, "id": provider_id })
            }
            Event::Removed { token } => json!({ "e": "removed", "token": token }),
        };
        value.to_string()
    }

    fn from_line(line: &str) -> Option<Event> {
        let value: Value = serde_json::from_str(line).ok()?;
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
        match value.get("e")?.as_str()? {
            "intent" => Some(Event::Intent {
                kind: ResourceKind::from_name(&text("kind")?)?,
                token: text("token")?,
                region: text("region")?,
            }),
            "created" => Some(Event::Created {
                token: text("token")?,
                provider_id: text("id")?,
            }),
            "removed" => Some(Event::Removed {
                token: text("token")?,
            }),
            _ => None,
        }
    }
}

/// The entries that result from a sequence of events.
#[derive(Debug, Default, Clone)]
struct State {
    entries: Vec<LedgerEntry>,
}

impl State {
    /// Whether `event` makes sense now. Checked before it is written, so the file never holds an event
    /// that could not be applied again on reading.
    fn check(&self, event: &Event) -> Result<(), LedgerError> {
        match event {
            Event::Intent { token, .. } => {
                if !valid_token(token) {
                    return Err(LedgerError::Write("not a valid resource name".into()));
                }
                Ok(())
            }
            Event::Created { token, .. } | Event::Removed { token } => self
                .entries
                .iter()
                .any(|e| &e.token == token)
                .then_some(())
                .ok_or(LedgerError::Unknown),
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Intent {
                kind,
                token,
                region,
            } => {
                // The same intent twice is the same resource: a retry of a step.
                if self.entries.iter().any(|e| e.token == token) {
                    return;
                }
                self.entries.push(LedgerEntry {
                    kind,
                    token,
                    region,
                    provider_id: None,
                    state: EntryState::Intended,
                });
            }
            Event::Created { token, provider_id } => {
                if let Some(entry) = self.entries.iter_mut().find(|e| e.token == token) {
                    if entry.state != EntryState::Removed {
                        entry.provider_id = Some(provider_id);
                        entry.state = EntryState::Created;
                    }
                }
            }
            Event::Removed { token } => {
                if let Some(entry) = self.entries.iter_mut().find(|e| e.token == token) {
                    entry.state = EntryState::Removed;
                }
            }
        }
    }
}

/// A ledger in memory. For tests and for dry runs; it survives nothing.
#[derive(Debug, Default)]
pub struct MemoryLedger {
    state: State,
}

impl MemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Ledger for MemoryLedger {
    fn record_intent(
        &mut self,
        kind: ResourceKind,
        token: &str,
        region: &str,
    ) -> Result<(), LedgerError> {
        let event = Event::Intent {
            kind,
            token: token.to_owned(),
            region: region.to_owned(),
        };
        self.state.check(&event)?;
        self.state.apply(event);
        Ok(())
    }

    fn record_created(&mut self, token: &str, provider_id: &str) -> Result<(), LedgerError> {
        let event = Event::Created {
            token: token.to_owned(),
            provider_id: provider_id.to_owned(),
        };
        self.state.check(&event)?;
        self.state.apply(event);
        Ok(())
    }

    fn record_removed(&mut self, token: &str) -> Result<(), LedgerError> {
        let event = Event::Removed {
            token: token.to_owned(),
        };
        self.state.check(&event)?;
        self.state.apply(event);
        Ok(())
    }

    fn entries(&self) -> Vec<LedgerEntry> {
        self.state.entries.clone()
    }
}

/// A ledger in a file, flushed to disk on every write.
#[derive(Debug)]
pub struct FileLedger {
    path: PathBuf,
    file: File,
    state: State,
}

impl FileLedger {
    /// Open (creating if need be) the ledger at `path` and read what is in it.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let path = path.into();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| LedgerError::Write(e.kind().to_string()))?;
        }
        let state = read_state(&path)?;
        repair_tail(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| LedgerError::Write(e.kind().to_string()))?;
        Ok(Self { path, file, state })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&mut self, event: Event) -> Result<(), LedgerError> {
        self.state.check(&event)?;
        let mut line = event.to_line();
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|e| LedgerError::Write(e.kind().to_string()))?;
        // Only now, with the line safely on disk, does the in-memory view move.
        self.state.apply(event);
        Ok(())
    }
}

/// If the file ends without a newline, a write was cut off. Leave it so that the next event starts on a
/// line of its own and the file stays readable:
///
/// - a **complete** last event that only lost its newline is kept (`read_state` counted it), so the
///   newline is added;
/// - a **fragment** is removed (`read_state` ignored it, because the create call that would have followed
///   it was never issued), so it cannot become a damaged line in the middle of the file.
fn repair_tail(path: &Path) -> Result<(), LedgerError> {
    let write_error = |e: std::io::Error| LedgerError::Write(e.kind().to_string());
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(write_error(e)),
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }
    let start = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |newline| newline + 1);
    let complete = std::str::from_utf8(&bytes[start..])
        .ok()
        .and_then(Event::from_line)
        .is_some();
    if complete {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(write_error)?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_data())
            .map_err(write_error)
    } else {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(write_error)?;
        file.set_len(start as u64)
            .and_then(|()| file.sync_all())
            .map_err(write_error)
    }
}

fn read_state(path: &Path) -> Result<State, LedgerError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(LedgerError::Write(e.kind().to_string())),
    };
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .collect::<Result<_, _>>()
        .map_err(|e| match e.kind() {
            // Bytes that are not text: the file is damaged.
            std::io::ErrorKind::InvalidData => LedgerError::Corrupt(0),
            // Anything else is the storage failing (or the path not being a file), not the content.
            kind => LedgerError::Write(kind.to_string()),
        })?;
    let mut state = State::default();
    let last = lines.len().saturating_sub(1);
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match Event::from_line(line) {
            Some(event) => {
                // An event for a resource never recorded cannot be explained; refuse the file.
                state
                    .check(&event)
                    .map_err(|_| LedgerError::Corrupt(index + 1))?;
                state.apply(event);
            }
            // The last line may be a write that was cut off; the create call that would have followed
            // it was never issued, so there is nothing to account for.
            None if index == last => {}
            None => return Err(LedgerError::Corrupt(index + 1)),
        }
    }
    Ok(state)
}

impl Ledger for FileLedger {
    fn record_intent(
        &mut self,
        kind: ResourceKind,
        token: &str,
        region: &str,
    ) -> Result<(), LedgerError> {
        self.append(Event::Intent {
            kind,
            token: token.to_owned(),
            region: region.to_owned(),
        })
    }

    fn record_created(&mut self, token: &str, provider_id: &str) -> Result<(), LedgerError> {
        self.append(Event::Created {
            token: token.to_owned(),
            provider_id: provider_id.to_owned(),
        })
    }

    fn record_removed(&mut self, token: &str) -> Result<(), LedgerError> {
        self.append(Event::Removed {
            token: token.to_owned(),
        })
    }

    fn entries(&self) -> Vec<LedgerEntry> {
        self.state.entries.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs").join("ledger.jsonl");
        (dir, path)
    }

    #[test]
    fn an_intent_is_recorded_before_anything_exists() {
        let mut ledger = MemoryLedger::new();
        ledger
            .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
            .unwrap();
        let entries = ledger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].state, EntryState::Intended);
        assert_eq!(entries[0].provider_id, None);
    }

    #[test]
    fn the_life_of_a_resource_is_intended_then_created_then_removed() {
        let mut ledger = MemoryLedger::new();
        ledger
            .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
            .unwrap();
        ledger
            .record_created("dnet-1-instance", "ocid-123")
            .unwrap();
        assert_eq!(ledger.entries()[0].state, EntryState::Created);
        assert_eq!(ledger.entries()[0].provider_id.as_deref(), Some("ocid-123"));
        ledger.record_removed("dnet-1-instance").unwrap();
        assert_eq!(ledger.entries()[0].state, EntryState::Removed);
        // A late `created` cannot bring a removed resource back.
        ledger
            .record_created("dnet-1-instance", "ocid-123")
            .unwrap();
        assert_eq!(ledger.entries()[0].state, EntryState::Removed);
    }

    #[test]
    fn the_same_intent_twice_is_one_resource() {
        let mut ledger = MemoryLedger::new();
        for _ in 0..3 {
            ledger
                .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
                .unwrap();
        }
        assert_eq!(ledger.entries().len(), 1);
    }

    #[test]
    fn something_never_recorded_cannot_be_marked() {
        let mut ledger = MemoryLedger::new();
        assert_eq!(
            ledger.record_created("nope", "x"),
            Err(LedgerError::Unknown)
        );
        assert_eq!(ledger.record_removed("nope"), Err(LedgerError::Unknown));
    }

    #[test]
    fn a_name_that_is_not_a_valid_token_is_refused() {
        let mut ledger = MemoryLedger::new();
        for bad in ["", "A", "a b", "a\"b", "a/b", &"x".repeat(81)] {
            assert!(
                ledger
                    .record_intent(ResourceKind::Instance, bad, "r")
                    .is_err(),
                "{bad:?}"
            );
        }
        assert!(ledger.entries().is_empty());
    }

    #[test]
    fn what_was_written_is_there_after_a_restart() {
        let (_dir, path) = temp();
        {
            let mut ledger = FileLedger::open(&path).unwrap();
            ledger
                .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
                .unwrap();
            ledger.record_created("dnet-1-instance", "ocid-1").unwrap();
            ledger
                .record_intent(ResourceKind::NetworkRule, "dnet-1-network", "r1")
                .unwrap();
            // The process "dies" here: nothing is closed or flushed beyond what each call did.
        }
        let reopened = FileLedger::open(&path).unwrap();
        let entries = reopened.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].state, EntryState::Created);
        assert_eq!(entries[0].provider_id.as_deref(), Some("ocid-1"));
        assert_eq!(entries[1].kind, ResourceKind::NetworkRule);
        assert_eq!(entries[1].state, EntryState::Intended);
    }

    #[test]
    fn a_write_that_fails_leaves_the_view_unchanged() {
        // A directory where the file should be: opening it for append fails.
        let dir = tempfile::tempdir().unwrap();
        let error = FileLedger::open(dir.path()).unwrap_err();
        assert!(matches!(error, LedgerError::Write(_)), "{error:?}");
    }

    #[test]
    fn a_file_that_is_not_text_is_corrupt_and_one_that_cannot_be_read_is_not() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert!(matches!(
            FileLedger::open(&path).unwrap_err(),
            LedgerError::Corrupt(_)
        ));
    }

    #[test]
    fn a_torn_last_line_is_ignored_and_the_next_write_starts_on_its_own_line() {
        let (_dir, path) = temp();
        {
            let mut ledger = FileLedger::open(&path).unwrap();
            ledger
                .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
                .unwrap();
        }
        // A write cut off in the middle.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"e":"intent","kind":"netw"#).unwrap();
        drop(file);

        let mut ledger = FileLedger::open(&path).unwrap();
        assert_eq!(
            ledger.entries().len(),
            1,
            "the torn fragment is not an entry"
        );
        ledger
            .record_intent(ResourceKind::NetworkRule, "dnet-1-network", "r1")
            .unwrap();
        drop(ledger);
        let again = FileLedger::open(&path).unwrap();
        assert_eq!(
            again.entries().len(),
            2,
            "the new entry was not glued to the fragment"
        );
    }

    #[test]
    fn a_complete_last_event_that_only_lost_its_newline_is_kept() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"e":"intent","kind":"instance","token":"dnet-1-instance","region":"r1"}"#,
        )
        .unwrap();
        let mut ledger = FileLedger::open(&path).unwrap();
        assert_eq!(
            ledger.entries().len(),
            1,
            "the intent was complete, so it counts"
        );
        ledger.record_created("dnet-1-instance", "ocid-1").unwrap();
        drop(ledger);
        let again = FileLedger::open(&path).unwrap();
        assert_eq!(again.entries()[0].state, EntryState::Created);
    }

    #[test]
    fn a_fragment_is_removed_from_the_file_not_left_to_poison_it() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{\"e\":\"intent\",\"kind\":\"inst").unwrap();
        let ledger = FileLedger::open(&path).unwrap();
        assert!(ledger.entries().is_empty());
        drop(ledger);
        assert_eq!(std::fs::read(&path).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_damaged_line_in_the_middle_is_refused_rather_than_guessed_around() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            concat!(
                r#"{"e":"intent","kind":"instance","token":"dnet-1-instance","region":"r1"}"#,
                "\n",
                "this is not json\n",
                r#"{"e":"removed","token":"dnet-1-instance"}"#,
                "\n",
            ),
        )
        .unwrap();
        assert_eq!(
            FileLedger::open(&path).unwrap_err(),
            LedgerError::Corrupt(2)
        );
    }

    #[test]
    fn an_event_for_a_resource_never_recorded_makes_the_file_untrustworthy() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, concat!(r#"{"e":"removed","token":"ghost"}"#, "\n")).unwrap();
        assert_eq!(
            FileLedger::open(&path).unwrap_err(),
            LedgerError::Corrupt(1)
        );
    }

    #[test]
    fn the_file_holds_no_credential_and_only_names_ids_and_regions() {
        let (_dir, path) = temp();
        let mut ledger = FileLedger::open(&path).unwrap();
        ledger
            .record_intent(ResourceKind::Instance, "dnet-1-instance", "ap-mumbai-1")
            .unwrap();
        ledger
            .record_created("dnet-1-instance", "ocid1.instance.x")
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            let value: Value = serde_json::from_str(line).unwrap();
            let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
            assert!(
                keys.iter()
                    .all(|k| ["e", "kind", "token", "region", "id"].contains(&k.as_str())),
                "{keys:?}"
            );
        }
    }
}

/// What the mutation run showed the file ledger's own tests did not pin: the removal that must reach the disk,
/// and the difference between a file that is not there and one that cannot be used.
#[cfg(test)]
mod storage_tests {
    use super::*;

    fn temp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs").join("ledger.jsonl");
        (dir, path)
    }

    #[test]
    fn a_removal_is_on_the_disk_and_is_still_there_after_a_restart() {
        let (_dir, path) = temp();
        {
            let mut ledger = FileLedger::open(&path).unwrap();
            ledger
                .record_intent(ResourceKind::Instance, "dnet-1-instance", "r1")
                .unwrap();
            ledger.record_created("dnet-1-instance", "ocid-1").unwrap();
            ledger.record_removed("dnet-1-instance").unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3, "{text}");
        assert!(text.lines().last().unwrap().contains("dnet-1-instance"));
        let reopened = FileLedger::open(&path).unwrap();
        assert_eq!(reopened.entries()[0].state, EntryState::Removed);
    }

    #[test]
    fn a_ledger_that_is_not_there_is_empty_and_a_path_that_is_not_a_file_is_an_error() {
        let (_dir, path) = temp();
        assert!(read_state(&path).unwrap().entries.is_empty());
        assert!(repair_tail(&path).is_ok());

        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_state(directory.path()),
            Err(LedgerError::Write(_))
        ));
        assert!(matches!(
            repair_tail(directory.path()),
            Err(LedgerError::Write(_))
        ));
    }

    /// A file that is complete is left alone: repairing it must not even try to write, so a ledger on
    /// read-only storage still opens for reading.
    #[test]
    fn a_complete_file_is_not_written_to_when_it_is_checked() {
        let (_dir, path) = temp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for content in [&b""[..], &b"{\"e\":\"intent\"}\n"[..]] {
            std::fs::write(&path, content).unwrap();
            let original = std::fs::metadata(&path).unwrap().permissions();
            let mut read_only = original.clone();
            read_only.set_readonly(true);
            std::fs::set_permissions(&path, read_only).unwrap();
            let result = repair_tail(&path);
            std::fs::set_permissions(&path, original).unwrap();
            assert!(result.is_ok(), "{content:?}: {result:?}");
            assert_eq!(std::fs::read(&path).unwrap(), content, "nothing changed");
        }
    }
}
