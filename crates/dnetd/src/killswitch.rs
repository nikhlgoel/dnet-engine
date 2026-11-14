// SPDX-License-Identifier: GPL-3.0-or-later
//! T161 — the person's choice about the kill switch (ADR-0006 §5a), remembered across restarts.
//!
//! Whether the service keeps a firewall guard in while a connection is up is the person's decision, and
//! it is off until they turn it on: a guard that cuts the network when the tunnel is gone is the point of
//! it, and also a thing to be chosen, not met by surprise.
//!
//! The file sits beside the configuration under the same owner and DACL check. It is read like this:
//!
//! - **no file:** off (never chosen, or turned off);
//! - **exactly what this module writes:** the choice it records;
//! - **a file that is there but cannot be read, or is not what this build wrote:** **on.** Somebody asked
//!   for protection once; a damaged record must not quietly take it away. This is the opposite of the
//!   remembered connection (`intent.rs`), which reads as off, because routing is changed at start-up only
//!   on a clear record; here the doubt is about whether to *keep* a protection, and the way out
//!   (`ReleaseGuard`, `dnetctl guard-release`) never depends on this file.

use dnet_config::persist::StateFile;
use serde_json::{json, Map, Value};

/// The only format this build writes.
const VERSION: u64 = 1;

/// The person's choice, kept in one small state file.
///
/// What was last set in this run is also held in memory and wins over the file: a choice whose file could not
/// be written still stands until the service stops.
pub struct KillSwitch {
    file: Box<dyn StateFile>,
    choice: std::sync::Mutex<Option<bool>>,
}

impl KillSwitch {
    #[cfg_attr(not(windows), allow(dead_code))] // The Windows service builds one; so do the tests.
    pub fn new(file: Box<dyn StateFile>) -> Self {
        Self {
            file,
            choice: std::sync::Mutex::new(None),
        }
    }

    fn remember(&self, enabled: bool) {
        *self
            .choice
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(enabled);
    }

    /// Whether the kill switch is on.
    pub fn enabled(&self) -> bool {
        let mut choice = self
            .choice
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(enabled) = *choice {
            return enabled;
        }
        let enabled = self.read_file();
        *choice = Some(enabled);
        enabled
    }

    fn read_file(&self) -> bool {
        let bytes = match self.file.read() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(%error, "the kill-switch choice could not be read; keeping it on");
                return true;
            }
        };
        decode(&bytes).unwrap_or_else(|| {
            tracing::warn!(
                "the kill-switch choice is not in a form this build wrote; keeping it on"
            );
            true
        })
    }

    /// The person turned it on or off. Off leaves no file. The choice stands in memory even if the file could
    /// not be written; the error says so, for the log and the reply.
    pub fn set(&self, enabled: bool) -> Result<(), String> {
        self.remember(enabled);
        if enabled {
            let mut record = Map::new();
            record.insert("version".into(), json!(VERSION));
            record.insert("enabled".into(), json!(true));
            self.file
                .write(Value::Object(record).to_string().as_bytes())
        } else {
            self.file.remove()
        }
    }
}

/// `Some(choice)` for exactly the record this build writes (or the same with `false`); anything else `None`.
fn decode(bytes: &[u8]) -> Option<bool> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let record = value.as_object()?;
    if record
        .keys()
        .any(|key| !matches!(key.as_str(), "version" | "enabled"))
    {
        return None;
    }
    if record.get("version")?.as_u64()? != VERSION {
        return None;
    }
    record.get("enabled")?.as_bool()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnet_config::persist::MemoryStateFile;

    use super::*;

    fn switch_over(bytes: Option<&str>) -> (KillSwitch, Arc<MemoryStateFile>) {
        let file = Arc::new(MemoryStateFile::with_bytes(
            bytes.map(|b| b.as_bytes().to_vec()),
        ));
        (KillSwitch::new(Box::new(Arc::clone(&file))), file)
    }

    #[test]
    fn it_is_off_until_the_person_turns_it_on() {
        assert!(!switch_over(None).0.enabled());
    }

    #[test]
    fn turning_it_on_survives_a_restart() {
        let (switch, file) = switch_over(None);
        switch.set(true).unwrap();
        assert!(switch.enabled());
        // A new service over the same file.
        let again = KillSwitch::new(Box::new(Arc::clone(&file)));
        assert!(again.enabled());
    }

    #[test]
    fn turning_it_off_leaves_no_file() {
        let (switch, file) = switch_over(None);
        switch.set(true).unwrap();
        switch.set(false).unwrap();
        assert!(!switch.enabled());
        assert_eq!(file.bytes(), None);
        // Off again is not an error.
        switch.set(false).unwrap();
        assert!(!KillSwitch::new(Box::new(Arc::clone(&file))).enabled());
    }

    #[test]
    fn the_record_has_exactly_the_fields_this_build_reads() {
        let (switch, file) = switch_over(None);
        switch.set(true).unwrap();
        let written: Value = serde_json::from_slice(&file.bytes().unwrap()).unwrap();
        assert_eq!(written, json!({ "version": 1, "enabled": true }));
    }

    /// A record that is there but is not what this build wrote keeps the protection on.
    #[test]
    fn a_damaged_record_keeps_it_on() {
        for bytes in [
            "",
            "not json",
            "[]",
            "null",
            "true",
            r#"{"version":1}"#,
            r#"{"version":2,"enabled":true}"#,
            r#"{"version":1,"enabled":"true"}"#,
            r#"{"version":1,"enabled":1}"#,
            r#"{"version":1,"enabled":true,"profile":"x"}"#,
            r#"{"enabled":true}"#,
        ] {
            assert!(switch_over(Some(bytes)).0.enabled(), "{bytes:?}");
        }
    }

    #[test]
    fn a_record_that_says_off_is_off() {
        assert!(!switch_over(Some(r#"{"version":1,"enabled":false}"#))
            .0
            .enabled());
    }

    #[test]
    fn a_file_that_cannot_be_read_keeps_it_on() {
        struct Broken;
        impl StateFile for Broken {
            fn read(&self) -> Result<Option<Vec<u8>>, String> {
                Err("access denied".into())
            }
            fn write(&self, _: &[u8]) -> Result<(), String> {
                Err("access denied".into())
            }
            fn remove(&self) -> Result<(), String> {
                Err("access denied".into())
            }
        }
        assert!(KillSwitch::new(Box::new(Broken)).enabled());
    }

    /// A choice whose file could not be written still stands for this run, and the caller is told.
    #[test]
    fn a_choice_that_could_not_be_saved_still_stands_and_says_so() {
        struct Broken;
        impl StateFile for Broken {
            fn read(&self) -> Result<Option<Vec<u8>>, String> {
                Ok(None)
            }
            fn write(&self, _: &[u8]) -> Result<(), String> {
                Err("disk full".into())
            }
            fn remove(&self) -> Result<(), String> {
                Err("disk full".into())
            }
        }
        let switch = KillSwitch::new(Box::new(Broken));
        assert_eq!(switch.set(true), Err("disk full".to_owned()));
        assert!(switch.enabled());
        assert_eq!(switch.set(false), Err("disk full".to_owned()));
        assert!(!switch.enabled());
    }
}
