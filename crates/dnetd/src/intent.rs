//! T147 — the connection stays the way the person left it (FR-036).
//!
//! A connect the person asked for is remembered, and a disconnect they asked for forgets it. When the
//! service starts again (a reboot, an update, a crash) and the last thing asked was a connect, it
//! connects again with the same choice of profile. Nothing else changes what is remembered: a failed
//! attempt, the service being stopped and the machine shutting down all leave it as it was, so a
//! person who turned the product on does not have to turn it on again after every restart.
//!
//! The file sits beside the configuration, under the same owner and DACL check, so only SYSTEM and
//! Administrators can make the service connect at start-up. Anything in it that is not exactly what
//! this module writes reads as "off": routing is changed at start-up only on a clear record of the
//! person asking for it (fail closed).

use dnet_config::persist::StateFile;
use dnet_core::ids::ProfileId;
use serde_json::{json, Map, Value};

/// The only format this build writes or reads.
const VERSION: u64 = 1;

/// The longest profile id a client may name (contracts/ipc-protocol.md).
const MAX_PROFILE_ID_LEN: usize = 64;

/// What the person last asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remembered {
    /// Nothing to resume: never connected, last asked to disconnect, or the record is unreadable.
    Off,
    /// Connect again at start-up, with this profile only, or the best one when `None`.
    On { profile: Option<ProfileId> },
}

/// The remembered intent, kept in one small state file.
///
/// What the person last asked for in this run is also held in memory, and wins over the file: a
/// disconnect whose file could not be removed is still off now (T148 must not retry it), and a connect
/// that could not be saved is still on until the service stops.
pub struct Intent {
    file: Box<dyn StateFile>,
    wish: std::sync::Mutex<Option<Remembered>>,
}

impl Intent {
    #[cfg_attr(not(windows), allow(dead_code))] // The Windows service builds one; so do the tests.
    pub fn new(file: Box<dyn StateFile>) -> Self {
        Self {
            file,
            wish: std::sync::Mutex::new(None),
        }
    }

    fn set_wish(&self, remembered: Remembered) {
        *self
            .wish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(remembered);
    }

    /// What was last asked for. `Off` for a missing, unreadable or unexpected file; the reason is
    /// logged, never the contents.
    pub fn load(&self) -> Remembered {
        let mut wish = self
            .wish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(remembered) = wish.as_ref() {
            return remembered.clone();
        }
        let remembered = self.read_file();
        *wish = Some(remembered.clone());
        remembered
    }

    fn read_file(&self) -> Remembered {
        let bytes = match self.file.read() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Remembered::Off,
            Err(error) => {
                tracing::warn!(%error, "the remembered connection could not be read; staying off");
                return Remembered::Off;
            }
        };
        decode(&bytes).unwrap_or_else(|| {
            tracing::warn!(
                "the remembered connection is not in a form this build wrote; staying off"
            );
            Remembered::Off
        })
    }

    /// The person asked to connect and it was accepted.
    pub fn remember_on(&self, profile: Option<&ProfileId>) -> Result<(), String> {
        self.set_wish(Remembered::On {
            profile: profile.cloned(),
        });
        let mut record = Map::new();
        record.insert("version".into(), json!(VERSION));
        record.insert("connect".into(), json!(true));
        if let Some(profile) = profile {
            record.insert("profile".into(), json!(profile.as_str()));
        }
        self.file
            .write(Value::Object(record).to_string().as_bytes())
    }

    /// The person asked to disconnect.
    pub fn forget(&self) -> Result<(), String> {
        self.set_wish(Remembered::Off);
        self.file.remove()
    }
}

fn decode(bytes: &[u8]) -> Option<Remembered> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let record = value.as_object()?;
    if record
        .keys()
        .any(|key| !matches!(key.as_str(), "version" | "connect" | "profile"))
    {
        return None;
    }
    if record.get("version")?.as_u64()? != VERSION || !record.get("connect")?.as_bool()? {
        return None;
    }
    let profile = match record.get("profile") {
        None => None,
        Some(Value::String(id)) if is_profile_id(id) => Some(ProfileId::new(id.as_str())),
        Some(_) => return None,
    };
    Some(Remembered::On { profile })
}

/// The same rule the control protocol applies to a profile a client names.
fn is_profile_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_PROFILE_ID_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !raw.starts_with('-')
        && !raw.ends_with('-')
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnet_config::persist::MemoryStateFile;

    use super::*;

    fn intent_over(bytes: Option<&str>) -> (Intent, Arc<MemoryStateFile>) {
        let file = Arc::new(MemoryStateFile::with_bytes(
            bytes.map(|b| b.as_bytes().to_vec()),
        ));
        (Intent::new(Box::new(Arc::clone(&file))), file)
    }

    #[test]
    fn nothing_remembered_is_off() {
        assert_eq!(intent_over(None).0.load(), Remembered::Off);
    }

    #[test]
    fn a_connect_is_remembered_with_its_profile_or_without_one() {
        let (intent, _) = intent_over(None);
        intent
            .remember_on(Some(&ProfileId::new("hy2-default")))
            .unwrap();
        assert_eq!(
            intent.load(),
            Remembered::On {
                profile: Some(ProfileId::new("hy2-default"))
            }
        );
        intent.remember_on(None).unwrap();
        assert_eq!(intent.load(), Remembered::On { profile: None });
    }

    #[test]
    fn a_disconnect_forgets_and_leaves_no_file() {
        let (intent, file) = intent_over(None);
        intent.remember_on(None).unwrap();
        intent.forget().unwrap();
        assert_eq!(intent.load(), Remembered::Off);
        assert_eq!(file.bytes(), None);
        intent.forget().unwrap();
    }

    /// Routing changes at start-up only on a record this build wrote. Anything else is off.
    #[test]
    fn anything_unexpected_reads_as_off() {
        for bytes in [
            "",
            "not json",
            "[]",
            "null",
            r#"{"version":1}"#,
            r#"{"version":1,"connect":false}"#,
            r#"{"version":1,"connect":"true"}"#,
            r#"{"version":2,"connect":true}"#,
            r#"{"connect":true}"#,
            r#"{"version":1,"connect":true,"extra":1}"#,
            r#"{"version":1,"connect":true,"profile":null}"#,
            r#"{"version":1,"connect":true,"profile":""}"#,
            r#"{"version":1,"connect":true,"profile":"HY2"}"#,
            r#"{"version":1,"connect":true,"profile":"-x"}"#,
            r#"{"version":1,"connect":true,"profile":"a/b"}"#,
            "{\"version\":1,\"connect\":true,\"profile\":\"hy2-default\u{202e}\"}",
        ] {
            assert_eq!(
                intent_over(Some(bytes)).0.load(),
                Remembered::Off,
                "{bytes}"
            );
        }
        let long = format!(
            r#"{{"version":1,"connect":true,"profile":"{}"}}"#,
            "a".repeat(65)
        );
        assert_eq!(intent_over(Some(&long)).0.load(), Remembered::Off);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_off() {
        struct Broken;
        impl StateFile for Broken {
            fn read(&self) -> Result<Option<Vec<u8>>, String> {
                Err("denied".into())
            }
            fn write(&self, _: &[u8]) -> Result<(), String> {
                Err("denied".into())
            }
            fn remove(&self) -> Result<(), String> {
                Err("denied".into())
            }
        }
        let intent = Intent::new(Box::new(Broken));
        assert_eq!(intent.load(), Remembered::Off);
        // Not saved, but what the person asked for still holds for this run, both ways.
        assert!(intent.remember_on(None).is_err());
        assert_eq!(intent.load(), Remembered::On { profile: None });
        assert!(intent.forget().is_err());
        assert_eq!(intent.load(), Remembered::Off);
    }
}
