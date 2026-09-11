//! Credential material that reaches a supervised core's configuration and nowhere else.
//!
//! The primary core reads its credentials (the Hysteria 2 passwords, the VLESS user id, the
//! REALITY short id) from its config file, so they must be serialized there (CC-08: the file
//! is restricted to SYSTEM and Administrators). They must not reach a log line, a diagnostic
//! bundle or an error message (FR-035). [`Secret`] makes the two paths differ: `Serialize`
//! writes the value, while `Debug` and `Display` never do. Everything that ends up in a log
//! goes through `Debug` or `Display`.

use std::fmt;

use serde::{Serialize, Serializer};

/// A credential value, resolved from the credential store at the system boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(material: impl Into<String>) -> Self {
        Self(material.into())
    }

    /// The value, for validation and serialization inside this crate only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Writes the value. Only the generated core configuration is serialized.
impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints_itself() {
        let s = Secret::new("TOPSECRET");
        assert!(!format!("{s:?}").contains("TOPSECRET"));
        assert!(!format!("{s}").contains("TOPSECRET"));
    }

    #[test]
    fn a_secret_serializes_its_value_for_the_core() {
        let s = Secret::new("TOPSECRET");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"TOPSECRET\"");
        assert_eq!(s.expose(), "TOPSECRET");
    }
}
