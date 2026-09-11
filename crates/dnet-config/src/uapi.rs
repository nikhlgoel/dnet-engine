//! T050 — the AmneziaWG UAPI client wire format (research.md §R5).
//!
//! AmneziaWG is configured at runtime over its UAPI named pipe (under
//! `\\.\pipe\ProtectedPrefix\Administrators\...`; the exact leaf is the adapter name and
//! is supplied by the OS pipe layer, not spelled here) as text `key=value` lines, one
//! operation terminated by a blank line. This module builds that wire text.
//!
//! Secret values (the private key) are marked as such so a request can be rendered for a
//! log or diagnostic with the secret redacted, while only the wire form written to the
//! pipe carries the real value (AW-05, AWG-06). The `Debug` impl is the redacted form,
//! so a request can never leak a key through `{:?}` in a log line.

use std::fmt;

/// One `key=value` line, flagged if its value is secret.
#[derive(Clone, PartialEq, Eq)]
struct UapiLine {
    key: String,
    value: String,
    secret: bool,
}

/// A single UAPI operation: an ordered set of `key=value` lines.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UapiRequest {
    lines: Vec<UapiLine>,
}

impl UapiRequest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a non-secret line.
    pub fn push(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.lines.push(UapiLine {
            key: key.into(),
            value: value.into(),
            secret: false,
        });
        self
    }

    /// Append a secret line (its value is redacted in every rendering except the wire
    /// form written to the pipe).
    pub fn push_secret(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.lines.push(UapiLine {
            key: key.into(),
            value: value.into(),
            secret: true,
        });
        self
    }

    /// Whether a line with this key is present.
    pub fn has_key(&self, key: &str) -> bool {
        self.lines.iter().any(|l| l.key == key)
    }

    /// The wire text sent to the UAPI pipe: every value in full, blank-line terminated.
    /// This is the **only** rendering that contains secret values.
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(&line.key);
            out.push('=');
            out.push_str(&line.value);
            out.push('\n');
        }
        out.push('\n');
        out
    }

    /// A log-safe rendering: secret values replaced with `<redacted>`.
    pub fn redacted(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(&line.key);
            out.push('=');
            out.push_str(if line.secret {
                "<redacted>"
            } else {
                &line.value
            });
            out.push('\n');
        }
        out
    }
}

/// `Debug` is the redacted form, so a request logged with `{:?}` never leaks a secret.
impl fmt::Debug for UapiRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UapiRequest(\n{})", self.redacted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_carries_secrets_but_redacted_and_debug_do_not() {
        let mut req = UapiRequest::new();
        req.push_secret("private_key", "DEADBEEFSECRETKEY")
            .push("public_key", "PEERPUBLIC");

        assert!(req.to_wire().contains("DEADBEEFSECRETKEY"));
        assert!(!req.redacted().contains("DEADBEEFSECRETKEY"));
        assert!(req.redacted().contains("private_key=<redacted>"));
        assert!(!format!("{req:?}").contains("DEADBEEFSECRETKEY"));
        // Non-secret values remain visible.
        assert!(req.redacted().contains("public_key=PEERPUBLIC"));
    }

    #[test]
    fn wire_is_blank_line_terminated() {
        let mut req = UapiRequest::new();
        req.push("public_key", "abc");
        assert!(req.to_wire().ends_with("\n\n"));
    }
}
