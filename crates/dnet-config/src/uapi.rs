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

impl UapiRequest {
    /// The complete `set` operation as sent on the pipe: `set=1`, the lines, and the
    /// terminating blank line (framing verified against the pinned core's `IpcHandle`).
    pub fn to_set_operation(&self) -> String {
        format!("set=1\n{}", self.to_wire())
    }
}

/// A UAPI failure. Never carries request content, so it is always safe to log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UapiError {
    /// The pipe did not appear (the core never started listening) within the timeout.
    #[error("UAPI pipe did not become available within the timeout")]
    PipeUnavailable,
    /// Connecting, writing, or reading the pipe failed.
    #[error("UAPI pipe I/O failed: {0}")]
    Io(String),
    /// The core answered but rejected the operation with a non-zero `errno`.
    #[error("UAPI operation rejected by the core (errno={0})")]
    Rejected(i64),
    /// The response was not a well-formed `errno=N` block.
    #[error("malformed UAPI response")]
    Malformed,
    /// No complete response arrived within the timeout.
    #[error("UAPI response timed out")]
    Timeout,
}

/// Parse a `set` response. The core replies `errno=0` on success and `errno=N` (non-zero)
/// on failure, followed by a blank line.
pub fn parse_set_response(response: &str) -> Result<(), UapiError> {
    let errno = response
        .lines()
        .find_map(|l| l.strip_prefix("errno="))
        .ok_or(UapiError::Malformed)?
        .trim()
        .parse::<i64>()
        .map_err(|_| UapiError::Malformed)?;
    match errno {
        0 => Ok(()),
        n => Err(UapiError::Rejected(n)),
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
    fn set_operation_is_framed_with_set_and_a_blank_line() {
        let mut req = UapiRequest::new();
        req.push("replace_peers", "true");
        assert_eq!(req.to_set_operation(), "set=1\nreplace_peers=true\n\n");
    }

    #[test]
    fn responses_parse_to_success_or_a_distinct_rejection() {
        assert_eq!(parse_set_response("errno=0\n\n"), Ok(()));
        assert_eq!(
            parse_set_response("errno=-22\n\n"),
            Err(UapiError::Rejected(-22))
        );
        assert_eq!(parse_set_response("garbage\n\n"), Err(UapiError::Malformed));
        assert_eq!(parse_set_response("errno=x\n\n"), Err(UapiError::Malformed));
    }

    #[test]
    fn wire_is_blank_line_terminated() {
        let mut req = UapiRequest::new();
        req.push("public_key", "abc");
        assert!(req.to_wire().ends_with("\n\n"));
    }
}
