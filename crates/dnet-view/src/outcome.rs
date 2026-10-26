//! T100 — the result of something the person asked for, as the window reads it.
//!
//! Success is `{ "ok": true, ..extra }`. Anything else is `{ "ok": false, "reason": <text>, "code": <one of
//! four> }`. The reason is the service's own `detail` (cleaned and bounded) so the person reads what the
//! service said; it is never a sentence composed here to hide one. The code is the little the window needs to
//! decide what to do next: ask for a consent, say the service is busy, say nothing is connected, or just show
//! the reason.

use dnet_ipc::client::{ClientError, Reply};
use serde_json::{json, Value};

use crate::text::plain;

/// The longest reason shown. A refusal is a sentence or two; more is not a refusal.
const REASON_MAX: usize = 400;

/// A success, with whatever the caller adds to it.
#[must_use]
pub fn done(extra: Value) -> Value {
    let mut out = json!({ "ok": true });
    if let (Some(out), Value::Object(extra)) = (out.as_object_mut(), extra) {
        out.extend(extra);
    }
    out
}

/// A refusal in the window's four codes.
#[must_use]
pub fn refused(reason: &str, code: &str) -> Value {
    json!({ "ok": false, "reason": plain(reason, REASON_MAX), "code": code })
}

/// The window's code for the service's wire code.
#[must_use]
pub fn code_for(wire: &str) -> &'static str {
    match wire {
        "TierDowngradeRequiresConsent" => "TierConsentRequired",
        "ServiceBusy" => "ServiceBusy",
        "NotConnected" => "NotConnected",
        _ => "Refused",
    }
}

/// What a failure to ask at all looks like: the service is not there, or does not speak this program's
/// protocol. The text says which, and what to do (`ClientError` always does).
#[must_use]
pub fn unreachable(error: &ClientError) -> Value {
    refused(&error.to_string(), "ServiceBusy")
}

/// Read a reply to a request that changes something.
///
/// `on_done` reads the service's answer and returns the extra fields of the success; an `Err` means the answer
/// was not what the contract promises, which is reported as such and never as success.
pub fn from_reply(
    result: Result<Reply, ClientError>,
    on_done: impl FnOnce(&Value) -> Result<Value, String>,
) -> Value {
    match result {
        Err(error) => unreachable(&error),
        Ok(Reply::Refused(refusal)) => {
            let reason = if refusal.detail.is_empty() {
                "The service declined, and gave no reason."
            } else {
                &refusal.detail
            };
            refused(reason, code_for(&refusal.code))
        }
        Ok(Reply::Done(value)) => match on_done(&value) {
            Ok(extra) => done(extra),
            Err(why) => refused(&why, "Refused"),
        },
    }
}
