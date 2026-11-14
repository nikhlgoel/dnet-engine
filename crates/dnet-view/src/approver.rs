// SPDX-License-Identifier: GPL-3.0-or-later
//! T160b — approving a waiting change from the window.
//!
//! The window is an ordinary program of the person, so the service refuses it the one thing it must not
//! be able to do alone: approving a change that redirects traffic. Only an *elevated* client may, and the
//! person makes one by answering the Windows prompt. So the window does not ask the service to approve; it
//! starts `dnetctl approve <id>`, which shows the change, asks Windows for elevation, shows the change
//! again there (the Windows prompt names the program, not the server) and applies it only if the person
//! types `yes`. This module is the part of that which needs no window: what to run, and what its ending
//! means to the person. The shell does the running.
//!
//! The id is checked with the service's own grammar before anything is started, and it is the only thing
//! handed to the other program: a window command cannot make `dnetctl` do anything but approve one change.

use dnet_ipc::protocol::decode_request;
use serde_json::{json, Value};

use crate::outcome::{done, refused};

/// The program that approves: it sits beside the window's own program.
pub const APPROVER: &str = "dnetctl.exe";

/// `dnetctl`'s exit code for "done".
const OK: i32 = 0;
/// `dnetctl`'s exit code for "refused or failed": declined at the Windows prompt, not typed `yes`, the
/// change is gone, or the service refused.
const REFUSED: i32 = 1;

/// The arguments for `dnetctl` to approve `id`, or why they cannot be made. `any_service` passes the
/// development option the window itself was started with, so both talk to the same pipe.
pub fn arguments(id: &str, any_service: bool) -> Result<Vec<String>, String> {
    // The service's grammar for a change id, applied here, so a bad name is refused before a program
    // is started.
    let wire = json!({ "request": "ApproveChange", "id": id });
    decode_request(&wire.to_string()).map_err(|e| e.to_string())?;
    let mut args = vec!["approve".to_owned(), id.to_owned()];
    if any_service {
        args.push("--allow-unprivileged-service".to_owned());
    }
    Ok(args)
}

/// What the end of the approving program means, as the window's outcome. `exit` is its exit code, or
/// `None` when it could not be started or ended without one.
pub fn outcome(exit: Option<i32>) -> Value {
    match exit {
        Some(OK) => done(json!({})),
        Some(REFUSED) => refused(
            "Not approved. Nothing was changed: the Windows prompt was declined, yes was not typed, or the \
             change is no longer waiting. It stays waiting for the ten minutes it was given, unless you drop it.",
            "Refused",
        ),
        Some(other) => refused(
            &format!(
                "The approval window ended without a clear answer (code {other}). Nothing is known to \
                 have changed; check the list of waiting changes."
            ),
            "Refused",
        ),
        None => refused(
            "The approval program could not be started or ended without an answer. Nothing is known to have \
             changed; check the list of waiting changes.",
            "Refused",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_name_of_the_change_is_handed_over() {
        assert_eq!(
            arguments("a1b2c3d4", false).unwrap(),
            ["approve", "a1b2c3d4"]
        );
    }

    #[test]
    fn the_development_option_is_passed_only_when_the_window_has_it() {
        let with = arguments("a1", true).unwrap();
        assert_eq!(with, ["approve", "a1", "--allow-unprivileged-service"]);
        assert!(!arguments("a1", false)
            .unwrap()
            .iter()
            .any(|a| a.starts_with("--")));
    }

    /// Nothing that is not a plain short name reaches a command line: no space, quote, path or option.
    #[test]
    fn a_name_that_is_not_a_plain_short_name_starts_nothing() {
        let too_long = "a".repeat(33);
        for bad in [
            "",
            "A1",
            "a b",
            "a\"b",
            "../x",
            "-x",
            "--yes",
            "a;b",
            "a&b",
            "é",
            too_long.as_str(),
        ] {
            assert!(arguments(bad, false).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_successful_approval_is_done() {
        assert_eq!(outcome(Some(0)), json!({ "ok": true }));
    }

    #[test]
    fn a_refusal_says_nothing_changed_and_how_long_it_waits() {
        let shown = outcome(Some(1));
        assert_eq!(shown["ok"], json!(false));
        let reason = shown["reason"].as_str().unwrap();
        assert!(reason.contains("Nothing was changed"), "{reason}");
        assert!(reason.contains("ten minutes"), "{reason}");
    }

    /// An ending nobody can read is never reported as an approval, and never as certainly not one.
    #[test]
    fn an_unclear_ending_is_not_reported_as_done() {
        for exit in [Some(2), Some(3), Some(-1), Some(i32::MAX), None] {
            let shown = outcome(exit);
            assert_eq!(shown["ok"], json!(false), "{exit:?}");
            assert!(
                shown["reason"]
                    .as_str()
                    .unwrap()
                    .contains("Nothing is known to have changed"),
                "{exit:?}"
            );
        }
    }
}
