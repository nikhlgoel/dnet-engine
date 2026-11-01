//! T160 — changes that redirect traffic wait for an elevated client (ADR-0008 F13;
//! `docs/research/2026-10-31-solutions.md` section 3.2).
//!
//! A program running as the console user can do everything the person can do from the window, so it
//! can also point the connection at a server of its own. A change that does that is therefore *held*
//! here, not applied, and a person approves it from an elevated client: Windows asks them on the
//! secure desktop, where a program running as the same user cannot answer for them.
//!
//! This module is only the holding: what is waiting, for how long, and under what name. It does no
//! I/O and reads no clock, so every rule is tested with times that are given. Which requests are held,
//! and who may approve, are decided elsewhere (`service_impl`, and `dnet_ipc::authz`).

use dnet_ipc::protocol::Request;
use serde_json::json;

/// How long a change waits. After that it is dropped and must be asked for again.
pub const HOLD_FOR_MS: u64 = 10 * 60 * 1000;

/// How many changes may wait at once. A program that asks for many cannot push out the one the
/// person is looking at: past this, new ones are refused until some are approved, withdrawn or expire.
pub const MAX_HELD: usize = 8;

/// A change that is waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub id: String,
    /// What it would do, in the person's words, naming the server or rule.
    pub what: String,
    pub request: Request,
    pub proposed_unix_ms: u64,
    pub expires_unix_ms: u64,
}

/// Why a change could not be held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldError {
    /// [`MAX_HELD`] changes are already waiting.
    Full,
}

/// Why a held change could not be found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindError {
    /// No change has this id (it may have been applied, withdrawn, or never existed).
    Unknown,
    /// It waited too long and was dropped.
    Expired,
}

/// The changes waiting for approval.
#[derive(Debug, Default)]
pub struct PendingChanges {
    held: Vec<Held>,
}

impl PendingChanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop what has waited too long.
    fn expire(&mut self, now_ms: u64) {
        self.held.retain(|h| h.expires_unix_ms > now_ms);
    }

    /// Hold `request` and return the id it waits under. Asking again for exactly the same change
    /// returns the same id and does not extend its time: a program cannot keep one alive for ever.
    /// `new_id` is called only when a new id is needed, and must not repeat one that is waiting.
    pub fn hold(
        &mut self,
        request: Request,
        what: String,
        now_ms: u64,
        new_id: impl FnOnce() -> String,
    ) -> Result<String, HoldError> {
        self.expire(now_ms);
        if let Some(same) = self.held.iter().find(|h| h.request == request) {
            return Ok(same.id.clone());
        }
        if self.held.len() >= MAX_HELD {
            return Err(HoldError::Full);
        }
        let mut id = new_id();
        // An id that is already waiting would let one change be approved as another.
        while self.held.iter().any(|h| h.id == id) {
            id.push('x');
        }
        self.held.push(Held {
            id: id.clone(),
            what,
            request,
            proposed_unix_ms: now_ms,
            expires_unix_ms: now_ms.saturating_add(HOLD_FOR_MS),
        });
        Ok(id)
    }

    /// The change waiting under `id`, if any, without removing it.
    pub fn find(&mut self, id: &str, now_ms: u64) -> Result<Held, FindError> {
        let expired = self
            .held
            .iter()
            .any(|h| h.id == id && h.expires_unix_ms <= now_ms);
        self.expire(now_ms);
        match self.held.iter().find(|h| h.id == id) {
            Some(held) => Ok(held.clone()),
            None if expired => Err(FindError::Expired),
            None => Err(FindError::Unknown),
        }
    }

    /// Forget the change under `id`. Whether there was one.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.held.len();
        self.held.retain(|h| h.id != id);
        self.held.len() != before
    }

    /// What is waiting, oldest first, as the wire reply to `ListPending`.
    pub fn list_json(&mut self, now_ms: u64) -> String {
        self.expire(now_ms);
        json!({
            "pending": self.held.iter().map(|h| json!({
                "id": h.id,
                "what": h.what,
                "proposed_unix_ms": h.proposed_unix_ms,
                "expires_unix_ms": h.expires_unix_ms,
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use dnet_core::ids::EndpointId;

    use super::*;

    fn change(enabled: bool) -> Request {
        Request::SetEndpointEnabled {
            endpoint: EndpointId::new(),
            enabled,
        }
    }

    fn hold_one(changes: &mut PendingChanges, request: Request, now: u64, id: &str) -> String {
        changes
            .hold(request, "a change".into(), now, || id.to_string())
            .unwrap()
    }

    #[test]
    fn a_held_change_is_found_by_its_id_and_is_exactly_the_one_that_was_held() {
        let mut changes = PendingChanges::new();
        let request = change(true);
        let id = hold_one(&mut changes, request.clone(), 1_000, "a1b2");
        let found = changes.find(&id, 2_000).unwrap();
        assert_eq!(found.request, request);
        assert_eq!(found.proposed_unix_ms, 1_000);
        assert_eq!(found.expires_unix_ms, 1_000 + HOLD_FOR_MS);
        // Finding does not remove it: a failed application leaves it for another try.
        assert!(changes.find(&id, 3_000).is_ok());
    }

    #[test]
    fn a_change_is_dropped_after_ten_minutes_and_says_so() {
        let mut changes = PendingChanges::new();
        let id = hold_one(&mut changes, change(true), 0, "a1");
        assert!(changes.find(&id, HOLD_FOR_MS - 1).is_ok());
        assert_eq!(changes.find(&id, HOLD_FOR_MS), Err(FindError::Expired));
        // Once reported, it is simply unknown.
        assert_eq!(changes.find(&id, HOLD_FOR_MS + 1), Err(FindError::Unknown));
    }

    #[test]
    fn an_id_nobody_holds_is_unknown() {
        let mut changes = PendingChanges::new();
        hold_one(&mut changes, change(true), 0, "a1");
        assert_eq!(changes.find("zz", 1), Err(FindError::Unknown));
    }

    #[test]
    fn asking_again_for_the_same_change_gives_the_same_id_and_the_same_deadline() {
        let mut changes = PendingChanges::new();
        let request = change(true);
        let first = hold_one(&mut changes, request.clone(), 0, "a1");
        let again = changes
            .hold(request, "a change".into(), 500_000, || {
                panic!("no new id for the same change")
            })
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(changes.len(), 1);
        // Not extended: it still ends ten minutes after the first ask.
        assert_eq!(changes.find(&first, HOLD_FOR_MS), Err(FindError::Expired));
    }

    #[test]
    fn only_so_many_changes_wait_and_a_flood_cannot_push_out_the_first() {
        let mut changes = PendingChanges::new();
        let first = change(true);
        let first_id = hold_one(&mut changes, first.clone(), 0, "first");
        for n in 1..MAX_HELD {
            hold_one(&mut changes, change(true), n as u64, &format!("id{n}"));
        }
        let refused = changes.hold(change(true), "one more".into(), 100, || "late".into());
        assert_eq!(refused, Err(HoldError::Full));
        // The first is still there, untouched.
        assert_eq!(changes.find(&first_id, 101).unwrap().request, first);
        // Room comes back by withdrawing one, or by time.
        assert!(changes.remove("id1"));
        assert!(changes
            .hold(change(true), "one more".into(), 102, || "late".into())
            .is_ok());
    }

    #[test]
    fn room_comes_back_when_the_old_ones_expire() {
        let mut changes = PendingChanges::new();
        for n in 0..MAX_HELD {
            hold_one(&mut changes, change(true), 0, &format!("id{n}"));
        }
        assert!(changes
            .hold(change(true), "x".into(), HOLD_FOR_MS, || "new".into())
            .is_ok());
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn two_changes_never_share_an_id() {
        let mut changes = PendingChanges::new();
        let a = hold_one(&mut changes, change(true), 0, "same");
        let b = hold_one(&mut changes, change(true), 0, "same");
        assert_ne!(a, b);
        assert_eq!(changes.len(), 2);
        // The ids still pass the wire rule for a change id.
        for id in [&a, &b] {
            assert!(id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn withdrawing_removes_it_and_says_whether_there_was_one() {
        let mut changes = PendingChanges::new();
        let id = hold_one(&mut changes, change(true), 0, "a1");
        assert!(changes.remove(&id));
        assert!(!changes.remove(&id));
        assert_eq!(changes.find(&id, 1), Err(FindError::Unknown));
    }

    #[test]
    fn the_list_is_oldest_first_and_has_no_expired_change() {
        let mut changes = PendingChanges::new();
        hold_one(&mut changes, change(true), 0, "old");
        hold_one(&mut changes, change(true), HOLD_FOR_MS, "new");
        let listed: serde_json::Value =
            serde_json::from_str(&changes.list_json(HOLD_FOR_MS + 1)).unwrap();
        let ids: Vec<_> = listed["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap().to_string())
            .collect();
        // "old" was held at 0, so it is gone by HOLD_FOR_MS + 1.
        assert_eq!(ids, ["new"]);
        let entry = &listed["pending"][0];
        assert_eq!(entry["what"], "a change");
        assert!(entry["expires_unix_ms"].as_u64().unwrap() > HOLD_FOR_MS);
    }

    #[test]
    fn the_list_carries_no_credential_whatever_is_held() {
        // `what` is the only description that leaves the module; the request itself never does.
        let mut changes = PendingChanges::new();
        hold_one(&mut changes, change(true), 0, "a1");
        let text = changes.list_json(1);
        assert!(!text.contains("credentials"));
        assert!(!text.contains("request"));
    }
}
