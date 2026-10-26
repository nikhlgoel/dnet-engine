//! T092 — taking back what a job made (PR-08, PR-09, PR-11, SC-011).
//!
//! Cleanup runs when a person cancels, when a stage fails, and when a crashed job is picked up again. It
//! works from the **ledger**, not from what the job remembers, so it covers exactly what the job recorded
//! before it made anything (T090). For each resource, newest first (the firewall rules before the machine
//! they belong to):
//!
//! - if the provider's id was recorded, delete by it;
//! - if only the intent was recorded (the job died between "about to create" and "created"), look for the
//!   resource by the **token** the job chose; if nothing has that token, it was never made;
//! - if the provider says it is already gone, that is success.
//!
//! **Idempotent (PR-11).** Running it twice produces the same report and no error: a resource already
//! marked removed is not touched again, and one that is gone at the provider counts as removed.
//!
//! **Honest about failure (PR-09, SC-011).** A resource that cannot be removed (the provider refuses, the
//! credential no longer works, the network is down) is never dropped from the report. It is listed with
//! what the person needs to remove it by hand: what it is, its id or the name to search for, and where.
//! Cleanup that quietly leaves a billable machine running is the worst thing this crate could do.

use crate::ledger::{EntryState, Ledger, LedgerEntry, LedgerError};
use crate::provider::{DeleteOutcome, Provider, ResourceKind};
use crate::sanitize::Sanitizer;

/// A resource that is gone (removed now, removed earlier, or never made).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub kind: ResourceKind,
    pub token: String,
    pub region: String,
}

/// A resource that is still there, with what is needed to remove it by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unremovable {
    pub kind: ResourceKind,
    /// The name the job gave it: searchable in the provider's console.
    pub token: String,
    pub provider_id: Option<String>,
    pub region: String,
    /// Why it could not be removed, in the provider's words, with any credential removed.
    pub reason: String,
}

impl Unremovable {
    /// One line a person can act on.
    pub fn describe(&self) -> String {
        let id = self.provider_id.as_deref().map_or_else(
            || format!("search for the name \"{}\"", self.token),
            |id| format!("id {id}"),
        );
        format!(
            "{} in {} ({id}) is still there: {}",
            self.kind.as_str(),
            self.region,
            self.reason
        )
    }
}

/// The state of the job's resources after cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupReport {
    /// Everything the ledger records as gone, oldest first.
    pub removed: Vec<Removed>,
    /// Everything still there, newest first (the order removal was tried in).
    pub unremovable: Vec<Unremovable>,
}

impl CleanupReport {
    /// Whether nothing is left behind.
    pub fn is_complete(&self) -> bool {
        self.unremovable.is_empty()
    }
}

/// Remove everything `ledger` records as not yet gone. `Err` only when the ledger itself cannot be written.
pub fn cleanup(
    provider: &dyn Provider,
    ledger: &mut dyn Ledger,
    sanitizer: &Sanitizer,
) -> Result<CleanupReport, LedgerError> {
    let mut unremovable = Vec::new();
    let entries = ledger.entries();
    for entry in entries
        .iter()
        .rev()
        .filter(|e| e.state != EntryState::Removed)
    {
        match remove_one(provider, entry, sanitizer) {
            Ok(()) => ledger.record_removed(&entry.token)?,
            Err(reason) => unremovable.push(Unremovable {
                kind: entry.kind,
                token: entry.token.clone(),
                provider_id: entry.provider_id.clone(),
                region: entry.region.clone(),
                reason,
            }),
        }
    }
    let removed = ledger
        .entries()
        .into_iter()
        .filter(|e| e.state == EntryState::Removed)
        .map(|e| Removed {
            kind: e.kind,
            token: e.token,
            region: e.region,
        })
        .collect();
    Ok(CleanupReport {
        removed,
        unremovable,
    })
}

/// `Ok` when the resource is gone; `Err` with the reason when it may not be.
fn remove_one(
    provider: &dyn Provider,
    entry: &LedgerEntry,
    sanitizer: &Sanitizer,
) -> Result<(), String> {
    let id = match &entry.provider_id {
        Some(id) => id.clone(),
        // Only the intent was recorded. Ask the provider whether anything carries the token.
        None => match provider.find(entry.kind, &entry.token, &entry.region) {
            Ok(Some(id)) => id,
            Ok(None) => return Ok(()),
            Err(e) => return Err(sanitizer.clean(&e.to_string())),
        },
    };
    match provider.delete(entry.kind, &id, &entry.region) {
        Ok(DeleteOutcome::Deleted | DeleteOutcome::AlreadyGone) => Ok(()),
        Err(e) => Err(sanitizer.clean(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::MemoryLedger;
    use crate::mock::MockProvider;
    use crate::provider::ProviderError;

    fn ledger_with(created: &[(ResourceKind, &str, Option<&str>)]) -> MemoryLedger {
        let mut ledger = MemoryLedger::new();
        for (kind, token, id) in created {
            ledger.record_intent(*kind, token, "r1").unwrap();
            if let Some(id) = id {
                ledger.record_created(token, id).unwrap();
            }
        }
        ledger
    }

    #[test]
    fn everything_recorded_is_removed_newest_first() {
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "i-1");
        provider.seed(ResourceKind::NetworkRule, "t-network", "n-1");
        let mut ledger = ledger_with(&[
            (ResourceKind::Instance, "t-instance", Some("i-1")),
            (ResourceKind::NetworkRule, "t-network", Some("n-1")),
        ]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(report.is_complete());
        assert_eq!(report.removed.len(), 2);
        assert_eq!(provider.remaining(), 0);
        assert_eq!(
            provider.deletions(),
            ["network-rule:n-1", "instance:i-1"],
            "the rules go before the machine they belong to"
        );
    }

    #[test]
    fn a_resource_whose_id_was_never_recorded_is_found_by_its_token() {
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "i-9");
        // The job died after the intent and before the id was recorded.
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "t-instance", None)]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(report.is_complete());
        assert_eq!(provider.remaining(), 0, "the leaked machine is gone");
    }

    #[test]
    fn an_intent_that_never_became_a_resource_is_simply_marked_gone() {
        let provider = MockProvider::new();
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "t-instance", None)]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(report.is_complete());
        assert_eq!(report.removed.len(), 1);
        assert!(
            provider.deletions().is_empty(),
            "nothing was there to delete"
        );
    }

    #[test]
    fn a_resource_already_gone_at_the_provider_counts_as_removed() {
        let provider = MockProvider::new();
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "t-instance", Some("i-1"))]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(report.is_complete());
    }

    #[test]
    fn running_it_twice_gives_the_same_report_and_touches_nothing_the_second_time() {
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "i-1");
        provider.seed(ResourceKind::NetworkRule, "t-network", "n-1");
        let mut ledger = ledger_with(&[
            (ResourceKind::Instance, "t-instance", Some("i-1")),
            (ResourceKind::NetworkRule, "t-network", Some("n-1")),
        ]);
        let first = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        let calls_after_first = provider.call_count();
        let second = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            provider.call_count(),
            calls_after_first,
            "the second run made no provider call"
        );
    }

    #[test]
    fn what_cannot_be_removed_is_reported_with_what_is_needed_to_remove_it_by_hand() {
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "ocid-instance-1");
        provider.seed(ResourceKind::NetworkRule, "t-network", "n-1");
        provider.refuse_deleting(
            "ocid-instance-1",
            ProviderError::Rejected("still has an attached volume".into()),
        );
        let mut ledger = ledger_with(&[
            (
                ResourceKind::Instance,
                "t-instance",
                Some("ocid-instance-1"),
            ),
            (ResourceKind::NetworkRule, "t-network", Some("n-1")),
        ]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(!report.is_complete());
        assert_eq!(report.removed.len(), 1, "the rule was removed regardless");
        let left = &report.unremovable[0];
        assert_eq!(left.provider_id.as_deref(), Some("ocid-instance-1"));
        assert_eq!(left.region, "r1");
        let line = left.describe();
        for needed in ["instance", "r1", "ocid-instance-1", "attached volume"] {
            assert!(line.contains(needed), "{line}");
        }
    }

    #[test]
    fn a_resource_with_no_recorded_id_is_described_by_the_name_to_search_for() {
        let provider = MockProvider::new();
        provider.fail_finding(ProviderError::Transient(
            "the provider is unreachable".into(),
        ));
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "dnet-abc-instance", None)]);
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        let line = report.unremovable[0].describe();
        assert!(
            line.contains("search for the name \"dnet-abc-instance\""),
            "{line}"
        );
    }

    #[test]
    fn an_unremovable_resource_is_tried_again_by_the_next_run() {
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "i-1");
        provider.refuse_deleting("i-1", ProviderError::Transient("busy".into()));
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "t-instance", Some("i-1"))]);
        assert!(!cleanup(&provider, &mut ledger, &Sanitizer::new())
            .unwrap()
            .is_complete());
        provider.allow_deleting("i-1");
        let report = cleanup(&provider, &mut ledger, &Sanitizer::new()).unwrap();
        assert!(report.is_complete());
        assert_eq!(provider.remaining(), 0);
    }

    #[test]
    fn a_credential_in_the_providers_words_never_reaches_the_report() {
        use crate::secret::Secret;
        const KEY: &str = "SENTINEL-credential-0123456789abcdef";
        let provider = MockProvider::new();
        provider.seed(ResourceKind::Instance, "t-instance", "i-1");
        provider.refuse_deleting(
            "i-1",
            ProviderError::Rejected(format!("bad signature for {KEY}")),
        );
        let mut ledger = ledger_with(&[(ResourceKind::Instance, "t-instance", Some("i-1"))]);
        let sanitizer = Sanitizer::new().with_secret(Secret::new(KEY));
        let report = cleanup(&provider, &mut ledger, &sanitizer).unwrap();
        assert!(!format!("{report:?}").contains("SENTINEL"), "{report:?}");
        assert!(!report.unremovable[0].describe().contains("SENTINEL"));
    }
}
