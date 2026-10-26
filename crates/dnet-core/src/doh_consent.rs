//! T071 — the first-run disclosure and the single-action opt-out for the encrypted-DNS override
//! (FR-025a).
//!
//! The product overrides a setting the person (or their program) chose: a browser set to use an
//! encrypted resolver will be sent back to the system's. That is done so the person's destination rules
//! work without their having to know any of this, but it is still the product changing what a program
//! does, so it must be said plainly, where the person will see it, and must be undoable in one action
//! with the cost of undoing it stated.
//!
//! - **Disclosure** (`disclosure`): shown in the first-run flow, not only in documentation. It says
//!   what is overridden, why, and how to turn it off. `ConsentState` remembers which version of the
//!   text the person has been shown, so a changed text is shown again.
//! - **Opt-out** (`ConsentState::opt_out`): one call, no confirmation ladder. It returns the consequence
//!   that must be shown ("destination-based rules will not apply to that application's traffic"), and
//!   that the person has seen the disclosure is implied by the control being on the disclosure itself.
//! - **Restoring** the block needs no consent: it only narrows what programs may do, so it is always
//!   allowed.
//!
//! What is stored is two small values. Anything unreadable falls back to the **protective** default
//! (block, and show the disclosure again): a damaged file must never turn the override off silently.
//!
//! Pure logic: no I/O.

use crate::doh_block::Policy;

/// Bumped whenever the disclosure's meaning changes, so the new text is shown again.
pub const DISCLOSURE_VERSION: u32 = 1;

/// The text shown in the first-run flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    pub version: u32,
    pub headline: &'static str,
    /// What is overridden.
    pub what: &'static str,
    /// Why it is done.
    pub why: &'static str,
    /// How to undo it.
    pub how_to_opt_out: &'static str,
}

/// The first-run disclosure (FR-025a). Plain words; names no technology.
pub fn disclosure() -> Disclosure {
    Disclosure {
        version: DISCLOSURE_VERSION,
        headline: "Some programs hide the sites they look up. DNet turns that off.",
        what: "Web browsers and some other programs can send their name lookups over an encrypted \
               connection of their own. While DNet is connected it makes them use the system's \
               lookup instead, by blocking the well-known encrypted lookup services.",
        why: "Your rules for sites and domains can only work if DNet can see which site a program is \
              asking for. A program that hides its lookups cannot be routed by site, so a rule such \
              as \"keep this site off the tunnel\" would quietly not apply to it.",
        how_to_opt_out: "You can turn this off in one step in Settings. Programs will then keep using \
                         their own encrypted lookups.",
    }
}

/// What must be shown when the person opts out (FR-025a).
pub fn consequence_of_opting_out() -> &'static str {
    "Rules for sites and domains will not apply to traffic from programs that use their own \
     encrypted lookups. Those programs will be routed by address only."
}

/// The result of opting out: the consequence the interface must show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptOut {
    pub consequence: &'static str,
}

/// The person's choice and whether they have been told about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentState {
    policy: Policy,
    disclosed: Option<u32>,
}

impl Default for ConsentState {
    /// The product's default: block, and nothing disclosed yet.
    fn default() -> Self {
        Self {
            policy: Policy::Block,
            disclosed: None,
        }
    }
}

impl ConsentState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The policy now in force.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Whether the first-run flow still has to show the disclosure (never shown, or the text changed).
    pub fn needs_disclosure(&self) -> bool {
        self.disclosed != Some(DISCLOSURE_VERSION)
    }

    /// The person has been shown the current disclosure.
    pub fn acknowledge_disclosure(&mut self) {
        self.disclosed = Some(DISCLOSURE_VERSION);
    }

    /// Turn the override off, in one action. The control is part of the disclosure, so this counts as
    /// the disclosure having been seen. Returns what the interface must now show.
    pub fn opt_out(&mut self) -> OptOut {
        self.policy = Policy::Allow;
        self.disclosed = Some(DISCLOSURE_VERSION);
        OptOut {
            consequence: consequence_of_opting_out(),
        }
    }

    /// Turn the override back on. Needs no consent: it only narrows what programs may do.
    pub fn restore(&mut self) {
        self.policy = Policy::Block;
    }

    /// The two stored values: the policy's name and the disclosure version shown (0 for none).
    pub fn to_stored(&self) -> (&'static str, u32) {
        (
            match self.policy {
                Policy::Block => "block",
                Policy::Allow => "allow",
            },
            self.disclosed.unwrap_or(0),
        )
    }

    /// Read the stored values back. Anything not recognised gives the protective default for that
    /// part: a damaged record must not switch the override off.
    pub fn from_stored(policy: &str, disclosed: u32) -> Self {
        Self {
            policy: if policy == "allow" {
                Policy::Allow
            } else {
                Policy::Block
            },
            disclosed: (disclosed != 0).then_some(disclosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window (`apps/dnet-tray`) shows this text from a file it imports, not from the service, so the
    /// two are pinned to each other here: the person is told exactly what the product does, and a change
    /// to either side that is not made to the other fails this test.
    #[test]
    fn the_window_shows_exactly_the_disclosure_the_service_defines() {
        let shown: serde_json::Value = serde_json::from_str(include_str!(
            "../../../apps/dnet-tray/src/lib/disclosure.json"
        ))
        .expect("the window's disclosure is JSON");
        let d = disclosure();
        assert_eq!(shown["version"], d.version);
        assert_eq!(shown["headline"], d.headline);
        assert_eq!(shown["what"], d.what);
        assert_eq!(shown["why"], d.why);
        assert_eq!(shown["howToOptOut"], d.how_to_opt_out);
        assert_eq!(shown["consequenceOfOptingOut"], consequence_of_opting_out());
        assert_eq!(
            shown.as_object().map(|o| o.len()),
            Some(6),
            "a field added on one side only"
        );
    }

    #[test]
    fn a_new_install_blocks_and_has_not_yet_told_the_person() {
        let state = ConsentState::new();
        assert_eq!(state.policy(), Policy::Block);
        assert!(state.needs_disclosure());
    }

    #[test]
    fn showing_the_disclosure_is_remembered_and_does_not_change_the_policy() {
        let mut state = ConsentState::new();
        state.acknowledge_disclosure();
        assert!(!state.needs_disclosure());
        assert_eq!(state.policy(), Policy::Block);
    }

    #[test]
    fn opting_out_is_one_action_and_returns_the_consequence() {
        let mut state = ConsentState::new();
        let out = state.opt_out();
        assert_eq!(state.policy(), Policy::Allow);
        assert!(out.consequence.contains("will not apply"));
        assert!(out.consequence.contains("sites and domains"));
        assert!(
            !state.needs_disclosure(),
            "the opt-out is on the disclosure"
        );
    }

    #[test]
    fn the_block_can_be_restored_without_any_consent() {
        let mut state = ConsentState::new();
        let _ = state.opt_out();
        state.restore();
        assert_eq!(state.policy(), Policy::Block);
    }

    #[test]
    fn a_changed_disclosure_is_shown_again() {
        let older = ConsentState::from_stored("block", DISCLOSURE_VERSION - 1);
        // Version 0 means "never"; a real older version is one that is not the current.
        let stale = ConsentState::from_stored("block", DISCLOSURE_VERSION + 1);
        assert!(older.needs_disclosure());
        assert!(stale.needs_disclosure());
    }

    #[test]
    fn stored_values_round_trip() {
        for state in [
            ConsentState::new(),
            {
                let mut s = ConsentState::new();
                s.acknowledge_disclosure();
                s
            },
            {
                let mut s = ConsentState::new();
                let _ = s.opt_out();
                s
            },
        ] {
            let (policy, disclosed) = state.to_stored();
            assert_eq!(ConsentState::from_stored(policy, disclosed), state);
        }
    }

    #[test]
    fn a_damaged_record_never_switches_the_override_off() {
        for policy in ["", "ALLOW", "allow ", "true", "off", "\u{0}", "allo"] {
            assert_eq!(
                ConsentState::from_stored(policy, 1).policy(),
                Policy::Block,
                "{policy:?}"
            );
        }
        assert_eq!(
            ConsentState::from_stored("allow", 1).policy(),
            Policy::Allow
        );
    }

    #[test]
    fn the_disclosure_says_what_why_and_how_and_is_versioned() {
        let d = disclosure();
        assert_eq!(d.version, DISCLOSURE_VERSION);
        for part in [d.headline, d.what, d.why, d.how_to_opt_out] {
            assert!(part.len() > 20, "{part:?}");
        }
        assert!(d.why.contains("rule"));
        assert!(d.how_to_opt_out.contains("one step"));
    }
}
