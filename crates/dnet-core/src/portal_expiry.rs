// SPDX-License-Identifier: GPL-3.0-or-later
//! T078 — a portal whose session ends mid-connection is reported as a portal, not as a generic loss
//! (US6-3).
//!
//! A person signs in to a café's portal, connects, and an hour later the portal forgets them. To the
//! tunnel that is indistinguishable from the network dying: every probe fails. If the product then
//! says "no usable network" or "this network is blocking every method", the person goes looking for the
//! wrong problem. The right words are "this network needs you to log in first", with a way to the login
//! page, and the difference between those two is the whole point of the flow.
//!
//! [`PortalWatch`] reads a stream of portal readings (`portal::PortalState`, from the probes of
//! `portal.rs`) and says when the network has **become** a portal, and when it has stopped being one.
//!
//! # How sure it has to be
//!
//! One odd response is not a portal: a flaky link can truncate a reply. So a portal is only declared
//! after two readings in a row show interception. After the person has signed in once on this network
//! (a portal seen, then an open reading), one reading is enough: a network that was open a moment ago
//! and now intercepts again is, overwhelmingly, a portal session that ended, and every second spent
//! reporting a generic failure is a second the person spends confused.
//!
//! A reading that proves nothing (no answer, or an answer that is neither expected nor a portal's)
//! neither confirms nor clears: a dead network is not a portal, and a portal that stops answering is
//! still the portal until an unchanged probe says otherwise.
//!
//! A new network starts over ([`PortalWatch::new_network`]): what was true of the last one says
//! nothing about this one.
//!
//! Pure logic: no clock, no I/O.

use crate::portal::PortalState;

/// What changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognised {
    /// This network has just turned out to be a portal that wants a login: the first time on it.
    PortalAppeared { login: Option<String> },
    /// A portal that had been signed in to has asked again: the session ended.
    SessionExpired { login: Option<String> },
    /// The portal has been satisfied: an unchanged probe came back.
    Cleared,
}

/// Readings in a row that must show interception before a portal is declared, unless the person has
/// already signed in on this network.
const CONFIRM_READINGS: u32 = 2;

/// Remembers whether the network is a portal, and whether a login has been given on it.
#[derive(Debug, Clone, Default)]
pub struct PortalWatch {
    /// Interception seen in a row, not yet declared.
    run: u32,
    /// The network has been declared a portal and no unchanged probe has come back since.
    active: bool,
    /// A portal was declared and then cleared on this network: the person has signed in once.
    signed_in_before: bool,
    login: Option<String>,
}

impl PortalWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the network is a portal now. `Environment::captive_portal` is this.
    pub fn is_portal(&self) -> bool {
        self.active
    }

    /// Where to sign in, as the portal last gave it (already checked by `portal::login_url`).
    pub fn login(&self) -> Option<&str> {
        self.login.as_deref()
    }

    /// The machine has moved to another network: nothing known about the last one applies.
    pub fn new_network(&mut self) {
        *self = Self::default();
    }

    /// Take one reading into account. Returns what it changed, if anything.
    #[must_use]
    pub fn observe(&mut self, reading: &PortalState) -> Option<Recognised> {
        match reading {
            PortalState::Open => {
                self.run = 0;
                if self.active {
                    self.active = false;
                    self.signed_in_before = true;
                    self.login = None;
                    return Some(Recognised::Cleared);
                }
                None
            }
            PortalState::Intercepted { login } => {
                // The portal's own words are the best source of where to sign in; keep the latest.
                if login.is_some() {
                    self.login = login.clone();
                }
                if self.active {
                    return None;
                }
                self.run += 1;
                let needed = if self.signed_in_before {
                    1
                } else {
                    CONFIRM_READINGS
                };
                if self.run < needed {
                    return None;
                }
                self.active = true;
                let login = self.login.clone();
                Some(if self.signed_in_before {
                    Recognised::SessionExpired { login }
                } else {
                    Recognised::PortalAppeared { login }
                })
            }
            // Neither confirms nor clears.
            PortalState::Unreachable | PortalState::Inconclusive => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn portal(login: Option<&str>) -> PortalState {
        PortalState::Intercepted {
            login: login.map(str::to_owned),
        }
    }

    #[test]
    fn an_open_network_is_not_a_portal_and_says_nothing() {
        let mut w = PortalWatch::new();
        for _ in 0..10 {
            assert_eq!(w.observe(&PortalState::Open), None);
        }
        assert!(!w.is_portal());
    }

    #[test]
    fn one_intercepted_reading_is_not_yet_a_portal() {
        let mut w = PortalWatch::new();
        assert_eq!(w.observe(&portal(None)), None);
        assert!(!w.is_portal());
    }

    #[test]
    fn two_in_a_row_make_a_portal_and_it_is_announced_once() {
        let mut w = PortalWatch::new();
        assert_eq!(w.observe(&portal(Some("http://p/login"))), None);
        assert_eq!(
            w.observe(&portal(None)),
            Some(Recognised::PortalAppeared {
                login: Some("http://p/login".into())
            }),
            "the address the portal gave is kept even if the second reading had none"
        );
        assert!(w.is_portal());
        assert_eq!(w.login(), Some("http://p/login"));
        assert_eq!(w.observe(&portal(None)), None, "said once");
    }

    #[test]
    fn an_open_reading_between_two_resets_the_count() {
        let mut w = PortalWatch::new();
        assert_eq!(w.observe(&portal(None)), None);
        assert_eq!(w.observe(&PortalState::Open), None);
        assert_eq!(w.observe(&portal(None)), None, "the first of a new run");
        assert!(!w.is_portal());
    }

    #[test]
    fn readings_that_prove_nothing_neither_confirm_nor_break_the_run() {
        let mut w = PortalWatch::new();
        assert_eq!(w.observe(&portal(None)), None);
        assert_eq!(w.observe(&PortalState::Unreachable), None);
        assert_eq!(w.observe(&PortalState::Inconclusive), None);
        assert!(!w.is_portal(), "silence does not confirm");
        assert!(matches!(
            w.observe(&portal(None)),
            Some(Recognised::PortalAppeared { .. })
        ));
    }

    #[test]
    fn a_dead_network_is_never_a_portal() {
        let mut w = PortalWatch::new();
        for _ in 0..50 {
            assert_eq!(w.observe(&PortalState::Unreachable), None);
        }
        assert!(!w.is_portal());
    }

    #[test]
    fn a_portal_that_goes_quiet_is_still_the_portal() {
        let mut w = PortalWatch::new();
        let _ = w.observe(&portal(None));
        let _ = w.observe(&portal(None));
        assert!(w.is_portal());
        assert_eq!(w.observe(&PortalState::Unreachable), None);
        assert!(w.is_portal(), "only an unchanged probe clears it");
    }

    #[test]
    fn signing_in_clears_the_portal() {
        let mut w = PortalWatch::new();
        let _ = w.observe(&portal(Some("http://p/")));
        let _ = w.observe(&portal(None));
        assert_eq!(w.observe(&PortalState::Open), Some(Recognised::Cleared));
        assert!(!w.is_portal());
        assert_eq!(w.login(), None);
        assert_eq!(w.observe(&PortalState::Open), None, "said once");
    }

    #[test]
    fn a_portal_that_asks_again_after_a_login_is_recognised_at_once_as_an_expired_session() {
        let mut w = PortalWatch::new();
        let _ = w.observe(&portal(None));
        let _ = w.observe(&portal(None));
        let _ = w.observe(&PortalState::Open); // signed in

        // One reading is enough now: it was open a moment ago.
        assert_eq!(
            w.observe(&portal(Some("http://p/relogin"))),
            Some(Recognised::SessionExpired {
                login: Some("http://p/relogin".into())
            })
        );
        assert!(w.is_portal());
    }

    #[test]
    fn a_new_network_forgets_the_last_one() {
        let mut w = PortalWatch::new();
        let _ = w.observe(&portal(None));
        let _ = w.observe(&portal(None));
        let _ = w.observe(&PortalState::Open);
        w.new_network();
        assert!(!w.is_portal());
        // The login on the old network says nothing about this one: two readings are needed again.
        assert_eq!(w.observe(&portal(None)), None);
        assert!(matches!(
            w.observe(&portal(None)),
            Some(Recognised::PortalAppeared { .. })
        ));
    }

    #[test]
    fn a_failed_login_that_keeps_intercepting_is_not_announced_again() {
        let mut w = PortalWatch::new();
        let _ = w.observe(&portal(None));
        let _ = w.observe(&portal(None));
        for _ in 0..20 {
            assert_eq!(w.observe(&portal(None)), None);
        }
    }
}
