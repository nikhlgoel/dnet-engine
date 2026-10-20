//! T064 — telling the user *why* a connection failed (FR-039, SC-020).
//!
//! [`classify`] picks exactly one of the seven [`FailureCause`]s from what the daemon can see;
//! [`explain`] turns a cause into words the user can act on. There is no generic error: a
//! failure that reaches the user without a distinguishable cause is a defect.
//!
//! **Order matters.** Causes are tested from the most fundamental to the most specific, because
//! an earlier one makes later ones look true:
//!
//! 1. no privilege, 2. unusable configuration, 3. a core that keeps failing, 4. no network
//!    path, 5. a captive portal (it makes every endpoint and every profile look blocked),
//! 6. no endpoint reachable, 7. every profile blocked.
//!
//! **Endpoint versus profile.** "No endpoint reachable" and "all profiles blocked" are told apart
//! by a reachability check made *outside* any profile (a plain connection to the endpoint's
//! address). If no endpoint answers that, the endpoints are the problem. If they answer but no
//! profile carries traffic, the network is blocking the profiles. [`Reach::Unknown`] never
//! counts as unreachable.
//!
//! This lives in `dnet-core` rather than `dnetd`, as T064 first suggested, so that it is covered
//! by the coverage floor and the tray can reuse the same wording.

use crate::profile::{ConnectionProfile, CoreBinding, Viability};
use crate::session::FailureCause;

/// Whether an endpoint answered a plain reachability check made outside any profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Reachable,
    Unreachable,
    /// Not checked, or the check was inconclusive.
    Unknown,
}

/// Everything [`classify`] looks at.
#[derive(Debug, Clone, Copy)]
pub struct Situation<'a> {
    /// The service runs with the privilege it needs.
    pub privileged: bool,
    /// Why the configuration cannot be used, if it cannot. **Shown to the user verbatim**, so it
    /// must be one of our own messages (for example a `ConfigError`, which names a credential
    /// but never its value) and never raw output from a supervised core.
    pub configuration_error: Option<&'a str>,
    /// A supervised core whose restarts have stopped, if any.
    pub core_failed: Option<CoreBinding>,
    /// How many network paths can carry traffic.
    pub usable_paths: usize,
    /// A captive portal is intercepting traffic.
    pub captive_portal: bool,
    /// One entry per configured endpoint.
    pub endpoint_reach: &'a [Reach],
    pub profiles: &'a [ConnectionProfile],
}

/// The cause of the failure, or `None` if nothing is wrong.
pub fn classify(situation: &Situation<'_>) -> Option<FailureCause> {
    if !situation.privileged {
        return Some(FailureCause::InsufficientPrivilege);
    }
    if let Some(detail) = situation.configuration_error {
        return Some(FailureCause::ConfigurationInvalid {
            detail: detail.to_string(),
        });
    }
    if situation.endpoint_reach.is_empty() {
        return Some(FailureCause::ConfigurationInvalid {
            detail: "no endpoint is configured; add one before connecting".to_string(),
        });
    }
    if situation.profiles.is_empty() {
        return Some(FailureCause::ConfigurationInvalid {
            detail: "no connection profile is defined".to_string(),
        });
    }
    if let Some(core) = situation.core_failed {
        return Some(FailureCause::CoreFailedPersistently { core });
    }
    if situation.usable_paths == 0 {
        return Some(FailureCause::NoUsablePath);
    }
    if situation.captive_portal {
        return Some(FailureCause::CaptivePortalUnsatisfied);
    }
    // Non-empty, checked above. `Unknown` is deliberately not "unreachable".
    if situation
        .endpoint_reach
        .iter()
        .all(|r| *r == Reach::Unreachable)
    {
        return Some(FailureCause::NoEndpointReachable);
    }
    let profiles = situation.profiles;
    if !profiles.is_empty()
        && profiles
            .iter()
            .all(|p| matches!(p.viability(), Viability::Blocked { .. }))
    {
        return Some(FailureCause::AllProfilesBlocked);
    }
    None
}

/// A failure in words the user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// What happened, in a few words.
    pub title: String,
    /// What it means.
    pub detail: String,
    /// What the user can do about it.
    pub action: String,
}

/// A supervised core in words a user can read. The primary core is never named after its vendor
/// (branding rule, `lint-branding`).
pub fn core_description(core: &CoreBinding) -> &'static str {
    match core {
        CoreBinding::PrimaryCore => "the main connection engine",
        CoreBinding::AmneziaWgCore => "the AmneziaWG engine",
    }
}

/// Explain a cause. Every cause has its own title, detail and action.
pub fn explain(cause: &FailureCause) -> Explanation {
    let (title, detail, action) = match cause {
        FailureCause::NoEndpointReachable => (
            "No exit endpoint is reachable",
            "None of your endpoints answered a direct connection test, so there is nowhere to \
             send your traffic. Nothing is being tunnelled."
                .to_string(),
            "Check that the endpoint server is running and that this network allows \
             connections to it, or add another endpoint.",
        ),
        FailureCause::AllProfilesBlocked => (
            "This network is blocking every connection method",
            "Your endpoint answers, but this network is blocking every connection method, so \
             none of them can carry traffic. Nothing is being tunnelled."
                .to_string(),
            "Try a different network, such as mobile data, or check for a profile update \
             that adds a method this network does not recognise.",
        ),
        FailureCause::CaptivePortalUnsatisfied => (
            "Sign-in is required on this network",
            "The network is holding all traffic until you sign in, which also stops the tunnel \
             from connecting."
                .to_string(),
            "Open a browser, complete the network's sign-in page, then connect again.",
        ),
        FailureCause::InsufficientPrivilege => (
            "DNet Engine needs administrator rights",
            "The background service is not running with the privileges it needs to change \
             network settings, so it will not start a connection."
                .to_string(),
            "Restart the DNet Engine service as an administrator, or reinstall it, and try again.",
        ),
        FailureCause::CoreFailedPersistently { core } => {
            let name = core_description(core);
            (
                "A connection component keeps failing",
                format!(
                    "{name} stopped repeatedly, and DNet Engine has stopped restarting it to \
                     avoid a restart loop."
                ),
                "Open the diagnostics to read the component's last messages, then restart the \
                 service. If it keeps failing, report the problem.",
            )
        }
        FailureCause::NoUsablePath => (
            "No network connection is available",
            "None of this computer's network connections can carry traffic right now.".to_string(),
            "Connect to Wi-Fi or mobile data, then try again.",
        ),
        FailureCause::ConfigurationInvalid { detail } => (
            "The configuration cannot be used",
            detail.clone(),
            "Correct the setting named above in the endpoint or profile settings, then try again.",
        ),
    };
    Explanation {
        title: title.to_string(),
        detail,
        action: action.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ProfileId;
    use crate::profile::{ProfileKind, ProfileParams};
    use std::time::Instant;

    fn profile(name: &str, blocked: bool) -> ConnectionProfile {
        let mut p = ConnectionProfile::new(
            ProfileId::new(name),
            ProfileKind::VlessReality,
            ProfileParams::new(),
        );
        if blocked {
            p.mark_blocked(Instant::now(), "reset");
        }
        p
    }

    fn healthy_situation<'a>(
        reach: &'a [Reach],
        profiles: &'a [ConnectionProfile],
    ) -> Situation<'a> {
        Situation {
            privileged: true,
            configuration_error: None,
            core_failed: None,
            usable_paths: 1,
            captive_portal: false,
            endpoint_reach: reach,
            profiles,
        }
    }

    const REACH: &[Reach] = &[Reach::Reachable];

    #[test]
    fn nothing_wrong_is_no_failure() {
        let profiles = [profile("a", false)];
        assert_eq!(classify(&healthy_situation(REACH, &profiles)), None);
    }

    #[test]
    fn each_cause_is_chosen_for_its_own_situation() {
        let blocked = [profile("a", true), profile("b", true)];
        let fine = [profile("a", false)];

        let mut s = healthy_situation(REACH, &fine);
        s.privileged = false;
        assert_eq!(classify(&s), Some(FailureCause::InsufficientPrivilege));

        let mut s = healthy_situation(REACH, &fine);
        s.configuration_error = Some("the REALITY key is not valid");
        assert_eq!(
            classify(&s),
            Some(FailureCause::ConfigurationInvalid {
                detail: "the REALITY key is not valid".into()
            })
        );

        let mut s = healthy_situation(REACH, &fine);
        s.core_failed = Some(CoreBinding::AmneziaWgCore);
        assert_eq!(
            classify(&s),
            Some(FailureCause::CoreFailedPersistently {
                core: CoreBinding::AmneziaWgCore
            })
        );

        let mut s = healthy_situation(REACH, &fine);
        s.usable_paths = 0;
        assert_eq!(classify(&s), Some(FailureCause::NoUsablePath));

        let mut s = healthy_situation(REACH, &fine);
        s.captive_portal = true;
        assert_eq!(classify(&s), Some(FailureCause::CaptivePortalUnsatisfied));

        let down = [Reach::Unreachable, Reach::Unreachable];
        assert_eq!(
            classify(&healthy_situation(&down, &fine)),
            Some(FailureCause::NoEndpointReachable)
        );

        assert_eq!(
            classify(&healthy_situation(REACH, &blocked)),
            Some(FailureCause::AllProfilesBlocked)
        );
    }

    /// An earlier cause hides the later ones that it makes look true.
    #[test]
    fn the_most_fundamental_cause_wins() {
        let blocked = [profile("a", true)];
        let down = [Reach::Unreachable];
        let mut s = healthy_situation(&down, &blocked);
        s.captive_portal = true;
        assert_eq!(
            classify(&s),
            Some(FailureCause::CaptivePortalUnsatisfied),
            "a portal makes endpoints and profiles look blocked"
        );
        s.usable_paths = 0;
        assert_eq!(classify(&s), Some(FailureCause::NoUsablePath));
        s.core_failed = Some(CoreBinding::PrimaryCore);
        assert!(matches!(
            classify(&s),
            Some(FailureCause::CoreFailedPersistently { .. })
        ));
        s.configuration_error = Some("bad");
        assert!(matches!(
            classify(&s),
            Some(FailureCause::ConfigurationInvalid { .. })
        ));
        s.privileged = false;
        assert_eq!(classify(&s), Some(FailureCause::InsufficientPrivilege));
    }

    #[test]
    fn no_configured_endpoint_is_a_configuration_problem_not_an_unreachable_one() {
        let profiles = [profile("a", false)];
        let cause = classify(&healthy_situation(&[], &profiles));
        assert!(
            matches!(cause, Some(FailureCause::ConfigurationInvalid { ref detail }) if detail.contains("endpoint")),
            "{cause:?}"
        );
    }

    /// The test that tells the two network causes apart.
    #[test]
    fn endpoints_that_answer_while_every_profile_is_blocked_mean_the_network_blocks_the_profiles() {
        let blocked = [profile("a", true)];
        assert_eq!(
            classify(&healthy_situation(
                &[Reach::Reachable, Reach::Unreachable],
                &blocked
            )),
            Some(FailureCause::AllProfilesBlocked)
        );
    }

    #[test]
    fn an_unchecked_endpoint_is_not_called_unreachable() {
        let fine = [profile("a", false)];
        assert_eq!(
            classify(&healthy_situation(
                &[Reach::Unknown, Reach::Unreachable],
                &fine
            )),
            None
        );
    }

    #[test]
    fn an_untested_profile_is_not_a_blocked_one() {
        let untested = [profile("a", false), profile("b", true)];
        assert_eq!(untested[0].viability(), &Viability::Untested);
        assert_eq!(classify(&healthy_situation(REACH, &untested)), None);
    }

    /// With no profile defined there is nothing to connect with, which is a configuration
    /// problem. It must not read as "nothing is wrong", and it is not "all profiles blocked".
    #[test]
    fn no_profiles_at_all_is_a_configuration_problem() {
        let cause = classify(&healthy_situation(REACH, &[]));
        assert!(
            matches!(cause, Some(FailureCause::ConfigurationInvalid { ref detail }) if detail.contains("profile")),
            "{cause:?}"
        );
    }

    // -------------------------------------------------------------- explain

    fn every_cause() -> Vec<FailureCause> {
        vec![
            FailureCause::NoEndpointReachable,
            FailureCause::AllProfilesBlocked,
            FailureCause::CaptivePortalUnsatisfied,
            FailureCause::InsufficientPrivilege,
            FailureCause::CoreFailedPersistently {
                core: CoreBinding::PrimaryCore,
            },
            FailureCause::NoUsablePath,
            FailureCause::ConfigurationInvalid {
                detail: "the endpoint address is empty".into(),
            },
        ]
    }

    /// SC-020: every failure has its own message, and none is generic.
    #[test]
    fn every_cause_has_its_own_actionable_explanation() {
        let all = every_cause();
        let explained: Vec<Explanation> = all.iter().map(explain).collect();
        for (i, e) in explained.iter().enumerate() {
            assert!(!e.title.trim().is_empty(), "{:?}", all[i]);
            assert!(!e.detail.trim().is_empty(), "{:?}", all[i]);
            assert!(!e.action.trim().is_empty(), "{:?}", all[i]);
            let text = format!("{} {} {}", e.title, e.detail, e.action).to_lowercase();
            for generic in ["unknown error", "something went wrong", "unexpected error"] {
                assert!(!text.contains(generic), "{:?}: {text}", all[i]);
            }
            for (j, other) in explained.iter().enumerate() {
                if i != j {
                    assert_ne!(e.title, other.title, "titles must differ");
                    assert_ne!(e.action, other.action, "actions must differ");
                }
            }
        }
    }

    #[test]
    fn the_configuration_detail_reaches_the_user() {
        let e = explain(&FailureCause::ConfigurationInvalid {
            detail: "the endpoint address is empty".into(),
        });
        assert!(e.detail.contains("the endpoint address is empty"));
    }

    #[test]
    fn a_failed_core_is_named_without_the_vendor_name() {
        let primary = explain(&FailureCause::CoreFailedPersistently {
            core: CoreBinding::PrimaryCore,
        });
        let amnezia = explain(&FailureCause::CoreFailedPersistently {
            core: CoreBinding::AmneziaWgCore,
        });
        assert_ne!(primary.detail, amnezia.detail);
        let text = format!("{primary:?}{amnezia:?}").to_lowercase();
        // Assembled at runtime so this file does not itself trip `xtask lint-branding`, which
        // rejects these names in any linted source.
        let banned = [
            ["sing", "box"].join("-"),
            ["sing", "box"].join(""),
            ["wire", "guard"].join(""),
            ["win", "tun"].join(""),
        ];
        for name in &banned {
            assert!(!text.contains(name.as_str()), "branding obligation: {name}");
        }
    }

    #[test]
    fn the_portal_and_the_network_causes_tell_the_user_different_things() {
        let portal = explain(&FailureCause::CaptivePortalUnsatisfied);
        let blocked = explain(&FailureCause::AllProfilesBlocked);
        let endpoint = explain(&FailureCause::NoEndpointReachable);
        assert!(portal.action.to_lowercase().contains("browser"));
        assert!(blocked.detail.to_lowercase().contains("block"));
        assert!(endpoint.detail.to_lowercase().contains("endpoint"));
    }
}
