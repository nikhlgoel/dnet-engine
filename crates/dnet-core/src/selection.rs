//! T061 — choosing a profile, Tier 1 preference and Tier 2 consent (FR-016b).
//!
//! - With no request, the best viable profile wins: Tier 1 before Tier 2, ties by the order the
//!   profiles are given (the catalogue order).
//! - A requested profile must be viable. If it is Tier 2 while a Tier 1 profile is viable, the
//!   user must have acknowledged that established connections will not survive an interface
//!   change; otherwise the request is refused rather than quietly downgraded.
//! - Every Tier 2 selection carries `warn_tier2`, so the interface warns *before* connecting
//!   even when no Tier 1 profile existed to prefer. Tier is measured, and today none is Tier 1,
//!   so the warning is always shown (owner decision 2026-09-12, tasks.md T027).

use crate::ids::ProfileId;
use crate::profile::{ConnectionProfile, Viability};
use crate::tier::FailoverTier;

/// A profile chosen to carry traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub profile: ProfileId,
    pub tier: FailoverTier,
    /// Tell the user, before connecting, that established connections may break when the
    /// network interface changes.
    pub warn_tier2: bool,
}

/// Why no profile could be selected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("no connection profile is working on this network")]
    NoViableProfile,
    #[error("there is no connection profile named {0}")]
    UnknownProfile(ProfileId),
    #[error("profile {0} is not working on this network")]
    NotViable(ProfileId),
    /// A Tier 1 profile is working, so choosing this Tier 2 one needs the user's say-so.
    #[error(
        "profile {requested} would not keep established connections across a network change, \
         and a profile that would is available; confirm to use it anyway"
    )]
    TierDowngradeRequiresConsent { requested: ProfileId },
}

/// Choose a profile. `requested` is the user's explicit pick, if any.
pub fn select(
    profiles: &[ConnectionProfile],
    requested: Option<&ProfileId>,
    acknowledged_tier2: bool,
) -> Result<Selected, SelectionError> {
    let is_working = |p: &ConnectionProfile| matches!(p.viability(), Viability::Working { .. });
    let selected = |p: &ConnectionProfile| Selected {
        profile: p.id().clone(),
        tier: p.tier(),
        warn_tier2: p.tier() == FailoverTier::Tier2,
    };

    let Some(wanted) = requested else {
        // `min_by_key` keeps the first of equal keys, so ties keep the given order.
        return profiles
            .iter()
            .filter(|p| is_working(p))
            .min_by_key(|p| p.tier())
            .map(selected)
            .ok_or(SelectionError::NoViableProfile);
    };

    let profile = profiles
        .iter()
        .find(|p| p.id() == wanted)
        .ok_or_else(|| SelectionError::UnknownProfile(wanted.clone()))?;
    if !is_working(profile) {
        return Err(SelectionError::NotViable(wanted.clone()));
    }
    let tier1_available = profiles
        .iter()
        .any(|p| is_working(p) && p.tier() == FailoverTier::Tier1);
    if profile.tier() == FailoverTier::Tier2 && tier1_available && !acknowledged_tier2 {
        return Err(SelectionError::TierDowngradeRequiresConsent {
            requested: wanted.clone(),
        });
    }
    Ok(selected(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ProfileKind, ProfileParams};
    use crate::tier::SurvivalMeasurement;
    use std::time::Instant;

    fn id(s: &str) -> ProfileId {
        ProfileId::new(s)
    }

    fn working(mut p: ConnectionProfile) -> ConnectionProfile {
        p.mark_working(Instant::now());
        p
    }

    fn t2(name: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(id(name), kind, ProfileParams::new())
    }

    fn t1(name: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::measured(
            id(name),
            kind,
            ProfileParams::new(),
            SurvivalMeasurement::Survived,
        )
    }

    #[test]
    fn nothing_working_means_no_viable_profile() {
        let profiles = [t2("a", ProfileKind::AmneziaWg)];
        assert_eq!(
            select(&profiles, None, false),
            Err(SelectionError::NoViableProfile)
        );
        assert_eq!(
            select(&[], None, false),
            Err(SelectionError::NoViableProfile)
        );
    }

    #[test]
    fn a_blocked_or_untested_profile_is_never_chosen_automatically() {
        let mut blocked = t2("a", ProfileKind::AmneziaWg);
        blocked.mark_blocked(Instant::now(), "reset");
        let profiles = [blocked, t2("b", ProfileKind::VlessReality)];
        assert_eq!(
            select(&profiles, None, false),
            Err(SelectionError::NoViableProfile)
        );
    }

    #[test]
    fn tier1_is_preferred_over_an_earlier_tier2() {
        let profiles = [
            working(t2("reality", ProfileKind::VlessReality)),
            working(t1("hy2", ProfileKind::Hysteria2)),
        ];
        let chosen = select(&profiles, None, false).unwrap();
        assert_eq!(chosen.profile, id("hy2"));
        assert_eq!(chosen.tier, FailoverTier::Tier1);
        assert!(!chosen.warn_tier2);
    }

    #[test]
    fn equal_tiers_keep_the_given_order() {
        let profiles = [
            working(t2("awg", ProfileKind::AmneziaWg)),
            working(t2("reality", ProfileKind::VlessReality)),
        ];
        assert_eq!(select(&profiles, None, false).unwrap().profile, id("awg"));
    }

    /// FR-016b: the warning applies to every Tier 2 selection, even with no Tier 1 to prefer.
    #[test]
    fn a_tier2_selection_always_warns() {
        let profiles = [working(t2("reality", ProfileKind::VlessReality))];
        let chosen = select(&profiles, None, false).unwrap();
        assert_eq!(chosen.tier, FailoverTier::Tier2);
        assert!(chosen.warn_tier2);
    }

    #[test]
    fn a_requested_profile_is_used_when_it_is_working() {
        let profiles = [
            working(t2("awg", ProfileKind::AmneziaWg)),
            working(t2("reality", ProfileKind::VlessReality)),
        ];
        let chosen = select(&profiles, Some(&id("reality")), false).unwrap();
        assert_eq!(chosen.profile, id("reality"));
    }

    #[test]
    fn a_request_for_an_unknown_or_not_working_profile_is_refused() {
        let profiles = [
            working(t2("awg", ProfileKind::AmneziaWg)),
            t2("reality", ProfileKind::VlessReality),
        ];
        assert_eq!(
            select(&profiles, Some(&id("nope")), false),
            Err(SelectionError::UnknownProfile(id("nope")))
        );
        assert_eq!(
            select(&profiles, Some(&id("reality")), false),
            Err(SelectionError::NotViable(id("reality")))
        );
    }

    /// Choosing a Tier 2 profile while a Tier 1 one works needs consent, and consent suffices.
    #[test]
    fn a_tier2_request_while_tier1_is_available_needs_consent() {
        let profiles = [
            working(t1("hy2", ProfileKind::Hysteria2)),
            working(t2("reality", ProfileKind::VlessReality)),
        ];
        assert_eq!(
            select(&profiles, Some(&id("reality")), false),
            Err(SelectionError::TierDowngradeRequiresConsent {
                requested: id("reality")
            })
        );
        let chosen = select(&profiles, Some(&id("reality")), true).unwrap();
        assert_eq!(chosen.profile, id("reality"));
        assert!(chosen.warn_tier2);
    }

    /// With no Tier 1 profile working there is nothing to downgrade from: no consent needed.
    #[test]
    fn a_tier2_request_with_no_tier1_working_needs_no_consent() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            working(t2("reality", ProfileKind::VlessReality)),
        ];
        assert!(select(&profiles, Some(&id("reality")), false).is_ok());
    }

    #[test]
    fn errors_read_as_sentences_for_the_user() {
        let e = SelectionError::TierDowngradeRequiresConsent {
            requested: id("reality"),
        };
        assert!(e.to_string().contains("confirm"));
        assert!(!SelectionError::NoViableProfile.to_string().is_empty());
    }
}
