//! Fail-closed routing posture — the kill switch (data-model §3, Cross-cutting §5).
//!
//! The system is **never** permitted to send would-be-tunnelled traffic to the raw
//! physical interface. When no usable tunnel remains, the only posture is `FailClosed`:
//! tunnelled traffic — including DNS — is dropped, and only the built-in bypass rules
//! (local ranges, captive-portal probes) stay direct.
//!
//! This is a *structural* guarantee: `RoutingPosture` has no variant that falls back to
//! the physical interface, so no amount of state-machine transition can express one.
//! The default, computed whenever there is no carrying path or no viable profile, is
//! `FailClosed`.

use crate::path::{NetworkPath, PathRole};
use crate::profile::{ConnectionProfile, Viability};
use crate::tier::FailoverTier;

/// How the system routes traffic right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPosture {
    /// A tunnel is carrying traffic at this failover tier.
    Tunnelled {
        /// The tier in effect, which decides whether established connections survive an
        /// interface change (data-model §2.1).
        tier: FailoverTier,
    },
    /// No usable tunnel. Tunnelled traffic — and DNS — is dropped; only the built-in
    /// bypass rules apply. This is the kill switch.
    FailClosed,
}

impl RoutingPosture {
    /// Whether the kill switch is engaged (traffic that would be tunnelled is dropped).
    pub fn is_fail_closed(&self) -> bool {
        matches!(self, RoutingPosture::FailClosed)
    }
}

/// Compute the routing posture from the current profiles and paths.
///
/// A profile contributes its tier only if it is `Working` on this network. A path can
/// carry only if one is in the `Carrying` role. If either is missing — no carrying path,
/// or every profile blocked/untested — the posture is `FailClosed`, never a direct
/// fallback to the physical interface (the kill-switch invariant).
///
/// Among viable profiles the *preferred* tier wins (`Tier1` over `Tier2`, FR-016b),
/// which is the minimum under `FailoverTier`'s ordering.
pub fn select_posture(profiles: &[ConnectionProfile], paths: &[NetworkPath]) -> RoutingPosture {
    let has_carrying_path = paths.iter().any(|p| p.role == PathRole::Carrying);
    if !has_carrying_path {
        return RoutingPosture::FailClosed;
    }

    match best_viable_tier(profiles) {
        Some(tier) => RoutingPosture::Tunnelled { tier },
        None => RoutingPosture::FailClosed,
    }
}

/// The preferred tier among profiles that are `Working` on this network, or `None` if
/// none is viable.
fn best_viable_tier(profiles: &[ConnectionProfile]) -> Option<FailoverTier> {
    profiles
        .iter()
        .filter(|p| matches!(p.viability(), Viability::Working { .. }))
        .map(ConnectionProfile::tier)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{InterfaceId, ProfileId};
    use crate::path::{NetworkPath, PathKind, PathQuality, PathRole};
    use crate::profile::{ConnectionProfile, ProfileKind, ProfileParams};
    use crate::tier::SurvivalMeasurement;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn profile(kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
    }

    fn working(kind: ProfileKind) -> ConnectionProfile {
        let mut p = profile(kind);
        p.mark_working(Instant::now());
        p
    }

    fn path(role: PathRole) -> NetworkPath {
        NetworkPath {
            interface_id: InterfaceId::new(1),
            kind: PathKind::Wifi,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            quality: PathQuality::unmeasured(),
            role,
            preference: 0,
        }
    }

    #[test]
    fn no_carrying_path_is_fail_closed() {
        let profiles = [working(ProfileKind::AmneziaWg)];
        let paths = [path(PathRole::Standby)];
        assert_eq!(
            select_posture(&profiles, &paths),
            RoutingPosture::FailClosed
        );
    }

    #[test]
    fn a_carrying_path_but_no_viable_profile_is_fail_closed() {
        // The kill switch: a path is up, but every profile is blocked. We must drop
        // traffic, not fall back to the raw interface.
        let mut blocked = profile(ProfileKind::AmneziaWg);
        blocked.mark_blocked(Instant::now(), "reset by peer");
        let profiles = [blocked];
        let paths = [path(PathRole::Carrying)];
        assert_eq!(
            select_posture(&profiles, &paths),
            RoutingPosture::FailClosed
        );
    }

    #[test]
    fn untested_profiles_do_not_open_the_tunnel() {
        let profiles = [profile(ProfileKind::AmneziaWg)]; // Untested
        let paths = [path(PathRole::Carrying)];
        assert_eq!(
            select_posture(&profiles, &paths),
            RoutingPosture::FailClosed
        );
    }

    #[test]
    fn an_empty_configuration_is_fail_closed_by_default() {
        assert_eq!(select_posture(&[], &[]), RoutingPosture::FailClosed);
        assert!(select_posture(&[], &[]).is_fail_closed());
    }

    #[test]
    fn a_working_profile_over_a_carrying_path_tunnels_at_its_tier() {
        let profiles = [working(ProfileKind::VlessReality)];
        let paths = [path(PathRole::Carrying)];
        assert_eq!(
            select_posture(&profiles, &paths),
            RoutingPosture::Tunnelled {
                tier: FailoverTier::Tier2
            }
        );
    }

    #[test]
    fn the_preferred_tier_wins_when_several_profiles_are_viable() {
        // A Tier 2 and a measured Tier 1 profile both working: Tier 1 is preferred (FR-016b).
        let mut measured_tier1 = ConnectionProfile::measured(
            ProfileId::new("awg"),
            ProfileKind::AmneziaWg,
            ProfileParams::new(),
            SurvivalMeasurement::Survived,
        );
        measured_tier1.mark_working(Instant::now());
        let profiles = [working(ProfileKind::VlessReality), measured_tier1];
        let paths = [path(PathRole::Carrying)];
        assert_eq!(
            select_posture(&profiles, &paths),
            RoutingPosture::Tunnelled {
                tier: FailoverTier::Tier1
            }
        );
    }
}
