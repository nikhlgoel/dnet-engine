//! T027 — `FailoverTier`: whether established connections survive a change of network
//! interface (data-model §2.1, research.md R9, FR-016a).
//!
//! **Tier is set from measurement and never inferred from the profile kind.** Tier 1 is a
//! property of the pinned core versions, proven only by HV-07 (SPIKE-R9, T085): an open
//! transfer surviving an interface change. Until that measurement is recorded for a kind,
//! its profiles are Tier 2, so the UI never claims more than was measured (data-model
//! §Cross-cutting 4, Principle VI). Owner decision 2026-09-12: no design-intent Tier 1.

use crate::profile::ProfileKind;

/// Failover behaviour of a connection profile.
///
/// `Ord` follows preference: `Tier1 < Tier2`, so the *minimum* tier is the *preferred*
/// one. This is relied on by `posture::select_posture` when several profiles are viable
/// (FR-016b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailoverTier {
    /// Established connections survive an interface change. Preferred when several
    /// profiles are viable (FR-016b).
    Tier1,
    /// Access only: established connections break and re-establish. The user is
    /// warned before selection (FR-016b).
    Tier2,
}

/// The HV-07 result for one profile kind at the pinned core versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurvivalMeasurement {
    /// Not measured at the pinned versions. Claims nothing.
    NotMeasured,
    /// An open transfer survived an interface change.
    Survived,
    /// An open transfer broke on an interface change.
    Broke,
}

impl FailoverTier {
    /// Tier 1 only for a recorded survival; anything else is Tier 2.
    pub fn from_measurement(measurement: SurvivalMeasurement) -> Self {
        match measurement {
            SurvivalMeasurement::Survived => FailoverTier::Tier1,
            SurvivalMeasurement::NotMeasured | SurvivalMeasurement::Broke => FailoverTier::Tier2,
        }
    }
}

/// The recorded HV-07 result for each kind at the pinned core versions.
///
/// **T085 records results here, with the core versions and the evidence in `tasks.md`.**
/// Bumping a core pin invalidates the result for the kinds that core serves: set them back
/// to `NotMeasured` until HV-07 is re-run. Every kind is listed explicitly, so adding a kind
/// forces a decision.
pub fn recorded_survival(kind: ProfileKind) -> SurvivalMeasurement {
    match kind {
        // HV-07 has not run (SPIKE-R9 is Phase 6, T085).
        ProfileKind::AmneziaWg => SurvivalMeasurement::NotMeasured,
        ProfileKind::Hysteria2 => SurvivalMeasurement::NotMeasured,
        ProfileKind::VlessReality => SurvivalMeasurement::NotMeasured,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_recorded_survival_earns_tier1() {
        assert_eq!(
            FailoverTier::from_measurement(SurvivalMeasurement::Survived),
            FailoverTier::Tier1
        );
        assert_eq!(
            FailoverTier::from_measurement(SurvivalMeasurement::Broke),
            FailoverTier::Tier2
        );
        assert_eq!(
            FailoverTier::from_measurement(SurvivalMeasurement::NotMeasured),
            FailoverTier::Tier2
        );
    }

    /// Update this when T085 records HV-07 results: it pins the claim to the evidence.
    #[test]
    fn until_spike_r9_is_recorded_no_kind_claims_tier1() {
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            assert_eq!(
                recorded_survival(kind),
                SurvivalMeasurement::NotMeasured,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn tier1_is_preferred_by_ordering() {
        assert!(FailoverTier::Tier1 < FailoverTier::Tier2);
    }
}
