//! T026 — connection profiles (data-model §2).
//!
//! A profile is a named way of reaching an endpoint, with the parameters that shape
//! how it appears to an observer. Several invariants are made structural here rather
//! than merely validated:
//!
//! - **`carrier` and `provided_by` are derived from `kind`**, not stored, so a profile
//!   can never disagree with itself (e.g. an AmneziaWG profile bound to the primary
//!   core, or a REALITY profile claiming UDP).
//! - **Brutal congestion control can only be enabled on a Hysteria 2 profile, and only
//!   with an explicit acknowledgement** (FR-006).
//! - **`tier` follows measurement**: it starts at the kind's expected tier and is
//!   demoted only by observation (SPIKE-R9), never inferred elsewhere.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::error::DomainError;
use crate::ids::ProfileId;
use crate::tier::FailoverTier;

/// Which supervised process serves a profile (research.md R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreBinding {
    /// The primary transport core: Hysteria 2 and VLESS+REALITY.
    PrimaryCore,
    /// The separate AmneziaWG process.
    AmneziaWgCore,
}

/// The transport a profile uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Carrier {
    /// Connectionless. Blocked or throttled on some managed networks.
    Udp,
    /// Connection-oriented, TLS-shaped. The mandatory fallback (FR-002).
    Tcp,
}

/// The kind of transport a profile speaks. This alone determines the carrier, the
/// serving core, and the expected failover tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileKind {
    /// Obfuscated WireGuard, served by the AmneziaWG process. UDP, Tier 1.
    AmneziaWg,
    /// QUIC with Salamander/Gecko, served by the primary core. UDP, Tier 1.
    Hysteria2,
    /// TLS-camouflaged, served by the primary core. TCP, Tier 2.
    VlessReality,
}

impl ProfileKind {
    /// The carrier this kind uses.
    pub fn carrier(&self) -> Carrier {
        match self {
            ProfileKind::VlessReality => Carrier::Tcp,
            ProfileKind::AmneziaWg | ProfileKind::Hysteria2 => Carrier::Udp,
        }
    }

    /// Which supervised process serves this kind.
    pub fn core_binding(&self) -> CoreBinding {
        match self {
            ProfileKind::AmneziaWg => CoreBinding::AmneziaWgCore,
            ProfileKind::Hysteria2 | ProfileKind::VlessReality => CoreBinding::PrimaryCore,
        }
    }

    /// The failover tier this kind is *expected* to achieve, before measurement.
    /// The live tier may be demoted by SPIKE-R9 (`ConnectionProfile::demote_to_tier2`).
    pub fn expected_tier(&self) -> FailoverTier {
        match self {
            ProfileKind::AmneziaWg | ProfileKind::Hysteria2 => FailoverTier::Tier1,
            ProfileKind::VlessReality => FailoverTier::Tier2,
        }
    }
}

/// An up/down bandwidth pair, in megabits per second, for Brutal congestion control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthPair {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

/// Whether a profile is known to work on the current network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Viability {
    /// Not yet probed on this network.
    Untested,
    /// Carried usable traffic when last probed.
    Working { measured_at: Instant },
    /// Was blocked when last probed.
    Blocked {
        measured_at: Instant,
        reason: String,
    },
}

/// Kind-specific transport parameters, opaque to `dnet-core`.
///
/// `dnet-core` never interprets these; `dnet-config` turns them into the supervised
/// core's configuration. Modelled as string key/values so the domain layer needs no
/// knowledge of any particular transport's schema.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileParams(BTreeMap<String, String>);

impl ProfileParams {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A named way of reaching an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProfile {
    id: ProfileId,
    kind: ProfileKind,
    tier: FailoverTier,
    params: ProfileParams,
    viability: Viability,
    brutal: Option<BandwidthPair>,
}

impl ConnectionProfile {
    /// Create a profile. Its tier starts at the kind's expected tier, its viability is
    /// `Untested`, and Brutal is off (so BBR is used — data-model §2, R2).
    pub fn new(id: ProfileId, kind: ProfileKind, params: ProfileParams) -> Self {
        Self {
            id,
            tier: kind.expected_tier(),
            kind,
            params,
            viability: Viability::Untested,
            brutal: None,
        }
    }

    pub fn id(&self) -> &ProfileId {
        &self.id
    }

    pub fn kind(&self) -> ProfileKind {
        self.kind
    }

    /// The carrier, derived from the kind.
    pub fn carrier(&self) -> Carrier {
        self.kind.carrier()
    }

    /// The serving core, derived from the kind.
    pub fn core_binding(&self) -> CoreBinding {
        self.kind.core_binding()
    }

    pub fn tier(&self) -> FailoverTier {
        self.tier
    }

    /// Demote to Tier 2 after a failed Tier 1 survival measurement (SPIKE-R9, R9).
    /// There is deliberately no `promote` — tier only ever follows a *failed*
    /// measurement downward; a profile earns Tier 1 by being constructed as a Tier 1
    /// kind, not by a runtime claim.
    pub fn demote_to_tier2(&mut self) {
        self.tier = FailoverTier::Tier2;
    }

    pub fn params(&self) -> &ProfileParams {
        &self.params
    }

    pub fn viability(&self) -> &Viability {
        &self.viability
    }

    pub fn mark_working(&mut self, measured_at: Instant) {
        self.viability = Viability::Working { measured_at };
    }

    pub fn mark_blocked(&mut self, measured_at: Instant, reason: impl Into<String>) {
        self.viability = Viability::Blocked {
            measured_at,
            reason: reason.into(),
        };
    }

    /// The Brutal bandwidth pair, if enabled. `None` means BBR (the default), which
    /// `dnet-config` realises by omitting the bandwidth section entirely (R2).
    pub fn brutal(&self) -> Option<&BandwidthPair> {
        self.brutal.as_ref()
    }

    /// Enable Brutal congestion control.
    ///
    /// Refused unless this is a Hysteria 2 profile and the caller passes an explicit
    /// acknowledgement of the shared-access-point impact (FR-006).
    pub fn enable_brutal(
        &mut self,
        bandwidth: BandwidthPair,
        acknowledged: bool,
    ) -> Result<(), DomainError> {
        if self.kind != ProfileKind::Hysteria2 {
            return Err(DomainError::BrutalRequiresHysteria2);
        }
        if !acknowledged {
            return Err(DomainError::BrutalNotAcknowledged);
        }
        self.brutal = Some(bandwidth);
        Ok(())
    }

    /// Turn Brutal off, returning to BBR.
    pub fn disable_brutal(&mut self) {
        self.brutal = None;
    }
}

/// Validate a profile set: it must contain at least one TCP-carrier profile, or it is
/// dead on a network that blocks UDP (FR-002).
pub fn validate_profile_set(profiles: &[ConnectionProfile]) -> Result<(), DomainError> {
    if profiles.iter().any(|p| p.carrier() == Carrier::Tcp) {
        Ok(())
    } else {
        Err(DomainError::NoTcpFallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
    }

    #[test]
    fn carrier_and_core_are_derived_from_kind() {
        let awg = profile(ProfileKind::AmneziaWg);
        assert_eq!(awg.carrier(), Carrier::Udp);
        assert_eq!(awg.core_binding(), CoreBinding::AmneziaWgCore);

        let hy2 = profile(ProfileKind::Hysteria2);
        assert_eq!(hy2.carrier(), Carrier::Udp);
        assert_eq!(hy2.core_binding(), CoreBinding::PrimaryCore);

        let reality = profile(ProfileKind::VlessReality);
        assert_eq!(reality.carrier(), Carrier::Tcp);
        assert_eq!(reality.core_binding(), CoreBinding::PrimaryCore);
    }

    #[test]
    fn tier_starts_at_the_kinds_expected_tier() {
        assert_eq!(profile(ProfileKind::AmneziaWg).tier(), FailoverTier::Tier1);
        assert_eq!(profile(ProfileKind::Hysteria2).tier(), FailoverTier::Tier1);
        assert_eq!(
            profile(ProfileKind::VlessReality).tier(),
            FailoverTier::Tier2
        );
    }

    #[test]
    fn a_tier1_profile_can_be_demoted_by_measurement() {
        let mut p = profile(ProfileKind::AmneziaWg);
        p.demote_to_tier2();
        assert_eq!(p.tier(), FailoverTier::Tier2);
    }

    #[test]
    fn new_profile_defaults_to_bbr_not_brutal() {
        assert!(profile(ProfileKind::Hysteria2).brutal().is_none());
    }

    #[test]
    fn brutal_requires_a_hysteria2_profile() {
        let bw = BandwidthPair {
            up_mbps: 50,
            down_mbps: 200,
        };
        for kind in [ProfileKind::AmneziaWg, ProfileKind::VlessReality] {
            let mut p = profile(kind);
            assert_eq!(
                p.enable_brutal(bw, true),
                Err(DomainError::BrutalRequiresHysteria2)
            );
            assert!(p.brutal().is_none());
        }
    }

    #[test]
    fn brutal_requires_acknowledgement() {
        let mut p = profile(ProfileKind::Hysteria2);
        let bw = BandwidthPair {
            up_mbps: 50,
            down_mbps: 200,
        };
        assert_eq!(
            p.enable_brutal(bw, false),
            Err(DomainError::BrutalNotAcknowledged)
        );
        assert!(p.brutal().is_none());
        assert_eq!(p.enable_brutal(bw, true), Ok(()));
        assert_eq!(p.brutal(), Some(&bw));
    }

    #[test]
    fn viability_transitions_are_recorded() {
        let mut p = profile(ProfileKind::Hysteria2);
        assert_eq!(p.viability(), &Viability::Untested);
        let t = Instant::now();
        p.mark_working(t);
        assert_eq!(p.viability(), &Viability::Working { measured_at: t });
        p.mark_blocked(t, "reset by peer");
        assert!(
            matches!(p.viability(), Viability::Blocked { reason, .. } if reason == "reset by peer")
        );
    }

    #[test]
    fn params_are_opaque_key_values() {
        let mut params = ProfileParams::new();
        params.set("jc", "4");
        assert_eq!(params.get("jc"), Some("4"));
        assert_eq!(params.get("absent"), None);
    }

    #[test]
    fn profile_set_requires_a_tcp_fallback() {
        let udp_only = [
            profile(ProfileKind::AmneziaWg),
            profile(ProfileKind::Hysteria2),
        ];
        assert_eq!(
            validate_profile_set(&udp_only),
            Err(DomainError::NoTcpFallback)
        );

        let with_tcp = [
            profile(ProfileKind::AmneziaWg),
            profile(ProfileKind::VlessReality),
        ];
        assert_eq!(validate_profile_set(&with_tcp), Ok(()));
    }
}
