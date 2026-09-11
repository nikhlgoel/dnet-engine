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
//! - **`tier` follows measurement** (T027): it comes from the recorded HV-07 result for the
//!   kind at the pinned core versions, and is Tier 2 until one is recorded. It is never
//!   inferred from the kind.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::error::DomainError;
use crate::ids::ProfileId;
use crate::tier::{recorded_survival, FailoverTier, SurvivalMeasurement};

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

/// The kind of transport a profile speaks. This alone determines the carrier and the
/// serving core. It does **not** determine the failover tier, which is measured (T027).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileKind {
    /// Obfuscated WG transport, served by the AmneziaWG process. UDP; a Tier 1 candidate.
    AmneziaWg,
    /// QUIC with Salamander/Gecko, served by the primary core. UDP; a Tier 1 candidate.
    Hysteria2,
    /// TLS-camouflaged, served by the primary core. TCP; designed as Tier 2 (FR-016a).
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
}

/// An up/down bandwidth pair, in megabits per second, for Brutal congestion control.
///
/// A zero on either side is a partial configuration. It is refused when configuration is
/// generated (CC-04, `dnet-config::brutal`), which is the gate every path to the core passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthPair {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

/// Revision of the shared-capacity warning the user must acknowledge before Brutal is enabled
/// (FR-006, T105). **Bump it whenever the warning's substance changes**: every existing
/// acknowledgement then stops counting, and Brutal is not generated until the user accepts
/// the new text.
pub const BRUTAL_WARNING_REVISION: u32 = 1;

/// A recorded acknowledgement of the Brutal shared-capacity warning (FR-006).
///
/// A record, not a flag: it names the warning revision that was shown and when it was
/// accepted, so an acknowledgement of an older warning can be told apart from one of the
/// current warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalAcknowledgement {
    /// The `BRUTAL_WARNING_REVISION` the user was shown.
    pub warning_revision: u32,
    /// When the user accepted it, in seconds since the Unix epoch.
    pub acknowledged_at_unix: u64,
}

impl BrutalAcknowledgement {
    /// Whether this acknowledges the warning currently in force.
    pub fn is_current(&self) -> bool {
        self.warning_revision == BRUTAL_WARNING_REVISION
    }
}

/// Brutal congestion control, enabled together with the acknowledgement that permitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalOptIn {
    bandwidth: BandwidthPair,
    acknowledgement: BrutalAcknowledgement,
}

impl BrutalOptIn {
    pub fn bandwidth(&self) -> &BandwidthPair {
        &self.bandwidth
    }

    pub fn acknowledgement(&self) -> &BrutalAcknowledgement {
        &self.acknowledgement
    }
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
    brutal: Option<BrutalOptIn>,
}

impl ConnectionProfile {
    /// Create a profile. Its tier is the recorded HV-07 result for its kind (Tier 2 until
    /// one is recorded), its viability is `Untested`, and Brutal is off (so BBR is used —
    /// data-model §2, R2).
    pub fn new(id: ProfileId, kind: ProfileKind, params: ProfileParams) -> Self {
        Self::with_survival(id, kind, params, recorded_survival(kind))
    }

    /// A profile whose tier comes from the given measurement. Only for tests in this crate:
    /// production tiers come solely from the recorded results.
    #[cfg(test)]
    pub(crate) fn measured(
        id: ProfileId,
        kind: ProfileKind,
        params: ProfileParams,
        measurement: SurvivalMeasurement,
    ) -> Self {
        Self::with_survival(id, kind, params, measurement)
    }

    fn with_survival(
        id: ProfileId,
        kind: ProfileKind,
        params: ProfileParams,
        measurement: SurvivalMeasurement,
    ) -> Self {
        Self {
            id,
            tier: FailoverTier::from_measurement(measurement),
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

    /// The measured failover tier. There is no setter: it changes only when a recorded
    /// HV-07 result changes (T085).
    pub fn tier(&self) -> FailoverTier {
        self.tier
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

    /// The Brutal opt-in, if enabled. `None` means BBR (the default), which `dnet-config`
    /// realises by omitting the bandwidth section entirely (R2).
    pub fn brutal(&self) -> Option<&BrutalOptIn> {
        self.brutal.as_ref()
    }

    /// Enable Brutal congestion control.
    ///
    /// Refused unless this is a Hysteria 2 profile and the acknowledgement is of the warning
    /// currently in force (FR-006). The acknowledgement is kept with the bandwidth, so
    /// generation can re-check it if the warning revision changes later.
    pub fn enable_brutal(
        &mut self,
        bandwidth: BandwidthPair,
        acknowledgement: BrutalAcknowledgement,
    ) -> Result<(), DomainError> {
        if self.kind != ProfileKind::Hysteria2 {
            return Err(DomainError::BrutalRequiresHysteria2);
        }
        if !acknowledgement.is_current() {
            return Err(DomainError::BrutalNotAcknowledged);
        }
        self.brutal = Some(BrutalOptIn {
            bandwidth,
            acknowledgement,
        });
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
    fn a_profile_takes_its_tier_from_the_recorded_measurement_not_its_kind() {
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            assert_eq!(
                profile(kind).tier(),
                FailoverTier::from_measurement(recorded_survival(kind)),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_same_kind_gets_whatever_tier_was_measured() {
        let measured = |m| {
            ConnectionProfile::measured(
                ProfileId::new("p"),
                ProfileKind::AmneziaWg,
                ProfileParams::new(),
                m,
            )
            .tier()
        };
        assert_eq!(measured(SurvivalMeasurement::Survived), FailoverTier::Tier1);
        assert_eq!(measured(SurvivalMeasurement::Broke), FailoverTier::Tier2);
        assert_eq!(
            measured(SurvivalMeasurement::NotMeasured),
            FailoverTier::Tier2
        );
    }

    #[test]
    fn new_profile_defaults_to_bbr_not_brutal() {
        assert!(profile(ProfileKind::Hysteria2).brutal().is_none());
    }

    const BW: BandwidthPair = BandwidthPair {
        up_mbps: 50,
        down_mbps: 200,
    };

    fn current_ack() -> BrutalAcknowledgement {
        BrutalAcknowledgement {
            warning_revision: BRUTAL_WARNING_REVISION,
            acknowledged_at_unix: 1_757_635_200,
        }
    }

    #[test]
    fn brutal_requires_a_hysteria2_profile() {
        for kind in [ProfileKind::AmneziaWg, ProfileKind::VlessReality] {
            let mut p = profile(kind);
            assert_eq!(
                p.enable_brutal(BW, current_ack()),
                Err(DomainError::BrutalRequiresHysteria2)
            );
            assert!(p.brutal().is_none());
        }
    }

    #[test]
    fn brutal_records_the_acknowledgement_with_the_bandwidth() {
        let mut p = profile(ProfileKind::Hysteria2);
        assert_eq!(p.enable_brutal(BW, current_ack()), Ok(()));
        let opt_in = p.brutal().expect("enabled");
        assert_eq!(opt_in.bandwidth(), &BW);
        assert_eq!(opt_in.acknowledgement(), &current_ack());
    }

    /// An acknowledgement of a different warning text is not an acknowledgement of this one.
    #[test]
    fn brutal_refuses_an_acknowledgement_of_another_warning_revision() {
        let mut p = profile(ProfileKind::Hysteria2);
        for revision in [0, BRUTAL_WARNING_REVISION + 1] {
            let ack = BrutalAcknowledgement {
                warning_revision: revision,
                ..current_ack()
            };
            assert_eq!(
                p.enable_brutal(BW, ack),
                Err(DomainError::BrutalNotAcknowledged)
            );
            assert!(p.brutal().is_none());
        }
    }

    #[test]
    fn disabling_brutal_returns_to_bbr() {
        let mut p = profile(ProfileKind::Hysteria2);
        p.enable_brutal(BW, current_ack()).unwrap();
        p.disable_brutal();
        assert!(p.brutal().is_none());
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
