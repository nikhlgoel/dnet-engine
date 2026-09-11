//! T057: the Brutal opt-in gate at generation time (CC-04, FR-006, research.md §R2).
//!
//! Brutal is on when, and only when, the Hysteria 2 outbound carries `up_mbps` and `down_mbps`.
//! It ignores congestion signals and degrades every other user of the same access point, so
//! it is emitted only when both hold:
//!
//! - **the acknowledgement is of the warning currently in force.** The domain checks this when
//!   Brutal is enabled. It is checked again here because the warning revision can be bumped
//!   after a record was stored, and a stale record must stop producing Brutal;
//! - **both directions are set.** One side alone silently half-enables Brutal, so a zero on
//!   either side fails generation rather than being dropped or defaulted.

use dnet_core::profile::{BrutalOptIn, BRUTAL_WARNING_REVISION};

use crate::error::ConfigError;

/// The bandwidth pair to emit, in megabits per second. Both sides are always non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalBandwidth {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

/// The bandwidth to emit for a profile's Brutal setting: `None` for BBR (no opt-in).
pub fn brutal_bandwidth(
    opt_in: Option<&BrutalOptIn>,
) -> Result<Option<BrutalBandwidth>, ConfigError> {
    resolve(opt_in, BRUTAL_WARNING_REVISION)
}

fn resolve(
    opt_in: Option<&BrutalOptIn>,
    current_revision: u32,
) -> Result<Option<BrutalBandwidth>, ConfigError> {
    let Some(opt_in) = opt_in else {
        return Ok(None);
    };
    if opt_in.acknowledgement().warning_revision != current_revision {
        return Err(ConfigError::BrutalNotAcknowledged);
    }
    let bandwidth = opt_in.bandwidth();
    if bandwidth.up_mbps == 0 || bandwidth.down_mbps == 0 {
        return Err(ConfigError::PartialBrutalBandwidth);
    }
    Ok(Some(BrutalBandwidth {
        up_mbps: bandwidth.up_mbps,
        down_mbps: bandwidth.down_mbps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::{
        BandwidthPair, BrutalAcknowledgement, ConnectionProfile, ProfileKind, ProfileParams,
    };

    fn hysteria2_with(up_mbps: u32, down_mbps: u32) -> ConnectionProfile {
        let mut p = ConnectionProfile::new(
            ProfileId::new("hy2"),
            ProfileKind::Hysteria2,
            ProfileParams::new(),
        );
        p.enable_brutal(
            BandwidthPair { up_mbps, down_mbps },
            BrutalAcknowledgement {
                warning_revision: BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_757_635_200,
            },
        )
        .unwrap();
        p
    }

    #[test]
    fn no_opt_in_means_bbr() {
        assert_eq!(brutal_bandwidth(None), Ok(None));
    }

    #[test]
    fn a_current_acknowledgement_with_both_sides_emits_both() {
        let p = hysteria2_with(50, 200);
        assert_eq!(
            brutal_bandwidth(p.brutal()),
            Ok(Some(BrutalBandwidth {
                up_mbps: 50,
                down_mbps: 200
            }))
        );
    }

    #[test]
    fn either_side_missing_fails_generation() {
        for (up, down) in [(0, 200), (50, 0), (0, 0)] {
            assert_eq!(
                brutal_bandwidth(hysteria2_with(up, down).brutal()),
                Err(ConfigError::PartialBrutalBandwidth)
            );
        }
    }

    /// A record made before the warning text changed no longer produces Brutal.
    #[test]
    fn a_warning_revision_bump_invalidates_the_stored_acknowledgement() {
        let p = hysteria2_with(50, 200);
        assert_eq!(
            resolve(p.brutal(), BRUTAL_WARNING_REVISION + 1),
            Err(ConfigError::BrutalNotAcknowledged)
        );
    }

    /// The acknowledgement is checked before the bandwidth: a stale record is reported as
    /// unacknowledged even when its bandwidth is also partial.
    #[test]
    fn a_stale_acknowledgement_is_reported_before_partial_bandwidth() {
        let p = hysteria2_with(0, 200);
        assert_eq!(
            resolve(p.brutal(), BRUTAL_WARNING_REVISION + 1),
            Err(ConfigError::BrutalNotAcknowledged)
        );
    }
}
