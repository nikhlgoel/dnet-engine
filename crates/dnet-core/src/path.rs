//! T028 — network paths (data-model §3).
//!
//! One `NetworkPath` is one physical way the machine reaches the internet. Owned by
//! `dnet-netstate`, projected into `dnet-core` for selection and failover.
//!
//! A path becoming `Unusable` never routes tunnelled traffic to the raw interface: the
//! resulting routing posture is decided by [`crate::posture::select_posture`], which
//! fails closed when no path carries and no profile is viable (the kill switch).

use std::net::IpAddr;
use std::time::Duration;

use crate::error::DomainError;
use crate::ids::InterfaceId;

/// The kind of physical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// The role a path currently plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRole {
    /// Carrying traffic now. At most one path holds this (see `validate_paths`).
    Carrying,
    /// Healthy and available, but not carrying.
    Standby,
    /// Not usable right now.
    Unusable,
}

/// Smoothed quality of a path. All three are EWMA-smoothed; raw samples never drive
/// transitions directly (FR-018, SC-007).
///
/// `loss_ewma` is a fraction in `[0.0, 1.0]`, so this type is `PartialEq` but not `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct PathQuality {
    pub loss_ewma: f64,
    pub rtt_ewma: Option<Duration>,
    pub jitter_ewma: Option<Duration>,
}

impl PathQuality {
    /// An unmeasured path: no loss observed yet, no RTT or jitter estimate.
    pub fn unmeasured() -> Self {
        Self {
            loss_ewma: 0.0,
            rtt_ewma: None,
            jitter_ewma: None,
        }
    }
}

impl Default for PathQuality {
    fn default() -> Self {
        Self::unmeasured()
    }
}

/// One physical way the machine reaches the internet.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkPath {
    pub interface_id: InterfaceId,
    pub kind: PathKind,
    /// Gateway address. **Required** to install the endpoint host route (R4); a path
    /// without one cannot carry Profile A.
    pub gateway: Option<IpAddr>,
    pub quality: PathQuality,
    pub role: PathRole,
    /// User-assigned preference; higher wins, ties broken by quality.
    pub preference: i32,
}

impl NetworkPath {
    /// Whether this path can carry the AmneziaWG profile (Profile A).
    ///
    /// The R4 endpoint host route is installed via the physical gateway, so a path
    /// with no gateway cannot carry Profile A without creating the routing loop
    /// (data-model §3 invariant).
    pub fn can_carry_profile_a(&self) -> bool {
        self.gateway.is_some()
    }
}

/// Validate a set of paths: at most one may be `Carrying` (data-model §3). Zero
/// carrying paths means disconnected, which is legal.
pub fn validate_paths(paths: &[NetworkPath]) -> Result<(), DomainError> {
    let carrying = paths
        .iter()
        .filter(|p| p.role == PathRole::Carrying)
        .count();
    if carrying > 1 {
        return Err(DomainError::MultipleCarryingPaths(carrying));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn path(role: PathRole, gateway: Option<IpAddr>) -> NetworkPath {
        NetworkPath {
            interface_id: InterfaceId::new(1),
            kind: PathKind::Wifi,
            gateway,
            quality: PathQuality::unmeasured(),
            role,
            preference: 0,
        }
    }

    fn gw() -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
    }

    #[test]
    fn a_path_without_a_gateway_cannot_carry_profile_a() {
        assert!(!path(PathRole::Standby, None).can_carry_profile_a());
        assert!(path(PathRole::Standby, gw()).can_carry_profile_a());
    }

    #[test]
    fn at_most_one_path_may_be_carrying() {
        let one = [
            path(PathRole::Carrying, gw()),
            path(PathRole::Standby, gw()),
        ];
        assert_eq!(validate_paths(&one), Ok(()));

        let none = [
            path(PathRole::Standby, gw()),
            path(PathRole::Unusable, None),
        ];
        assert_eq!(
            validate_paths(&none),
            Ok(()),
            "zero carrying = disconnected, legal"
        );

        let two = [
            path(PathRole::Carrying, gw()),
            path(PathRole::Carrying, gw()),
        ];
        assert_eq!(
            validate_paths(&two),
            Err(DomainError::MultipleCarryingPaths(2))
        );
    }

    #[test]
    fn unmeasured_quality_has_no_estimates() {
        let q = PathQuality::unmeasured();
        assert_eq!(q.loss_ewma, 0.0);
        assert_eq!(q.rtt_ewma, None);
        assert_eq!(q.jitter_ewma, None);
    }
}
