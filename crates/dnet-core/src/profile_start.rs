//! T054 — Profile A start guard (AWG-01, research.md §R4).
//!
//! This is the **primary routing-loop prevention**. AmneziaWG (Profile A) installs a
//! host route to the endpoint via the *physical gateway*. With no gateway on the
//! carrying path there is nowhere to install that route, and starting the tunnel anyway
//! would send the tunnel's own packets to the endpoint back into the tunnel — the R4
//! loop, which presents as a successful handshake with zero throughput.
//!
//! So a Profile A start with no usable gateway must fail cleanly with `NoUsablePath` and
//! start **no** tunnel. Returning the gateway here, as a `Result`, makes "no gateway" a
//! value the caller cannot ignore on the way to bringing the tunnel up.

use std::net::IpAddr;

use crate::path::NetworkPath;
use crate::session::FailureCause;

/// The physical gateway Profile A must route the endpoint host route through, or
/// `NoUsablePath` if the carrying path has none. On error, no tunnel is started.
pub fn gateway_for_profile_a(carrying_path: &NetworkPath) -> Result<IpAddr, FailureCause> {
    // `can_carry_profile_a` is exactly "has a gateway"; going through it keeps the R4
    // rationale attached to the decision rather than duplicating the predicate.
    if !carrying_path.can_carry_profile_a() {
        return Err(FailureCause::NoUsablePath);
    }
    carrying_path.gateway.ok_or(FailureCause::NoUsablePath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::InterfaceId;
    use crate::path::{NetworkPath, PathKind, PathQuality, PathRole};
    use std::net::Ipv4Addr;

    fn path(gateway: Option<IpAddr>) -> NetworkPath {
        NetworkPath {
            interface_id: InterfaceId::new(1),
            kind: PathKind::Wifi,
            gateway,
            quality: PathQuality::unmeasured(),
            role: PathRole::Carrying,
            preference: 0,
        }
    }

    #[test]
    fn a_path_with_a_gateway_yields_it() {
        let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(gateway_for_profile_a(&path(Some(gw))), Ok(gw));
    }

    #[test]
    fn a_path_without_a_gateway_fails_with_no_usable_path() {
        assert_eq!(
            gateway_for_profile_a(&path(None)),
            Err(FailureCause::NoUsablePath)
        );
    }
}
