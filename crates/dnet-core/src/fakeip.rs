//! T069 — FakeIP, as the product sees it (FR-020, FR-021).
//!
//! The primary core answers a lookup for a name with a **placeholder address** from a private pool,
//! remembers which name it handed it out for, and routes the connection that follows by that name. The
//! synthesis and the reverse lookup are the core's; the product does not read its table, and does not need
//! to: rules are evaluated on names (`rule_eval`), and a connection to a placeholder is, by construction,
//! a connection to a name.
//!
//! What the product does own is the **definition of the pool** (one place, here, used by the config
//! generator and by the checks that keep rules out of it) and two guards:
//!
//! - [`is_placeholder`] says whether an address is one of the placeholders, so anything that shows or logs a
//!   destination can say "a name" instead of printing an address that means nothing outside the tunnel.
//! - [`check_user_range`] refuses a rule of the person's that sits **inside** the pool. Nothing real lives
//!   at those addresses, so such a rule could only ever be a mistake, and what the core does with a
//!   placeholder it also has a name for is not something a rule should lean on. (A range that merely
//!   *contains* the pool, such as `0.0.0.0/0`, is fine: it says something true about real addresses.)
//!
//! Each tunnel hands out only one half of the pool (T131, CC-02); the halves live with the generator
//! (`dnet_config::primary::FakeIpHalf`), the whole pool lives here.
//!
//! Pure logic: no I/O.

use std::net::IpAddr;

use crate::error::DomainError;
use crate::rule::IpCidr;

/// The IPv4 pool (CC-02, research.md R3).
pub const INET4_POOL: &str = "198.18.0.0/15";
/// The IPv6 pool (CC-02, research.md R3).
pub const INET6_POOL: &str = "fc00::/18";

fn pools() -> [IpCidr; 2] {
    [
        IpCidr::parse(INET4_POOL).expect("the IPv4 pool constant is a valid CIDR"),
        IpCidr::parse(INET6_POOL).expect("the IPv6 pool constant is a valid CIDR"),
    ]
}

/// An address with an IPv4-mapped IPv6 form turned into the IPv4 address it is.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Whether `ip` is a placeholder the core hands out for a name.
pub fn is_placeholder(ip: IpAddr) -> bool {
    let ip = canonical(ip);
    let host = IpCidr::parse(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
        .expect("an address with a full-length prefix is a valid CIDR");
    pools().iter().any(|pool| pool.overlaps(&host))
}

/// Refuse a range of the person's that lies inside the pool.
pub fn check_user_range(range: &IpCidr) -> Result<(), DomainError> {
    let inside = pools()
        .iter()
        .any(|pool| pool.overlaps(range) && range.prefix_len() >= pool.prefix_len());
    if inside {
        return Err(DomainError::RangeInsideFakeIpPool(range.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{RoutingRule, RuleAction, RuleMatcher};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> IpCidr {
        IpCidr::parse(s).unwrap()
    }

    #[test]
    fn the_pool_edges_are_exact() {
        for inside in [
            "198.18.0.0",
            "198.18.0.2",
            "198.19.255.255",
            "fc00::",
            "fc00::1",
            "fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(is_placeholder(ip(inside)), "{inside}");
        }
        for outside in [
            "198.17.255.255",
            "198.20.0.0",
            "172.19.0.1",
            "10.0.0.1",
            "93.184.216.34",
            "fc00:4000::",
            "fd00::1",
            "2606:4700::1",
        ] {
            assert!(!is_placeholder(ip(outside)), "{outside}");
        }
    }

    #[test]
    fn an_address_written_the_other_way_is_still_that_address() {
        assert!(is_placeholder(ip("::ffff:198.18.0.5")));
        assert!(!is_placeholder(ip("::ffff:198.20.0.5")));
    }

    #[test]
    fn a_range_inside_the_pool_is_refused() {
        for inside in [
            "198.18.0.0/15",
            "198.18.0.0/16",
            "198.19.0.0/16",
            "198.18.1.0/24",
            "198.18.0.7/32",
            "fc00::/18",
            "fc00::/19",
            "fc00:2000::/19",
            "fc00::1/128",
        ] {
            assert!(
                matches!(
                    check_user_range(&cidr(inside)),
                    Err(DomainError::RangeInsideFakeIpPool(_))
                ),
                "{inside}"
            );
        }
    }

    #[test]
    fn a_range_that_contains_the_pool_or_misses_it_is_fine() {
        for fine in [
            "0.0.0.0/0",
            "198.0.0.0/8",
            "198.16.0.0/14",
            "198.20.0.0/16",
            "10.0.0.0/8",
            "::/0",
            "fc00::/7",
            "fd00::/8",
            "2001:db8::/32",
        ] {
            assert_eq!(check_user_range(&cidr(fine)), Ok(()), "{fine}");
        }
    }

    #[test]
    fn a_rule_the_person_makes_is_checked_when_it_is_made() {
        assert!(matches!(
            RoutingRule::user(
                RuleMatcher::IpCidr(cidr("198.18.0.0/15")),
                RuleAction::Bypass,
                300
            ),
            Err(DomainError::RangeInsideFakeIpPool(_))
        ));
        assert!(RoutingRule::user(
            RuleMatcher::IpCidr(cidr("198.0.0.0/8")),
            RuleAction::Bypass,
            300
        )
        .is_ok());
    }

    #[test]
    fn the_pool_constants_are_what_the_generator_publishes() {
        // `dnet_config::primary::FAKEIP_INET4/6` are these constants; this keeps the numbers in the
        // contract (CC-02) and in the spec's research note (R3) from drifting apart silently.
        assert_eq!(INET4_POOL, "198.18.0.0/15");
        assert_eq!(INET6_POOL, "fc00::/18");
    }
}
