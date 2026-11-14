// SPDX-License-Identifier: GPL-3.0-or-later
//! T029 — routing rules (data-model §4).
//!
//! The load-bearing invariant here is made structural: **an application rule is always
//! best-effort**. `reliability()` is *derived* from the matcher, not a stored field, so
//! there is no way to construct a `Deterministic` application rule (Principle VI,
//! FR-023). Domain and address rules are deterministic.

use std::net::IpAddr;

use crate::error::DomainError;
use crate::ids::RuleId;

/// How reliably a rule can be enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    /// Applied exactly, from information available before the connection is made.
    Deterministic,
    /// Applied on a best effort: application attribution is a connect-time heuristic
    /// (ETW), so it can miss short-lived connections.
    BestEffort,
}

/// What a rule does with matching traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Send it through the tunnel.
    Tunnel,
    /// Keep it on the local network, direct.
    Bypass,
    /// Force it into the TUN for FakeIP resolution, and **drop it if the tunnel is not
    /// up** — never let it reach the physical interface. Used only for the built-in
    /// DNS-capture rule, so no plaintext port-53 query can leak to the local network
    /// (DNS-leak prevention).
    Capture,
    /// Refuse it: the lookup gets no answer and the connection is not made. Used only by built-in
    /// rules (the encrypted-DNS block, T070), so a person's rule can never silently black-hole
    /// traffic they did not mean to.
    Reject,
}

/// A parsed CIDR block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// Parse `a.b.c.d/n` or `[v6]/n`. Rejects a missing or out-of-range prefix.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let err = || DomainError::InvalidCidr(s.to_string());
        let (addr_str, prefix_str) = s.split_once('/').ok_or_else(err)?;
        let addr: IpAddr = addr_str.parse().map_err(|_| err())?;
        let prefix_len: u8 = prefix_str.parse().map_err(|_| err())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(err());
        }
        Ok(Self { addr, prefix_len })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether the two blocks share any address. CIDR blocks either nest or are disjoint,
    /// so this is containment in either direction; blocks of different families never
    /// overlap.
    pub fn overlaps(&self, other: &IpCidr) -> bool {
        let shared = self.prefix_len.min(other.prefix_len);
        match (self.addr, other.addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(shared)).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(shared)).unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// What a rule matches against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatcher {
    /// An exact domain name.
    Domain(String),
    /// A domain and all its subdomains.
    DomainSuffix(String),
    /// An address range.
    IpCidr(IpCidr),
    /// An originating application by executable path. Always best-effort.
    Application(String),
    /// All outbound DNS traffic — destination port 53, on both UDP and TCP. Matched
    /// before any address- or domain-based rule so no query can be routed around the
    /// tunnel. Only ever paired with `RuleAction::Capture`.
    DnsPort,
    /// Destination port 853, DNS over TLS (TCP) and over QUIC (UDP). Only ever paired with
    /// `RuleAction::Reject` (T070).
    EncryptedDnsPort,
}

/// A statement that traffic matching a criterion is tunnelled or bypassed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    id: RuleId,
    matcher: RuleMatcher,
    action: RuleAction,
    /// Lower wins (data-model §4). Documented and shown to the user (FR-022).
    precedence: u32,
    builtin: bool,
}

impl RoutingRule {
    /// Create a user-defined rule, validating the matcher pattern is non-empty.
    pub fn user(
        matcher: RuleMatcher,
        action: RuleAction,
        precedence: u32,
    ) -> Result<Self, DomainError> {
        Self::build(RuleId::new(), matcher, action, precedence, false)
    }

    /// A person's rule read back from the saved configuration, with the id it was saved under. It
    /// passes the checks a new one does, and may only be what a person can make: a domain, suffix,
    /// address or program rule that tunnels or bypasses. Port matchers and `Capture` belong to the
    /// built-in set alone.
    pub fn restored_user(
        id: RuleId,
        matcher: RuleMatcher,
        action: RuleAction,
        precedence: u32,
    ) -> Result<Self, DomainError> {
        let personal = !matches!(
            matcher,
            RuleMatcher::DnsPort | RuleMatcher::EncryptedDnsPort
        ) && matches!(action, RuleAction::Tunnel | RuleAction::Bypass);
        if !personal {
            return Err(DomainError::NotAPersonalRule);
        }
        Self::build(id, matcher, action, precedence, false)
    }

    /// Create a built-in rule. Crate-private: only `builtin_rules` makes these, so no
    /// caller outside `dnet-core` can mark a rule non-deletable.
    pub(crate) fn builtin(
        matcher: RuleMatcher,
        action: RuleAction,
        precedence: u32,
    ) -> Result<Self, DomainError> {
        Self::build(RuleId::new(), matcher, action, precedence, true)
    }

    fn build(
        id: RuleId,
        matcher: RuleMatcher,
        action: RuleAction,
        precedence: u32,
        builtin: bool,
    ) -> Result<Self, DomainError> {
        let pattern_empty = match &matcher {
            RuleMatcher::Domain(p) | RuleMatcher::DomainSuffix(p) | RuleMatcher::Application(p) => {
                p.trim().is_empty()
            }
            RuleMatcher::IpCidr(_) | RuleMatcher::DnsPort | RuleMatcher::EncryptedDnsPort => false,
        };
        if pattern_empty {
            return Err(DomainError::EmptyPattern);
        }
        // A name pattern must be one a connection could carry: it goes into a generated configuration,
        // and a pattern that cannot match anything is a rule that silently does nothing.
        if let RuleMatcher::Domain(p) | RuleMatcher::DomainSuffix(p) = &matcher {
            crate::rule_eval::check_domain_pattern(p)?;
        }
        // The product's own rules may name the pool's neighbours; a person's may not sit inside it.
        if let (RuleMatcher::IpCidr(range), false) = (&matcher, builtin) {
            crate::fakeip::check_user_range(range)?;
        }
        // Port-53 traffic must always be *captured*: never tunnelled-with-fallback and
        // never bypassed, or a query could reach the physical network.
        if matches!(matcher, RuleMatcher::DnsPort) && action != RuleAction::Capture {
            return Err(DomainError::DnsPortRequiresCapture);
        }
        if matches!(matcher, RuleMatcher::EncryptedDnsPort) && action != RuleAction::Reject {
            return Err(DomainError::EncryptedDnsPortRequiresReject);
        }
        if action == RuleAction::Reject && !builtin {
            return Err(DomainError::RejectIsBuiltinOnly);
        }
        Ok(Self {
            id,
            matcher,
            action,
            precedence,
            builtin,
        })
    }

    pub fn id(&self) -> RuleId {
        self.id
    }

    pub fn matcher(&self) -> &RuleMatcher {
        &self.matcher
    }

    pub fn action(&self) -> RuleAction {
        self.action
    }

    pub fn precedence(&self) -> u32 {
        self.precedence
    }

    /// Whether this is a built-in rule the user cannot delete (data-model §4).
    pub fn is_builtin(&self) -> bool {
        self.builtin
    }

    /// Reliability, **derived** from the matcher: application matchers are always
    /// best-effort; every other matcher is deterministic. There is no way to make a
    /// deterministic application rule (Principle VI, FR-023).
    pub fn reliability(&self) -> Reliability {
        match self.matcher {
            RuleMatcher::Application(_) => Reliability::BestEffort,
            _ => Reliability::Deterministic,
        }
    }

    /// Whether this rule is the DNS-capture rule (port-53 traffic forced into the
    /// tunnel). There is exactly one, built-in and non-deletable.
    /// The same rule at another precedence. Crate-private: only the built-in layout moves rules
    /// (`builtin_rules::with_active_endpoint`), and never a person's.
    pub(crate) fn renumbered(&self, precedence: u32) -> Self {
        Self {
            precedence,
            ..self.clone()
        }
    }

    pub fn is_dns_capture(&self) -> bool {
        matches!(self.matcher, RuleMatcher::DnsPort) && self.action == RuleAction::Capture
    }
}

/// Validate a set of rules: no two may share a precedence value (FR-022). Precedence
/// collisions are rejected at configuration time, not resolved arbitrarily.
pub fn validate_rule_set(rules: &[RoutingRule]) -> Result<(), DomainError> {
    let mut seen = std::collections::HashSet::new();
    for rule in rules {
        if !seen.insert(rule.precedence) {
            return Err(DomainError::PrecedenceCollision(rule.precedence));
        }
    }
    Ok(())
}

/// A person's rules come after every built-in rule and after the encrypted-DNS block, whether or
/// not the block is in force (T108): from [`crate::doh_block::USER_RULES_START`] on. Order is
/// safety-critical here: a person's "tunnel" rule ahead of the endpoint bypass would send the
/// tunnel's own packets into the tunnel.
pub fn validate_user_rules_follow_builtins(rules: &[RoutingRule]) -> Result<(), DomainError> {
    let start = crate::doh_block::USER_RULES_START;
    let highest_builtin = rules
        .iter()
        .filter(|r| r.is_builtin())
        .map(RoutingRule::precedence)
        .max()
        .unwrap_or(0);
    match rules
        .iter()
        .filter(|r| !r.is_builtin())
        .map(RoutingRule::precedence)
        .find(|p| *p < start || *p <= highest_builtin)
    {
        Some(low) => Err(DomainError::UserRuleOutranksBuiltins(low, start)),
        None => Ok(()),
    }
}

/// The precedence the next rule a person adds gets: after every rule there is, and never below
/// [`crate::doh_block::USER_RULES_START`]. `None` when there is no number left.
pub fn next_user_precedence(rules: &[RoutingRule]) -> Option<u32> {
    let after = rules
        .iter()
        .map(RoutingRule::precedence)
        .max()
        .map_or(Some(0), |p| p.checked_add(1))?;
    Some(after.max(crate::doh_block::USER_RULES_START))
}

/// Validate that a rule set protects against DNS leaks: it must contain the DNS-capture
/// rule, and that rule must hold the strictly-lowest precedence, so no bypass can route
/// port-53 traffic around the tunnel. Enforced on every rule-set mutation.
pub fn validate_dns_leak_protection(rules: &[RoutingRule]) -> Result<(), DomainError> {
    let capture = rules
        .iter()
        .find(|r| r.is_dns_capture())
        .ok_or(DomainError::MissingDnsCapture)?;
    let min_precedence = rules.iter().map(RoutingRule::precedence).min();
    if min_precedence != Some(capture.precedence()) {
        return Err(DomainError::MissingDnsCapture);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin_rules::builtin_rules;

    #[test]
    fn application_rules_are_always_best_effort() {
        let rule = RoutingRule::user(
            RuleMatcher::Application(r"C:\chrome.exe".into()),
            RuleAction::Tunnel,
            10,
        )
        .unwrap();
        assert_eq!(rule.reliability(), Reliability::BestEffort);
    }

    #[test]
    fn domain_and_cidr_rules_are_deterministic() {
        let domain = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            1,
        )
        .unwrap();
        assert_eq!(domain.reliability(), Reliability::Deterministic);

        let cidr = RoutingRule::user(
            RuleMatcher::IpCidr(IpCidr::parse("10.0.0.0/8").unwrap()),
            RuleAction::Bypass,
            2,
        )
        .unwrap();
        assert_eq!(cidr.reliability(), Reliability::Deterministic);
    }

    #[test]
    fn empty_patterns_are_rejected() {
        for matcher in [
            RuleMatcher::Domain(String::new()),
            RuleMatcher::DomainSuffix("   ".into()),
            RuleMatcher::Application(String::new()),
        ] {
            assert_eq!(
                RoutingRule::user(matcher, RuleAction::Tunnel, 1),
                Err(DomainError::EmptyPattern)
            );
        }
    }

    #[test]
    fn a_domain_pattern_that_cannot_be_a_name_is_refused_when_the_rule_is_made() {
        for bad in ["a b.com", "x\u{7}.com", "ünï.com", "a..b", "-x.com"] {
            for matcher in [
                RuleMatcher::Domain(bad.into()),
                RuleMatcher::DomainSuffix(bad.into()),
            ] {
                assert!(
                    matches!(
                        RoutingRule::user(matcher, RuleAction::Tunnel, 1),
                        Err(DomainError::InvalidDomainPattern(_))
                    ),
                    "{bad:?}"
                );
            }
        }
        // An application path is not a domain name, and keeps its own rules.
        assert!(RoutingRule::user(
            RuleMatcher::Application(r"C:\Program Files\a b.exe".into()),
            RuleAction::Tunnel,
            1
        )
        .is_ok());
    }

    #[test]
    fn cidr_parsing_validates_prefix_range() {
        assert!(IpCidr::parse("192.168.0.0/16").is_ok());
        assert!(IpCidr::parse("fe80::/10").is_ok());
        assert!(matches!(
            IpCidr::parse("10.0.0.0/33"),
            Err(DomainError::InvalidCidr(_))
        ));
        assert!(matches!(
            IpCidr::parse("10.0.0.0"),
            Err(DomainError::InvalidCidr(_))
        ));
        assert!(matches!(
            IpCidr::parse("not-an-ip/8"),
            Err(DomainError::InvalidCidr(_))
        ));
    }

    #[test]
    fn user_rules_are_not_builtin() {
        let rule = RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            1,
        )
        .unwrap();
        assert!(!rule.is_builtin());
    }

    #[test]
    fn cidr_overlap_is_containment_in_either_direction_within_a_family() {
        let c = |s: &str| IpCidr::parse(s).unwrap();
        assert!(c("fc00::/7").overlaps(&c("fc00::/18")));
        assert!(c("fc00::/18").overlaps(&c("fc00::/7")));
        assert!(c("198.18.0.0/15").overlaps(&c("198.19.255.255/32")));
        assert!(!c("198.18.0.0/15").overlaps(&c("198.20.0.0/16")));
        assert!(!c("192.168.0.0/16").overlaps(&c("198.18.0.0/15")));
        assert!(!c("fe80::/10").overlaps(&c("fc00::/18")));
        assert!(c("0.0.0.0/0").overlaps(&c("10.1.2.3/32")));
        // Different families never overlap.
        assert!(!c("0.0.0.0/0").overlaps(&c("::/0")));
    }

    #[test]
    fn user_rules_can_never_be_builtin_and_builtins_are_marked() {
        let builtin = RoutingRule::builtin(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Bypass,
            3,
        )
        .unwrap();
        assert!(builtin.is_builtin());
        // The same constructor validation applies to built-ins.
        assert_eq!(
            RoutingRule::builtin(RuleMatcher::DnsPort, RuleAction::Bypass, 0),
            Err(DomainError::DnsPortRequiresCapture)
        );
    }

    #[test]
    fn a_dns_port_matcher_may_not_bypass_or_tunnel() {
        for action in [RuleAction::Bypass, RuleAction::Tunnel] {
            assert_eq!(
                RoutingRule::user(RuleMatcher::DnsPort, action, 5),
                Err(DomainError::DnsPortRequiresCapture)
            );
        }
        // Capture is accepted.
        assert!(RoutingRule::user(RuleMatcher::DnsPort, RuleAction::Capture, 5).is_ok());
    }

    #[test]
    fn leak_protection_requires_the_capture_rule_at_top_precedence() {
        let ok = builtin_rules(None);
        assert_eq!(validate_dns_leak_protection(&ok), Ok(()));

        // A set with no DNS-capture rule is rejected.
        let no_dns = vec![RoutingRule::user(
            RuleMatcher::Domain("x.example".into()),
            RuleAction::Tunnel,
            1,
        )
        .unwrap()];
        assert_eq!(
            validate_dns_leak_protection(&no_dns),
            Err(DomainError::MissingDnsCapture)
        );

        // A capture rule that does not hold the lowest precedence is rejected: a lower
        // bypass could otherwise route port-53 around the tunnel.
        let capture_outranked = vec![
            RoutingRule::user(RuleMatcher::DnsPort, RuleAction::Capture, 5).unwrap(),
            RoutingRule::user(
                RuleMatcher::IpCidr(IpCidr::parse("8.8.8.8/32").unwrap()),
                RuleAction::Bypass,
                1,
            )
            .unwrap(),
        ];
        assert_eq!(
            validate_dns_leak_protection(&capture_outranked),
            Err(DomainError::MissingDnsCapture)
        );
    }

    #[test]
    fn precedence_collisions_are_rejected() {
        let a = RoutingRule::user(
            RuleMatcher::Domain("a.example".into()),
            RuleAction::Tunnel,
            5,
        )
        .unwrap();
        let b = RoutingRule::user(
            RuleMatcher::Domain("b.example".into()),
            RuleAction::Bypass,
            5,
        )
        .unwrap();
        assert_eq!(
            validate_rule_set(&[a, b]),
            Err(DomainError::PrecedenceCollision(5))
        );
    }

    #[test]
    fn distinct_precedences_validate() {
        let a = RoutingRule::user(
            RuleMatcher::Domain("a.example".into()),
            RuleAction::Tunnel,
            5,
        )
        .unwrap();
        let b = RoutingRule::user(
            RuleMatcher::Domain("b.example".into()),
            RuleAction::Bypass,
            6,
        )
        .unwrap();
        assert_eq!(validate_rule_set(&[a, b]), Ok(()));
    }

    // ---------------------------------------------------------------- a person's rules (T108)

    fn mine(precedence: u32) -> RoutingRule {
        RoutingRule::user(
            RuleMatcher::Domain("example.com".into()),
            RuleAction::Bypass,
            precedence,
        )
        .unwrap()
    }

    /// A person's rule never outranks a built-in, whatever the encrypted-DNS choice: the built-ins
    /// keep DNS captured, the endpoint off the tunnel and local resources reachable.
    #[test]
    fn a_users_rule_below_the_user_range_is_refused() {
        let mut rules = builtin_rules(None);
        rules.push(mine(crate::doh_block::USER_RULES_START - 1));
        assert!(matches!(
            validate_user_rules_follow_builtins(&rules),
            Err(DomainError::UserRuleOutranksBuiltins(..))
        ));
        let mut rules = builtin_rules(None);
        rules.push(mine(crate::doh_block::USER_RULES_START));
        assert_eq!(validate_user_rules_follow_builtins(&rules), Ok(()));
    }

    #[test]
    fn the_next_users_rule_goes_after_every_other() {
        let mut rules = builtin_rules(None);
        assert_eq!(
            next_user_precedence(&rules),
            Some(crate::doh_block::USER_RULES_START)
        );
        rules.push(mine(crate::doh_block::USER_RULES_START + 7));
        assert_eq!(
            next_user_precedence(&rules),
            Some(crate::doh_block::USER_RULES_START + 8)
        );
        rules.push(mine(u32::MAX));
        assert_eq!(
            next_user_precedence(&rules),
            None,
            "no room is not a wrap-around"
        );
    }

    /// A saved rule comes back with the id it was saved under, through the same checks as a new one.
    #[test]
    fn a_restored_rule_keeps_its_id_and_is_checked_like_a_new_one() {
        let id = RuleId::new();
        let rule = RoutingRule::restored_user(
            id,
            RuleMatcher::DomainSuffix("example.com".into()),
            RuleAction::Tunnel,
            300,
        )
        .unwrap();
        assert_eq!(rule.id(), id);
        assert!(!rule.is_builtin());
        assert!(
            RoutingRule::restored_user(id, RuleMatcher::DnsPort, RuleAction::Capture, 300).is_err()
        );
        assert!(RoutingRule::restored_user(
            id,
            RuleMatcher::Domain("example.com".into()),
            RuleAction::Reject,
            300
        )
        .is_err());
    }
}
