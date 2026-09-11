//! T029 — routing rules (data-model §4).
//!
//! The load-bearing invariant here is made structural: **an application rule is always
//! best-effort**. `reliability()` is *derived* from the matcher, not a stored field, so
//! there is no way to construct a `Deterministic` application rule (Principle VI,
//! FR-023). Domain and address rules are deterministic.

use std::net::IpAddr;

use crate::endpoint::EndpointAddress;
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
            RuleMatcher::IpCidr(_) | RuleMatcher::DnsPort => false,
        };
        if pattern_empty {
            return Err(DomainError::EmptyPattern);
        }
        // Port-53 traffic must always be *captured*: never tunnelled-with-fallback and
        // never bypassed, or a query could reach the physical network.
        if matches!(matcher, RuleMatcher::DnsPort) && action != RuleAction::Capture {
            return Err(DomainError::DnsPortRequiresCapture);
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
    pub fn is_dns_capture(&self) -> bool {
        matches!(self.matcher, RuleMatcher::DnsPort) && self.action == RuleAction::Capture
    }
}

/// The captive-portal probe hosts that must stay reachable before login (FR-026).
const CAPTIVE_PORTAL_PROBE_HOSTS: &[&str] = &[
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "connectivitycheck.gstatic.com",
    "captive.apple.com",
];

/// The private / non-routable ranges that stay direct by default (FR-024, SC-018).
const LOCAL_BYPASS_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16", // link-local
    "224.0.0.0/4",    // multicast
    "fe80::/10",      // IPv6 link-local
    "ff00::/8",       // IPv6 multicast
];

/// The DNS-capture rule: all outbound port-53 traffic is forced into the tunnel for
/// FakeIP resolution, and dropped if the tunnel is down. It takes precedence 0 — the
/// lowest value, so it wins over every other rule including the local-range bypasses —
/// so no plaintext DNS query can be routed around the tunnel (DNS-leak prevention).
fn dns_capture_rule() -> RoutingRule {
    RoutingRule::build(
        RuleId::new(),
        RuleMatcher::DnsPort,
        RuleAction::Capture,
        0,
        true,
    )
    .expect("built-in DNS-capture rule is always valid")
}

/// The built-in, non-deletable rules, lowest precedence first (they win):
/// 1. **DNS capture** (port 53) — the top-priority anti-leak rule.
/// 2. `Bypass` for the active endpoint address, mirroring the R4 host route so rule
///    evaluation and the route table agree.
/// 3. `Bypass` for local ranges (RFC1918, link-local, multicast) and captive-portal
///    probe hosts, so local resources and portal login work with no configuration
///    (FR-024, FR-026, SC-018).
pub fn builtin_rules(active_endpoint: Option<&EndpointAddress>) -> Vec<RoutingRule> {
    // Precedence 0 is reserved for DNS capture; everything else starts at 1.
    let mut rules = vec![dns_capture_rule()];
    let mut precedence = 1u32;
    let mut push = |matcher: RuleMatcher, p: &mut u32| {
        // Built-in matchers are constructed from constants and never empty, so this
        // cannot fail; `expect` documents that.
        let rule = RoutingRule::build(RuleId::new(), matcher, RuleAction::Bypass, *p, true)
            .expect("built-in bypass rule is always valid");
        rules.push(rule);
        *p += 1;
    };

    // The active endpoint must bypass the tunnel, mirroring the R4 host route.
    if let Some(addr) = active_endpoint {
        push(
            RuleMatcher::Domain(addr.host().to_string()),
            &mut precedence,
        );
    }
    for cidr in LOCAL_BYPASS_CIDRS {
        let parsed = IpCidr::parse(cidr).expect("built-in CIDR constant is valid");
        push(RuleMatcher::IpCidr(parsed), &mut precedence);
    }
    for host in CAPTIVE_PORTAL_PROBE_HOSTS {
        push(RuleMatcher::Domain((*host).to_string()), &mut precedence);
    }
    rules
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
    fn builtins_cover_local_ranges_portal_hosts_and_the_endpoint() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let rules = builtin_rules(Some(&addr));

        assert!(rules.iter().all(RoutingRule::is_builtin));
        // Every built-in bypasses, except the single DNS-capture rule.
        assert!(rules
            .iter()
            .all(|r| r.action() == RuleAction::Bypass || r.is_dns_capture()));

        // Endpoint host present.
        assert!(rules
            .iter()
            .any(|r| matches!(r.matcher(), RuleMatcher::Domain(h) if h == "vpn.example")));
        // A private range present.
        assert!(rules.iter().any(
            |r| matches!(r.matcher(), RuleMatcher::IpCidr(c) if c.to_string() == "192.168.0.0/16")
        ));
        // A captive-portal probe host present.
        assert!(rules
            .iter()
            .any(|r| matches!(r.matcher(), RuleMatcher::Domain(h) if h == "captive.apple.com")));

        // Precedences are unique, so the built-in set is internally valid.
        assert_eq!(validate_rule_set(&rules), Ok(()));
    }

    #[test]
    fn builtins_without_an_endpoint_omit_the_endpoint_rule() {
        let rules = builtin_rules(None);
        assert!(rules.iter().all(RoutingRule::is_builtin));
        assert!(!rules.is_empty());
    }

    #[test]
    fn the_dns_capture_rule_is_built_in_and_wins_over_everything() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let rules = builtin_rules(Some(&addr));

        let capture: Vec<_> = rules.iter().filter(|r| r.is_dns_capture()).collect();
        assert_eq!(capture.len(), 1, "exactly one DNS-capture rule");

        let dns = capture[0];
        assert!(dns.is_builtin());
        assert_eq!(dns.action(), RuleAction::Capture);
        assert_eq!(dns.reliability(), Reliability::Deterministic);
        // It holds the strictly-lowest precedence, so it beats every bypass.
        let min = rules.iter().map(RoutingRule::precedence).min().unwrap();
        assert_eq!(dns.precedence(), min);
        assert_eq!(dns.precedence(), 0);
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
}
