//! T031 — the built-in, non-deletable rule set (data-model §4, FR-024, FR-026, SC-018).
//!
//! Lowest precedence first (lower wins):
//! 1. **DNS capture** (port 53), precedence `0` — the anti-leak rule outranks everything.
//! 2. `Bypass` for the **active endpoint address**, mirroring the R4 host route so rule
//!    evaluation and the route table agree (data-model §Cross-cutting 2).
//! 3. `Bypass` for **local ranges**: RFC1918, link-local, multicast.
//! 4. `Bypass` for the **captive-portal probe hosts**, so portal detection and login work
//!    before the tunnel can.
//!
//! **Non-deletable** is enforced by [`validate_builtin_rules_present`], which every rule-set
//! mutation runs, and user rules can never be marked built-in.
//!
//! **Deliberately not bypassed: IPv6 unique-local `fc00::/7`.** It is the IPv6 private range,
//! but it contains the FakeIP pool `fc00::/18`; bypassing it would send every IPv6 FakeIP
//! address around the tunnel and break domain routing.

use std::net::IpAddr;

use crate::endpoint::EndpointAddress;
use crate::error::DomainError;
use crate::rule::{IpCidr, RoutingRule, RuleAction, RuleMatcher};

/// The private and non-routable ranges that stay direct by default (FR-024, SC-018).
pub const LOCAL_BYPASS_CIDRS: &[&str] = &[
    "10.0.0.0/8",     // RFC1918
    "172.16.0.0/12",  // RFC1918
    "192.168.0.0/16", // RFC1918
    "169.254.0.0/16", // IPv4 link-local
    "224.0.0.0/4",    // IPv4 multicast
    "fe80::/10",      // IPv6 link-local
    "ff00::/8",       // IPv6 multicast
];

/// The captive-portal probe domains (FR-026), as suffixes so every host under them matches.
///
/// Windows' Network Connectivity Status Indicator probes `www.msftconnecttest.com` (and the
/// legacy `www.msftncsi.com`), and Microsoft's guidance for restricted networks is to allow
/// `*.msftconnecttest.com` and `*.msftncsi.com` on port 80 (Microsoft Learn, KB 4494446,
/// "An Internet Explorer or Edge window opens when your computer connects to a corporate
/// network or a public network"). v1 is Windows-only, so other platforms' probe hosts are
/// not bypassed: they would only send traffic around the tunnel for nothing.
pub const CAPTIVE_PORTAL_PROBE_SUFFIXES: &[&str] = &["msftconnecttest.com", "msftncsi.com"];

/// The built-in rules for the given active endpoint (or none when disconnected).
pub fn builtin_rules(active_endpoint: Option<&EndpointAddress>) -> Vec<RoutingRule> {
    // Built-in matchers come from constants and validated endpoint addresses, so
    // construction cannot fail; `expect` documents that.
    let mut rules = vec![
        RoutingRule::builtin(RuleMatcher::DnsPort, RuleAction::Capture, 0)
            .expect("the built-in DNS-capture rule is valid"),
    ];

    let mut bypasses: Vec<RuleMatcher> = Vec::new();
    bypasses.extend(active_endpoint.map(endpoint_matcher));
    bypasses.extend(LOCAL_BYPASS_CIDRS.iter().map(|c| {
        RuleMatcher::IpCidr(IpCidr::parse(c).expect("built-in CIDR constants are valid"))
    }));
    bypasses.extend(
        CAPTIVE_PORTAL_PROBE_SUFFIXES
            .iter()
            .map(|s| RuleMatcher::DomainSuffix((*s).to_string())),
    );

    // Precedence 0 is DNS capture's; the bypasses follow in order from 1.
    for (matcher, precedence) in bypasses.into_iter().zip(1u32..) {
        rules.push(
            RoutingRule::builtin(matcher, RuleAction::Bypass, precedence)
                .expect("built-in bypass rules are valid"),
        );
    }
    rules
}

/// The built-in rules plus, unless the person opted out, the encrypted-DNS block (T070, FR-025).
///
/// The block sits between the bypasses and every user rule (`doh_block::FIRST_PRECEDENCE`), and is
/// kept out of [`builtin_rules`] on purpose: that set is what is **required** to be present, and the
/// block is removable by the one documented opt-out.
pub fn builtin_rules_for(
    active_endpoint: Option<&EndpointAddress>,
    policy: crate::doh_block::Policy,
) -> Vec<RoutingRule> {
    let mut rules = builtin_rules(active_endpoint);
    rules.extend(crate::doh_block::blocking_rules(policy));
    rules
}

/// The rule set a tunnel to `endpoint` is generated from: `rules` (the set held while disconnected) plus
/// the built-in bypass of the active endpoint, which mirrors the host route (R4, CC-05, data-model §4).
///
/// The endpoint bypass takes precedence 1, right after DNS capture, as [`builtin_rules`] places it; the
/// other built-in bypasses move down by one to make room, keeping their ids and their order. Nothing at
/// or beyond `doh_block::FIRST_PRECEDENCE` moves, so the encrypted-DNS block and every person's rule keep
/// their numbers. The result is checked as every rule set is; a set that already bypasses this endpoint
/// is returned as it is.
pub fn with_active_endpoint(
    rules: &[RoutingRule],
    endpoint: &EndpointAddress,
) -> Result<Vec<RoutingRule>, DomainError> {
    let matcher = endpoint_matcher(endpoint);
    if rules
        .iter()
        .any(|r| r.is_builtin() && r.action() == RuleAction::Bypass && r.matcher() == &matcher)
    {
        return Ok(rules.to_vec());
    }
    let first_after_bypasses = crate::doh_block::FIRST_PRECEDENCE;
    let mut out: Vec<RoutingRule> = rules
        .iter()
        .map(|r| {
            let moves = r.is_builtin()
                && !r.is_dns_capture()
                && (1..first_after_bypasses).contains(&r.precedence());
            if moves {
                r.renumbered(r.precedence() + 1)
            } else {
                r.clone()
            }
        })
        .collect();
    if out.iter().any(|r| {
        r.is_builtin() && r.action() == RuleAction::Bypass && r.precedence() >= first_after_bypasses
    }) {
        // The last bypass was pushed onto the block's first number: the layout no longer fits.
        return Err(DomainError::PrecedenceCollision(first_after_bypasses));
    }
    out.push(RoutingRule::builtin(matcher, RuleAction::Bypass, 1)?);
    crate::rule::validate_rule_set(&out)?;
    crate::rule::validate_dns_leak_protection(&out)?;
    validate_builtin_rules_present(&out, Some(endpoint))?;
    Ok(out)
}

/// A human-readable name for a built-in rule, for errors.
fn describe(rule: &RoutingRule) -> String {
    match rule.matcher() {
        RuleMatcher::EncryptedDnsPort => "encrypted DNS block (port 853)".to_string(),
        RuleMatcher::DnsPort => "DNS capture (port 53)".to_string(),
        RuleMatcher::IpCidr(c) => format!("bypass {c}"),
        RuleMatcher::Domain(d) => format!("bypass {d}"),
        RuleMatcher::DomainSuffix(d) => format!("bypass *.{d}"),
        RuleMatcher::Application(p) => format!("application {p}"),
    }
}

/// The matcher for the active-endpoint bypass. An IP-literal endpoint must bypass by
/// address (`/32` or `/128`): a domain matcher never matches raw IP traffic, so the
/// tunnel's own packets to an IP endpoint would slip past a `Domain` rule and loop.
fn endpoint_matcher(addr: &EndpointAddress) -> RuleMatcher {
    match addr.host().parse::<IpAddr>() {
        Ok(ip) => {
            let len = if ip.is_ipv4() { 32 } else { 128 };
            let cidr = IpCidr::parse(&format!("{ip}/{len}"))
                .expect("a parsed IP with a full-length prefix is a valid CIDR");
            RuleMatcher::IpCidr(cidr)
        }
        Err(_) => RuleMatcher::Domain(addr.host().to_string()),
    }
}

/// Reject a rule set that has lost any built-in rule. Every rule-set mutation runs this, so
/// a built-in cannot be deleted by replacing the set without it.
pub fn validate_builtin_rules_present(
    rules: &[RoutingRule],
    active_endpoint: Option<&EndpointAddress>,
) -> Result<(), DomainError> {
    for expected in builtin_rules(active_endpoint) {
        let present = rules.iter().any(|r| {
            r.is_builtin() && r.matcher() == expected.matcher() && r.action() == expected.action()
        });
        if !present {
            return Err(DomainError::BuiltinRuleMissing(describe(&expected)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{validate_dns_leak_protection, validate_rule_set, Reliability};

    fn bypass_matchers(rules: &[RoutingRule]) -> Vec<RuleMatcher> {
        rules
            .iter()
            .filter(|r| r.action() == RuleAction::Bypass)
            .map(|r| r.matcher().clone())
            .collect()
    }

    fn cidr(s: &str) -> RuleMatcher {
        RuleMatcher::IpCidr(IpCidr::parse(s).unwrap())
    }

    #[test]
    fn builtins_cover_every_required_class() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let rules = builtin_rules(Some(&addr));
        let bypass = bypass_matchers(&rules);

        assert!(rules.iter().all(RoutingRule::is_builtin));
        assert!(rules
            .iter()
            .all(|r| r.action() == RuleAction::Bypass || r.is_dns_capture()));
        // RFC1918, link-local, and multicast in both families.
        for range in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "fe80::/10",
            "ff00::/8",
        ] {
            assert!(bypass.contains(&cidr(range)), "missing {range}");
        }
        // The Windows probe domains, as suffixes.
        for suffix in ["msftconnecttest.com", "msftncsi.com"] {
            assert!(
                bypass.contains(&RuleMatcher::DomainSuffix(suffix.into())),
                "missing {suffix}"
            );
        }
        // The active endpoint.
        assert!(bypass.contains(&RuleMatcher::Domain("vpn.example".into())));
        // Internally valid.
        assert_eq!(validate_rule_set(&rules), Ok(()));
        assert_eq!(validate_dns_leak_protection(&rules), Ok(()));
    }

    #[test]
    fn only_windows_probe_hosts_are_bypassed() {
        let bypass = bypass_matchers(&builtin_rules(None));
        let domains: Vec<_> = bypass
            .iter()
            .filter(|m| matches!(m, RuleMatcher::Domain(_) | RuleMatcher::DomainSuffix(_)))
            .collect();
        assert_eq!(domains.len(), 2, "unexpected bypassed domains: {domains:?}");
    }

    #[test]
    fn unique_local_ipv6_is_not_bypassed_because_it_holds_the_fakeip_pool() {
        let bypass = bypass_matchers(&builtin_rules(None));
        let fakeip6 = IpCidr::parse("fc00::/18").unwrap();
        assert!(!bypass
            .iter()
            .any(|m| matches!(m, RuleMatcher::IpCidr(c) if c.overlaps(&fakeip6))));
    }

    #[test]
    fn an_ip_literal_endpoint_bypasses_by_address_not_domain() {
        let v4 = EndpointAddress::new("203.0.113.9", 51820).unwrap();
        let bypass = bypass_matchers(&builtin_rules(Some(&v4)));
        assert!(bypass.contains(&cidr("203.0.113.9/32")));
        assert!(!bypass.contains(&RuleMatcher::Domain("203.0.113.9".into())));

        let v6 = EndpointAddress::new("2001:db8::9", 51820).unwrap();
        assert!(bypass_matchers(&builtin_rules(Some(&v6))).contains(&cidr("2001:db8::9/128")));
    }

    #[test]
    fn the_endpoint_rule_outranks_the_local_and_portal_bypasses() {
        let addr = EndpointAddress::new("203.0.113.9", 51820).unwrap();
        let rules = builtin_rules(Some(&addr));
        let endpoint = rules
            .iter()
            .find(|r| r.matcher() == &cidr("203.0.113.9/32"))
            .unwrap();
        let others = rules
            .iter()
            .filter(|r| !r.is_dns_capture() && r.id() != endpoint.id());
        assert!(others
            .into_iter()
            .all(|r| r.precedence() > endpoint.precedence()));
    }

    #[test]
    fn builtins_without_an_endpoint_omit_the_endpoint_rule() {
        let with = builtin_rules(Some(&EndpointAddress::new("vpn.example", 443).unwrap()));
        let without = builtin_rules(None);
        assert_eq!(with.len(), without.len() + 1);
    }

    #[test]
    fn the_dns_capture_rule_is_built_in_and_wins_over_everything() {
        let rules = builtin_rules(Some(&EndpointAddress::new("vpn.example", 443).unwrap()));
        let capture: Vec<_> = rules.iter().filter(|r| r.is_dns_capture()).collect();
        assert_eq!(capture.len(), 1, "exactly one DNS-capture rule");
        let dns = capture[0];
        assert!(dns.is_builtin());
        assert_eq!(dns.reliability(), Reliability::Deterministic);
        assert_eq!(dns.precedence(), 0);
        assert_eq!(rules.iter().map(RoutingRule::precedence).min(), Some(0));
    }

    #[test]
    fn a_full_set_with_user_rules_keeps_its_builtins() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let mut rules = builtin_rules(Some(&addr));
        rules.push(
            RoutingRule::user(
                RuleMatcher::Domain("x.example".into()),
                RuleAction::Tunnel,
                1000,
            )
            .unwrap(),
        );
        assert_eq!(validate_builtin_rules_present(&rules, Some(&addr)), Ok(()));
    }

    #[test]
    fn removing_any_builtin_is_rejected() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let full = builtin_rules(Some(&addr));
        for missing in 0..full.len() {
            let mut rules = full.clone();
            let removed = rules.remove(missing);
            assert!(
                matches!(
                    validate_builtin_rules_present(&rules, Some(&addr)),
                    Err(DomainError::BuiltinRuleMissing(_))
                ),
                "removing {:?} must be rejected",
                removed.matcher()
            );
        }
    }

    #[test]
    fn a_user_rule_cannot_stand_in_for_a_builtin() {
        let mut rules = builtin_rules(None);
        let index = rules
            .iter()
            .position(|r| r.matcher() == &cidr("192.168.0.0/16"))
            .unwrap();
        let precedence = rules[index].precedence();
        rules[index] =
            RoutingRule::user(cidr("192.168.0.0/16"), RuleAction::Bypass, precedence).unwrap();
        assert!(matches!(
            validate_builtin_rules_present(&rules, None),
            Err(DomainError::BuiltinRuleMissing(_))
        ));
    }

    #[test]
    fn the_endpoint_rule_is_required_only_while_an_endpoint_is_active() {
        let addr = EndpointAddress::new("vpn.example", 443).unwrap();
        let disconnected = builtin_rules(None);
        assert_eq!(validate_builtin_rules_present(&disconnected, None), Ok(()));
        assert!(validate_builtin_rules_present(&disconnected, Some(&addr)).is_err());
    }

    // ---------------------------------------------------------------- the endpoint at connect time

    fn connected_set() -> (Vec<RoutingRule>, EndpointAddress) {
        let disconnected = builtin_rules_for(None, crate::doh_block::Policy::Block);
        let endpoint = EndpointAddress::new("203.0.113.10", 44443).unwrap();
        (
            with_active_endpoint(&disconnected, &endpoint).unwrap(),
            endpoint,
        )
    }

    /// The rule set a tunnel is generated from must carry the endpoint bypass that mirrors the host
    /// route (data-model §4, CC-05), right after DNS capture and ahead of everything else.
    #[test]
    fn a_connected_set_bypasses_the_endpoint_right_after_dns_capture() {
        let (rules, endpoint) = connected_set();
        let mut sorted: Vec<&RoutingRule> = rules.iter().collect();
        sorted.sort_by_key(|r| r.precedence());
        assert!(sorted[0].is_dns_capture());
        assert_eq!(sorted[1].matcher(), &cidr("203.0.113.10/32"));
        assert_eq!(sorted[1].action(), RuleAction::Bypass);
        assert!(sorted[1].is_builtin());
        assert_eq!(
            validate_builtin_rules_present(&rules, Some(&endpoint)),
            Ok(())
        );
        assert_eq!(validate_rule_set(&rules), Ok(()));
        assert_eq!(validate_dns_leak_protection(&rules), Ok(()));
    }

    /// Nothing else is lost, reordered or renamed: the other rules keep their ids and their order.
    #[test]
    fn adding_the_endpoint_keeps_every_other_rule_and_its_order() {
        let disconnected = builtin_rules_for(None, crate::doh_block::Policy::Block);
        let endpoint = EndpointAddress::new("203.0.113.10", 44443).unwrap();
        let rules = with_active_endpoint(&disconnected, &endpoint).unwrap();
        assert_eq!(rules.len(), disconnected.len() + 1);
        let order = |set: &[RoutingRule]| {
            let mut v: Vec<&RoutingRule> = set.iter().collect();
            v.sort_by_key(|r| r.precedence());
            v.into_iter().map(RoutingRule::id).collect::<Vec<_>>()
        };
        let before = order(&disconnected);
        let after: Vec<_> = order(&rules)
            .into_iter()
            .filter(|id| disconnected.iter().any(|r| r.id() == *id))
            .collect();
        assert_eq!(before, after);
        // The encrypted-DNS block stays where it was, ahead of every user rule.
        let block_before: Vec<u32> = disconnected
            .iter()
            .filter(|r| r.action() == RuleAction::Reject)
            .map(RoutingRule::precedence)
            .collect();
        let block_after: Vec<u32> = rules
            .iter()
            .filter(|r| r.action() == RuleAction::Reject)
            .map(RoutingRule::precedence)
            .collect();
        assert_eq!(block_before, block_after);
    }

    #[test]
    fn adding_the_same_endpoint_twice_changes_nothing() {
        let (rules, endpoint) = connected_set();
        assert_eq!(with_active_endpoint(&rules, &endpoint).unwrap(), rules);
    }

    /// A person's rule is never renumbered: only the built-in bypasses move to make room.
    #[test]
    fn a_users_rule_keeps_its_precedence() {
        let mut disconnected = builtin_rules_for(None, crate::doh_block::Policy::Block);
        let mine = RoutingRule::user(
            RuleMatcher::Domain("example.com".into()),
            RuleAction::Tunnel,
            crate::doh_block::USER_RULES_START,
        )
        .unwrap();
        disconnected.push(mine.clone());
        let endpoint = EndpointAddress::new("203.0.113.10", 44443).unwrap();
        let rules = with_active_endpoint(&disconnected, &endpoint).unwrap();
        assert!(rules.contains(&mine));
    }
}
