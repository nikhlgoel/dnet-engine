//! T070 — encrypted-DNS endpoints are blocked so applications fall back to the system resolver (FR-025).
//!
//! Domain rules only work if the product sees the name a program asks for. A browser using DNS over
//! HTTPS asks a resolver of its own over an encrypted connection: the product sees a connection to
//! `dns.example`, not the names inside it, and every destination rule is silently bypassed for that
//! program. FR-025 gives two ways out and picks one as the default: **make such programs fall back to
//! the system resolver**, where the tunnel's own resolver answers and the names are visible.
//!
//! The mechanism is the one browsers document for exactly this case: when their encrypted resolver
//! cannot be reached, they use the system's. So the well-known resolvers' names are made unreachable
//! (a refused lookup and a refused connection), and port 853 (DNS over TLS and QUIC) is refused.
//!
//! # What this cannot do, said plainly
//!
//! - It is a **list of names**. A resolver not on it, or one reached by a bare address, is not blocked,
//!   and a program using it keeps bypassing destination rules. The list is the browsers' own bundled
//!   resolvers, which is what nearly every program using DoH uses; it is not a guarantee.
//! - It is **overridden only by the person**, once, with the consequence stated (`doh_consent`).
//!   A rule the person adds cannot undo it: these rules outrank every user rule.
//! - Firefox's documented "canary" name is included, so that it turns its own encrypted resolver off
//!   rather than being left to find the block by failing.
//!
//! The rules are built in but **not non-removable** like the local-network and portal bypasses: opting
//! out removes them, which is the point of the opt-out (FR-025a).
//!
//! Pure logic: no I/O.

use crate::error::DomainError;
use crate::rule::{RoutingRule, RuleAction, RuleMatcher};

/// Port used by DNS over TLS (TCP) and over QUIC (UDP).
pub const ENCRYPTED_DNS_PORT: u16 = 853;

/// Encrypted resolvers programs ship with, as suffixes (a resolver also answers under subdomains).
///
/// Source: the resolver lists bundled in current Chromium and Firefox and the providers' own
/// documentation, as of 2026-10. Best-effort and meant to be extended: a name that is missing here is
/// a resolver that is **not** blocked.
pub const ENCRYPTED_RESOLVER_SUFFIXES: &[&str] = &[
    // Firefox's canary: answering it as "no such name" makes Firefox switch its encrypted DNS off.
    "use-application-dns.net",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.cloudflare.com",
    "dns.google",
    "dns.quad9.net",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.mullvad.net",
    "doh.dns.sb",
    "dns.sb",
];

/// Where the blocking rules sit in precedence: after every built-in bypass (which use the numbers
/// below this) and before every user rule (which start at [`USER_RULES_START`]).
pub const FIRST_PRECEDENCE: u32 = 100;

/// The lowest precedence a person's rule may have while the block is in force.
pub const USER_RULES_START: u32 = 200;

/// A person's rules must not outrank the block, or a rule for `dns.google` set to "bypass" would
/// quietly undo it. With no block in the set (the person opted out) there is nothing to protect.
pub fn validate_block_outranks_user_rules(rules: &[RoutingRule]) -> Result<(), DomainError> {
    let blocking = rules.iter().any(|r| r.action() == RuleAction::Reject);
    if !blocking {
        return Ok(());
    }
    match rules
        .iter()
        .filter(|r| !r.is_builtin() && r.precedence() < USER_RULES_START)
        .map(RoutingRule::precedence)
        .min()
    {
        Some(low) => Err(DomainError::OutranksEncryptedDnsBlock(
            low,
            USER_RULES_START,
        )),
        None => Ok(()),
    }
}

/// Whether encrypted DNS is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// The default: programs fall back to the system resolver (FR-025).
    #[default]
    Block,
    /// The person opted out, with the consequence stated (`doh_consent`).
    Allow,
}

/// Whether `rules` carries exactly the blocking that `policy` calls for: every blocking rule while
/// blocking, none once the person has opted out. The rule list cannot be used to lift the block
/// (only the opt-out does that), and an opt-out cannot leave half of it behind.
pub fn validate_block_matches_policy(
    rules: &[RoutingRule],
    policy: Policy,
) -> Result<(), DomainError> {
    let present = |wanted: &RoutingRule| {
        rules.iter().any(|r| {
            r.is_builtin() && r.matcher() == wanted.matcher() && r.action() == wanted.action()
        })
    };
    match policy {
        Policy::Block => match blocking_rules(Policy::Block).iter().find(|w| !present(w)) {
            Some(missing) => Err(DomainError::BuiltinRuleMissing(match missing.matcher() {
                RuleMatcher::DomainSuffix(d) => format!("block *.{d}"),
                _ => "block encrypted DNS (port 853)".to_owned(),
            })),
            None => Ok(()),
        },
        Policy::Allow => match rules.iter().find(|r| r.action() == RuleAction::Reject) {
            Some(_) => Err(DomainError::EncryptedDnsBlockLeftBehind),
            None => Ok(()),
        },
    }
}

/// The rules that implement `policy`: refuse each resolver's name and refuse port 853, or nothing.
pub fn blocking_rules(policy: Policy) -> Vec<RoutingRule> {
    if policy == Policy::Allow {
        return Vec::new();
    }
    ENCRYPTED_RESOLVER_SUFFIXES
        .iter()
        .map(|suffix| RuleMatcher::DomainSuffix((*suffix).to_owned()))
        .chain(std::iter::once(RuleMatcher::EncryptedDnsPort))
        .zip(FIRST_PRECEDENCE..)
        .map(|(matcher, precedence)| {
            RoutingRule::builtin(matcher, RuleAction::Reject, precedence)
                .expect("the built-in encrypted-DNS rules are valid")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::validate_rule_set;
    use crate::rule_eval::{evaluate, normalize_domain, Flow, Transport};

    #[test]
    fn every_listed_resolver_is_a_valid_distinct_name() {
        let mut seen = std::collections::HashSet::new();
        for suffix in ENCRYPTED_RESOLVER_SUFFIXES {
            let name = normalize_domain(suffix).unwrap_or_else(|| panic!("{suffix}"));
            assert_eq!(&name, suffix, "written in the normal form");
            assert!(seen.insert(name), "{suffix} listed twice");
        }
    }

    #[test]
    fn blocking_refuses_each_resolver_and_the_encrypted_dns_port() {
        let rules = blocking_rules(Policy::Block);
        assert_eq!(rules.len(), ENCRYPTED_RESOLVER_SUFFIXES.len() + 1);
        assert!(rules.iter().all(|r| r.action() == RuleAction::Reject));
        assert!(rules.iter().all(RoutingRule::is_builtin));
        for suffix in ENCRYPTED_RESOLVER_SUFFIXES {
            for name in [(*suffix).to_owned(), format!("host.{suffix}")] {
                assert_eq!(
                    evaluate(&rules, &Flow::named(&name)).action,
                    RuleAction::Reject,
                    "{name}"
                );
            }
        }
        for transport in [Transport::Tcp, Transport::Udp] {
            let flow = Flow::named("anything.example").on_port(ENCRYPTED_DNS_PORT, transport);
            assert_eq!(evaluate(&rules, &flow).action, RuleAction::Reject);
        }
    }

    #[test]
    fn allowing_removes_every_rule() {
        assert!(blocking_rules(Policy::Allow).is_empty());
    }

    #[test]
    fn the_default_is_to_block() {
        assert_eq!(Policy::default(), Policy::Block);
    }

    #[test]
    fn ordinary_names_are_untouched() {
        let rules = blocking_rules(Policy::Block);
        for name in [
            "example.com",
            "notdns.google.evil.test",
            "dnsgoogle",
            "cloudflare.com",
        ] {
            assert_eq!(
                evaluate(&rules, &Flow::named(name)).action,
                RuleAction::Tunnel,
                "{name}"
            );
        }
    }

    #[test]
    fn the_rules_are_a_valid_set_with_distinct_precedences_in_their_own_band() {
        let rules = blocking_rules(Policy::Block);
        assert_eq!(validate_rule_set(&rules), Ok(()));
        let min = rules.iter().map(RoutingRule::precedence).min().unwrap();
        let max = rules.iter().map(RoutingRule::precedence).max().unwrap();
        assert_eq!(min, FIRST_PRECEDENCE);
        assert!(max < USER_RULES_START, "{max}");
    }

    #[test]
    fn a_rule_the_person_adds_cannot_undo_the_block() {
        // The blocking rules outrank every user rule, so only the opt-out lifts them.
        let mut rules = blocking_rules(Policy::Block);
        let user = RoutingRule::user(
            RuleMatcher::DomainSuffix("dns.google".into()),
            RuleAction::Tunnel,
            USER_RULES_START,
        )
        .unwrap();
        rules.push(user);
        assert_eq!(validate_block_outranks_user_rules(&rules), Ok(()));
        assert_eq!(
            evaluate(&rules, &Flow::named("dns.google")).action,
            RuleAction::Reject
        );
    }

    #[test]
    fn a_user_rule_that_would_outrank_the_block_is_refused() {
        for precedence in [50, 150, USER_RULES_START - 1] {
            let mut rules = crate::builtin_rules::builtin_rules_for(None, Policy::Block);
            rules.push(
                RoutingRule::user(
                    RuleMatcher::DomainSuffix("dns.google".into()),
                    RuleAction::Bypass,
                    precedence,
                )
                .unwrap(),
            );
            assert_eq!(
                validate_block_outranks_user_rules(&rules),
                Err(DomainError::OutranksEncryptedDnsBlock(
                    precedence,
                    USER_RULES_START
                )),
                "{precedence}"
            );
        }
    }

    #[test]
    fn without_the_block_a_user_rule_may_have_any_precedence() {
        // The person opted out: nothing to protect, so nothing to refuse.
        let mut rules = crate::builtin_rules::builtin_rules_for(None, Policy::Allow);
        rules.push(
            RoutingRule::user(
                RuleMatcher::DomainSuffix("dns.google".into()),
                RuleAction::Bypass,
                50,
            )
            .unwrap(),
        );
        assert_eq!(validate_block_outranks_user_rules(&rules), Ok(()));
    }

    #[test]
    fn the_set_must_carry_exactly_the_blocking_the_policy_calls_for() {
        use crate::builtin_rules::builtin_rules_for;
        let blocked = builtin_rules_for(None, Policy::Block);
        let open = builtin_rules_for(None, Policy::Allow);
        assert_eq!(
            validate_block_matches_policy(&blocked, Policy::Block),
            Ok(())
        );
        assert_eq!(validate_block_matches_policy(&open, Policy::Allow), Ok(()));
        // Every single blocking rule is required while blocking.
        for i in 0..blocked.len() {
            if blocked[i].action() != RuleAction::Reject {
                continue;
            }
            let mut fewer = blocked.clone();
            fewer.remove(i);
            assert!(
                matches!(
                    validate_block_matches_policy(&fewer, Policy::Block),
                    Err(DomainError::BuiltinRuleMissing(_))
                ),
                "{:?}",
                blocked[i].matcher()
            );
        }
        // And none may stay once the person has opted out.
        assert_eq!(
            validate_block_matches_policy(&blocked, Policy::Allow),
            Err(DomainError::EncryptedDnsBlockLeftBehind)
        );
        // The block with the opt-out missing is not the open set either.
        assert!(validate_block_matches_policy(&open, Policy::Block).is_err());
    }

    #[test]
    fn only_the_product_may_refuse_traffic() {
        assert_eq!(
            RoutingRule::user(
                RuleMatcher::DomainSuffix("example.com".into()),
                RuleAction::Reject,
                500
            ),
            Err(DomainError::RejectIsBuiltinOnly)
        );
    }

    #[test]
    fn port_853_is_only_ever_refused() {
        for action in [RuleAction::Tunnel, RuleAction::Bypass, RuleAction::Capture] {
            assert_eq!(
                RoutingRule::builtin(RuleMatcher::EncryptedDnsPort, action, 1),
                Err(DomainError::EncryptedDnsPortRequiresReject),
                "{action:?}"
            );
        }
    }
}
