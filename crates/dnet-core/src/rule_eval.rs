//! T072 — which rule applies to a connection, and which rules can never apply (FR-021, FR-022, FR-023).
//!
//! The primary core does the routing at run time, from a configuration generated out of the rule set
//! (`dnet-config`). This is the same decision made in the open, as pure code, for three reasons: the
//! rule screen can show *which rule would apply* to a destination a person types; a rule that can never
//! apply can be pointed out when it is added; and `dnet-config`'s tests can check that the generated
//! configuration and this evaluator agree on every destination, so the two cannot drift (SC-017).
//!
//! # Precedence
//!
//! Rules are tried from the lowest `precedence` number up, and **the first that matches decides**
//! (data-model §4). Two rules never share a precedence (`rule::validate_rule_set` refuses it); if one
//! somehow did, the one listed first wins, so the answer is still the same every time.
//!
//! # What a rule matches against
//!
//! - **A name, when there is one (FR-021).** A connection to a destination that was asked for *by
//!   name* is routed by that name. The address it resolved to is not consulted: for a name the tunnel
//!   resolves (FakeIP), the address is a placeholder that means nothing outside the machine, and a
//!   range rule that matched it would be matching an accident. So an address-range rule does not
//!   apply to a named destination.
//! - **An address, when that is all there is.** A connection made straight to an address is matched
//!   by address-range rules, and domain rules do not apply to it.
//! - **An application, only when it is known (FR-023).** The program that made the connection is
//!   identified at connect time on a best-effort basis. When it is not known, application rules are
//!   skipped: a miss is never turned into a guess.
//! - **Port 53** is matched by the built-in DNS-capture rule, which always has the lowest precedence
//!   so that no other rule can route a plaintext query around the tunnel.
//!
//! Domain names are compared case-insensitively and without a trailing dot; a suffix rule matches the
//! name itself and every name beneath it, on label boundaries (`example.com` matches `a.example.com`,
//! not `badexample.com`). Application paths are compared the way Windows reports them: case-insensitive,
//! with either slash, and without a `\\?\` prefix.
//!
//! Pure logic: no I/O.

use std::net::IpAddr;

use crate::error::DomainError;
use crate::ids::RuleId;
use crate::rule::{IpCidr, Reliability, RoutingRule, RuleAction, RuleMatcher};

/// The transport of a connection, for the one rule that depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Where a connection is going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Asked for by name. The name decides; any address it resolved to is not consulted.
    Named(String),
    /// Made straight to an address.
    Address(IpAddr),
}

/// One connection, as far as a rule can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub destination: Destination,
    pub port: u16,
    pub transport: Transport,
    /// The program that made it, if it could be told (best-effort).
    pub application: Option<String>,
}

impl Flow {
    /// A connection to a name, over TCP port 443, from an unknown program.
    pub fn named(name: &str) -> Self {
        Self {
            destination: Destination::Named(name.to_owned()),
            port: 443,
            transport: Transport::Tcp,
            application: None,
        }
    }

    /// A connection straight to an address, over TCP port 443, from an unknown program.
    pub fn to_address(ip: IpAddr) -> Self {
        Self {
            destination: Destination::Address(ip),
            port: 443,
            transport: Transport::Tcp,
            application: None,
        }
    }

    #[must_use]
    pub fn from_application(mut self, path: &str) -> Self {
        self.application = Some(path.to_owned());
        self
    }

    #[must_use]
    pub fn on_port(mut self, port: u16, transport: Transport) -> Self {
        self.port = port;
        self.transport = transport;
        self
    }
}

/// What to do with a connection, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: RuleAction,
    /// The rule that decided. `None` when no rule matched and the default applied.
    pub rule: Option<RuleId>,
    /// How reliably that rule can be enforced: `BestEffort` for an application rule. `None` for the
    /// default.
    pub reliability: Option<Reliability>,
}

/// What happens to a connection no rule matches: through the tunnel. The product exists to carry
/// traffic, and a connection nobody made an exception for is not one to leave unprotected.
pub const DEFAULT_ACTION: RuleAction = RuleAction::Tunnel;

/// A domain name made comparable: ASCII lower case, no trailing dot. `None` for a name that cannot be
/// a DNS name (empty, a space or control character in it, an empty label, a label over 63 characters,
/// more than 253 characters, or anything outside ASCII: an internationalised name must be given in
/// its `xn--` form, because that is the form a connection arrives in).
pub fn normalize_domain(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    let ok = lower.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(lower)
}

/// Whether `domain` (already normalised) is `suffix` itself or a name beneath it.
fn under(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|head| head.ends_with('.'))
}

/// A Windows image path made comparable: lower case, forward slashes turned to back slashes, no
/// `\\?\` prefix, no trailing slash.
pub fn normalize_application(path: &str) -> String {
    let slashed = path.replace('/', "\\");
    slashed
        .strip_prefix(r"\\?\")
        .unwrap_or(&slashed)
        .trim_end_matches('\\')
        .to_lowercase()
}

/// An address with an IPv4-mapped IPv6 form (`::ffff:a.b.c.d`) turned into the IPv4 address it is,
/// so a rule for `10.0.0.0/8` cannot be sidestepped by writing the address the other way.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Whether `cidr` contains `ip`.
fn contains(cidr: &IpCidr, ip: IpAddr) -> bool {
    let host_bits = match canonical(ip) {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    // A host address is the /32 or /128 block of itself; blocks nest or are disjoint.
    IpCidr::parse(&format!("{}/{host_bits}", canonical(ip)))
        .is_ok_and(|host| cidr.overlaps(&host) && cidr.prefix_len() <= host_bits)
}

/// Whether `rule` matches `flow`.
fn matches(rule: &RoutingRule, flow: &Flow) -> bool {
    match rule.matcher() {
        RuleMatcher::DnsPort => flow.port == 53,
        RuleMatcher::EncryptedDnsPort => flow.port == crate::doh_block::ENCRYPTED_DNS_PORT,
        RuleMatcher::Domain(pattern) => match (&flow.destination, normalize_domain(pattern)) {
            (Destination::Named(name), Some(pattern)) => {
                normalize_domain(name).is_some_and(|name| name == pattern)
            }
            _ => false,
        },
        RuleMatcher::DomainSuffix(pattern) => {
            match (&flow.destination, normalize_domain(pattern)) {
                (Destination::Named(name), Some(pattern)) => {
                    normalize_domain(name).is_some_and(|name| under(&name, &pattern))
                }
                _ => false,
            }
        }
        RuleMatcher::IpCidr(cidr) => match &flow.destination {
            Destination::Address(ip) => contains(cidr, *ip),
            // A named destination is routed by its name, not by an address it may not even have.
            Destination::Named(_) => false,
        },
        RuleMatcher::Application(path) => flow
            .application
            .as_deref()
            .is_some_and(|app| normalize_application(app) == normalize_application(path)),
    }
}

/// The rules in the order they are tried: lowest precedence first, ties in the order given.
fn in_order(rules: &[RoutingRule]) -> Vec<&RoutingRule> {
    let mut ordered: Vec<&RoutingRule> = rules.iter().collect();
    ordered.sort_by_key(|r| r.precedence()); // stable: ties keep their order
    ordered
}

/// What to do with `flow` under `rules`.
pub fn evaluate(rules: &[RoutingRule], flow: &Flow) -> Decision {
    in_order(rules)
        .into_iter()
        .find(|rule| matches(rule, flow))
        .map_or(
            Decision {
                action: DEFAULT_ACTION,
                rule: None,
                reliability: None,
            },
            |rule| Decision {
                action: rule.action(),
                rule: Some(rule.id()),
                reliability: Some(rule.reliability()),
            },
        )
}

// ---------------------------------------------------------------- adding a rule

/// Whether a domain pattern can be written into a rule. The same test as [`normalize_domain`]: a
/// pattern that cannot be a name could never match one, and one with a space or a control character
/// in it has no business in a generated configuration.
pub fn check_domain_pattern(pattern: &str) -> Result<(), DomainError> {
    normalize_domain(pattern)
        .map(|_| ())
        .ok_or_else(|| DomainError::InvalidDomainPattern(pattern.chars().take(64).collect()))
}

// ---------------------------------------------------------------- rules that never apply

/// A rule that can never decide anything, because a rule that is tried first always catches what it
/// would have matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadowed {
    /// The rule that is never reached.
    pub rule: RuleId,
    /// The rule that catches everything it would match.
    pub by: RuleId,
}

/// Whether everything `inner` matches is also matched by `outer`.
fn covers(outer: &RuleMatcher, inner: &RuleMatcher) -> bool {
    use RuleMatcher::*;
    match (outer, inner) {
        (Domain(a), Domain(b)) => same_name(a, b),
        (DomainSuffix(a), Domain(b)) | (DomainSuffix(a), DomainSuffix(b)) => {
            match (normalize_domain(a), normalize_domain(b)) {
                (Some(a), Some(b)) => under(&b, &a),
                _ => false,
            }
        }
        (IpCidr(a), IpCidr(b)) => a.prefix_len() <= b.prefix_len() && a.overlaps(b),
        (Application(a), Application(b)) => normalize_application(a) == normalize_application(b),
        (DnsPort, DnsPort) => true,
        _ => false,
    }
}

fn same_name(a: &str, b: &str) -> bool {
    matches!((normalize_domain(a), normalize_domain(b)), (Some(a), Some(b)) if a == b)
}

/// The rules that are never reached. Not an error: a person may want a broad rule and a narrow one
/// beneath it for later. But the rule screen should say "this rule never applies, because that one
/// catches it first", since the alternative is a rule that looks as though it works.
pub fn shadowed(rules: &[RoutingRule]) -> Vec<Shadowed> {
    let ordered = in_order(rules);
    let mut found = Vec::new();
    for (i, rule) in ordered.iter().enumerate() {
        if let Some(winner) = ordered[..i]
            .iter()
            .find(|earlier| covers(earlier.matcher(), rule.matcher()))
        {
            found.push(Shadowed {
                rule: rule.id(),
                by: winner.id(),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin_rules::builtin_rules;
    use crate::rule::validate_rule_set;

    fn user(matcher: RuleMatcher, action: RuleAction, precedence: u32) -> RoutingRule {
        RoutingRule::user(matcher, action, precedence).unwrap()
    }
    fn suffix(s: &str) -> RuleMatcher {
        RuleMatcher::DomainSuffix(s.into())
    }
    fn domain(s: &str) -> RuleMatcher {
        RuleMatcher::Domain(s.into())
    }
    fn cidr(s: &str) -> RuleMatcher {
        RuleMatcher::IpCidr(IpCidr::parse(s).unwrap())
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ------------------------------------------------------------------ limits and shadowing, from mutation testing
    //
    // Each of these edges and kinds went untested: a rule's name could be accepted at one character too many or
    // too few, and a rule could be reported as never reached (or not) for the wrong kind of matcher.

    #[test]
    fn a_domain_name_is_a_name_only_within_the_dns_limits() {
        let label = |n: usize| "a".repeat(n);
        let name253 = format!("{}.{}.{}.{}", label(63), label(63), label(63), label(61));
        assert_eq!(name253.len(), 253);
        assert_eq!(
            normalize_domain(&name253).as_deref(),
            Some(name253.as_str())
        );
        assert_eq!(
            normalize_domain(&format!("{name253}.")).as_deref(),
            Some(name253.as_str()),
            "a trailing dot is dropped"
        );
        let name254 = format!("{}.{}.{}.{}", label(63), label(63), label(63), label(62));
        assert_eq!(normalize_domain(&name254), None, "254 characters");
        assert_eq!(
            normalize_domain(&label(63)).as_deref(),
            Some(label(63).as_str())
        );
        assert_eq!(normalize_domain(&label(64)), None, "a label of 64");
        for bad in [
            "",
            ".",
            "é.com",
            "ex ample.com",
            "a..b",
            "-a.com",
            "a-.com",
            "a.com\u{7}",
        ] {
            assert_eq!(normalize_domain(bad), None, "{bad:?}");
        }
        assert_eq!(
            normalize_domain("ExAmple.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
    }

    #[test]
    fn a_rule_covers_another_only_when_it_matches_everything_that_one_would() {
        let app = |s: &str| RuleMatcher::Application(s.into());
        // The same name, however it is written.
        assert!(covers(&domain("Example.com."), &domain("example.com")));
        assert!(!covers(&domain("example.com"), &domain("other.com")));
        assert!(!covers(&domain("example.com"), &domain("www.example.com")));
        // What is not a name covers nothing, not even itself.
        assert!(!covers(&domain("bad name"), &domain("bad name")));
        // The same program, however its path is spelled; a different program is not covered.
        assert!(covers(&app(r"C:\Tools\a.exe"), &app("c:/tools/a.exe")));
        assert!(!covers(&app(r"C:\Tools\a.exe"), &app(r"C:\Tools\b.exe")));
        // Kinds never cover each other, except that the DNS-port rule covers itself.
        assert!(covers(&RuleMatcher::DnsPort, &RuleMatcher::DnsPort));
        assert!(!covers(&RuleMatcher::DnsPort, &domain("example.com")));
        assert!(!covers(&domain("example.com"), &RuleMatcher::DnsPort));
        assert!(!covers(&app(r"C:\Tools\a.exe"), &domain("example.com")));
    }

    // ------------------------------------------------------------------ precedence

    #[test]
    fn nothing_matching_means_the_tunnel() {
        let d = evaluate(&[], &Flow::named("example.com"));
        assert_eq!(d.action, RuleAction::Tunnel);
        assert_eq!((d.rule, d.reliability), (None, None));
    }

    #[test]
    fn the_lowest_precedence_that_matches_decides() {
        let broad = user(suffix("example.com"), RuleAction::Bypass, 10);
        let narrow = user(domain("api.example.com"), RuleAction::Tunnel, 5);
        let rules = [broad.clone(), narrow.clone()];
        assert_eq!(
            evaluate(&rules, &Flow::named("api.example.com")).rule,
            Some(narrow.id())
        );
        assert_eq!(
            evaluate(&rules, &Flow::named("www.example.com")).rule,
            Some(broad.id())
        );
        // And the other way round: the broad rule outranks, so the narrow one is never reached.
        let rules = [
            user(suffix("example.com"), RuleAction::Bypass, 1),
            user(domain("api.example.com"), RuleAction::Tunnel, 2),
        ];
        assert_eq!(
            evaluate(&rules, &Flow::named("api.example.com")).action,
            RuleAction::Bypass
        );
    }

    #[test]
    fn the_order_the_rules_are_given_in_does_not_matter() {
        let a = user(suffix("example.com"), RuleAction::Bypass, 1);
        let b = user(domain("api.example.com"), RuleAction::Tunnel, 2);
        let flow = Flow::named("api.example.com");
        assert_eq!(
            evaluate(&[a.clone(), b.clone()], &flow),
            evaluate(&[b, a], &flow)
        );
    }

    // ------------------------------------------------------------------ names

    #[test]
    fn a_name_is_compared_without_case_or_trailing_dot() {
        let rules = [user(domain("Example.COM."), RuleAction::Bypass, 1)];
        for name in ["example.com", "EXAMPLE.com", "example.com."] {
            assert_eq!(
                evaluate(&rules, &Flow::named(name)).action,
                RuleAction::Bypass,
                "{name}"
            );
        }
    }

    #[test]
    fn a_suffix_matches_the_name_and_everything_beneath_it_on_label_boundaries() {
        let rules = [user(suffix("example.com"), RuleAction::Bypass, 1)];
        for yes in ["example.com", "a.example.com", "a.b.example.com"] {
            assert_eq!(
                evaluate(&rules, &Flow::named(yes)).action,
                RuleAction::Bypass,
                "{yes}"
            );
        }
        for no in [
            "badexample.com",
            "example.com.evil.net",
            "example.org",
            "com",
        ] {
            assert_eq!(
                evaluate(&rules, &Flow::named(no)).action,
                RuleAction::Tunnel,
                "{no}"
            );
        }
    }

    #[test]
    fn an_exact_domain_rule_does_not_match_its_subdomains() {
        let rules = [user(domain("example.com"), RuleAction::Bypass, 1)];
        assert_eq!(
            evaluate(&rules, &Flow::named("www.example.com")).action,
            RuleAction::Tunnel
        );
    }

    // ------------------------------------------------------------------ names versus addresses (FR-021)

    #[test]
    fn a_named_destination_is_never_matched_by_an_address_range() {
        // The address a name resolved to (a placeholder, when the tunnel resolves it) is not consulted.
        // A rule inside the placeholder pool is refused when it is made (T069), so the nearest a rule
        // can come is a range that contains it.
        let rules = [user(cidr("198.0.0.0/8"), RuleAction::Bypass, 1)];
        assert_eq!(
            evaluate(&rules, &Flow::named("example.com")).action,
            RuleAction::Tunnel
        );
    }

    #[test]
    fn an_address_is_matched_by_ranges_and_never_by_names() {
        let rules = [
            user(suffix("example.com"), RuleAction::Bypass, 1),
            user(cidr("10.0.0.0/8"), RuleAction::Bypass, 2),
        ];
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("10.9.9.9"))).action,
            RuleAction::Bypass
        );
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("93.184.216.34"))).action,
            RuleAction::Tunnel
        );
    }

    #[test]
    fn an_address_written_in_its_ipv4_mapped_form_is_still_that_address() {
        let rules = [user(cidr("10.0.0.0/8"), RuleAction::Bypass, 1)];
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("::ffff:10.1.2.3"))).action,
            RuleAction::Bypass,
            "a range cannot be sidestepped by writing the address the other way"
        );
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("::ffff:11.1.2.3"))).action,
            RuleAction::Tunnel
        );
    }

    #[test]
    fn a_v4_range_never_matches_a_v6_address_and_the_reverse() {
        let rules = [user(cidr("0.0.0.0/0"), RuleAction::Bypass, 1)];
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("2001:db8::1"))).action,
            RuleAction::Tunnel
        );
        let rules = [user(cidr("::/0"), RuleAction::Bypass, 1)];
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("192.0.2.1"))).action,
            RuleAction::Tunnel
        );
    }

    #[test]
    fn range_edges_are_exact() {
        let rules = [user(cidr("192.168.1.0/24"), RuleAction::Bypass, 1)];
        for (addr, want) in [
            ("192.168.1.0", RuleAction::Bypass),
            ("192.168.1.255", RuleAction::Bypass),
            ("192.168.0.255", RuleAction::Tunnel),
            ("192.168.2.0", RuleAction::Tunnel),
        ] {
            assert_eq!(
                evaluate(&rules, &Flow::to_address(ip(addr))).action,
                want,
                "{addr}"
            );
        }
    }

    // ------------------------------------------------------------------ applications (FR-023)

    #[test]
    fn an_application_rule_applies_only_when_the_program_is_known() {
        let rule = user(
            RuleMatcher::Application(r"C:\Apps\Chrome.exe".into()),
            RuleAction::Bypass,
            1,
        );
        let rules = [rule.clone()];
        let known = Flow::named("example.com").from_application(r"c:/apps/chrome.EXE");
        let d = evaluate(&rules, &known);
        assert_eq!((d.action, d.rule), (RuleAction::Bypass, Some(rule.id())));
        assert_eq!(
            d.reliability,
            Some(Reliability::BestEffort),
            "an application rule is always best-effort"
        );
        // Unknown program: the rule is skipped, never guessed at.
        assert_eq!(
            evaluate(&rules, &Flow::named("example.com")).action,
            RuleAction::Tunnel
        );
        // Another program.
        let other = Flow::named("example.com").from_application(r"C:\Apps\Firefox.exe");
        assert_eq!(evaluate(&rules, &other).action, RuleAction::Tunnel);
    }

    #[test]
    fn an_image_path_is_compared_the_way_windows_reports_it() {
        assert_eq!(
            normalize_application(r"\\?\C:\Apps\Chrome.exe"),
            normalize_application("c:/apps/chrome.exe")
        );
        assert_ne!(
            normalize_application(r"C:\Apps\a.exe"),
            normalize_application(r"C:\Other\a.exe")
        );
    }

    #[test]
    fn a_domain_rule_deterministically_outranks_a_best_effort_application_rule_only_by_precedence()
    {
        // Precedence decides, as for any rules: the person ordered them.
        let app = user(
            RuleMatcher::Application(r"C:\a.exe".into()),
            RuleAction::Bypass,
            1,
        );
        let dom = user(suffix("example.com"), RuleAction::Tunnel, 2);
        let flow = Flow::named("www.example.com").from_application(r"C:\a.exe");
        assert_eq!(
            evaluate(&[app.clone(), dom.clone()], &flow).rule,
            Some(app.id())
        );
        let app = user(
            RuleMatcher::Application(r"C:\a.exe".into()),
            RuleAction::Bypass,
            3,
        );
        assert_eq!(evaluate(&[app, dom.clone()], &flow).rule, Some(dom.id()));
    }

    // ------------------------------------------------------------------ the built-in rules

    #[test]
    fn port_53_is_captured_whatever_else_is_configured() {
        let mut rules = builtin_rules(None);
        rules.push(user(suffix("example.com"), RuleAction::Bypass, 5));
        rules.push(user(cidr("0.0.0.0/0"), RuleAction::Bypass, 6));
        for flow in [
            Flow::named("example.com").on_port(53, Transport::Udp),
            Flow::to_address(ip("8.8.8.8")).on_port(53, Transport::Tcp),
            Flow::to_address(ip("192.168.1.1")).on_port(53, Transport::Udp),
        ] {
            assert_eq!(
                evaluate(&rules, &flow).action,
                RuleAction::Capture,
                "{flow:?}"
            );
        }
    }

    #[test]
    fn local_addresses_stay_direct_by_default_and_the_portal_probe_host_too() {
        let rules = builtin_rules(None);
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("192.168.1.10"))).action,
            RuleAction::Bypass
        );
        assert_eq!(
            evaluate(&rules, &Flow::to_address(ip("fe80::1"))).action,
            RuleAction::Bypass
        );
        assert_eq!(
            evaluate(&rules, &Flow::named("www.msftconnecttest.com")).action,
            RuleAction::Bypass
        );
        assert_eq!(
            evaluate(&rules, &Flow::named("example.com")).action,
            RuleAction::Tunnel
        );
    }

    // ------------------------------------------------------------------ never-reached rules

    #[test]
    fn a_rule_caught_by_a_stronger_one_is_reported() {
        let broad = user(suffix("example.com"), RuleAction::Bypass, 1);
        let narrow = user(domain("api.example.com"), RuleAction::Tunnel, 2);
        let rules = [narrow.clone(), broad.clone()];
        assert_eq!(
            shadowed(&rules),
            [Shadowed {
                rule: narrow.id(),
                by: broad.id()
            }]
        );
    }

    #[test]
    fn a_narrow_rule_that_outranks_a_broad_one_is_not_shadowed() {
        let narrow = user(domain("api.example.com"), RuleAction::Tunnel, 1);
        let broad = user(suffix("example.com"), RuleAction::Bypass, 2);
        assert_eq!(shadowed(&[narrow, broad]), []);
    }

    #[test]
    fn nested_ranges_and_repeated_rules_are_found_too() {
        let wide = user(cidr("10.0.0.0/8"), RuleAction::Bypass, 1);
        let inner = user(cidr("10.1.0.0/16"), RuleAction::Tunnel, 2);
        let again = user(suffix("a.com"), RuleAction::Bypass, 3);
        let twice = user(suffix("a.com"), RuleAction::Tunnel, 4);
        let found = shadowed(&[wide.clone(), inner.clone(), again.clone(), twice.clone()]);
        assert_eq!(
            found,
            [
                Shadowed {
                    rule: inner.id(),
                    by: wide.id()
                },
                Shadowed {
                    rule: twice.id(),
                    by: again.id()
                },
            ]
        );
    }

    #[test]
    fn different_kinds_and_different_families_never_shadow_each_other() {
        let rules = [
            user(suffix("example.com"), RuleAction::Bypass, 1),
            user(cidr("10.0.0.0/8"), RuleAction::Bypass, 2),
            user(cidr("fe80::/10"), RuleAction::Bypass, 3),
            user(
                RuleMatcher::Application("a.exe".into()),
                RuleAction::Bypass,
                4,
            ),
        ];
        assert_eq!(shadowed(&rules), []);
    }

    #[test]
    fn the_builtin_set_has_no_shadowed_rules() {
        assert_eq!(shadowed(&builtin_rules(None)), []);
    }

    // ------------------------------------------------------------------ adding a rule

    #[test]
    fn a_pattern_that_cannot_be_a_name_is_refused() {
        for bad in [
            "",
            " ",
            "a b.com",
            "a..com",
            "-",
            "-a.com",
            "a-.com",
            "bad\u{1}.com",
            "ünïcode.com",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(check_domain_pattern(bad).is_err(), "{bad:?}");
        }
        for good in [
            "example.com",
            "Example.COM.",
            "xn--nxasmq6b.example",
            "a-b_c.d.e",
            "localhost",
        ] {
            assert!(check_domain_pattern(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn a_valid_rule_set_has_no_collision_and_evaluation_is_total() {
        let rules = builtin_rules(None);
        assert!(validate_rule_set(&rules).is_ok());
        // Any flow gets an answer.
        for flow in [
            Flow::named("x.test"),
            Flow::to_address(ip("1.1.1.1")),
            Flow::named(".."),
        ] {
            let _ = evaluate(&rules, &flow);
        }
    }
}
