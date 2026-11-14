// SPDX-License-Identifier: GPL-3.0-or-later
//! T073 — the generated configuration and the rule evaluator agree on every destination (SC-017).
//!
//! The primary core routes at run time from a configuration generated out of the rule set; the product
//! predicts and explains routing with `dnet_core::rule_eval`. If the two ever disagree, the interface
//! says one thing and the machine does another, and a destination a person marked "bypass" could go
//! through the tunnel (or the reverse). The first is a broken promise; the second is a leak.
//!
//! So this takes the *generated* route rules, reads them the way the core does (the first rule whose
//! every condition holds decides; `direct` is a bypass, `proxy` is the tunnel, `hijack-dns` is capture),
//! and demands the same answer as the evaluator for every destination, over generated rule sets.
//!
//! What is assumed about the core, stated so it can be checked against it in the lab (T079): a `domain`
//! condition is an exact, case-insensitive match; a `domain_suffix` matches the name and everything
//! beneath it; an `ip_cidr` condition is tested against a destination that was given as an address, not
//! one that was asked for by name (a name routed through FakeIP is decided by its name). Application
//! rules are compared exactly as written, so they are left out of the equality and checked separately.

use std::net::IpAddr;

use dnet_config::primary::{route_rules, RouteRule};
use dnet_core::builtin_rules::builtin_rules_for;
use dnet_core::doh_block::{Policy, ENCRYPTED_DNS_PORT};
use dnet_core::rule::{IpCidr, RoutingRule, RuleAction, RuleMatcher};
use dnet_core::rule_eval::{evaluate, normalize_domain, Destination, Flow, Transport};
use proptest::prelude::*;

/// How the core reads one generated route rule against a connection.
fn rule_holds(rule: &RouteRule, flow: &Flow) -> bool {
    let name = match &flow.destination {
        Destination::Named(n) => Some(n.to_ascii_lowercase()),
        Destination::Address(_) => None,
    };
    let any_of = |wanted: &[String], test: &dyn Fn(&str) -> bool| {
        wanted.is_empty() || wanted.iter().any(|w| test(w))
    };
    any_of(&rule.domain, &|d| {
        name.as_deref() == Some(&d.to_ascii_lowercase())
    }) && any_of(&rule.domain_suffix, &|s| {
        let s = s.to_ascii_lowercase();
        name.as_deref()
            .is_some_and(|n| n == s || n.ends_with(&format!(".{s}")))
    }) && any_of(
        &rule.ip_cidr,
        &|c| match (&flow.destination, IpCidr::parse(c)) {
            (Destination::Address(ip), Ok(cidr)) => {
                let host = IpCidr::parse(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
                    .unwrap();
                cidr.overlaps(&host)
            }
            _ => false,
        },
    ) && (rule.process_path.is_empty()
        || rule
            .process_path
            .iter()
            .any(|p| flow.application.as_deref() == Some(p.as_str())))
        && (rule.port.is_empty() || rule.port.contains(&flow.port))
}

/// What the core would do with `flow`: the first generated rule that holds, else the final outbound.
fn core_decision(rules: &[RouteRule], flow: &Flow) -> RuleAction {
    for rule in rules {
        if rule_holds(rule, flow) {
            return match (rule.action, rule.outbound.as_deref()) {
                ("hijack-dns", _) => RuleAction::Capture,
                ("reject", _) => RuleAction::Reject,
                (_, Some("direct")) => RuleAction::Bypass,
                _ => RuleAction::Tunnel,
            };
        }
    }
    RuleAction::Tunnel // `final` is the tunnel
}

// ------------------------------------------------------------------ the pools

const NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "a.b.example.com",
    "badexample.com",
    "example.org",
    "intranet.corp.test",
    "www.msftconnecttest.com",
    "api.service.test",
    "dns.google",
    "host.cloudflare-dns.com",
    "use-application-dns.net",
];

const PATTERNS: &[&str] = &[
    "example.com",
    "Example.COM",
    "example.com.",
    "www.example.com",
    "corp.test",
    "service.test",
    "msftconnecttest.com",
];

const CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "10.1.0.0/16",
    "192.168.0.0/16",
    "203.0.113.0/24",
    "0.0.0.0/0",
    "2001:db8::/32",
    "fe80::/10",
];

const ADDRESSES: &[&str] = &[
    "10.1.2.3",
    "10.200.0.1",
    "192.168.1.1",
    "203.0.113.9",
    "93.184.216.34",
    "2001:db8::5",
    "fe80::1",
    "2606:4700::1",
];

fn matcher() -> impl Strategy<Value = RuleMatcher> {
    prop_oneof![
        prop::sample::select(PATTERNS).prop_map(|p| RuleMatcher::Domain(p.into())),
        prop::sample::select(PATTERNS).prop_map(|p| RuleMatcher::DomainSuffix(p.into())),
        prop::sample::select(CIDRS).prop_map(|c| RuleMatcher::IpCidr(IpCidr::parse(c).unwrap())),
    ]
}

fn action() -> impl Strategy<Value = RuleAction> {
    prop::sample::select(vec![RuleAction::Tunnel, RuleAction::Bypass])
}

/// User rules with distinct precedences, placed among the built-in ones.
fn rule_set() -> impl Strategy<Value = Vec<RoutingRule>> {
    prop::collection::vec((matcher(), action()), 0..7).prop_map(|specs| {
        let mut rules = builtin_rules_for(None, Policy::Block);
        // Built-ins hold the low numbers; user rules take distinct numbers above them.
        let floor = rules.iter().map(RoutingRule::precedence).max().unwrap_or(0) + 1;
        for (i, (matcher, action)) in specs.into_iter().enumerate() {
            rules.push(RoutingRule::user(matcher, action, floor + i as u32).unwrap());
        }
        rules
    })
}

fn flow() -> impl Strategy<Value = Flow> {
    let port = prop::sample::select(vec![
        (443u16, Transport::Tcp),
        (80, Transport::Tcp),
        (53, Transport::Udp),
        (53, Transport::Tcp),
        (ENCRYPTED_DNS_PORT, Transport::Tcp),
        (ENCRYPTED_DNS_PORT, Transport::Udp),
    ]);
    prop_oneof![
        (prop::sample::select(NAMES), port.clone())
            .prop_map(|(n, (p, t))| Flow::named(n).on_port(p, t)),
        (prop::sample::select(ADDRESSES), port)
            .prop_map(|(a, (p, t))| Flow::to_address(a.parse::<IpAddr>().unwrap()).on_port(p, t)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// The agreement, over generated rule sets and destinations.
    #[test]
    fn the_generated_configuration_routes_every_destination_the_way_the_evaluator_says(
        rules in rule_set(),
        flow in flow(),
    ) {
        let generated = route_rules(&rules);
        prop_assert_eq!(
            core_decision(&generated, &flow),
            evaluate(&rules, &flow).action,
            "rules {:?}\nflow {:?}", rules, flow
        );
    }

    /// SC-017, stated directly: whatever the evaluator calls a bypass, the generated configuration
    /// sends to the unbound `direct` outbound and never to the tunnel.
    #[test]
    fn a_destination_that_matches_a_bypass_rule_never_reaches_the_tunnel(
        rules in rule_set(),
        flow in flow(),
    ) {
        if evaluate(&rules, &flow).action == RuleAction::Bypass {
            prop_assert_eq!(core_decision(&route_rules(&rules), &flow), RuleAction::Bypass);
        }
    }

    /// No rule the person adds can undo the encrypted-DNS block (T070). What the built-ins alone refuse
    /// stays refused whatever user rules are added, in the evaluator and in the generated configuration.
    /// (Things that outrank the block by design, such as the local network and plaintext DNS, are
    /// decided by the built-ins alone and so are not claimed here.)
    #[test]
    fn no_user_rule_can_lift_what_the_builtins_refuse(rules in rule_set(), flow in flow()) {
        let builtins = builtin_rules_for(None, Policy::Block);
        if evaluate(&builtins, &flow).action == RuleAction::Reject {
            prop_assert_eq!(evaluate(&rules, &flow).action, RuleAction::Reject);
            prop_assert_eq!(core_decision(&route_rules(&rules), &flow), RuleAction::Reject);
        }
    }

    /// The claim above is not vacuous: resolver names and port 853 are in fact refused by the built-ins.
    #[test]
    fn the_builtins_do_refuse_resolver_names_and_the_encrypted_dns_port(
        name in prop::sample::select(vec!["dns.google", "host.cloudflare-dns.com", "use-application-dns.net"]),
    ) {
        let builtins = builtin_rules_for(None, Policy::Block);
        prop_assert_eq!(evaluate(&builtins, &Flow::named(name)).action, RuleAction::Reject);
        let on_853 = Flow::named("elsewhere.example").on_port(ENCRYPTED_DNS_PORT, Transport::Tcp);
        prop_assert_eq!(evaluate(&builtins, &on_853).action, RuleAction::Reject);
    }

    /// A plaintext DNS query is always captured: no rule the person adds can send it anywhere else.
    #[test]
    fn port_53_is_always_captured(rules in rule_set(), flow in flow()) {
        let flow = flow.on_port(53, Transport::Udp);
        prop_assert_eq!(core_decision(&route_rules(&rules), &flow), RuleAction::Capture);
    }
}

#[test]
fn an_application_rule_is_written_exactly_as_given_and_skipped_when_the_program_is_unknown() {
    let path = r"C:\Program Files\App\app.exe";
    let rule = RoutingRule::user(
        RuleMatcher::Application(path.into()),
        RuleAction::Bypass,
        100,
    )
    .unwrap();
    let generated = route_rules(std::slice::from_ref(&rule));
    assert_eq!(generated[0].process_path, [path]);
    let flow = Flow::named("example.com").from_application(path);
    assert_eq!(
        evaluate(std::slice::from_ref(&rule), &flow).action,
        RuleAction::Bypass
    );
    assert_eq!(core_decision(&generated, &flow), RuleAction::Bypass);
    // Not known: the evaluator skips the rule, and so does the core (no process was attributed).
    let unknown = Flow::named("example.com");
    assert_eq!(
        evaluate(std::slice::from_ref(&rule), &unknown).action,
        RuleAction::Tunnel
    );
    assert_eq!(core_decision(&generated, &unknown), RuleAction::Tunnel);
}

#[test]
fn patterns_are_written_in_the_form_a_connection_arrives_in() {
    // `Example.COM.` and `example.com` are the same name; the core compares names as it is given them,
    // so the configuration carries the normalised form.
    let rule = RoutingRule::user(
        RuleMatcher::Domain("Example.COM.".into()),
        RuleAction::Bypass,
        100,
    )
    .unwrap();
    let generated = route_rules(std::slice::from_ref(&rule));
    assert_eq!(generated[0].domain, ["example.com"]);
    assert_eq!(
        normalize_domain("Example.COM."),
        Some("example.com".to_owned())
    );
}
