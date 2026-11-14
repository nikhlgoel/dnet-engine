// SPDX-License-Identifier: GPL-3.0-or-later
//! T047 — primary-core configuration generation (CC-01, CC-02, CC-05..CC-09).
//!
//! Turns the active profile, endpoint, and routing rules into the primary core's JSON
//! configuration, deterministically. The generation is a pure function of its input, so
//! identical domain state yields byte-identical output (CC-09).
//!
//! **Schema.** Targets the pinned primary core (v1.14.0, ADR-0004), verified against its
//! documentation at the pinned commit: typed DNS servers (the legacy server format was
//! removed in 1.14), rule actions instead of the removed `dns`/`block` outbounds (1.13),
//! and the merged TUN `address` field (1.12). The DNS-capture rule is realised as the
//! native `hijack-dns` action, and `route.auto_detect_interface` is always on: it binds
//! the core's own outbounds to the physical NIC so `direct` (bypass) traffic cannot
//! re-enter the TUN. Profile A overrides it with an explicit `bind_interface`.

use serde::Serialize;

use dnet_core::profile::{ConnectionProfile, ProfileKind};
use dnet_core::rule::{RoutingRule, RuleAction, RuleMatcher};

use crate::bind::DirectBoundOutbound;
use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;
use crate::hysteria2::{hysteria2_outbound, Hysteria2Outbound, Hysteria2Transport};
use crate::reality::{reality_outbound, RealityTransport, VlessOutbound};
use crate::session::{Experimental, SelectorOutbound, SessionEndpoint};

/// FakeIP pools (CC-02, research.md R3). Documented defaults. A tunnel hands out addresses from only
/// one half of each (see [`FakeIpHalf`]); these are the whole pools, which nothing else may use.
pub const FAKEIP_INET4: &str = dnet_core::fakeip::INET4_POOL;
pub const FAKEIP_INET6: &str = dnet_core::fakeip::INET6_POOL;

/// Which half of the FakeIP pools one tunnel hands out (T131, CC-02).
///
/// Every tunnel starts handing out addresses from the bottom of its pool, so an address a program
/// remembered from the last session can belong to a **different name** in the next: over plain HTTP the
/// program would reach the wrong host, and the name it meant is revealed to it. Alternating between the
/// two halves per tunnel start turns that into the harmless case, an address the core does not know and
/// refuses. The choice is an input, not read from a clock here, so the output stays a pure function of
/// its input (CC-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeIpHalf {
    Low,
    High,
}

impl FakeIpHalf {
    /// `198.18.0.0/16` or `198.19.0.0/16`.
    pub const fn inet4(self) -> &'static str {
        match self {
            FakeIpHalf::Low => "198.18.0.0/16",
            FakeIpHalf::High => "198.19.0.0/16",
        }
    }

    /// `fc00::/19` or `fc00:2000::/19`.
    pub const fn inet6(self) -> &'static str {
        match self {
            FakeIpHalf::Low => "fc00::/19",
            FakeIpHalf::High => "fc00:2000::/19",
        }
    }

    pub const fn other(self) -> Self {
        match self {
            FakeIpHalf::Low => FakeIpHalf::High,
            FakeIpHalf::High => FakeIpHalf::Low,
        }
    }
}

/// Hands out the half for each tunnel start, alternating, starting with `first`.
#[derive(Debug)]
pub struct FakeIpRotation(std::sync::atomic::AtomicBool);

impl FakeIpRotation {
    pub fn new(first: FakeIpHalf) -> Self {
        Self(std::sync::atomic::AtomicBool::new(
            first == FakeIpHalf::High,
        ))
    }

    /// The half for this start; the next call returns the other.
    pub fn take(&self) -> FakeIpHalf {
        // `fetch_xor` returns the previous value and flips it, so concurrent starts never share one.
        if self.0.fetch_xor(true, std::sync::atomic::Ordering::SeqCst) {
            FakeIpHalf::High
        } else {
            FakeIpHalf::Low
        }
    }
}

const TUN_TAG: &str = "tun-in";
/// The TUN adapter name the primary core creates.
pub const TUN_INTERFACE: &str = "dnet-tun0";
/// Deliberately outside the FakeIP pool, so a fake address can never collide with the
/// TUN's own address.
const TUN_ADDRESS: &str = "172.19.0.1/30";

pub(crate) const PROXY_TAG: &str = "proxy";
pub(crate) const DIRECT_TAG: &str = "direct";

pub(crate) const FAKEIP_DNS: &str = "fakeip";
pub(crate) const LOCAL_DNS: &str = "local";
const TUNNEL_DNS: &str = "tunnel-dns";
/// The resolver Profile A queries through the tunnel unless the profile overrides it
/// with a `dns` parameter.
const DEFAULT_TUNNEL_DNS_SERVER: &str = "1.1.1.1";

/// Everything needed to generate the primary-core configuration for one active profile.
#[derive(Debug, Clone, Copy)]
pub struct PrimaryCoreInput<'a> {
    /// The profile currently selected to carry traffic.
    pub active_profile: &'a ConnectionProfile,
    /// The single source for the active-endpoint bypass (rule + host route).
    pub endpoint_bypass: &'a ActiveEndpointBypass,
    /// The full routing-rule set, including the built-in DNS-capture and bypass rules.
    pub rules: &'a [RoutingRule],
    /// The AmneziaWG adapter name. **Required** when the active profile is AmneziaWG,
    /// so its outbound can be bound to that adapter and nothing else (CC-07).
    pub amneziawg_adapter: Option<&'a str>,
    /// Transport settings and credentials for the profiles the primary core carries itself.
    /// **Required**, and of the matching kind, when the active profile is Hysteria 2 or
    /// VLESS+REALITY. Unused for AmneziaWG.
    pub primary_transport: Option<PrimaryTransport<'a>>,
    /// The half of the FakeIP pools this tunnel hands out (T131).
    pub fakeip: FakeIpHalf,
}

/// Settings and credentials for a profile the primary core carries itself.
#[derive(Debug, Clone, Copy)]
pub enum PrimaryTransport<'a> {
    Hysteria2(&'a Hysteria2Transport),
    VlessReality(&'a RealityTransport),
}

/// The generated primary-core configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrimaryCoreConfig {
    pub log: Log,
    pub dns: Dns,
    pub inbounds: Vec<TunInbound>,
    pub outbounds: Vec<Outbound>,
    /// The session endpoint (ADR-0008). Empty, and so absent from the output, for the three
    /// profiles that carry traffic on their own.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SessionEndpoint>,
    pub route: Route,
    /// The control API (ADR-0008), only when a session needs its carrier switched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Log {
    pub level: &'static str,
    pub timestamp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dns {
    pub servers: Vec<DnsServer>,
    pub rules: Vec<DnsRule>,
    #[serde(rename = "final")]
    pub final_server: String,
}

/// A typed DNS server (1.12+ format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsServer {
    /// Answers every query with an address from the FakeIP pool.
    FakeIp {
        tag: String,
        inet4_range: String,
        inet6_range: String,
    },
    /// The system resolver on the physical network — used only for bypassed names
    /// (captive-portal probes, the endpoint) that must resolve to real addresses.
    Local { tag: String },
    /// A plain UDP resolver bound to an interface — Profile A's in-tunnel resolver.
    Udp {
        tag: String,
        server: String,
        server_port: u16,
        bind_interface: String,
    },
}

/// A DNS rule: route matching queries to a named server, or reject them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DnsRule {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `route` or `reject`.
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunInbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub interface_name: String,
    pub address: Vec<String>,
    pub auto_route: bool,
    pub strict_route: bool,
    /// `hijack`: native per-interface DNS plus port-53 hijacking into the TUN — the
    /// core-side half of DNS-leak prevention.
    pub dns_mode: &'static str,
}

/// An outbound. Untagged: each variant carries its own `type` field, so serialization
/// emits exactly the inner object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Outbound {
    /// Profile A: a `direct` outbound bound to the AmneziaWG adapter (CC-07).
    DirectBound(DirectBoundOutbound),
    Hysteria2(Hysteria2Outbound),
    Vless(VlessOutbound),
    /// The unbound `direct` outbound used by bypass rules.
    Direct(DirectOutbound),
    /// The switch over the carriers of a session (ADR-0008).
    Selector(SelectorOutbound),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectOutbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    pub rules: Vec<RouteRule>,
    #[serde(rename = "final")]
    pub final_outbound: String,
    /// Always `true`: binds the core's own outbounds to the physical NIC so bypassed
    /// traffic cannot loop back into the TUN (R4).
    pub auto_detect_interface: bool,
    pub default_domain_resolver: String,
}

/// One route rule. Empty match fields are omitted so the output stays minimal and the
/// determinism assertion is meaningful.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RouteRule {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    /// `route` or `hijack-dns`.
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

/// Generate the primary-core configuration for the active profile.
pub fn generate_primary_core_config(
    input: PrimaryCoreInput<'_>,
) -> Result<PrimaryCoreConfig, ConfigError> {
    let profile = input.active_profile;
    let mut servers = vec![
        DnsServer::FakeIp {
            tag: FAKEIP_DNS.to_string(),
            inet4_range: input.fakeip.inet4().to_string(),
            inet6_range: input.fakeip.inet6().to_string(),
        },
        DnsServer::Local {
            tag: LOCAL_DNS.to_string(),
        },
    ];

    let proxy =
        match profile.kind() {
            ProfileKind::AmneziaWg => {
                let adapter = input
                    .amneziawg_adapter
                    .ok_or(ConfigError::MissingAmneziaWgAdapter)?;
                servers.push(DnsServer::Udp {
                    tag: TUNNEL_DNS.to_string(),
                    server: profile
                        .params()
                        .get("dns")
                        .unwrap_or(DEFAULT_TUNNEL_DNS_SERVER)
                        .to_string(),
                    server_port: 53,
                    bind_interface: adapter.to_string(),
                });
                Outbound::DirectBound(DirectBoundOutbound::to_amneziawg_adapter(
                    PROXY_TAG, adapter, TUNNEL_DNS,
                ))
            }
            ProfileKind::Hysteria2 => match input.primary_transport {
                Some(PrimaryTransport::Hysteria2(transport)) => {
                    Outbound::Hysteria2(hysteria2_outbound(
                        PROXY_TAG,
                        input.endpoint_bypass,
                        transport,
                        profile.brutal(),
                    )?)
                }
                _ => return Err(ConfigError::MissingTransport("Hysteria 2")),
            },
            ProfileKind::VlessReality => match input.primary_transport {
                Some(PrimaryTransport::VlessReality(transport)) => Outbound::Vless(
                    reality_outbound(PROXY_TAG, input.endpoint_bypass, transport)?,
                ),
                _ => return Err(ConfigError::MissingTransport("VLESS+REALITY")),
            },
        };

    Ok(PrimaryCoreConfig {
        log: Log {
            level: "info",
            timestamp: true,
        },
        dns: Dns {
            servers,
            rules: dns_rules(
                input.rules,
                (profile.kind() == ProfileKind::AmneziaWg).then_some(TUNNEL_DNS),
            ),
            // Must be a real resolver (the core refuses FakeIP as default); the rule
            // chain decides every non-bypassed query before this is consulted.
            final_server: LOCAL_DNS.to_string(),
        },
        inbounds: vec![tun_inbound()],
        outbounds: vec![proxy, direct_outbound()],
        endpoints: Vec::new(),
        route: Route {
            rules: route_rules(input.rules),
            final_outbound: PROXY_TAG.to_string(),
            auto_detect_interface: true,
            default_domain_resolver: LOCAL_DNS.to_string(),
        },
        experimental: None,
    })
}

/// The tunnel inbound every generated configuration has.
pub(crate) fn tun_inbound() -> TunInbound {
    TunInbound {
        kind: "tun",
        tag: TUN_TAG.to_string(),
        interface_name: TUN_INTERFACE.to_string(),
        address: vec![TUN_ADDRESS.to_string()],
        auto_route: true,
        strict_route: true,
        dns_mode: "hijack",
    }
}

/// The unbound `direct` outbound that bypass rules use.
pub(crate) fn direct_outbound() -> Outbound {
    Outbound::Direct(DirectOutbound {
        kind: "direct",
        tag: DIRECT_TAG.to_string(),
    })
}

/// A domain pattern in the form a connection arrives in: lower case, no trailing dot.
///
/// The core compares the names it is given as they are, so a rule written `Example.COM.` would never
/// match `example.com`, and a destination the person marked "bypass" would go through the tunnel (found
/// by the agreement test against `dnet_core::rule_eval`, T073). Patterns are validated when the rule is
/// made, so the fallback is only for a pattern that somehow was not.
fn written(pattern: &str) -> String {
    dnet_core::rule_eval::normalize_domain(pattern).unwrap_or_else(|| pattern.to_owned())
}

/// Rules sorted by ascending precedence, so lower values (built-ins, DNS capture) win.
fn by_precedence(rules: &[RoutingRule]) -> Vec<&RoutingRule> {
    let mut sorted: Vec<&RoutingRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.precedence());
    sorted
}

/// Map the domain routing rules to route entries. The DNS-capture rule becomes the
/// native `hijack-dns` action; everything else routes to an outbound.
pub fn route_rules(rules: &[RoutingRule]) -> Vec<RouteRule> {
    by_precedence(rules)
        .into_iter()
        .map(|rule| {
            let (action, outbound) = match rule.action() {
                RuleAction::Capture => ("hijack-dns", None),
                RuleAction::Reject => ("reject", None),
                RuleAction::Bypass => ("route", Some(DIRECT_TAG.to_string())),
                RuleAction::Tunnel => ("route", Some(PROXY_TAG.to_string())),
            };
            let mut entry = RouteRule {
                action,
                outbound,
                ..RouteRule::default()
            };
            match rule.matcher() {
                RuleMatcher::Domain(d) => entry.domain.push(written(d)),
                RuleMatcher::DomainSuffix(d) => entry.domain_suffix.push(written(d)),
                RuleMatcher::IpCidr(c) => entry.ip_cidr.push(c.to_string()),
                RuleMatcher::Application(p) => entry.process_path.push(p.clone()),
                RuleMatcher::DnsPort => entry.port.push(53),
                RuleMatcher::EncryptedDnsPort => {
                    entry.port.push(dnet_core::doh_block::ENCRYPTED_DNS_PORT);
                }
            }
            entry
        })
        .collect()
}

/// The DNS rule chain. Every query is decided by a rule, so the default (`final`) server —
/// which the pinned core requires to be a real resolver, never FakeIP (verified with its
/// `check` command) — is unreachable for non-bypassed names:
///
/// 1. bypassed names resolve to **real** addresses on the physical network (a fake
///    address is useless off-tunnel);
/// 2. `A`/`AAAA` queries get FakeIP answers;
/// 3. every other query type goes through the tunnel resolver (Profile A) or is refused
///    (Profiles B/C, until their remote resolver lands in Phase 5) — never to the local
///    network, which would leak it.
pub(crate) fn dns_rules(rules: &[RoutingRule], tunnel_resolver: Option<&str>) -> Vec<DnsRule> {
    let mut chain: Vec<DnsRule> = by_precedence(rules)
        .into_iter()
        .filter(|r| matches!(r.action(), RuleAction::Bypass | RuleAction::Reject))
        .filter_map(|r| {
            let (domain, domain_suffix) = match r.matcher() {
                RuleMatcher::Domain(d) => (vec![written(d)], Vec::new()),
                RuleMatcher::DomainSuffix(d) => (Vec::new(), vec![written(d)]),
                _ => return None,
            };
            // A refused name gets no answer at all, so the program falls back to the system
            // resolver (T070); a bypassed name is answered by the local resolver.
            let (action, server) = if r.action() == RuleAction::Reject {
                ("reject", None)
            } else {
                ("route", Some(LOCAL_DNS.to_string()))
            };
            Some(DnsRule {
                domain,
                domain_suffix,
                action,
                server,
                ..DnsRule::default()
            })
        })
        .collect();

    chain.push(DnsRule {
        query_type: vec!["A", "AAAA"],
        action: "route",
        server: Some(FAKEIP_DNS.to_string()),
        ..DnsRule::default()
    });
    chain.push(match tunnel_resolver {
        Some(server) => DnsRule {
            query_type: vec!["A", "AAAA"],
            invert: true,
            action: "route",
            server: Some(server.to_string()),
            ..DnsRule::default()
        },
        None => DnsRule {
            query_type: vec!["A", "AAAA"],
            invert: true,
            action: "reject",
            ..DnsRule::default()
        },
    });
    chain
}

/// Serialize a generated config to pretty JSON. Deterministic for identical input.
///
/// **The output contains credentials** (CC-08): write it only to the restricted config file
/// (`write::write_restricted`), never to a log or diagnostic. Log the config's `Debug` form
/// instead, which redacts them.
pub fn to_json(config: &PrimaryCoreConfig) -> String {
    serde_json::to_string_pretty(config).expect("PrimaryCoreConfig always serializes")
}

/// The DNS rule chain, written out rule by rule. It decides which names are answered locally, which are
/// refused, which get a stand-in address and which go through the tunnel, so a rule that loses its action or
/// its match is a name resolved the wrong way.
#[cfg(test)]
mod dns_chain_tests {
    use dnet_core::rule::{RoutingRule, RuleAction, RuleMatcher};
    use serde_json::{json, Value};

    use super::*;

    fn rule(matcher: RuleMatcher, action: RuleAction, precedence: u32) -> RoutingRule {
        RoutingRule::user(matcher, action, precedence).unwrap()
    }

    fn chain(rules: &[RoutingRule], resolver: Option<&str>) -> Vec<Value> {
        dns_rules(rules, resolver)
            .iter()
            .map(|r| serde_json::to_value(r).unwrap())
            .collect()
    }

    fn fakeip() -> Value {
        json!({ "query_type": ["A", "AAAA"], "action": "route", "server": "fakeip" })
    }

    fn through_tunnel(server: &str) -> Value {
        json!({ "query_type": ["A", "AAAA"], "invert": true, "action": "route", "server": server })
    }

    fn refused_others() -> Value {
        json!({ "query_type": ["A", "AAAA"], "invert": true, "action": "reject" })
    }

    #[test]
    fn with_no_rules_every_name_gets_a_stand_in_and_every_other_query_goes_through_the_tunnel() {
        assert_eq!(
            chain(&[], Some("1.1.1.1")),
            [fakeip(), through_tunnel("1.1.1.1")]
        );
    }

    #[test]
    fn without_a_tunnel_resolver_every_other_query_is_refused_and_never_sent_to_the_local_network()
    {
        assert_eq!(chain(&[], None), [fakeip(), refused_others()]);
    }

    #[test]
    fn a_bypassed_site_is_answered_by_the_local_resolver_with_its_own_name() {
        let rules = [rule(
            RuleMatcher::Domain("printer.lan".into()),
            RuleAction::Bypass,
            200,
        )];
        assert_eq!(
            chain(&rules, None)[0],
            json!({ "domain": ["printer.lan"], "action": "route", "server": "local" })
        );
    }

    #[test]
    fn a_bypassed_site_and_its_subdomains_is_matched_as_a_suffix() {
        let rules = [rule(
            RuleMatcher::DomainSuffix("corp.example".into()),
            RuleAction::Bypass,
            200,
        )];
        assert_eq!(
            chain(&rules, None)[0],
            json!({ "domain_suffix": ["corp.example"], "action": "route", "server": "local" })
        );
    }

    /// Today nothing can refuse a *name*: a person's rule cannot reject (that is for the built-in set), and the
    /// built-in set refuses a port, not names. So the chain has no name-refusing rule, and the branch of
    /// `dns_rules` that would write one is not reached by any rule set that can exist. If a built-in rule
    /// ever refuses names, this fails, and the chain's refusal (no answer, no server) must then be tested.
    #[test]
    fn no_rule_that_can_exist_today_refuses_a_name() {
        for matcher in [
            RuleMatcher::Domain("blocked.example".into()),
            RuleMatcher::DomainSuffix("blocked.example".into()),
        ] {
            assert!(
                RoutingRule::user(matcher, RuleAction::Reject, 200).is_err(),
                "a person's rule must not reject"
            );
        }
        let builtin = dnet_core::builtin_rules::builtin_rules(None);
        assert!(
            builtin
                .iter()
                .filter(|r| r.action() == RuleAction::Reject)
                .all(|r| matches!(r.matcher(), RuleMatcher::EncryptedDnsPort)),
            "the built-in set refuses only the encrypted-name port"
        );
        let got = chain(&builtin, None);
        let refusals: Vec<_> = got.iter().filter(|e| e["action"] == "reject").collect();
        assert_eq!(
            refusals.len(),
            1,
            "only the closing rule, which refuses other query types"
        );
        assert!(refusals[0].get("domain").is_none() && refusals[0].get("domain_suffix").is_none());
    }

    #[test]
    fn rules_that_are_not_about_names_or_that_tunnel_add_nothing_to_the_chain() {
        let rules = [
            rule(
                RuleMatcher::Domain("through.example".into()),
                RuleAction::Tunnel,
                200,
            ),
            rule(
                RuleMatcher::DomainSuffix("through.example".into()),
                RuleAction::Tunnel,
                201,
            ),
            rule(
                RuleMatcher::IpCidr(dnet_core::rule::IpCidr::parse("198.51.100.0/24").unwrap()),
                RuleAction::Bypass,
                202,
            ),
            rule(
                RuleMatcher::Application(r"C:\Apps\a.exe".into()),
                RuleAction::Bypass,
                203,
            ),
        ];
        assert_eq!(chain(&rules, None), [fakeip(), refused_others()]);
    }

    #[test]
    fn the_chain_follows_precedence_and_the_stand_in_rules_always_come_last() {
        let rules = [
            rule(
                RuleMatcher::Domain("late.example".into()),
                RuleAction::Bypass,
                300,
            ),
            rule(
                RuleMatcher::Domain("early.example".into()),
                RuleAction::Bypass,
                100,
            ),
            rule(
                RuleMatcher::DomainSuffix("mid.example".into()),
                RuleAction::Bypass,
                200,
            ),
        ];
        let got = chain(&rules, Some("9.9.9.9"));
        assert_eq!(got.len(), 5);
        assert_eq!(got[0]["domain"], json!(["early.example"]));
        assert_eq!(got[1]["domain_suffix"], json!(["mid.example"]));
        assert_eq!(got[2]["domain"], json!(["late.example"]));
        assert_eq!(got[3], fakeip());
        assert_eq!(got[4], through_tunnel("9.9.9.9"));
    }

    #[test]
    fn every_rule_in_the_chain_has_an_action_and_only_two_kinds_exist() {
        let mut rules = dnet_core::builtin_rules::builtin_rules(None);
        rules.push(rule(
            RuleMatcher::Domain("a.example".into()),
            RuleAction::Bypass,
            900,
        ));
        for resolver in [None, Some("1.1.1.1")] {
            for entry in chain(&rules, resolver) {
                let action = entry["action"].as_str().expect("an action");
                assert!(["route", "reject"].contains(&action), "{entry}");
            }
        }
    }

    #[test]
    fn the_tunnel_resolver_given_is_the_one_used() {
        for server in ["1.1.1.1", "9.9.9.9", "tunnel-dns"] {
            assert_eq!(chain(&[], Some(server))[1], through_tunnel(server));
        }
    }

    #[test]
    fn a_domain_is_written_in_its_normal_form() {
        let rules = [rule(
            RuleMatcher::Domain("Example.COM".into()),
            RuleAction::Bypass,
            200,
        )];
        assert_eq!(chain(&rules, None)[0]["domain"], json!(["example.com"]));
    }
}
