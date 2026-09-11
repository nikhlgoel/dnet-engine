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

/// FakeIP pools (CC-02, research.md R3). Documented defaults.
pub const FAKEIP_INET4: &str = "198.18.0.0/15";
pub const FAKEIP_INET6: &str = "fc00::/18";

const TUN_TAG: &str = "tun-in";
/// The TUN adapter name the primary core creates.
pub const TUN_INTERFACE: &str = "dnet-tun0";
/// Deliberately outside the FakeIP pool, so a fake address can never collide with the
/// TUN's own address.
const TUN_ADDRESS: &str = "172.19.0.1/30";

const PROXY_TAG: &str = "proxy";
const DIRECT_TAG: &str = "direct";

const FAKEIP_DNS: &str = "fakeip";
const LOCAL_DNS: &str = "local";
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
}

/// The generated primary-core configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrimaryCoreConfig {
    pub log: Log,
    pub dns: Dns,
    pub inbounds: Vec<TunInbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectOutbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hysteria2Outbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    /// Present only when Brutal is enabled; absence yields BBR (CC-03). `up_mbps` and
    /// `down_mbps` are always emitted together (CC-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VlessOutbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
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
            inet4_range: FAKEIP_INET4.to_string(),
            inet6_range: FAKEIP_INET6.to_string(),
        },
        DnsServer::Local {
            tag: LOCAL_DNS.to_string(),
        },
    ];

    let proxy = match profile.kind() {
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
        ProfileKind::Hysteria2 => {
            let (up_mbps, down_mbps) = match profile.brutal() {
                None => (None, None),
                // A zero on either side is a half-configured Brutal — refuse it rather
                // than silently half-enable (CC-04).
                Some(bp) if bp.up_mbps == 0 || bp.down_mbps == 0 => {
                    return Err(ConfigError::PartialBrutalBandwidth)
                }
                Some(bp) => (Some(bp.up_mbps), Some(bp.down_mbps)),
            };
            Outbound::Hysteria2(Hysteria2Outbound {
                kind: "hysteria2",
                tag: PROXY_TAG.to_string(),
                server: input.endpoint_bypass.host().to_string(),
                server_port: input.endpoint_bypass.port(),
                up_mbps,
                down_mbps,
            })
        }
        ProfileKind::VlessReality => Outbound::Vless(VlessOutbound {
            kind: "vless",
            tag: PROXY_TAG.to_string(),
            server: input.endpoint_bypass.host().to_string(),
            server_port: input.endpoint_bypass.port(),
        }),
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
        inbounds: vec![TunInbound {
            kind: "tun",
            tag: TUN_TAG.to_string(),
            interface_name: TUN_INTERFACE.to_string(),
            address: vec![TUN_ADDRESS.to_string()],
            auto_route: true,
            strict_route: true,
            dns_mode: "hijack",
        }],
        outbounds: vec![
            proxy,
            Outbound::Direct(DirectOutbound {
                kind: "direct",
                tag: DIRECT_TAG.to_string(),
            }),
        ],
        route: Route {
            rules: route_rules(input.rules),
            final_outbound: PROXY_TAG.to_string(),
            auto_detect_interface: true,
            default_domain_resolver: LOCAL_DNS.to_string(),
        },
    })
}

/// Rules sorted by ascending precedence, so lower values (built-ins, DNS capture) win.
fn by_precedence(rules: &[RoutingRule]) -> Vec<&RoutingRule> {
    let mut sorted: Vec<&RoutingRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.precedence());
    sorted
}

/// Map the domain routing rules to route entries. The DNS-capture rule becomes the
/// native `hijack-dns` action; everything else routes to an outbound.
fn route_rules(rules: &[RoutingRule]) -> Vec<RouteRule> {
    by_precedence(rules)
        .into_iter()
        .map(|rule| {
            let (action, outbound) = match rule.action() {
                RuleAction::Capture => ("hijack-dns", None),
                RuleAction::Bypass => ("route", Some(DIRECT_TAG.to_string())),
                RuleAction::Tunnel => ("route", Some(PROXY_TAG.to_string())),
            };
            let mut entry = RouteRule {
                action,
                outbound,
                ..RouteRule::default()
            };
            match rule.matcher() {
                RuleMatcher::Domain(d) => entry.domain.push(d.clone()),
                RuleMatcher::DomainSuffix(d) => entry.domain_suffix.push(d.clone()),
                RuleMatcher::IpCidr(c) => entry.ip_cidr.push(c.to_string()),
                RuleMatcher::Application(p) => entry.process_path.push(p.clone()),
                RuleMatcher::DnsPort => entry.port.push(53),
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
fn dns_rules(rules: &[RoutingRule], tunnel_resolver: Option<&str>) -> Vec<DnsRule> {
    let mut chain: Vec<DnsRule> = by_precedence(rules)
        .into_iter()
        .filter(|r| r.action() == RuleAction::Bypass)
        .filter_map(|r| {
            let (domain, domain_suffix) = match r.matcher() {
                RuleMatcher::Domain(d) => (vec![d.clone()], Vec::new()),
                RuleMatcher::DomainSuffix(d) => (Vec::new(), vec![d.clone()]),
                _ => return None,
            };
            Some(DnsRule {
                domain,
                domain_suffix,
                action: "route",
                server: Some(LOCAL_DNS.to_string()),
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
pub fn to_json(config: &PrimaryCoreConfig) -> String {
    serde_json::to_string_pretty(config).expect("PrimaryCoreConfig always serializes")
}
