//! T047 — primary-core configuration generation (CC-01, CC-02, CC-05..CC-09).
//!
//! Turns the active profile, endpoint, and routing rules into the primary core's JSON
//! configuration, deterministically. The generation is a pure function of its input, so
//! identical domain state yields byte-identical output (CC-09).

use serde::Serialize;

use dnet_core::profile::{ConnectionProfile, ProfileKind};
use dnet_core::rule::{RoutingRule, RuleAction, RuleMatcher};

use crate::bind::DirectBoundOutbound;
use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;

/// FakeIP pools (CC-02, research.md R3). Documented defaults.
const FAKEIP_INET4: &str = "198.18.0.0/15";
const FAKEIP_INET6: &str = "fc00::/18";

const TUN_TAG: &str = "tun-in";
const TUN_INTERFACE: &str = "dnet-tun0";
const TUN_INET4: &str = "198.18.0.1/30";

const PROXY_TAG: &str = "proxy";
const DIRECT_TAG: &str = "direct";
const DNS_TAG: &str = "dns-out";
const BLOCK_TAG: &str = "block";

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
    pub dns: Dns,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dns {
    pub servers: Vec<DnsServer>,
    pub fakeip: FakeIp,
    pub independent_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsServer {
    pub tag: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FakeIp {
    pub enabled: bool,
    pub inet4_range: String,
    pub inet6_range: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename = "tun")]
pub struct Inbound {
    pub tag: String,
    pub interface_name: String,
    pub inet4_address: String,
    pub auto_route: bool,
    pub strict_route: bool,
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
    /// A tag-and-type-only outbound: general `direct`, `dns`, `block`.
    Simple(SimpleOutbound),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimpleOutbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hysteria2Outbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub server: String,
    pub server_port: u16,
    /// Present only when Brutal is enabled; its absence yields BBR (CC-03). Both `up`
    /// and `down` are always present together (CC-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<Bandwidth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bandwidth {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VlessOutbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub server: String,
    pub server_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    pub rules: Vec<RouteRule>,
    #[serde(rename = "final")]
    pub final_outbound: String,
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
    pub outbound: String,
}

/// Generate the primary-core configuration for the active profile.
pub fn generate_primary_core_config(
    input: PrimaryCoreInput<'_>,
) -> Result<PrimaryCoreConfig, ConfigError> {
    let server = input.endpoint_bypass.host().to_string();
    let server_port = input.endpoint_bypass.port();

    // The active (proxy) outbound depends on the profile kind.
    let proxy = match input.active_profile.kind() {
        ProfileKind::AmneziaWg => {
            let adapter = input
                .amneziawg_adapter
                .ok_or(ConfigError::MissingAmneziaWgAdapter)?;
            Outbound::DirectBound(DirectBoundOutbound::to_amneziawg_adapter(
                PROXY_TAG, adapter,
            ))
        }
        ProfileKind::Hysteria2 => {
            let bandwidth = match input.active_profile.brutal() {
                None => None,
                Some(bp) => {
                    // A zero on either side is a half-configured Brutal — refuse it
                    // rather than silently half-enable (CC-04).
                    if bp.up_mbps == 0 || bp.down_mbps == 0 {
                        return Err(ConfigError::PartialBrutalBandwidth);
                    }
                    Some(Bandwidth {
                        up_mbps: bp.up_mbps,
                        down_mbps: bp.down_mbps,
                    })
                }
            };
            Outbound::Hysteria2(Hysteria2Outbound {
                tag: PROXY_TAG.to_string(),
                kind: "hysteria2",
                server,
                server_port,
                bandwidth,
            })
        }
        ProfileKind::VlessReality => Outbound::Vless(VlessOutbound {
            tag: PROXY_TAG.to_string(),
            kind: "vless",
            server,
            server_port,
        }),
    };

    let outbounds = vec![
        proxy,
        Outbound::Simple(SimpleOutbound {
            tag: DIRECT_TAG.to_string(),
            kind: "direct".to_string(),
        }),
        Outbound::Simple(SimpleOutbound {
            tag: DNS_TAG.to_string(),
            kind: "dns".to_string(),
        }),
        Outbound::Simple(SimpleOutbound {
            tag: BLOCK_TAG.to_string(),
            kind: "block".to_string(),
        }),
    ];

    let route = Route {
        rules: route_rules(input.rules),
        final_outbound: PROXY_TAG.to_string(),
    };

    Ok(PrimaryCoreConfig {
        dns: Dns {
            servers: vec![DnsServer {
                tag: "fakeip".to_string(),
                address: "fakeip".to_string(),
            }],
            fakeip: FakeIp {
                enabled: true,
                inet4_range: FAKEIP_INET4.to_string(),
                inet6_range: FAKEIP_INET6.to_string(),
            },
            independent_cache: true,
        },
        inbounds: vec![Inbound {
            tag: TUN_TAG.to_string(),
            interface_name: TUN_INTERFACE.to_string(),
            inet4_address: TUN_INET4.to_string(),
            auto_route: true,
            strict_route: true,
        }],
        outbounds,
        route,
    })
}

/// Map the domain routing rules to route entries, in ascending precedence order so the
/// DNS-capture rule (precedence 0) comes first and lower-precedence rules win.
fn route_rules(rules: &[RoutingRule]) -> Vec<RouteRule> {
    let mut sorted: Vec<&RoutingRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.precedence());

    sorted
        .into_iter()
        .map(|rule| {
            let outbound = match rule.action() {
                RuleAction::Bypass => DIRECT_TAG,
                RuleAction::Tunnel => PROXY_TAG,
                RuleAction::Capture => DNS_TAG,
            }
            .to_string();

            let mut entry = RouteRule {
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

/// Serialize a generated config to pretty JSON. Deterministic for identical input.
pub fn to_json(config: &PrimaryCoreConfig) -> String {
    serde_json::to_string_pretty(config).expect("PrimaryCoreConfig always serializes")
}
