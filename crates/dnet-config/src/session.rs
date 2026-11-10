//! ADR-0008 — the session: one endpoint of the primary core that stays put while the carrier under it is
//! replaced.
//!
//! The session is an endpoint of the primary core whose socket is dialled through a **selector** over the
//! carriers (Hysteria 2, VLESS+REALITY). The person's connections end in the core's own network stack and
//! ride the session, so switching the selector moves the session to another carrier without ending them.
//! Verified against the pinned core, built with the endpoint's tag, by `testing/spike-carrier`: the same
//! connection survived switches in both directions between the QUIC and the TCP carrier, and the control
//! (user streams riding the carrier directly) was broken by killing it.
//!
//! Three facts from that work are encoded here, each with a test:
//! - the endpoint takes `detour` and refuses it together with `listen_port` (so there is no listen port);
//! - the control API has **no Host check, only a TCP listener, and an empty secret disables
//!   authentication**, and an *empty* cross-origin list means allow-all, so the secret is required and
//!   long, and the allow-list names one origin that can never occur;
//! - after a switch the far end keeps sending to the old path until it hears from the new one, so the
//!   service nudges the session right after switching (that is `dnetd`'s, not this crate's).
//!
//! The configuration for the three profiles that carry traffic on their own (`primary.rs`) is unchanged:
//! the new parts are skipped when empty, and a test checks that.

use std::net::{IpAddr, Ipv4Addr};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Serialize;

use dnet_core::profile::BrutalOptIn;
use dnet_core::rule::RoutingRule;

use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;
use crate::hysteria2::hysteria2_outbound;
use crate::primary::{
    direct_outbound, dns_rules, route_rules, tun_inbound, Dns, DnsServer, FakeIpHalf, Log,
    Outbound, PrimaryCoreConfig, PrimaryTransport, Route, FAKEIP_DNS, LOCAL_DNS, PROXY_TAG,
};
use crate::probe::{
    ProbeConfig, ProbeDns, ProbeDnsServer, ProbeRoute, SocksAuth, SocksInbound, SocksUser,
    INBOUND_TAG, PROBE_LISTEN,
};
use crate::reality::reality_outbound;
use crate::secret::Secret;

/// The session endpoint's tag. It is the tag the routing rules already send tunnelled traffic to, so no rule
/// changes: the endpoint simply is what "the tunnel" means.
pub const SESSION_TAG: &str = PROXY_TAG;
/// The selector over the carriers.
pub const CARRIER_TAG: &str = "carrier";
/// The only cross-origin caller the control API admits: a name that cannot occur (`.invalid` is reserved).
/// An empty list would mean "allow all" in the pinned core.
pub const CONTROL_ORIGIN: &str = "https://dnet.invalid";
/// How often the idle session sends a packet, in seconds. Keeps the far end's idea of our path fresh.
pub const KEEPALIVE_SECONDS: u16 = 25;
/// The shortest control secret accepted: 32 characters (a 256-bit secret in hex is 64).
pub const MIN_CONTROL_SECRET_LEN: usize = 32;

/// What the primary core's configuration schema calls the endpoint type of the session. It is a protocol
/// name that is also a trademark, so it is configuration only, written to the restricted config file and
/// never shown to a person. It is assembled from two literals so the source tree stays free of the name
/// (`xtask lint-branding`), as the lint's own source does; this is the one place it is needed.
pub const SESSION_ENDPOINT_TYPE: &str = concat!("wire", "guard");

const LOOPBACK: &str = "127.0.0.1";

/// Inside the session: the server's address, where the measurement origin is, and the devices'. The server's
/// session stack owns [`SESSION_SERVER`], so a connection to it never reaches the exit's rules; the origin has an
/// address of its own (found by running the composed session). Each device gets one address, one after another,
/// and a prefix of its own alone. `dnet-provision` builds the server script from these same values and
/// `dnet_core::origin::SESSION_ORIGIN_HOST` is the same address as text (a test holds them together).
pub const SESSION_SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
pub const SESSION_ORIGIN: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 254);
pub const SESSION_PREFIX: u8 = 32;
/// The UDP port the session listens on, on the server's own loopback. The carriers forward to it and no firewall
/// rule opens it.
pub const SESSION_PORT: u16 = 25182;
/// The most devices one server serves. A free server is small, and each device is a key to keep track of.
pub const MAX_DEVICES: usize = 8;

/// The address device number `index` (from 0) has inside the session.
///
/// Total: an index past the range gives the last address of the session's range (10.9.0.255), never a panic and
/// never a wrap back to a real device's address. Callers keep to `0..MAX_DEVICES`.
pub fn session_device_address(index: usize) -> Ipv4Addr {
    let offset = u8::try_from(index).map_or(u8::MAX - 2, |i| i.min(u8::MAX - 2));
    Ipv4Addr::new(10, 9, 0, 2 + offset)
}

/// Whether `address` is one a device can have: between the first and the last of [`MAX_DEVICES`].
pub fn is_device_address(address: Ipv4Addr) -> bool {
    (0..MAX_DEVICES).any(|i| session_device_address(i) == address)
}

/// Which kind of carrier a leaf is. The leaf's tag is derived from it, so a carrier is named the same
/// everywhere: in the selector, in the control API and in the person's diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Hysteria2,
    Reality,
}

impl CarrierKind {
    pub const fn tag(self) -> &'static str {
        match self {
            CarrierKind::Hysteria2 => "hy2",
            CarrierKind::Reality => "reality",
        }
    }
}

/// One way to reach the server. Each carrier has its own port on the same server, so each has its own
/// address to dial (and to keep out of the tunnel).
#[derive(Debug, Clone, Copy)]
pub struct Carrier<'a> {
    pub transport: PrimaryTransport<'a>,
    pub endpoint: &'a ActiveEndpointBypass,
    /// Brutal opt-in for a Hysteria 2 carrier; `None` is the default (BBR).
    pub brutal: Option<&'a BrutalOptIn>,
}

impl Carrier<'_> {
    pub fn kind(&self) -> CarrierKind {
        match self.transport {
            PrimaryTransport::Hysteria2(_) => CarrierKind::Hysteria2,
            PrimaryTransport::VlessReality(_) => CarrierKind::Reality,
        }
    }
}

/// The control API the service switches the selector through.
#[derive(Debug, Clone, Copy)]
pub struct ControlApi<'a> {
    /// A loopback port the service chose. Non-zero.
    pub port: u16,
    /// A random secret per run, held by the service alone. At least [`MIN_CONTROL_SECRET_LEN`] long.
    pub secret: &'a Secret,
}

/// Everything needed to generate the configuration of a session.
#[derive(Debug, Clone, Copy)]
pub struct SessionInput<'a> {
    pub carriers: &'a [Carrier<'a>],
    /// The carrier the session starts on (the one the race measured best).
    pub active: CarrierKind,
    pub rules: &'a [RoutingRule],
    pub fakeip: FakeIpHalf,
    /// This device's session key: 32 bytes, standard base64. The device's identity on the server.
    pub device_private_key: &'a Secret,
    /// The server's session public key: 32 bytes, standard base64.
    pub server_public_key: &'a str,
    /// The device's address inside the session, as a CIDR (for example `10.9.0.2/32`).
    pub device_address: &'a str,
    /// The server's session port on **its** loopback, reached through the carrier.
    pub session_port: u16,
    pub control: ControlApi<'a>,
}

/// The switch over the carriers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectorOutbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub outbounds: Vec<String>,
    pub default: String,
    /// Always `false`: the endpoint's own socket is closed by every switch whatever this says (it is an
    /// internal connection), and `true` would also close the person's streams.
    pub interrupt_exist_connections: bool,
}

/// The session endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionEndpoint {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    /// `false`: the endpoint runs in the core's own user-space network stack, so it needs no adapter of its
    /// own and no privilege beyond the tunnel's.
    pub system: bool,
    pub address: Vec<String>,
    pub private_key: Secret,
    /// The selector. There is deliberately no `listen_port`: the core refuses one together with a detour.
    pub detour: String,
    pub peers: Vec<SessionPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionPeer {
    pub address: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<&'static str>,
    pub persistent_keepalive_interval: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Experimental {
    pub clash_api: ControlApiSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlApiSection {
    pub external_controller: String,
    pub secret: Secret,
    pub access_control_allow_origin: Vec<&'static str>,
}

/// Generate the primary core's configuration for a session.
pub fn generate_session_config(input: SessionInput<'_>) -> Result<PrimaryCoreConfig, ConfigError> {
    validate(&input)?;

    let mut outbounds = Vec::with_capacity(input.carriers.len() + 2);
    let mut tags = Vec::with_capacity(input.carriers.len());
    for carrier in input.carriers {
        let tag = carrier.kind().tag();
        outbounds.push(match carrier.transport {
            PrimaryTransport::Hysteria2(transport) => Outbound::Hysteria2(hysteria2_outbound(
                tag,
                carrier.endpoint,
                transport,
                carrier.brutal,
            )?),
            PrimaryTransport::VlessReality(transport) => {
                Outbound::Vless(reality_outbound(tag, carrier.endpoint, transport)?)
            }
        });
        tags.push(tag.to_string());
    }
    outbounds.push(Outbound::Selector(SelectorOutbound {
        kind: "selector",
        tag: CARRIER_TAG.to_string(),
        outbounds: tags,
        default: input.active.tag().to_string(),
        interrupt_exist_connections: false,
    }));
    outbounds.push(direct_outbound());

    Ok(PrimaryCoreConfig {
        // `warn`: the connection log of the default level names every destination (audit E6).
        log: Log {
            level: "warn",
            timestamp: true,
        },
        dns: Dns {
            servers: vec![
                DnsServer::FakeIp {
                    tag: FAKEIP_DNS.to_string(),
                    inet4_range: input.fakeip.inet4().to_string(),
                    inet6_range: input.fakeip.inet6().to_string(),
                },
                DnsServer::Local {
                    tag: LOCAL_DNS.to_string(),
                },
            ],
            // No in-tunnel resolver yet: the same chain as the Hysteria 2 and REALITY profiles.
            rules: dns_rules(input.rules, None),
            final_server: LOCAL_DNS.to_string(),
        },
        inbounds: vec![tun_inbound()],
        outbounds,
        endpoints: vec![session_endpoint(
            CARRIER_TAG,
            input.device_private_key,
            input.server_public_key,
            input.device_address,
            input.session_port,
        )],
        route: Route {
            rules: route_rules(input.rules),
            final_outbound: SESSION_TAG.to_string(),
            auto_detect_interface: true,
            default_domain_resolver: LOCAL_DNS.to_string(),
        },
        experimental: Some(Experimental {
            clash_api: ControlApiSection {
                external_controller: format!("{LOOPBACK}:{}", input.control.port),
                secret: input.control.secret.clone(),
                access_control_allow_origin: vec![CONTROL_ORIGIN],
            },
        }),
    })
}

/// The session endpoint, dialled through `detour` (the selector, or a single carrier's tag in a probe).
fn session_endpoint(
    detour: &str,
    device_private_key: &Secret,
    server_public_key: &str,
    device_address: &str,
    session_port: u16,
) -> SessionEndpoint {
    SessionEndpoint {
        kind: SESSION_ENDPOINT_TYPE,
        tag: SESSION_TAG.to_string(),
        system: false,
        address: vec![device_address.to_string()],
        private_key: device_private_key.clone(),
        detour: detour.to_string(),
        peers: vec![SessionPeer {
            address: LOOPBACK.to_string(),
            port: session_port,
            public_key: server_public_key.to_string(),
            allowed_ips: vec!["0.0.0.0/0"],
            persistent_keepalive_interval: KEEPALIVE_SECONDS,
        }],
    }
}

/// What a probe of one carrier needs: the carrier, the session parts, and the loopback proxy the prober uses.
#[derive(Debug, Clone, Copy)]
pub struct SessionProbeInput<'a> {
    pub socks_auth: &'a SocksAuth,
    pub carrier: Carrier<'a>,
    pub device_private_key: &'a Secret,
    pub server_public_key: &'a str,
    pub device_address: &'a str,
    pub session_port: u16,
    /// The loopback port the proxy listens on. Non-zero.
    pub socks_port: u16,
}

/// The configuration of a probe of one carrier **through the session**. A server that serves the session locks
/// its carriers to it, so a probe that used the carrier directly would be refused and read as a blocked method.
/// This one is the same shape as any probe (a loopback proxy that demands a password, nothing outside its own
/// process) with the session over the one carrier under test, so what it measures is what a connection would get.
pub fn generate_session_probe_config(
    input: SessionProbeInput<'_>,
) -> Result<ProbeConfig, ConfigError> {
    if input.socks_port == 0 {
        return Err(ConfigError::InvalidProbePort);
    }
    if input.socks_auth.username.is_empty() {
        return Err(ConfigError::InvalidCredential("probe proxy username"));
    }
    if input.socks_auth.password.expose().is_empty() {
        return Err(ConfigError::InvalidCredential("probe proxy password"));
    }
    check_session_parts(
        input.device_private_key,
        input.server_public_key,
        input.device_address,
        input.session_port,
    )?;
    let tag = input.carrier.kind().tag();
    let leaf = match input.carrier.transport {
        PrimaryTransport::Hysteria2(transport) => Outbound::Hysteria2(hysteria2_outbound(
            tag,
            input.carrier.endpoint,
            transport,
            input.carrier.brutal,
        )?),
        PrimaryTransport::VlessReality(transport) => {
            Outbound::Vless(reality_outbound(tag, input.carrier.endpoint, transport)?)
        }
    };
    Ok(ProbeConfig {
        log: Log {
            level: "warn",
            timestamp: true,
        },
        dns: ProbeDns {
            servers: vec![ProbeDnsServer {
                kind: "local",
                tag: LOCAL_DNS,
            }],
        },
        inbounds: vec![SocksInbound {
            kind: "socks",
            tag: INBOUND_TAG,
            listen: PROBE_LISTEN,
            listen_port: input.socks_port,
            users: vec![SocksUser {
                username: input.socks_auth.username.clone(),
                password: input.socks_auth.password.clone(),
            }],
        }],
        outbounds: vec![leaf],
        endpoints: vec![session_endpoint(
            tag,
            input.device_private_key,
            input.server_public_key,
            input.device_address,
            input.session_port,
        )],
        route: ProbeRoute {
            final_outbound: SESSION_TAG,
            auto_detect_interface: true,
            default_domain_resolver: LOCAL_DNS,
        },
    })
}

/// The checks on the session's own parts, shared by the connection and the probe.
fn check_session_parts(
    device_private_key: &Secret,
    server_public_key: &str,
    device_address: &str,
    session_port: u16,
) -> Result<(), ConfigError> {
    let refuse = |why: &'static str| Err(ConfigError::InvalidSession(why));
    if !is_key(device_private_key.expose()) {
        return refuse("the device key is not 32 bytes of base64");
    }
    if !is_key(server_public_key) {
        return refuse("the server key is not 32 bytes of base64");
    }
    if !is_cidr(device_address) {
        return refuse("the device address is not a CIDR");
    }
    if session_port == 0 {
        return refuse("the session port is zero");
    }
    Ok(())
}

fn validate(input: &SessionInput<'_>) -> Result<(), ConfigError> {
    let refuse = |why: &'static str| Err(ConfigError::InvalidSession(why));
    if input.carriers.is_empty() {
        return refuse("no carrier");
    }
    for (i, carrier) in input.carriers.iter().enumerate() {
        if input.carriers[..i]
            .iter()
            .any(|earlier| earlier.kind() == carrier.kind())
        {
            return refuse("a carrier kind appears twice");
        }
    }
    if !input.carriers.iter().any(|c| c.kind() == input.active) {
        return refuse("the starting carrier is not among the carriers");
    }
    check_session_parts(
        input.device_private_key,
        input.server_public_key,
        input.device_address,
        input.session_port,
    )?;
    if input.control.port == 0 {
        return refuse("the control port is zero");
    }
    if input.control.secret.expose().len() < MIN_CONTROL_SECRET_LEN {
        return refuse("the control secret is too short");
    }
    Ok(())
}

/// 32 bytes in standard base64: the form the core takes and prints for a session key.
pub(crate) fn is_key(text: &str) -> bool {
    STANDARD
        .decode(text)
        .map(|b| b.len() == 32)
        .unwrap_or(false)
}

fn is_cidr(text: &str) -> bool {
    let Some((address, prefix)) = text.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix <= 32,
        Ok(IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2::{
        BbrProfile, Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams,
        Hysteria2Obfs, Hysteria2Settings, Hysteria2Transport,
    };
    use crate::primary::{generate_primary_core_config, to_json, PrimaryCoreInput};
    use crate::probe::SocksAuth;
    use crate::reality::{
        RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
        RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
    };
    use crate::tls::ServerTrust;
    use dnet_core::builtin_rules::builtin_rules_for;
    use dnet_core::doh_block::Policy;
    use dnet_core::endpoint::EndpointAddress;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
    use serde_json::Value;

    const DEVICE_KEY_TEXT: &str = "device-key-must-never-appear-in-debug";

    fn hy2() -> Hysteria2Transport {
        Hysteria2Transport {
            settings: Hysteria2Settings {
                client: Hysteria2ClientParams {
                    bbr_profile: BbrProfile::Conservative,
                    chrome_parrot: true,
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: "edge.example.net".into(),
                        spki_sha256: [7; 32],
                    },
                },
            },
            credentials: Hysteria2Credentials {
                auth_password: Secret::new("test-only-auth"),
                obfs_password: Secret::new("test-only-obfs"),
            },
        }
    }

    fn reality() -> RealityTransport {
        RealityTransport {
            settings: RealitySettings {
                client: RealityClientParams {
                    utls_fingerprint: UtlsFingerprint::Chrome,
                },
                endpoint: RealityEndpointParams {
                    target_domain: TargetDomain::parse("www.example.com").unwrap(),
                    public_key: RealityPublicKey::parse(
                        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    )
                    .unwrap(),
                    flow: VlessFlow::Vision,
                },
            },
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("0123456789abcdef"),
            },
        }
    }

    struct Fixture {
        hy2: Hysteria2Transport,
        reality: RealityTransport,
        hy2_addr: ActiveEndpointBypass,
        reality_addr: ActiveEndpointBypass,
        rules: Vec<RoutingRule>,
        device_key: Secret,
        server_key: String,
        control_secret: Secret,
    }

    fn fixture() -> Fixture {
        let hy2_at = EndpointAddress::new("203.0.113.9", 8443).unwrap();
        let reality_at = EndpointAddress::new("203.0.113.9", 443).unwrap();
        Fixture {
            hy2: hy2(),
            reality: reality(),
            hy2_addr: ActiveEndpointBypass::new(&hy2_at),
            reality_addr: ActiveEndpointBypass::new(&reality_at),
            rules: builtin_rules_for(Some(&hy2_at), Policy::Block),
            device_key: Secret::new(STANDARD.encode([1u8; 32])),
            server_key: STANDARD.encode([2u8; 32]),
            control_secret: Secret::new("c".repeat(64)),
        }
    }

    fn input<'a>(f: &'a Fixture, carriers: &'a [Carrier<'a>]) -> SessionInput<'a> {
        SessionInput {
            carriers,
            active: CarrierKind::Hysteria2,
            rules: &f.rules,
            fakeip: FakeIpHalf::Low,
            device_private_key: &f.device_key,
            server_public_key: &f.server_key,
            device_address: "10.9.0.2/32",
            session_port: 25182,
            control: ControlApi {
                port: 29090,
                secret: &f.control_secret,
            },
        }
    }

    fn both(f: &Fixture) -> [Carrier<'_>; 2] {
        [
            Carrier {
                transport: PrimaryTransport::Hysteria2(&f.hy2),
                endpoint: &f.hy2_addr,
                brutal: None,
            },
            Carrier {
                transport: PrimaryTransport::VlessReality(&f.reality),
                endpoint: &f.reality_addr,
                brutal: None,
            },
        ]
    }

    fn json(f: &Fixture, mutate: impl FnOnce(&mut SessionInput<'_>)) -> Value {
        let carriers = both(f);
        let mut i = input(f, &carriers);
        mutate(&mut i);
        serde_json::from_str(&to_json(&generate_session_config(i).unwrap())).unwrap()
    }

    /// Why a finished input is refused. The caller builds the input, so the references in it may live
    /// shorter than the fixture.
    fn refused(input: SessionInput<'_>) -> String {
        generate_session_config(input).unwrap_err().to_string()
    }

    #[test]
    fn the_session_is_an_endpoint_dialled_through_the_selector() {
        let f = fixture();
        let v = json(&f, |_| {});
        let endpoint = &v["endpoints"][0];
        assert_eq!(endpoint["type"], SESSION_ENDPOINT_TYPE);
        assert_eq!(SESSION_ENDPOINT_TYPE.len(), 9);
        assert_eq!(endpoint["tag"], SESSION_TAG);
        assert_eq!(endpoint["detour"], CARRIER_TAG);
        // The core refuses a listen port together with a detour.
        assert!(endpoint.get("listen_port").is_none());
        // User space: no adapter of its own.
        assert_eq!(endpoint["system"], false);
        let peer = &endpoint["peers"][0];
        assert_eq!(peer["address"], "127.0.0.1");
        assert_eq!(peer["port"], 25182);
        assert_eq!(peer["persistent_keepalive_interval"], KEEPALIVE_SECONDS);
        assert_eq!(v["endpoints"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_selector_lists_every_carrier_and_starts_on_the_active_one() {
        let f = fixture();
        let v = json(&f, |i| i.active = CarrierKind::Reality);
        let outbounds = v["outbounds"].as_array().unwrap();
        let selector = outbounds.iter().find(|o| o["type"] == "selector").unwrap();
        assert_eq!(selector["tag"], CARRIER_TAG);
        assert_eq!(selector["outbounds"], serde_json::json!(["hy2", "reality"]));
        assert_eq!(selector["default"], "reality");
        // A switch must never close the person's own streams.
        assert_eq!(selector["interrupt_exist_connections"], false);
        // Each carrier is its own leaf with the tag the selector names, dialling its own port.
        let leaf = |tag: &str| {
            outbounds
                .iter()
                .find(|o| o["tag"] == tag)
                .unwrap_or_else(|| panic!("no leaf {tag}"))
        };
        assert_eq!(leaf("hy2")["type"], "hysteria2");
        assert_eq!(leaf("hy2")["server_port"], 8443);
        assert_eq!(leaf("reality")["type"], "vless");
        assert_eq!(leaf("reality")["server_port"], 443);
    }

    #[test]
    fn tunnelled_traffic_ends_at_the_session_and_nothing_else_is_called_proxy() {
        let f = fixture();
        let v = json(&f, |_| {});
        assert_eq!(v["route"]["final"], SESSION_TAG);
        let named_proxy = v["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["tag"] == SESSION_TAG)
            .count();
        assert_eq!(named_proxy, 0, "an outbound shares the endpoint's tag");
        // The rules the person's routing rules produce still point at the tags they always did.
        assert!(v["route"]["rules"].as_array().unwrap().iter().all(|r| r
            .get("outbound")
            .is_none_or(|o| o == "direct" || o == SESSION_TAG)));
    }

    #[test]
    fn the_control_api_is_loopback_only_with_a_secret_and_an_impossible_origin() {
        let f = fixture();
        let v = json(&f, |_| {});
        let api = &v["experimental"]["clash_api"];
        assert_eq!(api["external_controller"], "127.0.0.1:29090");
        assert_eq!(api["secret"], "c".repeat(64));
        // One origin that cannot occur: an empty list would mean "allow all" in the pinned core.
        assert_eq!(
            api["access_control_allow_origin"],
            serde_json::json!([CONTROL_ORIGIN])
        );
        assert!(CONTROL_ORIGIN.ends_with(".invalid"));
    }

    #[test]
    fn a_weak_or_missing_control_secret_or_port_is_refused() {
        let f = fixture();
        let carriers = both(&f);
        let short = Secret::new("c".repeat(MIN_CONTROL_SECRET_LEN - 1));
        let empty = Secret::new("");
        for weak in [&short, &empty] {
            let mut i = input(&f, &carriers);
            i.control.secret = weak;
            let why = refused(i);
            assert!(why.contains("control secret"), "{why}");
        }
        let enough = Secret::new("c".repeat(MIN_CONTROL_SECRET_LEN));
        let mut ok = input(&f, &carriers);
        ok.control.secret = &enough;
        assert!(generate_session_config(ok).is_ok());
        let mut i = input(&f, &carriers);
        i.control.port = 0;
        let why = refused(i);
        assert!(why.contains("control port"), "{why}");
    }

    #[test]
    fn bad_keys_addresses_and_ports_are_refused_without_echoing_them() {
        let f = fixture();
        let carriers = both(&f);
        let not_base64 = Secret::new(DEVICE_KEY_TEXT);
        let short = Secret::new(STANDARD.encode([1u8; 31]));
        for bad in [&not_base64, &short] {
            let mut i = input(&f, &carriers);
            i.device_private_key = bad;
            let why = refused(i);
            assert!(why.contains("device key"), "{why}");
            assert!(!why.contains(DEVICE_KEY_TEXT), "{why}");
        }
        let mut i = input(&f, &carriers);
        i.server_public_key = "not a key";
        let why = refused(i);
        assert!(why.contains("server key"), "{why}");
        assert!(!why.contains("not a key"), "{why}");
        for address in ["10.9.0.2", "10.9.0.2/33", "nope/32", "10.9.0.2/x", ""] {
            let mut i = input(&f, &carriers);
            i.device_address = address;
            let why = refused(i);
            assert!(why.contains("device address"), "{address}: {why}");
        }
        let mut i = input(&f, &carriers);
        i.session_port = 0;
        let why = refused(i);
        assert!(why.contains("session port"), "{why}");
    }

    #[test]
    fn the_carrier_list_is_checked() {
        let f = fixture();
        let carriers = both(&f);
        assert!(refused(input(&f, &[])).contains("no carrier"));
        let twice = [carriers[0], carriers[0]];
        assert!(refused(input(&f, &twice)).contains("twice"));
        let only_reality = [carriers[1]];
        // `input` starts on Hysteria 2, which this list does not have.
        assert!(refused(input(&f, &only_reality)).contains("starting carrier"));
        // A single carrier is a session too: the ladder grows without a new configuration shape.
        let mut one = input(&f, &only_reality);
        one.active = CarrierKind::Reality;
        assert!(generate_session_config(one).is_ok());
    }

    #[test]
    fn the_output_is_deterministic_and_secrets_stay_out_of_debug() {
        let f = fixture();
        let carriers = both(&f);
        let a = generate_session_config(input(&f, &carriers)).unwrap();
        let b = generate_session_config(input(&f, &carriers)).unwrap();
        assert_eq!(to_json(&a), to_json(&b));
        let shown = format!("{a:?}");
        for secret in [
            STANDARD.encode([1u8; 32]),
            "c".repeat(64),
            "test-only-auth".to_string(),
            "test-only-obfs".to_string(),
            "bf000d23-0752-40b4-affe-68f7707a9661".to_string(),
        ] {
            assert!(!shown.contains(&secret), "a secret reached Debug");
        }
        // The file the core reads does hold them (it is the restricted config file).
        assert!(to_json(&a).contains(&"c".repeat(64)));
    }

    #[test]
    fn the_profiles_that_carry_traffic_themselves_gain_nothing() {
        let f = fixture();
        let profile = ConnectionProfile::new(
            ProfileId::new("b"),
            ProfileKind::Hysteria2,
            ProfileParams::new(),
        );
        let config = generate_primary_core_config(PrimaryCoreInput {
            active_profile: &profile,
            endpoint_bypass: &f.hy2_addr,
            rules: &f.rules,
            amneziawg_adapter: None,
            primary_transport: Some(PrimaryTransport::Hysteria2(&f.hy2)),
            fakeip: FakeIpHalf::Low,
        })
        .unwrap();
        let text = to_json(&config);
        for absent in [
            "\"endpoints\"",
            "\"experimental\"",
            "\"selector\"",
            "clash_api",
        ] {
            assert!(
                !text.contains(absent),
                "{absent} leaked into a plain profile"
            );
        }
    }

    // ---- a probe of one carrier through the session

    fn socks_auth() -> SocksAuth {
        SocksAuth {
            username: "probe-user".into(),
            password: Secret::new("probe-pass-0123456789"),
        }
    }

    fn probe_json(carrier_index: usize, edit: impl FnOnce(&mut SessionProbeInput<'_>)) -> Value {
        let f = fixture();
        let carriers = both(&f);
        let auth = socks_auth();
        let mut input = SessionProbeInput {
            socks_auth: &auth,
            carrier: carriers[carrier_index],
            device_private_key: &f.device_key,
            server_public_key: &f.server_key,
            device_address: "10.9.0.2/32",
            session_port: 25182,
            socks_port: 51234,
        };
        edit(&mut input);
        serde_json::from_str(&crate::probe::to_json(
            &generate_session_probe_config(input).unwrap(),
        ))
        .unwrap()
    }

    #[test]
    fn a_session_probe_is_the_session_over_the_one_carrier_under_test() {
        for (index, tag, kind) in [(0, "hy2", "hysteria2"), (1, "reality", "vless")] {
            let v = probe_json(index, |_| {});
            let outbounds = v["outbounds"].as_array().unwrap();
            assert_eq!(outbounds.len(), 1, "{tag}: only the carrier under test");
            assert_eq!(outbounds[0]["type"], kind);
            assert_eq!(outbounds[0]["tag"], tag);
            let endpoint = &v["endpoints"][0];
            assert_eq!(endpoint["type"], SESSION_ENDPOINT_TYPE);
            // Dialled through that one carrier, not through a selector: a probe never switches.
            assert_eq!(endpoint["detour"], tag);
            assert!(endpoint.get("listen_port").is_none());
            assert_eq!(v["route"]["final"], SESSION_TAG);
            assert_eq!(endpoint["tag"], SESSION_TAG);
        }
    }

    #[test]
    fn a_session_probe_keeps_every_invariant_a_probe_has() {
        let v = probe_json(0, |_| {});
        // A loopback proxy that demands a password, and nothing else listening.
        let inbounds = v["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["listen_port"], 51234);
        assert_eq!(inbounds[0]["users"].as_array().unwrap().len(), 1);
        assert_eq!(inbounds[0]["users"][0]["username"], "probe-user");
        // Nothing outside its own process: no tunnel, no capture, no control API.
        let text = v.to_string();
        for absent in [
            "\"tun\"",
            "auto_route",
            "hijack",
            "fakeip",
            "clash_api",
            "experimental",
        ] {
            assert!(!text.contains(absent), "a probe must not contain {absent}");
        }
        // Its own sockets follow the physical network, not an active tunnel.
        assert_eq!(v["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn a_session_probe_is_refused_for_the_things_a_probe_is_refused_for() {
        let f = fixture();
        let carriers = both(&f);
        let auth = socks_auth();
        let base = SessionProbeInput {
            socks_auth: &auth,
            carrier: carriers[0],
            device_private_key: &f.device_key,
            server_public_key: &f.server_key,
            device_address: "10.9.0.2/32",
            session_port: 25182,
            socks_port: 51234,
        };
        let no_user = SocksAuth {
            username: String::new(),
            password: Secret::new("x"),
        };
        let no_password = SocksAuth {
            username: "u".into(),
            password: Secret::new(""),
        };
        let bad_key = Secret::new("not a key");
        for (label, input, expected) in [
            (
                "port zero",
                SessionProbeInput {
                    socks_port: 0,
                    ..base
                },
                ConfigError::InvalidProbePort,
            ),
            (
                "no proxy user",
                SessionProbeInput {
                    socks_auth: &no_user,
                    ..base
                },
                ConfigError::InvalidCredential("probe proxy username"),
            ),
            (
                "no proxy password",
                SessionProbeInput {
                    socks_auth: &no_password,
                    ..base
                },
                ConfigError::InvalidCredential("probe proxy password"),
            ),
            (
                "a device key that is not a key",
                SessionProbeInput {
                    device_private_key: &bad_key,
                    ..base
                },
                ConfigError::InvalidSession("the device key is not 32 bytes of base64"),
            ),
            (
                "a server key that is not a key",
                SessionProbeInput {
                    server_public_key: "AAAA",
                    ..base
                },
                ConfigError::InvalidSession("the server key is not 32 bytes of base64"),
            ),
            (
                "an address that is not a CIDR",
                SessionProbeInput {
                    device_address: "10.9.0.2",
                    ..base
                },
                ConfigError::InvalidSession("the device address is not a CIDR"),
            ),
            (
                "a session port of zero",
                SessionProbeInput {
                    session_port: 0,
                    ..base
                },
                ConfigError::InvalidSession("the session port is zero"),
            ),
        ] {
            assert_eq!(
                generate_session_probe_config(input).unwrap_err(),
                expected,
                "{label}"
            );
        }
        assert!(generate_session_probe_config(base).is_ok());
    }

    #[test]
    fn a_session_probe_hides_its_secrets_from_debug_and_is_deterministic() {
        let f = fixture();
        let carriers = both(&f);
        let auth = socks_auth();
        let input = SessionProbeInput {
            socks_auth: &auth,
            carrier: carriers[0],
            device_private_key: &f.device_key,
            server_public_key: &f.server_key,
            device_address: "10.9.0.2/32",
            session_port: 25182,
            socks_port: 51234,
        };
        let (a, b) = (
            generate_session_probe_config(input).unwrap(),
            generate_session_probe_config(input).unwrap(),
        );
        assert_eq!(crate::probe::to_json(&a), crate::probe::to_json(&b));
        let shown = format!("{a:?}");
        for secret in [
            STANDARD.encode([1u8; 32]),
            "probe-pass-0123456789".to_string(),
            "test-only-auth".to_string(),
        ] {
            assert!(!shown.contains(&secret), "a secret reached Debug");
        }
    }

    #[test]
    fn the_probes_that_use_a_carrier_directly_are_unchanged() {
        // The ordinary probe has no endpoint, and none appears in its output.
        let f = fixture();
        let profile = ConnectionProfile::new(
            ProfileId::new("b"),
            ProfileKind::Hysteria2,
            ProfileParams::new(),
        );
        let auth = socks_auth();
        let config = crate::probe::generate_probe_config(crate::probe::ProbeInput {
            socks_auth: &auth,
            profile: &profile,
            endpoint: &f.hy2_addr,
            transport: Some(PrimaryTransport::Hysteria2(&f.hy2)),
            socks_port: 51234,
        })
        .unwrap();
        assert!(!crate::probe::to_json(&config).contains("endpoints"));
    }
}

#[cfg(test)]
mod pinned_tests {
    use super::*;

    #[test]
    fn the_first_device_is_dot_two_and_each_next_one_is_one_higher() {
        assert_eq!(session_device_address(0), Ipv4Addr::new(10, 9, 0, 2));
        for i in 0..MAX_DEVICES {
            assert_eq!(
                session_device_address(i),
                Ipv4Addr::new(10, 9, 0, 2 + i as u8),
                "device {i}"
            );
        }
    }

    /// The server and the measurement origin are never a device's address.
    #[test]
    fn no_device_has_the_servers_address_or_the_origins() {
        for i in 0..MAX_DEVICES {
            let address = session_device_address(i);
            assert_ne!(address, SESSION_SERVER);
            assert_ne!(address, SESSION_ORIGIN);
        }
    }

    /// Whatever number is asked for, the answer is an address inside the session's range and never a panic.
    #[test]
    fn any_index_gives_an_address_in_the_session_and_never_panics() {
        for index in (0..=600usize).chain([usize::MAX, usize::MAX - 1, 1 << 40, 253, 254, 255, 256])
        {
            let address = session_device_address(index);
            assert_eq!(&address.octets()[..3], &[10, 9, 0], "index {index}");
            assert!(address.octets()[3] >= 2, "index {index}");
        }
    }

    #[test]
    fn indexes_past_the_range_all_give_the_last_address_and_do_not_wrap_back_to_a_real_device() {
        let last = Ipv4Addr::new(10, 9, 0, 255);
        for index in [253usize, 254, 255, 256, 1000, usize::MAX] {
            assert_eq!(session_device_address(index), last, "index {index}");
        }
        assert_eq!(session_device_address(252), Ipv4Addr::new(10, 9, 0, 254));
    }

    #[test]
    fn addresses_rise_with_the_index_until_the_range_ends() {
        let mut previous = session_device_address(0);
        for index in 1..=253usize {
            let now = session_device_address(index);
            assert!(now > previous, "index {index}");
            previous = now;
        }
    }

    #[test]
    fn exactly_the_addresses_of_the_eight_devices_are_device_addresses() {
        for host in 0..=255u8 {
            let address = Ipv4Addr::new(10, 9, 0, host);
            assert_eq!(
                is_device_address(address),
                (2..=9).contains(&host),
                "{address}"
            );
        }
        for other in [
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 9, 1, 2),
            Ipv4Addr::new(11, 9, 0, 2),
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(!is_device_address(other), "{other}");
        }
    }

    #[test]
    fn a_cidr_is_an_address_and_a_prefix_no_longer_than_the_family_allows() {
        for good in [
            "0.0.0.0/0",
            "10.9.0.2/32",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "::/0",
            "fd00::/8",
            "fd00::2/128",
            "2001:db8::/32",
        ] {
            assert!(is_cidr(good), "{good}");
        }
        for bad in [
            "10.9.0.2/33",
            "10.9.0.2/255",
            "fd00::2/129",
            "fd00::/200",
            "10.9.0.2",
            "10.9.0.2/",
            "/32",
            "/",
            "10.9.0.2/-1",
            "10.9.0.2/ 8",
            "10.9.0.2/8/8",
            "10.9.0/24",
            "not-an-address/8",
            "",
            "10.9.0.2/256",
            "10.9.0.2/1e1",
        ] {
            assert!(!is_cidr(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_prefix_limits_are_exact_on_both_sides_for_both_families() {
        assert!(is_cidr("10.0.0.1/32"));
        assert!(!is_cidr("10.0.0.1/33"));
        assert!(is_cidr("fd00::1/128"));
        assert!(!is_cidr("fd00::1/129"));
    }
}
