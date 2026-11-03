//! T126 step 2 — what one connection needs, worked out as plain data.
//!
//! The real effects start cores, install routes and open pipes. Everything that decides *what* to
//! start is here instead, with no I/O, so it is tested on any machine and the Windows-only code that
//! carries it out stays thin: given an endpoint, a profile and the credentials stored for that
//! endpoint, this produces the primary core's configuration, the endpoint address everything is
//! derived from, and (for AmneziaWG) the peer to configure.
//!
//! **One address, one source.** The server port a profile dials is stored with that profile's
//! credentials (an `Endpoint` carries one port, but one host serves three protocols on three ports).
//! The host comes from the endpoint. Both go into a single [`ActiveEndpointBypass`], and the core's
//! `direct` rule, the host route and the peer address are all derived from it, so they cannot
//! disagree (the R4 loop guard, CC-05).
//!
//! **An address must be an IP literal for now.** A host *name* would have to be resolved before the
//! tunnel exists, on whatever resolver the network provides, and the answer would decide where the
//! host route points. That is a decision about name resolution and DNS leakage, not a detail, so a
//! name is refused with a message that says so rather than resolved quietly.
//!
//! **Secrets.** A [`TunnelPlan`] holds credentials (the generated configuration contains them), so
//! its `Debug` shows none of it and the configuration is exposed only to the code that writes the
//! restricted file for the core.

use std::net::{IpAddr, Ipv4Addr};

use dnet_config::amneziawg::{ObfuscationParams, PeerConfig, PrivateKey};
use dnet_config::credentials::EndpointCredentials;
use dnet_config::hysteria2::{Hysteria2ClientParams, Hysteria2Settings, Hysteria2Transport};
use dnet_config::primary::{
    generate_primary_core_config, to_json, FakeIpHalf, PrimaryCoreInput, PrimaryTransport,
};
use dnet_config::probe::SocksAuth;
use dnet_config::reality::{RealityClientParams, RealitySettings, RealityTransport};
use dnet_config::secret::Secret;
use dnet_config::secret_store::{SecretKey, SecretStore};
use dnet_config::session::{
    generate_session_config, Carrier as SessionCarrier, CarrierKind, ControlApi, SessionInput,
    SessionProbeInput, SESSION_PREFIX,
};
use dnet_config::ActiveEndpointBypass;
use dnet_core::builtin_rules::with_active_endpoint;
use dnet_core::endpoint::{Endpoint, EndpointAddress};
use dnet_core::feed::ClientDefinitions;
use dnet_core::profile::{Carrier, ConnectionProfile, CoreBinding, ProfileKind};
use dnet_core::rule::RoutingRule;
use dnet_core::session::FailureCause;
use dnet_probe::runner::ProbeJob;

use crate::session_switch::{pick_control_port, ControlSecret};

/// The AmneziaWG adapter's name. It is also the leaf of the core's control pipe.
pub const AMNEZIAWG_ADAPTER: &str = "dnet-awg0";

/// Why a connection could not be planned. The text is for the user: it says what is wrong with the
/// configuration and never carries a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(String);

impl PlanError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    pub fn detail(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<PlanError> for FailureCause {
    fn from(error: PlanError) -> Self {
        FailureCause::ConfigurationInvalid { detail: error.0 }
    }
}

/// The AmneziaWG tunnel's own parameters: what is configured on the adapter and the peer.
#[derive(Clone)]
pub struct AwgTunnel {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub private_key: PrivateKey,
    pub obfuscation: ObfuscationParams,
    pub peer: PeerConfig,
}

/// Everything one connection needs.
pub struct TunnelPlan {
    /// Which core carries the profile. An AmneziaWG profile also needs the primary core.
    pub core: CoreBinding,
    /// The endpoint's address, as dialled: its host and the profile's server port.
    pub bypass: ActiveEndpointBypass,
    /// Present for an AmneziaWG profile only.
    pub awg: Option<AwgTunnel>,
    /// Present when the connection is a session over carriers (ADR-0008): how to reach the core's control API
    /// and which carriers it holds, so that the carrier can be switched without ending the connection.
    pub session: Option<SessionInfo>,
    /// The primary core's configuration. **Contains credentials.**
    config_json: String,
}

/// How the service reaches one core's control API: a loopback port and a secret made for this connection alone.
/// The secret is also written into the core's restricted configuration file; nowhere else.
#[derive(Clone)]
pub struct ControlChannel {
    pub port: u16,
    pub secret: ControlSecret,
}

impl ControlChannel {
    /// A free loopback port and a fresh secret.
    pub fn fresh() -> Result<Self, PlanError> {
        Ok(Self {
            port: pick_control_port().map_err(|_| {
                PlanError::new("no loopback port was available for the core's control")
            })?,
            secret: ControlSecret::generate().map_err(|_| {
                PlanError::new("no randomness was available for the core's control")
            })?,
        })
    }
}

impl std::fmt::Debug for ControlChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ControlChannel {{ port: {}, secret: <redacted> }}",
            self.port
        )
    }
}

/// What a session connection holds besides its configuration. Read by the carrier switch (T169 step e), which
/// is not wired yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub control: ControlChannel,
    /// The carriers in the core's selector, in the order they were given.
    pub carriers: Vec<CarrierKind>,
    /// The carrier the session starts on.
    pub active: CarrierKind,
}

impl TunnelPlan {
    /// The primary core's configuration, to be written to a file only the service can read.
    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    /// A plan with no real configuration, for tests of what carries a plan out.
    #[cfg(test)]
    pub fn for_tests(
        core: CoreBinding,
        bypass: ActiveEndpointBypass,
        awg: Option<AwgTunnel>,
    ) -> Self {
        Self {
            core,
            bypass,
            awg,
            session: None,
            config_json: "{}".into(),
        }
    }
}

impl std::fmt::Debug for TunnelPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelPlan")
            .field("core", &self.core)
            .field("bypass", &self.bypass)
            .field("awg", &self.awg.as_ref().map(|_| "<tunnel parameters>"))
            .field("session", &self.session)
            .field("config_json", &"<redacted>")
            .finish()
    }
}

/// The endpoint's address as `profile` dials it: the endpoint's host and the profile's own port.
fn dialled(
    endpoint: &Endpoint,
    profile: &ConnectionProfile,
    credentials: &EndpointCredentials,
) -> Result<(Ipv4Addr, ActiveEndpointBypass), PlanError> {
    let port = server_port(profile.kind(), credentials).ok_or_else(|| {
        PlanError::new(format!(
            "endpoint '{}' has no credentials for the {} profile; add them or choose another profile",
            endpoint.label(),
            kind_name(profile.kind())
        ))
    })?;
    let host = endpoint.address().host();
    let ip = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip,
        Ok(IpAddr::V6(_)) => {
            return Err(PlanError::new(format!(
                "endpoint '{}' is an IPv6 address, which is not supported yet; use an IPv4 address",
                endpoint.label()
            )))
        }
        Err(_) => {
            return Err(PlanError::new(format!(
                "endpoint '{}' is a host name; connecting by name is not supported yet because the \
                 name would have to be resolved before the tunnel exists. Use its IP address",
                endpoint.label()
            )))
        }
    };
    let address = EndpointAddress::new(ip.to_string(), port)
        .map_err(|_| PlanError::new("the endpoint address is not valid"))?;
    Ok((ip, ActiveEndpointBypass::new(&address)))
}

/// The port the server of `kind` listens on, if the endpoint has credentials for it.
pub fn server_port(kind: ProfileKind, credentials: &EndpointCredentials) -> Option<u16> {
    match kind {
        ProfileKind::AmneziaWg => credentials.amneziawg.as_ref().map(|a| a.server_port),
        ProfileKind::Hysteria2 => credentials.hysteria2.as_ref().map(|h| h.server_port),
        ProfileKind::VlessReality => credentials.reality.as_ref().map(|r| r.server_port),
    }
}

/// Where a profile's probes and live checks fetch from. A profile carried by the session is measured at the
/// session's origin (an address inside the session, reachable only through it); AmneziaWG, and an endpoint
/// set up before the session existed, keep the origin stored with the endpoint.
pub fn origin_for(
    kind: ProfileKind,
    credentials: &EndpointCredentials,
) -> Option<dnet_core::origin::Origin> {
    if kind != ProfileKind::AmneziaWg && credentials.session.is_some() {
        return Some(dnet_provision::bootstrap::session_measurement_origin());
    }
    credentials.measure_origin.clone()
}

/// Where the profiles of a race are measured. A race covers the profiles a proxy can probe (never AmneziaWG),
/// so on an endpoint with a session it is the session's origin, and otherwise the one stored with the endpoint.
pub fn race_origin(credentials: &EndpointCredentials) -> Option<dnet_core::origin::Origin> {
    origin_for(ProfileKind::Hysteria2, credentials)
}

/// Whether a connection of `kind` to an endpoint with these credentials is a session over carriers.
pub fn carried_by_session(kind: ProfileKind, credentials: &EndpointCredentials) -> bool {
    kind != ProfileKind::AmneziaWg && credentials.session.is_some()
}

/// The ports the pre-connect reachability check may touch: the ports of profiles carried over TCP,
/// and no others.
///
/// A TCP connection to a port that only serves UDP (AmneziaWG, Hysteria 2) tells nothing the check
/// can use, and it is a burst of unusual traffic to the endpoint, from a client that has not yet
/// started hiding anything, which a network observer could use to recognise this software. The
/// REALITY port is different: that server answers a bare TCP connection like the ordinary web
/// server it imitates. With no TCP profile there is nothing to try, and the answer is "unknown".
pub fn reach_ports(credentials: &EndpointCredentials) -> Vec<u16> {
    [
        ProfileKind::AmneziaWg,
        ProfileKind::Hysteria2,
        ProfileKind::VlessReality,
    ]
    .into_iter()
    .filter(|kind| kind.carrier() == Carrier::Tcp)
    .filter_map(|kind| server_port(kind, credentials))
    .collect()
}

fn kind_name(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::AmneziaWg => "AmneziaWG",
        ProfileKind::Hysteria2 => "Hysteria 2",
        ProfileKind::VlessReality => "VLESS+REALITY",
    }
}

/// The transport settings of a primary-core profile. Built here, owned by the caller, because
/// [`PrimaryTransport`] only borrows them.
pub enum OwnedTransport {
    Hysteria2(Hysteria2Transport),
    VlessReality(RealityTransport),
}

impl OwnedTransport {
    pub fn borrowed(&self) -> PrimaryTransport<'_> {
        match self {
            OwnedTransport::Hysteria2(t) => PrimaryTransport::Hysteria2(t),
            OwnedTransport::VlessReality(t) => PrimaryTransport::VlessReality(t),
        }
    }
}

/// The transport for a profile the primary core carries itself, or `None` for AmneziaWG (which has
/// its own core) or when the endpoint has no credentials for the profile.
///
/// `client` is what an applied profile feed says about the client-only parameters (ADR-0002 §6); where
/// it says nothing, the bundled defaults apply. The endpoint's own parameters always come from its
/// stored credentials.
pub fn primary_transport(
    kind: ProfileKind,
    credentials: &EndpointCredentials,
    client: &ClientDefinitions,
) -> Option<OwnedTransport> {
    match kind {
        ProfileKind::AmneziaWg => None,
        ProfileKind::Hysteria2 => credentials.hysteria2.as_ref().map(|bundle| {
            OwnedTransport::Hysteria2(Hysteria2Transport {
                settings: Hysteria2Settings {
                    client: hysteria2_client(client),
                    endpoint: bundle.endpoint.clone(),
                },
                credentials: bundle.credentials.clone(),
            })
        }),
        ProfileKind::VlessReality => credentials.reality.as_ref().map(|bundle| {
            OwnedTransport::VlessReality(RealityTransport {
                settings: RealitySettings {
                    client: reality_client(client),
                    endpoint: bundle.endpoint.clone(),
                },
                credentials: bundle.credentials.clone(),
            })
        }),
    }
}

/// Hysteria 2's client parameters: the feed's where it gave one, the bundled default where not.
fn hysteria2_client(client: &ClientDefinitions) -> Hysteria2ClientParams {
    let bundled = Hysteria2ClientParams::default();
    Hysteria2ClientParams {
        bbr_profile: client.hysteria2.bbr_profile.unwrap_or(bundled.bbr_profile),
        chrome_parrot: client
            .hysteria2
            .chrome_parrot
            .unwrap_or(bundled.chrome_parrot),
    }
}

/// REALITY's client parameters: the feed's where it gave one, the bundled default where not.
fn reality_client(client: &ClientDefinitions) -> RealityClientParams {
    RealityClientParams {
        utls_fingerprint: client
            .reality
            .utls_fingerprint
            .unwrap_or(RealityClientParams::default().utls_fingerprint),
    }
}

/// The endpoints a connection can actually use, and why each of the others cannot.
#[derive(Debug)]
pub struct Assessment {
    /// In their original order.
    pub usable: Vec<Endpoint>,
    /// One sentence per unusable endpoint, written for the user. Never carries a credential.
    pub problems: Vec<String>,
    /// The kinds of profile that at least one usable endpoint has credentials for.
    pub served: Vec<ProfileKind>,
}

/// The profiles worth offering the engine: those some usable endpoint can actually serve.
///
/// A profile no endpoint has credentials for cannot be tested or started, and offering it anyway
/// makes the engine race it, fail it for lack of a reply, and tell the user it was *blocked*: a
/// statement about their network that is false (nothing was ever sent). With no usable endpoint
/// at all the list is returned whole, because the connect fails with the configuration problem
/// before any profile matters.
pub fn served_profiles(
    profiles: Vec<ConnectionProfile>,
    served: &[ProfileKind],
) -> Vec<ConnectionProfile> {
    if served.is_empty() {
        return profiles;
    }
    profiles
        .into_iter()
        .filter(|profile| served.contains(&profile.kind()))
        .collect()
}

/// Decide, once at start-up, which of `endpoints` a connection can use: its credentials are stored
/// and readable, they name a measurement origin, and its host is an address the service can route
/// to. The credentials are read to check this and **not kept**.
///
/// An endpoint that fails any of these is left out of what the engine is given, and the reason is
/// reported. Leaving it in would let the engine choose it and fail midway, after a race, with a
/// message about something the user could have been told before connecting.
pub fn assess_endpoints(endpoints: &[Endpoint], secrets: &dyn SecretStore) -> Assessment {
    let mut usable = Vec::new();
    let mut problems = Vec::new();
    let mut served: Vec<ProfileKind> = Vec::new();
    for endpoint in endpoints {
        match endpoint_kinds(endpoint, secrets) {
            Ok(kinds) => {
                usable.push(endpoint.clone());
                for kind in kinds {
                    if !served.contains(&kind) {
                        served.push(kind);
                    }
                }
            }
            Err(problem) => problems.push(problem),
        }
    }
    Assessment {
        usable,
        problems,
        served,
    }
}

/// The kinds of profile `endpoint` can be used with, or why it cannot be used at all.
fn endpoint_kinds(
    endpoint: &Endpoint,
    secrets: &dyn SecretStore,
) -> Result<Vec<ProfileKind>, String> {
    if let Some(problem) = endpoint_problem(endpoint, secrets) {
        return Err(problem);
    }
    // `endpoint_problem` read these successfully a moment ago.
    let kinds = SecretKey::parse(endpoint.credentials())
        .ok()
        .and_then(|key| secrets.get(&key).ok().flatten())
        .map(|credentials| {
            [
                ProfileKind::AmneziaWg,
                ProfileKind::Hysteria2,
                ProfileKind::VlessReality,
            ]
            .into_iter()
            .filter(|kind| server_port(*kind, &credentials).is_some())
            .collect()
        })
        .unwrap_or_default();
    Ok(kinds)
}

fn endpoint_problem(endpoint: &Endpoint, secrets: &dyn SecretStore) -> Option<String> {
    let label = endpoint.label();
    let key = match SecretKey::parse(endpoint.credentials()) {
        Ok(key) => key,
        Err(_) => {
            return Some(format!(
                "endpoint '{label}' refers to its credentials in a form that is not valid"
            ))
        }
    };
    let credentials = match secrets.get(&key) {
        Ok(Some(credentials)) => credentials,
        Ok(None) => {
            return Some(format!(
                "endpoint '{label}' has no credentials stored; import or provision them"
            ))
        }
        // The store's error names the key and the reason, never a byte of the credentials.
        Err(error) => {
            return Some(format!(
                "endpoint '{label}': its credentials could not be read ({error})"
            ))
        }
    };
    if credentials.measure_origin.is_none() {
        return Some(format!(
            "endpoint '{label}' has no measurement origin; without one a connection cannot be \
             tested, and this project provides none to fall back on"
        ));
    }
    match endpoint.address().host().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => None,
        Ok(IpAddr::V6(_)) => Some(format!(
            "endpoint '{label}' is an IPv6 address, which is not supported yet; use an IPv4 address"
        )),
        Err(_) => Some(format!(
            "endpoint '{label}' is a host name; connecting by name is not supported yet because \
             the name would have to be resolved before the tunnel exists. Use its IP address"
        )),
    }
}

/// The job that probes `profile` against `endpoint`, with its SOCKS proxy on `socks_port`.
///
/// AmneziaWG cannot be probed through a proxy (it needs an adapter of its own), so it has no job:
/// asking for one is an error, not an empty probe that would read as a failed profile.
pub fn probe_job(
    profile: &ConnectionProfile,
    endpoint: &Endpoint,
    credentials: &EndpointCredentials,
    client: &ClientDefinitions,
    socks_port: u16,
) -> Result<ProbeJob, PlanError> {
    let (_, bypass) = dialled(endpoint, profile, credentials)?;
    let transport = primary_transport(profile.kind(), credentials, client).ok_or_else(|| {
        PlanError::new(format!(
            "the {} profile cannot be tested through a proxy",
            kind_name(profile.kind())
        ))
    })?;
    // A server that serves the session forwards its carriers to the session and nothing else, so it is
    // probed the way it will be used: the session over the one carrier under test.
    if let (true, Some(session)) = (
        carried_by_session(profile.kind(), credentials),
        credentials.session.as_ref(),
    ) {
        // Replaced by the job, which makes the proxy's credentials itself.
        let placeholder = SocksAuth {
            username: "x".into(),
            password: Secret::new("x"),
        };
        let device_address = format!("{}/{SESSION_PREFIX}", session.device_address);
        return ProbeJob::new_session(
            profile.clone(),
            SessionProbeInput {
                socks_auth: &placeholder,
                carrier: SessionCarrier {
                    transport: transport.borrowed(),
                    endpoint: &bypass,
                    brutal: profile.brutal(),
                },
                device_private_key: &session.device_private_key,
                server_public_key: &session.server_public_key,
                device_address: &device_address,
                session_port: session.session_port,
                socks_port,
            },
        )
        .map_err(|e| PlanError::new(format!("the connection could not be tested: {e}")));
    }
    ProbeJob::new(profile.clone(), &bypass, transport.borrowed(), socks_port)
        .map_err(|e| PlanError::new(format!("the connection could not be tested: {e}")))
}

/// Plan a connection of `profile` to `endpoint` with the credentials stored for that endpoint.
/// `fakeip` is the half of the FakeIP pools this tunnel hands out (T131).
pub fn plan_tunnel(
    profile: &ConnectionProfile,
    endpoint: &Endpoint,
    credentials: &EndpointCredentials,
    client: &ClientDefinitions,
    rules: &[RoutingRule],
    fakeip: FakeIpHalf,
) -> Result<TunnelPlan, PlanError> {
    plan_tunnel_with(
        PlanInputs {
            profile,
            endpoint,
            credentials,
            client,
            rules,
            fakeip,
        },
        None,
    )
}

/// Everything one connection is planned from.
#[derive(Clone, Copy)]
pub struct PlanInputs<'a> {
    pub profile: &'a ConnectionProfile,
    pub endpoint: &'a Endpoint,
    pub credentials: &'a EndpointCredentials,
    pub client: &'a ClientDefinitions,
    pub rules: &'a [RoutingRule],
    pub fakeip: FakeIpHalf,
}

/// [`plan_tunnel`] with the control channel given (a session connection makes a fresh one when it is `None`).
pub fn plan_tunnel_with(
    inputs: PlanInputs<'_>,
    control: Option<ControlChannel>,
) -> Result<TunnelPlan, PlanError> {
    let PlanInputs {
        profile,
        endpoint,
        credentials,
        client,
        rules,
        fakeip,
    } = inputs;
    let (endpoint_ip, bypass) = dialled(endpoint, profile, credentials)?;
    let transport = primary_transport(profile.kind(), credentials, client);
    // The rules held while disconnected have no endpoint to bypass. The tunnel's must: the core's
    // `direct` rule for the endpoint mirrors the host route, and the two must agree or the loop
    // returns (R4, CC-05). A set that cannot take it is not generated.
    let rules = with_active_endpoint(rules, endpoint.address()).map_err(|e| {
        PlanError::new(format!(
            "the routing rules could not be completed for this endpoint: {e}"
        ))
    })?;

    if carried_by_session(profile.kind(), credentials) {
        let control = match control {
            Some(control) => control,
            None => ControlChannel::fresh()?,
        };
        let (config, info) = session_config(
            PlanInputs {
                rules: &rules,
                ..inputs
            },
            endpoint_ip,
            control,
        )?;
        return Ok(TunnelPlan {
            core: profile.core_binding(),
            bypass,
            awg: None,
            session: Some(info),
            config_json: to_json(&config),
        });
    }

    let config = generate_primary_core_config(PrimaryCoreInput {
        active_profile: profile,
        endpoint_bypass: &bypass,
        rules: &rules,
        amneziawg_adapter: (profile.kind() == ProfileKind::AmneziaWg).then_some(AMNEZIAWG_ADAPTER),
        primary_transport: transport.as_ref().map(OwnedTransport::borrowed),
        fakeip,
    })
    // The generator's errors name what is wrong, not a value (config crate contract).
    .map_err(|e| PlanError::new(format!("the connection could not be configured: {e}")))?;

    let awg = match (profile.kind(), &credentials.amneziawg) {
        (ProfileKind::AmneziaWg, Some(a)) => Some(AwgTunnel {
            address: IpAddr::V4(a.client_address),
            prefix_len: a.prefix_len,
            private_key: a.client_private_key.clone(),
            obfuscation: a.obfuscation,
            peer: PeerConfig {
                public_key: a.server_public_key.clone(),
                endpoint: format!("{endpoint_ip}:{}", a.server_port),
                // Everything goes through the tunnel; the host route keeps the tunnel's own
                // packets off it.
                allowed_ips: vec!["0.0.0.0/0".into()],
                persistent_keepalive: Some(25),
            },
        }),
        _ => None,
    };

    Ok(TunnelPlan {
        core: profile.core_binding(),
        bypass,
        awg,
        session: None,
        config_json: to_json(&config),
    })
}

/// The configuration of a session connection: every carrier the endpoint has (so the connection can move
/// between them without ending), starting on the one `profile` names.
fn session_config(
    inputs: PlanInputs<'_>,
    endpoint_ip: Ipv4Addr,
    control: ControlChannel,
) -> Result<(dnet_config::PrimaryCoreConfig, SessionInfo), PlanError> {
    let PlanInputs {
        profile,
        credentials,
        client,
        rules,
        fakeip,
        ..
    } = inputs;
    let session = credentials
        .session
        .as_ref()
        .ok_or_else(|| PlanError::new("the endpoint has no session"))?;
    let active = match profile.kind() {
        ProfileKind::Hysteria2 => CarrierKind::Hysteria2,
        ProfileKind::VlessReality => CarrierKind::Reality,
        ProfileKind::AmneziaWg => {
            return Err(PlanError::new("AmneziaWG does not run over the session"))
        }
    };

    // One leaf per carrier the endpoint has, each dialling its own port on the endpoint's host.
    struct Leaf {
        kind: CarrierKind,
        transport: OwnedTransport,
        bypass: ActiveEndpointBypass,
    }
    let mut leaves = Vec::new();
    for (kind, profile_kind) in [
        (CarrierKind::Hysteria2, ProfileKind::Hysteria2),
        (CarrierKind::Reality, ProfileKind::VlessReality),
    ] {
        let (Some(transport), Some(port)) = (
            primary_transport(profile_kind, credentials, client),
            server_port(profile_kind, credentials),
        ) else {
            continue;
        };
        let address = EndpointAddress::new(endpoint_ip.to_string(), port)
            .map_err(|_| PlanError::new("the endpoint address is not valid"))?;
        leaves.push(Leaf {
            kind,
            transport,
            bypass: ActiveEndpointBypass::new(&address),
        });
    }
    let carriers: Vec<SessionCarrier<'_>> = leaves
        .iter()
        .map(|leaf| SessionCarrier {
            transport: leaf.transport.borrowed(),
            endpoint: &leaf.bypass,
            // The person's opt-in applies to the Hysteria 2 carrier, and only while it is the chosen profile.
            brutal: (leaf.kind == CarrierKind::Hysteria2
                && profile.kind() == ProfileKind::Hysteria2)
                .then(|| profile.brutal())
                .flatten(),
        })
        .collect();

    let device_address = format!("{}/{SESSION_PREFIX}", session.device_address);
    let control_secret = control.secret.for_config();
    let config = generate_session_config(SessionInput {
        carriers: &carriers,
        active,
        rules,
        fakeip,
        device_private_key: &session.device_private_key,
        server_public_key: &session.server_public_key,
        device_address: &device_address,
        session_port: session.session_port,
        control: ControlApi {
            port: control.port,
            secret: &control_secret,
        },
    })
    .map_err(|e| PlanError::new(format!("the connection could not be configured: {e}")))?;

    let kinds = leaves.iter().map(|leaf| leaf.kind).collect();
    Ok((
        config,
        SessionInfo {
            control,
            carriers: kinds,
            active,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use dnet_config::credentials::{AmneziaWgCredentials, Hysteria2Bundle, RealityBundle};
    use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
    use dnet_config::reality::{
        RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
    };
    use dnet_config::secret::Secret;
    use dnet_config::tls::ServerTrust;
    use dnet_core::builtin_rules::builtin_rules;
    use dnet_core::credential::CredentialRef;
    use dnet_core::endpoint::EndpointOrigin;
    use dnet_core::ids::{EndpointId, ProfileId};
    use dnet_core::profile::ProfileParams;
    use serde_json::Value;

    /// Appears in every secret below. If it ever shows up in a `Debug` string or an error, a
    /// secret leaked.
    const SENTINEL: &str = "SENTINEL-6f1c0b7e";

    fn endpoint(host: &str) -> Endpoint {
        Endpoint::new(
            EndpointId::new(),
            "harness",
            EndpointAddress::new(host, 443).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new("endpoint-x"),
        )
        .unwrap()
    }

    fn profile(kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
    }

    fn credentials() -> EndpointCredentials {
        EndpointCredentials {
            amneziawg: Some(AmneziaWgCredentials {
                client_private_key: PrivateKey::new(format!("{:0>64}", "ab")),
                server_public_key: format!("{:0>64}", "cd"),
                client_address: Ipv4Addr::new(10, 66, 0, 2),
                prefix_len: 24,
                obfuscation: ObfuscationParams {
                    jc: 4,
                    jmin: 40,
                    jmax: 70,
                    s1: 15,
                    s2: 20,
                    h1: 1_053_421_987,
                    h2: 2_083_245_612,
                    h3: 3_175_921_403,
                    h4: 4_012_837_465,
                },
                server_port: 51820,
            }),
            hysteria2: Some(Hysteria2Bundle {
                server_port: 44443,
                credentials: Hysteria2Credentials {
                    auth_password: Secret::new(format!("auth-{SENTINEL}")),
                    obfs_password: Secret::new(format!("obfs-{SENTINEL}")),
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: "hy2.harness.test".into(),
                        spki_sha256: [7; 32],
                    },
                },
            }),
            measure_origin: Some(
                dnet_core::origin::Origin::parse("http://203.0.113.80:8080").unwrap(),
            ),
            reality: Some(RealityBundle {
                server_port: 8443,
                credentials: RealityCredentials {
                    uuid: Secret::new("123e4567-e89b-42d3-a456-426614174000"),
                    short_id: Secret::new("0123abcd"),
                },
                endpoint: RealityEndpointParams {
                    target_domain: TargetDomain::parse("www.example.com").unwrap(),
                    public_key: RealityPublicKey::parse(
                        "c2VjcmV0LXB1YmxpYy1rZXktMzItYnl0ZXMhISEhISE",
                    )
                    .unwrap(),
                    flow: VlessFlow::Vision,
                },
            }),
            session: None,
        }
    }

    fn plan(kind: ProfileKind, host: &str) -> Result<TunnelPlan, PlanError> {
        plan_tunnel(
            &profile(kind),
            &endpoint(host),
            &credentials(),
            &ClientDefinitions::default(),
            &builtin_rules(None),
            FakeIpHalf::Low,
        )
    }

    /// T105: a profile with Brutal on (as `EnableBrutal` leaves it) reaches the core with both directions;
    /// without it the core gets no bandwidth at all, which is BBR (CC-03, CC-04).
    #[test]
    fn brutal_reaches_the_core_only_when_it_is_on() {
        let off = to_json_text(&plan(ProfileKind::Hysteria2, "203.0.113.10").unwrap());
        assert!(
            !off.contains("up_mbps") && !off.contains("down_mbps"),
            "{off}"
        );

        let mut hy2 = profile(ProfileKind::Hysteria2);
        hy2.enable_brutal(
            dnet_core::profile::BandwidthPair {
                up_mbps: 50,
                down_mbps: 200,
            },
            dnet_core::profile::BrutalAcknowledgement {
                warning_revision: dnet_core::profile::BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_790_000_000,
            },
        )
        .unwrap();
        let on = plan_tunnel(
            &hy2,
            &endpoint("203.0.113.10"),
            &credentials(),
            &ClientDefinitions::default(),
            &builtin_rules(None),
            FakeIpHalf::Low,
        )
        .unwrap();
        let outbound = json(&on)["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "hysteria2")
            .cloned()
            .expect("a Hysteria 2 outbound");
        assert_eq!(outbound["up_mbps"], 50);
        assert_eq!(outbound["down_mbps"], 200);
    }

    fn to_json_text(plan: &TunnelPlan) -> String {
        plan.config_json.clone()
    }

    #[test]
    fn the_planned_tunnel_hands_out_the_half_of_the_fakeip_pools_it_was_given() {
        for half in [FakeIpHalf::Low, FakeIpHalf::High] {
            let plan = plan_tunnel(
                &profile(ProfileKind::Hysteria2),
                &endpoint("203.0.113.10"),
                &credentials(),
                &ClientDefinitions::default(),
                &builtin_rules(None),
                half,
            )
            .unwrap();
            let json = json(&plan);
            let fakeip = json["dns"]["servers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["type"] == "fakeip")
                .expect("a fakeip server");
            assert_eq!(fakeip["inet4_range"], half.inet4());
            assert_eq!(fakeip["inet6_range"], half.inet6());
        }
    }

    fn json(plan: &TunnelPlan) -> Value {
        serde_json::from_str(plan.config_json()).expect("the generator emits JSON")
    }

    #[test]
    fn each_profile_dials_its_own_port_on_the_endpoints_host() {
        // The endpoint says 443; none of the three profiles listens there.
        for (kind, port) in [
            (ProfileKind::AmneziaWg, 51820),
            (ProfileKind::Hysteria2, 44443),
            (ProfileKind::VlessReality, 8443),
        ] {
            let plan = plan(kind, "203.0.113.10").unwrap();
            assert_eq!(plan.bypass.host(), "203.0.113.10", "{kind:?}");
            assert_eq!(plan.bypass.port(), port, "{kind:?}");
        }
    }

    #[test]
    fn a_primary_core_profile_carries_its_own_outbound_and_no_amneziawg_parameters() {
        for (kind, outbound) in [
            (ProfileKind::Hysteria2, "hysteria2"),
            (ProfileKind::VlessReality, "vless"),
        ] {
            let plan = plan(kind, "203.0.113.10").unwrap();
            assert!(plan.awg.is_none());
            assert_eq!(plan.core, CoreBinding::PrimaryCore);
            let config = json(&plan);
            assert_eq!(config["outbounds"][0]["type"], outbound);
            assert_eq!(config["outbounds"][0]["server"], "203.0.113.10");
        }
    }

    #[test]
    fn amneziawg_binds_the_primary_core_to_its_adapter_and_configures_the_peer() {
        let plan = plan(ProfileKind::AmneziaWg, "203.0.113.10").unwrap();
        assert_eq!(plan.core, CoreBinding::AmneziaWgCore);
        assert_eq!(
            json(&plan)["outbounds"][0]["bind_interface"],
            AMNEZIAWG_ADAPTER
        );

        let awg = plan
            .awg
            .as_ref()
            .expect("AmneziaWG has a tunnel to configure");
        assert_eq!(awg.address, IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)));
        assert_eq!(awg.prefix_len, 24);
        assert_eq!(awg.peer.endpoint, "203.0.113.10:51820");
        assert_eq!(awg.peer.allowed_ips, ["0.0.0.0/0"]);
    }

    /// The host route is built from the same value as the peer's address. If these two ever
    /// differed, the packets to the endpoint would not take the route that keeps them off the
    /// tunnel, which is the loop.
    #[test]
    fn the_peer_address_and_the_bypass_are_the_same_address() {
        let plan = plan(ProfileKind::AmneziaWg, "203.0.113.10").unwrap();
        let peer = &plan.awg.as_ref().unwrap().peer.endpoint;
        assert_eq!(
            peer,
            &format!("{}:{}", plan.bypass.host(), plan.bypass.port())
        );
    }

    #[test]
    fn the_endpoint_bypass_is_in_the_generated_rules() {
        let plan = plan(ProfileKind::Hysteria2, "203.0.113.10").unwrap();
        let text = plan.config_json();
        assert!(text.contains("203.0.113.10"), "{text}");
        assert_eq!(json(&plan)["route"]["auto_detect_interface"], true);
    }

    /// The route table and the core's rules must agree (data-model §4, CC-05): the endpoint's own
    /// address is a `direct` route rule, ahead of every rule that could send it into the tunnel. Its
    /// appearing somewhere in the text (as the outbound's server) is not that.
    #[test]
    fn the_endpoint_bypass_is_a_direct_route_rule_ahead_of_the_rest() {
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            let plan = plan(kind, "203.0.113.10").unwrap();
            let rules = json(&plan)["route"]["rules"].as_array().unwrap().clone();
            let at = rules
                .iter()
                .position(|r| {
                    r["ip_cidr"]
                        .as_array()
                        .is_some_and(|c| c.iter().any(|x| x == "203.0.113.10/32"))
                })
                .unwrap_or_else(|| panic!("{kind:?}: no route rule for the endpoint: {rules:#?}"));
            assert_eq!(rules[at]["outbound"], "direct", "{kind:?}");
            // Only the DNS capture (which matches port 53 alone) may come before it.
            assert!(
                rules[..at].iter().all(|r| r["action"] == "hijack-dns"),
                "{kind:?}: {:#?}",
                &rules[..at]
            );
        }
    }

    #[test]
    fn a_host_name_is_refused_with_the_reason_rather_than_resolved() {
        let error = plan(ProfileKind::Hysteria2, "vpn.example.com").unwrap_err();
        assert!(error.detail().contains("host name"), "{error}");
        assert!(error.detail().contains("IP address"), "{error}");
        assert!(
            error.detail().contains("harness"),
            "names the endpoint: {error}"
        );
    }

    #[test]
    fn an_ipv6_address_is_refused_with_the_reason() {
        let error = plan(ProfileKind::Hysteria2, "2001:db8::1").unwrap_err();
        assert!(error.detail().contains("IPv6"), "{error}");
    }

    #[test]
    fn a_profile_the_endpoint_has_no_credentials_for_is_refused_by_name() {
        for (kind, name) in [
            (ProfileKind::AmneziaWg, "AmneziaWG"),
            (ProfileKind::Hysteria2, "Hysteria 2"),
            (ProfileKind::VlessReality, "VLESS+REALITY"),
        ] {
            let mut stored = credentials();
            match kind {
                ProfileKind::AmneziaWg => stored.amneziawg = None,
                ProfileKind::Hysteria2 => stored.hysteria2 = None,
                ProfileKind::VlessReality => stored.reality = None,
            }
            let error = plan_tunnel(
                &profile(kind),
                &endpoint("203.0.113.10"),
                &stored,
                &ClientDefinitions::default(),
                &builtin_rules(None),
                FakeIpHalf::Low,
            )
            .unwrap_err();
            assert!(error.detail().contains(name), "{kind:?}: {error}");
        }
    }

    #[test]
    fn a_failed_plan_becomes_the_configuration_cause() {
        let error = plan(ProfileKind::Hysteria2, "vpn.example.com").unwrap_err();
        let detail = error.detail().to_string();
        assert_eq!(
            FailureCause::from(error),
            FailureCause::ConfigurationInvalid { detail }
        );
    }

    #[test]
    fn nothing_that_is_printed_shows_a_credential() {
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            let plan = plan(kind, "203.0.113.10").unwrap();
            let shown = format!("{plan:?}");
            for secret in [SENTINEL, "123e4567", "0123abcd", &format!("{:0>64}", "ab")] {
                assert!(!shown.contains(secret), "{kind:?} leaked {secret}: {shown}");
            }
        }
        // The configuration is where they are, and that is the point of exposing it separately.
        let hy2 = plan(ProfileKind::Hysteria2, "203.0.113.10").unwrap();
        assert!(hy2.config_json().contains(SENTINEL));
    }

    #[test]
    fn planning_is_deterministic() {
        let (a, b) = (
            plan(ProfileKind::Hysteria2, "203.0.113.10").unwrap(),
            plan(ProfileKind::Hysteria2, "203.0.113.10").unwrap(),
        );
        assert_eq!(a.config_json(), b.config_json());
    }

    #[test]
    fn the_server_port_is_known_per_profile_and_absent_without_credentials() {
        let stored = credentials();
        assert_eq!(server_port(ProfileKind::AmneziaWg, &stored), Some(51820));
        assert_eq!(server_port(ProfileKind::Hysteria2, &stored), Some(44443));
        assert_eq!(server_port(ProfileKind::VlessReality, &stored), Some(8443));
        assert_eq!(
            server_port(ProfileKind::Hysteria2, &EndpointCredentials::default()),
            None
        );
    }

    #[test]
    fn the_reachability_check_touches_only_ports_that_carry_tcp() {
        assert_eq!(reach_ports(&credentials()), [8443]);

        let udp_only = EndpointCredentials {
            reality: None,
            ..credentials()
        };
        assert!(
            reach_ports(&udp_only).is_empty(),
            "a TCP connection to a UDP port must never be attempted"
        );
        assert!(reach_ports(&EndpointCredentials::default()).is_empty());
    }

    #[test]
    fn amneziawg_has_no_primary_transport() {
        let bundled = ClientDefinitions::default();
        assert!(primary_transport(ProfileKind::AmneziaWg, &credentials(), &bundled).is_none());
        assert!(primary_transport(ProfileKind::Hysteria2, &credentials(), &bundled).is_some());
        assert!(primary_transport(ProfileKind::VlessReality, &credentials(), &bundled).is_some());
    }

    // ------------------------------------------------------------------ the profile feed's client section

    fn from_a_feed() -> ClientDefinitions {
        use dnet_core::feed::document::{Hysteria2ClientProposal, RealityClientProposal};
        use dnet_core::transport_params::{BbrProfile, UtlsFingerprint};
        ClientDefinitions {
            hysteria2: Hysteria2ClientProposal {
                bbr_profile: Some(BbrProfile::Conservative),
                chrome_parrot: Some(false),
            },
            reality: RealityClientProposal {
                utls_fingerprint: Some(UtlsFingerprint::Firefox),
            },
            sequence: Some(5),
        }
    }

    /// The JSON with its whitespace removed, so a test can look for `"key":"value"`.
    fn compact(json: &str) -> String {
        json.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn planned_with(kind: ProfileKind, client: &ClientDefinitions) -> String {
        let plan = plan_tunnel(
            &profile(kind),
            &endpoint("203.0.113.10"),
            &credentials(),
            client,
            &builtin_rules(None),
            FakeIpHalf::Low,
        )
        .unwrap();
        compact(plan.config_json())
    }

    #[test]
    fn without_a_feed_the_bundled_client_parameters_are_used() {
        let bundled = ClientDefinitions::default();
        let hy2 = planned_with(ProfileKind::Hysteria2, &bundled);
        assert!(hy2.contains(r#""bbr_profile":"standard""#), "{hy2}");
        // Parroting Chrome is the default, and is expressed by saying nothing.
        assert!(!hy2.contains("disable_chrome_parrot"), "{hy2}");
        let reality = planned_with(ProfileKind::VlessReality, &bundled);
        assert!(reality.contains(r#""fingerprint":"chrome""#), "{reality}");
    }

    #[test]
    fn an_applied_feeds_client_parameters_reach_the_next_configuration() {
        let hy2 = planned_with(ProfileKind::Hysteria2, &from_a_feed());
        assert!(hy2.contains(r#""bbr_profile":"conservative""#), "{hy2}");
        assert!(hy2.contains(r#""disable_chrome_parrot":true"#), "{hy2}");
        let reality = planned_with(ProfileKind::VlessReality, &from_a_feed());
        assert!(reality.contains(r#""fingerprint":"firefox""#), "{reality}");
    }

    #[test]
    fn a_feed_never_changes_what_the_endpoint_is_told_to_share() {
        // The endpoint's own parameters come from its stored credentials, whatever the feed says.
        let with_feed = planned_with(ProfileKind::Hysteria2, &from_a_feed());
        let without = planned_with(ProfileKind::Hysteria2, &ClientDefinitions::default());
        for shared in ["obfs", "salamander", "server_name"] {
            assert_eq!(
                with_feed.contains(shared),
                without.contains(shared),
                "{shared}"
            );
        }
    }

    #[test]
    fn what_is_raced_is_what_will_run() {
        // A probe job and a tunnel both take their transport from `primary_transport`, so the race
        // measures a profile with the parameters the tunnel will then use; otherwise it would pick a
        // profile on the strength of a configuration nobody connects with.
        let Some(OwnedTransport::Hysteria2(transport)) =
            primary_transport(ProfileKind::Hysteria2, &credentials(), &from_a_feed())
        else {
            panic!("Hysteria 2 has a primary transport");
        };
        assert_eq!(
            transport.settings.client.bbr_profile,
            dnet_core::transport_params::BbrProfile::Conservative
        );
        assert!(!transport.settings.client.chrome_parrot);
        assert!(probe_job(
            &profile(ProfileKind::Hysteria2),
            &endpoint("203.0.113.10"),
            &credentials(),
            &from_a_feed(),
            51999,
        )
        .is_ok());
    }

    // ------------------------------------------------------------------ probe jobs

    fn job(kind: ProfileKind) -> Result<ProbeJob, PlanError> {
        probe_job(
            &profile(kind),
            &endpoint("203.0.113.10"),
            &credentials(),
            &ClientDefinitions::default(),
            51999,
        )
    }

    #[test]
    fn the_proxied_profiles_get_a_job_on_the_requested_port() {
        for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
            let job = job(kind).unwrap();
            assert_eq!(job.socks_port(), 51999);
            assert_eq!(job.profile().kind(), kind);
        }
    }

    #[test]
    fn amneziawg_has_no_probe_job_rather_than_an_empty_one() {
        let error = job(ProfileKind::AmneziaWg).unwrap_err();
        assert!(error.detail().contains("proxy"), "{error}");
    }

    #[test]
    fn a_probe_job_for_a_name_or_a_missing_credential_is_refused_like_a_tunnel() {
        let by_name = probe_job(
            &profile(ProfileKind::Hysteria2),
            &endpoint("vpn.example.com"),
            &credentials(),
            &ClientDefinitions::default(),
            51999,
        )
        .unwrap_err();
        assert!(by_name.detail().contains("host name"), "{by_name}");

        let none = probe_job(
            &profile(ProfileKind::Hysteria2),
            &endpoint("203.0.113.10"),
            &EndpointCredentials::default(),
            &ClientDefinitions::default(),
            51999,
        )
        .unwrap_err();
        assert!(none.detail().contains("Hysteria 2"), "{none}");
    }

    #[test]
    fn a_probe_job_never_shows_a_credential() {
        let shown = format!("{:?}", job(ProfileKind::Hysteria2).unwrap());
        assert!(!shown.contains(SENTINEL), "{shown}");
    }

    // ------------------------------------------------------------------ assessing endpoints

    use dnet_config::secret_store::MemorySecretStore;

    fn stored(
        label: &str,
        host: &str,
        credentials: Option<EndpointCredentials>,
    ) -> (Endpoint, MemorySecretStore) {
        let id = EndpointId::new();
        let key = SecretKey::for_endpoint(id);
        let secrets = MemorySecretStore::new();
        if let Some(credentials) = credentials {
            secrets.put(&key, &credentials).unwrap();
        }
        let endpoint = Endpoint::new(
            id,
            label,
            EndpointAddress::new(host, 443).unwrap(),
            EndpointOrigin::Manual,
            key.credential_ref(),
        )
        .unwrap();
        (endpoint, secrets)
    }

    #[test]
    fn an_endpoint_with_credentials_an_origin_and_an_address_is_usable() {
        let (endpoint, secrets) = stored("home", "203.0.113.10", Some(credentials()));
        let assessed = assess_endpoints(std::slice::from_ref(&endpoint), &secrets);
        assert_eq!(assessed.usable, [endpoint]);
        assert!(assessed.problems.is_empty());
    }

    #[test]
    fn each_way_an_endpoint_can_be_unusable_is_named_for_the_user() {
        let without_origin = EndpointCredentials {
            measure_origin: None,
            ..credentials()
        };
        let cases = [
            ("no-creds", "203.0.113.10", None, "no credentials stored"),
            (
                "no-origin",
                "203.0.113.10",
                Some(without_origin),
                "no measurement origin",
            ),
            (
                "by-name",
                "vpn.example.com",
                Some(credentials()),
                "host name",
            ),
            ("v6", "2001:db8::1", Some(credentials()), "IPv6"),
        ];
        for (label, host, creds, mention) in cases {
            let (endpoint, secrets) = stored(label, host, creds);
            let assessed = assess_endpoints(&[endpoint], &secrets);
            assert!(assessed.usable.is_empty(), "{label}");
            assert_eq!(assessed.problems.len(), 1, "{label}");
            assert!(
                assessed.problems[0].contains(mention),
                "{label}: {}",
                assessed.problems[0]
            );
            assert!(
                assessed.problems[0].contains(label),
                "names the endpoint: {}",
                assessed.problems[0]
            );
        }
    }

    #[test]
    fn usable_endpoints_keep_their_order_and_the_unusable_do_not_hide_them() {
        let (first, secrets_a) = stored("a", "203.0.113.1", Some(credentials()));
        let (broken, _) = stored("b", "203.0.113.2", None);
        let (last, secrets_c) = stored("c", "203.0.113.3", Some(credentials()));
        // One store holding both usable endpoints' credentials.
        let secrets = MemorySecretStore::new();
        for (endpoint, from) in [(&first, &secrets_a), (&last, &secrets_c)] {
            let key = SecretKey::parse(endpoint.credentials()).unwrap();
            secrets
                .put(&key, &from.get(&key).unwrap().unwrap())
                .unwrap();
        }

        let assessed = assess_endpoints(&[first.clone(), broken, last.clone()], &secrets);

        assert_eq!(assessed.usable, [first, last]);
        assert_eq!(assessed.problems.len(), 1);
    }

    #[test]
    fn the_kinds_an_endpoint_serves_are_the_kinds_it_has_credentials_for() {
        let only_awg = EndpointCredentials {
            hysteria2: None,
            reality: None,
            ..credentials()
        };
        let (endpoint, secrets) = stored("home", "203.0.113.10", Some(only_awg));
        let assessed = assess_endpoints(&[endpoint], &secrets);
        assert_eq!(assessed.served, [ProfileKind::AmneziaWg]);

        let (all, secrets) = stored("all", "203.0.113.11", Some(credentials()));
        assert_eq!(assess_endpoints(&[all], &secrets).served.len(), 3);
    }

    /// A profile no endpoint can serve is left out, so the engine cannot "block" a profile that
    /// was never tried.
    #[test]
    fn profiles_no_endpoint_serves_are_not_offered_to_the_engine() {
        let all = vec![
            profile(ProfileKind::AmneziaWg),
            profile(ProfileKind::Hysteria2),
            profile(ProfileKind::VlessReality),
        ];
        let kept = served_profiles(all.clone(), &[ProfileKind::AmneziaWg]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind(), ProfileKind::AmneziaWg);

        let kept = served_profiles(all, &[ProfileKind::Hysteria2, ProfileKind::VlessReality]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn with_nothing_served_every_profile_is_kept_so_the_real_problem_is_reported() {
        let all = vec![
            profile(ProfileKind::AmneziaWg),
            profile(ProfileKind::Hysteria2),
        ];
        assert_eq!(served_profiles(all, &[]).len(), 2);
    }

    #[test]
    fn no_endpoints_is_nothing_usable_and_nothing_wrong() {
        let assessed = assess_endpoints(&[], &MemorySecretStore::new());
        assert!(assessed.usable.is_empty() && assessed.problems.is_empty());
    }

    #[test]
    fn a_problem_never_shows_a_credential() {
        let (endpoint, secrets) = stored("home", "vpn.example.com", Some(credentials()));
        let text = assess_endpoints(&[endpoint], &secrets).problems.join(" ");
        assert!(!text.contains(SENTINEL), "{text}");
    }

    // ---------------------------------------------------------------- the session (ADR-0008, T169)

    fn session_bundle() -> dnet_config::credentials::SessionBundle {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        dnet_config::credentials::SessionBundle {
            device_private_key: Secret::new(STANDARD.encode([5u8; 32])),
            server_public_key: STANDARD.encode([6u8; 32]),
            device_address: Ipv4Addr::new(10, 9, 0, 2),
            session_port: 25182,
        }
    }

    fn with_session() -> EndpointCredentials {
        EndpointCredentials {
            session: Some(session_bundle()),
            ..credentials()
        }
    }

    fn control() -> ControlChannel {
        ControlChannel {
            port: 29090,
            secret: ControlSecret::new("k".repeat(64)).unwrap(),
        }
    }

    fn session_plan(kind: ProfileKind, credentials: &EndpointCredentials) -> TunnelPlan {
        plan_tunnel_with(
            PlanInputs {
                profile: &profile(kind),
                endpoint: &endpoint("203.0.113.10"),
                credentials,
                client: &ClientDefinitions::default(),
                rules: &builtin_rules(None),
                fakeip: FakeIpHalf::Low,
            },
            Some(control()),
        )
        .unwrap()
    }

    #[test]
    fn a_hysteria_2_or_reality_connection_to_an_endpoint_with_a_session_runs_over_the_session() {
        for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
            let plan = session_plan(kind, &with_session());
            let v = json(&plan);
            assert_eq!(v["endpoints"][0]["detour"], "carrier", "{kind:?}");
            assert_eq!(v["route"]["final"], "proxy", "{kind:?}");
            let info = plan.session.as_ref().expect("session information");
            assert_eq!(
                info.carriers,
                vec![CarrierKind::Hysteria2, CarrierKind::Reality]
            );
            assert_eq!(info.control.port, 29090);
        }
    }

    #[test]
    fn the_chosen_profile_is_the_carrier_the_session_starts_on() {
        let hy2 = session_plan(ProfileKind::Hysteria2, &with_session());
        let reality = session_plan(ProfileKind::VlessReality, &with_session());
        let default_of = |plan: &TunnelPlan| {
            json(plan)["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["type"] == "selector")
                .unwrap()["default"]
                .clone()
        };
        assert_eq!(default_of(&hy2), "hy2");
        assert_eq!(default_of(&reality), "reality");
        assert_eq!(hy2.session.unwrap().active, CarrierKind::Hysteria2);
        assert_eq!(reality.session.unwrap().active, CarrierKind::Reality);
    }

    #[test]
    fn each_carrier_dials_its_own_port_and_the_host_route_is_for_the_chosen_one() {
        let plan = session_plan(ProfileKind::VlessReality, &with_session());
        let outbounds = json(&plan)["outbounds"].clone();
        let port_of = |tag: &str| {
            outbounds
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == tag)
                .unwrap()["server_port"]
                .clone()
        };
        assert_eq!(port_of("hy2"), 44443);
        assert_eq!(port_of("reality"), 8443);
        assert_eq!(plan.bypass.host(), "203.0.113.10");
        assert_eq!(plan.bypass.port(), 8443);
    }

    #[test]
    fn an_endpoint_with_one_carrier_gets_a_session_over_just_that_one() {
        let mut only_reality = with_session();
        only_reality.hysteria2 = None;
        let plan = session_plan(ProfileKind::VlessReality, &only_reality);
        assert_eq!(
            plan.session.as_ref().unwrap().carriers,
            vec![CarrierKind::Reality]
        );
        let selector = json(&plan)["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "selector")
            .unwrap()
            .clone();
        assert_eq!(selector["outbounds"], serde_json::json!(["reality"]));
    }

    #[test]
    fn amneziawg_and_an_endpoint_without_a_session_keep_the_shape_they_always_had() {
        // AmneziaWG does not run over the session even when the endpoint has one.
        let awg = session_plan(ProfileKind::AmneziaWg, &with_session());
        assert!(awg.session.is_none() && awg.awg.is_some());
        assert!(!to_json_text(&awg).contains("endpoints"));
        // And an endpoint set up before the session existed is planned as before.
        for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
            let old = plan(kind, "203.0.113.10").unwrap();
            assert!(old.session.is_none(), "{kind:?}");
            let text = to_json_text(&old);
            for absent in ["\"endpoints\"", "\"selector\"", "clash_api"] {
                assert!(!text.contains(absent), "{kind:?}: {absent}");
            }
        }
    }

    #[test]
    fn what_is_written_into_the_core_is_what_the_service_will_send_to_it() {
        let plan = session_plan(ProfileKind::Hysteria2, &with_session());
        let api = &json(&plan)["experimental"]["clash_api"];
        assert_eq!(api["external_controller"], "127.0.0.1:29090");
        assert_eq!(api["secret"], "k".repeat(64));
    }

    #[test]
    fn a_session_connection_makes_a_fresh_control_channel_each_time() {
        let make = || {
            plan_tunnel(
                &profile(ProfileKind::Hysteria2),
                &endpoint("203.0.113.10"),
                &with_session(),
                &ClientDefinitions::default(),
                &builtin_rules(None),
                FakeIpHalf::Low,
            )
            .unwrap()
        };
        let (a, b) = (make(), make());
        let secret_of =
            |plan: &TunnelPlan| json(plan)["experimental"]["clash_api"]["secret"].clone();
        assert_ne!(secret_of(&a), secret_of(&b), "a secret was reused");
        assert_eq!(secret_of(&a).as_str().unwrap().len(), 64);
    }

    #[test]
    fn planning_a_session_with_the_same_control_channel_is_deterministic() {
        let a = session_plan(ProfileKind::Hysteria2, &with_session());
        let b = session_plan(ProfileKind::Hysteria2, &with_session());
        assert_eq!(to_json_text(&a), to_json_text(&b));
    }

    #[test]
    fn nothing_that_is_printed_about_a_session_plan_shows_a_secret() {
        let plan = session_plan(ProfileKind::Hysteria2, &with_session());
        let shown = format!("{plan:?} {:?}", plan.session);
        for secret in [SENTINEL.to_owned(), "k".repeat(16), {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine as _;
            STANDARD.encode([5u8; 32])
        }] {
            assert!(!shown.contains(&secret), "a secret was shown: {shown}");
        }
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn the_session_is_measured_at_its_own_origin_and_amneziawg_at_the_stored_one() {
        let creds = with_session();
        let session_origin = origin_for(ProfileKind::Hysteria2, &creds).unwrap();
        assert_eq!(session_origin.host(), "10.9.0.254");
        assert_eq!(
            origin_for(ProfileKind::VlessReality, &creds),
            Some(session_origin)
        );
        // AmneziaWG, and an endpoint with no session, keep the stored origin.
        let stored = creds.measure_origin.clone();
        assert_eq!(origin_for(ProfileKind::AmneziaWg, &creds), stored);
        assert_eq!(
            origin_for(ProfileKind::Hysteria2, &credentials()),
            credentials().measure_origin
        );
        assert!(carried_by_session(ProfileKind::Hysteria2, &creds));
        assert!(!carried_by_session(ProfileKind::AmneziaWg, &creds));
        assert!(!carried_by_session(ProfileKind::Hysteria2, &credentials()));
    }

    #[test]
    fn the_session_origin_is_tunnelled_by_the_rules_the_tunnel_is_given() {
        // The origin is a private address; the built-in rules must send it into the tunnel (found by running
        // the composed session), or a measurement through the session would never enter it.
        use dnet_core::rule_eval::{evaluate, Flow, Transport};
        let origin = origin_for(ProfileKind::Hysteria2, &with_session()).unwrap();
        let flow =
            Flow::to_address(origin.host().parse().unwrap()).on_port(origin.port(), Transport::Tcp);
        assert_eq!(
            evaluate(&builtin_rules(None), &flow).action,
            dnet_core::rule::RuleAction::Tunnel
        );
    }

    #[test]
    fn the_real_core_accepts_what_the_plan_produces_for_a_session() {
        let exe = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/primary-core/primary-core.exe");
        if !(cfg!(windows) && exe.is_file()) {
            eprintln!(
                "SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)"
            );
            return;
        }
        for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
            let plan = session_plan(kind, &with_session());
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("core.json");
            std::fs::write(&file, plan.config_json()).unwrap();
            let out = std::process::Command::new(&exe)
                .args(["check", "-c"])
                .arg(&file)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{kind:?}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // ------------------------------------------------------------------ probes through the session (T169)

    fn session_job_for(
        kind: ProfileKind,
        credentials: &EndpointCredentials,
    ) -> Result<ProbeJob, PlanError> {
        probe_job(
            &profile(kind),
            &endpoint("203.0.113.10"),
            credentials,
            &ClientDefinitions::default(),
            51999,
        )
    }

    #[test]
    fn an_endpoint_with_a_session_is_probed_through_it_over_the_one_carrier_under_test() {
        for (kind, tag, port) in [
            (ProfileKind::Hysteria2, "hy2", 44443),
            (ProfileKind::VlessReality, "reality", 8443),
        ] {
            let job = session_job_for(kind, &with_session()).unwrap();
            let config: Value = serde_json::from_str(job.config_json()).unwrap();
            assert_eq!(config["endpoints"][0]["detour"], tag, "{kind:?}");
            assert_eq!(config["outbounds"].as_array().unwrap().len(), 1, "{kind:?}");
            assert_eq!(config["outbounds"][0]["tag"], tag);
            assert_eq!(config["outbounds"][0]["server_port"], port);
            assert_eq!(config["inbounds"][0]["listen_port"], 51999);
            assert_eq!(config["route"]["final"], "proxy");
        }
    }

    #[test]
    fn an_endpoint_without_a_session_is_probed_as_it_always_was() {
        for kind in [ProfileKind::Hysteria2, ProfileKind::VlessReality] {
            let job = session_job_for(kind, &credentials()).unwrap();
            assert!(!job.config_json().contains("\"endpoints\""), "{kind:?}");
            let config: Value = serde_json::from_str(job.config_json()).unwrap();
            assert_eq!(config["outbounds"][0]["tag"], "proxy", "{kind:?}");
        }
    }

    #[test]
    fn amneziawg_is_still_not_probed_through_a_proxy_even_when_the_endpoint_has_a_session() {
        assert!(session_job_for(ProfileKind::AmneziaWg, &with_session()).is_err());
    }

    #[test]
    fn a_session_probe_for_a_carrier_the_endpoint_does_not_have_is_refused_by_name() {
        let mut only_reality = with_session();
        only_reality.hysteria2 = None;
        let error = session_job_for(ProfileKind::Hysteria2, &only_reality).unwrap_err();
        assert!(error.detail().contains("Hysteria 2"), "{error}");
        assert!(session_job_for(ProfileKind::VlessReality, &only_reality).is_ok());
    }

    #[test]
    fn a_session_probe_never_shows_a_credential_in_its_error_or_debug() {
        let job = session_job_for(ProfileKind::Hysteria2, &with_session()).unwrap();
        let shown = format!("{job:?}");
        assert!(
            !shown.contains(SENTINEL) && !shown.contains("endpoints"),
            "{shown}"
        );
        // The configuration itself holds them: it is for the restricted file (this keeps the checks above honest).
        assert!(job.config_json().contains(SENTINEL));
    }

    #[test]
    fn a_race_is_measured_at_the_sessions_origin_when_the_endpoint_has_one() {
        let session_origin = race_origin(&with_session()).unwrap();
        assert_eq!(session_origin.host(), "10.9.0.254");
        assert_eq!(session_origin.port(), 8080);
        // An endpoint without a session is measured where it always was.
        assert_eq!(race_origin(&credentials()), credentials().measure_origin);
        // And the answer is the same as for either carrier profile.
        assert_eq!(
            Some(session_origin.clone()),
            origin_for(ProfileKind::VlessReality, &with_session())
        );
    }

    fn brutal_hysteria2() -> ConnectionProfile {
        let mut hy2 = profile(ProfileKind::Hysteria2);
        hy2.enable_brutal(
            dnet_core::profile::BandwidthPair {
                up_mbps: 50,
                down_mbps: 200,
            },
            dnet_core::profile::BrutalAcknowledgement {
                warning_revision: dnet_core::profile::BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_757_635_200,
            },
        )
        .unwrap();
        hy2
    }

    #[test]
    fn the_brutal_opt_in_reaches_a_session_probe_and_a_session_tunnel_only_for_hysteria_2() {
        let creds = with_session();
        let hy2 = brutal_hysteria2();
        // The probe measures the profile as the tunnel will run it.
        let probe = probe_job(
            &hy2,
            &endpoint("203.0.113.10"),
            &creds,
            &ClientDefinitions::default(),
            51999,
        )
        .unwrap();
        assert!(
            probe.config_json().contains("up_mbps"),
            "the probe lost Brutal"
        );
        assert!(probe.config_json().contains("down_mbps"));
        let tunnel = plan_tunnel_with(
            PlanInputs {
                profile: &hy2,
                endpoint: &endpoint("203.0.113.10"),
                credentials: &creds,
                client: &ClientDefinitions::default(),
                rules: &builtin_rules(None),
                fakeip: FakeIpHalf::Low,
            },
            Some(control()),
        )
        .unwrap();
        assert!(
            tunnel.config_json().contains("up_mbps"),
            "the tunnel lost Brutal"
        );
        // Off: neither carries any bandwidth, which is the default congestion control.
        let plain = probe_job(
            &profile(ProfileKind::Hysteria2),
            &endpoint("203.0.113.10"),
            &creds,
            &ClientDefinitions::default(),
            51999,
        )
        .unwrap();
        assert!(!plain.config_json().contains("up_mbps"));
        // A REALITY connection never gets the Hysteria 2 carrier's Brutal, even with the carrier present.
        let reality = session_plan(ProfileKind::VlessReality, &creds);
        assert!(!reality.config_json().contains("up_mbps"));
    }
}
