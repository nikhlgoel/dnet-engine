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
    generate_primary_core_config, to_json, PrimaryCoreInput, PrimaryTransport,
};
use dnet_config::reality::{RealityClientParams, RealitySettings, RealityTransport};
use dnet_config::secret_store::{SecretKey, SecretStore};
use dnet_config::ActiveEndpointBypass;
use dnet_core::endpoint::{Endpoint, EndpointAddress};
use dnet_core::profile::{Carrier, ConnectionProfile, CoreBinding, ProfileKind};
use dnet_core::rule::RoutingRule;
use dnet_core::session::FailureCause;
use dnet_probe::runner::ProbeJob;

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
    /// The primary core's configuration. **Contains credentials.**
    config_json: String,
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
pub fn primary_transport(
    kind: ProfileKind,
    credentials: &EndpointCredentials,
) -> Option<OwnedTransport> {
    match kind {
        ProfileKind::AmneziaWg => None,
        ProfileKind::Hysteria2 => credentials.hysteria2.as_ref().map(|bundle| {
            OwnedTransport::Hysteria2(Hysteria2Transport {
                settings: Hysteria2Settings {
                    client: Hysteria2ClientParams::default(),
                    endpoint: bundle.endpoint.clone(),
                },
                credentials: bundle.credentials.clone(),
            })
        }),
        ProfileKind::VlessReality => credentials.reality.as_ref().map(|bundle| {
            OwnedTransport::VlessReality(RealityTransport {
                settings: RealitySettings {
                    client: RealityClientParams::default(),
                    endpoint: bundle.endpoint.clone(),
                },
                credentials: bundle.credentials.clone(),
            })
        }),
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
    socks_port: u16,
) -> Result<ProbeJob, PlanError> {
    let (_, bypass) = dialled(endpoint, profile, credentials)?;
    let transport = primary_transport(profile.kind(), credentials).ok_or_else(|| {
        PlanError::new(format!(
            "the {} profile cannot be tested through a proxy",
            kind_name(profile.kind())
        ))
    })?;
    ProbeJob::new(profile.clone(), &bypass, transport.borrowed(), socks_port)
        .map_err(|e| PlanError::new(format!("the connection could not be tested: {e}")))
}

/// Plan a connection of `profile` to `endpoint` with the credentials stored for that endpoint.
pub fn plan_tunnel(
    profile: &ConnectionProfile,
    endpoint: &Endpoint,
    credentials: &EndpointCredentials,
    rules: &[RoutingRule],
) -> Result<TunnelPlan, PlanError> {
    let (endpoint_ip, bypass) = dialled(endpoint, profile, credentials)?;
    let transport = primary_transport(profile.kind(), credentials);

    let config = generate_primary_core_config(PrimaryCoreInput {
        active_profile: profile,
        endpoint_bypass: &bypass,
        rules,
        amneziawg_adapter: (profile.kind() == ProfileKind::AmneziaWg).then_some(AMNEZIAWG_ADAPTER),
        primary_transport: transport.as_ref().map(OwnedTransport::borrowed),
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
        config_json: to_json(&config),
    })
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
        }
    }

    fn plan(kind: ProfileKind, host: &str) -> Result<TunnelPlan, PlanError> {
        plan_tunnel(
            &profile(kind),
            &endpoint(host),
            &credentials(),
            &builtin_rules(None),
        )
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
                &builtin_rules(None),
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
        assert!(primary_transport(ProfileKind::AmneziaWg, &credentials()).is_none());
        assert!(primary_transport(ProfileKind::Hysteria2, &credentials()).is_some());
        assert!(primary_transport(ProfileKind::VlessReality, &credentials()).is_some());
    }

    // ------------------------------------------------------------------ probe jobs

    fn job(kind: ProfileKind) -> Result<ProbeJob, PlanError> {
        probe_job(
            &profile(kind),
            &endpoint("203.0.113.10"),
            &credentials(),
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
            51999,
        )
        .unwrap_err();
        assert!(by_name.detail().contains("host name"), "{by_name}");

        let none = probe_job(
            &profile(ProfileKind::Hysteria2),
            &endpoint("203.0.113.10"),
            &EndpointCredentials::default(),
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
}
