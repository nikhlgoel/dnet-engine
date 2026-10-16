//! Probe configuration: one profile's transport behind a loopback SOCKS proxy, and nothing else.
//!
//! The daemon cannot bring up a TUN for each profile it wants to try: only one TUN can own the
//! routing table. A probe instead runs a separate core process whose only inbound is a SOCKS
//! proxy on `127.0.0.1`, and whose only outbound is the profile under test. The prober connects
//! through that proxy, moves some bytes, and measures (`dnet_core::probe`). Several probes can
//! run at once on different ports, which is what makes racing profiles possible.
//!
//! **Invariants** (each has a test):
//! - The inbound is SOCKS on loopback only. A probe that listened on a routable address would
//!   be an open proxy into the user's endpoint.
//! - There is no TUN, no route table change and no DNS capture: a probe touches nothing outside
//!   its own process.
//! - `route.auto_detect_interface` stays **on**. When a probe runs while a tunnel is already
//!   carrying traffic (re-probing after a block), the probe's own sockets would otherwise follow
//!   the TUN's default route into the active tunnel and measure the wrong path.
//! - AmneziaWG is refused: it needs an adapter, and there is no proxy to measure through.
//!
//! The credentials are in the output: write it only to a file the caller alone can read, and
//! log only the `Debug` form, which redacts them.

use serde::Serialize;

use dnet_core::profile::{ConnectionProfile, ProfileKind};

use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;
use crate::hysteria2::hysteria2_outbound;
use crate::primary::{Log, Outbound, PrimaryTransport};
use crate::reality::reality_outbound;
use crate::secret::Secret;

const PROXY_TAG: &str = "proxy";
const INBOUND_TAG: &str = "probe-in";
const LOCAL_DNS: &str = "local";
/// The only address a probe listens on.
pub const PROBE_LISTEN: &str = "127.0.0.1";

/// The username and password the probe's SOCKS proxy demands. Random per probe: the proxy
/// listens on loopback, but any local process could otherwise use it as a relay into the user's
/// endpoint, or answer in its place and feed the prober a fake measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksAuth {
    pub username: String,
    /// Redacted from `Debug`; written to the configuration file.
    pub password: Secret,
}

/// Everything needed to generate one probe configuration.
#[derive(Debug, Clone, Copy)]
pub struct ProbeInput<'a> {
    /// What the proxy demands of whoever connects to it. Both parts must be non-empty.
    pub socks_auth: &'a SocksAuth,
    /// The profile under test.
    pub profile: &'a ConnectionProfile,
    /// The endpoint it dials.
    pub endpoint: &'a ActiveEndpointBypass,
    /// Transport settings and credentials. Required, and of the matching kind.
    pub transport: Option<PrimaryTransport<'a>>,
    /// The loopback port the SOCKS proxy listens on. Non-zero.
    pub socks_port: u16,
}

/// The generated probe configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeConfig {
    pub log: Log,
    pub dns: ProbeDns,
    pub inbounds: Vec<SocksInbound>,
    pub outbounds: Vec<Outbound>,
    pub route: ProbeRoute,
}

/// A resolver for an endpoint given as a hostname. The probe has no FakeIP and no capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeDns {
    pub servers: Vec<ProbeDnsServer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeDnsServer {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocksInbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: &'static str,
    pub listen: &'static str,
    pub listen_port: u16,
    /// Always exactly one user: a proxy that asked for no credentials would be open.
    pub users: Vec<SocksUser>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocksUser {
    pub username: String,
    pub password: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeRoute {
    #[serde(rename = "final")]
    pub final_outbound: &'static str,
    /// Always `true`; see the module notes.
    pub auto_detect_interface: bool,
    pub default_domain_resolver: &'static str,
}

/// Generate the probe configuration for one profile.
pub fn generate_probe_config(input: ProbeInput<'_>) -> Result<ProbeConfig, ConfigError> {
    if input.socks_port == 0 {
        return Err(ConfigError::InvalidProbePort);
    }
    if input.socks_auth.username.is_empty() {
        return Err(ConfigError::InvalidCredential("probe proxy username"));
    }
    if input.socks_auth.password.expose().is_empty() {
        return Err(ConfigError::InvalidCredential("probe proxy password"));
    }
    let proxy = match (input.profile.kind(), input.transport) {
        (ProfileKind::AmneziaWg, _) => return Err(ConfigError::ProbeNeedsOwnAdapter),
        (ProfileKind::Hysteria2, Some(PrimaryTransport::Hysteria2(transport))) => {
            Outbound::Hysteria2(hysteria2_outbound(
                PROXY_TAG,
                input.endpoint,
                transport,
                input.profile.brutal(),
            )?)
        }
        (ProfileKind::VlessReality, Some(PrimaryTransport::VlessReality(transport))) => {
            Outbound::Vless(reality_outbound(PROXY_TAG, input.endpoint, transport)?)
        }
        (ProfileKind::Hysteria2, _) => return Err(ConfigError::MissingTransport("Hysteria 2")),
        (ProfileKind::VlessReality, _) => {
            return Err(ConfigError::MissingTransport("VLESS+REALITY"))
        }
    };
    Ok(ProbeConfig {
        log: Log {
            level: "info",
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
        outbounds: vec![proxy],
        route: ProbeRoute {
            final_outbound: PROXY_TAG,
            auto_detect_interface: true,
            default_domain_resolver: LOCAL_DNS,
        },
    })
}

/// Serialize to JSON. Deterministic for identical input. **Contains credentials.**
pub fn to_json(config: &ProbeConfig) -> String {
    serde_json::to_string_pretty(config).expect("ProbeConfig always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2::{
        Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs,
        Hysteria2Settings, Hysteria2Transport,
    };
    use crate::reality::{
        RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
        RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
    };
    use crate::tls::ServerTrust;
    use dnet_core::endpoint::EndpointAddress;
    use dnet_core::ids::ProfileId;
    use dnet_core::profile::ProfileParams;

    const AUTH: &str = "probe-test-auth-secret";
    const OBFS: &str = "probe-test-obfs-secret";
    const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
    const SHORT_ID: &str = "0123456789abcdef";

    fn hy2() -> Hysteria2Transport {
        Hysteria2Transport {
            settings: Hysteria2Settings {
                client: Hysteria2ClientParams::default(),
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: "hy2.harness.test".into(),
                        spki_sha256: [7; 32],
                    },
                },
            },
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(AUTH),
                obfs_password: Secret::new(OBFS),
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
                uuid: Secret::new(UUID),
                short_id: Secret::new(SHORT_ID),
            },
        }
    }

    const PROXY_USER: &str = "probe-user-1234";
    const PROXY_PASS: &str = "probe-pass-secret-5678";

    fn auth() -> SocksAuth {
        SocksAuth {
            username: PROXY_USER.into(),
            password: Secret::new(PROXY_PASS),
        }
    }

    fn profile(kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new("p"), kind, ProfileParams::new())
    }

    fn bypass(host: &str, port: u16) -> ActiveEndpointBypass {
        ActiveEndpointBypass::new(&EndpointAddress::new(host, port).unwrap())
    }

    fn hy2_config(port: u16) -> Result<ProbeConfig, ConfigError> {
        let (profile, endpoint, transport) = (
            profile(ProfileKind::Hysteria2),
            bypass("203.0.113.9", 44443),
            hy2(),
        );
        generate_probe_config(ProbeInput {
            socks_auth: &auth(),
            profile: &profile,
            endpoint: &endpoint,
            transport: Some(PrimaryTransport::Hysteria2(&transport)),
            socks_port: port,
        })
    }

    fn reality_config(port: u16) -> Result<ProbeConfig, ConfigError> {
        let (profile, endpoint, transport) = (
            profile(ProfileKind::VlessReality),
            bypass("203.0.113.9", 8443),
            reality(),
        );
        generate_probe_config(ProbeInput {
            socks_auth: &auth(),
            profile: &profile,
            endpoint: &endpoint,
            transport: Some(PrimaryTransport::VlessReality(&transport)),
            socks_port: port,
        })
    }

    #[test]
    fn the_only_inbound_is_socks_on_loopback() {
        for config in [hy2_config(51001).unwrap(), reality_config(51002).unwrap()] {
            assert_eq!(config.inbounds.len(), 1);
            let inbound = &config.inbounds[0];
            assert_eq!(inbound.kind, "socks");
            assert_eq!(inbound.listen, "127.0.0.1");
            assert_eq!(PROBE_LISTEN, "127.0.0.1");
        }
        assert_eq!(hy2_config(51001).unwrap().inbounds[0].listen_port, 51001);
    }

    /// A probe touches nothing outside its own process.
    #[test]
    fn there_is_no_tun_and_no_capture_anywhere_in_the_output() {
        for config in [hy2_config(51001).unwrap(), reality_config(51002).unwrap()] {
            let json = to_json(&config);
            for forbidden in ["\"tun\"", "auto_route", "hijack", "fakeip", "strict_route"] {
                assert!(
                    !json.contains(forbidden),
                    "{forbidden} must not appear: {json}"
                );
            }
        }
    }

    /// Without this, a re-probe while a tunnel is up would measure the active tunnel.
    #[test]
    fn the_probes_own_sockets_are_bound_to_the_physical_interface() {
        for config in [hy2_config(51001).unwrap(), reality_config(51002).unwrap()] {
            assert!(config.route.auto_detect_interface);
        }
    }

    #[test]
    fn the_profile_is_the_only_way_out() {
        let config = hy2_config(51001).unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert!(matches!(config.outbounds[0], Outbound::Hysteria2(_)));
        assert_eq!(config.route.final_outbound, "proxy");

        let config = reality_config(51002).unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert!(matches!(config.outbounds[0], Outbound::Vless(_)));
    }

    #[test]
    fn port_zero_is_refused() {
        assert_eq!(hy2_config(0), Err(ConfigError::InvalidProbePort));
        assert_eq!(reality_config(0), Err(ConfigError::InvalidProbePort));
    }

    #[test]
    fn amneziawg_cannot_be_probed_through_a_proxy() {
        let (profile, endpoint) = (
            profile(ProfileKind::AmneziaWg),
            bypass("203.0.113.9", 51820),
        );
        let result = generate_probe_config(ProbeInput {
            socks_auth: &auth(),
            profile: &profile,
            endpoint: &endpoint,
            transport: None,
            socks_port: 51003,
        });
        assert_eq!(result, Err(ConfigError::ProbeNeedsOwnAdapter));
    }

    #[test]
    fn missing_or_mismatched_transport_is_refused() {
        let (hy2_profile, endpoint) = (profile(ProfileKind::Hysteria2), bypass("203.0.113.9", 1));
        let none = generate_probe_config(ProbeInput {
            socks_auth: &auth(),
            profile: &hy2_profile,
            endpoint: &endpoint,
            transport: None,
            socks_port: 51004,
        });
        assert_eq!(none, Err(ConfigError::MissingTransport("Hysteria 2")));

        let reality = reality();
        let mismatched = generate_probe_config(ProbeInput {
            socks_auth: &auth(),
            profile: &hy2_profile,
            endpoint: &endpoint,
            transport: Some(PrimaryTransport::VlessReality(&reality)),
            socks_port: 51004,
        });
        assert_eq!(mismatched, Err(ConfigError::MissingTransport("Hysteria 2")));
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(
            to_json(&hy2_config(51001).unwrap()),
            to_json(&hy2_config(51001).unwrap())
        );
        assert_ne!(
            to_json(&hy2_config(51001).unwrap()),
            to_json(&hy2_config(51009).unwrap())
        );
    }

    /// The Debug form is what gets logged: it must not carry a credential.
    #[test]
    fn debug_output_redacts_every_credential() {
        let shown = format!(
            "{:?}{:?}",
            hy2_config(51001).unwrap(),
            reality_config(51002).unwrap()
        );
        for secret in [AUTH, OBFS, UUID, SHORT_ID, PROXY_PASS] {
            assert!(!shown.contains(secret), "{secret} leaked into Debug output");
        }
    }

    #[test]
    fn the_proxy_demands_the_credentials_it_was_given() {
        let config = hy2_config(51001).unwrap();
        let users = &config.inbounds[0].users;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, PROXY_USER);
        let json = to_json(&config);
        assert!(json.contains(PROXY_USER) && json.contains(PROXY_PASS));
    }

    #[test]
    fn an_empty_proxy_username_or_password_is_refused() {
        let (profile, endpoint, transport) = (
            profile(ProfileKind::Hysteria2),
            bypass("203.0.113.9", 44443),
            hy2(),
        );
        for bad in [
            SocksAuth {
                username: String::new(),
                password: Secret::new("x"),
            },
            SocksAuth {
                username: "u".into(),
                password: Secret::new(""),
            },
        ] {
            let result = generate_probe_config(ProbeInput {
                socks_auth: &bad,
                profile: &profile,
                endpoint: &endpoint,
                transport: Some(PrimaryTransport::Hysteria2(&transport)),
                socks_port: 51001,
            });
            assert!(
                matches!(result, Err(ConfigError::InvalidCredential(_))),
                "{result:?}"
            );
        }
    }

    #[test]
    fn the_file_form_does_carry_the_credentials_the_core_needs() {
        let json = to_json(&hy2_config(51001).unwrap());
        assert!(json.contains(AUTH) && json.contains(OBFS));
    }
}
