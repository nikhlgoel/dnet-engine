//! T056: the Hysteria 2 outbound for the primary core (CC-03, CC-04, CC-10; research.md §R2).
//!
//! Schema from the pinned core (`option/hysteria2.go`, `protocol/hysteria2/outbound.go` at
//! `0b89958`):
//!
//! - **BBR by default.** Hysteria 2 uses its Brutal congestion control if and only if
//!   `up_mbps`/`down_mbps` are present. They are emitted only through the [`crate::brutal`]
//!   gate. Otherwise they are absent and `bbr_profile` is set explicitly.
//! - **Obfuscation is mandatory.** The core accepts an outbound with no `obfs`, but then the
//!   handshake is a recognisable QUIC exchange, which this profile exists to avoid. The type
//!   makes an unobfuscated outbound unrepresentable. Salamander and Gecko are both supported by
//!   the pinned core (Gecko since 1.14.0; tuning is T067).
//! - **TLS is always on**, which the core requires, and certificate verification is never off
//!   (see [`crate::tls`]).
//! - **Chrome QUIC parroting** stays on unless the client parameters turn it off. With it on,
//!   the endpoint's certificate must be ECDSA or RSA, never Ed25519 (pinned core documentation).
//!   Provisioning must issue accordingly.
//!
//! Parameters are split the way ADR-0002 §5.4 splits them. Client parameters can change
//! without touching the endpoint; endpoint parameters cannot.

use serde::Serialize;

use dnet_core::profile::BrutalOptIn;

use crate::brutal::brutal_bandwidth;
use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;
use crate::secret::Secret;
use crate::tls::{OutboundTls, ServerTrust};

/// Smallest Gecko on-wire packet size accepted (ADR-0002 §5.4).
pub const GECKO_PACKET_SIZE_MIN: u16 = 256;
/// Largest Gecko on-wire packet size accepted: below the common path MTU once IP and UDP
/// headers are added (ADR-0002 §5.4).
pub const GECKO_PACKET_SIZE_MAX: u16 = 1400;

/// The BBR tuning profile used when Brutal is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BbrProfile {
    #[default]
    Standard,
    Conservative,
    Aggressive,
}

impl BbrProfile {
    fn as_str(self) -> &'static str {
        match self {
            BbrProfile::Standard => "standard",
            BbrProfile::Conservative => "conservative",
            BbrProfile::Aggressive => "aggressive",
        }
    }
}

/// Parameters the client may change alone (ADR-0002 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hysteria2ClientParams {
    pub bbr_profile: BbrProfile,
    /// Shape the QUIC handshake like Chrome's.
    pub chrome_parrot: bool,
}

impl Default for Hysteria2ClientParams {
    fn default() -> Self {
        Self {
            bbr_profile: BbrProfile::Standard,
            chrome_parrot: true,
        }
    }
}

/// The QUIC obfuscation layer. Both sides must use the same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hysteria2Obfs {
    Salamander,
    /// Salamander plus fragmentation of long-header packets into randomly sized, padded segments.
    Gecko {
        min_packet_size: u16,
        max_packet_size: u16,
    },
}

/// Parameters the endpoint must share (ADR-0002 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2EndpointParams {
    pub obfs: Hysteria2Obfs,
    pub trust: ServerTrust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Settings {
    pub client: Hysteria2ClientParams,
    pub endpoint: Hysteria2EndpointParams,
}

/// Credentials resolved from the credential store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Credentials {
    /// The user's authentication password, sent inside TLS.
    pub auth_password: Secret,
    /// The obfuscation pre-shared key.
    pub obfs_password: Secret,
}

/// Everything the Hysteria 2 outbound needs besides the endpoint address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Transport {
    pub settings: Hysteria2Settings,
    pub credentials: Hysteria2Credentials,
}

/// The generated `hysteria2` outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hysteria2Outbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    /// Present only when Brutal passed its gate. Absence yields BBR (CC-03). Always emitted
    /// together with `down_mbps` (CC-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
    pub obfs: ObfsSection,
    pub password: Secret,
    pub tls: OutboundTls,
    /// Only meaningful under BBR, so absent when Brutal is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbr_profile: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disable_chrome_parrot: bool,
}

/// The `obfs` object. The Gecko packet sizes are omitted for Salamander.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObfsSection {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub password: Secret,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_packet_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_packet_size: Option<u16>,
}

/// Build the Hysteria 2 outbound for `endpoint`.
pub fn hysteria2_outbound(
    tag: &str,
    endpoint: &ActiveEndpointBypass,
    transport: &Hysteria2Transport,
    brutal: Option<&BrutalOptIn>,
) -> Result<Hysteria2Outbound, ConfigError> {
    let Hysteria2Transport {
        settings,
        credentials,
    } = transport;
    validate_credentials(credentials)?;
    let obfs = obfs_section(settings.endpoint.obfs, &credentials.obfs_password)?;
    let tls = OutboundTls::verified_by(&settings.endpoint.trust)?;
    let bandwidth = brutal_bandwidth(brutal)?;

    Ok(Hysteria2Outbound {
        kind: "hysteria2",
        tag: tag.to_string(),
        server: endpoint.host().to_string(),
        server_port: endpoint.port(),
        up_mbps: bandwidth.map(|b| b.up_mbps),
        down_mbps: bandwidth.map(|b| b.down_mbps),
        obfs,
        password: credentials.auth_password.clone(),
        tls,
        bbr_profile: bandwidth
            .is_none()
            .then(|| settings.client.bbr_profile.as_str()),
        disable_chrome_parrot: !settings.client.chrome_parrot,
    })
}

/// Both passwords must be present and different. The core refuses an empty obfuscation
/// password. A shared value means one leak exposes both the obfuscation key and the account.
fn validate_credentials(credentials: &Hysteria2Credentials) -> Result<(), ConfigError> {
    if credentials.auth_password.expose().is_empty() {
        return Err(ConfigError::InvalidCredential("Hysteria 2 auth password"));
    }
    if credentials.obfs_password.expose().is_empty() {
        return Err(ConfigError::InvalidCredential(
            "Hysteria 2 obfuscation password",
        ));
    }
    if credentials.auth_password == credentials.obfs_password {
        return Err(ConfigError::InvalidCredential(
            "Hysteria 2 obfuscation password (must differ from the auth password)",
        ));
    }
    Ok(())
}

fn obfs_section(obfs: Hysteria2Obfs, password: &Secret) -> Result<ObfsSection, ConfigError> {
    let (kind, min_packet_size, max_packet_size) = match obfs {
        Hysteria2Obfs::Salamander => ("salamander", None, None),
        Hysteria2Obfs::Gecko {
            min_packet_size,
            max_packet_size,
        } => {
            let bounds = GECKO_PACKET_SIZE_MIN..=GECKO_PACKET_SIZE_MAX;
            if !bounds.contains(&min_packet_size)
                || !bounds.contains(&max_packet_size)
                || min_packet_size > max_packet_size
            {
                return Err(ConfigError::InvalidGeckoPacketSize);
            }
            ("gecko", Some(min_packet_size), Some(max_packet_size))
        }
    };
    Ok(ObfsSection {
        kind,
        password: password.clone(),
        min_packet_size,
        max_packet_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::endpoint::EndpointAddress;

    fn transport() -> Hysteria2Transport {
        Hysteria2Transport {
            settings: Hysteria2Settings {
                client: Hysteria2ClientParams::default(),
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PublicCa {
                        server_name: "edge.example.net".into(),
                    },
                },
            },
            credentials: Hysteria2Credentials {
                auth_password: Secret::new("auth"),
                obfs_password: Secret::new("obfs"),
            },
        }
    }

    fn build(t: &Hysteria2Transport) -> Result<Hysteria2Outbound, ConfigError> {
        let addr = EndpointAddress::new("edge.example.net", 8443).unwrap();
        hysteria2_outbound("proxy", &ActiveEndpointBypass::new(&addr), t, None)
    }

    #[test]
    fn defaults_are_bbr_standard_with_chrome_parroting() {
        let out = build(&transport()).unwrap();
        assert_eq!(out.bbr_profile, Some("standard"));
        assert!(!out.disable_chrome_parrot);
        assert_eq!((out.up_mbps, out.down_mbps), (None, None));
        assert_eq!(out.server_port, 8443);
    }

    #[test]
    fn client_params_reach_the_outbound() {
        let mut t = transport();
        t.settings.client = Hysteria2ClientParams {
            bbr_profile: BbrProfile::Conservative,
            chrome_parrot: false,
        };
        let json = serde_json::to_string(&build(&t).unwrap()).unwrap();
        assert!(json.contains("\"bbr_profile\":\"conservative\""));
        assert!(json.contains("\"disable_chrome_parrot\":true"));
    }

    #[test]
    fn gecko_bounds_are_inclusive() {
        let mut t = transport();
        t.settings.endpoint.obfs = Hysteria2Obfs::Gecko {
            min_packet_size: GECKO_PACKET_SIZE_MIN,
            max_packet_size: GECKO_PACKET_SIZE_MAX,
        };
        assert!(build(&t).is_ok());
        t.settings.endpoint.obfs = Hysteria2Obfs::Gecko {
            min_packet_size: 600,
            max_packet_size: 600,
        };
        assert!(build(&t).is_ok());
    }

    #[test]
    fn an_empty_auth_password_is_refused() {
        let mut t = transport();
        t.credentials.auth_password = Secret::new("");
        assert!(matches!(build(&t), Err(ConfigError::InvalidCredential(_))));
    }
}
