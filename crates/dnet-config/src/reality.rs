//! T058: the VLESS+REALITY outbound for the primary core (CC-11; Research-Critique §4.3).
//!
//! REALITY borrows the TLS handshake of a real third-party site, the **target domain**. The
//! endpoint forwards anything that fails REALITY authentication to that site, so an active
//! probe sees the real site. The target has to be plausible and reachable from where the user
//! is, so it is **first-class configuration, validated, never a constant**. It becomes the
//! ClientHello `server_name`.
//!
//! Schema from the pinned core (`option/vless.go`, `option/tls.go`,
//! `common/tls/reality_client.go` at `0b89958`):
//!
//! - REALITY requires uTLS. The core refuses `reality` without `utls.enabled`, so both are
//!   always emitted together.
//! - `public_key` is 32 bytes in unpadded URL-safe base64. `short_id` is hex, at most 8 bytes.
//!   Both are checked here, so a malformed value fails generation rather than core start-up.
//! - No certificate options are emitted: REALITY authenticates the endpoint by its key.
//!
//! **Known risk.** The core's documentation warns that uTLS has had repeated fingerprinting
//! vulnerabilities (Research-Critique §6.2). The fingerprint is a client parameter so that it
//! can be changed without touching the endpoint (ADR-0002 §5.4).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

use dnet_core::hostname::validate_target_domain;
/// Shared with the profile feed, so feed values and generated values use one definition.
pub use dnet_core::transport_params::UtlsFingerprint;

use crate::endpoint_bypass::ActiveEndpointBypass;
use crate::error::ConfigError;
use crate::secret::Secret;
use crate::tls::OutboundTls;

/// Maximum REALITY short id, in bytes (pinned `reality_client.go`: an 8-byte array).
const SHORT_ID_MAX_BYTES: usize = 8;
/// Canonical text form of a UUID: 8-4-4-4-12 hex digits.
const UUID_TEXT_LEN: usize = 36;

/// The VLESS sub-protocol. The endpoint's user entry must name the same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    /// No flow: plain VLESS inside the REALITY tunnel.
    None,
    /// `xtls-rprx-vision`, which pads the inner TLS handshake so its lengths do not show through.
    Vision,
}

impl VlessFlow {
    fn as_str(self) -> Option<&'static str> {
        match self {
            VlessFlow::None => None,
            VlessFlow::Vision => Some("xtls-rprx-vision"),
        }
    }
}

/// The borrowed TLS target: a validated hostname, stored lower-case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDomain(String);

impl TargetDomain {
    /// Accept a multi-label DNS hostname that is not an IP literal, and not a name the
    /// built-in rules bypass around the tunnel (T031, ADR-0002 §5.4).
    pub fn parse(name: &str) -> Result<Self, ConfigError> {
        validate_target_domain(name)
            .map(Self)
            .map_err(ConfigError::InvalidTargetDomain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The endpoint's REALITY public key, as the core writes it (unpadded URL-safe base64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityPublicKey(String);

impl RealityPublicKey {
    /// Accept exactly 32 bytes in canonical unpadded URL-safe base64.
    pub fn parse(encoded: &str) -> Result<Self, ConfigError> {
        match URL_SAFE_NO_PAD.decode(encoded) {
            Ok(bytes) if bytes.len() == 32 => Ok(Self(encoded.to_string())),
            _ => Err(ConfigError::InvalidRealityPublicKey),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parameters the client may change alone (ADR-0002 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealityClientParams {
    pub utls_fingerprint: UtlsFingerprint,
}

/// Parameters the endpoint must share (ADR-0002 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityEndpointParams {
    pub target_domain: TargetDomain,
    pub public_key: RealityPublicKey,
    pub flow: VlessFlow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub client: RealityClientParams,
    pub endpoint: RealityEndpointParams,
}

/// Credentials resolved from the credential store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityCredentials {
    /// The VLESS user id.
    pub uuid: Secret,
    /// The REALITY short id: hex, 1 to 8 bytes.
    pub short_id: Secret,
}

/// Everything the VLESS+REALITY outbound needs besides the endpoint address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityTransport {
    pub settings: RealitySettings,
    pub credentials: RealityCredentials,
}

/// The `tls.utls` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UtlsSection {
    pub enabled: bool,
    pub fingerprint: &'static str,
}

/// The `tls.reality` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealitySection {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: Secret,
}

/// The generated `vless` outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VlessOutbound {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: Secret,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<&'static str>,
    pub tls: OutboundTls,
}

/// Build the VLESS+REALITY outbound for `endpoint`.
pub fn reality_outbound(
    tag: &str,
    endpoint: &ActiveEndpointBypass,
    transport: &RealityTransport,
) -> Result<VlessOutbound, ConfigError> {
    let RealityTransport {
        settings,
        credentials,
    } = transport;
    validate_uuid(&credentials.uuid)?;
    validate_short_id(&credentials.short_id)?;

    Ok(VlessOutbound {
        kind: "vless",
        tag: tag.to_string(),
        server: endpoint.host().to_string(),
        server_port: endpoint.port(),
        uuid: credentials.uuid.clone(),
        flow: settings.endpoint.flow.as_str(),
        tls: OutboundTls {
            enabled: true,
            server_name: settings.endpoint.target_domain.as_str().to_string(),
            certificate_public_key_sha256: Vec::new(),
            utls: Some(UtlsSection {
                enabled: true,
                fingerprint: settings.client.utls_fingerprint.as_str(),
            }),
            reality: Some(RealitySection {
                enabled: true,
                public_key: settings.endpoint.public_key.as_str().to_string(),
                short_id: credentials.short_id.clone(),
            }),
        },
    })
}

/// Require the canonical hyphenated form, so the value the core receives is unambiguous.
fn validate_uuid(uuid: &Secret) -> Result<(), ConfigError> {
    let text = uuid.expose();
    if text.len() == UUID_TEXT_LEN && uuid::Uuid::try_parse(text).is_ok() {
        Ok(())
    } else {
        Err(ConfigError::InvalidCredential("VLESS user id"))
    }
}

fn validate_short_id(short_id: &Secret) -> Result<(), ConfigError> {
    let text = short_id.expose();
    let valid = !text.is_empty()
        && text.len() % 2 == 0
        && text.len() <= SHORT_ID_MAX_BYTES * 2
        && text.bytes().all(|b| b.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidCredential("REALITY short id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_domain_is_normalised_to_lower_case() {
        assert_eq!(
            TargetDomain::parse("WWW.Example.COM").unwrap().as_str(),
            "www.example.com"
        );
    }

    #[test]
    fn a_target_domain_must_be_a_hostname() {
        for name in [
            "",
            "localhost",
            "203.0.113.9",
            "[2001:db8::1]",
            "exa mple.com",
        ] {
            assert_eq!(
                TargetDomain::parse(name),
                Err(ConfigError::InvalidTargetDomain("not a DNS hostname")),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_target_domain_may_not_be_a_bypassed_probe_host() {
        for name in [
            "msftconnecttest.com",
            "www.msftconnecttest.com",
            "dns.msftncsi.com",
        ] {
            assert!(
                matches!(
                    TargetDomain::parse(name),
                    Err(ConfigError::InvalidTargetDomain(_))
                ),
                "{name}"
            );
        }
        // A suffix match is by label, not by substring.
        assert!(TargetDomain::parse("notmsftncsi.com").is_ok());
    }

    #[test]
    fn a_public_key_is_32_bytes_of_unpadded_url_safe_base64() {
        let valid = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
        assert!(RealityPublicKey::parse(valid).is_ok());
        for bad in [
            "",
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0=", // padded
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI+T4E7RoLJS0",  // standard alphabet
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS",   // 31.x bytes
            "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS1",  // non-canonical trailing bits
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 35 bytes
        ] {
            assert_eq!(
                RealityPublicKey::parse(bad),
                Err(ConfigError::InvalidRealityPublicKey),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn short_ids_of_one_to_eight_bytes_are_accepted() {
        for id in ["00", "0123456789abcdef", "ABCDEF"] {
            assert!(validate_short_id(&Secret::new(id)).is_ok(), "{id}");
        }
    }

    #[test]
    fn only_the_canonical_uuid_form_is_accepted() {
        assert!(validate_uuid(&Secret::new("bf000d23-0752-40b4-affe-68f7707a9661")).is_ok());
        for bad in [
            "bf000d2307524 0b4affe68f7707a9661",
            "bf000d23075240b4affe68f7707a9661",
            "{bf000d23-0752-40b4-affe-68f7707a9661}",
            "urn:uuid:bf000d23-0752-40b4-affe-68f7707a9661",
        ] {
            assert!(validate_uuid(&Secret::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn no_flow_emits_no_flow_key() {
        let addr = dnet_core::endpoint::EndpointAddress::new("edge.example.net", 443).unwrap();
        let transport = RealityTransport {
            settings: RealitySettings {
                client: RealityClientParams::default(),
                endpoint: RealityEndpointParams {
                    target_domain: TargetDomain::parse("www.example.com").unwrap(),
                    public_key: RealityPublicKey::parse(
                        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    )
                    .unwrap(),
                    flow: VlessFlow::None,
                },
            },
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("01"),
            },
        };
        let out = reality_outbound("proxy", &ActiveEndpointBypass::new(&addr), &transport).unwrap();
        assert!(!serde_json::to_string(&out).unwrap().contains("flow"));
    }
}
