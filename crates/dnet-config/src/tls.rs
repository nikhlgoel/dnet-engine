//! Outbound TLS options for the primary core's Hysteria 2 and VLESS+REALITY outbounds.
//!
//! Schema from the pinned core (`option/tls.go` at `0b89958`). Two rules hold for every
//! outbound this crate emits:
//!
//! - **Certificate verification is never switched off.** There is no `insecure` field here at
//!   all. An endpoint with a self-signed certificate is trusted by pinning its public key,
//!   which the pinned core checks against the leaf certificate (`VerifyPublicKeySHA256`).
//! - **No `spoof` option is emitted.** TLS spoofing needs the packet-diversion driver, which
//!   is not built into or shipped with the core (ADR-0004 Finding 4).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;

use crate::error::ConfigError;
use crate::reality::{RealitySection, UtlsSection};
use dnet_core::hostname::is_dns_hostname;

/// How the client decides the endpoint's certificate is genuine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerTrust {
    /// A certificate issued by a public CA for `server_name`, checked against the system roots.
    PublicCa { server_name: String },
    /// A self-signed certificate, trusted because its public key hashes to `spki_sha256`: the
    /// SHA-256 of the DER `SubjectPublicKeyInfo`. `server_name` is sent as SNI.
    PinnedPublicKey {
        server_name: String,
        spki_sha256: [u8; 32],
    },
}

impl ServerTrust {
    pub fn server_name(&self) -> &str {
        match self {
            ServerTrust::PublicCa { server_name }
            | ServerTrust::PinnedPublicKey { server_name, .. } => server_name,
        }
    }
}

/// The `tls` object of an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutboundTls {
    pub enabled: bool,
    pub server_name: String,
    /// Standard base64, as the core expects. Empty unless the key is pinned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificate_public_key_sha256: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utls: Option<UtlsSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealitySection>,
}

impl OutboundTls {
    /// TLS verified by `trust`, for an outbound that authenticates its endpoint by certificate.
    pub(crate) fn verified_by(trust: &ServerTrust) -> Result<Self, ConfigError> {
        if !is_dns_hostname(trust.server_name()) {
            return Err(ConfigError::InvalidServerName);
        }
        let certificate_public_key_sha256 = match trust {
            ServerTrust::PublicCa { .. } => Vec::new(),
            ServerTrust::PinnedPublicKey { spki_sha256, .. } => vec![STANDARD.encode(spki_sha256)],
        };
        Ok(Self {
            enabled: true,
            server_name: trust.server_name().to_string(),
            certificate_public_key_sha256,
            utls: None,
            reality: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_ca_endpoint_pins_nothing() {
        let tls = OutboundTls::verified_by(&ServerTrust::PublicCa {
            server_name: "edge.example.net".into(),
        })
        .unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.server_name, "edge.example.net");
        assert!(tls.certificate_public_key_sha256.is_empty());
    }

    #[test]
    fn a_pinned_key_is_emitted_as_standard_base64() {
        let tls = OutboundTls::verified_by(&ServerTrust::PinnedPublicKey {
            server_name: "edge.example.net".into(),
            spki_sha256: [0xff; 32],
        })
        .unwrap();
        assert_eq!(
            tls.certificate_public_key_sha256,
            ["//////////////////////////////////////////8="]
        );
    }

    #[test]
    fn a_malformed_server_name_is_refused() {
        for server_name in ["", "203.0.113.9", "no_underscores.example"] {
            assert_eq!(
                OutboundTls::verified_by(&ServerTrust::PublicCa {
                    server_name: server_name.into()
                }),
                Err(ConfigError::InvalidServerName),
                "{server_name:?}"
            );
        }
    }

    #[test]
    fn no_insecure_or_spoof_key_is_ever_serialized() {
        let tls = OutboundTls::verified_by(&ServerTrust::PublicCa {
            server_name: "edge.example.net".into(),
        })
        .unwrap();
        let json = serde_json::to_string(&tls).unwrap();
        assert!(!json.contains("insecure") && !json.contains("spoof"));
    }
}
