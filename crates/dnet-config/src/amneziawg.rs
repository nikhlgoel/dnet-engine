//! T051 — AmneziaWG peer + obfuscation configuration (AW-04, AW-05, AWG-05, AWG-06).
//!
//! A WG-family peer configured **without** its AmneziaWG obfuscation parameters produces
//! a bare, unobfuscated handshake — exactly the signature this profile exists to avoid. So
//! the obfuscation parameters and the peer are built into a **single UAPI request**
//! here: `build_set_device` takes both and there is no way to produce a peer-only
//! request through this module (AW-04).
//!
//! The private key is a [`PrivateKey`] that redacts itself in `Debug`/`Display`, and is
//! only ever written to the UAPI wire form — never to a log, diagnostic, or disk
//! (AW-05, AWG-06).

use std::fmt;

use crate::error::ConfigError;
use crate::uapi::UapiRequest;

/// A private key that never prints its material. Only `expose_wire` yields the value,
/// and only the UAPI wire form calls it.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey(String);

impl PrivateKey {
    pub fn new(material: impl Into<String>) -> Self {
        Self(material.into())
    }

    /// The key material, for writing to the UAPI pipe only.
    pub fn expose_wire(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The remote peer (the endpoint's AmneziaWG server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// AmneziaWG obfuscation parameters. Their presence is what makes the handshake *not*
/// look like a bare WG handshake; they are set on the device in the same request as the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObfuscationParams {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

/// Build the single UAPI `set_device` request that configures the private key, the
/// obfuscation parameters, and the peer — all together (AW-04). There is no separate
/// "configure peer" path, so a peer can never be configured without obfuscation.
pub fn build_set_device(
    private_key: &PrivateKey,
    obfuscation: &ObfuscationParams,
    peer: &PeerConfig,
) -> Result<UapiRequest, ConfigError> {
    if peer.public_key.trim().is_empty() || peer.endpoint.trim().is_empty() {
        return Err(ConfigError::IncompletePeer);
    }

    let mut req = UapiRequest::new();
    // Device-level: the private key (secret) and the obfuscation parameters. These come
    // before the peer, in the same request.
    req.push_secret("private_key", private_key.expose_wire());
    req.push("jc", obfuscation.jc.to_string())
        .push("jmin", obfuscation.jmin.to_string())
        .push("jmax", obfuscation.jmax.to_string())
        .push("s1", obfuscation.s1.to_string())
        .push("s2", obfuscation.s2.to_string())
        .push("h1", obfuscation.h1.to_string())
        .push("h2", obfuscation.h2.to_string())
        .push("h3", obfuscation.h3.to_string())
        .push("h4", obfuscation.h4.to_string());

    // Peer section: public_key begins it, then its attributes.
    req.push("public_key", peer.public_key.clone())
        .push("endpoint", peer.endpoint.clone());
    for allowed in &peer.allowed_ips {
        req.push("allowed_ip", allowed.clone());
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        req.push("persistent_keepalive_interval", keepalive.to_string());
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obf() -> ObfuscationParams {
        ObfuscationParams {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 15,
            s2: 20,
            h1: 1,
            h2: 2,
            h3: 3,
            h4: 4,
        }
    }

    fn peer() -> PeerConfig {
        PeerConfig {
            public_key: "PEERPUB".into(),
            endpoint: "edge.example:51820".into(),
            allowed_ips: vec!["0.0.0.0/0".into()],
            persistent_keepalive: Some(25),
        }
    }

    #[test]
    fn a_peer_is_never_configured_without_obfuscation() {
        let req = build_set_device(&PrivateKey::new("SECRET"), &obf(), &peer()).unwrap();
        // Both the peer and the obfuscation live in the one request.
        assert!(req.has_key("public_key"));
        assert!(req.has_key("jc") && req.has_key("s1") && req.has_key("h4"));
    }

    #[test]
    fn an_incomplete_peer_is_rejected() {
        let mut p = peer();
        p.public_key = "  ".into();
        assert_eq!(
            build_set_device(&PrivateKey::new("SECRET"), &obf(), &p),
            Err(ConfigError::IncompletePeer)
        );
    }

    #[test]
    fn the_private_key_never_prints_itself() {
        let key = PrivateKey::new("TOPSECRETKEY");
        assert!(!format!("{key:?}").contains("TOPSECRETKEY"));
        assert!(!format!("{key}").contains("TOPSECRETKEY"));
        assert_eq!(key.expose_wire(), "TOPSECRETKEY");
    }
}
