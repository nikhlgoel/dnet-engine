//! T124 — the secret material of one endpoint, and its stored form.
//!
//! An endpoint is reached through up to three profiles, and what each needs from the endpoint is
//! generated together when the endpoint is provisioned (T093) or imported (T097). So the secret
//! store keeps one bundle per endpoint, named by the endpoint's `CredentialRef`: the AmneziaWG
//! client key and obfuscation, the Hysteria 2 passwords with the obfuscation and certificate trust
//! they go with, and the REALITY user id and short id with the target and public key.
//!
//! Each profile has its own **server port** (one host serves AmneziaWG, Hysteria 2 and REALITY on
//! different ports and different protocols), so the port is stored with the profile credentials and
//! the orchestrator pairs it with the host of the endpoint. An `Endpoint` still carries one address,
//! host plus port as the data model gives it; the port there is not used to connect.
//!
//! The bundle also names the **measurement origin**: an `http://host:port` the endpoint's probes and
//! live checks fetch from, reachable only through the endpoint. It is not secret, but it is
//! provisioned with the endpoint and means nothing without it, so it is kept here. There is no
//! default and no shared host: this project operates no infrastructure to point at.
//!
//! The bundle holds the parameters the endpoint must share (ADR-0002 §5.4) beside the secrets, and
//! not in the profile: they are provisioned as a set, and a client that applied one alone would
//! no longer match its server. The parameters the client may change alone stay with the profile.
//!
//! **This module's plaintext form contains secrets.** It exists only to be sealed by a secret store
//! and is never logged, sent over IPC or written beside the configuration. `Debug` redacts every
//! secret field. The form is strict: a field it does not know, a value the generators would refuse,
//! or a version it does not understand fails the whole bundle, because a half-read credential set
//! is a connection that fails in a way nobody can explain.

use std::net::Ipv4Addr;

use dnet_core::hostname::is_dns_hostname;
use dnet_core::origin::Origin;
use dnet_core::transport_params::gecko_packet_sizes_valid;
use serde::{Deserialize, Serialize};

use crate::amneziawg::{ObfuscationParams, PrivateKey};
use crate::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use crate::reality::{
    validate_short_id, validate_uuid, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    TargetDomain, VlessFlow,
};
use crate::secret::Secret;
use crate::tls::ServerTrust;

/// The newest version of the stored form this version reads and the one it writes when a bundle needs it.
/// Bumped on any change a reader of the old form would misread. Version 2 added the session (ADR-0008);
/// a bundle without one is still written as version 1, so a version that predates the session keeps reading
/// every bundle that does not need it, and says "version 2" about one that does.
pub const FORMAT_VERSION: u32 = 2;
/// The oldest version still read.
const OLDEST_VERSION: u32 = 1;

/// The largest stored form accepted, so a damaged or hostile blob cannot make the service allocate
/// without bound. A real bundle is about 1 KiB.
pub const MAX_STORED_LEN: usize = 16 * 1024;

/// Why a stored bundle was refused. Names the field at fault, never its value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialsError {
    #[error("the stored credentials are not in a form this version understands: {0}")]
    Malformed(String),
    #[error("the stored credentials use format version {found}; this version reads version {FORMAT_VERSION}")]
    UnsupportedVersion { found: u32 },
    #[error("the stored credentials are larger than {MAX_STORED_LEN} bytes")]
    TooLarge,
    #[error("the stored credentials have an invalid {0}")]
    Invalid(&'static str),
}

/// What AmneziaWG needs from an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziaWgCredentials {
    pub client_private_key: PrivateKey,
    /// The server's public key, 64 lowercase hex digits (the UAPI form).
    pub server_public_key: String,
    /// The client's address inside the tunnel.
    pub client_address: Ipv4Addr,
    pub prefix_len: u8,
    pub obfuscation: ObfuscationParams,
    /// The UDP port the AmneziaWG server listens on.
    pub server_port: u16,
}

/// What Hysteria 2 needs from an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Bundle {
    /// The UDP port the Hysteria 2 server listens on.
    pub server_port: u16,
    pub credentials: Hysteria2Credentials,
    pub endpoint: Hysteria2EndpointParams,
}

/// What VLESS+REALITY needs from an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityBundle {
    /// The TCP port the REALITY server listens on.
    pub server_port: u16,
    pub credentials: RealityCredentials,
    pub endpoint: RealityEndpointParams,
}

/// What the session needs from an endpoint (ADR-0008): this device's own key, the server's session key, and where
/// this device sits in the session. The session runs over the Hysteria 2 and REALITY carriers, so a bundle with a
/// session also has at least one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBundle {
    /// This device's private key, 32 bytes in standard base64. Made on this device and never sent anywhere; the
    /// server holds only the public half.
    pub device_private_key: Secret,
    /// The server's session public key, 32 bytes in standard base64.
    pub server_public_key: String,
    /// This device's address inside the session (one of the first [`crate::session::MAX_DEVICES`] after the server).
    pub device_address: Ipv4Addr,
    /// The UDP port the session listens on, on the server's own loopback, reached through a carrier.
    pub session_port: u16,
}

/// Everything secret about one endpoint. A profile the endpoint does not serve is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EndpointCredentials {
    pub amneziawg: Option<AmneziaWgCredentials>,
    pub hysteria2: Option<Hysteria2Bundle>,
    pub reality: Option<RealityBundle>,
    /// The session over the carriers (ADR-0008). `None` for an endpoint set up before it existed.
    pub session: Option<SessionBundle>,
    /// Where probes and live checks fetch from. Without it the endpoint can be stored but not
    /// measured, so a connect says so instead of guessing a target.
    pub measure_origin: Option<Origin>,
}

impl EndpointCredentials {
    /// Whether the bundle carries no profile, which no endpoint should. The origin alone does not
    /// make a bundle: there would be nothing to connect with.
    pub fn is_empty(&self) -> bool {
        self.amneziawg.is_none() && self.hysteria2.is_none() && self.reality.is_none()
    }

    /// The stored form, **with the secrets in clear**. Only a secret store calls this, to seal the
    /// result. Refuses a bundle the reader would refuse, so a store can never write what it cannot
    /// read back.
    pub fn to_plaintext_json(&self) -> Result<Vec<u8>, CredentialsError> {
        self.validate()?;
        let wire = Wire {
            // The lowest version that can hold this bundle.
            version: if self.session.is_some() {
                FORMAT_VERSION
            } else {
                OLDEST_VERSION
            },
            measure_origin: self
                .measure_origin
                .as_ref()
                .map(|o| format!("http://{}:{}", o.host(), o.port())),
            amneziawg: self.amneziawg.as_ref().map(|a| AwgWire {
                client_private_key: a.client_private_key.expose_wire().to_owned(),
                server_public_key: a.server_public_key.clone(),
                client_address: a.client_address,
                prefix_len: a.prefix_len,
                obfuscation: ObfuscationWire::from(a.obfuscation),
                server_port: a.server_port,
            }),
            hysteria2: self.hysteria2.as_ref().map(|h| Hy2Wire {
                server_port: h.server_port,
                auth_password: h.credentials.auth_password.expose().to_owned(),
                obfs_password: h.credentials.obfs_password.expose().to_owned(),
                obfs: match h.endpoint.obfs {
                    Hysteria2Obfs::Salamander => ObfsWire {
                        kind: "salamander".into(),
                        min_packet_size: None,
                        max_packet_size: None,
                    },
                    Hysteria2Obfs::Gecko {
                        min_packet_size,
                        max_packet_size,
                    } => ObfsWire {
                        kind: "gecko".into(),
                        min_packet_size: Some(min_packet_size),
                        max_packet_size: Some(max_packet_size),
                    },
                },
                trust: match &h.endpoint.trust {
                    ServerTrust::PublicCa { server_name } => TrustWire {
                        kind: "public_ca".into(),
                        server_name: server_name.clone(),
                        spki_sha256: None,
                    },
                    ServerTrust::PinnedPublicKey {
                        server_name,
                        spki_sha256,
                    } => TrustWire {
                        kind: "pinned_public_key".into(),
                        server_name: server_name.clone(),
                        spki_sha256: Some(hex_encode(spki_sha256)),
                    },
                },
            }),
            reality: self.reality.as_ref().map(|r| RealityWire {
                server_port: r.server_port,
                uuid: r.credentials.uuid.expose().to_owned(),
                short_id: r.credentials.short_id.expose().to_owned(),
                target_domain: r.endpoint.target_domain.as_str().to_owned(),
                public_key: r.endpoint.public_key.as_str().to_owned(),
                flow: match r.endpoint.flow {
                    VlessFlow::None => "none".into(),
                    VlessFlow::Vision => "xtls-rprx-vision".into(),
                },
            }),
            session: self.session.as_ref().map(|s| SessionWire {
                device_private_key: s.device_private_key.expose().to_owned(),
                server_public_key: s.server_public_key.clone(),
                device_address: s.device_address,
                session_port: s.session_port,
            }),
        };
        serde_json::to_vec(&wire).map_err(|e| CredentialsError::Malformed(e.to_string()))
    }

    /// Read the stored form. Strict: see the module documentation.
    pub fn from_plaintext_json(bytes: &[u8]) -> Result<Self, CredentialsError> {
        if bytes.len() > MAX_STORED_LEN {
            return Err(CredentialsError::TooLarge);
        }
        // Checked before the full parse so a future format is named as such, not as "malformed".
        let probe: VersionProbe = serde_json::from_slice(bytes)
            .map_err(|e| CredentialsError::Malformed(serde_error_summary(&e)))?;
        if !(OLDEST_VERSION..=FORMAT_VERSION).contains(&probe.version) {
            return Err(CredentialsError::UnsupportedVersion {
                found: probe.version,
            });
        }
        let wire: Wire = serde_json::from_slice(bytes)
            .map_err(|e| CredentialsError::Malformed(serde_error_summary(&e)))?;
        // A form that says it predates the session cannot hold one: it was not written by this code.
        if wire.version < 2 && wire.session.is_some() {
            return Err(CredentialsError::Malformed(
                "a version 1 form holds a session".to_owned(),
            ));
        }

        let amneziawg = wire.amneziawg.map(|a| AmneziaWgCredentials {
            client_private_key: PrivateKey::new(a.client_private_key),
            server_public_key: a.server_public_key,
            client_address: a.client_address,
            prefix_len: a.prefix_len,
            obfuscation: a.obfuscation.into(),
            server_port: a.server_port,
        });

        let hysteria2 = wire
            .hysteria2
            .map(|h| -> Result<_, CredentialsError> {
                let obfs = match (
                    h.obfs.kind.as_str(),
                    h.obfs.min_packet_size,
                    h.obfs.max_packet_size,
                ) {
                    ("salamander", None, None) => Hysteria2Obfs::Salamander,
                    ("gecko", Some(min_packet_size), Some(max_packet_size)) => {
                        Hysteria2Obfs::Gecko {
                            min_packet_size,
                            max_packet_size,
                        }
                    }
                    _ => return Err(CredentialsError::Invalid("Hysteria 2 obfuscation")),
                };
                let trust = match (h.trust.kind.as_str(), h.trust.spki_sha256) {
                    ("public_ca", None) => ServerTrust::PublicCa {
                        server_name: h.trust.server_name,
                    },
                    ("pinned_public_key", Some(pin)) => ServerTrust::PinnedPublicKey {
                        server_name: h.trust.server_name,
                        spki_sha256: hex_decode_32(&pin)
                            .ok_or(CredentialsError::Invalid("Hysteria 2 certificate pin"))?,
                    },
                    _ => return Err(CredentialsError::Invalid("Hysteria 2 certificate trust")),
                };
                Ok(Hysteria2Bundle {
                    server_port: h.server_port,
                    credentials: Hysteria2Credentials {
                        auth_password: Secret::new(h.auth_password),
                        obfs_password: Secret::new(h.obfs_password),
                    },
                    endpoint: Hysteria2EndpointParams { obfs, trust },
                })
            })
            .transpose()?;

        let reality = wire
            .reality
            .map(|r| -> Result<_, CredentialsError> {
                let flow = match r.flow.as_str() {
                    "none" => VlessFlow::None,
                    "xtls-rprx-vision" => VlessFlow::Vision,
                    _ => return Err(CredentialsError::Invalid("REALITY flow")),
                };
                Ok(RealityBundle {
                    server_port: r.server_port,
                    credentials: RealityCredentials {
                        uuid: Secret::new(r.uuid),
                        short_id: Secret::new(r.short_id),
                    },
                    endpoint: RealityEndpointParams {
                        target_domain: TargetDomain::parse(&r.target_domain)
                            .map_err(|_| CredentialsError::Invalid("REALITY target domain"))?,
                        public_key: RealityPublicKey::parse(&r.public_key)
                            .map_err(|_| CredentialsError::Invalid("REALITY public key"))?,
                        flow,
                    },
                })
            })
            .transpose()?;

        let session = wire.session.map(|s| SessionBundle {
            device_private_key: Secret::new(s.device_private_key),
            server_public_key: s.server_public_key,
            device_address: s.device_address,
            session_port: s.session_port,
        });

        let measure_origin = wire
            .measure_origin
            .map(|text| Origin::parse(&text))
            .transpose()
            .map_err(|_| CredentialsError::Invalid("measurement origin"))?;

        let bundle = Self {
            amneziawg,
            hysteria2,
            reality,
            session,
            measure_origin,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    /// The rules both directions apply, reusing the generators' own validators where they exist, so
    /// a bundle that is stored is one a generator will accept.
    fn validate(&self) -> Result<(), CredentialsError> {
        if let Some(a) = &self.amneziawg {
            if !is_lower_hex(a.client_private_key.expose_wire(), 64) {
                return Err(CredentialsError::Invalid("AmneziaWG client key"));
            }
            if !is_lower_hex(&a.server_public_key, 64) {
                return Err(CredentialsError::Invalid("AmneziaWG server key"));
            }
            if a.server_port == 0 {
                return Err(CredentialsError::Invalid("AmneziaWG server port"));
            }
            if !(1..=32).contains(&a.prefix_len) {
                return Err(CredentialsError::Invalid("AmneziaWG tunnel prefix length"));
            }
            a.obfuscation
                .validate()
                .map_err(|_| CredentialsError::Invalid("AmneziaWG obfuscation"))?;
        }
        if let Some(h) = &self.hysteria2 {
            if h.server_port == 0 {
                return Err(CredentialsError::Invalid("Hysteria 2 server port"));
            }
            let (auth, obfs) = (
                h.credentials.auth_password.expose(),
                h.credentials.obfs_password.expose(),
            );
            if auth.is_empty() {
                return Err(CredentialsError::Invalid("Hysteria 2 password"));
            }
            // The obfuscation key must differ from the password (CC-10): sharing one lets anyone who
            // sees either learn both.
            if obfs.is_empty() || obfs == auth {
                return Err(CredentialsError::Invalid("Hysteria 2 obfuscation password"));
            }
            if let Hysteria2Obfs::Gecko {
                min_packet_size,
                max_packet_size,
            } = h.endpoint.obfs
            {
                if !gecko_packet_sizes_valid(min_packet_size, max_packet_size) {
                    return Err(CredentialsError::Invalid("Hysteria 2 packet sizes"));
                }
            }
            if !is_dns_hostname(h.endpoint.trust.server_name()) {
                return Err(CredentialsError::Invalid("Hysteria 2 server name"));
            }
        }
        if let Some(r) = &self.reality {
            if r.server_port == 0 {
                return Err(CredentialsError::Invalid("REALITY server port"));
            }
            validate_uuid(&r.credentials.uuid)
                .map_err(|_| CredentialsError::Invalid("VLESS user id"))?;
            validate_short_id(&r.credentials.short_id)
                .map_err(|_| CredentialsError::Invalid("REALITY short id"))?;
        }
        if let Some(s) = &self.session {
            // The session rides the carriers; without one of them it has nothing to ride.
            if self.hysteria2.is_none() && self.reality.is_none() {
                return Err(CredentialsError::Invalid("session (it has no carrier)"));
            }
            if !crate::session::is_key(s.device_private_key.expose()) {
                return Err(CredentialsError::Invalid("session device key"));
            }
            if !crate::session::is_key(&s.server_public_key) {
                return Err(CredentialsError::Invalid("session server key"));
            }
            if !crate::session::is_device_address(s.device_address) {
                return Err(CredentialsError::Invalid("session device address"));
            }
            if s.session_port == 0 {
                return Err(CredentialsError::Invalid("session port"));
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ wire

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    measure_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amneziawg: Option<AwgWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hysteria2: Option<Hy2Wire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reality: Option<RealityWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<SessionWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    device_private_key: String,
    server_public_key: String,
    device_address: Ipv4Addr,
    session_port: u16,
}

/// Reads only the version, ignoring everything else.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwgWire {
    client_private_key: String,
    server_public_key: String,
    client_address: Ipv4Addr,
    prefix_len: u8,
    obfuscation: ObfuscationWire,
    server_port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfuscationWire {
    jc: u32,
    jmin: u32,
    jmax: u32,
    s1: u32,
    s2: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl From<ObfuscationParams> for ObfuscationWire {
    fn from(o: ObfuscationParams) -> Self {
        Self {
            jc: o.jc,
            jmin: o.jmin,
            jmax: o.jmax,
            s1: o.s1,
            s2: o.s2,
            h1: o.h1,
            h2: o.h2,
            h3: o.h3,
            h4: o.h4,
        }
    }
}

impl From<ObfuscationWire> for ObfuscationParams {
    fn from(o: ObfuscationWire) -> Self {
        Self {
            jc: o.jc,
            jmin: o.jmin,
            jmax: o.jmax,
            s1: o.s1,
            s2: o.s2,
            h1: o.h1,
            h2: o.h2,
            h3: o.h3,
            h4: o.h4,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2Wire {
    server_port: u16,
    auth_password: String,
    obfs_password: String,
    obfs: ObfsWire,
    trust: TrustWire,
}

// Flat structs with a `kind` string instead of internally tagged enums: serde does not enforce
// `deny_unknown_fields` for those (it did not for the profile feed's Salamander, FEED-09).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfsWire {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min_packet_size: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_packet_size: Option<u16>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustWire {
    kind: String,
    server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spki_sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityWire {
    server_port: u16,
    uuid: String,
    short_id: String,
    target_domain: String,
    public_key: String,
    flow: String,
}

// ------------------------------------------------------------------ helpers

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A SHA-256 certificate pin in the form it is stored and exchanged: 64 lowercase hex digits.
pub fn parse_spki_sha256_hex(text: &str) -> Option<[u8; 32]> {
    hex_decode_32(text)
}

fn hex_decode_32(text: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(text, 64) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A serde error says where the form is wrong, and for a string value it can quote the value. A
/// bundle is mostly secrets, so report the position and kind of error only.
fn serde_error_summary(e: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let kind = match e.classify() {
        Category::Io => "unreadable",
        Category::Syntax => "not valid JSON",
        Category::Data => "a field is missing, unknown or of the wrong type",
        Category::Eof => "ends unexpectedly",
    };
    format!("{kind} (line {}, column {})", e.line(), e.column())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appears in every secret below. If it ever shows up in an error, a log line or a `Debug`
    /// string, a secret leaked.
    const SENTINEL: &str = "SENTINEL-d41d8cd98f00";

    fn awg() -> AmneziaWgCredentials {
        AmneziaWgCredentials {
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
        }
    }

    fn hy2(trust: ServerTrust, obfs: Hysteria2Obfs) -> Hysteria2Bundle {
        Hysteria2Bundle {
            server_port: 44443,
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(format!("auth-{SENTINEL}")),
                obfs_password: Secret::new(format!("obfs-{SENTINEL}")),
            },
            endpoint: Hysteria2EndpointParams { obfs, trust },
        }
    }

    fn reality() -> RealityBundle {
        RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new("123e4567-e89b-42d3-a456-426614174000"),
                short_id: Secret::new("0123abcd"),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("c2VjcmV0LXB1YmxpYy1rZXktMzItYnl0ZXMhISEhISE")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        }
    }

    fn full() -> EndpointCredentials {
        EndpointCredentials {
            amneziawg: Some(awg()),
            hysteria2: Some(hy2(
                ServerTrust::PinnedPublicKey {
                    server_name: "vpn.example.com".into(),
                    spki_sha256: [7; 32],
                },
                Hysteria2Obfs::Gecko {
                    min_packet_size: 300,
                    max_packet_size: 1200,
                },
            )),
            reality: Some(reality()),
            measure_origin: Some(Origin::parse("http://203.0.113.80:8080").unwrap()),
            session: None,
        }
    }

    // ---- the session (ADR-0008)

    fn session() -> SessionBundle {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        SessionBundle {
            device_private_key: Secret::new(STANDARD.encode([5u8; 32])),
            server_public_key: STANDARD.encode([6u8; 32]),
            device_address: Ipv4Addr::new(10, 9, 0, 2),
            session_port: 25182,
        }
    }

    fn with_session() -> EndpointCredentials {
        EndpointCredentials {
            session: Some(session()),
            ..full()
        }
    }

    #[test]
    fn a_bundle_with_a_session_round_trips_and_is_version_2() {
        let bundle = with_session();
        let stored = bundle.to_plaintext_json().unwrap();
        assert!(String::from_utf8_lossy(&stored).starts_with("{\"version\":2"));
        assert_eq!(
            EndpointCredentials::from_plaintext_json(&stored).unwrap(),
            bundle
        );
    }

    #[test]
    fn a_bundle_without_one_is_still_written_as_version_1_so_older_readers_keep_working() {
        let stored = full().to_plaintext_json().unwrap();
        assert!(String::from_utf8_lossy(&stored).starts_with("{\"version\":1"));
        assert!(!String::from_utf8_lossy(&stored).contains("session"));
        // And a version 1 form from before the session is read as it always was.
        let read = EndpointCredentials::from_plaintext_json(&stored).unwrap();
        assert_eq!(read.session, None);
    }

    #[test]
    fn a_form_that_says_version_1_cannot_hold_a_session() {
        let stored = String::from_utf8(with_session().to_plaintext_json().unwrap()).unwrap();
        let forged = stored.replacen("\"version\":2", "\"version\":1", 1);
        assert!(matches!(
            EndpointCredentials::from_plaintext_json(forged.as_bytes()),
            Err(CredentialsError::Malformed(_))
        ));
    }

    #[test]
    fn a_session_needs_a_carrier_to_ride() {
        let alone = EndpointCredentials {
            session: Some(session()),
            ..Default::default()
        };
        let amnezia_only = EndpointCredentials {
            amneziawg: Some(awg()),
            session: Some(session()),
            ..Default::default()
        };
        for bundle in [alone, amnezia_only] {
            assert_eq!(
                bundle.to_plaintext_json(),
                Err(CredentialsError::Invalid("session (it has no carrier)"))
            );
        }
        // Either carrier is enough.
        for carriers in [(true, false), (false, true)] {
            let bundle = EndpointCredentials {
                hysteria2: carriers.0.then(|| {
                    hy2(
                        ServerTrust::PublicCa {
                            server_name: "vpn.example.com".into(),
                        },
                        Hysteria2Obfs::Salamander,
                    )
                }),
                reality: carriers.1.then(reality),
                session: Some(session()),
                ..Default::default()
            };
            assert!(bundle.to_plaintext_json().is_ok(), "{carriers:?}");
        }
    }

    #[test]
    fn a_session_with_a_value_that_cannot_be_what_it_claims_is_refused_by_field() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let broken = |edit: &dyn Fn(&mut SessionBundle)| {
            let mut bundle = with_session();
            edit(bundle.session.as_mut().unwrap());
            bundle.to_plaintext_json().unwrap_err()
        };
        let short = Secret::new(STANDARD.encode([1u8; 31]));
        type Edit = Box<dyn Fn(&mut SessionBundle)>;
        let cases: Vec<(&str, Edit, &str)> = vec![
            (
                "device key not base64",
                Box::new(|s| s.device_private_key = Secret::new(SENTINEL)),
                "session device key",
            ),
            (
                "device key too short",
                Box::new(move |s| s.device_private_key = short.clone()),
                "session device key",
            ),
            (
                "server key empty",
                Box::new(|s| s.server_public_key = String::new()),
                "session server key",
            ),
            (
                "server key not a key",
                Box::new(|s| s.server_public_key = "AAAA".into()),
                "session server key",
            ),
            (
                "the server's own address",
                Box::new(|s| s.device_address = Ipv4Addr::new(10, 9, 0, 1)),
                "session device address",
            ),
            (
                "the origin's address",
                Box::new(|s| s.device_address = Ipv4Addr::new(10, 9, 0, 254)),
                "session device address",
            ),
            (
                "another network",
                Box::new(|s| s.device_address = Ipv4Addr::new(10, 66, 0, 2)),
                "session device address",
            ),
            (
                "one past the last device",
                Box::new(|s| s.device_address = Ipv4Addr::new(10, 9, 0, 10)),
                "session device address",
            ),
            (
                "port zero",
                Box::new(|s| s.session_port = 0),
                "session port",
            ),
        ];
        for (label, edit, field) in &cases {
            let error = broken(edit.as_ref());
            assert_eq!(error, CredentialsError::Invalid(field), "{label}");
            // The refusal names the field and never repeats a value.
            assert!(!error.to_string().contains(SENTINEL), "{label}: {error}");
        }
        // The first and the last device addresses are fine.
        for last_octet in [2u8, 9] {
            let mut ok = with_session();
            ok.session.as_mut().unwrap().device_address = Ipv4Addr::new(10, 9, 0, last_octet);
            assert!(ok.to_plaintext_json().is_ok(), "10.9.0.{last_octet}");
        }
    }

    #[test]
    fn a_stored_session_with_an_unknown_field_or_a_bad_address_is_refused() {
        let stored = String::from_utf8(with_session().to_plaintext_json().unwrap()).unwrap();
        let extra = stored.replacen(
            "\"session_port\":25182",
            "\"session_port\":25182,\"extra\":1",
            1,
        );
        assert!(matches!(
            EndpointCredentials::from_plaintext_json(extra.as_bytes()),
            Err(CredentialsError::Malformed(_))
        ));
        let moved = stored.replacen("10.9.0.2", "10.9.0.200", 1);
        assert_eq!(
            EndpointCredentials::from_plaintext_json(moved.as_bytes()),
            Err(CredentialsError::Invalid("session device address"))
        );
    }

    #[test]
    fn the_session_key_never_shows_in_debug_or_in_an_error() {
        let bundle = with_session();
        let key = {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine as _;
            STANDARD.encode([5u8; 32])
        };
        assert!(
            !format!("{bundle:?}").contains(&key),
            "Debug leaked the key"
        );
        // And the stored form does hold it, so that absence check is not vacuous.
        let stored = String::from_utf8(bundle.to_plaintext_json().unwrap()).unwrap();
        assert!(stored.contains(&key));
    }

    #[test]
    fn a_full_bundle_round_trips() {
        let bundle = full();
        let stored = bundle.to_plaintext_json().unwrap();
        assert_eq!(
            EndpointCredentials::from_plaintext_json(&stored).unwrap(),
            bundle
        );
    }

    #[test]
    fn each_profile_may_be_absent_and_every_combination_round_trips() {
        let parts = full();
        for mask in 0u8..8 {
            let bundle = EndpointCredentials {
                amneziawg: parts.amneziawg.clone().filter(|_| mask & 1 != 0),
                hysteria2: parts.hysteria2.clone().filter(|_| mask & 2 != 0),
                reality: parts.reality.clone().filter(|_| mask & 4 != 0),
                measure_origin: parts.measure_origin.clone().filter(|_| mask & 1 != 0),
                session: None,
            };
            let stored = bundle.to_plaintext_json().unwrap();
            assert_eq!(
                EndpointCredentials::from_plaintext_json(&stored).unwrap(),
                bundle,
                "mask {mask:03b}"
            );
        }
    }

    #[test]
    fn both_certificate_trust_forms_and_both_obfuscation_layers_round_trip() {
        for trust in [
            ServerTrust::PublicCa {
                server_name: "vpn.example.com".into(),
            },
            ServerTrust::PinnedPublicKey {
                server_name: "vpn.example.com".into(),
                spki_sha256: [0xAB; 32],
            },
        ] {
            for obfs in [
                Hysteria2Obfs::Salamander,
                Hysteria2Obfs::Gecko {
                    min_packet_size: 256,
                    max_packet_size: 1400,
                },
            ] {
                let bundle = EndpointCredentials {
                    hysteria2: Some(hy2(trust.clone(), obfs)),
                    ..Default::default()
                };
                let stored = bundle.to_plaintext_json().unwrap();
                assert_eq!(
                    EndpointCredentials::from_plaintext_json(&stored).unwrap(),
                    bundle
                );
            }
        }
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let text = format!("{:?}", full());
        for secret in [SENTINEL, "123e4567", "0123abcd", &format!("{:0>64}", "ab")] {
            assert!(!text.contains(secret), "Debug leaked {secret}: {text}");
        }
    }

    #[test]
    fn the_stored_form_does_contain_the_secrets_so_the_absence_checks_are_not_vacuous() {
        let stored = String::from_utf8(full().to_plaintext_json().unwrap()).unwrap();
        assert!(stored.contains(SENTINEL));
    }

    #[test]
    fn errors_name_the_field_and_never_the_value() {
        let mut bad = full();
        bad.hysteria2.as_mut().unwrap().credentials.obfs_password = bad
            .hysteria2
            .as_ref()
            .unwrap()
            .credentials
            .auth_password
            .clone();
        let err = bad.to_plaintext_json().unwrap_err();
        assert_eq!(
            err,
            CredentialsError::Invalid("Hysteria 2 obfuscation password")
        );
        assert!(!err.to_string().contains(SENTINEL));

        // A damaged form containing a secret: the parse error must not quote it.
        let damaged =
            format!(r#"{{"version":1,"hysteria2":{{"auth_password":"{SENTINEL}","bogus":1}}}}"#);
        let err = EndpointCredentials::from_plaintext_json(damaged.as_bytes()).unwrap_err();
        assert!(!err.to_string().contains(SENTINEL), "{err}");
    }

    #[test]
    fn a_form_with_an_unknown_field_is_refused_at_every_level() {
        let good = String::from_utf8(full().to_plaintext_json().unwrap()).unwrap();
        for (needle, injected) in [
            ("\"version\":1", "\"version\":1,\"extra\":1"),
            ("\"jc\":4", "\"jc\":4,\"extra\":1"),
            ("\"kind\":\"gecko\"", "\"kind\":\"gecko\",\"extra\":1"),
            ("\"flow\":", "\"extra\":1,\"flow\":"),
        ] {
            let tampered = good.replacen(needle, injected, 1);
            assert_ne!(tampered, good, "the injection point {needle} must exist");
            assert!(
                matches!(
                    EndpointCredentials::from_plaintext_json(tampered.as_bytes()),
                    Err(CredentialsError::Malformed(_))
                ),
                "{needle}"
            );
        }
    }

    #[test]
    fn another_format_version_is_named_as_such() {
        let good = String::from_utf8(full().to_plaintext_json().unwrap()).unwrap();
        // 2 is the session's version and is read now; 3 and beyond are not known yet.
        for version in [0u32, 3, 99] {
            let other = good.replacen("\"version\":1", &format!("\"version\":{version}"), 1);
            assert_eq!(
                EndpointCredentials::from_plaintext_json(other.as_bytes()),
                Err(CredentialsError::UnsupportedVersion { found: version })
            );
        }
        // A future form is reported as a version problem even if its other fields are unknown.
        assert_eq!(
            EndpointCredentials::from_plaintext_json(br#"{"version":3,"shiny":true}"#),
            Err(CredentialsError::UnsupportedVersion { found: 3 })
        );
    }

    #[test]
    fn a_missing_or_non_numeric_version_is_malformed_not_defaulted() {
        for wire in [
            r#"{}"#,
            r#"{"version":"1"}"#,
            r#"{"version":-1}"#,
            "null",
            "[]",
            "",
        ] {
            assert!(
                matches!(
                    EndpointCredentials::from_plaintext_json(wire.as_bytes()),
                    Err(CredentialsError::Malformed(_))
                ),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn an_oversized_form_is_refused_before_it_is_parsed() {
        let big = vec![b' '; MAX_STORED_LEN + 1];
        assert_eq!(
            EndpointCredentials::from_plaintext_json(&big),
            Err(CredentialsError::TooLarge)
        );
    }

    /// Each case breaks exactly one thing in an otherwise valid bundle, so the field named in the
    /// error is the one that was broken.
    #[test]
    fn values_the_generators_would_refuse_are_refused_on_the_way_in() {
        type Break = fn(&mut EndpointCredentials);
        let cases: [(&str, Break); 12] = [
            ("AmneziaWG server port", |c| {
                c.amneziawg.as_mut().unwrap().server_port = 0
            }),
            ("Hysteria 2 server port", |c| {
                c.hysteria2.as_mut().unwrap().server_port = 0
            }),
            ("REALITY server port", |c| {
                c.reality.as_mut().unwrap().server_port = 0
            }),
            ("AmneziaWG server key", |c| {
                c.amneziawg.as_mut().unwrap().server_public_key = "not-hex".into()
            }),
            ("AmneziaWG client key", |c| {
                // Upper-case hex: the UAPI form is lower-case.
                c.amneziawg.as_mut().unwrap().client_private_key = PrivateKey::new("AB".repeat(32))
            }),
            ("AmneziaWG tunnel prefix length", |c| {
                c.amneziawg.as_mut().unwrap().prefix_len = 0
            }),
            ("AmneziaWG obfuscation", |c| {
                let o = &mut c.amneziawg.as_mut().unwrap().obfuscation;
                o.h2 = o.h1;
            }),
            ("Hysteria 2 password", |c| {
                c.hysteria2.as_mut().unwrap().credentials.auth_password = Secret::new("")
            }),
            ("Hysteria 2 packet sizes", |c| {
                c.hysteria2.as_mut().unwrap().endpoint.obfs = Hysteria2Obfs::Gecko {
                    min_packet_size: 100,
                    max_packet_size: 200,
                }
            }),
            ("Hysteria 2 server name", |c| {
                // An IP literal is not a certificate name.
                c.hysteria2.as_mut().unwrap().endpoint.trust = ServerTrust::PublicCa {
                    server_name: "203.0.113.5".into(),
                }
            }),
            ("VLESS user id", |c| {
                c.reality.as_mut().unwrap().credentials.uuid =
                    Secret::new("{123e4567-e89b-42d3-a456-426614174000}")
            }),
            ("REALITY short id", |c| {
                c.reality.as_mut().unwrap().credentials.short_id = Secret::new("xyz")
            }),
        ];
        for (field, break_it) in cases {
            let mut bundle = full();
            break_it(&mut bundle);
            assert_eq!(
                bundle.to_plaintext_json(),
                Err(CredentialsError::Invalid(field)),
                "{field}"
            );
        }
    }

    #[test]
    fn a_stored_form_that_names_a_bad_value_is_refused_on_read() {
        let good = String::from_utf8(full().to_plaintext_json().unwrap()).unwrap();
        for (needle, replacement, field) in [
            (
                "\"flow\":\"xtls-rprx-vision\"",
                "\"flow\":\"other\"",
                "REALITY flow",
            ),
            (
                "\"kind\":\"gecko\"",
                "\"kind\":\"morse\"",
                "Hysteria 2 obfuscation",
            ),
            (
                "\"kind\":\"pinned_public_key\"",
                "\"kind\":\"insecure\"",
                "Hysteria 2 certificate trust",
            ),
            (
                "\"target_domain\":\"www.example.com\"",
                "\"target_domain\":\"203.0.113.9\"",
                "REALITY target domain",
            ),
            (
                "\"public_key\":\"c2Vj",
                "\"public_key\":\"!!!",
                "REALITY public key",
            ),
        ] {
            let tampered = good.replacen(needle, replacement, 1);
            assert_ne!(tampered, good, "{needle}");
            assert_eq!(
                EndpointCredentials::from_plaintext_json(tampered.as_bytes()),
                Err(CredentialsError::Invalid(field)),
                "{needle}"
            );
        }
    }

    #[test]
    fn a_gecko_without_sizes_and_a_salamander_with_sizes_are_both_refused() {
        let good = String::from_utf8(full().to_plaintext_json().unwrap()).unwrap();
        let no_sizes = good.replacen(",\"min_packet_size\":300", "", 1).replacen(
            ",\"max_packet_size\":1200",
            "",
            1,
        );
        assert_ne!(no_sizes, good);
        assert_eq!(
            EndpointCredentials::from_plaintext_json(no_sizes.as_bytes()),
            Err(CredentialsError::Invalid("Hysteria 2 obfuscation"))
        );
        let salamander_with_sizes =
            good.replacen("\"kind\":\"gecko\"", "\"kind\":\"salamander\"", 1);
        assert_eq!(
            EndpointCredentials::from_plaintext_json(salamander_with_sizes.as_bytes()),
            Err(CredentialsError::Invalid("Hysteria 2 obfuscation"))
        );
    }

    #[test]
    fn an_empty_bundle_is_reported_empty() {
        assert!(EndpointCredentials::default().is_empty());
        assert!(!full().is_empty());
    }

    #[test]
    fn hex_helpers_agree() {
        let bytes = [0x00, 0x01, 0xAB, 0xFF].repeat(8);
        let text = hex_encode(&bytes);
        assert_eq!(text.len(), 64);
        assert_eq!(hex_decode_32(&text).unwrap().to_vec(), bytes);
        assert!(hex_decode_32(&text.to_uppercase()).is_none());
        assert!(hex_decode_32(&text[..62]).is_none());
    }

    // ------------------------------------------------------------ measurement origin

    fn with_stored_origin(origin: &str) -> Vec<u8> {
        let mut json: serde_json::Value =
            serde_json::from_slice(&full().to_plaintext_json().unwrap()).unwrap();
        json["measure_origin"] = serde_json::Value::String(origin.to_owned());
        serde_json::to_vec(&json).unwrap()
    }

    #[test]
    fn the_measurement_origin_round_trips_and_may_be_absent() {
        let with = full();
        let stored = with.to_plaintext_json().unwrap();
        let read = EndpointCredentials::from_plaintext_json(&stored).unwrap();
        assert_eq!(
            read.measure_origin.as_ref().map(|o| (o.host(), o.port())),
            Some(("203.0.113.80", 8080))
        );

        let without = EndpointCredentials {
            measure_origin: None,
            ..full()
        };
        let stored = without.to_plaintext_json().unwrap();
        assert!(!String::from_utf8(stored.clone())
            .unwrap()
            .contains("measure_origin"));
        assert_eq!(
            EndpointCredentials::from_plaintext_json(&stored).unwrap(),
            without
        );
    }

    /// The same rule the prober applies, applied when it is stored: a value that could not be used
    /// is refused now, not at the first connect.
    #[test]
    fn a_measurement_origin_the_prober_would_refuse_is_refused_when_stored() {
        for bad in [
            "https://203.0.113.80",
            "203.0.113.80:8080",
            "http://203.0.113.80/bytes/1",
            "http://user@203.0.113.80",
            "http://203.0.113.80:0",
            "http://a b.net",
            "",
        ] {
            let error =
                EndpointCredentials::from_plaintext_json(&with_stored_origin(bad)).expect_err(bad);
            assert_eq!(
                error,
                CredentialsError::Invalid("measurement origin"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_refused_origin_is_not_echoed() {
        let marker = "ORIGIN-MARKER-9c1e";
        let error = EndpointCredentials::from_plaintext_json(&with_stored_origin(&format!(
            "https://{marker}.example"
        )))
        .unwrap_err();
        assert!(!error.to_string().contains(marker), "{error}");
    }

    #[test]
    fn an_origin_alone_is_not_a_credential_set() {
        let only_origin = EndpointCredentials {
            measure_origin: full().measure_origin,
            ..EndpointCredentials::default()
        };
        assert!(only_origin.is_empty());
    }
}
