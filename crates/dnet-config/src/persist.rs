//! T124 — the persisted configuration: endpoints and per-profile settings.
//!
//! `%PROGRAMDATA%\DNet Engine\state\config.json`, readable and writable only by SYSTEM and
//! Administrators (`dnet_config::trusted_file`). It holds **no secrets**: an endpoint carries the
//! key of its credentials (`dnet_config::secret_store`), nothing more.
//!
//! The file is input from a place a local user may have been able to reach, so it is read as
//! hostile: strictly typed with no unknown fields, bounded in size and count, and every value that
//! reaches a generated core configuration or a route (a host, a label, a parameter) is validated
//! the way a client request would be. **One bad entry refuses the whole file**: a half-read
//! configuration is a connection to the wrong place with no explanation. The caller then keeps the
//! service up read-only and says why (it never overwrites a file it could not read).
//!
//! Profiles are not stored, only their settings (parameters and the Brutal opt-in). The set of
//! profiles is the bundled catalogue, and an id outside it is refused (ADR-0002 §5.3): a profile
//! cannot be added from a file. Health and viability are measurements of the current network, so
//! they are never stored.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;

use crate::secret_store::SecretKey;
use crate::write::default_run_dir;
use dnet_core::catalogue::bundled_kind;
use dnet_core::credential::CredentialRef;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::hostname::is_dns_hostname;
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::profile::{
    BandwidthPair, BrutalAcknowledgement, ConnectionProfile, ProfileKind, ProfileParams,
    BRUTAL_WARNING_REVISION,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The version of the stored form.
pub const FORMAT_VERSION: u32 = 1;
/// The largest file read. A real one is a few KiB.
pub const MAX_CONFIG_LEN: usize = 256 * 1024;
pub const MAX_ENDPOINTS: usize = 64;
const MAX_PARAMS: usize = 64;
const MAX_PARAM_KEY_LEN: usize = 64;
const MAX_PARAM_VALUE_LEN: usize = 512;
const MAX_RESOURCE_IDS: usize = 32;
const MAX_TEXT_LEN: usize = 256;
/// Bandwidth above this is a typo, not a link (one terabit per second).
const MAX_BRUTAL_MBPS: u32 = 1_000_000;

/// Why the configuration could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    /// The file could not be read or written, or is not trusted.
    Storage(String),
    /// The file is larger than [`MAX_CONFIG_LEN`].
    TooLarge,
    /// The file is not valid JSON of the expected shape.
    Malformed(String),
    /// The file is of a format this version does not read.
    UnsupportedVersion(u32),
    /// An entry is invalid. Names the entry and the reason.
    Invalid(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Storage(detail) => {
                write!(f, "the saved configuration could not be read or written ({detail})")
            }
            PersistError::TooLarge => write!(
                f,
                "the saved configuration is larger than {MAX_CONFIG_LEN} bytes"
            ),
            PersistError::Malformed(detail) => {
                write!(f, "the saved configuration is not in the expected form ({detail})")
            }
            PersistError::UnsupportedVersion(found) => write!(
                f,
                "the saved configuration is format version {found}; this version reads version {FORMAT_VERSION}"
            ),
            PersistError::Invalid(detail) => {
                write!(f, "the saved configuration has an invalid entry ({detail})")
            }
        }
    }
}

impl std::error::Error for PersistError {}

/// Where the configuration file is.
pub fn default_config_path() -> PathBuf {
    default_run_dir()
        .with_file_name("state")
        .join("config.json")
}

/// Where the sealed secrets are.
pub fn default_secrets_dir() -> PathBuf {
    default_run_dir().with_file_name("state").join("secrets")
}

/// The settings of one profile that survive a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSettings {
    pub id: ProfileId,
    pub params: ProfileParams,
    pub brutal: Option<(BandwidthPair, BrutalAcknowledgement)>,
}

/// A configuration read back from the file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedConfig {
    pub endpoints: Vec<Endpoint>,
    pub profiles: Vec<ProfileSettings>,
    /// Things worth telling the user that are not errors: a setting that was dropped because it no
    /// longer applies. For the log and the session's events.
    pub notes: Vec<String>,
}

/// One file of bytes. The production one is a `TrustedFile`; tests use memory.
pub trait StateFile: Send + Sync {
    fn read(&self) -> Result<Option<Vec<u8>>, String>;
    fn write(&self, bytes: &[u8]) -> Result<(), String>;
}

/// The saved configuration.
pub struct ConfigStore {
    file: Box<dyn StateFile>,
}

impl ConfigStore {
    pub fn new(file: Box<dyn StateFile>) -> Self {
        Self { file }
    }

    /// The saved configuration, or `None` if nothing was ever saved (a first run).
    pub fn load(&self) -> Result<Option<LoadedConfig>, PersistError> {
        match self.file.read().map_err(PersistError::Storage)? {
            None => Ok(None),
            Some(bytes) => decode(&bytes).map(Some),
        }
    }

    /// Save `endpoints` and the settings of `profiles`, replacing what was there.
    pub fn save(
        &self,
        endpoints: &[Endpoint],
        profiles: &[ConnectionProfile],
    ) -> Result<(), PersistError> {
        let bytes = encode(endpoints, profiles)?;
        self.file.write(&bytes).map_err(PersistError::Storage)
    }

    /// Save a configuration as it was loaded, replacing what was there.
    pub fn save_config(&self, config: &LoadedConfig) -> Result<(), PersistError> {
        let bytes = encode_config(config)?;
        self.file.write(&bytes).map_err(PersistError::Storage)
    }
}

/// A state file held in memory: for dry runs, and for tests of anything that saves a configuration.
#[derive(Default)]
pub struct MemoryStateFile {
    bytes: std::sync::Mutex<Option<Vec<u8>>>,
}

impl MemoryStateFile {
    /// A file that already holds `bytes` (or does not exist, for `None`).
    pub fn with_bytes(bytes: Option<Vec<u8>>) -> Self {
        Self {
            bytes: std::sync::Mutex::new(bytes),
        }
    }

    /// What the file holds now.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl StateFile for MemoryStateFile {
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.bytes())
    }
    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        *self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bytes.to_vec());
        Ok(())
    }
}

/// A shared handle to a state file is a state file, so a caller can keep one end.
impl<T: StateFile + ?Sized> StateFile for std::sync::Arc<T> {
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        (**self).read()
    }
    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        (**self).write(bytes)
    }
}

#[cfg(windows)]
pub use windows_file::TrustedStateFile;

#[cfg(windows)]
mod windows_file {
    use crate::trusted_file::TrustedFile;

    use super::StateFile;

    /// The production file: restricted to SYSTEM and Administrators, refused if it is not.
    pub struct TrustedStateFile(TrustedFile);

    impl TrustedStateFile {
        pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
            Self(TrustedFile::new(path))
        }
    }

    impl StateFile for TrustedStateFile {
        fn read(&self) -> Result<Option<Vec<u8>>, String> {
            self.0.read().map_err(|e| e.to_string())
        }
        fn write(&self, bytes: &[u8]) -> Result<(), String> {
            self.0.write(bytes).map_err(|e| e.to_string())
        }
    }
}

// ------------------------------------------------------------------ wire

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    endpoints: Vec<EndpointWire>,
    profiles: Vec<ProfileWire>,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointWire {
    id: String,
    label: String,
    host: String,
    port: u16,
    origin: OriginWire,
    credential: String,
    enabled: bool,
}

// A flat struct with a `kind`, not an internally tagged enum: serde does not enforce
// `deny_unknown_fields` for those.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginWire {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_ids: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileWire {
    id: String,
    params: BTreeMap<String, String>,
    brutal: Option<BrutalWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrutalWire {
    up_mbps: u32,
    down_mbps: u32,
    warning_revision: u32,
    acknowledged_at_unix: u64,
}

/// A profile id fit to repeat in an error: only if it has the shape of an id. Anything else is
/// text from a file that may have been planted, and is not echoed.
fn shown(id: &str) -> &str {
    let ok = (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        id
    } else {
        "(not a valid id)"
    }
}

fn invalid(what: impl Into<String>) -> PersistError {
    PersistError::Invalid(what.into())
}

fn malformed(e: &serde_json::Error) -> PersistError {
    use serde_json::error::Category;
    let kind = match e.classify() {
        Category::Io => "unreadable",
        Category::Syntax => "not valid JSON",
        Category::Data => "a field is missing, unknown or of the wrong type",
        Category::Eof => "ends unexpectedly",
    };
    PersistError::Malformed(format!("{kind}, line {} column {}", e.line(), e.column()))
}

/// Text a user typed or a provider returned that ends up in a log line, a label or a file name:
/// printable ASCII, bounded. Anything else is refused rather than escaped.
fn plain_text(value: &str, what: &str) -> Result<(), PersistError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_LEN
        || !value.bytes().all(|b| (0x20..0x7F).contains(&b))
    {
        return Err(invalid(format!(
            "{what} must be 1 to {MAX_TEXT_LEN} printable ASCII characters"
        )));
    }
    Ok(())
}

// ------------------------------------------------------------------ encode

/// The stored form of `endpoints` and the settings of `profiles`.
///
/// Refuses what [`decode`] would refuse, so the service can never write a file it cannot read back
/// (which would turn the next restart into a refused configuration).
pub fn encode(
    endpoints: &[Endpoint],
    profiles: &[ConnectionProfile],
) -> Result<Vec<u8>, PersistError> {
    finish(
        endpoints,
        profiles
            .iter()
            .map(|p| ProfileWire {
                id: p.id().as_str().to_owned(),
                params: p
                    .params()
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                brutal: p.brutal().map(|b| BrutalWire {
                    up_mbps: b.bandwidth().up_mbps,
                    down_mbps: b.bandwidth().down_mbps,
                    warning_revision: b.acknowledgement().warning_revision,
                    acknowledged_at_unix: b.acknowledgement().acknowledged_at_unix,
                }),
            })
            .collect(),
    )
}

/// The stored form of a configuration that was read back (or built from one), for a tool that
/// changes the saved configuration without a running service. Same rules as [`encode`].
pub fn encode_config(config: &LoadedConfig) -> Result<Vec<u8>, PersistError> {
    finish(
        &config.endpoints,
        config
            .profiles
            .iter()
            .map(|p| ProfileWire {
                id: p.id.as_str().to_owned(),
                params: p
                    .params
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                brutal: p.brutal.map(|(bandwidth, ack)| BrutalWire {
                    up_mbps: bandwidth.up_mbps,
                    down_mbps: bandwidth.down_mbps,
                    warning_revision: ack.warning_revision,
                    acknowledged_at_unix: ack.acknowledged_at_unix,
                }),
            })
            .collect(),
    )
}

fn endpoint_wire(e: &Endpoint) -> EndpointWire {
    EndpointWire {
        id: e.id().to_string(),
        label: e.label().to_owned(),
        host: e.address().host().to_owned(),
        port: e.address().port(),
        origin: match e.origin() {
            EndpointOrigin::Manual => OriginWire {
                kind: "manual".into(),
                provider: None,
                region: None,
                resource_ids: None,
            },
            EndpointOrigin::Provisioned {
                provider,
                region,
                resource_ids,
            } => OriginWire {
                kind: "provisioned".into(),
                provider: Some(provider.clone()),
                region: Some(region.clone()),
                resource_ids: Some(resource_ids.clone()),
            },
        },
        credential: e.credentials().store_key().to_owned(),
        enabled: e.is_enabled(),
    }
}

fn finish(endpoints: &[Endpoint], profiles: Vec<ProfileWire>) -> Result<Vec<u8>, PersistError> {
    let wire = Wire {
        version: FORMAT_VERSION,
        endpoints: endpoints.iter().map(endpoint_wire).collect(),
        profiles,
    };
    let bytes = serde_json::to_vec_pretty(&wire).map_err(|e| malformed(&e))?;
    // The strongest statement that what is written can be read: read it.
    decode(&bytes)?;
    Ok(bytes)
}

// ------------------------------------------------------------------ decode

/// Read the stored form. See the module documentation for what is refused.
pub fn decode(bytes: &[u8]) -> Result<LoadedConfig, PersistError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(PersistError::TooLarge);
    }
    let probe: VersionProbe = serde_json::from_slice(bytes).map_err(|e| malformed(&e))?;
    if probe.version != FORMAT_VERSION {
        return Err(PersistError::UnsupportedVersion(probe.version));
    }
    let wire: Wire = serde_json::from_slice(bytes).map_err(|e| malformed(&e))?;

    if wire.endpoints.len() > MAX_ENDPOINTS {
        return Err(invalid(format!("more than {MAX_ENDPOINTS} endpoints")));
    }
    let mut seen_ids = HashSet::new();
    let mut seen_labels = HashSet::new();
    let mut endpoints = Vec::with_capacity(wire.endpoints.len());
    for (index, e) in wire.endpoints.into_iter().enumerate() {
        let endpoint = decode_endpoint(e, index)?;
        if !seen_ids.insert(endpoint.id()) {
            return Err(invalid(format!("endpoint {index}: its id is used twice")));
        }
        if !seen_labels.insert(endpoint.label().to_owned()) {
            return Err(invalid(format!(
                "endpoint {index}: its label is used twice"
            )));
        }
        endpoints.push(endpoint);
    }

    let mut notes = Vec::new();
    let mut seen_profiles = HashSet::new();
    let mut profiles = Vec::with_capacity(wire.profiles.len());
    for p in wire.profiles {
        if !seen_profiles.insert(p.id.clone()) {
            return Err(invalid(format!("profile '{}' appears twice", shown(&p.id))));
        }
        profiles.push(decode_profile(p, &mut notes)?);
    }

    Ok(LoadedConfig {
        endpoints,
        profiles,
        notes,
    })
}

fn decode_endpoint(e: EndpointWire, index: usize) -> Result<Endpoint, PersistError> {
    let at = |what: &str| format!("endpoint {index}: {what}");

    if e.id.len() != 36 {
        return Err(invalid(at("the id is not a UUID")));
    }
    let id = Uuid::parse_str(&e.id).map_err(|_| invalid(at("the id is not a UUID")))?;

    plain_text(&e.label, &at("the label"))?;

    let host_ok = e.host.parse::<IpAddr>().is_ok() || is_dns_hostname(&e.host);
    if !host_ok {
        return Err(invalid(at(
            "the host is neither an IP address nor a host name",
        )));
    }
    let address =
        EndpointAddress::new(e.host, e.port).map_err(|err| invalid(at(&err.to_string())))?;

    // The reference must be a key the secret store will accept, so a hostile file cannot make the
    // store name a path of its choosing.
    let reference = CredentialRef::new(e.credential);
    SecretKey::parse(&reference).map_err(|err| invalid(at(&err.to_string())))?;

    let origin = match (
        e.origin.kind.as_str(),
        e.origin.provider,
        e.origin.region,
        e.origin.resource_ids,
    ) {
        ("manual", None, None, None) => EndpointOrigin::Manual,
        ("provisioned", Some(provider), Some(region), Some(resource_ids)) => {
            plain_text(&provider, &at("the provider"))?;
            plain_text(&region, &at("the region"))?;
            if resource_ids.len() > MAX_RESOURCE_IDS {
                return Err(invalid(at("too many cloud resource ids")));
            }
            for id in &resource_ids {
                plain_text(id, &at("a cloud resource id"))?;
            }
            EndpointOrigin::Provisioned {
                provider,
                region,
                resource_ids,
            }
        }
        _ => {
            return Err(invalid(at(
                "the origin is not 'manual' or a complete 'provisioned'",
            )))
        }
    };

    let mut endpoint = Endpoint::new(
        EndpointId::from_uuid(id),
        e.label,
        address,
        origin,
        reference,
    )
    .map_err(|err| invalid(at(&err.to_string())))?;
    endpoint.set_enabled(e.enabled);
    Ok(endpoint)
}

fn decode_profile(
    p: ProfileWire,
    notes: &mut Vec<String>,
) -> Result<ProfileSettings, PersistError> {
    let kind = bundled_kind(&p.id).ok_or_else(|| {
        invalid(format!(
            "profile '{}' is not one this build defines",
            shown(&p.id)
        ))
    })?;

    if p.params.len() > MAX_PARAMS {
        return Err(invalid(format!(
            "profile '{}': too many parameters",
            shown(&p.id)
        )));
    }
    let mut params = ProfileParams::new();
    for (key, value) in p.params {
        let key_ok = !key.is_empty()
            && key.len() <= MAX_PARAM_KEY_LEN
            && key.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
            });
        let value_ok =
            value.len() <= MAX_PARAM_VALUE_LEN && value.bytes().all(|b| (0x20..0x7F).contains(&b));
        if !key_ok || !value_ok {
            return Err(invalid(format!(
                "profile '{}': a parameter name or value is not allowed",
                shown(&p.id)
            )));
        }
        params.set(key, value);
    }

    let brutal = match p.brutal {
        None => None,
        Some(b) => {
            if kind != ProfileKind::Hysteria2 {
                return Err(invalid(format!(
                    "profile '{}': only Hysteria 2 has a Brutal setting",
                    shown(&p.id)
                )));
            }
            if b.up_mbps == 0
                || b.down_mbps == 0
                || b.up_mbps > MAX_BRUTAL_MBPS
                || b.down_mbps > MAX_BRUTAL_MBPS
            {
                return Err(invalid(format!(
                    "profile '{}': the Brutal bandwidth is not a plausible pair",
                    shown(&p.id)
                )));
            }
            if b.warning_revision != BRUTAL_WARNING_REVISION {
                // An acknowledgement of a different warning does not count (FR-006). Brutal goes
                // back to off, which is BBR, and the user is told, not the file refused.
                notes.push(format!(
                    "profile '{}': Brutal congestion control was turned off because the warning \
                     it was accepted under has changed; enable it again to accept the new one",
                    shown(&p.id)
                ));
                None
            } else {
                Some((
                    BandwidthPair {
                        up_mbps: b.up_mbps,
                        down_mbps: b.down_mbps,
                    },
                    BrutalAcknowledgement {
                        warning_revision: b.warning_revision,
                        acknowledged_at_unix: b.acknowledged_at_unix,
                    },
                ))
            }
        }
    };

    Ok(ProfileSettings {
        id: ProfileId::new(p.id),
        params,
        brutal,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::credentials::{EndpointCredentials, Hysteria2Bundle};
    use crate::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
    use crate::secret::Secret;
    use crate::secret_store::{MemorySecretStore, SecretStore};
    use crate::tls::ServerTrust;

    use super::*;

    const ID_A: &str = "123e4567-e89b-42d3-a456-426614174000";
    const ID_B: &str = "223e4567-e89b-42d3-a456-426614174001";

    fn endpoint(id: &str, label: &str, host: &str, origin: EndpointOrigin) -> Endpoint {
        let uuid = Uuid::parse_str(id).unwrap();
        Endpoint::new(
            EndpointId::from_uuid(uuid),
            label,
            EndpointAddress::new(host, 443).unwrap(),
            origin,
            CredentialRef::new(format!("endpoint-{id}")),
        )
        .unwrap()
    }

    fn endpoints() -> Vec<Endpoint> {
        let mut second = endpoint(
            ID_B,
            "oracle-mumbai",
            "203.0.113.7",
            EndpointOrigin::Provisioned {
                provider: "oci".into(),
                region: "ap-mumbai-1".into(),
                resource_ids: vec!["ocid1.instance.oc1.ap-mumbai-1.example".into()],
            },
        );
        second.set_enabled(false);
        vec![
            endpoint(ID_A, "home", "vpn.example.com", EndpointOrigin::Manual),
            second,
        ]
    }

    fn profiles() -> Vec<ConnectionProfile> {
        let mut dns = ProfileParams::new();
        dns.set("dns", "9.9.9.9");
        let mut hy2 =
            ConnectionProfile::new(ProfileId::new("hy2-default"), ProfileKind::Hysteria2, dns);
        hy2.enable_brutal(
            BandwidthPair {
                up_mbps: 50,
                down_mbps: 200,
            },
            BrutalAcknowledgement {
                warning_revision: BRUTAL_WARNING_REVISION,
                acknowledged_at_unix: 1_760_000_000,
            },
        )
        .unwrap();
        vec![
            ConnectionProfile::new(
                ProfileId::new("awg-default"),
                ProfileKind::AmneziaWg,
                ProfileParams::new(),
            ),
            hy2,
            ConnectionProfile::new(
                ProfileId::new("reality-default"),
                ProfileKind::VlessReality,
                ProfileParams::new(),
            ),
        ]
    }

    fn good_text() -> String {
        String::from_utf8(encode(&endpoints(), &profiles()).unwrap()).unwrap()
    }

    /// Replace `needle` once and require that it was there, so a typo in a test cannot make a
    /// tamper case pass vacuously.
    fn tamper(needle: &str, replacement: &str) -> Result<LoadedConfig, PersistError> {
        let good = good_text();
        let changed = good.replacen(needle, replacement, 1);
        assert_ne!(
            changed, good,
            "the text {needle:?} must be in the stored form"
        );
        decode(changed.as_bytes())
    }

    #[derive(Default)]
    struct MemoryFile(Mutex<Option<Vec<u8>>>);

    impl StateFile for Arc<MemoryFile> {
        fn read(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn write(&self, bytes: &[u8]) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    // ---------------------------------------------------------------- round trip

    #[test]
    fn a_saved_configuration_loads_back_identical() {
        let loaded = decode(&encode(&endpoints(), &profiles()).unwrap()).unwrap();

        assert_eq!(loaded.endpoints, endpoints());
        assert!(loaded.notes.is_empty());
        let hy2 = loaded
            .profiles
            .iter()
            .find(|p| p.id.as_str() == "hy2-default")
            .unwrap();
        assert_eq!(hy2.params.get("dns"), Some("9.9.9.9"));
        let (bandwidth, ack) = hy2.brutal.unwrap();
        assert_eq!((bandwidth.up_mbps, bandwidth.down_mbps), (50, 200));
        assert_eq!(ack.acknowledged_at_unix, 1_760_000_000);
        assert!(loaded
            .profiles
            .iter()
            .filter(|p| p.id.as_str() != "hy2-default")
            .all(|p| p.brutal.is_none()));
    }

    #[test]
    fn the_stored_form_is_deterministic() {
        assert_eq!(
            encode(&endpoints(), &profiles()).unwrap(),
            encode(&endpoints(), &profiles()).unwrap()
        );
    }

    #[test]
    fn an_empty_configuration_round_trips() {
        let loaded = decode(&encode(&[], &[]).unwrap()).unwrap();
        assert!(loaded.endpoints.is_empty() && loaded.profiles.is_empty());
    }

    #[test]
    fn enabled_state_and_origin_survive() {
        let loaded = decode(&encode(&endpoints(), &profiles()).unwrap()).unwrap();
        assert!(loaded.endpoints[0].is_enabled());
        assert!(!loaded.endpoints[1].is_enabled());
        assert!(matches!(
            loaded.endpoints[1].origin(),
            EndpointOrigin::Provisioned { region, .. } if region == "ap-mumbai-1"
        ));
    }

    #[test]
    fn health_is_not_stored() {
        let mut e = endpoints();
        e[0].set_health(dnet_core::health::EndpointHealth::new());
        let text = String::from_utf8(encode(&e, &profiles()).unwrap())
            .unwrap()
            .to_lowercase();
        for measurement in ["health", "rtt", "viab"] {
            assert!(
                !text.contains(measurement),
                "{measurement} must not be stored"
            );
        }
    }

    // ---------------------------------------------------------------- the store

    #[test]
    fn a_first_run_has_no_saved_configuration() {
        let store = ConfigStore::new(Box::new(Arc::new(MemoryFile::default())));
        assert_eq!(store.load(), Ok(None));
    }

    #[test]
    fn save_then_load_through_the_store() {
        let file = Arc::new(MemoryFile::default());
        let store = ConfigStore::new(Box::new(Arc::clone(&file)));
        store.save(&endpoints(), &profiles()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().endpoints, endpoints());
    }

    #[test]
    fn a_storage_failure_is_reported_as_one_and_loses_nothing() {
        struct Failing;
        impl StateFile for Failing {
            fn read(&self) -> Result<Option<Vec<u8>>, String> {
                Err("refusing the file: not controlled only by SYSTEM".into())
            }
            fn write(&self, _: &[u8]) -> Result<(), String> {
                Err("disk full".into())
            }
        }
        let store = ConfigStore::new(Box::new(Failing));
        assert!(matches!(store.load(), Err(PersistError::Storage(m)) if m.contains("refusing")));
        assert!(matches!(
            store.save(&endpoints(), &profiles()),
            Err(PersistError::Storage(m)) if m.contains("disk full")
        ));
    }

    // ---------------------------------------------------------------- hostile input

    #[test]
    fn the_file_holds_no_secret() {
        // An endpoint's credentials are in the secret store; the file must carry only their key.
        const SENTINEL: &str = "SENTINEL-persist-77";
        let secrets = MemorySecretStore::new();
        let key = SecretKey::parse(endpoints()[0].credentials()).unwrap();
        let bundle = EndpointCredentials {
            hysteria2: Some(Hysteria2Bundle {
                server_port: 44443,
                credentials: Hysteria2Credentials {
                    auth_password: Secret::new(format!("a-{SENTINEL}")),
                    obfs_password: Secret::new(format!("o-{SENTINEL}")),
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PublicCa {
                        server_name: "vpn.example.com".into(),
                    },
                },
            }),
            ..Default::default()
        };
        secrets.put(&key, &bundle).unwrap();

        let text = good_text();

        assert!(!text.contains(SENTINEL));
        assert!(
            text.contains(key.as_str()),
            "the file names the credentials by key"
        );
        assert_eq!(secrets.get(&key).unwrap(), Some(bundle));
    }

    #[test]
    fn another_version_is_named_as_such() {
        assert_eq!(
            tamper("\"version\": 1", "\"version\": 2").unwrap_err(),
            PersistError::UnsupportedVersion(2)
        );
        assert_eq!(
            decode(br#"{"version":9,"anything":true}"#).unwrap_err(),
            PersistError::UnsupportedVersion(9)
        );
    }

    #[test]
    fn a_missing_or_malformed_form_is_refused_not_defaulted() {
        for wire in [
            "",
            "null",
            "[]",
            "{}",
            r#"{"version":"1"}"#,
            r#"{"version":1}"#,
            "{",
        ] {
            assert!(
                matches!(decode(wire.as_bytes()), Err(PersistError::Malformed(_))),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_refused_at_every_level() {
        for (needle, injected) in [
            ("\"version\": 1", "\"version\": 1,\n  \"extra\": 1"),
            (
                "\"label\": \"home\"",
                "\"label\": \"home\",\n      \"extra\": 1",
            ),
            (
                "\"kind\": \"manual\"",
                "\"kind\": \"manual\",\n        \"extra\": 1",
            ),
            ("\"up_mbps\": 50", "\"up_mbps\": 50,\n        \"extra\": 1"),
        ] {
            assert!(
                matches!(tamper(needle, injected), Err(PersistError::Malformed(_))),
                "{needle}"
            );
        }
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        assert_eq!(
            decode(&vec![b' '; MAX_CONFIG_LEN + 1]).unwrap_err(),
            PersistError::TooLarge
        );
    }

    #[test]
    fn too_many_endpoints_are_refused() {
        let many: Vec<Endpoint> = (0..=MAX_ENDPOINTS)
            .map(|i| {
                endpoint(
                    &Uuid::from_u128(i as u128 + 1).to_string(),
                    &format!("e{i}"),
                    "vpn.example.com",
                    EndpointOrigin::Manual,
                )
            })
            .collect();
        assert!(
            matches!(encode(&many, &[]), Err(PersistError::Invalid(m)) if m.contains("more than"))
        );
    }

    #[test]
    fn each_endpoint_rule_refuses_the_whole_file() {
        let id = "\"id\": \"123e4567-e89b-42d3-a456-426614174000\"";
        let credential = "\"credential\": \"endpoint-123e4567-e89b-42d3-a456-426614174000\"";
        let host = "\"host\": \"vpn.example.com\"";
        let cases: [(&str, &str, &str); 12] = [
            (id, "\"id\": \"not-a-uuid\"", "not a UUID"),
            (
                id,
                "\"id\": \"{123e4567-e89b-42d3-a456-426614174000}\"",
                "not a UUID",
            ),
            ("\"label\": \"home\"", "\"label\": \"\"", "label"),
            ("\"label\": \"home\"", "\"label\": \"ho\\nme\"", "label"),
            (host, "\"host\": \"vpn example.com\"", "host"),
            (host, "\"host\": \"http://vpn.example.com\"", "host"),
            (host, "\"host\": \"localhost\"", "host"),
            ("\"port\": 443", "\"port\": 0", "port"),
            (
                credential,
                "\"credential\": \"..\\\\..\\\\x\"",
                "credential",
            ),
            (credential, "\"credential\": \"dpapi:home\"", "credential"),
            ("\"kind\": \"manual\"", "\"kind\": \"cloud\"", "origin"),
            ("\"provider\": \"oci\"", "\"provider\": \"\"", "provider"),
        ];
        for (needle, replacement, mention) in cases {
            let err = tamper(needle, replacement).unwrap_err();
            let PersistError::Invalid(message) = &err else {
                panic!("{needle} -> {err:?} should be an invalid entry");
            };
            assert!(message.contains(mention), "{needle}: {message}");
            assert!(
                message.starts_with("endpoint "),
                "the entry is named: {message}"
            );
        }
    }

    #[test]
    fn a_label_or_id_used_twice_is_refused() {
        let mut dup_label = endpoints();
        dup_label[1] = endpoint(ID_B, "home", "203.0.113.7", EndpointOrigin::Manual);
        assert!(
            matches!(encode(&dup_label, &[]), Err(PersistError::Invalid(m)) if m.contains("label"))
        );

        let mut dup_id = endpoints();
        dup_id[1] = endpoint(ID_A, "other", "203.0.113.7", EndpointOrigin::Manual);
        assert!(matches!(encode(&dup_id, &[]), Err(PersistError::Invalid(m)) if m.contains("id")));
    }

    #[test]
    fn an_ip_literal_host_is_accepted_in_both_families() {
        for host in ["203.0.113.7", "2001:db8::7"] {
            let e = vec![endpoint(ID_A, "home", host, EndpointOrigin::Manual)];
            assert_eq!(
                decode(&encode(&e, &[]).unwrap()).unwrap().endpoints,
                e,
                "{host}"
            );
        }
    }

    #[test]
    fn a_provisioned_origin_needs_all_three_fields_and_a_manual_one_none() {
        assert!(tamper(
            "\"kind\": \"manual\"",
            "\"kind\": \"manual\",\n        \"region\": \"x\""
        )
        .is_err());
        assert!(tamper("\"region\": \"ap-mumbai-1\",\n        ", "").is_err());
    }

    #[test]
    fn the_profile_rules_refuse_the_whole_file() {
        let cases: [(&str, &str, &str); 6] = [
            (
                "\"id\": \"awg-default\"",
                "\"id\": \"my-own-profile\"",
                "not one this build defines",
            ),
            (
                "\"id\": \"reality-default\"",
                "\"id\": \"hy2-default\"",
                "appears twice",
            ),
            ("\"dns\": \"9.9.9.9\"", "\"DNS\": \"9.9.9.9\"", "parameter"),
            (
                "\"dns\": \"9.9.9.9\"",
                "\"dns\": \"9.9.9.9\\n\"",
                "parameter",
            ),
            ("\"up_mbps\": 50", "\"up_mbps\": 0", "plausible"),
            ("\"up_mbps\": 50", "\"up_mbps\": 2000000", "plausible"),
        ];
        for (needle, replacement, mention) in cases {
            let err = tamper(needle, replacement).unwrap_err();
            let PersistError::Invalid(message) = &err else {
                panic!("{needle} -> {err:?} should be an invalid entry");
            };
            assert!(message.contains(mention), "{needle}: {message}");
        }
    }

    #[test]
    fn a_bandwidth_that_does_not_fit_is_malformed_not_wrapped() {
        // 4,000,000,000 does not fit a u32 on this field's wire type; it must not wrap to a
        // plausible number.
        assert!(matches!(
            tamper("\"down_mbps\": 200", "\"down_mbps\": 4294967296"),
            Err(PersistError::Malformed(_))
        ));
    }

    #[test]
    fn brutal_on_a_profile_that_is_not_hysteria_2_is_refused() {
        let good = good_text();
        let needle = "\"id\": \"awg-default\",\n      \"params\": {},\n      \"brutal\": null";
        let injected = "\"id\": \"awg-default\",\n      \"params\": {},\n      \"brutal\": {\"up_mbps\":1,\"down_mbps\":1,\"warning_revision\":1,\"acknowledged_at_unix\":1}";
        let text = good.replacen(needle, injected, 1);
        assert_ne!(text, good, "the injection point must exist");
        assert!(matches!(
            decode(text.as_bytes()),
            Err(PersistError::Invalid(m)) if m.contains("only Hysteria 2")
        ));
    }

    #[test]
    fn a_brutal_acknowledgement_of_another_warning_turns_brutal_off_and_says_so() {
        let loaded = tamper(
            &format!("\"warning_revision\": {BRUTAL_WARNING_REVISION}"),
            &format!("\"warning_revision\": {}", BRUTAL_WARNING_REVISION + 1),
        )
        .expect("a stale acknowledgement is dropped, not an error");

        let hy2 = loaded
            .profiles
            .iter()
            .find(|p| p.id.as_str() == "hy2-default")
            .unwrap();
        assert!(
            hy2.brutal.is_none(),
            "Brutal must not survive an acknowledgement of another warning"
        );
        assert_eq!(loaded.notes.len(), 1);
        assert!(loaded.notes[0].contains("hy2-default") && loaded.notes[0].contains("turned off"));
        // The rest of the file is intact.
        assert_eq!(loaded.endpoints, endpoints());
        assert_eq!(hy2.params.get("dns"), Some("9.9.9.9"));
    }

    #[test]
    fn encode_refuses_what_decode_would_refuse() {
        // A reference that is not a valid secret-store key would turn the next start into a refused
        // configuration, so it must not be written.
        let bad = Endpoint::new(
            EndpointId::new(),
            "home",
            EndpointAddress::new("vpn.example.com", 443).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new("dpapi:home"),
        )
        .unwrap();
        assert!(matches!(encode(&[bad], &[]), Err(PersistError::Invalid(_))));
    }

    #[test]
    fn errors_never_quote_the_file() {
        // A refused file may have been planted; what it says is not echoed back. (A label may
        // legitimately contain printable ASCII, so plant the text where it is refused.)
        let good = good_text();
        for (needle, field) in [
            ("\"vpn.example.com\"", "host"),
            ("\"oci\"", "provider"),
            ("\"awg-default\"", "profile id"),
        ] {
            let planted = good.replacen(needle, "\"<script>alert(1)</script>\\n\"", 1);
            assert_ne!(planted, good, "{field}");
            let err = decode(planted.as_bytes()).expect_err(field).to_string();
            assert!(!err.contains("<script>"), "{field}: {err}");
        }
    }

    #[test]
    fn the_default_paths_are_beside_the_run_directory() {
        assert!(default_config_path().ends_with(r"DNet Engine\state\config.json"));
        assert!(default_secrets_dir().ends_with(r"DNet Engine\state\secrets"));
    }
}
