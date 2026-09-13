//! The v1 feed document (ADR-0002 §5.3, §5.4): proposals for bundled profiles' parameters,
//! nothing else.
//!
//! The schema is closed. Every object refuses unknown fields, so routing rules, DNS servers,
//! endpoints, credentials, Brutal bandwidth and free text have nowhere to go (ADR-0002 §1,
//! FEED-14). Parameters are split into `client` (the client may apply them alone) and
//! `endpoint` (they need the endpoint reconfigured first, §6).

use serde::Deserialize;

use crate::catalogue::bundled_kind;
use crate::hostname::{validate_target_domain, MAX_NAME_LEN};
use crate::ids::ProfileId;
use crate::profile::ProfileKind;
use crate::transport_params::amneziawg_feed as awg;
use crate::transport_params::{gecko_packet_sizes_valid, BbrProfile, UtlsFingerprint};

use super::keys::{check_issued_and_expiry, lifetime};
use super::{Document, FeedError, FEED_MAX_LIFETIME_SECS};

/// Most profile entries in one feed.
pub const MAX_PROFILES: usize = 16;
/// Most REALITY target-domain candidates in one entry.
pub const MAX_TARGET_CANDIDATES: usize = 8;

// ------------------------------------------------------------------ wire schema

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedDocumentJson {
    keys_version: u64,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    profiles: Vec<ProfileEntryJson>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProfileEntryJson {
    AmneziaWg {
        profile_id: String,
        client: Option<AwgClientJson>,
        endpoint: Option<AwgEndpointJson>,
    },
    Hysteria2 {
        profile_id: String,
        client: Option<Hy2ClientJson>,
        endpoint: Option<Hy2EndpointJson>,
    },
    VlessReality {
        profile_id: String,
        client: Option<RealityClientJson>,
        endpoint: Option<RealityEndpointJson>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwgClientJson {
    jc: Option<u32>,
    jmin: Option<u32>,
    jmax: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwgEndpointJson {
    s1: Option<u32>,
    s2: Option<u32>,
    h1: Option<u32>,
    h2: Option<u32>,
    h3: Option<u32>,
    h4: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2ClientJson {
    bbr_profile: Option<BbrProfile>,
    chrome_parrot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2EndpointJson {
    obfs: Option<ObfsJson>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ObfsJson {
    /// An empty struct variant, not a unit variant: serde ignores unknown fields on an
    /// internally tagged unit variant even under `deny_unknown_fields` (caught by FEED-09).
    Salamander {},
    Gecko {
        min_packet_size: u16,
        max_packet_size: u16,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityClientJson {
    utls_fingerprint: Option<UtlsFingerprint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityEndpointJson {
    target_domain_candidates: Option<Vec<String>>,
}

// ------------------------------------------------------------------ validated form

/// A feed document whose schema, bounds and catalogue references have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedDocument {
    pub keys_version: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub profiles: Vec<ProfileProposal>,
}

/// Proposed parameters for one bundled profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileProposal {
    pub profile_id: ProfileId,
    pub params: ProposedParams,
}

/// Proposed parameters by kind. An absent section is a proposal with every field `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposedParams {
    AmneziaWg {
        client: JunkPacketProposal,
        endpoint: AmneziaWgHeaderProposal,
    },
    Hysteria2 {
        client: Hysteria2ClientProposal,
        endpoint: Hysteria2EndpointProposal,
    },
    VlessReality {
        client: RealityClientProposal,
        endpoint: RealityEndpointProposal,
    },
}

/// AmneziaWG junk-packet parameters, the client-only group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JunkPacketProposal {
    pub jc: Option<u32>,
    pub jmin: Option<u32>,
    pub jmax: Option<u32>,
}

/// AmneziaWG junk-packet values in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JunkPackets {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
}

impl JunkPacketProposal {
    fn is_empty(&self) -> bool {
        self.jc.is_none() && self.jmin.is_none() && self.jmax.is_none()
    }

    /// The values in effect once this proposal is applied over `current`. The cross-field
    /// rule is checked on the result (ADR-0002 §5.4).
    pub fn merged_over(&self, current: JunkPackets) -> Result<JunkPackets, FeedError> {
        let merged = JunkPackets {
            jc: self.jc.unwrap_or(current.jc),
            jmin: self.jmin.unwrap_or(current.jmin),
            jmax: self.jmax.unwrap_or(current.jmax),
        };
        if merged.jmin >= merged.jmax {
            return Err(invalid("jmin", "must be less than jmax"));
        }
        Ok(merged)
    }
}

/// AmneziaWG padding and header parameters, which the endpoint must share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmneziaWgHeaderProposal {
    pub s1: Option<u32>,
    pub s2: Option<u32>,
    pub h1: Option<u32>,
    pub h2: Option<u32>,
    pub h3: Option<u32>,
    pub h4: Option<u32>,
}

/// AmneziaWG padding and header values in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaWgHeaders {
    pub s1: u32,
    pub s2: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl AmneziaWgHeaderProposal {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The values in effect once this proposal is applied over `current`, with the
    /// cross-field rules checked on the result.
    pub fn merged_over(&self, current: AmneziaWgHeaders) -> Result<AmneziaWgHeaders, FeedError> {
        let merged = AmneziaWgHeaders {
            s1: self.s1.unwrap_or(current.s1),
            s2: self.s2.unwrap_or(current.s2),
            h1: self.h1.unwrap_or(current.h1),
            h2: self.h2.unwrap_or(current.h2),
            h3: self.h3.unwrap_or(current.h3),
            h4: self.h4.unwrap_or(current.h4),
        };
        check_padding_sizes_differ(merged.s1, merged.s2)?;
        check_distinct_headers(&[merged.h1, merged.h2, merged.h3, merged.h4])?;
        Ok(merged)
    }
}

/// Hysteria 2 client-only parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hysteria2ClientProposal {
    pub bbr_profile: Option<BbrProfile>,
    pub chrome_parrot: Option<bool>,
}

/// Hysteria 2 parameters the endpoint must share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hysteria2EndpointProposal {
    pub obfs: Option<ObfsProposal>,
}

/// A whole obfuscation layer. Proposed as a unit, never field by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsProposal {
    Salamander,
    Gecko {
        min_packet_size: u16,
        max_packet_size: u16,
    },
}

/// VLESS+REALITY client-only parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealityClientProposal {
    pub utls_fingerprint: Option<UtlsFingerprint>,
}

/// VLESS+REALITY parameters the endpoint must share.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityEndpointProposal {
    /// Validated, lower-cased, distinct hostnames. Provisioning picks one (§6).
    pub target_domain_candidates: Option<Vec<String>>,
}

// ------------------------------------------------------------------ parsing

impl FeedDocument {
    /// Parse a **verified** feed payload and apply every rule that does not depend on the clock
    /// or on stored state: schema, lifetime, catalogue references, parameter bounds.
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, FeedError> {
        let json: FeedDocumentJson =
            serde_json::from_slice(payload).map_err(|e| FeedError::MalformedPayload {
                document: Document::Feed,
                detail: e.to_string(),
            })?;
        lifetime(
            json.issued_at,
            json.expires_at,
            FEED_MAX_LIFETIME_SECS,
            "feed lifetime",
        )?;
        if json.profiles.is_empty() || json.profiles.len() > MAX_PROFILES {
            return Err(invalid("profiles", "must list 1 to 16 entries"));
        }

        let mut profiles: Vec<ProfileProposal> = Vec::with_capacity(json.profiles.len());
        for entry in json.profiles {
            let proposal = parse_entry(entry)?;
            if profiles.iter().any(|p| p.profile_id == proposal.profile_id) {
                return Err(FeedError::DuplicateProfile(
                    proposal.profile_id.as_str().to_string(),
                ));
            }
            profiles.push(proposal);
        }

        Ok(Self {
            keys_version: json.keys_version,
            sequence: json.sequence,
            issued_at: json.issued_at,
            expires_at: json.expires_at,
            profiles,
        })
    }

    /// The feed time checks (ADR-0002 §4, feed step 7).
    pub(crate) fn check_current(&self, now: u64) -> Result<(), FeedError> {
        check_issued_and_expiry(Document::Feed, self.issued_at, self.expires_at, now)
    }
}

fn parse_entry(entry: ProfileEntryJson) -> Result<ProfileProposal, FeedError> {
    let (profile_id, kind, params, empty) = match entry {
        ProfileEntryJson::AmneziaWg {
            profile_id,
            client,
            endpoint,
        } => {
            let client = client.map(awg_client).transpose()?.unwrap_or_default();
            let endpoint = endpoint.map(awg_endpoint).transpose()?.unwrap_or_default();
            let empty = client.is_empty() && endpoint.is_empty();
            (
                profile_id,
                ProfileKind::AmneziaWg,
                ProposedParams::AmneziaWg { client, endpoint },
                empty,
            )
        }
        ProfileEntryJson::Hysteria2 {
            profile_id,
            client,
            endpoint,
        } => {
            let client = client
                .map(|c| Hysteria2ClientProposal {
                    bbr_profile: c.bbr_profile,
                    chrome_parrot: c.chrome_parrot,
                })
                .unwrap_or_default();
            let endpoint = endpoint.map(hy2_endpoint).transpose()?.unwrap_or_default();
            let empty = client == Hysteria2ClientProposal::default()
                && endpoint == Hysteria2EndpointProposal::default();
            (
                profile_id,
                ProfileKind::Hysteria2,
                ProposedParams::Hysteria2 { client, endpoint },
                empty,
            )
        }
        ProfileEntryJson::VlessReality {
            profile_id,
            client,
            endpoint,
        } => {
            let client = client
                .map(|c| RealityClientProposal {
                    utls_fingerprint: c.utls_fingerprint,
                })
                .unwrap_or_default();
            let endpoint = endpoint
                .map(reality_endpoint)
                .transpose()?
                .unwrap_or_default();
            let empty = client == RealityClientProposal::default()
                && endpoint == RealityEndpointProposal::default();
            (
                profile_id,
                ProfileKind::VlessReality,
                ProposedParams::VlessReality { client, endpoint },
                empty,
            )
        }
    };

    if profile_id.len() > MAX_NAME_LEN {
        return Err(invalid("profile_id", "is too long"));
    }
    match bundled_kind(&profile_id) {
        None => return Err(FeedError::UnknownProfile(profile_id)),
        Some(defined) if defined != kind => return Err(FeedError::KindMismatch(profile_id)),
        Some(_) => {}
    }
    if empty {
        return Err(FeedError::EmptyProposal(profile_id));
    }
    Ok(ProfileProposal {
        profile_id: ProfileId::new(profile_id),
        params,
    })
}

fn awg_client(json: AwgClientJson) -> Result<JunkPacketProposal, FeedError> {
    if let Some(jc) = json.jc {
        in_range("jc", jc, awg::JC_MIN, awg::JC_MAX)?;
    }
    for (field, value) in [("jmin", json.jmin), ("jmax", json.jmax)] {
        if let Some(v) = value {
            in_range(field, v, 0, awg::JUNK_SIZE_MAX)?;
        }
    }
    if let (Some(jmin), Some(jmax)) = (json.jmin, json.jmax) {
        if jmin >= jmax {
            return Err(invalid("jmin", "must be less than jmax"));
        }
    }
    Ok(JunkPacketProposal {
        jc: json.jc,
        jmin: json.jmin,
        jmax: json.jmax,
    })
}

fn awg_endpoint(json: AwgEndpointJson) -> Result<AmneziaWgHeaderProposal, FeedError> {
    if let Some(s1) = json.s1 {
        in_range("s1", s1, 0, awg::S1_MAX)?;
    }
    if let Some(s2) = json.s2 {
        in_range("s2", s2, 0, awg::S2_MAX)?;
    }
    if let (Some(s1), Some(s2)) = (json.s1, json.s2) {
        check_padding_sizes_differ(s1, s2)?;
    }
    let headers = [
        ("h1", json.h1),
        ("h2", json.h2),
        ("h3", json.h3),
        ("h4", json.h4),
    ];
    for (field, value) in headers {
        if let Some(h) = value {
            in_range(field, h, awg::HEADER_MIN, awg::HEADER_MAX)?;
        }
    }
    let present: Vec<u32> = headers.iter().filter_map(|(_, v)| *v).collect();
    check_distinct_headers(&present)?;
    Ok(AmneziaWgHeaderProposal {
        s1: json.s1,
        s2: json.s2,
        h1: json.h1,
        h2: json.h2,
        h3: json.h3,
        h4: json.h4,
    })
}

fn hy2_endpoint(json: Hy2EndpointJson) -> Result<Hysteria2EndpointProposal, FeedError> {
    let obfs = match json.obfs {
        None => None,
        Some(ObfsJson::Salamander {}) => Some(ObfsProposal::Salamander),
        Some(ObfsJson::Gecko {
            min_packet_size,
            max_packet_size,
        }) => {
            if !gecko_packet_sizes_valid(min_packet_size, max_packet_size) {
                return Err(invalid(
                    "obfs.min_packet_size",
                    "Gecko sizes must satisfy 256 <= min <= max <= 1400",
                ));
            }
            Some(ObfsProposal::Gecko {
                min_packet_size,
                max_packet_size,
            })
        }
    };
    Ok(Hysteria2EndpointProposal { obfs })
}

fn reality_endpoint(json: RealityEndpointJson) -> Result<RealityEndpointProposal, FeedError> {
    let Some(candidates) = json.target_domain_candidates else {
        return Ok(RealityEndpointProposal::default());
    };
    if candidates.is_empty() || candidates.len() > MAX_TARGET_CANDIDATES {
        return Err(invalid(
            "target_domain_candidates",
            "must list 1 to 8 names",
        ));
    }
    let mut validated: Vec<String> = Vec::with_capacity(candidates.len());
    for name in &candidates {
        let name = validate_target_domain(name)
            .map_err(|reason| invalid("target_domain_candidates", reason))?;
        if validated.contains(&name) {
            return Err(invalid("target_domain_candidates", "lists a name twice"));
        }
        validated.push(name);
    }
    Ok(RealityEndpointProposal {
        target_domain_candidates: Some(validated),
    })
}

fn check_padding_sizes_differ(s1: u32, s2: u32) -> Result<(), FeedError> {
    if s1.checked_add(awg::INIT_RESPONSE_SIZE_DIFFERENCE) == Some(s2) {
        return Err(invalid(
            "s2",
            "must not equal s1 + 56 (padded initiation and response would match in size)",
        ));
    }
    Ok(())
}

fn check_distinct_headers(headers: &[u32]) -> Result<(), FeedError> {
    for (i, a) in headers.iter().enumerate() {
        if headers[i + 1..].contains(a) {
            return Err(invalid("h1..h4", "must be pairwise distinct"));
        }
    }
    Ok(())
}

fn in_range(field: &'static str, value: u32, min: u32, max: u32) -> Result<(), FeedError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(invalid(field, "is out of bounds"))
    }
}

fn invalid(field: &'static str, reason: &'static str) -> FeedError {
    FeedError::InvalidField { field, reason }
}
