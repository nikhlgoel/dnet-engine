// SPDX-License-Identifier: GPL-3.0-or-later
//! T066a — feed step 8: a trial configuration for every profile, with the proposed values (ADR-0002
//! §4).
//!
//! A feed that parses and verifies can still carry values the cores would refuse once they are put
//! together: an obfuscation layer the pinned core does not accept, a header set that overlaps, a
//! junk-packet range that leaves no room. Finding that out on a person's machine, mid-connection, is
//! the worst place to find it. So before a feed is kept, a configuration is generated for each profile
//! the build defines, through the same functions a real connection uses (`plan_tunnel`,
//! `build_set_device`), with the feed's client **and** endpoint values in place. If any one fails the
//! feed is refused whole (step 9).
//!
//! The endpoint and credentials used are a fixture: an address from the documentation range
//! (192.0.2.0/24, RFC 5737) and fixed made-up key material. Nothing here is ever connected to, and
//! nothing about the person's endpoints is read: this checks the feed, not the person's setup.
//!
//! What generation cannot say is whether a value *works* against a real server. The bounds in
//! `dnet_core::feed::document` keep proposals inside what the cores accept, and a feed's values are
//! only ever applied to the client side alone (endpoint values wait for the person's consent).

use std::net::Ipv4Addr;

use dnet_config::amneziawg::{build_set_device, ObfuscationParams, PeerConfig, PrivateKey};
use dnet_config::credentials::{
    AmneziaWgCredentials, EndpointCredentials, Hysteria2Bundle, RealityBundle,
};
use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use dnet_config::primary::FakeIpHalf;
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_core::builtin_rules::builtin_rules_for;
use dnet_core::catalogue::BUNDLED_PROFILES;
use dnet_core::credential::CredentialRef;
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::feed::document::{AmneziaWgHeaders, JunkPackets, ObfsProposal, ProposedParams};
use dnet_core::feed::{ClientDefinitions, FeedDocument};
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};

use crate::plan::plan_tunnel;

/// The fixture's address, from the range reserved for documentation.
const TRIAL_HOST: &str = "192.0.2.1";

/// The values AmneziaWG has when the feed says nothing, which a proposal is merged over.
const BUNDLED_JUNK: JunkPackets = JunkPackets {
    jc: 4,
    jmin: 40,
    jmax: 70,
};
const BUNDLED_HEADERS: AmneziaWgHeaders = AmneziaWgHeaders {
    s1: 15,
    s2: 20,
    h1: 1_053_421_987,
    h2: 2_083_245_612,
    h3: 3_175_921_403,
    h4: 4_012_837_465,
};

/// Generate a configuration for every bundled profile with `document`'s values. `Err` names the
/// profile and what the generator refused (never a value from the feed that it was not already
/// willing to show: the document is signed content).
pub fn trial_generate(document: &FeedDocument) -> Result<(), String> {
    let definitions = ClientDefinitions::from_feed(document);
    for entry in BUNDLED_PROFILES {
        let profile =
            ConnectionProfile::new(ProfileId::new(entry.id), entry.kind, ProfileParams::new());
        let proposal = document
            .profiles
            .iter()
            .find(|p| p.profile_id.as_str() == entry.id)
            .map(|p| &p.params);
        for credentials in fixtures(entry.kind, proposal)? {
            generate(&profile, &credentials, &definitions)
                .map_err(|why| format!("{}: {why}", entry.id))?;
        }
        if let Some(ProposedParams::AmneziaWg { client, endpoint }) = proposal {
            amneziawg_device(client, endpoint).map_err(|why| format!("{}: {why}", entry.id))?;
        }
    }
    Ok(())
}

fn generate(
    profile: &ConnectionProfile,
    credentials: &EndpointCredentials,
    definitions: &ClientDefinitions,
) -> Result<(), String> {
    let endpoint = Endpoint::new(
        EndpointId::new(),
        "trial",
        EndpointAddress::new(TRIAL_HOST, 443).expect("a fixed, valid address"),
        EndpointOrigin::Manual,
        CredentialRef::new("trial"),
    )
    .expect("a fixed, valid label");
    plan_tunnel(
        profile,
        &endpoint,
        credentials,
        definitions,
        &builtin_rules_for(None, Policy::Block),
        FakeIpHalf::Low,
    )
    .map(drop)
    .map_err(|e| e.to_string())
}

/// The fixtures a profile is generated against: one per endpoint value the feed proposes (a Gecko
/// layer, each candidate REALITY domain), or the bundled values when it proposes none.
fn fixtures(
    kind: ProfileKind,
    proposal: Option<&ProposedParams>,
) -> Result<Vec<EndpointCredentials>, String> {
    Ok(match kind {
        ProfileKind::AmneziaWg => vec![awg_fixture()],
        ProfileKind::Hysteria2 => {
            let obfs = match proposal {
                Some(ProposedParams::Hysteria2 { endpoint, .. }) => endpoint.obfs,
                _ => None,
            };
            vec![hysteria2_fixture(match obfs {
                Some(ObfsProposal::Gecko {
                    min_packet_size,
                    max_packet_size,
                }) => Hysteria2Obfs::Gecko {
                    min_packet_size,
                    max_packet_size,
                },
                Some(ObfsProposal::Salamander) | None => Hysteria2Obfs::Salamander,
            })]
        }
        ProfileKind::VlessReality => {
            let candidates: Vec<String> = match proposal {
                Some(ProposedParams::VlessReality { endpoint, .. }) => endpoint
                    .target_domain_candidates
                    .clone()
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            if candidates.is_empty() {
                vec![reality_fixture("www.example.com")?]
            } else {
                candidates
                    .iter()
                    .map(|d| reality_fixture(d))
                    .collect::<Result<_, _>>()?
            }
        }
    })
}

fn awg_fixture() -> EndpointCredentials {
    EndpointCredentials {
        amneziawg: Some(AmneziaWgCredentials {
            client_private_key: PrivateKey::new("a".repeat(64)),
            server_public_key: "b".repeat(64),
            client_address: Ipv4Addr::new(10, 66, 0, 2),
            prefix_len: 24,
            obfuscation: ObfuscationParams {
                jc: BUNDLED_JUNK.jc,
                jmin: BUNDLED_JUNK.jmin,
                jmax: BUNDLED_JUNK.jmax,
                s1: BUNDLED_HEADERS.s1,
                s2: BUNDLED_HEADERS.s2,
                h1: BUNDLED_HEADERS.h1,
                h2: BUNDLED_HEADERS.h2,
                h3: BUNDLED_HEADERS.h3,
                h4: BUNDLED_HEADERS.h4,
            },
            server_port: 51820,
        }),
        ..EndpointCredentials::default()
    }
}

fn hysteria2_fixture(obfs: Hysteria2Obfs) -> EndpointCredentials {
    EndpointCredentials {
        hysteria2: Some(Hysteria2Bundle {
            server_port: 44443,
            credentials: Hysteria2Credentials {
                auth_password: Secret::new("trial-auth-0123456789"),
                obfs_password: Secret::new("trial-obfs-0123456789"),
            },
            endpoint: Hysteria2EndpointParams {
                obfs,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: "trial.invalid".into(),
                    spki_sha256: [7; 32],
                },
            },
        }),
        ..EndpointCredentials::default()
    }
}

fn reality_fixture(domain: &str) -> Result<EndpointCredentials, String> {
    // A domain the generator's own parser refuses is a refusal of the feed, not of the fixture.
    let target_domain = TargetDomain::parse(domain)
        .map_err(|e| format!("a REALITY target domain candidate was refused: {e}"))?;
    Ok(EndpointCredentials {
        reality: Some(RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new("123e4567-e89b-42d3-a456-426614174000"),
                short_id: Secret::new("0123abcd"),
            },
            endpoint: RealityEndpointParams {
                target_domain,
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .expect("a fixed key"),
                flow: VlessFlow::Vision,
            },
        }),
        ..EndpointCredentials::default()
    })
}

/// AW-04: the device request, with the proposal merged over the bundled values, must be buildable.
fn amneziawg_device(
    client: &dnet_core::feed::document::JunkPacketProposal,
    endpoint: &dnet_core::feed::document::AmneziaWgHeaderProposal,
) -> Result<(), String> {
    let junk = client
        .merged_over(BUNDLED_JUNK)
        .map_err(|e| e.to_string())?;
    let headers = endpoint
        .merged_over(BUNDLED_HEADERS)
        .map_err(|e| e.to_string())?;
    let obfuscation = ObfuscationParams {
        jc: junk.jc,
        jmin: junk.jmin,
        jmax: junk.jmax,
        s1: headers.s1,
        s2: headers.s2,
        h1: headers.h1,
        h2: headers.h2,
        h3: headers.h3,
        h4: headers.h4,
    };
    build_set_device(
        &PrivateKey::new("a".repeat(64)),
        &obfuscation,
        &PeerConfig {
            public_key: "b".repeat(64),
            endpoint: format!("{TRIAL_HOST}:51820"),
            allowed_ips: vec!["0.0.0.0/0".into()],
            persistent_keepalive: Some(25),
        },
    )
    .map(drop)
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
