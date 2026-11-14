// SPDX-License-Identifier: GPL-3.0-or-later
//! What an applied feed means for this client (ADR-0002 §6).
//!
//! A feed proposes parameters per bundled profile in two sections, and the sections are treated
//! very differently:
//!
//! - The **client** section can be applied by the client alone, because the endpoint does not care
//!   which value it is: how the QUIC handshake is shaped, which congestion profile is used, which
//!   browser the TLS hello imitates. [`ClientDefinitions`] carries those, and a connection generated
//!   *after* they are applied uses them. A connection already up is never regenerated.
//! - The **endpoint** section is *never applied by the client alone*, because the endpoint would
//!   still be running the old values and the connection would fail. [`staged_endpoint_updates`] lists
//!   what the feed proposes, for the interface to offer to apply to the person's endpoint with their
//!   consent. The values in effect always come from the endpoint record; the feed proposes and never
//!   overrides.
//!
//! AmneziaWG's junk-packet proposal (`jc`, `jmin`, `jmax`) is a client parameter in the feed's own
//! terms, but this client keeps those three numbers inside the endpoint's stored credentials, beside
//! the padding and header values the endpoint shares, and nothing records whether a person chose them
//! or provisioning filled them in. A feed that overrode them could silently replace a value someone
//! set, so it does not: they are validated and kept with the feed, and not applied. (Precedence in
//! the ADR is user, then feed, then bundled default; there is no way yet to tell the first from the
//! third.)
//!
//! Pure logic: no I/O.

use crate::ids::ProfileId;

use super::document::{
    FeedDocument, Hysteria2ClientProposal, ProposedParams, RealityClientProposal,
};

/// The client-section parameters in effect from an applied feed. `Default` is "the feed says
/// nothing": every field `None`, so the bundled defaults apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientDefinitions {
    pub hysteria2: Hysteria2ClientProposal,
    pub reality: RealityClientProposal,
    /// The sequence of the feed these came from, for "definitions updated (sequence N)".
    pub sequence: Option<u64>,
}

impl ClientDefinitions {
    /// What `document` says about the client sections of the profiles this build knows.
    pub fn from_feed(document: &FeedDocument) -> Self {
        let mut definitions = Self {
            sequence: Some(document.sequence),
            ..Self::default()
        };
        for proposal in &document.profiles {
            match &proposal.params {
                ProposedParams::Hysteria2 { client, .. } => definitions.hysteria2 = *client,
                ProposedParams::VlessReality { client, .. } => definitions.reality = *client,
                // Not applied; see the module documentation.
                ProposedParams::AmneziaWg { .. } => {}
            }
        }
        definitions
    }
}

/// One profile's endpoint-section proposal, staged for the person to apply to their endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEndpointUpdate {
    pub profile: ProfileId,
    pub params: ProposedParams,
}

/// The endpoint-section proposals in `document` that actually propose something.
pub fn staged_endpoint_updates(document: &FeedDocument) -> Vec<StagedEndpointUpdate> {
    document
        .profiles
        .iter()
        .filter(|p| proposes_endpoint_change(&p.params))
        .map(|p| StagedEndpointUpdate {
            profile: p.profile_id.clone(),
            params: p.params.clone(),
        })
        .collect()
}

fn proposes_endpoint_change(params: &ProposedParams) -> bool {
    match params {
        ProposedParams::AmneziaWg { endpoint, .. } => *endpoint != Default::default(),
        ProposedParams::Hysteria2 { endpoint, .. } => *endpoint != Default::default(),
        ProposedParams::VlessReality { endpoint, .. } => *endpoint != Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::document::{
        AmneziaWgHeaderProposal, Hysteria2EndpointProposal, JunkPacketProposal, ObfsProposal,
        ProfileProposal, RealityEndpointProposal,
    };
    use super::*;
    use crate::transport_params::{BbrProfile, UtlsFingerprint};

    fn document(profiles: Vec<ProfileProposal>) -> FeedDocument {
        FeedDocument {
            keys_version: 1,
            sequence: 9,
            issued_at: 0,
            expires_at: 1,
            profiles,
        }
    }

    fn hy2(
        client: Hysteria2ClientProposal,
        endpoint: Hysteria2EndpointProposal,
    ) -> ProfileProposal {
        ProfileProposal {
            profile_id: ProfileId::new("hy2-default"),
            params: ProposedParams::Hysteria2 { client, endpoint },
        }
    }

    fn reality(
        client: RealityClientProposal,
        endpoint: RealityEndpointProposal,
    ) -> ProfileProposal {
        ProfileProposal {
            profile_id: ProfileId::new("reality-default"),
            params: ProposedParams::VlessReality { client, endpoint },
        }
    }

    fn awg(client: JunkPacketProposal, endpoint: AmneziaWgHeaderProposal) -> ProfileProposal {
        ProfileProposal {
            profile_id: ProfileId::new("awg-default"),
            params: ProposedParams::AmneziaWg { client, endpoint },
        }
    }

    #[test]
    fn a_feed_that_says_nothing_about_the_client_changes_nothing() {
        let definitions = ClientDefinitions::from_feed(&document(vec![]));
        assert_eq!(
            definitions,
            ClientDefinitions {
                sequence: Some(9),
                ..ClientDefinitions::default()
            }
        );
    }

    #[test]
    fn client_sections_are_taken_for_the_profiles_that_can_apply_them() {
        let definitions = ClientDefinitions::from_feed(&document(vec![
            hy2(
                Hysteria2ClientProposal {
                    bbr_profile: Some(BbrProfile::Conservative),
                    chrome_parrot: Some(false),
                },
                Default::default(),
            ),
            reality(
                RealityClientProposal {
                    utls_fingerprint: Some(UtlsFingerprint::Firefox),
                },
                Default::default(),
            ),
        ]));
        assert_eq!(
            definitions.hysteria2.bbr_profile,
            Some(BbrProfile::Conservative)
        );
        assert_eq!(definitions.hysteria2.chrome_parrot, Some(false));
        assert_eq!(
            definitions.reality.utls_fingerprint,
            Some(UtlsFingerprint::Firefox)
        );
    }

    #[test]
    fn amneziawg_junk_packets_are_not_applied_over_the_endpoints_own_values() {
        let definitions = ClientDefinitions::from_feed(&document(vec![awg(
            JunkPacketProposal {
                jc: Some(9),
                jmin: Some(10),
                jmax: Some(20),
            },
            Default::default(),
        )]));
        assert_eq!(
            definitions,
            ClientDefinitions {
                sequence: Some(9),
                ..ClientDefinitions::default()
            },
            "nothing records whether a person chose those numbers"
        );
    }

    #[test]
    fn an_endpoint_section_is_staged_and_never_part_of_the_client_definitions() {
        let feed = document(vec![
            hy2(
                Default::default(),
                Hysteria2EndpointProposal {
                    obfs: Some(ObfsProposal::Gecko {
                        min_packet_size: 512,
                        max_packet_size: 1200,
                    }),
                },
            ),
            reality(
                Default::default(),
                RealityEndpointProposal {
                    target_domain_candidates: Some(vec!["www.example.com".into()]),
                },
            ),
            awg(
                Default::default(),
                AmneziaWgHeaderProposal {
                    s1: Some(72),
                    ..Default::default()
                },
            ),
        ]);

        let staged = staged_endpoint_updates(&feed);

        assert_eq!(staged.len(), 3);
        assert_eq!(
            ClientDefinitions::from_feed(&feed).hysteria2,
            Default::default()
        );
    }

    #[test]
    fn a_profile_that_proposes_no_endpoint_change_stages_nothing() {
        let feed = document(vec![
            hy2(
                Hysteria2ClientProposal {
                    bbr_profile: Some(BbrProfile::Standard),
                    chrome_parrot: None,
                },
                Default::default(),
            ),
            reality(Default::default(), Default::default()),
            awg(Default::default(), Default::default()),
        ]);
        assert!(staged_endpoint_updates(&feed).is_empty());
    }
}
