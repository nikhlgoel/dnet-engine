//! The trial generation: what a verified feed can still get wrong once its values are put together.
//! The documents here are built directly, not parsed, so that values the feed parser would have
//! refused can reach the generator: this layer must not depend on that parser having been right.

use dnet_core::feed::document::{
    AmneziaWgHeaderProposal, Hysteria2ClientProposal, Hysteria2EndpointProposal,
    JunkPacketProposal, ObfsProposal, ProfileProposal, RealityClientProposal,
    RealityEndpointProposal,
};
use dnet_core::transport_params::{BbrProfile, UtlsFingerprint};

use super::*;

fn document(profiles: Vec<ProfileProposal>) -> FeedDocument {
    FeedDocument {
        keys_version: 1,
        sequence: 1,
        issued_at: 0,
        expires_at: 1,
        profiles,
    }
}

fn awg(client: JunkPacketProposal, endpoint: AmneziaWgHeaderProposal) -> ProfileProposal {
    ProfileProposal {
        profile_id: ProfileId::new("awg-default"),
        params: ProposedParams::AmneziaWg { client, endpoint },
    }
}

fn hy2(client: Hysteria2ClientProposal, endpoint: Hysteria2EndpointProposal) -> ProfileProposal {
    ProfileProposal {
        profile_id: ProfileId::new("hy2-default"),
        params: ProposedParams::Hysteria2 { client, endpoint },
    }
}

fn reality(client: RealityClientProposal, endpoint: RealityEndpointProposal) -> ProfileProposal {
    ProfileProposal {
        profile_id: ProfileId::new("reality-default"),
        params: ProposedParams::VlessReality { client, endpoint },
    }
}

/// The ADR-0002 §5.3 example, which must itself be accepted.
fn the_adr_example() -> Vec<ProfileProposal> {
    vec![
        awg(
            JunkPacketProposal {
                jc: Some(6),
                jmin: Some(40),
                jmax: Some(90),
            },
            AmneziaWgHeaderProposal {
                s1: Some(72),
                s2: Some(41),
                h1: Some(1_873_209),
                h2: Some(5_520_871),
                h3: Some(90_121),
                h4: Some(334_210),
            },
        ),
        hy2(
            Hysteria2ClientProposal {
                bbr_profile: Some(BbrProfile::Standard),
                chrome_parrot: Some(true),
            },
            Hysteria2EndpointProposal {
                obfs: Some(ObfsProposal::Gecko {
                    min_packet_size: 512,
                    max_packet_size: 1200,
                }),
            },
        ),
        reality(
            RealityClientProposal {
                utls_fingerprint: Some(UtlsFingerprint::Chrome),
            },
            RealityEndpointProposal {
                target_domain_candidates: Some(vec!["www.example.com".into()]),
            },
        ),
    ]
}

#[test]
fn a_feed_that_proposes_nothing_still_generates_for_every_bundled_profile() {
    assert_eq!(trial_generate(&document(vec![])), Ok(()));
}

#[test]
fn the_documented_example_generates() {
    assert_eq!(trial_generate(&document(the_adr_example())), Ok(()));
}

#[test]
fn every_value_a_client_section_can_take_generates() {
    for bbr in [
        BbrProfile::Standard,
        BbrProfile::Conservative,
        BbrProfile::Aggressive,
    ] {
        for parrot in [true, false] {
            let feed = document(vec![hy2(
                Hysteria2ClientProposal {
                    bbr_profile: Some(bbr),
                    chrome_parrot: Some(parrot),
                },
                Default::default(),
            )]);
            assert_eq!(trial_generate(&feed), Ok(()), "{bbr:?} {parrot}");
        }
    }
    for fingerprint in [
        UtlsFingerprint::Chrome,
        UtlsFingerprint::Firefox,
        UtlsFingerprint::Edge,
        UtlsFingerprint::Safari,
        UtlsFingerprint::Ios,
        UtlsFingerprint::Android,
    ] {
        let feed = document(vec![reality(
            RealityClientProposal {
                utls_fingerprint: Some(fingerprint),
            },
            Default::default(),
        )]);
        assert_eq!(trial_generate(&feed), Ok(()), "{fingerprint:?}");
    }
}

// ------------------------------------------------------------------ what it must refuse

#[test]
fn a_gecko_layer_whose_sizes_the_core_would_refuse_is_refused() {
    let feed = document(vec![hy2(
        Default::default(),
        Hysteria2EndpointProposal {
            obfs: Some(ObfsProposal::Gecko {
                min_packet_size: 1400,
                max_packet_size: 256,
            }),
        },
    )]);
    let error = trial_generate(&feed).unwrap_err();
    assert!(error.starts_with("hy2-default:"), "{error}");
}

#[test]
fn junk_packets_that_leave_no_room_once_merged_over_the_bundled_values_are_refused() {
    // jmin alone, above the bundled jmax: each is valid, the result is not.
    let feed = document(vec![awg(
        JunkPacketProposal {
            jmin: Some(100),
            ..Default::default()
        },
        Default::default(),
    )]);
    let error = trial_generate(&feed).unwrap_err();
    assert!(error.starts_with("awg-default:"), "{error}");
    assert!(error.contains("jmin"), "{error}");
}

#[test]
fn a_header_equal_to_one_already_in_effect_is_refused() {
    let feed = document(vec![awg(
        Default::default(),
        AmneziaWgHeaderProposal {
            h1: Some(BUNDLED_HEADERS.h2),
            ..Default::default()
        },
    )]);
    assert!(trial_generate(&feed)
        .unwrap_err()
        .starts_with("awg-default:"));
}

#[test]
fn padding_sizes_that_make_the_two_handshake_messages_the_same_size_are_refused() {
    let feed = document(vec![awg(
        Default::default(),
        AmneziaWgHeaderProposal {
            s2: Some(BUNDLED_HEADERS.s1 + 56),
            ..Default::default()
        },
    )]);
    assert!(trial_generate(&feed)
        .unwrap_err()
        .starts_with("awg-default:"));
}

#[test]
fn a_target_domain_the_generator_will_not_accept_is_refused() {
    for bad in ["not a domain", "", "203.0.113.5", "localhost"] {
        let feed = document(vec![reality(
            Default::default(),
            RealityEndpointProposal {
                target_domain_candidates: Some(vec!["www.example.com".into(), bad.into()]),
            },
        )]);
        let error = trial_generate(&feed).unwrap_err();
        assert!(error.contains("target domain"), "{bad:?}: {error}");
    }
}

#[test]
fn one_bad_profile_refuses_the_whole_feed_even_when_the_others_are_fine() {
    let mut profiles = the_adr_example();
    assert_eq!(trial_generate(&document(profiles.clone())), Ok(()));
    // Spoil only the AmneziaWG proposal.
    profiles[0] = awg(
        JunkPacketProposal {
            jmin: Some(2000),
            ..Default::default()
        },
        Default::default(),
    );
    let error = trial_generate(&document(profiles)).unwrap_err();
    assert!(error.starts_with("awg-default:"), "{error}");
}

#[test]
fn a_refusal_does_not_say_where_the_trial_looked() {
    // The fixture is in the range reserved for documentation, and nothing about the person's own
    // endpoints is read.
    assert_eq!(TRIAL_HOST, "192.0.2.1");
    let error = trial_generate(&document(vec![awg(
        JunkPacketProposal {
            jmin: Some(2000),
            ..Default::default()
        },
        Default::default(),
    )]))
    .unwrap_err();
    assert!(!error.contains("192.0.2"), "{error}");
}
