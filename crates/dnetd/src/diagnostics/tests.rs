// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the diagnostic bundle (IPC-07, FR-035).

use std::time::Duration;

use dnet_core::credential::CredentialRef;
use dnet_core::degraded::{Degradation, NoMove};
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::ids::{EndpointId, InterfaceId};
use dnet_core::path::{PathKind, PathRole};
use dnet_core::posture::RoutingPosture;
use dnet_core::quality::QualityBand;
use dnet_core::rule::{IpCidr, RoutingRule, RuleAction, RuleMatcher};
use dnet_core::session::FailureCause;
use dnet_core::telemetry::{PathView, PathsSnapshot, StatsSummary};
use dnet_core::tier::FailoverTier;
use dnet_ipc::protocol::{ActiveEndpoint, ActiveProfile, ConnectionStatus, StateSnapshot, Warning};
use serde_json::Value;

use super::*;

// Distinctive values that must never appear in a default bundle. Each stands for a kind of thing a person
// would not want to hand over.
const DOMAIN: &str = "secret-destination.example";
const APP: &str = r"C:\Users\Someone\Private\app.exe";
const RANGE_HOST: &str = "198.51.100.77";
const ENDPOINT_HOST: &str = "sentinel-host.example";
const ENDPOINT_LABEL: &str = "Sentinel Home Server";
const NETWORK: &str = "Sentinel-Cafe-WiFi";
const CREDENTIAL: &str = "SENTINEL-credential-0123456789";

fn state() -> StateSnapshot {
    StateSnapshot {
        status: ConnectionStatus::Connected,
        active_profile: Some(ActiveProfile {
            id: "hy2-default".into(),
            kind: "Hysteria2".into(),
            tier: FailoverTier::Tier2,
        }),
        active_endpoint: Some(ActiveEndpoint {
            id: "11111111-2222-3333-4444-555555555555".into(),
            // The label is the person's own word for the server; it is not copied into the bundle.
            label: ENDPOINT_LABEL.into(),
        }),
        failure: None,
        warnings: vec![Warning::Tier2ProfileActive],
        posture: RoutingPosture::Tunnelled {
            tier: FailoverTier::Tier2,
        },
    }
}

fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::new(
        EndpointId::new(),
        ENDPOINT_LABEL,
        EndpointAddress::new(ENDPOINT_HOST, 4433).unwrap(),
        EndpointOrigin::Provisioned {
            provider: "mock".into(),
            region: "r1".into(),
            resource_ids: vec!["i-1".into(), "n-1".into()],
        },
        CredentialRef::new("dpapi:endpoint-1"),
    )
    .unwrap()]
}

fn rules() -> Vec<RoutingRule> {
    let mut rules = dnet_core::builtin_rules::builtin_rules_for(None, Policy::Block);
    rules.extend([
        RoutingRule::user(
            RuleMatcher::DomainSuffix(DOMAIN.into()),
            RuleAction::Bypass,
            300,
        )
        .unwrap(),
        RoutingRule::user(
            RuleMatcher::Application(APP.into()),
            RuleAction::Tunnel,
            301,
        )
        .unwrap(),
        RoutingRule::user(
            RuleMatcher::IpCidr(IpCidr::parse(&format!("{RANGE_HOST}/32")).unwrap()),
            RuleAction::Bypass,
            302,
        )
        .unwrap(),
    ]);
    rules
}

fn view(id: u64, role: PathRole, measured: bool, name: Option<&str>) -> PathView {
    PathView {
        id: InterfaceId::new(id),
        kind: PathKind::Wifi,
        name: name.map(str::to_owned),
        role,
        measured,
        band: measured.then_some(QualityBand::Good),
        rtt: measured.then_some(Duration::from_micros(43_250)),
        jitter: measured.then_some(Duration::from_millis(4)),
        loss: measured.then_some(0.0234),
        trace_ms: vec![Some(40.0)],
        typical_ms: None,
    }
}

fn paths() -> PathsSnapshot {
    PathsSnapshot {
        paths: vec![
            view(7, PathRole::Carrying, true, Some(NETWORK)),
            view(9, PathRole::Standby, false, Some("Another-Network")),
        ],
        degradation: Some(Degradation {
            path: InterfaceId::new(7),
            band: QualityBand::Poor,
            staying: NoMove::OnlyPath,
        }),
    }
}

fn stats() -> StatsSummary {
    StatsSummary {
        connected_for: Duration::from_secs(3725),
        network_changes: 2,
        changes_that_drop_connections: 2,
        method_switches: 1,
        endpoint_switches: 0,
        degraded_periods: 1,
        longest_degraded: Duration::from_secs(40),
    }
}

struct Fixture {
    state: StateSnapshot,
    profiles: Vec<dnet_core::profile::ConnectionProfile>,
    endpoints: Vec<Endpoint>,
    rules: Vec<RoutingRule>,
    paths: PathsSnapshot,
    stats: StatsSummary,
}

impl Fixture {
    fn new() -> Self {
        Self {
            state: state(),
            profiles: crate::domain::DomainState::seeded().profiles().to_vec(),
            endpoints: endpoints(),
            rules: rules(),
            paths: paths(),
            stats: stats(),
        }
    }

    fn facts(&self) -> Facts<'_> {
        Facts {
            generated_unix_ms: 1_730_000_000_000,
            state: &self.state,
            profiles: &self.profiles,
            endpoints: &self.endpoints,
            rules: &self.rules,
            encrypted_dns: Policy::Block,
            paths: Some(&self.paths),
            stats: Some(&self.stats),
            recovery_ok: true,
            config_refused: false,
            connecting_available: true,
        }
    }
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("the bundle is JSON")
}

// ------------------------------------------------------------------ what is left out by default

#[test]
fn a_default_bundle_holds_no_destination_no_address_no_name_and_no_credential() {
    let fixture = Fixture::new();
    let text = render(&fixture.facts(), Options::default());
    for secret in [
        DOMAIN,
        APP,
        RANGE_HOST,
        ENDPOINT_HOST,
        ENDPOINT_LABEL,
        NETWORK,
        "Another-Network",
        CREDENTIAL,
        "Sentinel",
        "198.51.100",
    ] {
        assert!(
            !text.to_lowercase().contains(&secret.to_lowercase()),
            "the bundle contains {secret}:\n{text}"
        );
    }
}

#[test]
fn the_structure_alone_already_leaves_them_out_before_any_redaction() {
    // `build` before the redaction pass: the first of the two layers.
    let fixture = Fixture::new();
    let text = build(&fixture.facts(), Options::default())
        .to_string()
        .to_lowercase();
    for secret in [
        DOMAIN,
        APP,
        RANGE_HOST,
        ENDPOINT_HOST,
        ENDPOINT_LABEL,
        NETWORK,
    ] {
        assert!(
            !text.contains(&secret.to_lowercase()),
            "build() contains {secret}"
        );
    }
}

// ------------------------------------------------------------------ the contract test of IPC-07

#[test]
fn ipc_07_a_bundle_after_a_session_containing_a_known_domain_does_not_contain_that_domain() {
    // The session's failure text names the domain, as a careless message might.
    let mut fixture = Fixture::new();
    fixture.state.failure = Some(FailureCause::ConfigurationInvalid {
        detail: format!(
            "the connection could not be configured: no route for {DOMAIN} (ranges {RANGE_HOST}/32)"
        ),
    });
    let text = render(&fixture.facts(), Options::default());
    assert!(!text.to_lowercase().contains(DOMAIN), "{text}");
    assert!(!text.contains(RANGE_HOST), "{text}");
    // The failure is still explained: its kind and the words around the value survive.
    let bundle = parse(&text);
    assert_eq!(
        bundle["connection"]["failure"]["cause"],
        "ConfigurationInvalid"
    );
    let detail = bundle["connection"]["failure"]["detail"].as_str().unwrap();
    assert!(detail.contains("no route for <removed>"), "{detail}");
}

#[test]
fn redaction_ignores_case_and_catches_every_occurrence() {
    let mut fixture = Fixture::new();
    fixture.state.failure = Some(FailureCause::ConfigurationInvalid {
        detail: format!(
            "{} then {} and {}",
            DOMAIN.to_uppercase(),
            DOMAIN,
            ENDPOINT_HOST.to_uppercase()
        ),
    });
    let text = render(&fixture.facts(), Options::default());
    assert!(!text.to_lowercase().contains(DOMAIN));
    assert!(!text.to_lowercase().contains(ENDPOINT_HOST));
    let detail = parse(&text)["connection"]["failure"]["detail"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(detail.matches("<removed>").count(), 3, "{detail}");
}

#[test]
fn a_longer_value_is_removed_whole_before_a_shorter_one_inside_it() {
    let values = vec!["host.example:4433".to_owned(), "host.example".to_owned()];
    assert_eq!(
        scrub("connect host.example:4433 now", &values),
        "connect <removed> now"
    );
    // `sensitive_values` hands them over longest first.
    let fixture = Fixture::new();
    let v = sensitive_values(&fixture.facts(), Options::default());
    let lengths: Vec<usize> = v.iter().map(String::len).collect();
    assert!(lengths.windows(2).all(|w| w[0] >= w[1]), "{v:?}");
}

#[test]
fn values_too_short_to_identify_anything_are_not_scrubbed() {
    // A two-character label would mangle ordinary words.
    let mut fixture = Fixture::new();
    fixture.endpoints = vec![Endpoint::new(
        EndpointId::new(),
        "ab",
        EndpointAddress::new("203.0.113.9", 443).unwrap(),
        EndpointOrigin::Manual,
        CredentialRef::new("k"),
    )
    .unwrap()];
    let values = sensitive_values(&fixture.facts(), Options::default());
    assert!(!values.contains(&"ab".to_owned()));
    assert!(values.contains(&"203.0.113.9".to_owned()));
}

#[test]
fn a_non_ascii_value_is_matched_exactly_and_never_splits_a_character() {
    assert_eq!(
        scrub("see Café-Wifi here", &["Café-Wifi".to_owned()]),
        "see <removed> here"
    );
    // Text with multi-byte characters around a value is carried through intact.
    assert_eq!(
        scrub("日本 secret-x 日本", &["secret-x".to_owned()]),
        "日本 <removed> 日本"
    );
}

// ------------------------------------------------------------------ what a person can opt in to

#[test]
fn each_extra_is_a_separate_choice_that_adds_only_itself() {
    let fixture = Fixture::new();
    let with_addresses = render(
        &fixture.facts(),
        Options {
            endpoint_addresses: true,
            ..Options::default()
        },
    );
    assert!(with_addresses.contains(ENDPOINT_HOST) && with_addresses.contains(ENDPOINT_LABEL));
    assert!(!with_addresses.contains(DOMAIN) && !with_addresses.contains(NETWORK));

    let with_patterns = render(
        &fixture.facts(),
        Options {
            rule_patterns: true,
            ..Options::default()
        },
    );
    assert!(with_patterns.contains(DOMAIN), "{with_patterns}");
    assert!(!with_patterns.contains(ENDPOINT_HOST) && !with_patterns.contains(NETWORK));

    let with_names = render(
        &fixture.facts(),
        Options {
            network_names: true,
            ..Options::default()
        },
    );
    assert!(with_names.contains(NETWORK));
    assert!(!with_names.contains(ENDPOINT_HOST) && !with_names.contains(DOMAIN));
}

#[test]
fn a_credential_is_never_among_the_extras() {
    let fixture = Fixture::new();
    let everything = Options {
        endpoint_addresses: true,
        rule_patterns: true,
        network_names: true,
    };
    let text = render(&fixture.facts(), everything);
    assert!(!text.contains(CREDENTIAL));
    assert!(
        !text.contains("dpapi:endpoint-1"),
        "not even the reference to where one is kept"
    );
}

// ------------------------------------------------------------------ what it does say

#[test]
fn it_says_enough_to_explain_a_failure() {
    let mut fixture = Fixture::new();
    fixture.state.status = ConnectionStatus::Failed;
    fixture.state.failure = Some(FailureCause::AllProfilesBlocked);
    fixture.state.posture = RoutingPosture::FailClosed;
    let bundle = parse(&render(&fixture.facts(), Options::default()));
    assert_eq!(bundle["bundle_version"], BUNDLE_VERSION);
    assert_eq!(bundle["connection"]["status"], "Failed");
    assert_eq!(bundle["connection"]["posture"], "FailClosed");
    assert_eq!(
        bundle["connection"]["failure"]["cause"],
        "AllProfilesBlocked"
    );
    assert_eq!(bundle["encrypted_dns"], "blocked");
    assert_eq!(bundle["service"]["recovery"], "ok");
    assert_eq!(bundle["profiles"].as_array().unwrap().len(), 3);
    assert_eq!(bundle["endpoints"][0]["origin"], "Provisioned");
    assert_eq!(bundle["endpoints"][0]["cloud_resources"], 2);
    assert_eq!(bundle["session"]["network_changes"], 2);
    assert_eq!(bundle["networks"]["degraded"]["staying"], "OnlyPath");
}

#[test]
fn the_rules_are_counted_and_described_by_kind_never_by_pattern() {
    let fixture = Fixture::new();
    let bundle = parse(&render(&fixture.facts(), Options::default()));
    let counts = &bundle["rules"]["counts"];
    assert_eq!(counts["user"], 3);
    assert_eq!(counts["best_effort"], 1, "the application rule");
    assert!(counts["by_action"]["Reject"].as_u64().unwrap() > 0);
    let list = bundle["rules"]["list"].as_array().unwrap();
    let user_kinds: Vec<&str> = list
        .iter()
        .filter(|r| r["builtin"] == false)
        .map(|r| r["matches"].as_str().unwrap())
        .collect();
    assert_eq!(user_kinds, ["DomainSuffix", "Application", "IpCidr"]);
    assert!(list.iter().all(|r| r.get("pattern").is_none()));
}

#[test]
fn a_network_nobody_measured_claims_no_quality() {
    let fixture = Fixture::new();
    let bundle = parse(&render(&fixture.facts(), Options::default()));
    let networks = bundle["networks"]["paths"].as_array().unwrap();
    assert_eq!(networks[0]["measured"], true);
    assert_eq!(networks[0]["quality"], "Good");
    assert_eq!(networks[1]["measured"], false);
    for absent in ["quality", "rtt_ms", "jitter_ms", "loss"] {
        assert!(
            networks[1].get(absent).is_none(),
            "{absent} is claimed for an unmeasured network"
        );
    }
}

#[test]
fn what_is_not_known_is_null_not_invented() {
    let fixture = Fixture::new();
    let mut facts = fixture.facts();
    facts.paths = None;
    facts.stats = None;
    facts.recovery_ok = false;
    facts.config_refused = true;
    facts.connecting_available = false;
    let bundle = parse(&render(&facts, Options::default()));
    assert!(bundle["networks"].is_null());
    assert!(bundle["session"].is_null());
    assert_eq!(bundle["service"]["recovery"], "failed");
    assert_eq!(bundle["service"]["configuration"], "refused");
    assert_eq!(bundle["service"]["connecting_available"], false);
}

#[test]
fn the_active_endpoint_is_named_by_id_only() {
    let fixture = Fixture::new();
    let bundle = parse(&render(&fixture.facts(), Options::default()));
    let active = &bundle["connection"]["active_endpoint"];
    assert_eq!(active["id"], "11111111-2222-3333-4444-555555555555");
    assert!(active.get("label").is_none());
}

// ------------------------------------------------------------------ bounds and shape

#[test]
fn however_much_is_configured_the_bundle_stays_bounded() {
    let mut fixture = Fixture::new();
    for i in 0..500u32 {
        fixture.endpoints.push(
            Endpoint::new(
                EndpointId::new(),
                format!("server {i}"),
                EndpointAddress::new(format!("203.0.113.{}", i % 250 + 1), 443).unwrap(),
                EndpointOrigin::Manual,
                CredentialRef::new("k"),
            )
            .unwrap(),
        );
        fixture.rules.push(
            RoutingRule::user(
                RuleMatcher::Domain(format!("host{i}.example")),
                RuleAction::Tunnel,
                1000 + i,
            )
            .unwrap(),
        );
    }
    let text = render(&fixture.facts(), Options::default());
    assert!(text.len() < 64 * 1024, "{} bytes", text.len());
    let bundle = parse(&text);
    let endpoints = bundle["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), MAX_LISTED + 1);
    assert!(endpoints.last().unwrap()["left_out"].as_u64().unwrap() > 400);
}

#[test]
fn it_is_valid_json_with_the_expected_top_level_shape() {
    let fixture = Fixture::new();
    let bundle = parse(&render(&fixture.facts(), Options::default()));
    let mut keys: Vec<&str> = bundle
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "bundle_version",
            "connection",
            "encrypted_dns",
            "endpoints",
            "generated_unix_ms",
            "networks",
            "product_version",
            "profiles",
            "protocol_version",
            "rules",
            "service",
            "session",
        ]
    );
}
