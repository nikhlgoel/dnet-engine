//! Contract tests PRV-01 … PRV-09 (contracts/provisioning.md §5), and the guarantees around them.
//!
//! Every test runs a whole job through the public API against [`MockProvider`]. **No test creates a real
//! cloud resource**: the mock is the only provider the crate ships, and it keeps what it is asked to make in
//! a table so a test can look at what *exists* after a crash, a cancellation or a cleanup, not merely at what
//! the job believes.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dnet_config::reality::TargetDomain;
use dnet_config::secret_store::SecretKey;
use dnet_core::endpoint::EndpointOrigin;
use dnet_core::profile::ProfileKind;
use dnet_provision::bootstrap::{CorePin, Ports, ServerCores};
use dnet_provision::capacity::{Alternative, Capacity};
use dnet_provision::cleanup::cleanup;
use dnet_provision::credential::{CredentialProblem, Inspection, Standing, Subject};
use dnet_provision::keepalive::KeepalivePlan;
use dnet_provision::ledger::{EntryState, FileLedger, Ledger, LedgerError, MemoryLedger};
use dnet_provision::mock::{MockProvider, REQUIRED};
use dnet_provision::provider::{Provider, ProviderError, ResourceKind};
use dnet_provision::sanitize::Sanitizer;
use dnet_provision::secret::Secret;
use dnet_provision::stages::{
    run, CancelToken, Event, FailureReason, JobParams, Outcome, Services, Stage,
};
use dnet_provision::verify::{FixedReachability, VerifyFailure};
use serde_json::json;

const CREDENTIAL: &str = "SENTINEL-cloud-key-0123456789abcdef-9f3c";

// ------------------------------------------------------------------ fixtures

fn pin(name: &str, tag: char) -> CorePin {
    CorePin {
        name: name.to_owned(),
        version: "v1.14.0".to_owned(),
        url: format!("https://example.test/releases/{name}-linux-amd64"),
        sha256: tag.to_string().repeat(64),
        licence: "GPL-3.0-or-later".to_owned(),
        source: "https://example.test/source".to_owned(),
    }
}

fn params() -> JobParams {
    JobParams {
        job_id: "abc123".to_owned(),
        region: "r1".to_owned(),
        shape: "small".to_owned(),
        label: "my server".to_owned(),
        ports: Ports::default(),
        cores: ServerCores {
            primary_core: pin("primary-core", 'a'),
            amneziawg: pin("amneziawg-go", 'b'),
            arch: dnet_provision::bootstrap::ServerArch::Amd64,
        },
        hysteria2_server_name: "edge.example.net".to_owned(),
        reality_target: TargetDomain::parse("www.example.com").unwrap(),
        keepalive: KeepalivePlan::default(),
        acknowledged_over_privilege: false,
        measure_origin: None,
    }
}

/// What a correctly set-up server prints, for `params`.
fn report_for(p: &JobParams, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut report = json!({
        "version": 2,
        "amneziawg": {
            "server_public_key_hex": "d".repeat(64),
            "listen_port": p.ports.amneziawg_udp,
            "client_address": "10.66.0.2",
            "prefix_len": 24,
            "client_public_key_hex": "{CLIENT_PUB}"
        },
        "hysteria2": {
            "server_port": p.ports.hysteria2_udp,
            "server_name": p.hysteria2_server_name,
            "spki_sha256_hex": "e".repeat(64),
            "auth_password": "auth-secret-0123456789abcdef",
            "obfs_password": "obfs-secret-0123456789abcdef",
            "cert_key_algorithm": "ecdsa-p256"
        },
        "reality": {
            "server_port": p.ports.reality_tcp,
            "target_domain": p.reality_target.as_str(),
            "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
            "short_id": "0123456789abcdef",
            "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
            "flow": "xtls-rprx-vision"
        },
        "session": {
            "server_public_key": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
            "port": 25182,
            "server_address": "10.9.0.1",
            // The mock fills this in with the devices the script was given, as a real server would.
            "devices": "{SESSION_DEVICES}"
        },
        "cores": {
            "primary_core": { "version": p.cores.primary_core.version, "sha256": p.cores.primary_core.sha256 },
            "amneziawg": { "version": p.cores.amneziawg.version, "sha256": p.cores.amneziawg.sha256 }
        }
    });
    edit(&mut report);
    format!(
        "setting up...\nDNET-BOOTSTRAP-REPORT {}\n",
        serde_json::to_string(&report).unwrap()
    )
}

fn provider_for(p: &JobParams) -> MockProvider {
    let mock = MockProvider::new().with_credential(Secret::new(CREDENTIAL));
    mock.set_bootstrap_output(report_for(p, |_| {}));
    mock
}

fn all_work() -> FixedReachability {
    FixedReachability(vec![
        (ProfileKind::AmneziaWg, true),
        (ProfileKind::Hysteria2, true),
        (ProfileKind::VlessReality, true),
    ])
}

fn nothing_works() -> FixedReachability {
    FixedReachability(vec![
        (ProfileKind::AmneziaWg, false),
        (ProfileKind::Hysteria2, false),
        (ProfileKind::VlessReality, false),
    ])
}

fn sanitizer() -> Sanitizer {
    Sanitizer::new().with_secret(Secret::new(CREDENTIAL))
}

/// Run one job and hand back what it said, and every event it raised.
fn go(
    p: &JobParams,
    provider: &MockProvider,
    ledger: &mut dyn Ledger,
    reachability: &FixedReachability,
    cancel: &CancelToken,
) -> (Outcome, Vec<Event>) {
    let mut events = Vec::new();
    let clean = sanitizer();
    let outcome = {
        let mut sink = |e: Event| events.push(e);
        let mut services = Services {
            provider,
            ledger,
            reachability,
            sanitizer: &clean,
            cancel,
            events: &mut sink,
        };
        run(p, &mut services)
    };
    (outcome, events)
}

fn simple(p: &JobParams, provider: &MockProvider, reachability: &FixedReachability) -> Outcome {
    go(
        p,
        provider,
        &mut MemoryLedger::new(),
        reachability,
        &CancelToken::new(),
    )
    .0
}

fn failed(outcome: Outcome) -> dnet_provision::stages::Failure {
    match outcome {
        Outcome::Failed(f) => *f,
        other => panic!("expected a failure, got {other:?}"),
    }
}

// ------------------------------------------------------------------ the happy path

#[test]
fn a_good_job_ends_in_an_endpoint_that_names_what_was_made_and_where_its_credentials_are() {
    let p = params();
    let provider = provider_for(&p);
    let (outcome, events) = go(
        &p,
        &provider,
        &mut MemoryLedger::new(),
        &all_work(),
        &CancelToken::new(),
    );
    let Outcome::Provisioned(done) = outcome else {
        panic!("expected it to work, got {outcome:?}");
    };

    assert_eq!(done.endpoint.label(), "my server");
    assert!(done.endpoint.is_enabled());
    assert_eq!(done.working.len(), 3);
    match done.endpoint.origin() {
        EndpointOrigin::Provisioned {
            provider: name,
            region,
            resource_ids,
        } => {
            assert_eq!(name, "mock");
            assert_eq!(region, "r1");
            assert_eq!(
                resource_ids.len(),
                2,
                "the machine and its rules, so deleting the endpoint can offer to remove them"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(done.endpoint.has_cloud_resources());
    assert_eq!(
        done.endpoint.credentials(),
        &SecretKey::for_endpoint(done.endpoint.id()).credential_ref()
    );
    assert!(done.credentials.amneziawg.is_some());
    assert!(done.credentials.hysteria2.is_some());
    assert!(done.credentials.reality.is_some());
    assert_eq!(provider.remaining(), 2);

    // Progress goes through every stage in order.
    let started: Vec<Stage> = events
        .iter()
        .filter_map(|e| match e {
            Event::StageStarted(s) => Some(*s),
            _ => None,
        })
        .collect();
    let mut expected = Stage::WORK.to_vec();
    expected.push(Stage::Done);
    assert_eq!(started, expected);
}

#[test]
fn the_client_private_key_never_goes_to_the_server_and_the_scripts_hold_no_secret() {
    let p = params();
    let provider = provider_for(&p);
    let Outcome::Provisioned(done) = simple(&p, &provider, &all_work()) else {
        panic!("expected it to work");
    };
    let private = done
        .credentials
        .amneziawg
        .as_ref()
        .unwrap()
        .client_private_key
        .expose_wire()
        .to_owned();
    for script in [
        provider.last_bootstrap_script().unwrap(),
        provider.last_keepalive_script().unwrap(),
    ] {
        assert!(
            !script.contains(&private),
            "the client's private key was sent to the server"
        );
        assert!(
            !script.contains(CREDENTIAL),
            "the cloud credential was sent to the server"
        );
    }
}

// ------------------------------------------------------------------ PRV-01

#[test]
fn prv_01_a_tenancy_root_credential_is_rejected_at_validation_and_never_used_for_any_call() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_inspection(Inspection {
        subject: Subject::Root,
        standing: Standing::Valid,
        // Holding everything, including all that the job needs.
        granted: REQUIRED
            .iter()
            .map(|s| (*s).to_owned())
            .chain(["manage everything".to_owned()])
            .collect(),
    });
    let mut ledger = MemoryLedger::new();
    let (outcome, _) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());

    let failure = failed(outcome);
    assert_eq!(failure.stage, Stage::CredentialValidation);
    assert_eq!(
        failure.reason,
        FailureReason::Credential(CredentialProblem::RootCredential)
    );
    assert_eq!(
        provider.calls(),
        ["inspect_credential"],
        "after learning what the credential is, nothing else is asked of the provider"
    );
    assert_eq!(provider.remaining(), 0);
    assert!(ledger.entries().is_empty());
}

#[test]
fn prv_01_an_invalid_expired_or_revoked_credential_is_each_told_apart_and_stops_the_job() {
    for (standing, problem) in [
        (Standing::Invalid, CredentialProblem::Invalid),
        (Standing::Expired, CredentialProblem::Expired),
        (Standing::Revoked, CredentialProblem::Revoked),
    ] {
        let p = params();
        let provider = provider_for(&p);
        provider.set_inspection(Inspection {
            subject: Subject::DedicatedUser,
            standing,
            granted: vec![],
        });
        let failure = failed(simple(&p, &provider, &all_work()));
        assert_eq!(failure.reason, FailureReason::Credential(problem));
        assert_eq!(provider.call_count(), 1);
    }
    // A provider that stops accepting the credential partway is the same as an invalid one.
    let p = params();
    let provider = provider_for(&p);
    provider.fail_once("inspect_credential", ProviderError::Unauthorized);
    assert_eq!(
        failed(simple(&p, &provider, &all_work())).reason,
        FailureReason::Credential(CredentialProblem::Invalid)
    );
}

#[test]
fn a_credential_missing_what_the_job_needs_is_refused_and_the_missing_permissions_are_named() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_inspection(Inspection {
        subject: Subject::DedicatedUser,
        standing: Standing::Valid,
        granted: vec!["manage instances".to_owned()],
    });
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(
        failure.reason,
        FailureReason::Credential(CredentialProblem::MissingPermissions(vec![
            "manage network rules".to_owned()
        ]))
    );
}

#[test]
fn an_over_privileged_credential_needs_an_acknowledgement_and_then_works() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_inspection(Inspection {
        subject: Subject::DedicatedUser,
        standing: Standing::Valid,
        granted: REQUIRED
            .iter()
            .map(|s| (*s).to_owned())
            .chain(["delete buckets".to_owned()])
            .collect(),
    });
    match simple(&p, &provider, &all_work()) {
        Outcome::NeedsAcknowledgement { permissions } => {
            assert_eq!(permissions, ["delete buckets"])
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        provider.remaining(),
        0,
        "nothing was created before the person agreed"
    );
    assert_eq!(provider.call_count(), 1);

    let mut acknowledged = params();
    acknowledged.acknowledged_over_privilege = true;
    let (outcome, events) = go(
        &acknowledged,
        &provider,
        &mut MemoryLedger::new(),
        &all_work(),
        &CancelToken::new(),
    );
    assert!(matches!(outcome, Outcome::Provisioned(_)), "{outcome:?}");
    assert!(events.contains(&Event::OverPrivilegedAcknowledged { extra: 1 }));
}

// ------------------------------------------------------------------ PRV-02

#[test]
fn prv_02_the_credential_appears_in_no_output_whatever_goes_wrong() {
    let mut everything = String::new();
    let mut collect = |label: &str, text: String| {
        everything.push_str(&format!("[{label}] {text}\n"));
    };

    // Each scenario makes the provider put the credential into its own error text.
    type Scene = Box<dyn Fn(&MockProvider)>;
    let scenarios: Vec<(&str, Scene)> = vec![
        (
            "create fails",
            Box::new(|m| {
                m.fail_once(
                    "create_instance",
                    ProviderError::Rejected("bad request".into()),
                )
            }),
        ),
        (
            "quota",
            Box::new(|m| {
                m.fail_once(
                    "create_instance",
                    ProviderError::QuotaExceeded("limit reached".into()),
                )
            }),
        ),
        (
            "rules fail",
            Box::new(|m| m.fail_once("open_ports", ProviderError::Transient("busy".into()))),
        ),
        (
            "bootstrap fails",
            Box::new(|m| m.fail_once("bootstrap", ProviderError::Rejected("exit 4".into()))),
        ),
        (
            "capacity call fails",
            Box::new(|m| m.fail_once("check_capacity", ProviderError::Transient("busy".into()))),
        ),
        (
            "cleanup is refused",
            Box::new(|m| {
                m.fail_once("bootstrap", ProviderError::Rejected("exit 4".into()));
                m.refuse_deleting(
                    "instance-1",
                    ProviderError::Rejected("still attached".into()),
                );
            }),
        ),
    ];
    for (label, set) in scenarios {
        let p = params();
        let provider = provider_for(&p);
        provider.leak_credential_in_errors();
        set(&provider);
        let mut ledger = MemoryLedger::new();
        let (outcome, events) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
        collect(label, format!("{outcome:?}"));
        if let Outcome::Failed(f) = &outcome {
            collect(label, f.reason.to_string());
            for left in &f.cleanup.unremovable {
                collect(label, left.describe());
            }
        }
        collect(label, format!("{events:?}"));
        collect(label, format!("{:?}", ledger.entries()));
        // What the provider was sent.
        collect(label, provider.last_bootstrap_script().unwrap_or_default());
        collect(label, provider.last_keepalive_script().unwrap_or_default());
    }

    // The credential invalid, with the provider echoing it.
    let p = params();
    let provider = provider_for(&p);
    provider.leak_credential_in_errors();
    provider.fail_once("inspect_credential", ProviderError::Unauthorized);
    collect(
        "invalid",
        format!("{:?}", simple(&p, &provider, &all_work())),
    );

    assert!(
        !everything.contains("SENTINEL"),
        "the credential reached an output:\n{}",
        everything
            .lines()
            .filter(|l| l.contains("SENTINEL"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // The scan is not vacuous: the mock really did put it into its error text.
    let probe = MockProvider::new().with_credential(Secret::new(CREDENTIAL));
    probe.leak_credential_in_errors();
    probe.fail_once("check_capacity", ProviderError::Transient("busy".into()));
    assert!(probe
        .check_capacity("r", "s")
        .unwrap_err()
        .to_string()
        .contains("SENTINEL"));
}

#[test]
fn prv_02_the_ledger_file_holds_only_names_ids_and_regions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let p = params();
    let provider = provider_for(&p);
    provider.leak_credential_in_errors();
    let mut ledger = FileLedger::open(&path).unwrap();
    let _ = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("SENTINEL"), "{text}");
    assert!(text.contains("dnet-abc123-instance"));
}

// ------------------------------------------------------------------ PRV-03

#[test]
fn prv_03_no_capacity_is_an_outcome_with_alternatives_and_the_job_can_be_run_again() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_capacity(Capacity::Unavailable {
        alternatives: vec![
            Alternative {
                region: "far".into(),
                added_rtt_ms: 140,
            },
            Alternative {
                region: "near".into(),
                added_rtt_ms: 25,
            },
            Alternative {
                region: "r1".into(),
                added_rtt_ms: 0,
            },
        ],
    });
    let mut ledger = MemoryLedger::new();
    let (outcome, events) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    let Outcome::CapacityUnavailable { alternatives } = outcome else {
        panic!("expected no capacity, got {outcome:?}");
    };
    assert!(
        !alternatives.is_empty(),
        "at least one alternative is offered"
    );
    assert_eq!(
        alternatives
            .iter()
            .map(|a| (a.region.as_str(), a.added_rtt_ms))
            .collect::<Vec<_>>(),
        [("near", 25), ("far", 140)],
        "nearest first, what each costs, and not the region that was full"
    );
    // Nothing was created, so nothing needs cleaning.
    assert_eq!(provider.remaining(), 0);
    assert!(ledger.entries().is_empty());
    assert!(!events.iter().any(|e| matches!(e, Event::CleanupStarted)));

    // Retryable: pick an alternative, and it goes through.
    provider.set_capacity(Capacity::Available);
    let mut retry = params();
    retry.region = "near".to_owned();
    assert!(matches!(
        simple(&retry, &provider, &all_work()),
        Outcome::Provisioned(_)
    ));
}

#[test]
fn a_free_allowance_already_used_is_a_failure_that_says_so_and_cleans_up() {
    let p = params();
    let provider = provider_for(&p);
    provider.fail_once(
        "create_instance",
        ProviderError::QuotaExceeded("limit of 4 reached".into()),
    );
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::InstanceCreate);
    assert!(
        matches!(failure.reason, FailureReason::AllowanceUsed(ref t) if t.contains("limit of 4"))
    );
    assert!(failure.cleanup.is_complete());
    assert_eq!(provider.remaining(), 0);
}

// ------------------------------------------------------------------ PRV-04

/// A ledger that cannot be written to, standing for a full disk or a vanished file.
struct BrokenLedger(MemoryLedger);

impl Ledger for BrokenLedger {
    fn record_intent(&mut self, _: ResourceKind, _: &str, _: &str) -> Result<(), LedgerError> {
        Err(LedgerError::Write("the disk is full".into()))
    }
    fn record_created(&mut self, token: &str, id: &str) -> Result<(), LedgerError> {
        self.0.record_created(token, id)
    }
    fn record_removed(&mut self, token: &str) -> Result<(), LedgerError> {
        self.0.record_removed(token)
    }
    fn entries(&self) -> Vec<dnet_provision::ledger::LedgerEntry> {
        self.0.entries()
    }
}

#[test]
fn prv_04_a_crash_right_after_each_create_call_leaves_an_entry_for_what_was_made() {
    // "Parameterised over every stage": every stage that creates something in the cloud.
    for (method, kind, token) in [
        (
            "create_instance",
            ResourceKind::Instance,
            "dnet-abc123-instance",
        ),
        (
            "open_ports",
            ResourceKind::NetworkRule,
            "dnet-abc123-network",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let p = params();
        let provider = provider_for(&p);
        provider.crash_after(method);

        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut ledger = FileLedger::open(&path).unwrap();
            go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
        }));
        assert!(
            crashed.is_err(),
            "{method}: the simulated crash did not happen"
        );
        assert!(
            provider.existing_tokens().contains(&token.to_owned()),
            "{method}: the resource exists in the cloud although the call never returned"
        );

        // A new process opens the ledger the old one left.
        let reopened = FileLedger::open(&path).unwrap();
        let entry = reopened
            .entries()
            .into_iter()
            .find(|e| e.token == token)
            .unwrap_or_else(|| {
                panic!("{method}: the ledger has no entry for the resource that leaked")
            });
        assert_eq!(entry.kind, kind);
        assert_eq!(
            entry.state,
            EntryState::Intended,
            "{method}: only the intent could have been written"
        );
        assert_eq!(entry.region, "r1");
    }
}

#[test]
fn prv_04_and_what_a_crash_leaked_is_found_and_removed_by_the_next_cleanup() {
    for method in ["create_instance", "open_ports"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let p = params();
        let provider = provider_for(&p);
        provider.crash_after(method);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut ledger = FileLedger::open(&path).unwrap();
            go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
        }));
        assert!(provider.remaining() >= 1, "{method}: something leaked");

        let mut ledger = FileLedger::open(&path).unwrap();
        let report = cleanup(&provider, &mut ledger, &sanitizer()).unwrap();
        assert!(report.is_complete(), "{method}: {report:?}");
        assert_eq!(
            provider.remaining(),
            0,
            "{method}: the leaked resource is gone"
        );
    }
}

#[test]
fn prv_04_a_job_that_cannot_write_down_what_it_is_about_to_make_makes_nothing() {
    let p = params();
    let provider = provider_for(&p);
    let mut ledger = BrokenLedger(MemoryLedger::new());
    let (outcome, _) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    let failure = failed(outcome);
    assert_eq!(failure.stage, Stage::InstanceCreate);
    assert_eq!(failure.reason, FailureReason::LedgerUnavailable);
    assert_eq!(
        provider.count_of("create_instance"),
        0,
        "no create call was made"
    );
    assert_eq!(provider.remaining(), 0);
}

#[test]
fn prv_04_the_intent_is_written_before_the_call_not_after() {
    // The provider fails the create call: the ledger still has the intent, because it was written first.
    let p = params();
    let provider = provider_for(&p);
    provider.fail_always("create_instance", ProviderError::Transient("busy".into()));
    let mut ledger = MemoryLedger::new();
    let (outcome, _) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    assert!(matches!(outcome, Outcome::Failed(_)));
    let entries = ledger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].token, "dnet-abc123-instance");
    // Cleanup then finds nothing was made and marks the intent gone.
    assert_eq!(entries[0].state, EntryState::Removed);
}

// ------------------------------------------------------------------ PRV-05

#[test]
fn prv_05_cancelling_part_way_removes_every_recorded_resource() {
    let p = params();
    let provider = provider_for(&p);
    let cancel = CancelToken::new();
    let mut ledger = MemoryLedger::new();
    let mut events = Vec::new();
    let outcome = {
        let trigger = cancel.clone();
        let mut sink = |e: Event| {
            // The person presses Cancel while the keepalive is being installed.
            if e == Event::StageStarted(Stage::KeepaliveInstall) {
                trigger.cancel();
            }
            events.push(e);
        };
        let reachability = all_work();
        let clean = sanitizer();
        let mut services = Services {
            provider: &provider,
            ledger: &mut ledger,
            reachability: &reachability,
            sanitizer: &clean,
            cancel: &cancel,
            events: &mut sink,
        };
        run(&p, &mut services)
    };
    // The stage after it notices and stops. The two cloud resources exist by then, and must be gone.
    let Outcome::Cancelled { cleanup } = outcome else {
        panic!("expected a cancellation, got {outcome:?}");
    };
    assert!(cleanup.is_complete(), "{cleanup:?}");
    assert_eq!(cleanup.removed.len(), 2);
    assert_eq!(provider.remaining(), 0);
    assert!(ledger
        .entries()
        .iter()
        .all(|e| e.state == EntryState::Removed));
    assert!(events.contains(&Event::CleanupFinished { complete: true }));
}

#[test]
fn prv_05_a_cancel_before_anything_is_made_is_clean_and_makes_nothing() {
    let p = params();
    let provider = provider_for(&p);
    let cancel = CancelToken::new();
    cancel.cancel();
    let (outcome, _) = go(
        &p,
        &provider,
        &mut MemoryLedger::new(),
        &all_work(),
        &cancel,
    );
    assert!(matches!(outcome, Outcome::Cancelled { ref cleanup } if cleanup.is_complete()));
    assert_eq!(provider.call_count(), 0, "not even the credential was used");
}

#[test]
fn prv_05_what_cannot_be_removed_is_reported_with_enough_detail_to_remove_it_by_hand() {
    let p = params();
    let provider = provider_for(&p);
    // Fail the job late, and make the machine impossible to delete.
    provider.fail_once("bootstrap", ProviderError::Rejected("exit 4".into()));
    provider.refuse_deleting(
        "instance-1",
        ProviderError::Rejected("still has an attached volume".into()),
    );
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::ServerBootstrap);
    assert!(!failure.cleanup.is_complete());
    let left = &failure.cleanup.unremovable;
    assert_eq!(left.len(), 1);
    let line = left[0].describe();
    for needed in ["instance", "r1", "instance-1", "attached volume"] {
        assert!(line.contains(needed), "{line}");
    }
    assert_eq!(
        provider.remaining(),
        1,
        "the one that could not be removed is still there"
    );
    assert_eq!(
        failure.cleanup.removed.len(),
        1,
        "the rules were removed regardless"
    );
}

// ------------------------------------------------------------------ PRV-06

#[test]
fn prv_06_a_failure_at_reachability_creates_no_endpoint_and_leaves_nothing_behind() {
    let p = params();
    let provider = provider_for(&p);
    let failure = failed(simple(&p, &provider, &nothing_works()));
    assert_eq!(failure.stage, Stage::ReachabilityVerify);
    assert!(matches!(
        failure.reason,
        FailureReason::NotReachable(VerifyFailure::NoneReachable { .. })
    ));
    assert!(failure.cleanup.is_complete());
    assert_eq!(
        provider.remaining(),
        0,
        "the machine and the rules were removed"
    );
}

#[test]
fn prv_06_one_working_profile_is_enough_to_make_the_endpoint() {
    let p = params();
    let provider = provider_for(&p);
    let only_one = FixedReachability(vec![
        (ProfileKind::AmneziaWg, false),
        (ProfileKind::Hysteria2, true),
        (ProfileKind::VlessReality, false),
    ]);
    let Outcome::Provisioned(done) = simple(&p, &provider, &only_one) else {
        panic!("expected it to work");
    };
    assert_eq!(done.working, [ProfileKind::Hysteria2]);
}

#[test]
fn prv_06_nothing_tried_is_not_a_pass() {
    let p = params();
    let provider = provider_for(&p);
    let failure = failed(simple(&p, &provider, &FixedReachability(vec![])));
    assert_eq!(
        failure.reason,
        FailureReason::NotReachable(VerifyFailure::NothingTried)
    );
}

// ------------------------------------------------------------------ PRV-07

#[test]
fn prv_07_running_it_again_against_a_provisioned_endpoint_changes_nothing_and_succeeds() {
    let p = params();
    let provider = provider_for(&p);
    let mut ledger = MemoryLedger::new();
    let (first, _) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    let Outcome::Provisioned(first) = first else {
        panic!("{first:?}")
    };
    let ids_before = provider.existing_tokens();
    assert_eq!(ids_before.len(), 2);

    let (second, _) = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
    let Outcome::Provisioned(second) = second else {
        panic!("{second:?}")
    };

    assert_eq!(
        provider.existing_tokens(),
        ids_before,
        "no second machine, no second set of rules"
    );
    assert_eq!(provider.remaining(), 2);
    assert_eq!(ledger.entries().len(), 2);
    match (first.endpoint.origin(), second.endpoint.origin()) {
        (
            EndpointOrigin::Provisioned {
                resource_ids: a, ..
            },
            EndpointOrigin::Provisioned {
                resource_ids: b, ..
            },
        ) => assert_eq!(a, b, "the same resources"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn prv_07_the_server_script_makes_nothing_twice() {
    // The script's own idempotence is checked in `bootstrap::tests` (every key made only when its file is
    // missing, nothing deleted); here, that the job hands the provider that script.
    let p = params();
    let provider = provider_for(&p);
    let _ = simple(&p, &provider, &all_work());
    let script = provider.last_bootstrap_script().unwrap();
    assert!(script.contains("[ ! -s \"$STATE/primary/server.key\" ]"));
    assert!(!script.contains("rm -rf"));
}

// ------------------------------------------------------------------ PRV-08

#[test]
fn prv_08_cleanup_run_twice_gives_the_same_result_and_no_error() {
    let p = params();
    let provider = provider_for(&p);
    let mut ledger = MemoryLedger::new();
    // A job that made the resources and was then stopped by a failure it could not clean up after.
    provider.fail_once("bootstrap", ProviderError::Rejected("exit 4".into()));
    provider.refuse_deleting("instance-1", ProviderError::Transient("busy".into()));
    let _ = go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());

    let first = cleanup(&provider, &mut ledger, &sanitizer()).unwrap();
    let second = cleanup(&provider, &mut ledger, &sanitizer()).unwrap();
    assert_eq!(first, second, "the same report both times");

    // Once the provider lets the last one go, cleanup completes, and again it is repeatable.
    provider.allow_deleting("instance-1");
    let third = cleanup(&provider, &mut ledger, &sanitizer()).unwrap();
    let fourth = cleanup(&provider, &mut ledger, &sanitizer()).unwrap();
    assert!(third.is_complete());
    assert_eq!(third, fourth);
    assert_eq!(provider.remaining(), 0);
}

// ------------------------------------------------------------------ PRV-09

#[test]
fn prv_09_a_provisioned_endpoint_has_the_keepalive_installed_and_running() {
    let p = params();
    let provider = provider_for(&p);
    assert!(matches!(
        simple(&p, &provider, &all_work()),
        Outcome::Provisioned(_)
    ));
    let script = provider
        .last_keepalive_script()
        .expect("the keepalive was installed");
    assert!(script.contains("dnet-keepalive.timer"));
    assert!(
        provider.count_of("keepalive_installed") >= 1,
        "and it was checked afterwards"
    );
}

#[test]
fn prv_09_a_keepalive_that_is_not_there_afterwards_fails_the_job() {
    let p = params();
    let provider = provider_for(&p);
    provider.keepalive_does_not_stick();
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::KeepaliveInstall);
    assert_eq!(failure.reason, FailureReason::KeepaliveMissing);
    assert_eq!(provider.remaining(), 0, "and nothing is left behind");
}

#[test]
fn prv_09_a_keepalive_that_cannot_even_be_checked_fails_the_job_too() {
    let p = params();
    let provider = provider_for(&p);
    provider.fail_always(
        "keepalive_installed",
        ProviderError::Transient("busy".into()),
    );
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.reason, FailureReason::KeepaliveMissing);
}

// ------------------------------------------------------------------ the server, as the job sees it

#[test]
fn an_ed25519_certificate_fails_the_job_and_cleans_up() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_bootstrap_output(report_for(&p, |j| {
        j["hysteria2"]["cert_key_algorithm"] = json!("ed25519");
    }));
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::ServerBootstrap);
    assert!(
        matches!(&failure.reason, FailureReason::Bootstrap(t) if t.contains("Ed25519")),
        "{:?}",
        failure.reason
    );
    assert!(failure.cleanup.is_complete());
    assert_eq!(provider.remaining(), 0);
}

#[test]
fn a_server_running_cores_other_than_the_pinned_ones_fails_the_job() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_bootstrap_output(report_for(&p, |j| {
        j["cores"]["primary_core"]["sha256"] = json!("f".repeat(64));
    }));
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::ServerBootstrap);
    assert!(
        matches!(&failure.reason, FailureReason::Bootstrap(t) if t.contains("installed cores")),
        "{:?}",
        failure.reason
    );
}

#[test]
fn no_report_at_all_fails_the_job() {
    let p = params();
    let provider = provider_for(&p);
    provider.set_bootstrap_output("it ran and printed nothing useful\n");
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.stage, Stage::ServerBootstrap);
    assert!(failure.cleanup.is_complete());
}

#[test]
fn a_hostile_provider_text_is_cleaned_before_a_person_sees_it() {
    let p = params();
    let provider = provider_for(&p);
    provider.fail_once(
        "open_ports",
        ProviderError::Rejected("denied\r\n[INFO] all clear\u{1b}[2J".into()),
    );
    let failure = failed(simple(&p, &provider, &all_work()));
    let FailureReason::Provider(text) = &failure.reason else {
        panic!("{:?}", failure.reason)
    };
    assert!(!text.chars().any(char::is_control), "{text:?}");
}

// ------------------------------------------------------------------ the request

#[test]
fn a_job_that_is_not_well_formed_is_refused_before_the_provider_is_touched() {
    let edits: Vec<fn(&mut JobParams)> = vec![
        |p| p.job_id = "Has Capitals".to_owned(),
        |p| p.job_id = String::new(),
        |p| p.job_id = "x".repeat(41),
        |p| p.region = "  ".to_owned(),
        |p| p.shape = String::new(),
    ];
    for edit in edits {
        let mut p = params();
        edit(&mut p);
        let provider = provider_for(&p);
        let failure = failed(simple(&p, &provider, &all_work()));
        assert!(
            matches!(failure.reason, FailureReason::InvalidRequest(_)),
            "{:?}",
            failure.reason
        );
        assert_eq!(provider.call_count(), 0);
    }
}

#[test]
fn a_label_that_cannot_be_an_endpoint_name_fails_after_cleaning_up() {
    let mut p = params();
    p.label = "x".repeat(65);
    let provider = provider_for(&p);
    let failure = failed(simple(&p, &provider, &all_work()));
    assert_eq!(failure.reason, FailureReason::InvalidRequest("the label"));
    assert_eq!(
        provider.remaining(),
        0,
        "nothing was left running for a job that could not name its result"
    );
}

// ------------------------------------------------------------------ the sweep: whatever fails, nothing billable is lost

/// Every call a provider can fail, with every kind of error it can fail with, once and for good. A job that does not
/// end in an endpoint must leave nothing running at the provider (it costs the person money), or say exactly what is
/// left; and whatever is left must be in the ledger, so that the next cleanup finds it. One test for the whole
/// invariant, so a new stage or a new way of failing cannot slip past the individual cases.
#[test]
fn whichever_call_fails_with_whichever_error_nothing_billable_is_lost_or_it_is_named_and_recorded()
{
    let methods = [
        "inspect_credential",
        "check_capacity",
        "create_instance",
        "open_ports",
        "bootstrap",
        "install_keepalive",
        "keepalive_installed",
        "find",
        "delete",
    ];
    let errors = [
        ProviderError::Transient("busy".into()),
        ProviderError::Rejected("no".into()),
        ProviderError::Unauthorized,
        ProviderError::QuotaExceeded("used".into()),
    ];
    let mut ended_in = std::collections::BTreeMap::<&str, usize>::new();
    for method in methods {
        for error in &errors {
            for always in [false, true] {
                let p = params();
                let provider = provider_for(&p);
                if always {
                    provider.fail_always(method, error.clone());
                } else {
                    provider.fail_once(method, error.clone());
                }
                let mut ledger = MemoryLedger::new();
                let (outcome, _events) =
                    go(&p, &provider, &mut ledger, &all_work(), &CancelToken::new());
                let label = format!("{method} / {error:?} / always={always}");
                let left = provider.remaining();
                match &outcome {
                    Outcome::Provisioned(_) => {
                        ended_in
                            .entry("provisioned")
                            .and_modify(|n| *n += 1)
                            .or_insert(1);
                        assert_eq!(
                            left, 2,
                            "{label}: a provisioned job is the instance and its rules"
                        );
                    }
                    Outcome::Failed(failure) => {
                        ended_in
                            .entry("failed")
                            .and_modify(|n| *n += 1)
                            .or_insert(1);
                        assert_eq!(
                            left,
                            failure.cleanup.unremovable.len(),
                            "{label}: what is left at the provider is exactly what the failure says could not be removed"
                        );
                    }
                    Outcome::Cancelled { cleanup } => {
                        ended_in
                            .entry("cancelled")
                            .and_modify(|n| *n += 1)
                            .or_insert(1);
                        assert_eq!(left, cleanup.unremovable.len(), "{label}");
                    }
                    Outcome::NeedsAcknowledgement { .. } | Outcome::CapacityUnavailable { .. } => {
                        ended_in
                            .entry("nothing made")
                            .and_modify(|n| *n += 1)
                            .or_insert(1);
                        assert_eq!(
                            left, 0,
                            "{label}: nothing was to be made, so nothing is there"
                        );
                    }
                }
                // Whatever is still at the provider is in the ledger and not marked gone.
                for token in provider.existing_tokens() {
                    assert!(
                        ledger
                            .entries()
                            .iter()
                            .any(|e| e.token == token && e.state != EntryState::Removed),
                        "{label}: {token} exists at the provider but the ledger does not know it, so no cleanup would find it"
                    );
                }
            }
        }
    }
    // The sweep did not collapse into one kind of ending (a guard against it asserting nothing).
    assert!(
        ended_in.get("failed").copied().unwrap_or(0) >= 10,
        "{ended_in:?}"
    );
    assert!(
        ended_in.get("provisioned").copied().unwrap_or(0) >= 1,
        "{ended_in:?}"
    );
}
