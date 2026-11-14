// SPDX-License-Identifier: GPL-3.0-or-later
//! T089 — the provisioning job: its stages, in order, and what each one does when it goes wrong
//! (contracts/provisioning.md §2).
//!
//! ```text
//! CredentialValidation ─▶ CapacityCheck ─▶ InstanceCreate ─▶ NetworkConfigure
//!      ─▶ ServerBootstrap ─▶ KeepaliveInstall ─▶ ReachabilityVerify ─▶ Done
//! ```
//!
//! [`run`] drives one job from start to an [`Outcome`]. What it guarantees, and the tests that hold it to it:
//!
//! - **Nothing is made before it is written down** (PR-07, PRV-04). Each create call is preceded by a
//!   durable ledger entry; if the entry cannot be written, the call is not made. A crash at any moment
//!   leaves a ledger that accounts for everything that exists.
//! - **A root credential is never used** (PR-01, PRV-01). The first call a job makes with a credential
//!   asks the provider what it is; if it is the account owner's, the job stops there. No later call is made.
//! - **No capacity is an outcome, not an error** (US2-2, PRV-03): [`Outcome::CapacityUnavailable`], with the
//!   regions that do have room and what each costs in latency. Nothing has been created, so nothing needs
//!   cleaning, and the job can simply be run again with another region.
//! - **A failure cleans up after itself** (PR-08, PR-16), and says what it could not clean (PR-09).
//!   Cancellation is the same path.
//! - **No `Endpoint` unless it works** (PR-10, PRV-06): the last stage tries the profiles end to end, and a
//!   job where none works yields no endpoint at all.
//! - **The keepalive is not optional** (PRV-09): if it is not installed *and running* afterwards, the job
//!   fails.
//! - **Nothing a provider says reaches a person unwashed** (PR-04): provider text is passed through the
//!   [`Sanitizer`], which removes the credential.
//!
//! Events ([`Event`]) carry stage names and counts, never provider text or anything secret, so they can go
//! straight to the IPC `Subscribe` stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dnet_config::credentials::EndpointCredentials;
use dnet_config::reality::TargetDomain;
use dnet_config::secret_store::SecretKey;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::ids::EndpointId;
use dnet_core::origin::Origin;
use dnet_core::profile::ProfileKind;

use crate::bootstrap::{self, BootstrapPlan, BootstrapReport, Ports, ServerCores, SessionPlan};
use crate::capacity::{self, Alternative, Capacity};
use crate::cleanup::{cleanup, CleanupReport, Unremovable};
use crate::client_keys::{self, ClientKeys, SessionKeys};
use crate::credential::{validate, CredentialProblem};
use crate::keepalive::{self, KeepalivePlan};
use crate::ledger::{valid_token, EntryState, Ledger};
use crate::provider::{InstanceSpec, Provider, ProviderError, ResourceKind};
use crate::sanitize::Sanitizer;
use crate::verify::{require_one, Reachability, VerifyFailure};

/// One step of a job, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    CredentialValidation,
    CapacityCheck,
    InstanceCreate,
    NetworkConfigure,
    ServerBootstrap,
    KeepaliveInstall,
    ReachabilityVerify,
    Done,
}

impl Stage {
    /// Every stage that does work, in order.
    pub const WORK: [Stage; 7] = [
        Stage::CredentialValidation,
        Stage::CapacityCheck,
        Stage::InstanceCreate,
        Stage::NetworkConfigure,
        Stage::ServerBootstrap,
        Stage::KeepaliveInstall,
        Stage::ReachabilityVerify,
    ];

    /// The name used on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::CredentialValidation => "CredentialValidation",
            Stage::CapacityCheck => "CapacityCheck",
            Stage::InstanceCreate => "InstanceCreate",
            Stage::NetworkConfigure => "NetworkConfigure",
            Stage::ServerBootstrap => "ServerBootstrap",
            Stage::KeepaliveInstall => "KeepaliveInstall",
            Stage::ReachabilityVerify => "ReachabilityVerify",
            Stage::Done => "Done",
        }
    }

    /// What the wizard says while it is on this stage.
    pub fn plain(self) -> &'static str {
        match self {
            Stage::CredentialValidation => "Checking your key",
            Stage::CapacityCheck => "Checking that the region has room",
            Stage::InstanceCreate => "Creating the server",
            Stage::NetworkConfigure => "Opening the ports",
            Stage::ServerBootstrap => "Setting the server up",
            Stage::KeepaliveInstall => "Making sure it will not be taken back for being idle",
            Stage::ReachabilityVerify => "Trying it out",
            Stage::Done => "Done",
        }
    }
}

/// Progress, for the IPC stream. Carries no provider text and nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    StageStarted(Stage),
    StageFinished(Stage),
    /// The credential holds permissions beyond what is needed, and the person acknowledged them.
    OverPrivilegedAcknowledged {
        extra: usize,
    },
    CleanupStarted,
    CleanupFinished {
        complete: bool,
    },
}

/// Asks a running job to stop. Cloneable; any clone cancels all.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a job is asked to do.
#[derive(Debug, Clone)]
pub struct JobParams {
    /// Names the resources (`dnet-<job_id>-instance`): lower-case letters, digits and `-`, up to 40.
    pub job_id: String,
    pub region: String,
    pub shape: String,
    /// What the endpoint is called in the person's list.
    pub label: String,
    pub ports: Ports,
    pub cores: ServerCores,
    pub hysteria2_server_name: String,
    pub reality_target: TargetDomain,
    pub keepalive: KeepalivePlan,
    /// The person has seen the list of extra permissions and accepted them (PR-06).
    pub acknowledged_over_privilege: bool,
    /// Where probes of the new endpoint fetch from.
    pub measure_origin: Option<Origin>,
}

/// What a job needs from outside.
pub struct Services<'a> {
    pub provider: &'a dyn Provider,
    pub ledger: &'a mut dyn Ledger,
    pub reachability: &'a dyn Reachability,
    /// Cleans every provider-originated string; should know the credential.
    pub sanitizer: &'a Sanitizer,
    pub cancel: &'a CancelToken,
    pub events: &'a mut dyn FnMut(Event),
}

/// A finished endpoint, ready to be stored: the record, and the credentials to seal under
/// `SecretKey::for_endpoint(endpoint.id())`.
pub struct Provisioned {
    pub endpoint: Endpoint,
    pub credentials: EndpointCredentials,
    /// The profiles that worked when it was tried.
    pub working: Vec<ProfileKind>,
}

impl std::fmt::Debug for Provisioned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provisioned")
            .field("endpoint", &self.endpoint)
            .field("credentials", &"<redacted>")
            .field("working", &self.working)
            .finish()
    }
}

/// Why a job failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FailureReason {
    #[error("the request was not valid: {0}")]
    InvalidRequest(&'static str),
    #[error("{0}")]
    Credential(CredentialProblem),
    /// The free allowance is already used by other resources in the account.
    #[error("the free allowance in this account is already used: {0}")]
    AllowanceUsed(String),
    /// The job could not write down what it was about to make, so it made nothing more.
    #[error(
        "the record of what is being created could not be written, so nothing more was created"
    )]
    LedgerUnavailable,
    #[error("{0}")]
    Provider(String),
    #[error("the server did not set up as expected: {0}")]
    Bootstrap(String),
    #[error("the server is set up but nothing keeps it from being reclaimed for being idle")]
    KeepaliveMissing,
    #[error("{0}")]
    NotReachable(VerifyFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub stage: Stage,
    pub reason: FailureReason,
    /// What was made, and cleaned up or not. Empty when nothing was made.
    pub cleanup: CleanupReport,
}

/// How a job ended.
#[derive(Debug)]
pub enum Outcome {
    /// It worked.
    Provisioned(Box<Provisioned>),
    /// The credential holds more than it needs; nothing was created. Run again with the acknowledgement.
    NeedsAcknowledgement {
        permissions: Vec<String>,
    },
    /// The chosen region has no room. Nothing was created. Run again with one of these.
    CapacityUnavailable {
        alternatives: Vec<Alternative>,
    },
    /// The person stopped it. What had been made was cleaned up as far as it could be.
    Cancelled {
        cleanup: CleanupReport,
    },
    Failed(Box<Failure>),
}

fn instance_token(job_id: &str) -> String {
    format!("dnet-{job_id}-instance")
}

fn network_token(job_id: &str) -> String {
    format!("dnet-{job_id}-network")
}

fn check_params(params: &JobParams) -> Result<(), &'static str> {
    if !(1..=40).contains(&params.job_id.len()) || !valid_token(&instance_token(&params.job_id)) {
        return Err("the job name");
    }
    if params.region.trim().is_empty() || params.shape.trim().is_empty() {
        return Err("the region or the machine size");
    }
    Ok(())
}

/// Drive one job to its end.
pub fn run(params: &JobParams, s: &mut Services<'_>) -> Outcome {
    if let Err(what) = check_params(params) {
        return fail(
            s,
            Stage::CredentialValidation,
            FailureReason::InvalidRequest(what),
        );
    }

    // ---- CredentialValidation
    if let Some(done) = begin(s, Stage::CredentialValidation) {
        return done;
    }
    let inspection = match s.provider.inspect_credential() {
        Ok(inspection) => inspection,
        Err(ProviderError::Unauthorized) => {
            return fail(
                s,
                Stage::CredentialValidation,
                FailureReason::Credential(CredentialProblem::Invalid),
            )
        }
        Err(e) => return fail_provider(s, Stage::CredentialValidation, &e),
    };
    let validated = match validate(&inspection, s.provider.required_permissions()) {
        Ok(validated) => validated,
        Err(problem) => {
            return fail(
                s,
                Stage::CredentialValidation,
                FailureReason::Credential(problem),
            )
        }
    };
    if validated.needs_acknowledgement() {
        if !params.acknowledged_over_privilege {
            return Outcome::NeedsAcknowledgement {
                permissions: validated.over_privileged,
            };
        }
        (s.events)(Event::OverPrivilegedAcknowledged {
            extra: validated.over_privileged.len(),
        });
    }
    (s.events)(Event::StageFinished(Stage::CredentialValidation));

    // ---- CapacityCheck
    if let Some(done) = begin(s, Stage::CapacityCheck) {
        return done;
    }
    match s.provider.check_capacity(&params.region, &params.shape) {
        Ok(Capacity::Available) => {}
        Ok(Capacity::Unavailable { alternatives }) => {
            return Outcome::CapacityUnavailable {
                alternatives: capacity::rank(&alternatives, &params.region),
            }
        }
        Err(e) => return fail_provider(s, Stage::CapacityCheck, &e),
    }
    (s.events)(Event::StageFinished(Stage::CapacityCheck));

    // ---- InstanceCreate: the intent is written first, and if it cannot be, nothing is created.
    if let Some(done) = begin(s, Stage::InstanceCreate) {
        return done;
    }
    let token = instance_token(&params.job_id);
    if s.ledger
        .record_intent(ResourceKind::Instance, &token, &params.region)
        .is_err()
    {
        return fail(s, Stage::InstanceCreate, FailureReason::LedgerUnavailable);
    }
    let instance = match s.provider.create_instance(&InstanceSpec {
        token: token.clone(),
        region: params.region.clone(),
        shape: params.shape.clone(),
    }) {
        Ok(instance) => instance,
        Err(ProviderError::QuotaExceeded(text)) => {
            let text = s.sanitizer.clean(&text);
            return fail(s, Stage::InstanceCreate, FailureReason::AllowanceUsed(text));
        }
        Err(e) => return fail_provider(s, Stage::InstanceCreate, &e),
    };
    if s.ledger
        .record_created(&token, &instance.provider_id)
        .is_err()
    {
        return fail(s, Stage::InstanceCreate, FailureReason::LedgerUnavailable);
    }
    (s.events)(Event::StageFinished(Stage::InstanceCreate));

    // ---- NetworkConfigure
    if let Some(done) = begin(s, Stage::NetworkConfigure) {
        return done;
    }
    let network = network_token(&params.job_id);
    if s.ledger
        .record_intent(ResourceKind::NetworkRule, &network, &params.region)
        .is_err()
    {
        return fail(s, Stage::NetworkConfigure, FailureReason::LedgerUnavailable);
    }
    let rules =
        match s
            .provider
            .open_ports(&network, &params.region, &instance, &params.ports.rules())
        {
            Ok(rules) => rules,
            Err(e) => return fail_provider(s, Stage::NetworkConfigure, &e),
        };
    if s.ledger
        .record_created(&network, &rules.provider_id)
        .is_err()
    {
        return fail(s, Stage::NetworkConfigure, FailureReason::LedgerUnavailable);
    }
    (s.events)(Event::StageFinished(Stage::NetworkConfigure));

    // ---- ServerBootstrap
    if let Some(done) = begin(s, Stage::ServerBootstrap) {
        return done;
    }
    let keys = match ClientKeys::generate() {
        Ok(keys) => keys,
        Err(_) => {
            return fail(
                s,
                Stage::ServerBootstrap,
                FailureReason::Bootstrap("no randomness was available for the keys".into()),
            )
        }
    };
    let obfuscation = match client_keys::random_obfuscation() {
        Ok(obfuscation) => obfuscation,
        Err(_) => {
            return fail(
                s,
                Stage::ServerBootstrap,
                FailureReason::Bootstrap("no randomness was available for the parameters".into()),
            )
        }
    };
    let session_keys = match SessionKeys::generate() {
        Ok(keys) => keys,
        Err(_) => {
            return fail(
                s,
                Stage::ServerBootstrap,
                FailureReason::Bootstrap("no randomness was available for the keys".into()),
            )
        }
    };
    let plan = BootstrapPlan {
        cores: params.cores.clone(),
        ports: params.ports,
        awg_client_public_hex: keys.public_hex().to_owned(),
        obfuscation,
        hysteria2_server_name: params.hysteria2_server_name.clone(),
        reality_target: params.reality_target.clone(),
        session: SessionPlan {
            device_public_keys: vec![session_keys.public_b64().to_owned()],
        },
    };
    let script = match bootstrap::script(&plan) {
        Ok(script) => script,
        Err(e) => {
            return fail(
                s,
                Stage::ServerBootstrap,
                FailureReason::Bootstrap(e.to_string()),
            )
        }
    };
    let output = match s.provider.bootstrap(&instance, &script) {
        Ok(output) => output,
        Err(e) => return fail_provider(s, Stage::ServerBootstrap, &e),
    };
    let report = match BootstrapReport::parse(&output).and_then(|report| {
        report.check_against(&plan)?;
        Ok(report)
    }) {
        Ok(report) => report,
        Err(e) => {
            return fail(
                s,
                Stage::ServerBootstrap,
                FailureReason::Bootstrap(e.to_string()),
            )
        }
    };
    let credentials = report.credentials(
        &keys,
        &session_keys,
        obfuscation,
        params.measure_origin.clone(),
    );
    (s.events)(Event::StageFinished(Stage::ServerBootstrap));

    // ---- KeepaliveInstall: not optional.
    if let Some(done) = begin(s, Stage::KeepaliveInstall) {
        return done;
    }
    if let Err(e) = s
        .provider
        .install_keepalive(&instance, &keepalive::script(&params.keepalive))
    {
        return fail_provider(s, Stage::KeepaliveInstall, &e);
    }
    match s.provider.keepalive_installed(&instance) {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return fail(s, Stage::KeepaliveInstall, FailureReason::KeepaliveMissing)
        }
    }
    (s.events)(Event::StageFinished(Stage::KeepaliveInstall));

    // ---- ReachabilityVerify: no endpoint unless one profile works end to end.
    if let Some(done) = begin(s, Stage::ReachabilityVerify) {
        return done;
    }
    let results = s.reachability.verify(instance.public_ip, &credentials);
    let working = match require_one(&results) {
        Ok(working) => working,
        Err(e) => return fail(s, Stage::ReachabilityVerify, FailureReason::NotReachable(e)),
    };
    (s.events)(Event::StageFinished(Stage::ReachabilityVerify));

    // ---- Done
    let id = EndpointId::new();
    let display_port = credentials
        .amneziawg
        .as_ref()
        .map(|a| a.server_port)
        .unwrap_or(params.ports.amneziawg_udp);
    let endpoint = Endpoint::new(
        id,
        params.label.trim(),
        match EndpointAddress::new(instance.public_ip.to_string(), display_port) {
            Ok(address) => address,
            Err(_) => {
                return fail(
                    s,
                    Stage::Done,
                    FailureReason::InvalidRequest("the server's address"),
                )
            }
        },
        EndpointOrigin::Provisioned {
            provider: s.provider.name().to_owned(),
            region: params.region.clone(),
            resource_ids: vec![instance.provider_id.clone(), rules.provider_id.clone()],
        },
        SecretKey::for_endpoint(id).credential_ref(),
    );
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(_) => return fail(s, Stage::Done, FailureReason::InvalidRequest("the label")),
    };
    (s.events)(Event::StageStarted(Stage::Done));
    (s.events)(Event::StageFinished(Stage::Done));
    Outcome::Provisioned(Box::new(Provisioned {
        endpoint,
        credentials,
        working,
    }))
}

/// Announce a stage, or stop here if the person has cancelled.
fn begin(s: &mut Services<'_>, stage: Stage) -> Option<Outcome> {
    if s.cancel.is_cancelled() {
        let report = clean_up(s);
        return Some(Outcome::Cancelled { cleanup: report });
    }
    (s.events)(Event::StageStarted(stage));
    None
}

fn fail_provider(s: &mut Services<'_>, stage: Stage, error: &ProviderError) -> Outcome {
    let text = s.sanitizer.clean(&error.to_string());
    fail(s, stage, FailureReason::Provider(text))
}

fn fail(s: &mut Services<'_>, stage: Stage, reason: FailureReason) -> Outcome {
    let cleanup = clean_up(s);
    Outcome::Failed(Box::new(Failure {
        stage,
        reason,
        cleanup,
    }))
}

/// Remove whatever the ledger records. If the ledger itself cannot be written, everything not recorded as
/// gone is reported as still there, which is the safe thing to say.
fn clean_up(s: &mut Services<'_>) -> CleanupReport {
    let anything = s
        .ledger
        .entries()
        .iter()
        .any(|e| e.state != EntryState::Removed);
    if !anything {
        return CleanupReport::default();
    }
    (s.events)(Event::CleanupStarted);
    let report = match cleanup(s.provider, s.ledger, s.sanitizer) {
        Ok(report) => report,
        Err(_) => CleanupReport {
            removed: Vec::new(),
            unremovable: s
                .ledger
                .entries()
                .into_iter()
                .filter(|e| e.state != EntryState::Removed)
                .map(|e| Unremovable {
                    kind: e.kind,
                    token: e.token,
                    provider_id: e.provider_id,
                    region: e.region,
                    reason: "the record of this resource could not be updated".to_owned(),
                })
                .collect(),
        },
    };
    (s.events)(Event::CleanupFinished {
        complete: report.is_complete(),
    });
    report
}
