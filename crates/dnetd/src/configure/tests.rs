//! Tests of the configuration transactions, against a state file and a secret store that can be made
//! to fail. What each one pins is that a failure at any step leaves the store, the file and the
//! sealed credentials exactly as they were.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dnet_config::amneziawg::{ObfuscationParams, PrivateKey};
use dnet_config::credentials::{
    AmneziaWgCredentials, EndpointCredentials, Hysteria2Bundle, RealityBundle,
};
use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use dnet_config::persist::{ConfigStore, MemoryStateFile, StateFile, MAX_ENDPOINTS};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::secret_store::{MemorySecretStore, SecretKey, SecretStore, SecretStoreError};
use dnet_config::tls::ServerTrust;
use dnet_core::credential::CredentialRef;
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::ids::EndpointId;
use dnet_core::profile::{BandwidthPair, BrutalAcknowledgement, BRUTAL_WARNING_REVISION};
use dnet_core::rule::{RuleAction, RuleMatcher};
use dnet_ipc::protocol::NewEndpoint;

use super::{Configurator, ConfigureError};
use crate::domain::DomainState;

/// In every secret below. If it shows up in the saved file, an error or a reply, a secret leaked.
pub(crate) const SENTINEL: &str = "SENTINEL-cfg-7d21";

pub(crate) fn credentials() -> EndpointCredentials {
    EndpointCredentials {
        amneziawg: None,
        hysteria2: Some(Hysteria2Bundle {
            server_port: 44443,
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(format!("{SENTINEL}-auth-0123456789")),
                obfs_password: Secret::new(format!("{SENTINEL}-obfs-0123456789")),
            },
            endpoint: Hysteria2EndpointParams {
                obfs: Hysteria2Obfs::Salamander,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: "edge.example.net".into(),
                    spki_sha256: [7; 32],
                },
            },
        }),
        reality: Some(RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("0123456789abcdef"),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        }),
        measure_origin: None,
        session: None,
    }
}

/// A bundle serving only the UDP tunnel, to check which port is shown.
fn amneziawg_only() -> EndpointCredentials {
    EndpointCredentials {
        amneziawg: Some(AmneziaWgCredentials {
            client_private_key: PrivateKey::new("1".repeat(64)),
            server_public_key: "2".repeat(64),
            client_address: "10.66.0.2".parse().unwrap(),
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
        }),
        hysteria2: None,
        reality: None,
        measure_origin: None,
        session: None,
    }
}

pub(crate) fn new_endpoint(label: &str) -> NewEndpoint {
    NewEndpoint::new(label, "203.0.113.9", credentials()).unwrap()
}

/// A state file whose writes can be made to fail.
#[derive(Default)]
struct Flaky {
    inner: MemoryStateFile,
    fail_writes: AtomicBool,
}

impl StateFile for Flaky {
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        self.inner.read()
    }
    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err("disk full".into());
        }
        self.inner.write(bytes)
    }
    fn remove(&self) -> Result<(), String> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err("access denied".into());
        }
        self.inner.remove()
    }
}

/// A secret store whose puts and deletes can be made to fail.
#[derive(Default)]
struct FlakySecrets {
    inner: MemorySecretStore,
    fail_put: AtomicBool,
    fail_delete: AtomicBool,
}

impl SecretStore for FlakySecrets {
    fn put(
        &self,
        key: &SecretKey,
        credentials: &EndpointCredentials,
    ) -> Result<(), SecretStoreError> {
        if self.fail_put.load(Ordering::SeqCst) {
            return Err(SecretStoreError::Storage {
                key: key.as_str().to_owned(),
                reason: "no space".into(),
            });
        }
        self.inner.put(key, credentials)
    }
    fn get(&self, key: &SecretKey) -> Result<Option<EndpointCredentials>, SecretStoreError> {
        self.inner.get(key)
    }
    fn delete(&self, key: &SecretKey) -> Result<bool, SecretStoreError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(SecretStoreError::Storage {
                key: key.as_str().to_owned(),
                reason: "locked".into(),
            });
        }
        self.inner.delete(key)
    }
}

struct Rig {
    state: DomainState,
    configurator: Configurator,
    file: Arc<Flaky>,
    secrets: Arc<FlakySecrets>,
}

impl Rig {
    fn new() -> Self {
        let file = Arc::new(Flaky::default());
        let secrets = Arc::new(FlakySecrets::default());
        Self {
            state: DomainState::seeded(),
            configurator: Configurator::new(
                ConfigStore::new(Box::new(Arc::clone(&file))),
                Arc::clone(&secrets) as Arc<dyn SecretStore>,
            ),
            file,
            secrets,
        }
    }

    fn saved(&self) -> Option<dnet_config::persist::LoadedConfig> {
        ConfigStore::new(Box::new(Arc::clone(&self.file)))
            .load()
            .unwrap()
    }

    fn file_bytes(&self) -> Option<Vec<u8>> {
        self.file.inner.bytes()
    }

    fn add(&mut self, label: &str) -> EndpointId {
        self.configurator
            .add_endpoint(&mut self.state, &new_endpoint(label))
            .unwrap()
    }

    fn fail_writes(&self, fail: bool) {
        self.file.fail_writes.store(fail, Ordering::SeqCst);
    }
}

fn refused(error: &ConfigureError) -> &str {
    match error {
        ConfigureError::Refused(detail) => detail,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ------------------------------------------------------------------ add

#[test]
fn an_added_endpoint_is_in_the_store_the_file_and_the_sealed_credentials() {
    let mut rig = Rig::new();
    let id = rig.add("first");

    assert_eq!(rig.state.endpoints().len(), 1);
    assert_eq!(rig.state.endpoint(id).unwrap().label(), "first");

    let saved = rig.saved().expect("the file was written");
    assert_eq!(saved.endpoints.len(), 1);
    assert_eq!(saved.endpoints[0].id(), id);

    let stored = rig
        .secrets
        .get(&SecretKey::for_endpoint(id))
        .unwrap()
        .expect("the credentials were sealed under the endpoint's key");
    assert!(stored.hysteria2.is_some() && stored.reality.is_some());
    assert_eq!(
        saved.endpoints[0].credentials().store_key(),
        SecretKey::for_endpoint(id).as_str(),
        "the file names exactly the key the credentials are under"
    );
}

#[test]
fn the_saved_file_holds_no_secret() {
    let mut rig = Rig::new();
    rig.add("first");
    let text = String::from_utf8(rig.file_bytes().unwrap()).unwrap();
    assert!(!text.contains("SENTINEL"), "{text}");
}

#[test]
fn the_port_shown_is_the_first_profile_the_bundle_has() {
    let mut rig = Rig::new();
    let both = rig.add("both");
    let udp = rig
        .configurator
        .add_endpoint(
            &mut rig.state,
            &NewEndpoint::new("udp", "203.0.113.10", amneziawg_only()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        rig.state.endpoint(both).unwrap().address().port(),
        44443,
        "no UDP tunnel in the bundle: the next one"
    );
    assert_eq!(rig.state.endpoint(udp).unwrap().address().port(), 51820);
}

#[test]
fn a_duplicate_label_is_refused_and_nothing_changes() {
    let mut rig = Rig::new();
    rig.add("first");
    let (bytes, secrets) = (rig.file_bytes(), rig.secrets.inner.len());

    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("first"))
        .unwrap_err();
    assert!(refused(&error).contains("label"));
    assert_eq!(rig.state.endpoints().len(), 1);
    assert_eq!(rig.file_bytes(), bytes);
    assert_eq!(rig.secrets.inner.len(), secrets);
}

#[test]
fn a_refusal_does_not_repeat_what_the_client_sent() {
    let mut rig = Rig::new();
    rig.add("first");
    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("first"))
        .unwrap_err();
    let text = format!(
        "{error:?} {}",
        dnet_ipc::protocol::IpcError::from(error.clone())
    );
    assert!(!text.contains("first"), "{text}");
    assert!(!text.contains("203.0.113"), "{text}");
}

#[test]
fn a_failed_save_removes_the_credentials_it_sealed_and_restores_the_store() {
    let mut rig = Rig::new();
    rig.add("first");
    let (bytes, secrets) = (rig.file_bytes(), rig.secrets.inner.len());
    rig.fail_writes(true);

    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("second"))
        .unwrap_err();
    assert!(matches!(error, ConfigureError::Storage(_)), "{error:?}");
    assert_eq!(rig.state.endpoints().len(), 1, "the store is as it was");
    assert_eq!(rig.file_bytes(), bytes, "the file is as it was");
    assert_eq!(
        rig.secrets.inner.len(),
        secrets,
        "no sealed credentials without an endpoint"
    );
}

#[test]
fn credentials_that_cannot_be_sealed_leave_the_file_untouched() {
    let mut rig = Rig::new();
    rig.secrets.fail_put.store(true, Ordering::SeqCst);

    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("first"))
        .unwrap_err();
    assert!(matches!(error, ConfigureError::Storage(_)));
    assert!(rig.state.endpoints().is_empty());
    assert!(
        rig.file_bytes().is_none(),
        "a file naming credentials that do not exist is the worse outcome"
    );
}

#[test]
fn a_failed_cleanup_after_a_failed_save_still_reports_the_save() {
    let mut rig = Rig::new();
    rig.fail_writes(true);
    rig.secrets.fail_delete.store(true, Ordering::SeqCst);
    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("first"))
        .unwrap_err();
    match error {
        ConfigureError::Storage(detail) => assert!(detail.contains("disk full"), "{detail}"),
        other => panic!("{other:?}"),
    }
    assert!(rig.state.endpoints().is_empty());
}

#[test]
fn the_most_endpoints_that_can_be_kept_is_enforced() {
    let mut rig = Rig::new();
    for n in 0..MAX_ENDPOINTS {
        rig.add(&format!("e{n}"));
    }
    let bytes = rig.file_bytes();
    let error = rig
        .configurator
        .add_endpoint(&mut rig.state, &new_endpoint("one-too-many"))
        .unwrap_err();
    assert!(refused(&error).contains("64"), "{error:?}");
    assert_eq!(rig.state.endpoints().len(), MAX_ENDPOINTS);
    assert_eq!(rig.file_bytes(), bytes);
}

// ------------------------------------------------------------------ remove

#[test]
fn a_removed_endpoint_leaves_the_store_the_file_and_the_sealed_credentials() {
    let mut rig = Rig::new();
    let keep = rig.add("keep");
    let drop = rig.add("drop");

    rig.configurator
        .remove_endpoint(&mut rig.state, drop)
        .unwrap();

    assert_eq!(rig.state.endpoints().len(), 1);
    assert_eq!(rig.saved().unwrap().endpoints.len(), 1);
    assert!(rig
        .secrets
        .get(&SecretKey::for_endpoint(drop))
        .unwrap()
        .is_none());
    assert!(
        rig.secrets
            .get(&SecretKey::for_endpoint(keep))
            .unwrap()
            .is_some(),
        "the other endpoint's credentials are untouched"
    );
}

#[test]
fn removing_an_unknown_endpoint_is_refused_and_changes_nothing() {
    let mut rig = Rig::new();
    rig.add("keep");
    let bytes = rig.file_bytes();
    let error = rig
        .configurator
        .remove_endpoint(&mut rig.state, EndpointId::new())
        .unwrap_err();
    assert!(refused(&error).contains("no endpoint"));
    assert_eq!(rig.file_bytes(), bytes);
}

#[test]
fn a_failed_save_keeps_the_endpoint_and_its_credentials() {
    let mut rig = Rig::new();
    let id = rig.add("keep");
    let bytes = rig.file_bytes();
    rig.fail_writes(true);

    let error = rig
        .configurator
        .remove_endpoint(&mut rig.state, id)
        .unwrap_err();
    assert!(matches!(error, ConfigureError::Storage(_)));
    assert!(rig.state.endpoint(id).is_some());
    assert_eq!(rig.file_bytes(), bytes);
    assert!(
        rig.secrets
            .get(&SecretKey::for_endpoint(id))
            .unwrap()
            .is_some(),
        "credentials are forgotten only after the file stopped naming them"
    );
}

#[test]
fn a_credential_that_cannot_be_forgotten_does_not_undo_the_removal() {
    let mut rig = Rig::new();
    let id = rig.add("drop");
    rig.secrets.fail_delete.store(true, Ordering::SeqCst);

    rig.configurator
        .remove_endpoint(&mut rig.state, id)
        .expect("the endpoint is gone; the stray blob is only clutter");
    assert!(rig.state.endpoint(id).is_none());
    assert!(rig.saved().unwrap().endpoints.is_empty());
}

#[test]
fn an_endpoint_holding_cloud_resources_is_not_removed_here() {
    let mut rig = Rig::new();
    let id = EndpointId::new();
    rig.state
        .add_endpoint(
            Endpoint::new(
                id,
                "cloud",
                EndpointAddress::new("203.0.113.50", 443).unwrap(),
                EndpointOrigin::Provisioned {
                    provider: "example".into(),
                    region: "r1".into(),
                    resource_ids: vec!["i-1".into()],
                },
                CredentialRef::new(SecretKey::for_endpoint(id).as_str()),
            )
            .unwrap(),
        )
        .unwrap();

    let error = rig
        .configurator
        .remove_endpoint(&mut rig.state, id)
        .unwrap_err();
    assert!(refused(&error).contains("cloud resources"));
    assert!(rig.state.endpoint(id).is_some());
    assert!(rig.file_bytes().is_none(), "nothing was written");
}

// ------------------------------------------------------------------ enable and disable

#[test]
fn disabling_and_enabling_are_saved() {
    let mut rig = Rig::new();
    let id = rig.add("first");

    rig.configurator
        .set_endpoint_enabled(&mut rig.state, id, false)
        .unwrap();
    assert!(!rig.state.endpoint(id).unwrap().is_enabled());
    assert!(!rig.saved().unwrap().endpoints[0].is_enabled());

    rig.configurator
        .set_endpoint_enabled(&mut rig.state, id, true)
        .unwrap();
    assert!(rig.saved().unwrap().endpoints[0].is_enabled());
}

#[test]
fn a_failed_enable_save_leaves_the_endpoint_as_it_was() {
    let mut rig = Rig::new();
    let id = rig.add("first");
    rig.fail_writes(true);

    assert!(rig
        .configurator
        .set_endpoint_enabled(&mut rig.state, id, false)
        .is_err());
    assert!(
        rig.state.endpoint(id).unwrap().is_enabled(),
        "what the store says must be what is saved"
    );
}

#[test]
fn enabling_an_unknown_endpoint_is_refused() {
    let mut rig = Rig::new();
    let error = rig
        .configurator
        .set_endpoint_enabled(&mut rig.state, EndpointId::new(), true)
        .unwrap_err();
    assert!(refused(&error).contains("no endpoint"));
    assert!(rig.file_bytes().is_none());
}

// ------------------------------------------------------------------ Brutal (T105)

const NOW: u64 = 1_790_000_000;

fn hy2() -> dnet_core::ids::ProfileId {
    dnet_core::ids::ProfileId::new("hy2-default")
}

fn saved_brutal(rig: &Rig) -> Option<(BandwidthPair, BrutalAcknowledgement)> {
    rig.saved()
        .unwrap()
        .profiles
        .into_iter()
        .find(|p| p.id == hy2())
        .and_then(|p| p.brutal)
}

const PAIR: BandwidthPair = BandwidthPair {
    up_mbps: 50,
    down_mbps: 200,
};

#[test]
fn turning_brutal_on_is_saved_with_the_warning_and_the_time_it_was_accepted() {
    let mut rig = Rig::new();
    rig.configurator
        .set_brutal(&mut rig.state, &hy2(), Some(PAIR), NOW)
        .unwrap();

    let (bandwidth, ack) = saved_brutal(&rig).expect("saved");
    assert_eq!(bandwidth, PAIR);
    assert_eq!(ack.warning_revision, BRUTAL_WARNING_REVISION);
    assert_eq!(ack.acknowledged_at_unix, NOW);
    let profile = rig
        .state
        .profiles()
        .iter()
        .find(|p| p.id() == &hy2())
        .unwrap();
    assert_eq!(profile.brutal().map(|b| *b.bandwidth()), Some(PAIR));
}

#[test]
fn turning_brutal_off_is_saved() {
    let mut rig = Rig::new();
    rig.configurator
        .set_brutal(&mut rig.state, &hy2(), Some(PAIR), NOW)
        .unwrap();
    rig.configurator
        .set_brutal(&mut rig.state, &hy2(), None, NOW)
        .unwrap();
    assert_eq!(saved_brutal(&rig), None);
    assert!(rig.state.profiles().iter().all(|p| p.brutal().is_none()));
}

#[test]
fn brutal_on_a_profile_that_is_not_hysteria_2_or_does_not_exist_is_refused() {
    let mut rig = Rig::new();
    for id in ["awg-default", "reality-default", "no-such-profile"] {
        let error = rig
            .configurator
            .set_brutal(
                &mut rig.state,
                &dnet_core::ids::ProfileId::new(id),
                Some(PAIR),
                NOW,
            )
            .unwrap_err();
        assert!(!refused(&error).is_empty(), "{id}");
        assert!(!refused(&error).contains(id), "repeated {id}: {error:?}");
    }
    assert!(rig.file_bytes().is_none(), "nothing was saved");
}

#[test]
fn a_brutal_change_that_cannot_be_saved_changes_nothing() {
    let mut rig = Rig::new();
    rig.fail_writes(true);
    assert!(matches!(
        rig.configurator
            .set_brutal(&mut rig.state, &hy2(), Some(PAIR), NOW),
        Err(ConfigureError::Storage(_))
    ));
    assert!(rig.state.profiles().iter().all(|p| p.brutal().is_none()));
}

// ------------------------------------------------------------------ a person's rules (T108)

fn rule_count(rig: &Rig) -> usize {
    rig.state.rules().iter().filter(|r| !r.is_builtin()).count()
}

#[test]
fn a_rule_is_added_saved_and_removed() {
    let mut rig = Rig::new();
    let id = rig
        .configurator
        .add_rule(
            &mut rig.state,
            RuleMatcher::DomainSuffix("example.com".into()),
            RuleAction::Bypass,
        )
        .unwrap();
    assert_eq!(rule_count(&rig), 1);
    assert_eq!(rig.saved().unwrap().rules.len(), 1);
    assert_eq!(rig.saved().unwrap().rules[0].id(), id);

    rig.configurator.remove_rule(&mut rig.state, id).unwrap();
    assert_eq!(rule_count(&rig), 0);
    assert!(rig.saved().unwrap().rules.is_empty());
}

/// Program rules need connect-time attribution, which this build does not run. One added now would
/// do nothing at all, so it is refused with that reason rather than accepted as "best effort".
#[test]
fn a_program_rule_is_refused_while_programs_are_not_attributed() {
    let mut rig = Rig::new();
    let error = rig
        .configurator
        .add_rule(
            &mut rig.state,
            RuleMatcher::Application(r"C:pp.exe".into()),
            RuleAction::Tunnel,
        )
        .unwrap_err();
    assert!(refused(&error).contains("program"), "{error:?}");
    assert!(rig.file_bytes().is_none());
}

#[test]
fn removing_a_built_in_or_an_unknown_rule_is_refused() {
    let mut rig = Rig::new();
    let builtin = rig.state.rules()[0].id();
    assert!(!refused(
        &rig.configurator
            .remove_rule(&mut rig.state, builtin)
            .unwrap_err()
    )
    .is_empty());
    let unknown = dnet_core::ids::RuleId::new();
    assert!(refused(
        &rig.configurator
            .remove_rule(&mut rig.state, unknown)
            .unwrap_err()
    )
    .contains("no rule"));
    assert!(rig.file_bytes().is_none());
}

/// Every built-in rule is refused with the reason that is about built-in rules (what they keep working), not with
/// whatever a deeper check says, and none is touched.
#[test]
fn every_built_in_rule_is_refused_with_its_own_reason_and_stays_where_it_is() {
    let mut rig = Rig::new();
    let before: Vec<_> = rig.state.rules().iter().map(|r| r.id()).collect();
    let builtin: Vec<_> = rig
        .state
        .rules()
        .iter()
        .filter(|r| r.is_builtin())
        .map(|r| r.id())
        .collect();
    assert!(
        builtin.len() >= 4,
        "the default set has several built-in rules"
    );
    for id in builtin {
        let error = rig
            .configurator
            .remove_rule(&mut rig.state, id)
            .unwrap_err();
        let reason = refused(&error);
        assert!(
            reason.contains("built-in rule cannot be removed"),
            "{reason}"
        );
        assert!(reason.contains("keeps name lookups"), "{reason}");
    }
    let after: Vec<_> = rig.state.rules().iter().map(|r| r.id()).collect();
    assert_eq!(after, before, "no rule was touched");
    assert!(rig.file_bytes().is_none(), "nothing was saved");
}

#[test]
fn a_rule_that_cannot_be_saved_is_not_kept() {
    let mut rig = Rig::new();
    rig.fail_writes(true);
    assert!(matches!(
        rig.configurator.add_rule(
            &mut rig.state,
            RuleMatcher::Domain("example.com".into()),
            RuleAction::Tunnel
        ),
        Err(ConfigureError::Storage(_))
    ));
    assert_eq!(rule_count(&rig), 0);
}

#[test]
fn there_is_a_limit_to_how_many_rules_a_person_adds() {
    let mut rig = Rig::new();
    for i in 0..dnet_config::persist::MAX_USER_RULES {
        rig.configurator
            .add_rule(
                &mut rig.state,
                RuleMatcher::Domain(format!("host{i}.example.com")),
                RuleAction::Tunnel,
            )
            .unwrap();
    }
    let error = rig
        .configurator
        .add_rule(
            &mut rig.state,
            RuleMatcher::Domain("one-more.example.com".into()),
            RuleAction::Tunnel,
        )
        .unwrap_err();
    assert!(refused(&error).contains("at most"), "{error:?}");
}

// ------------------------------------------------------------------ checked before it is held (T160)

/// A change that redirects traffic is checked before anyone is asked to approve it: the check says
/// exactly what adding would say, and keeps nothing.
#[test]
fn checking_an_endpoint_says_what_adding_it_would_say_and_keeps_nothing() {
    let mut rig = Rig::new();
    rig.add("first");
    let (count, bytes, secrets) = (
        rig.state.endpoints().len(),
        rig.file_bytes(),
        rig.secrets.inner.len(),
    );

    rig.configurator
        .check_add_endpoint(&rig.state, &new_endpoint("second"))
        .unwrap();
    let checked = rig
        .configurator
        .check_add_endpoint(&rig.state, &new_endpoint("first"))
        .unwrap_err();
    let added = rig
        .configurator
        .add_endpoint(&mut rig.state.clone(), &new_endpoint("first"))
        .unwrap_err();
    assert_eq!(refused(&checked), refused(&added));
    assert_eq!(rig.state.endpoints().len(), count);
    assert_eq!(rig.file_bytes(), bytes);
    assert_eq!(rig.secrets.inner.len(), secrets);
}

#[test]
fn checking_an_endpoint_past_the_most_that_can_be_kept_is_refused() {
    let mut rig = Rig::new();
    for n in 0..MAX_ENDPOINTS {
        rig.add(&format!("e{n}"));
    }
    let error = rig
        .configurator
        .check_add_endpoint(&rig.state, &new_endpoint("one-too-many"))
        .unwrap_err();
    assert!(refused(&error).contains("64"), "{error:?}");
}

#[test]
fn checking_a_rule_says_what_adding_it_would_say_and_keeps_nothing() {
    let rig = Rig::new();
    let before = rig.state.rules().len();
    rig.configurator
        .check_add_rule(
            &rig.state,
            &RuleMatcher::Domain("example.com".into()),
            RuleAction::Bypass,
        )
        .unwrap();
    let program = rig
        .configurator
        .check_add_rule(
            &rig.state,
            &RuleMatcher::Application(r"C:pp.exe".into()),
            RuleAction::Bypass,
        )
        .unwrap_err();
    assert!(refused(&program).contains("program"), "{program:?}");
    assert_eq!(rig.state.rules().len(), before);
    assert!(rig.file_bytes().is_none());
}

#[test]
fn checking_a_rule_past_the_limit_is_refused() {
    let mut rig = Rig::new();
    for i in 0..dnet_config::persist::MAX_USER_RULES {
        rig.configurator
            .add_rule(
                &mut rig.state,
                RuleMatcher::Domain(format!("host{i}.example.com")),
                RuleAction::Tunnel,
            )
            .unwrap();
    }
    let error = rig
        .configurator
        .check_add_rule(
            &rig.state,
            &RuleMatcher::Domain("one-more.example.com".into()),
            RuleAction::Bypass,
        )
        .unwrap_err();
    assert!(refused(&error).contains("at most"), "{error:?}");
}

// ------------------------------------------------------------------ encrypted DNS

#[test]
fn opting_out_is_saved_and_returns_the_consequence_to_show() {
    let mut rig = Rig::new();
    let consequence = rig
        .configurator
        .set_encrypted_dns(&mut rig.state, false)
        .unwrap()
        .expect("opting out must say what it costs");
    assert_eq!(
        consequence,
        dnet_core::doh_consent::consequence_of_opting_out()
    );
    assert_eq!(rig.state.consent().policy(), Policy::Allow);

    let saved = rig.saved().unwrap();
    assert_eq!(
        saved
            .encrypted_dns
            .expect("the choice is recorded")
            .policy(),
        Policy::Allow,
        "a restart must not forget the person's choice"
    );
}

#[test]
fn choosing_the_block_on_a_fresh_install_records_that_the_disclosure_was_shown() {
    let mut rig = Rig::new();
    assert!(rig.state.consent().needs_disclosure());

    let shown = rig
        .configurator
        .set_encrypted_dns(&mut rig.state, true)
        .unwrap();

    assert_eq!(shown, None);
    assert!(!rig.state.consent().needs_disclosure());
    let saved = rig
        .saved()
        .unwrap()
        .encrypted_dns
        .expect("the choice is saved");
    assert!(!saved.needs_disclosure(), "a restart must not ask again");
    assert_eq!(saved.policy(), Policy::Block);
}

#[test]
fn restoring_the_block_is_saved_and_needs_no_consequence() {
    let mut rig = Rig::new();
    rig.configurator
        .set_encrypted_dns(&mut rig.state, false)
        .unwrap();
    let shown = rig
        .configurator
        .set_encrypted_dns(&mut rig.state, true)
        .unwrap();
    assert_eq!(shown, None);
    assert_eq!(rig.state.consent().policy(), Policy::Block);
    assert_eq!(
        rig.saved().unwrap().encrypted_dns.unwrap().policy(),
        Policy::Block
    );
}

#[test]
fn a_failed_save_does_not_leave_the_block_lifted() {
    let mut rig = Rig::new();
    rig.fail_writes(true);
    assert!(rig
        .configurator
        .set_encrypted_dns(&mut rig.state, false)
        .is_err());
    assert_eq!(
        rig.state.consent().policy(),
        Policy::Block,
        "the protective setting survives a failure to save the opt-out"
    );
    assert!(
        rig.state
            .rules()
            .iter()
            .any(|r| r.action() == dnet_core::rule::RuleAction::Reject),
        "and the blocking rules are still in the rule set"
    );
}

#[test]
fn the_replies_carry_no_value_the_client_sent() {
    let id = EndpointId::new();
    assert_eq!(super::added_reply(id), format!(r#"{{"endpoint":"{id}"}}"#));
    assert_eq!(super::dns_reply(true, None), r#"{"block":true}"#);
    let reply: serde_json::Value =
        serde_json::from_str(&super::dns_reply(false, Some("it costs this"))).unwrap();
    assert_eq!(reply["block"], false);
    assert_eq!(reply["consequence"], "it costs this");
}
