//! A provider that creates nothing real, for the contract tests (PRV-01…PRV-09) and the unit tests.
//!
//! "No test creates real cloud resources" (T086) is kept by construction: this is the only provider the
//! crate ships. It keeps the machines and rules it is asked for in a table, so a test can look at what
//! *exists* after a crash, a cancellation or a cleanup, and not merely at what the job believes.
//!
//! It can fail on demand (once, or every time) for any call, can panic right after a create has taken
//! effect (to stand for a crash at exactly the worst moment), and can put a credential into its error text
//! (to prove the job does not pass that on).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Mutex, MutexGuard};

use crate::capacity::Capacity;
use crate::credential::{Inspection, Standing, Subject};
use crate::provider::{
    DeleteOutcome, InstanceInfo, InstanceSpec, NetworkInfo, PortRule, Provider, ProviderError,
    ResourceKind,
};
use crate::secret::Secret;

/// The permissions the mock says a job needs.
pub const REQUIRED: &[&str] = &["manage instances", "manage network rules"];

#[derive(Debug, Clone)]
struct Resource {
    token: String,
    region: String,
}

struct State {
    credential: Option<Secret>,
    leak_credential: bool,
    inspection: Inspection,
    capacity: Capacity,
    resources: HashMap<(ResourceKind, String), Resource>,
    next_id: u32,
    calls: Vec<String>,
    deletions: Vec<String>,
    fail_once: HashMap<&'static str, ProviderError>,
    fail_always: HashMap<&'static str, ProviderError>,
    crash_after: HashSet<&'static str>,
    refuse_delete: HashMap<String, ProviderError>,
    bootstrap_output: String,
    last_bootstrap_script: Option<String>,
    last_keepalive_script: Option<String>,
    keepalive_installed: bool,
    install_keepalive_works: bool,
}

pub struct MockProvider {
    state: Mutex<State>,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProvider {
    /// A provider whose credential is a valid dedicated user holding exactly the needed permissions, with
    /// capacity everywhere, and that bootstraps to an empty reply (tests set what they need).
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                credential: None,
                leak_credential: false,
                inspection: Inspection {
                    subject: Subject::DedicatedUser,
                    standing: Standing::Valid,
                    granted: REQUIRED.iter().map(|s| (*s).to_owned()).collect(),
                },
                capacity: Capacity::Available,
                resources: HashMap::new(),
                next_id: 0,
                calls: Vec::new(),
                deletions: Vec::new(),
                fail_once: HashMap::new(),
                fail_always: HashMap::new(),
                crash_after: HashSet::new(),
                refuse_delete: HashMap::new(),
                bootstrap_output: String::new(),
                last_bootstrap_script: None,
                last_keepalive_script: None,
                keepalive_installed: false,
                install_keepalive_works: true,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A simulated crash panics while holding no lock the test still needs, but be tolerant anyway.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ------------------------------------------------------------ setting the scene

    /// The credential this provider "uses". With [`MockProvider::leak_credential_in_errors`] it appears in
    /// every error text this provider produces.
    pub fn with_credential(self, secret: Secret) -> Self {
        self.lock().credential = Some(secret);
        self
    }

    pub fn leak_credential_in_errors(&self) {
        self.lock().leak_credential = true;
    }

    pub fn set_inspection(&self, inspection: Inspection) {
        self.lock().inspection = inspection;
    }

    pub fn set_capacity(&self, capacity: Capacity) {
        self.lock().capacity = capacity;
    }

    pub fn set_bootstrap_output(&self, output: impl Into<String>) {
        self.lock().bootstrap_output = output.into();
    }

    /// Make the keepalive install quietly do nothing (it reports success, and is not there).
    pub fn keepalive_does_not_stick(&self) {
        self.lock().install_keepalive_works = false;
    }

    /// Fail the next call to `method`, once.
    pub fn fail_once(&self, method: &'static str, error: ProviderError) {
        self.lock().fail_once.insert(method, error);
    }

    /// Fail every call to `method`.
    pub fn fail_always(&self, method: &'static str, error: ProviderError) {
        self.lock().fail_always.insert(method, error);
    }

    /// Panic right after a `create_instance` or `open_ports` has taken effect: a crash at the worst moment.
    pub fn crash_after(&self, method: &'static str) {
        self.lock().crash_after.insert(method);
    }

    pub fn fail_finding(&self, error: ProviderError) {
        self.fail_always("find", error);
    }

    /// Put a resource into existence, as though a previous run had made it.
    pub fn seed(&self, kind: ResourceKind, token: &str, provider_id: &str) {
        self.lock().resources.insert(
            (kind, provider_id.to_owned()),
            Resource {
                token: token.to_owned(),
                region: "r1".to_owned(),
            },
        );
    }

    pub fn refuse_deleting(&self, provider_id: &str, error: ProviderError) {
        self.lock()
            .refuse_delete
            .insert(provider_id.to_owned(), error);
    }

    pub fn allow_deleting(&self, provider_id: &str) {
        self.lock().refuse_delete.remove(provider_id);
    }

    // ------------------------------------------------------------ looking at what happened

    /// How many resources exist right now.
    pub fn remaining(&self) -> usize {
        self.lock().resources.len()
    }

    /// The tokens of the resources that exist, sorted.
    pub fn existing_tokens(&self) -> Vec<String> {
        let mut tokens: Vec<String> = self
            .lock()
            .resources
            .values()
            .map(|r| r.token.clone())
            .collect();
        tokens.sort();
        tokens
    }

    /// Every call made, in order, by method name.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn call_count(&self) -> usize {
        self.lock().calls.len()
    }

    /// How many times `method` was called.
    pub fn count_of(&self, method: &str) -> usize {
        self.lock()
            .calls
            .iter()
            .filter(|c| c.as_str() == method)
            .count()
    }

    /// Resources deleted, in order, as `kind:id`.
    pub fn deletions(&self) -> Vec<String> {
        self.lock().deletions.clone()
    }

    pub fn last_bootstrap_script(&self) -> Option<String> {
        self.lock().last_bootstrap_script.clone()
    }

    pub fn last_keepalive_script(&self) -> Option<String> {
        self.lock().last_keepalive_script.clone()
    }

    // ------------------------------------------------------------ internals

    /// Record a call and apply any failure set for it.
    fn enter(&self, method: &'static str) -> Result<MutexGuard<'_, State>, ProviderError> {
        let mut state = self.lock();
        state.calls.push(method.to_owned());
        let failure = state
            .fail_once
            .remove(method)
            .or_else(|| state.fail_always.get(method).cloned());
        match failure {
            Some(error) => Err(state.dress(error)),
            None => Ok(state),
        }
    }
}

impl State {
    /// An error as the provider would word it: with the credential in it, if the test asked for that.
    fn dress(&self, error: ProviderError) -> ProviderError {
        let (Some(secret), true) = (&self.credential, self.leak_credential) else {
            return error;
        };
        let leak = format!(" (request signed with {})", secret.expose_secret());
        match error {
            ProviderError::Unauthorized => ProviderError::Rejected(format!("unauthorized{leak}")),
            ProviderError::QuotaExceeded(t) => ProviderError::QuotaExceeded(format!("{t}{leak}")),
            ProviderError::Transient(t) => ProviderError::Transient(format!("{t}{leak}")),
            ProviderError::Rejected(t) => ProviderError::Rejected(format!("{t}{leak}")),
        }
    }

    fn make(&mut self, kind: ResourceKind, token: &str, region: &str) -> String {
        if let Some(((_, id), _)) = self
            .resources
            .iter()
            .find(|((k, _), r)| *k == kind && r.token == token)
        {
            return id.clone();
        }
        self.next_id += 1;
        let id = format!("{}-{}", kind.as_str(), self.next_id);
        self.resources.insert(
            (kind, id.clone()),
            Resource {
                token: token.to_owned(),
                region: region.to_owned(),
            },
        );
        id
    }
}

impl Provider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    fn required_permissions(&self) -> &[&'static str] {
        REQUIRED
    }

    fn inspect_credential(&self) -> Result<Inspection, ProviderError> {
        Ok(self.enter("inspect_credential")?.inspection.clone())
    }

    fn check_capacity(&self, _region: &str, _shape: &str) -> Result<Capacity, ProviderError> {
        Ok(self.enter("check_capacity")?.capacity.clone())
    }

    fn create_instance(&self, spec: &InstanceSpec) -> Result<InstanceInfo, ProviderError> {
        let mut state = self.enter("create_instance")?;
        let id = state.make(ResourceKind::Instance, &spec.token, &spec.region);
        if state.crash_after.contains("create_instance") {
            drop(state);
            panic!("simulated crash after the instance was created");
        }
        let n = u8::try_from(state.next_id % 200).unwrap_or(1);
        Ok(InstanceInfo {
            provider_id: id,
            public_ip: Ipv4Addr::new(203, 0, 113, 10 + n),
        })
    }

    fn open_ports(
        &self,
        token: &str,
        region: &str,
        _instance: &InstanceInfo,
        _ports: &[PortRule],
    ) -> Result<NetworkInfo, ProviderError> {
        let mut state = self.enter("open_ports")?;
        let id = state.make(ResourceKind::NetworkRule, token, region);
        if state.crash_after.contains("open_ports") {
            drop(state);
            panic!("simulated crash after the rules were created");
        }
        Ok(NetworkInfo { provider_id: id })
    }

    fn bootstrap(&self, _instance: &InstanceInfo, script: &str) -> Result<String, ProviderError> {
        let mut state = self.enter("bootstrap")?;
        state.last_bootstrap_script = Some(script.to_owned());
        // A real server prints the client key it was given. `{CLIENT_PUB}` in the scripted output stands
        // for it, read from the script as the server would.
        let client_pub = script
            .lines()
            .find_map(|l| l.strip_prefix("public_key="))
            .unwrap_or_default();
        // The same for the session: the devices the script was given, as the server's report lists them.
        // (`"{SESSION_DEVICES}"` in the scripted output is replaced by that array.)
        // A new server's list is made from the keys the script hands to `dnet-devices sync`, in order, each at the
        // address its place gives it.
        let devices = script
            .lines()
            .find(|l| l.contains("dnet-devices\" sync "))
            .map(|line| {
                let list = line
                    .split('\'')
                    .skip(1)
                    .step_by(2)
                    .enumerate()
                    .map(|(i, key)| {
                        format!(
                            "{{\"address\": \"{}\", \"public_key\": \"{key}\"}}",
                            dnet_config::session::session_device_address(i)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{list}]")
            })
            .unwrap_or_else(|| "[]".to_owned());
        Ok(state
            .bootstrap_output
            .replace("{CLIENT_PUB}", client_pub)
            .replace("\"{SESSION_DEVICES}\"", &devices))
    }

    fn install_keepalive(
        &self,
        _instance: &InstanceInfo,
        script: &str,
    ) -> Result<(), ProviderError> {
        let mut state = self.enter("install_keepalive")?;
        state.last_keepalive_script = Some(script.to_owned());
        state.keepalive_installed = state.install_keepalive_works;
        Ok(())
    }

    fn keepalive_installed(&self, _instance: &InstanceInfo) -> Result<bool, ProviderError> {
        Ok(self.enter("keepalive_installed")?.keepalive_installed)
    }

    fn find(
        &self,
        kind: ResourceKind,
        token: &str,
        region: &str,
    ) -> Result<Option<String>, ProviderError> {
        let state = self.enter("find")?;
        // A provider searches inside one region, so a resource elsewhere is not found.
        Ok(state
            .resources
            .iter()
            .find(|((k, _), r)| *k == kind && r.token == token && r.region == region)
            .map(|((_, id), _)| id.clone()))
    }

    fn delete(
        &self,
        kind: ResourceKind,
        provider_id: &str,
        _region: &str,
    ) -> Result<DeleteOutcome, ProviderError> {
        let mut state = self.enter("delete")?;
        if let Some(error) = state.refuse_delete.get(provider_id).cloned() {
            return Err(state.dress(error));
        }
        state
            .deletions
            .push(format!("{}:{provider_id}", kind.as_str()));
        Ok(
            match state.resources.remove(&(kind, provider_id.to_owned())) {
                Some(_) => DeleteOutcome::Deleted,
                None => DeleteOutcome::AlreadyGone,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(token: &str) -> InstanceSpec {
        InstanceSpec {
            token: token.to_owned(),
            region: "r1".to_owned(),
            shape: "small".to_owned(),
        }
    }

    #[test]
    fn creating_the_same_token_twice_makes_one_machine() {
        let mock = MockProvider::new();
        let a = mock.create_instance(&spec("t")).unwrap();
        let b = mock.create_instance(&spec("t")).unwrap();
        assert_eq!(a.provider_id, b.provider_id);
        assert_eq!(mock.remaining(), 1);
    }

    #[test]
    fn find_and_delete_see_what_was_created() {
        let mock = MockProvider::new();
        let made = mock.create_instance(&spec("t")).unwrap();
        assert_eq!(
            mock.find(ResourceKind::Instance, "t", "r1")
                .unwrap()
                .as_deref(),
            Some(made.provider_id.as_str())
        );
        assert_eq!(
            mock.delete(ResourceKind::Instance, &made.provider_id, "r1")
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert_eq!(
            mock.delete(ResourceKind::Instance, &made.provider_id, "r1")
                .unwrap(),
            DeleteOutcome::AlreadyGone
        );
    }

    #[test]
    fn a_failure_can_be_set_once_or_always() {
        let mock = MockProvider::new();
        mock.fail_once("check_capacity", ProviderError::Transient("busy".into()));
        assert!(mock.check_capacity("r", "s").is_err());
        assert!(mock.check_capacity("r", "s").is_ok());
        mock.fail_always("check_capacity", ProviderError::Transient("busy".into()));
        assert!(mock.check_capacity("r", "s").is_err());
        assert!(mock.check_capacity("r", "s").is_err());
    }

    #[test]
    fn a_crash_happens_after_the_resource_exists() {
        let mock = MockProvider::new();
        mock.crash_after("create_instance");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = mock.create_instance(&spec("t"));
        }));
        assert!(result.is_err());
        assert_eq!(
            mock.remaining(),
            1,
            "the machine exists although the call never returned"
        );
    }

    #[test]
    fn the_mock_can_leak_the_credential_so_a_test_can_check_it_is_not_passed_on() {
        let mock = MockProvider::new().with_credential(Secret::new("SENTINEL-cred"));
        mock.leak_credential_in_errors();
        mock.fail_once("create_instance", ProviderError::Rejected("no".into()));
        let error = mock.create_instance(&spec("t")).unwrap_err().to_string();
        assert!(error.contains("SENTINEL-cred"));
    }
}
