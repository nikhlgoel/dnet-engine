//! Phase 9a — configuration changes a client asks for: add, remove, enable or disable an endpoint,
//! and the encrypted-DNS choice (IPC-17 to IPC-21).
//!
//! Each change is a transaction over the in-memory store, the sealed credentials and the saved
//! configuration. The order is chosen so that a failure at any step leaves nothing half-done:
//!
//! - **Add:** build and check the endpoint, apply it to the store, encode the new file (which reads
//!   it back), seal the credentials, *then* write the file. A failure after the credentials are
//!   sealed removes them again; a failure before leaves nothing to remove. The file never names
//!   credentials that do not exist.
//! - **Remove:** write the file first, then forget the credentials. A failure to forget costs a
//!   stray sealed blob, never an endpoint without credentials, and is logged.
//! - **Everything else:** encode, write, and on any failure put the store back as it was.
//!
//! The store is restored by replacing it with the copy taken before the change, so a failure cannot
//! leave a change half-applied however many steps the change had.
//!
//! This module never reads or writes a file for itself: the saved configuration and the secret store
//! are handed in, so the tests run against memory and the service against the trusted files.

use std::sync::Arc;

use dnet_config::persist::{ConfigStore, MAX_ENDPOINTS};
use dnet_config::secret_store::{SecretKey, SecretStore};
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::ids::EndpointId;
use dnet_ipc::protocol::{IpcError, NewEndpoint};
use serde_json::json;

use crate::domain::DomainState;

/// The reply to a change that was made. Carries nothing the client sent.
pub const APPLIED: &str = r#"{"applied":true}"#;

/// Why a change was not made. Nothing was changed when one of these is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigureError {
    /// The request asks for something that cannot be: a duplicate label, an unknown endpoint, too
    /// many endpoints. The text never repeats a value the client sent.
    Refused(String),
    /// The change was valid but could not be saved. The store is as it was.
    Storage(String),
}

impl From<ConfigureError> for IpcError {
    fn from(error: ConfigureError) -> Self {
        match error {
            ConfigureError::Refused(detail) => IpcError::InvalidRequest { detail },
            ConfigureError::Storage(detail) => IpcError::InternalError { detail },
        }
    }
}

fn refused(detail: &str) -> ConfigureError {
    ConfigureError::Refused(detail.to_owned())
}

fn storage(error: impl std::fmt::Display) -> ConfigureError {
    ConfigureError::Storage(error.to_string())
}

/// The saved configuration and the sealed credentials, and the changes that touch both.
pub struct Configurator {
    config: ConfigStore,
    secrets: Arc<dyn SecretStore>,
}

impl Configurator {
    pub fn new(config: ConfigStore, secrets: Arc<dyn SecretStore>) -> Self {
        Self { config, secrets }
    }

    /// Add an endpoint. Returns its id.
    pub fn add_endpoint(
        &self,
        state: &mut DomainState,
        new: &NewEndpoint,
    ) -> Result<EndpointId, ConfigureError> {
        if state.endpoints().len() >= MAX_ENDPOINTS {
            return Err(ConfigureError::Refused(format!(
                "there are already {MAX_ENDPOINTS} endpoints, the most that can be kept"
            )));
        }
        // A label already in use is refused by the store itself, which is the one place that rule lives.
        let id = EndpointId::new();
        let key = SecretKey::for_endpoint(id);
        let endpoint = Endpoint::new(
            id,
            new.label(),
            EndpointAddress::new(new.host(), display_port(new))
                .map_err(|_| refused("`host` is not a usable address"))?,
            EndpointOrigin::Manual,
            key.credential_ref(),
        )
        .map_err(|_| refused("`label` is not a usable label"))?;

        let before = state.clone();
        let result = self.apply_add(state, endpoint, &key, new);
        if result.is_err() {
            *state = before;
        }
        result.map(|()| id)
    }

    fn apply_add(
        &self,
        state: &mut DomainState,
        endpoint: Endpoint,
        key: &SecretKey,
        new: &NewEndpoint,
    ) -> Result<(), ConfigureError> {
        state
            .add_endpoint(endpoint)
            .map_err(|_| refused("an endpoint with that label already exists"))?;
        let bytes = state.to_config_bytes().map_err(storage)?;
        self.secrets.put(key, new.credentials()).map_err(storage)?;
        if let Err(e) = self.config.save_bytes(&bytes) {
            // The credentials have no endpoint to belong to. Best effort: a stray blob is clutter,
            // and no later add can collide with it (keys are fresh ids).
            if let Err(cleanup) = self.secrets.delete(key) {
                tracing::warn!(
                    "a sealed credential set was left behind after a failed save: {cleanup}"
                );
            }
            return Err(storage(e));
        }
        Ok(())
    }

    /// Remove an endpoint and forget its credentials.
    ///
    /// An endpoint that holds cloud resources is refused: removing it here would orphan them, and the
    /// request carries no way to say they should be cleaned up too (SC-011). That arrives with
    /// provisioning.
    pub fn remove_endpoint(
        &self,
        state: &mut DomainState,
        id: EndpointId,
    ) -> Result<(), ConfigureError> {
        let Some(endpoint) = state.endpoint(id) else {
            return Err(refused("there is no endpoint with that id"));
        };
        if endpoint.has_cloud_resources() {
            return Err(refused(
                "this endpoint holds cloud resources; removing it here would leave them running \
                 and billed. Remove it through the provisioning flow, which cleans them up",
            ));
        }
        let key = SecretKey::parse(endpoint.credentials()).map_err(storage)?;

        self.transact(state, |s| {
            s.remove_endpoint(id);
        })?;
        // The file no longer names the credentials; forgetting them is housekeeping.
        if let Err(e) = self.secrets.delete(&key) {
            tracing::warn!(
                "an endpoint was removed but its sealed credentials could not be deleted: {e}"
            );
        }
        Ok(())
    }

    /// Enable or disable an endpoint.
    pub fn set_endpoint_enabled(
        &self,
        state: &mut DomainState,
        id: EndpointId,
        enabled: bool,
    ) -> Result<(), ConfigureError> {
        if state.endpoint(id).is_none() {
            return Err(refused("there is no endpoint with that id"));
        }
        self.transact(state, |s| {
            s.set_endpoint_enabled(id, enabled);
        })
    }

    /// Block encrypted DNS (`true`, the default) or opt out (`false`). Returns the consequence the
    /// interface must show when opting out.
    pub fn set_encrypted_dns(
        &self,
        state: &mut DomainState,
        block: bool,
    ) -> Result<Option<&'static str>, ConfigureError> {
        let before = state.clone();
        let outcome = if block {
            state.choose_encrypted_dns_block().map(|()| None)
        } else {
            state
                .opt_out_of_encrypted_dns_block()
                .map(|o| Some(o.consequence))
        };
        let consequence = match outcome {
            Ok(consequence) => consequence,
            Err(e) => {
                *state = before;
                return Err(storage(e));
            }
        };
        if let Err(e) = self.save(state) {
            *state = before;
            return Err(e);
        }
        Ok(consequence)
    }

    /// Apply `change`, save, and put the store back if saving fails.
    fn transact(
        &self,
        state: &mut DomainState,
        change: impl FnOnce(&mut DomainState),
    ) -> Result<(), ConfigureError> {
        let before = state.clone();
        change(state);
        let saved = self.save(state);
        if saved.is_err() {
            *state = before;
        }
        saved
    }

    fn save(&self, state: &DomainState) -> Result<(), ConfigureError> {
        let bytes = state.to_config_bytes().map_err(storage)?;
        self.config.save_bytes(&bytes).map_err(storage)
    }
}

/// The reply to an add: the new endpoint's id, which is the only thing the client does not know.
pub fn added_reply(id: EndpointId) -> String {
    json!({ "endpoint": id.to_string() }).to_string()
}

/// The reply to the encrypted-DNS choice: what is now in force, and when opting out, the consequence
/// the person must be shown.
pub fn dns_reply(block: bool, consequence: Option<&str>) -> String {
    match consequence {
        Some(text) => json!({ "block": block, "consequence": text }).to_string(),
        None => json!({ "block": block }).to_string(),
    }
}

/// The port shown beside an endpoint in a listing. It is not used to connect: each profile has its
/// own in the credentials. It is the first profile's that the bundle has, so the listing says
/// something real.
fn display_port(new: &NewEndpoint) -> u16 {
    let c = new.credentials();
    c.amneziawg
        .as_ref()
        .map(|a| a.server_port)
        .or_else(|| c.hysteria2.as_ref().map(|h| h.server_port))
        .or_else(|| c.reality.as_ref().map(|r| r.server_port))
        // `NewEndpoint` refuses an empty bundle, so one of the above exists; a zero here would be
        // refused by `EndpointAddress`, not used.
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests;
