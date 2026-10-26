//! `DnetService` — the daemon's implementation of the IPC `Service` seam.
//!
//! Bridges authorized IPC requests to the in-memory domain store. Reached only after
//! `dnet-ipc` has authorized the request against the captured client identity, so this
//! never re-checks identity — but it also performs no privileged action beyond what the
//! request's class permits.
//!
//! The read-only queries are served from the domain store. With a connection orchestrator
//! attached (T126), `Connect`, `Disconnect` and `GetState` are served by it; without one they
//! answer honestly that connecting is not available.
//!
//! Endpoint changes and the encrypted-DNS choice (Phase 9a) go through a [`Configurator`]: saved first,
//! then applied to the store, then the orchestrator is rebuilt from the new store so the next connect
//! sees them. They are accepted only while nothing is connected or being connected, because the
//! engine and the effects it drives were built from the endpoints and rules of the moment; replacing
//! them under a live tunnel would leave the tunnel running on a configuration nobody can see. The
//! remaining configuration requests (rules, profile settings, Brutal, provisioning) are recognized
//! but still answer that they are not available. The privilege boundary and the read path are real.

use std::sync::{Arc, Mutex, PoisonError};

use dnet_core::feed::fetch::FetchRoute;
use dnet_core::posture::RoutingPosture;
use dnet_core::session::{CheckFailure, ConnectionEvent, DefinitionsChange};
use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::protocol::{encode_state_snapshot, FeedImport, IpcError, Request, RequestClass};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{EventBus, Subscription};

use crate::configure::{added_reply, dns_reply, Configurator, APPLIED};
use crate::domain::DomainState;
use crate::feed_fetch::{Busy, Fetcher, Pace, Transport};
use crate::feed_service::{FeedNote, FeedRefusal, FeedService, SharedDefinitions};
use crate::orchestrator::Handle;
use crate::recovery::{Recovered, RecoveryError};

/// The reply to a request the orchestrator took on. Progress follows on the event stream.
const ACCEPTED: &str = r#"{"accepted":true}"#;

/// How the service learns who the interactive console user is.
///
/// Boxed so tests can inject a fixed answer instead of querying the OS.
pub type ConsoleResolver = Box<dyn Fn() -> Option<ConsoleSession> + Send + Sync>;

/// Builds a new orchestrator from the store as it now is, for the service to swap in once a
/// configuration change has been saved. Must be called with a Tokio runtime current.
pub type Rebuild = Box<dyn Fn(&DomainState) -> Handle + Send + Sync>;

/// The daemon's `Service`: a domain store plus a way to resolve the console user.
pub struct DnetService {
    state: Mutex<DomainState>,
    console: ConsoleResolver,
    /// The start-up restoration result (T038). Only `Ok` carries the undo registry that
    /// routing mutations need; on `Err` every mutating request is refused.
    recovery: Result<Recovered, RecoveryError>,
    /// Where connection events are published (T126) and subscribers read them.
    events: EventBus,
    /// Why the saved configuration was refused at start-up (T124), if it was. While set, every
    /// mutating request is refused, exactly as after a failed recovery: the service keeps answering
    /// read-only queries so the user can see why, and it never saves over a file it could not read.
    config_refusal: Option<String>,
    /// The connection orchestrator (T126), once one is attached. Without it, connecting is not
    /// available and `GetState` reports the idle state. Replaced, while idle, when a configuration
    /// change is saved (see `rebuild`).
    orchestrator: Arc<Mutex<Option<Handle>>>,
    /// How to make the orchestrator again from the changed store. Without it a change is saved and
    /// applied to the store but a running orchestrator keeps what it was built from (tests only).
    rebuild: Option<Rebuild>,
    /// Saves configuration changes. Without it they answer that they are not available.
    configurator: Option<Configurator>,
    /// What the applied profile feed says about the client-only parameters. Shared with the code that
    /// generates configurations; the bundled defaults until a feed is accepted.
    definitions: SharedDefinitions,
    /// The signed profile feed (T066a). Absent when the build carries no trust anchor, in which case
    /// an import answers that it is not available.
    feed: Option<Arc<Mutex<FeedService>>>,
    /// Asks for a check for updated definitions now (`FetchFeed`). Present once a fetcher is attached.
    check_requester: Option<CheckRequester>,
}

/// Starts a requested check and says which network it will use, or that one is under way.
type CheckRequester = Box<dyn Fn() -> Result<FetchRoute, Busy> + Send + Sync>;

/// Tell subscribers what a feed operation changed, and, for a check the person asked for that came to
/// nothing, why. Also logged, since nobody may be subscribed.
fn announce(events: &EventBus, notes: &[FeedNote], failure: Option<CheckFailure>) {
    let changes = notes
        .iter()
        .map(|note| match note {
            FeedNote::Updated {
                sequence,
                endpoint_updates,
            } => DefinitionsChange::Updated {
                sequence: *sequence,
                endpoint_updates: u32::try_from(*endpoint_updates).unwrap_or(u32::MAX),
            },
            FeedNote::Evicted => DefinitionsChange::Evicted,
            FeedNote::OutOfDate => DefinitionsChange::OutOfDate,
            FeedNote::Discarded { .. } => DefinitionsChange::Discarded,
        })
        .chain(failure.map(|reason| DefinitionsChange::CheckFailed { reason }));
    for change in changes {
        tracing::info!(?change, "the connection method definitions changed");
        if let Err(error) = events.publish(&ConnectionEvent::DefinitionsChanged { change }) {
            tracing::warn!(%error, "a definitions change could not be announced");
        }
    }
}

/// Milliseconds since the Unix epoch, for stamping a reading. A clock set before 1970 reads as zero,
/// which a client sees as "too old to be current" rather than as a time.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl DnetService {
    /// Build a service over `state`, resolving the console user with `console`, gated by
    /// the outcome of start-up recovery.
    pub fn new(
        state: DomainState,
        console: ConsoleResolver,
        recovery: Result<Recovered, RecoveryError>,
    ) -> Self {
        Self {
            state: Mutex::new(state),
            console,
            recovery,
            events: EventBus::new(),
            config_refusal: None,
            orchestrator: Arc::new(Mutex::new(None)),
            rebuild: None,
            configurator: None,
            definitions: SharedDefinitions::default(),
            feed: None,
            check_requester: None,
        }
    }

    /// Attach the connection orchestrator. It must publish to [`DnetService::events`], so that a
    /// subscriber sees what it does.
    pub fn with_orchestrator(self, handle: Handle) -> Self {
        *self
            .orchestrator
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(handle);
        self
    }

    /// Let configuration changes be saved by `configurator`.
    pub fn with_configurator(mut self, configurator: Configurator) -> Self {
        self.configurator = Some(configurator);
        self
    }

    /// Let a saved change replace the orchestrator with one built from the changed store.
    #[cfg_attr(not(windows), allow(dead_code))] // Windows builds it; the tests supply their own.
    pub fn with_rebuild(mut self, rebuild: Rebuild) -> Self {
        self.rebuild = Some(rebuild);
        self
    }

    /// The definitions the connection code reads, for whoever builds the feed service to share.
    pub fn definitions(&self) -> SharedDefinitions {
        std::sync::Arc::clone(&self.definitions)
    }

    /// Hold the signed profile feed. `notes` are what starting it found (a stored document that no
    /// longer verified); they are published like any other change.
    pub fn with_feed(mut self, feed: FeedService, notes: &[FeedNote]) -> Self {
        self.feed = Some(Arc::new(Mutex::new(feed)));
        self.publish_feed_notes(notes);
        self
    }

    /// Tell subscribers what a feed operation changed. Also logged, since nobody may be subscribed.
    fn publish_feed_notes(&self, notes: &[FeedNote]) {
        announce(&self.events, notes, None);
    }

    /// Let the person ask for an update (`FetchFeed`), and check on a schedule while a tunnel is up
    /// (T066b). Needs the feed machinery (a build without a trust anchor has nothing to fetch for) and
    /// a Tokio runtime current. `pace` is `None` to ask only when told to.
    pub fn attach_fetcher<T: Transport>(mut self, transport: Arc<T>, pace: Option<Pace>) -> Self {
        let Some(feed) = &self.feed else {
            return self;
        };
        let (slot, events) = (Arc::clone(&self.orchestrator), self.events.clone());
        let fetcher = Fetcher::new(
            transport,
            Arc::clone(feed),
            // The orchestrator in use now: a configuration change replaces it. With none attached
            // nothing is tunnelled.
            Arc::new(move || {
                slot.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                    .map_or(RoutingPosture::FailClosed, |o| o.snapshot().posture)
            }),
            Arc::new(move |notes, failure| announce(&events, notes, failure)),
            Arc::new(|| unix_millis() / 1000),
        );
        if let Some(pace) = pace {
            fetcher.spawn_schedule(pace);
        }
        self.check_requester = Some(Box::new(move || fetcher.request()));
        self
    }

    /// Report an expired feed, once. Looked at when a client asks for the state, because nothing
    /// else would notice: the feed needs no timer of its own to keep working.
    fn check_feed_staleness(&self) {
        let Some(feed) = &self.feed else { return };
        let note = feed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check_staleness(unix_millis() / 1000);
        if let Some(note) = note {
            self.publish_feed_notes(&[note]);
        }
    }

    /// The orchestrator, for whoever must shut it down when the service stops.
    pub fn orchestrator_handle(&self) -> Option<Handle> {
        self.orchestrator()
    }

    fn orchestrator(&self) -> Option<Handle> {
        self.orchestrator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Swap the orchestrator for one built from `state`, now that a change has been saved.
    ///
    /// Called only while idle (`before_change`), with the store lock held, so no connect can slip in
    /// between the old orchestrator stopping and the new one starting. The old one is told to stop
    /// without waiting: idle, it has nothing to undo.
    fn reload(&self, state: &DomainState) {
        let Some(rebuild) = &self.rebuild else {
            return;
        };
        let mut slot = self
            .orchestrator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = slot.take() {
            old.retire();
            *slot = Some(rebuild(state));
        }
    }

    /// What must hold before a configuration change: something to save it with, and nothing connected
    /// or being connected.
    fn before_change(&self) -> Result<&Configurator, IpcError> {
        let Some(configurator) = &self.configurator else {
            return Err(Self::not_available("this configuration change").unwrap_err());
        };
        if self.orchestrator().is_some_and(|o| !o.is_idle()) {
            return Err(IpcError::InvalidRequest {
                detail: "disconnect before changing endpoints or encrypted-DNS handling; the                          change would not reach a connection that is already up"
                    .to_string(),
            });
        }
        Ok(configurator)
    }

    /// Attach the orchestrator with the real effects (T126), if the service is in a state to
    /// connect: start-up recovery succeeded, and the saved configuration was accepted. Otherwise
    /// the service is returned as it is, and every connect answers that connecting is unavailable,
    /// for the reason already logged. Must be called with a Tokio runtime current.
    #[cfg(windows)]
    pub fn with_production_orchestrator(self) -> Self {
        use std::sync::Arc;

        use dnet_config::persist::default_secrets_dir;
        use dnet_config::secret_store::{machine_secret_store, SecretStore};
        use dnet_core::engine::Engine;

        use crate::effects::{Dependencies, Layout, RealEffects};
        use crate::orchestrator::{self, Timing};

        let undo = match &self.recovery {
            Ok(recovered) => Arc::clone(recovered.undo()),
            Err(_) => return self,
        };
        if self.config_refusal.is_some() {
            return self;
        }
        let layout = match Layout::installed() {
            Ok(layout) => layout,
            Err(error) => {
                tracing::error!(kind = ?error.kind(), "the service cannot find its own files; connecting is unavailable");
                return self;
            }
        };
        let secrets: Arc<dyn SecretStore> = Arc::new(machine_secret_store(default_secrets_dir()));
        let timing = Timing {
            // A refused connection takes Windows about two seconds to report.
            reach_timeout: std::time::Duration::from_secs(4),
            ..Timing::default()
        };
        let bus = self.events.clone();
        let definitions = Arc::clone(&self.definitions);
        // Used now, and again whenever a saved change replaces the orchestrator.
        let build = move |state: &DomainState| -> Handle {
            let (effects, profiles, usable) = RealEffects::new(
                state.profiles().to_vec(),
                state.endpoints(),
                state.rules().to_vec(),
                Dependencies {
                    secrets: Arc::clone(&secrets),
                    undo: Arc::clone(&undo),
                    layout: layout.clone(),
                    definitions: Arc::clone(&definitions),
                },
            );
            // Only endpoints that can be used, and profiles they can serve, are known to the engine,
            // so it never chooses one that would fail after a race.
            let engine = Engine::new(profiles, usable);
            orchestrator::spawn(engine, Arc::new(effects), bus.clone(), timing)
        };
        let handle = {
            let state = self.state.lock().expect("domain state mutex poisoned");
            build(&state)
        };
        self.with_orchestrator(handle).with_rebuild(Box::new(build))
    }

    /// Mark the saved configuration as refused for `reason`. See the field.
    pub fn with_config_refusal(mut self, reason: Option<String>) -> Self {
        self.config_refusal = reason;
        self
    }

    /// The bus the connection orchestrator publishes to.
    #[allow(dead_code)] // The tests read it; the production service passes its own clone.
    pub fn events(&self) -> &EventBus {
        &self.events
    }

    /// The production service: the saved configuration (or the seeded defaults on a first run) and
    /// the real OS console lookup.
    #[cfg(windows)]
    pub fn production(recovery: Result<Recovered, RecoveryError>) -> Self {
        use std::sync::Arc;

        use crate::domain::StartupConfig;
        use dnet_config::persist::{
            default_config_path, default_secrets_dir, ConfigStore, TrustedStateFile,
        };
        use dnet_config::secret_store::machine_secret_store;

        let store = ConfigStore::new(Box::new(TrustedStateFile::new(default_config_path())));
        let StartupConfig {
            state,
            refusal,
            notes,
        } = DomainState::from_load_result(store.load());
        for note in &notes {
            tracing::warn!("{note}");
        }
        if let Some(reason) = &refusal {
            tracing::error!(
                "{reason}; mutating requests are refused until it is corrected or removed ({})",
                default_config_path().display()
            );
        }
        let configurator = Configurator::new(
            ConfigStore::new(Box::new(TrustedStateFile::new(default_config_path()))),
            Arc::new(machine_secret_store(default_secrets_dir())),
        );
        let service = Self::new(
            state,
            Box::new(crate::console::active_console_session),
            recovery,
        )
        .with_config_refusal(refusal)
        .with_configurator(configurator);

        // The signed profile feed, if this build carries a trust anchor (T066d). Its documents sit
        // beside the configuration, under the same owner and DACL check.
        match crate::feed_trust::anchor() {
            Some(trust) => {
                let beside = default_config_path();
                let (feed, notes) = FeedService::start(
                    trust,
                    Box::new(TrustedStateFile::new(
                        beside.with_file_name("feed-keys.dsse.json"),
                    )),
                    Box::new(TrustedStateFile::new(
                        beside.with_file_name("profile-feed.v1.dsse.json"),
                    )),
                    service.definitions(),
                );
                let service = service.with_feed(feed, &notes);
                // Fetching: on a schedule while a tunnel is up, and when the person asks.
                match crate::feed_fetch::HttpTransport::new() {
                    Ok(transport) => service.attach_fetcher(
                        Arc::new(transport),
                        Some(crate::feed_fetch::Pace::default()),
                    ),
                    Err(_) => {
                        tracing::error!("the HTTP client for profile updates could not be built; updates cannot be fetched");
                        service
                    }
                }
            }
            None => {
                tracing::info!("this build has no profile-feed trust anchor; connection method definitions are the built-in ones");
                service
            }
        }
    }

    fn not_available(what: &str) -> Result<String, IpcError> {
        Err(IpcError::InternalError {
            detail: format!("{what} is not available in this build yet"),
        })
    }

    /// Take the documents of an offline import, keys first, and say what changed.
    fn import_feed(&self, import: &FeedImport) -> Result<String, IpcError> {
        let Some(feed) = &self.feed else {
            return Self::not_available("importing a profile update");
        };
        let mut feed = feed.lock().unwrap_or_else(PoisonError::into_inner);
        let now = unix_millis() / 1000;
        let mut notes = Vec::new();
        let refused = |what: &str, taken: bool, refusal: FeedRefusal| {
            let prefix = if taken {
                "the keys document was taken, but "
            } else {
                ""
            };
            let detail = format!("{prefix}{what} was refused: {refusal}");
            match refusal {
                FeedRefusal::Storage(_) => IpcError::InternalError { detail },
                _ => IpcError::InvalidRequest { detail },
            }
        };
        if let Some(keys) = import.keys() {
            let taken = feed
                .offer_keys(keys.as_bytes(), now)
                .map_err(|e| refused("the keys document", false, e))?;
            notes.extend(taken);
        }
        if let Some(document) = import.feed() {
            // Step 8 of the acceptance rules: a trial configuration for every profile.
            let taken = feed
                .offer_feed(document.as_bytes(), now, &crate::feed_trial::trial_generate)
                .map_err(|e| {
                    // Publish what the keys did before reporting that the feed did not follow.
                    self.publish_feed_notes(&notes);
                    refused("the feed", import.keys().is_some(), e)
                })?;
            notes.extend(taken);
        }
        drop(feed);
        self.publish_feed_notes(&notes);
        let changes: Vec<&str> = notes
            .iter()
            .map(|note| match note {
                FeedNote::Updated { .. } => "Updated",
                FeedNote::Evicted => "Evicted",
                FeedNote::OutOfDate => "OutOfDate",
                FeedNote::Discarded { .. } => "Discarded",
            })
            .collect();
        Ok(serde_json::json!({ "imported": true, "changes": changes }).to_string())
    }
}

impl Service for DnetService {
    fn console_session(&self) -> Option<ConsoleSession> {
        (self.console)()
    }

    fn dispatch(&self, request: &Request) -> Result<String, IpcError> {
        // Strict gate (T038): nothing may change while a previous run's network changes
        // are still unrestored. Read-only queries still answer, so the user can see why.
        if request.class() == RequestClass::Mutating {
            if let Err(e) = &self.recovery {
                return Err(IpcError::InternalError {
                    detail: e.to_string(),
                });
            }
            if let Some(reason) = &self.config_refusal {
                return Err(IpcError::InternalError {
                    detail: format!(
                        "{reason}. DNet Engine will not connect or change anything until the \
                         file is corrected or removed, then the service restarted"
                    ),
                });
            }
        }
        let mut state = self.state.lock().expect("domain state mutex poisoned");
        let orchestrator = self.orchestrator();
        match request {
            // The dispatch in `dnet-ipc` answers this before the service is asked (T132); the same
            // answer here keeps the match complete and any other caller of `dispatch` honest.
            Request::GetVersion => Ok(dnet_ipc::version::reply()),
            // Fully served now.
            Request::GetState => {
                self.check_feed_staleness();
                match &orchestrator {
                    Some(orchestrator) => encode_state_snapshot(&orchestrator.snapshot()),
                    None => Ok(state.state_snapshot_json()),
                }
            }
            Request::GetSession => Ok(state.session_json()),
            Request::GetPaths => {
                // `watching` is whether anything is being looked at: nothing is, until a tunnel is up
                // and its networks are watched. The empty list then says "not looking".
                let watched = orchestrator.as_ref().and_then(|o| o.paths());
                Ok(dnet_ipc::netview::encode_paths(
                    &watched.clone().unwrap_or_default(),
                    watched.is_some(),
                    unix_millis(),
                ))
            }
            Request::GetStats => Ok(dnet_ipc::netview::encode_stats(
                orchestrator.as_ref().and_then(|o| o.stats()),
            )),
            Request::ListEndpoints => Ok(state.endpoints_json()),
            Request::ListProfiles => Ok(state.profiles_json()),
            Request::ListRules => Ok(state.rules_json()),
            Request::GetDiagnostics => {
                // T112: built from typed facts, with nothing that names a destination, an address, a
                // network or a credential (see `diagnostics`). The opt-in extras are not reachable from
                // here: a request carries no options yet, so a bundle is always the default one.
                let snapshot = match &orchestrator {
                    Some(orchestrator) => orchestrator.snapshot(),
                    None => state.idle_snapshot(),
                };
                let paths = orchestrator.as_ref().and_then(|o| o.paths());
                let stats = orchestrator.as_ref().and_then(|o| o.stats());
                Ok(crate::diagnostics::render(
                    &crate::diagnostics::Facts {
                        generated_unix_ms: unix_millis(),
                        state: &snapshot,
                        profiles: state.profiles(),
                        endpoints: state.endpoints(),
                        rules: state.rules(),
                        encrypted_dns: state.consent().policy(),
                        paths: paths.as_ref(),
                        stats: stats.as_ref(),
                        recovery_ok: self.recovery.is_ok(),
                        config_refused: self.config_refusal.is_some(),
                        connecting_available: orchestrator.is_some(),
                    },
                    crate::diagnostics::Options::default(),
                ))
            }

            Request::Connect {
                profile, endpoint, ..
            } => match &orchestrator {
                // `acknowledge_tier2` is not consulted: a connect races only the profiles it names
                // or all of them and prefers Tier 1, so the consent case the flag answers cannot
                // arise here (engine.rs). Tier 2 is warned about in the state, not refused.
                Some(orchestrator) => {
                    if endpoint.is_some() {
                        return Err(IpcError::InvalidRequest {
                            detail: "choosing a particular endpoint is not supported yet; connect \
                                     without one and the best endpoint is used"
                                .to_string(),
                        });
                    }
                    orchestrator.connect(profile.clone())?;
                    Ok(ACCEPTED.to_string())
                }
                None => Self::not_available("connecting"),
            },
            Request::Disconnect => match &orchestrator {
                Some(orchestrator) => {
                    orchestrator.disconnect()?;
                    Ok(ACCEPTED.to_string())
                }
                None => Self::not_available("disconnecting"),
            },

            // Configuration changes (Phase 9a). Each is refused while a connection is up or being
            // made, saved before it is applied, and followed by a rebuilt orchestrator.
            Request::AddEndpoint(new) => {
                let configurator = self.before_change()?;
                let id = configurator.add_endpoint(&mut state, new)?;
                self.reload(&state);
                Ok(added_reply(id))
            }
            Request::RemoveEndpoint { endpoint } => {
                let configurator = self.before_change()?;
                configurator.remove_endpoint(&mut state, *endpoint)?;
                self.reload(&state);
                Ok(APPLIED.to_string())
            }
            Request::SetEndpointEnabled { endpoint, enabled } => {
                let configurator = self.before_change()?;
                configurator.set_endpoint_enabled(&mut state, *endpoint, *enabled)?;
                self.reload(&state);
                Ok(APPLIED.to_string())
            }
            Request::SetEncryptedDnsHandling { block } => {
                let configurator = self.before_change()?;
                let consequence = configurator.set_encrypted_dns(&mut state, *block)?;
                self.reload(&state);
                Ok(dns_reply(*block, consequence))
            }

            Request::ImportFeed(import) => self.import_feed(import),
            Request::FetchFeed => match &self.check_requester {
                None => Self::not_available("checking for updated definitions"),
                Some(request) => match request() {
                    Ok(route) => Ok(serde_json::json!({
                        "started": true,
                        // Through the tunnel while one carries traffic; directly only because the
                        // person asked while disconnected (D2).
                        "route": match route {
                            FetchRoute::ThroughTunnel => "tunnel",
                            FetchRoute::PhysicalNetwork => "physical",
                            FetchRoute::NotAllowed => "none",
                        },
                    })
                    .to_string()),
                    Err(Busy) => Err(IpcError::ServiceBusy),
                },
            },

            // Recognized, authorized, but not yet actionable.
            Request::AddRule
            | Request::RemoveRule
            | Request::SetProfileParams
            | Request::EnableBrutal
            | Request::StartProvisioning
            | Request::CancelProvisioning => Self::not_available("this configuration change"),

            // Streaming is handled by the connection loop (`Service::subscribe`), not one-shot dispatch.
            Request::Subscribe => Err(IpcError::InvalidRequest {
                detail: "Subscribe is a streaming request, not a one-shot dispatch".to_string(),
            }),
        }
    }

    fn subscribe(&self) -> Result<Subscription, IpcError> {
        self.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnet_config::persist::{ConfigStore, MemoryStateFile};
    use dnet_config::secret_store::MemorySecretStore;
    use dnet_core::ids::EndpointId;

    use super::*;
    use crate::configure::tests::new_endpoint;
    use serde_json::Value;

    /// A service with a fixed (test) console identity, so `dispatch` can be exercised
    /// without the OS console lookup.
    fn service() -> DnetService {
        DnetService::new(
            DomainState::seeded(),
            Box::new(|| {
                Some(ConsoleSession {
                    session_id: 1,
                    user_sid: "S-1-5-21-test".to_string(),
                })
            }),
            Ok(Recovered::clean_for_tests()),
        )
    }

    #[test]
    fn read_only_queries_are_served_from_the_store() {
        let svc = service();

        let state: Value =
            serde_json::from_str(&svc.dispatch(&Request::GetState).unwrap()).unwrap();
        assert_eq!(state["status"], "Disconnected");

        let profiles: Value =
            serde_json::from_str(&svc.dispatch(&Request::ListProfiles).unwrap()).unwrap();
        assert_eq!(profiles["profiles"].as_array().unwrap().len(), 3);

        let rules: Value =
            serde_json::from_str(&svc.dispatch(&Request::ListRules).unwrap()).unwrap();
        assert!(!rules["rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn with_nothing_connected_the_networks_are_not_watched_and_nothing_is_counted() {
        let svc = service();

        let paths = dnet_ipc::netview::decode_paths(&svc.dispatch(&Request::GetPaths).unwrap())
            .expect("the daemon only serves what a client can read");
        assert!(
            !paths.watching,
            "an empty list here means not looking, not no networks"
        );
        assert!(paths.paths.is_empty());
        assert_eq!(paths.degraded, None);
        assert!(
            paths.as_of_unix_ms > 1_600_000_000_000,
            "stamped with the time"
        );

        assert_eq!(
            dnet_ipc::netview::decode_stats(&svc.dispatch(&Request::GetStats).unwrap()).unwrap(),
            dnet_ipc::netview::StatsReply::NotConnected
        );
    }

    #[test]
    fn connect_reports_it_is_not_available_yet_with_an_actionable_detail() {
        let svc = service();
        match svc.dispatch(&Request::Connect {
            acknowledge_tier2: false,
            profile: None,
            endpoint: None,
        }) {
            Err(IpcError::InternalError { detail }) => {
                assert!(!detail.trim().is_empty());
                assert!(detail.contains("not available"), "{detail}");
            }
            other => panic!("expected a not-available InternalError, got {other:?}"),
        }
    }

    #[test]
    fn config_mutations_report_not_available_rather_than_pretending() {
        let svc = service();
        // Not built yet.
        assert!(matches!(
            svc.dispatch(&Request::AddRule),
            Err(IpcError::InternalError { .. })
        ));
        // Built, but this service has nothing to save them with.
        for request in [
            Request::AddEndpoint(Box::new(new_endpoint("x"))),
            Request::RemoveEndpoint {
                endpoint: EndpointId::new(),
            },
            Request::SetEndpointEnabled {
                endpoint: EndpointId::new(),
                enabled: false,
            },
            Request::SetEncryptedDnsHandling { block: false },
        ] {
            match svc.dispatch(&request) {
                Err(IpcError::InternalError { detail }) => {
                    assert!(detail.contains("not available"), "{request:?}: {detail}")
                }
                other => panic!("{request:?}: {other:?}"),
            }
        }
    }

    // ---------------------------------------------------------------- the profile feed (T066a)

    /// The service with a feed service over memory, and its trust anchor's test keys.
    fn feeding_service() -> DnetService {
        use crate::feed_service::tests::trust;
        let service = service();
        let (feed, notes) = FeedService::start(
            trust(),
            Box::new(MemoryStateFile::default()),
            Box::new(MemoryStateFile::default()),
            service.definitions(),
        );
        service.with_feed(feed, &notes)
    }

    fn real_now() -> u64 {
        unix_millis() / 1000
    }

    fn import(keys: Option<Vec<u8>>, feed: Option<Vec<u8>>) -> Request {
        let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();
        Request::ImportFeed(FeedImport::new(keys.map(text), feed.map(text)).unwrap())
    }

    fn good_keys() -> Vec<u8> {
        use crate::feed_service::tests::{keys_envelope_at, signer};
        keys_envelope_at(real_now(), 1, &[&signer(1)])
    }

    fn good_feed(sequence: u64) -> Vec<u8> {
        use crate::feed_service::tests::{feed_envelope, feed_value_at, signer};
        feed_envelope(&feed_value_at(real_now(), 1, sequence), &signer(1))
    }

    /// A transport for a place where nothing is published.
    struct NothingPublished;

    impl Transport for NothingPublished {
        async fn get(
            &self,
            _url: &str,
        ) -> Result<crate::feed_fetch::Reply, crate::feed_fetch::TransportError> {
            Ok(crate::feed_fetch::Reply::Status(404))
        }
    }

    #[test]
    fn without_a_fetcher_checking_says_it_is_not_available() {
        for svc in [service(), feeding_service()] {
            match svc.dispatch(&Request::FetchFeed) {
                Err(IpcError::InternalError { detail }) => {
                    assert!(detail.contains("not available"), "{detail}")
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_fetcher_is_not_attached_where_there_is_no_feed_to_fetch_for() {
        let svc = service().attach_fetcher(Arc::new(NothingPublished), None);
        assert!(svc.check_requester.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn asking_for_updates_starts_a_check_and_the_outcome_arrives_as_an_event() {
        let svc = feeding_service().attach_fetcher(Arc::new(NothingPublished), None);
        let mut subscription = svc.subscribe().unwrap();

        let reply = json_of(svc.dispatch(&Request::FetchFeed));

        // Nothing is connected, so a check the person asked for goes directly (D2).
        assert_eq!(reply["started"], true);
        assert_eq!(reply["route"], "physical");
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let frame = subscription
            .live
            .try_recv()
            .expect("the outcome is announced");
        let event = dnet_ipc::wire::decode_event_view(&frame).unwrap();
        assert_eq!(event.event, "DefinitionsChanged");
        assert_eq!(event.value["change"], "CheckFailed");
        assert_eq!(event.value["reason"], "Unreachable");
    }

    #[test]
    fn without_a_trust_anchor_an_import_says_it_is_not_available() {
        let svc = service();
        match svc.dispatch(&import(Some(good_keys()), None)) {
            Err(IpcError::InternalError { detail }) => {
                assert!(detail.contains("not available"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_imported_feed_is_applied_announced_and_reported() {
        let svc = feeding_service();
        let mut subscription = svc.subscribe().unwrap();

        let reply = json_of(svc.dispatch(&import(Some(good_keys()), Some(good_feed(7)))));

        assert_eq!(reply["imported"], true);
        assert_eq!(reply["changes"], serde_json::json!(["Updated"]));
        let in_effect = *svc.definitions().lock().unwrap();
        assert_eq!(in_effect.sequence, Some(7));
        let frame = subscription
            .live
            .try_recv()
            .expect("announced to subscribers");
        let event = dnet_ipc::wire::decode_event_view(&frame).unwrap();
        assert_eq!(event.event, "DefinitionsChanged");
        assert_eq!(event.value["change"], "Updated");
        assert_eq!(event.value["sequence"], "7");
        assert!(event.because.contains("sequence 7"), "{}", event.because);
    }

    #[test]
    fn the_same_import_again_changes_nothing_and_says_so() {
        let svc = feeding_service();
        // Made once: documents made twice a second apart would differ, and a different document at
        // the same version is (rightly) refused as equivocation.
        let (keys, feed) = (good_keys(), good_feed(7));
        svc.dispatch(&import(Some(keys.clone()), Some(feed.clone())))
            .unwrap();
        let again = json_of(svc.dispatch(&import(Some(keys), Some(feed))));
        assert_eq!(again["changes"], serde_json::json!([]));
    }

    #[test]
    fn a_feed_signed_by_the_wrong_key_is_refused_without_repeating_it() {
        use crate::feed_service::tests::{feed_envelope, feed_value_at, signer};
        let svc = feeding_service();
        let hostile = feed_envelope(&feed_value_at(real_now(), 1, 1), &signer(2));
        match svc.dispatch(&import(Some(good_keys()), Some(hostile))) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(
                    detail.starts_with("the keys document was taken, but the feed was refused"),
                    "{detail}"
                );
                assert!(!detail.contains("payload"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(svc.definitions().lock().unwrap().sequence, None);
    }

    #[test]
    fn a_feed_that_parses_but_would_not_generate_is_refused_whole() {
        use crate::feed_service::tests::{feed_envelope, feed_value_at, signer};
        let svc = feeding_service();
        // jmin alone is within its own bounds; merged over the bundled jmax it leaves no room.
        let mut value = feed_value_at(real_now(), 1, 3);
        value["profiles"][0]["client"] = serde_json::json!({ "jmin": 100 });
        match svc.dispatch(&import(
            Some(good_keys()),
            Some(feed_envelope(&value, &signer(1))),
        )) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("awg-default"), "{detail}");
                assert!(detail.contains("refused whole"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            svc.definitions().lock().unwrap().sequence,
            None,
            "a feed with one bad entry changes nothing"
        );
    }

    #[test]
    fn garbage_is_refused_and_not_repeated() {
        let svc = feeding_service();
        match svc.dispatch(&import(Some(b"SENTINEL-not-an-envelope".to_vec()), None)) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(!detail.contains("SENTINEL"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
    }

    // ---------------------------------------------------------------- configuration changes (9a)

    fn memory_configurator() -> (Configurator, Arc<MemoryStateFile>) {
        let file = Arc::new(MemoryStateFile::default());
        let configurator = Configurator::new(
            ConfigStore::new(Box::new(Arc::clone(&file))),
            Arc::new(MemorySecretStore::new()),
        );
        (configurator, file)
    }

    fn configurable_service() -> (DnetService, Arc<MemoryStateFile>) {
        let (configurator, file) = memory_configurator();
        (service().with_configurator(configurator), file)
    }

    /// The endpoint id in an add reply, read the way a client would hand it back.
    fn id_in(reply: &Value) -> EndpointId {
        let wire =
            serde_json::json!({ "request": "RemoveEndpoint", "endpoint": reply["endpoint"] });
        match dnet_ipc::protocol::decode_request(&wire.to_string()).expect("a valid id") {
            Request::RemoveEndpoint { endpoint } => endpoint,
            other => panic!("{other:?}"),
        }
    }

    fn json_of(reply: Result<String, IpcError>) -> Value {
        serde_json::from_str(&reply.expect("the request is accepted")).unwrap()
    }

    #[test]
    fn an_endpoint_added_through_the_service_is_listed_and_saved() {
        let (svc, file) = configurable_service();
        let added = json_of(svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home")))));
        let id = added["endpoint"]
            .as_str()
            .expect("the reply names the new endpoint");

        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        let endpoints = listed["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["id"], id);
        assert_eq!(endpoints[0]["label"], "home");
        assert_eq!(endpoints[0]["enabled"], true);

        let saved = dnet_config::persist::decode(&file.bytes().expect("saved")).unwrap();
        assert_eq!(saved.endpoints.len(), 1);
        assert_eq!(saved.endpoints[0].id().to_string(), id);
    }

    #[test]
    fn an_endpoint_can_be_disabled_enabled_and_removed_through_the_service() {
        let (svc, file) = configurable_service();
        let added = json_of(svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home")))));
        let id = id_in(&added);

        let reply = svc.dispatch(&Request::SetEndpointEnabled {
            endpoint: id,
            enabled: false,
        });
        assert_eq!(reply.unwrap(), APPLIED);
        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        assert_eq!(listed["endpoints"][0]["enabled"], false);

        assert_eq!(
            svc.dispatch(&Request::RemoveEndpoint { endpoint: id })
                .unwrap(),
            APPLIED
        );
        assert!(json_of(svc.dispatch(&Request::ListEndpoints))["endpoints"]
            .as_array()
            .unwrap()
            .is_empty());
        let saved = dnet_config::persist::decode(&file.bytes().unwrap()).unwrap();
        assert!(saved.endpoints.is_empty());
    }

    #[test]
    fn a_change_the_store_refuses_is_an_invalid_request_that_says_why() {
        let (svc, _file) = configurable_service();
        svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home"))))
            .unwrap();
        match svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home")))) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("label"), "{detail}");
                assert!(
                    !detail.contains("home"),
                    "never repeats the client's value: {detail}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            svc.dispatch(&Request::RemoveEndpoint {
                endpoint: EndpointId::new()
            }),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn opting_out_of_the_encrypted_dns_block_says_what_it_costs() {
        let (svc, _file) = configurable_service();
        let reply = json_of(svc.dispatch(&Request::SetEncryptedDnsHandling { block: false }));
        assert_eq!(reply["block"], false);
        assert_eq!(
            reply["consequence"],
            dnet_core::doh_consent::consequence_of_opting_out()
        );

        let reply = json_of(svc.dispatch(&Request::SetEncryptedDnsHandling { block: true }));
        assert_eq!(reply["block"], true);
        assert!(reply.get("consequence").is_none());
    }

    #[test]
    fn the_gates_still_come_before_a_configuration_change() {
        let (configurator, file) = memory_configurator();
        let svc = service()
            .with_configurator(configurator)
            .with_config_refusal(Some("refused".into()));
        assert!(matches!(
            svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home")))),
            Err(IpcError::InternalError { .. })
        ));
        assert!(
            file.bytes().is_none(),
            "a refused configuration is never saved over"
        );
    }

    #[test]
    fn subscribe_is_not_a_dispatch_request() {
        let svc = service();
        assert!(matches!(
            svc.dispatch(&Request::Subscribe),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn a_subscription_sees_what_the_orchestrator_publishes() {
        use dnet_core::session::ConnectionEvent;
        let svc = service();
        svc.events()
            .publish(&ConnectionEvent::ProbeStarted)
            .unwrap();
        let sub = svc.subscribe().expect("a subscription is offered");
        assert_eq!(sub.backlog.len(), 1);
    }

    #[test]
    fn the_idle_snapshot_is_served_through_the_checked_encoder() {
        let svc = service();
        let wire = svc.dispatch(&Request::GetState).unwrap();
        let snapshot = dnet_ipc::protocol::decode_state_snapshot(&wire)
            .expect("what the daemon serves, a client can read");
        assert_eq!(
            snapshot.status,
            dnet_ipc::protocol::ConnectionStatus::Disconnected
        );
    }

    #[test]
    fn console_resolver_is_consulted() {
        let svc = service();
        assert_eq!(svc.console_session().unwrap().session_id, 1);
    }

    fn mutating_requests() -> Vec<Request> {
        let all = vec![
            Request::Connect {
                acknowledge_tier2: false,
                profile: None,
                endpoint: None,
            },
            Request::Disconnect,
            Request::AddEndpoint(Box::new(new_endpoint("x"))),
            Request::RemoveEndpoint {
                endpoint: EndpointId::new(),
            },
            Request::SetEndpointEnabled {
                endpoint: EndpointId::new(),
                enabled: true,
            },
            Request::AddRule,
            Request::RemoveRule,
            Request::SetProfileParams,
            Request::EnableBrutal,
            Request::SetEncryptedDnsHandling { block: true },
            Request::ImportFeed(FeedImport::new(Some("{}".to_string()), None).unwrap()),
            Request::FetchFeed,
            Request::StartProvisioning,
            Request::CancelProvisioning,
        ];
        assert!(all.iter().all(|r| r.class() == RequestClass::Mutating));
        all
    }

    fn unrecovered_service() -> DnetService {
        DnetService::new(
            DomainState::seeded(),
            Box::new(|| None),
            Err(RecoveryError::Unrestored {
                remaining: 1,
                first: "access denied".into(),
            }),
        )
    }

    #[test]
    fn after_a_failed_recovery_every_mutating_request_is_refused_with_the_reason() {
        let svc = unrecovered_service();
        for request in mutating_requests() {
            match svc.dispatch(&request) {
                Err(IpcError::InternalError { detail }) => {
                    assert!(detail.contains("will not connect"), "{request:?}: {detail}");
                    assert!(
                        detail.contains("could not be undone"),
                        "{request:?}: {detail}"
                    );
                }
                other => panic!("{request:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn after_a_failed_recovery_read_only_queries_still_answer() {
        let svc = unrecovered_service();
        for request in [
            Request::GetVersion,
            Request::GetState,
            Request::GetSession,
            Request::GetPaths,
            Request::GetStats,
            Request::ListEndpoints,
            Request::ListProfiles,
            Request::ListRules,
            Request::GetDiagnostics,
        ] {
            assert!(svc.dispatch(&request).is_ok(), "{request:?}");
        }
    }

    fn service_with_refused_config() -> DnetService {
        service().with_config_refusal(Some(
            "the saved configuration has an invalid entry (endpoint 0: the host is neither an IP address nor a host name)"
                .into(),
        ))
    }

    #[test]
    fn a_refused_saved_configuration_refuses_every_mutating_request_with_the_reason() {
        let svc = service_with_refused_config();
        for request in mutating_requests() {
            match svc.dispatch(&request) {
                Err(IpcError::InternalError { detail }) => {
                    assert!(detail.contains("endpoint 0"), "{request:?}: {detail}");
                    assert!(
                        detail.contains("corrected or removed"),
                        "{request:?}: {detail}"
                    );
                }
                other => panic!("{request:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_refused_saved_configuration_still_answers_read_only_queries() {
        let svc = service_with_refused_config();
        for request in [
            Request::GetVersion,
            Request::GetState,
            Request::GetSession,
            Request::GetPaths,
            Request::GetStats,
            Request::ListEndpoints,
            Request::ListProfiles,
            Request::ListRules,
            Request::GetDiagnostics,
        ] {
            assert!(svc.dispatch(&request).is_ok(), "{request:?}");
        }
    }

    #[test]
    fn a_good_configuration_does_not_gate_anything_new() {
        // `service()` has no refusal: the new gate must not change what was already answered.
        let svc = service().with_config_refusal(None);
        assert!(matches!(
            svc.dispatch(&Request::Disconnect),
            Err(IpcError::InternalError { detail }) if detail.contains("not available")
        ));
    }

    // ---------------------------------------------------------------- with an orchestrator (T126)

    mod orchestrated {
        use std::sync::Arc;
        use std::time::Duration;

        use dnet_core::credential::CredentialRef;
        use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
        use dnet_core::engine::{Engine, Environment};
        use dnet_core::failure::Reach;
        use dnet_core::health::ProbeOutcome;
        use dnet_core::ids::{EndpointId, ProfileId};
        use dnet_core::probe::{ProfileProbe, RaceDecision};
        use dnet_core::reprobe::LiveCheck;
        use dnet_core::session::FailureCause;
        use dnet_core::tier::FailoverTier;
        use dnet_ipc::protocol::{decode_state_snapshot, ConnectionStatus};
        use dnet_ipc::wire::decode_event_view;
        use tokio_util::sync::CancellationToken;

        use super::*;
        use crate::orchestrator::{self, Effects, RaceOutcome, Timing};

        /// An endpoint that always works: the race picks Hysteria 2 and the tunnel comes up.
        struct Quick;

        impl Effects for Quick {
            fn environment(&self) -> Environment {
                Environment::default()
            }
            async fn reach(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
                vec![Reach::Reachable; endpoints.len()]
            }
            async fn race(
                &self,
                _profiles: Vec<ProfileId>,
                _endpoint: EndpointId,
                cancel: CancellationToken,
            ) -> Option<RaceOutcome> {
                // Long enough that a test can act while the connect is still in progress.
                tokio::select! {
                    () = cancel.cancelled() => None,
                    () = tokio::time::sleep(Duration::from_secs(2)) => Some((
                        RaceDecision::Selected {
                            profile: ProfileId::new("hy2-default"),
                            tier: FailoverTier::Tier2,
                            bits_per_sec: 10_000_000,
                        },
                        vec![(
                            ProfileId::new("hy2-default"),
                            ProfileProbe::Transferred {
                                bytes: 1_000_000,
                                elapsed: Duration::from_secs(1),
                            },
                        )],
                    )),
                }
            }
            async fn start_tunnel(&self, _: &ProfileId, _: EndpointId) -> Result<(), FailureCause> {
                Ok(())
            }
            async fn stop_tunnel(&self) {}
            async fn live_check(&self, _: &ProfileId) -> LiveCheck {
                LiveCheck::Passed
            }
            type Watch = crate::netwatch::NoWatch;
            fn network_watch(&self, _: &ProfileId, _: EndpointId) -> Option<Self::Watch> {
                None
            }
            async fn probe_endpoint(&self, _: EndpointId) -> ProbeOutcome {
                ProbeOutcome::Ok {
                    rtt: Duration::from_millis(30),
                    loss: false,
                }
            }
        }

        fn connect_request() -> Request {
            Request::Connect {
                acknowledge_tier2: false,
                profile: None,
                endpoint: None,
            }
        }

        fn orchestrated_service() -> DnetService {
            let service = service();
            let endpoint = Endpoint::new(
                EndpointId::new(),
                "home",
                EndpointAddress::new("203.0.113.10", 51820).unwrap(),
                EndpointOrigin::Manual,
                CredentialRef::new("endpoint-home"),
            )
            .unwrap();
            let engine = Engine::new(DomainState::seeded().profiles().to_vec(), vec![endpoint]);
            let handle = orchestrator::spawn(
                engine,
                Arc::new(Quick),
                service.events().clone(),
                Timing::default(),
            );
            service.with_orchestrator(handle)
        }

        /// What a client reading `GetState` sees, decoded with the client rules.
        fn state_of(svc: &DnetService) -> dnet_ipc::protocol::StateSnapshot {
            decode_state_snapshot(&svc.dispatch(&Request::GetState).unwrap())
                .expect("the daemon only ever serves a state a client can read")
        }

        async fn until_status(svc: &DnetService, want: ConnectionStatus) {
            for _ in 0..1000 {
                if state_of(svc).status == want {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never reached {want:?}; last {:?}", state_of(svc));
        }

        #[tokio::test(start_paused = true)]
        async fn a_connect_through_the_service_runs_the_orchestrator() {
            let svc = orchestrated_service();
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);

            let reply = svc.dispatch(&connect_request()).unwrap();
            assert_eq!(reply, r#"{"accepted":true}"#);

            until_status(&svc, ConnectionStatus::Connected).await;
            let connected = state_of(&svc);
            assert_eq!(connected.active_profile.unwrap().id, "hy2-default");
            assert_eq!(connected.active_endpoint.unwrap().label, "home");
        }

        #[tokio::test(start_paused = true)]
        async fn a_connected_session_is_counted_for_the_client() {
            use dnet_ipc::netview::{decode_paths, decode_stats, StatsReply};

            let svc = orchestrated_service();
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Connected).await;
            tokio::time::sleep(Duration::from_secs(30)).await;

            match decode_stats(&svc.dispatch(&Request::GetStats).unwrap()).unwrap() {
                StatsReply::Connected {
                    connected_for_s,
                    network_changes,
                    ..
                } => {
                    assert!(connected_for_s >= 25, "{connected_for_s}");
                    assert_eq!(network_changes, 0);
                }
                other => panic!("a connection is up, but {other:?}"),
            }
            // This test's effects offer nothing to watch, so no network can be listed, and the
            // reply says it is not looking rather than that there are none.
            let paths = decode_paths(&svc.dispatch(&Request::GetPaths).unwrap()).unwrap();
            assert!(!paths.watching);

            svc.dispatch(&Request::Disconnect).unwrap();
            until_status(&svc, ConnectionStatus::Disconnected).await;
            assert_eq!(
                decode_stats(&svc.dispatch(&Request::GetStats).unwrap()).unwrap(),
                StatsReply::NotConnected
            );
        }

        #[tokio::test(start_paused = true)]
        async fn progress_arrives_on_the_event_stream_not_in_the_reply() {
            let svc = orchestrated_service();
            // Subscribe first, as a client would, then connect.
            let mut subscription = svc.subscribe().unwrap();

            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Connected).await;

            let mut seen = Vec::new();
            while let Ok(frame) = subscription.live.try_recv() {
                // Each is read with the client rule: a real `because`, never blank.
                seen.push(decode_event_view(&frame).expect("an explained event").event);
            }
            assert!(seen.contains(&"ProbeStarted".to_string()), "{seen:?}");
            assert!(seen.contains(&"ProfileSelected".to_string()), "{seen:?}");
        }

        #[tokio::test(start_paused = true)]
        async fn the_service_answers_honestly_about_what_it_cannot_do_in_the_current_state() {
            let svc = orchestrated_service();
            assert_eq!(
                svc.dispatch(&Request::Disconnect),
                Err(IpcError::NotConnected)
            );

            svc.dispatch(&connect_request()).unwrap();
            assert_eq!(
                svc.dispatch(&connect_request()),
                Err(IpcError::ServiceBusy),
                "a second connect while one is under way is refused, not ignored"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_named_endpoint_is_refused_with_a_reason_not_silently_ignored() {
            let svc = orchestrated_service();
            let request = Request::Connect {
                acknowledge_tier2: false,
                profile: None,
                endpoint: Some(EndpointId::new()),
            };
            match svc.dispatch(&request) {
                Err(IpcError::InvalidRequest { detail }) => {
                    assert!(detail.contains("not supported yet"), "{detail}")
                }
                other => panic!("expected a refusal that says why, got {other:?}"),
            }
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);
        }

        #[tokio::test(start_paused = true)]
        async fn disconnect_takes_a_live_connection_down() {
            let svc = orchestrated_service();
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Connected).await;

            assert_eq!(
                svc.dispatch(&Request::Disconnect).unwrap(),
                r#"{"accepted":true}"#
            );
            until_status(&svc, ConnectionStatus::Disconnected).await;
        }

        /// An orchestrated service that can be changed: saved to memory, and rebuilt by a closure that
        /// counts how often it is asked and hands the new orchestrator the changed store.
        fn rebuilding_service() -> (DnetService, Arc<std::sync::atomic::AtomicUsize>) {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let service = orchestrated_service().with_configurator(memory_configurator().0);
            let calls = Arc::new(AtomicUsize::new(0));
            let (bus, counter) = (service.events().clone(), Arc::clone(&calls));
            let service = service.with_rebuild(Box::new(move |state| {
                counter.fetch_add(1, Ordering::SeqCst);
                let engine = Engine::new(state.profiles().to_vec(), state.endpoints().to_vec());
                orchestrator::spawn(engine, Arc::new(Quick), bus.clone(), Timing::default())
            }));
            (service, calls)
        }

        #[tokio::test(start_paused = true)]
        async fn a_saved_change_replaces_the_orchestrator_with_one_built_from_the_changed_store() {
            use std::sync::atomic::Ordering;

            let (svc, calls) = rebuilding_service();
            let old = svc.orchestrator_handle().expect("one is attached");

            svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("second"))))
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            // The old one has stopped: nothing can connect through it any more.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                old.connect(None).is_err(),
                "a retired orchestrator accepts no connect"
            );

            // What the service hands out to be stopped at shutdown is the live one, not the retired
            // one: stopping the retired one would leave a connected tunnel up.
            let current = svc.orchestrator_handle().expect("one is attached");
            current
                .connect(None)
                .expect("the live orchestrator accepts a connect; the retired one refused");

            // It knows the endpoint that was just added, and only that one.
            until_status(&svc, ConnectionStatus::Connected).await;
            assert_eq!(state_of(&svc).active_endpoint.unwrap().label, "second");
        }

        #[tokio::test(start_paused = true)]
        async fn every_kind_of_change_rebuilds_once() {
            use std::sync::atomic::Ordering;

            let (svc, calls) = rebuilding_service();
            let added =
                json_of(svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("second")))));
            let id = id_in(&added);
            svc.dispatch(&Request::SetEndpointEnabled {
                endpoint: id,
                enabled: false,
            })
            .unwrap();
            svc.dispatch(&Request::SetEncryptedDnsHandling { block: false })
                .unwrap();
            svc.dispatch(&Request::RemoveEndpoint { endpoint: id })
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 4);
        }

        #[tokio::test(start_paused = true)]
        async fn a_refused_change_does_not_rebuild() {
            use std::sync::atomic::Ordering;

            let (svc, calls) = rebuilding_service();
            let _ = svc.dispatch(&Request::RemoveEndpoint {
                endpoint: EndpointId::new(),
            });
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn nothing_is_changed_while_a_connection_is_up_or_being_made() {
            use std::sync::atomic::Ordering;

            let (svc, calls) = rebuilding_service();
            svc.dispatch(&connect_request()).unwrap();
            let id = EndpointId::new();
            let during: Vec<Request> = vec![
                Request::AddEndpoint(Box::new(new_endpoint("second"))),
                Request::RemoveEndpoint { endpoint: id },
                Request::SetEndpointEnabled {
                    endpoint: id,
                    enabled: false,
                },
                Request::SetEncryptedDnsHandling { block: false },
            ];

            // Being made, then up: both refuse.
            for phase in ["probing", "connected"] {
                for request in &during {
                    match svc.dispatch(request) {
                        Err(IpcError::InvalidRequest { detail }) => {
                            assert!(
                                detail.contains("disconnect"),
                                "{phase} {request:?}: {detail}"
                            )
                        }
                        other => panic!("{phase} {request:?}: {other:?}"),
                    }
                }
                if phase == "probing" {
                    until_status(&svc, ConnectionStatus::Connected).await;
                }
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "the live orchestrator was left alone"
            );
            assert_eq!(state_of(&svc).status, ConnectionStatus::Connected);

            // Once disconnected, the same request goes through.
            svc.dispatch(&Request::Disconnect).unwrap();
            until_status(&svc, ConnectionStatus::Disconnected).await;
            svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("second"))))
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn the_recovery_and_configuration_gates_still_come_first() {
            // A refused saved configuration must keep the orchestrator from ever being asked.
            let svc = orchestrated_service().with_config_refusal(Some("refused".into()));
            assert!(matches!(
                svc.dispatch(&connect_request()),
                Err(IpcError::InternalError { .. })
            ));
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);
        }
    }

    #[test]
    fn the_refusal_message_reads_as_a_sentence() {
        // The wording once carried a run of spaces from a flattened line continuation.
        let svc = service_with_refused_config();
        let Err(IpcError::InternalError { detail }) = svc.dispatch(&Request::Disconnect) else {
            panic!("a mutating request must be refused");
        };
        assert!(!detail.contains("  "), "{detail:?}");
    }

    #[test]
    fn a_failed_recovery_is_reported_before_a_refused_configuration() {
        let svc = unrecovered_service().with_config_refusal(Some("config reason".into()));
        match svc.dispatch(&Request::Disconnect) {
            Err(IpcError::InternalError { detail }) => {
                assert!(detail.contains("could not be undone"), "{detail}");
            }
            other => panic!("expected the recovery refusal, got {other:?}"),
        }
    }

    /// The window reads what the service really says, not what its author remembered of the contract: a name
    /// that differs (`Deterministic`, where the window's first fixtures said `Reliable`) is found here and not
    /// by a person looking at a screen. The window's side is `dnet-view`; this is its contract test against the
    /// real producer.
    #[tokio::test]
    async fn the_window_can_read_what_the_service_really_says() {
        use std::future::Future;

        use dnet_ipc::client::{classify_reply, ClientError, Reply};
        use dnet_ipc::protocol::encode_ipc_error;

        /// The service, asked directly: what the pipe would carry, without the pipe.
        struct Direct(Arc<DnetService>);
        impl dnet_view::Link for Direct {
            fn call(
                &self,
                request: Request,
            ) -> impl Future<Output = Result<Reply, ClientError>> + Send {
                let reply = match self.0.dispatch(&request) {
                    Ok(text) => classify_reply(&text),
                    Err(error) => classify_reply(&encode_ipc_error(&error)),
                };
                async move { reply }
            }
        }

        let (svc, _file) = configurable_service();
        json_of(svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("home")))));
        let bridge = dnet_view::Bridge::new(Direct(Arc::new(svc)));

        let view = bridge
            .snapshot(None, 0)
            .await
            .expect("the state is readable");
        assert_eq!(view["status"], "Disconnected");
        assert_eq!(view["posture"]["kind"], "FailClosed");
        // Not connected: nothing is watched and nothing is counted, and the window is told so.
        assert_eq!(view["paths"]["watching"], false);
        assert_eq!(view["stats"]["connected"], false);

        let endpoints = bridge
            .endpoints()
            .await
            .expect("the endpoints are readable");
        assert_eq!(endpoints["endpoints"][0]["label"], "home");
        assert_eq!(endpoints["endpoints"][0]["health"], "Unknown");

        let rules = bridge.rules().await.expect("the rules are readable");
        let rules_list = rules["rules"].as_array().unwrap();
        assert!(rules_list
            .iter()
            .any(|r| r["reliability"] == "Deterministic"));
        assert_eq!(rules["encryptedDns"]["block"], true);

        // The opt-out states what it costs, in the service's words, and the setting then reads as off.
        let out = bridge.set_encrypted_dns(false).await;
        assert_eq!(out["ok"], true, "{out}");
        assert!(!out["consequence"].as_str().unwrap().is_empty());
        assert_eq!(
            bridge.rules().await.unwrap()["encryptedDns"]["block"],
            false
        );

        // A refusal arrives as the service's own reason, never as success.
        let refused = bridge
            .remove_endpoint("5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10")
            .await;
        assert_eq!(
            refused["ok"], false,
            "an endpoint that does not exist is not removed"
        );
        assert!(!refused["reason"].as_str().unwrap().is_empty());
    }
}
