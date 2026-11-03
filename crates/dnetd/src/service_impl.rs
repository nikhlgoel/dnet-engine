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
//! remaining configuration requests (profile settings, provisioning) are recognized
//! but still answer that they are not available. The privilege boundary and the read path are real.

use std::sync::{Arc, Mutex, PoisonError};

use dnet_core::feed::fetch::FetchRoute;
use dnet_core::posture::RoutingPosture;
use dnet_core::profile::BandwidthPair;
use dnet_core::rule::{RuleAction, RuleMatcher};
use dnet_core::session::{CheckFailure, ConnectionEvent, DefinitionsChange};
use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::protocol::{encode_state_snapshot, FeedImport, IpcError, Request, RequestClass};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{EventBus, Subscription};

use crate::configure::{added_reply, dns_reply, rule_added_reply, Configurator, APPLIED};
use crate::domain::DomainState;
use crate::feed_fetch::{Busy, Fetcher, Pace, Transport};
use crate::feed_service::{FeedNote, FeedRefusal, FeedService, SharedDefinitions};
use crate::intent::{Intent, Remembered};
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
    /// What the person last asked for, kept across restarts (T147). Without it nothing is remembered.
    intent: Option<Intent>,
    /// Setting up the person's own server from a script and a pasted result (T150). Without it the
    /// requests answer that they are not available.
    server_setup: Option<crate::server_setup::ServerSetup>,
    /// Changes that redirect traffic, waiting for an elevated client to approve them (T160).
    pending: Mutex<crate::approval::PendingChanges>,
    /// Held across approving a change, so the same one is not applied twice by two approvers.
    approving: Mutex<()>,
    /// Whether such changes are held at all. True for every service built by `new`; only the tests
    /// that exercise the changes themselves turn it off, and nothing outside tests can.
    hold_changes: bool,
    /// What each part of the connection last reported and when its state changed (T170).
    components: Mutex<crate::components::Tracker>,
}

/// Starts a requested check and says which network it will use, or that one is under way.
type CheckRequester = Box<dyn Fn() -> Result<FetchRoute, Busy> + Send + Sync>;

/// Tell subscribers what a feed operation changed, and, for a check the person asked for that came to
/// nothing, why. Also logged, since nobody may be subscribed.
/// A setup that cannot proceed, as the client is told. A build with no server downloads is the
/// service's limit, not the client's mistake.
fn setup_refusal(error: crate::server_setup::SetupError) -> IpcError {
    use crate::server_setup::SetupError;
    match error {
        SetupError::NoDownloads | SetupError::NoBuild | SetupError::Script => {
            IpcError::InternalError {
                detail: error.to_string(),
            }
        }
        other => IpcError::InvalidRequest {
            detail: other.to_string(),
        },
    }
}

impl crate::keep_trying::Retry for DnetService {
    /// Under the store lock, as every request is: a person's disconnect forgets the intent under the
    /// same lock, so a retry is either before it (and the disconnect stops it) or sees it off.
    fn retry_if_left_on(&self) -> crate::keep_trying::Tick {
        use crate::keep_trying::Tick;
        use dnet_ipc::protocol::ConnectionStatus;

        let _state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(Remembered::On { profile }) = self.intent.as_ref().map(Intent::load) else {
            return Tick::Idle;
        };
        let Some(orchestrator) = self.orchestrator() else {
            return Tick::Idle;
        };
        if !orchestrator.is_idle() {
            return match orchestrator.snapshot().status {
                ConnectionStatus::Connected => Tick::Healthy,
                _ => Tick::InProgress,
            };
        }
        match orchestrator.connect(profile) {
            Ok(()) => {
                tracing::info!("left on and not connected: trying again");
                Tick::Attempted
            }
            Err(_) => Tick::InProgress,
        }
    }
}

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

/// A short random name for a held change: eight lower-case hex digits. It names a change; it is
/// not a secret, since approving needs elevation and not the name.
fn fresh_change_id() -> String {
    let mut bytes = [0u8; 4];
    // The system generator failing is not a state to carry on from with a guessable id.
    getrandom::fill(&mut bytes).expect("the system random generator is available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unknown_change(error: crate::approval::FindError) -> IpcError {
    IpcError::InvalidRequest {
        detail: match error {
            crate::approval::FindError::Unknown => {
                "no change is waiting under that name; it may have been applied, withdrawn or \
                 dropped after ten minutes"
            }
            crate::approval::FindError::Expired => {
                "that change waited more than ten minutes and was dropped; ask for it again"
            }
        }
        .to_string(),
    }
}

/// Text from a request, made safe to show in a prompt: no control characters, and not long.
fn shown(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > 64 {
        let cut: String = clean.chars().take(64).collect();
        format!("{cut}...")
    } else {
        clean
    }
}

fn describe_matcher(matcher: &RuleMatcher) -> String {
    match matcher {
        RuleMatcher::Domain(name) => format!("traffic to {}", shown(name)),
        RuleMatcher::DomainSuffix(name) => format!("traffic to {} and its subdomains", shown(name)),
        RuleMatcher::IpCidr(range) => format!("traffic to {range}"),
        RuleMatcher::Application(path) => format!("traffic from {}", shown(path)),
        RuleMatcher::DnsPort => "name lookups".to_string(),
        RuleMatcher::EncryptedDnsPort => "encrypted name lookups".to_string(),
    }
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
            intent: None,
            server_setup: None,
            pending: Mutex::new(crate::approval::PendingChanges::new()),
            approving: Mutex::new(()),
            hold_changes: true,
            components: Mutex::new(crate::components::Tracker::new()),
        }
    }

    /// For tests of the changes themselves: apply them as they are asked for, without holding them.
    #[cfg(test)]
    pub fn applying_changes_without_approval(mut self) -> Self {
        self.hold_changes = false;
        self
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

    /// Let the person set up their own server (T150).
    #[cfg_attr(not(windows), allow(dead_code))] // Windows builds it; the tests supply their own.
    pub fn with_server_setup(mut self, setup: crate::server_setup::ServerSetup) -> Self {
        self.server_setup = Some(setup);
        self
    }

    /// Remember what the person asks for in `intent`, and resume it at start-up (T147).
    #[cfg_attr(not(windows), allow(dead_code))] // Windows builds it; the tests supply their own.
    pub fn with_intent(mut self, intent: Intent) -> Self {
        self.intent = Some(intent);
        self
    }

    /// Connect again if the person left it on (T147). Called once, at start-up, after recovery and
    /// after the orchestrator is attached; a service that may not connect does nothing and keeps the
    /// intent for a start that can.
    #[cfg_attr(not(windows), allow(dead_code))] // Called at start-up on Windows, and by the tests.
    pub fn resume_if_left_on(&self) {
        let Some(Remembered::On { profile }) = self.intent.as_ref().map(Intent::load) else {
            return;
        };
        let Some(orchestrator) = self.orchestrator() else {
            tracing::warn!("left on, but connecting is unavailable in this start; not resuming");
            return;
        };
        match orchestrator.connect(profile) {
            Ok(()) => tracing::info!("left on: connecting again"),
            Err(error) => {
                tracing::warn!(%error, "left on, but the connection could not be resumed")
            }
        }
    }

    /// Start trying again whenever the connection is down while left on (T148), for as long as the
    /// service exists. `changes` signals network changes, where the platform has them.
    #[cfg_attr(not(windows), allow(dead_code))] // Started on Windows; the tests drive the loop.
    pub fn keep_trying(
        self: &Arc<Self>,
        changes: Option<tokio::sync::mpsc::Receiver<()>>,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self) as std::sync::Weak<dyn crate::keep_trying::Retry>;
        tokio::spawn(crate::keep_trying::run(
            weak,
            changes,
            crate::keep_trying::Pace::default(),
        ))
    }

    fn remember(&self, profile: Option<&dnet_core::ids::ProfileId>) {
        if let Some(Err(error)) = self.intent.as_ref().map(|i| i.remember_on(profile)) {
            tracing::warn!(%error, "the connection will not be resumed after a restart: it could not be remembered");
        }
    }

    fn forget(&self) {
        if let Some(Err(error)) = self.intent.as_ref().map(Intent::forget) {
            tracing::warn!(%error, "the remembered connection could not be cleared; it may resume after a restart");
        }
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
                detail: "disconnect before changing settings; the change would not reach a connection that is \
                         already up"
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
        .with_configurator(configurator)
        // Beside the configuration, under the same owner and DACL check (T147).
        .with_intent(Intent::new(Box::new(TrustedStateFile::new(
            default_config_path().with_file_name("connection-intent.json"),
        ))));

        // The server downloads this release carries, beside the service in the folder only administrators
        // can change (T150). Absent or unreadable, setting up a server answers that it is not available.
        let service = service.with_server_setup(crate::server_setup::ServerSetup::new(
            crate::server_setup::installed_pins(),
        ));

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
        // The three requests about held changes are answered here, before the store is touched.
        match request {
            Request::ListPending => {
                return Ok(self
                    .pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .list_json(unix_millis()));
            }
            Request::RejectChange { id } => return self.reject_change(id),
            Request::ApproveChange { id } => return self.approve_change(id),
            _ => {}
        }
        if self.hold_changes {
            if let Some(what) = self.redirects_traffic(request) {
                return self.hold_change(request, what);
            }
        }
        self.apply(request)
    }

    fn subscribe(&self) -> Result<Subscription, IpcError> {
        self.events.subscribe()
    }
}

impl DnetService {
    /// The strict gate (T038, T124): refuses a change while a previous run's network changes are
    /// unrestored or the saved configuration was refused.
    fn refuse_while_unsafe(&self) -> Result<(), IpcError> {
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
        Ok(())
    }

    /// If `request` changes where traffic goes, what it would do, in words for the person (T160).
    ///
    /// Held: a new server (added by hand or by the setup guide), turning a server on, a rule that
    /// sends traffic around the tunnel, and an imported feed. Not held: everything that can only make
    /// the connection stricter or leave it where it is (removing or turning off a server, a rule that
    /// tunnels, captures or rejects, the encrypted-DNS setting, Brutal), and everything that is not a
    /// change at all.
    fn redirects_traffic(&self, request: &Request) -> Option<String> {
        match request {
            Request::AddEndpoint(new) => Some(format!(
                "Adding the server \"{}\" at {}",
                shown(new.label()),
                shown(new.host())
            )),
            Request::FinishServer { label, host, .. } => Some(format!(
                "Adding the server \"{}\" at {} made by the setup guide",
                shown(label),
                shown(host)
            )),
            Request::SetEndpointEnabled {
                endpoint,
                enabled: true,
            } => {
                let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                // An unknown server is not held: applying it fails, and changes nothing.
                let found = state.endpoints().iter().find(|e| e.id() == *endpoint)?;
                Some(format!(
                    "Turning on the server \"{}\"",
                    shown(found.label())
                ))
            }
            Request::AddRule {
                matcher,
                action: RuleAction::Bypass,
            } => Some(format!(
                "Sending {} around the tunnel",
                describe_matcher(matcher)
            )),
            Request::ImportFeed(_) => {
                Some("Importing connection-method definitions from a file".to_string())
            }
            _ => None,
        }
    }

    /// Hold `request` and say so as the refusal it is: nothing was applied.
    fn hold_change(&self, request: &Request, what: String) -> Result<String, IpcError> {
        // A change that could not be applied even if approved is not worth anyone's prompt.
        self.refuse_while_unsafe()?;
        let held = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hold(
                request.clone(),
                what.clone(),
                unix_millis(),
                fresh_change_id,
            );
        match held {
            Ok(id) => {
                // Only the id is logged: what a change names (a server's address) stays out of the log.
                tracing::info!(change = %id, "a change that redirects traffic is waiting for approval");
                Err(IpcError::ApprovalRequired { id, what })
            }
            Err(crate::approval::HoldError::Full) => Err(IpcError::InvalidRequest {
                detail: "too many changes are waiting for approval; approve or withdraw one first \
                         (`dnetctl pending`)"
                    .to_string(),
            }),
        }
    }

    /// Apply the held change `id`. Only reached for an elevated client in the console session
    /// (`dnet_ipc::authz`); the change applied is exactly the one held, never one the caller sends.
    fn approve_change(&self, id: &str) -> Result<String, IpcError> {
        let _one_at_a_time = self
            .approving
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let found = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .find(id, unix_millis());
        let held = found.map_err(unknown_change)?;
        // A change that fails (a connection is up, say) stays held until it expires, so the person
        // can try again without asking for it again.
        let reply = self.apply(&held.request)?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        tracing::info!(change = %id, "a change was approved by an elevated client");
        Ok(reply)
    }

    /// Drop the held change `id` without applying it.
    fn reject_change(&self, id: &str) -> Result<String, IpcError> {
        let found = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .find(id, unix_millis());
        found.map_err(unknown_change)?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        tracing::info!(change = %id, "a waiting change was withdrawn");
        Ok(APPLIED.to_string())
    }

    fn apply(&self, request: &Request) -> Result<String, IpcError> {
        // Strict gate (T038): nothing may change while a previous run's network changes
        // are still unrestored. Read-only queries still answer, so the user can see why.
        if request.class() == RequestClass::Mutating {
            self.refuse_while_unsafe()?;
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
            // T170: every part of the connection and how it is doing, from the same snapshots the other
            // read-only requests use. It holds no label, address or network name (see `components`).
            Request::GetComponents => {
                let snapshot = match &orchestrator {
                    Some(orchestrator) => orchestrator.snapshot(),
                    None => state.idle_snapshot(),
                };
                let paths = orchestrator
                    .as_ref()
                    .and_then(|o| o.paths())
                    .unwrap_or_default();
                Ok(self
                    .components
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .reply(&snapshot, &paths, unix_millis()))
            }
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
                    self.remember(profile.as_ref());
                    Ok(ACCEPTED.to_string())
                }
                None => Self::not_available("connecting"),
            },
            // The person said off, so it stays off after a restart whatever the answer below (T147).
            Request::Disconnect => {
                self.forget();
                match &orchestrator {
                    Some(orchestrator) => {
                        orchestrator.disconnect()?;
                        Ok(ACCEPTED.to_string())
                    }
                    None => Self::not_available("disconnecting"),
                }
            }

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
            Request::PrepareServer { arch } => {
                let Some(setup) = &self.server_setup else {
                    return Self::not_available("setting up a server");
                };
                match setup.prepare(*arch, unix_millis() / 1000) {
                    Ok(prepared) => Ok(dnet_ipc::server_setup::encode_prepared(&prepared)),
                    Err(error) => Err(setup_refusal(error)),
                }
            }
            Request::FinishServer {
                label,
                host,
                report,
            } => {
                // Idle only, like every change to the endpoints; checked before the result is read so a
                // refusal costs the person nothing.
                let configurator = self.before_change()?;
                let Some(setup) = &self.server_setup else {
                    return Self::not_available("setting up a server");
                };
                let credentials = setup
                    .finish(report, unix_millis() / 1000)
                    .map_err(setup_refusal)?;
                let new = dnet_ipc::protocol::NewEndpoint::new(label, host, credentials)?;
                let id = configurator.add_endpoint(&mut state, &new)?;
                // Saved: the keys that were waiting for it are no longer needed.
                setup.complete();
                self.reload(&state);
                Ok(added_reply(id))
            }
            Request::AddRule { matcher, action } => {
                let configurator = self.before_change()?;
                let id = configurator.add_rule(&mut state, matcher.clone(), *action)?;
                self.reload(&state);
                Ok(rule_added_reply(id))
            }
            Request::RemoveRule { rule } => {
                let configurator = self.before_change()?;
                configurator.remove_rule(&mut state, *rule)?;
                self.reload(&state);
                Ok(APPLIED.to_string())
            }
            Request::EnableBrutal {
                profile,
                up_mbps,
                down_mbps,
                // The IPC layer accepts only the revision in force; the acknowledgement is recorded
                // under that revision, at the service's time.
                warning_revision: _,
            } => {
                let configurator = self.before_change()?;
                let bandwidth = BandwidthPair {
                    up_mbps: *up_mbps,
                    down_mbps: *down_mbps,
                };
                configurator.set_brutal(
                    &mut state,
                    profile,
                    Some(bandwidth),
                    unix_millis() / 1000,
                )?;
                self.reload(&state);
                Ok(APPLIED.to_string())
            }
            Request::DisableBrutal { profile } => {
                let configurator = self.before_change()?;
                configurator.set_brutal(&mut state, profile, None, unix_millis() / 1000)?;
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
            Request::SetProfileParams
            | Request::StartProvisioning
            | Request::CancelProvisioning => Self::not_available("this configuration change"),

            // Answered by `dispatch` before `apply` is reached; they never come through here.
            Request::ListPending | Request::ApproveChange { .. } | Request::RejectChange { .. } => {
                Err(IpcError::InternalError {
                    detail: "a request about held changes reached the apply step".to_string(),
                })
            }

            // Streaming is handled by the connection loop (`Service::subscribe`), not one-shot dispatch.
            Request::Subscribe => Err(IpcError::InvalidRequest {
                detail: "Subscribe is a streaming request, not a one-shot dispatch".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnet_config::persist::{ConfigStore, MemoryStateFile};
    use dnet_config::secret_store::MemorySecretStore;
    use dnet_core::ids::{EndpointId, ProfileId};

    use super::*;
    use crate::configure::tests::new_endpoint;
    use serde_json::Value;

    /// A service with a fixed (test) console identity, so `dispatch` can be exercised
    /// without the OS console lookup.
    fn service() -> DnetService {
        holding_service().applying_changes_without_approval()
    }

    /// The service as it is built for real: changes that redirect traffic are held for approval.
    fn holding_service() -> DnetService {
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
    fn get_components_with_nothing_connected_reports_the_connection_and_routing_as_off() {
        use dnet_core::registry::{ComponentKind, ComponentState};
        let svc = service();

        let reply = dnet_ipc::componentview::decode_components(
            &svc.dispatch(&Request::GetComponents).unwrap(),
        )
        .expect("the daemon only serves what a client can read");

        assert_eq!(reply.overall, ComponentState::Off);
        let kinds: Vec<_> = reply.components.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, [ComponentKind::Session, ComponentKind::Routes]);
        assert!(reply
            .components
            .iter()
            .all(|c| c.state == ComponentState::Off));
        assert!(
            reply.as_of_unix_ms > 1_600_000_000_000,
            "stamped with the time"
        );
    }

    #[test]
    fn get_components_is_read_only_and_asking_again_changes_no_state() {
        let svc = service();
        let ask = |svc: &DnetService| {
            dnet_ipc::componentview::decode_components(
                &svc.dispatch(&Request::GetComponents).unwrap(),
            )
            .unwrap()
        };
        let first = ask(&svc);
        let second = ask(&svc);
        let words = |r: &dnet_ipc::componentview::ComponentsReply| {
            r.components
                .iter()
                .map(|c| (c.kind, c.id.clone(), c.state, c.reason.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(words(&first), words(&second));
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
            svc.dispatch(&Request::SetProfileParams),
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

    fn enable_brutal() -> Request {
        Request::EnableBrutal {
            profile: ProfileId::new("hy2-default"),
            up_mbps: 50,
            down_mbps: 200,
            warning_revision: dnet_core::profile::BRUTAL_WARNING_REVISION,
        }
    }

    fn brutal_listed(svc: &DnetService) -> bool {
        json_of(svc.dispatch(&Request::ListProfiles))["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "hy2-default")
            .unwrap()["brutal"]
            .as_bool()
            .unwrap()
    }

    /// T108: a rule added through the service is listed with its pattern, saved, and removed by id.
    #[test]
    fn a_rule_can_be_added_listed_and_removed_through_the_service() {
        let (svc, file) = configurable_service();
        let added = json_of(svc.dispatch(&Request::AddRule {
            matcher: dnet_core::rule::RuleMatcher::DomainSuffix("example.com".into()),
            action: dnet_core::rule::RuleAction::Bypass,
        }));
        let id = added["rule"]
            .as_str()
            .expect("the new rule's id")
            .to_owned();
        let listed = json_of(svc.dispatch(&Request::ListRules));
        let mine = listed["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id.as_str())
            .expect("listed")
            .clone();
        assert_eq!(mine["value"], "example.com");
        assert_eq!(mine["action"], "Bypass");
        let saved = dnet_config::persist::decode(&file.bytes().unwrap()).unwrap();
        assert_eq!(saved.rules.len(), 1);

        let rule = dnet_core::ids::RuleId::from_uuid(id.parse().unwrap());
        assert_eq!(
            svc.dispatch(&Request::RemoveRule { rule }).unwrap(),
            APPLIED
        );
        let saved = dnet_config::persist::decode(&file.bytes().unwrap()).unwrap();
        assert!(saved.rules.is_empty());
    }

    // ---------------------------------------------------------------- T150: the person's own server

    fn setup_pins() -> dnet_provision::server_pins::ServerPins {
        use serde_json::json;
        dnet_provision::server_pins::ServerPins::parse(
            &json!({
                "version": 1,
                "base_url": "https://example.test/d/",
                "primary_core": { "name": "primary-core", "version": "v1.14.0", "licence": "GPL-3.0-or-later",
                    "source": "https://example.test/s",
                    "amd64": { "file": "p-amd64", "sha256": "a".repeat(64) },
                    "arm64": { "file": "p-arm64", "sha256": "b".repeat(64) } },
                "amneziawg": { "name": "amneziawg-go", "version": "v3.1.0", "licence": "MIT",
                    "source": "https://example.test/a",
                    "amd64": { "file": "a-amd64", "sha256": "c".repeat(64) },
                    "arm64": { "file": "a-arm64", "sha256": "d".repeat(64) } },
            })
            .to_string(),
        )
        .unwrap()
    }

    fn serving() -> (DnetService, Arc<MemoryStateFile>) {
        let (svc, file) = configurable_service();
        (
            svc.with_server_setup(crate::server_setup::ServerSetup::new(Some(setup_pins()))),
            file,
        )
    }

    fn prepare_amd64() -> Request {
        Request::PrepareServer {
            arch: dnet_ipc::server_setup::ServerKind::Amd64,
        }
    }

    /// What the script would print, read off the reply the way the server would.
    fn printed(prepared: &dnet_ipc::server_setup::Prepared) -> String {
        let client = prepared
            .script
            .lines()
            .find_map(|l| l.strip_prefix("public_key="))
            .unwrap();
        let report = serde_json::json!({
            "version": 2,
            "session": crate::server_setup::session_printed_by(&prepared.script),
            "amneziawg": { "server_public_key_hex": "d".repeat(64), "listen_port": 51820,
                "client_address": "10.66.0.2", "prefix_len": 24, "client_public_key_hex": client },
            "hysteria2": { "server_port": 44443, "server_name": crate::server_setup::DEFAULT_SITE,
                "spki_sha256_hex": "e".repeat(64), "auth_password": "auth-secret-0123456789abcdef",
                "obfs_password": "obfs-secret-0123456789abcdef", "cert_key_algorithm": "ecdsa-p256" },
            "reality": { "server_port": 8443, "target_domain": crate::server_setup::DEFAULT_SITE,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                "short_id": "0123456789abcdef", "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
                "flow": "xtls-rprx-vision" },
            "cores": { "primary_core": { "version": "v1.14.0", "sha256": "a".repeat(64) },
                "amneziawg": { "version": "v3.1.0", "sha256": "c".repeat(64) } },
        });
        format!("root@vm:~# sh setup.sh\nDNET-BOOTSTRAP-REPORT {report}\nroot@vm:~# ")
    }

    fn finish(label: &str, report: String) -> Request {
        Request::FinishServer {
            label: label.to_owned(),
            host: "203.0.113.10".to_owned(),
            report,
        }
    }

    #[test]
    fn t150_a_server_is_set_up_from_a_script_and_a_pasted_result() {
        let (svc, _file) = serving();
        let prepared =
            dnet_ipc::server_setup::decode_prepared(&svc.dispatch(&prepare_amd64()).unwrap())
                .unwrap();
        assert!(prepared.script.starts_with("#!/bin/sh"));
        assert_eq!(prepared.ports.len(), 3);

        let reply = svc
            .dispatch(&finish("my server", printed(&prepared)))
            .unwrap();
        let id: Value = serde_json::from_str(&reply).unwrap();
        assert!(id["endpoint"].as_str().is_some(), "{reply}");

        let endpoints: Value =
            serde_json::from_str(&svc.dispatch(&Request::ListEndpoints).unwrap()).unwrap();
        let list = endpoints["endpoints"].as_array().expect("a list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["label"], "my server");
        // The result is used once: pasting it again finds nothing waiting.
        assert!(svc.dispatch(&finish("again", printed(&prepared))).is_err());
    }

    #[test]
    fn t150_a_failed_save_keeps_the_keys_so_the_person_can_choose_another_name() {
        let (svc, _file) = serving();
        let prepared =
            dnet_ipc::server_setup::decode_prepared(&svc.dispatch(&prepare_amd64()).unwrap())
                .unwrap();
        svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint("taken"))))
            .unwrap();
        let text = printed(&prepared);
        match svc.dispatch(&finish("taken", text.clone())) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("label"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
        assert!(svc.dispatch(&finish("another", text)).is_ok());
    }

    #[test]
    fn t150_a_bad_result_is_refused_with_a_reason_that_repeats_nothing() {
        let (svc, _file) = serving();
        svc.dispatch(&prepare_amd64()).unwrap();
        match svc.dispatch(&finish("x", "SENTINEL no report here".to_owned())) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(!detail.contains("SENTINEL"), "{detail}");
                assert!(detail.contains("no bootstrap report"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            serde_json::from_str::<Value>(&svc.dispatch(&Request::ListEndpoints).unwrap()).unwrap()
                ["endpoints"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn t150_without_downloads_in_this_build_it_says_so() {
        let (svc, _file) = configurable_service();
        let svc = svc.with_server_setup(crate::server_setup::ServerSetup::new(None));
        match svc.dispatch(&prepare_amd64()) {
            Err(IpcError::InternalError { detail }) => {
                assert!(detail.contains("not available"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
        // And a service with no setup machinery at all.
        let (svc, _file) = configurable_service();
        assert!(svc.dispatch(&prepare_amd64()).is_err());
    }

    /// T105: Brutal turned on through the service is listed, saved, and off again on request.
    #[test]
    fn brutal_can_be_turned_on_and_off_through_the_service() {
        let (svc, file) = configurable_service();
        assert!(!brutal_listed(&svc));

        assert_eq!(svc.dispatch(&enable_brutal()).unwrap(), APPLIED);
        assert!(brutal_listed(&svc));
        let saved = dnet_config::persist::decode(&file.bytes().unwrap()).unwrap();
        let hy2 = saved
            .profiles
            .iter()
            .find(|p| p.id.as_str() == "hy2-default")
            .unwrap();
        let (bandwidth, ack) = hy2.brutal.unwrap();
        assert_eq!((bandwidth.up_mbps, bandwidth.down_mbps), (50, 200));
        assert!(
            ack.acknowledged_at_unix > 1_600_000_000,
            "the service's clock"
        );

        let off = Request::DisableBrutal {
            profile: ProfileId::new("hy2-default"),
        };
        assert_eq!(svc.dispatch(&off).unwrap(), APPLIED);
        assert!(!brutal_listed(&svc));
    }

    #[test]
    fn brutal_on_another_kind_of_profile_is_an_invalid_request_that_says_why() {
        let (svc, file) = configurable_service();
        let request = Request::EnableBrutal {
            profile: ProfileId::new("awg-default"),
            up_mbps: 50,
            down_mbps: 200,
            warning_revision: dnet_core::profile::BRUTAL_WARNING_REVISION,
        };
        match svc.dispatch(&request) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("Hysteria 2"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
        assert!(file.bytes().is_none());
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
            Request::AddRule {
                matcher: dnet_core::rule::RuleMatcher::Domain("example.com".into()),
                action: dnet_core::rule::RuleAction::Bypass,
            },
            Request::RemoveRule {
                rule: dnet_core::ids::RuleId::new(),
            },
            Request::SetProfileParams,
            enable_brutal(),
            Request::DisableBrutal {
                profile: ProfileId::new("hy2-default"),
            },
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
        use crate::intent::{Intent, Remembered};
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

        /// T147: a service whose remembered intent lives in `file`.
        fn remembering(svc: DnetService, file: &Arc<MemoryStateFile>) -> DnetService {
            svc.with_intent(Intent::new(Box::new(Arc::clone(file))))
        }

        fn remembered(file: &Arc<MemoryStateFile>) -> Remembered {
            Intent::new(Box::new(Arc::clone(file))).load()
        }

        #[tokio::test(start_paused = true)]
        async fn t147_a_connect_is_remembered_and_a_disconnect_forgets_it() {
            let file = Arc::new(MemoryStateFile::default());
            let svc = remembering(orchestrated_service(), &file);
            svc.dispatch(&Request::Connect {
                acknowledge_tier2: false,
                profile: Some(ProfileId::new("hy2-default")),
                endpoint: None,
            })
            .unwrap();
            assert_eq!(
                remembered(&file),
                Remembered::On {
                    profile: Some(ProfileId::new("hy2-default"))
                }
            );
            until_status(&svc, ConnectionStatus::Connected).await;

            svc.dispatch(&Request::Disconnect).unwrap();
            assert_eq!(remembered(&file), Remembered::Off);
            until_status(&svc, ConnectionStatus::Disconnected).await;
        }

        /// The person said off; that holds whether or not anything was connected at the time.
        #[tokio::test(start_paused = true)]
        async fn t147_a_disconnect_forgets_even_when_nothing_was_connected() {
            let file = Arc::new(MemoryStateFile::default());
            Intent::new(Box::new(Arc::clone(&file)))
                .remember_on(None)
                .unwrap();
            let svc = remembering(orchestrated_service(), &file);
            assert!(svc.dispatch(&Request::Disconnect).is_err());
            assert_eq!(remembered(&file), Remembered::Off);
        }

        #[tokio::test(start_paused = true)]
        async fn t147_a_refused_connect_is_not_remembered() {
            let file = Arc::new(MemoryStateFile::default());
            let svc = remembering(orchestrated_service(), &file);
            assert!(svc
                .dispatch(&Request::Connect {
                    acknowledge_tier2: false,
                    profile: None,
                    endpoint: Some(EndpointId::new()),
                })
                .is_err());
            assert_eq!(remembered(&file), Remembered::Off);

            // Already connected: the second connect is refused as busy and changes nothing.
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Connected).await;
            assert!(svc
                .dispatch(&Request::Connect {
                    acknowledge_tier2: false,
                    profile: Some(ProfileId::new("awg-default")),
                    endpoint: None,
                })
                .is_err());
            assert_eq!(remembered(&file), Remembered::On { profile: None });
        }

        /// After a reboot, an update or a crash, a service left on connects by itself, with the same
        /// choice of profile.
        #[tokio::test(start_paused = true)]
        async fn t147_a_service_left_on_connects_by_itself_when_it_starts() {
            let file = Arc::new(MemoryStateFile::default());
            Intent::new(Box::new(Arc::clone(&file)))
                .remember_on(Some(&ProfileId::new("hy2-default")))
                .unwrap();
            let svc = remembering(orchestrated_service(), &file);
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);

            svc.resume_if_left_on();
            until_status(&svc, ConnectionStatus::Connected).await;
            assert_eq!(state_of(&svc).active_profile.unwrap().id, "hy2-default");
            assert_eq!(
                remembered(&file),
                Remembered::On {
                    profile: Some(ProfileId::new("hy2-default"))
                }
            );
        }

        #[tokio::test(start_paused = true)]
        async fn t147_a_service_left_off_stays_off() {
            let file = Arc::new(MemoryStateFile::default());
            let svc = remembering(orchestrated_service(), &file);
            svc.resume_if_left_on();
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);
        }

        /// A service that may not connect (a failed recovery, a refused configuration, no files) does not
        /// try, and keeps what the person asked for, for the start that can.
        #[tokio::test(start_paused = true)]
        async fn t147_a_service_that_cannot_connect_keeps_the_intent_for_later() {
            let file = Arc::new(MemoryStateFile::default());
            Intent::new(Box::new(Arc::clone(&file)))
                .remember_on(None)
                .unwrap();
            let svc = remembering(service(), &file);
            svc.resume_if_left_on();
            assert_eq!(remembered(&file), Remembered::On { profile: None });
        }

        /// Effects whose tunnel cannot start during the first `failures` connect attempts (one race each),
        /// then as `Quick`.
        struct Flaky {
            failures: usize,
            checks: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl Effects for Flaky {
            fn environment(&self) -> Environment {
                Quick.environment()
            }
            async fn reach(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
                Quick.reach(endpoints).await
            }
            async fn race(
                &self,
                profiles: Vec<ProfileId>,
                endpoint: EndpointId,
                cancel: CancellationToken,
            ) -> Option<RaceOutcome> {
                self.checks
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Quick.race(profiles, endpoint, cancel).await
            }
            async fn start_tunnel(&self, p: &ProfileId, e: EndpointId) -> Result<(), FailureCause> {
                if self.checks.load(std::sync::atomic::Ordering::SeqCst) <= self.failures {
                    Err(FailureCause::AllProfilesBlocked)
                } else {
                    Quick.start_tunnel(p, e).await
                }
            }
            async fn stop_tunnel(&self) {}
            async fn live_check(&self, p: &ProfileId) -> LiveCheck {
                Quick.live_check(p).await
            }
            type Watch = crate::netwatch::NoWatch;
            fn network_watch(&self, _: &ProfileId, _: EndpointId) -> Option<Self::Watch> {
                None
            }
            async fn probe_endpoint(&self, e: EndpointId) -> ProbeOutcome {
                Quick.probe_endpoint(e).await
            }
        }

        /// A service over `Flaky`, and the count of connect attempts.
        fn flaky_service(
            failures: usize,
        ) -> (Arc<DnetService>, Arc<std::sync::atomic::AtomicUsize>) {
            let service = service();
            let endpoint = Endpoint::new(
                EndpointId::new(),
                "home",
                EndpointAddress::new("203.0.113.10", 51820).unwrap(),
                EndpointOrigin::Manual,
                CredentialRef::new("endpoint-home"),
            )
            .unwrap();
            let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let engine = Engine::new(DomainState::seeded().profiles().to_vec(), vec![endpoint]);
            let handle = orchestrator::spawn(
                engine,
                Arc::new(Flaky {
                    failures,
                    checks: Arc::clone(&checks),
                }),
                service.events().clone(),
                Timing::default(),
            );
            (Arc::new(service.with_orchestrator(handle)), checks)
        }

        fn keep_trying(svc: &Arc<DnetService>) -> tokio::task::JoinHandle<()> {
            let weak = Arc::downgrade(svc) as std::sync::Weak<dyn crate::keep_trying::Retry>;
            tokio::spawn(crate::keep_trying::run(
                weak,
                None,
                crate::keep_trying::Pace::default(),
            ))
        }

        /// T148: left on at start-up with no network yet (two failed attempts), it connects by itself.
        #[tokio::test(start_paused = true)]
        async fn t148_a_service_left_on_keeps_trying_until_it_connects() {
            let (svc, checks) = flaky_service(2);
            let svc = Arc::new(
                Arc::into_inner(svc)
                    .unwrap()
                    .with_intent(Intent::new(Box::new(MemoryStateFile::default()))),
            );
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Failed).await;
            let task = keep_trying(&svc);
            until_status(&svc, ConnectionStatus::Connected).await;
            assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 3);
            task.abort();
        }

        /// The person turned it off: no retry follows, however long it waits.
        #[tokio::test(start_paused = true)]
        async fn t148_a_disconnect_stops_the_retries() {
            use std::sync::atomic::Ordering;
            let (svc, checks) = flaky_service(usize::MAX);
            let svc = Arc::new(
                Arc::into_inner(svc)
                    .unwrap()
                    .with_intent(Intent::new(Box::new(MemoryStateFile::default()))),
            );
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Failed).await;
            let task = keep_trying(&svc);
            tokio::time::sleep(Duration::from_secs(60)).await;
            let tried = checks.load(Ordering::SeqCst);
            assert!(tried >= 2, "it kept trying while left on: {tried}");

            svc.dispatch(&Request::Disconnect).unwrap();
            until_status(&svc, ConnectionStatus::Disconnected).await;
            let at_disconnect = checks.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(3600)).await;
            assert_eq!(checks.load(Ordering::SeqCst), at_disconnect);
            assert_eq!(state_of(&svc).status, ConnectionStatus::Disconnected);
            task.abort();
        }

        /// Without a remembered intent (never turned on through this service), a failure stays a failure.
        #[tokio::test(start_paused = true)]
        async fn t148_nothing_is_retried_unless_left_on() {
            use std::sync::atomic::Ordering;
            let (svc, checks) = flaky_service(usize::MAX);
            svc.dispatch(&connect_request()).unwrap();
            until_status(&svc, ConnectionStatus::Failed).await;
            let task = keep_trying(&svc);
            tokio::time::sleep(Duration::from_secs(3600)).await;
            assert_eq!(checks.load(Ordering::SeqCst), 1);
            task.abort();
        }

        /// Connected, it is only looked at.
        #[tokio::test(start_paused = true)]
        async fn t148_a_healthy_connection_is_left_alone() {
            use crate::keep_trying::{Retry, Tick};
            let (svc, checks) = flaky_service(0);
            let svc = Arc::new(
                Arc::into_inner(svc)
                    .unwrap()
                    .with_intent(Intent::new(Box::new(MemoryStateFile::default()))),
            );
            svc.dispatch(&connect_request()).unwrap();
            assert_eq!(svc.retry_if_left_on(), Tick::InProgress);
            until_status(&svc, ConnectionStatus::Connected).await;
            assert_eq!(svc.retry_if_left_on(), Tick::Healthy);
            assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 1);
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
                enable_brutal(),
                Request::AddRule {
                    matcher: dnet_core::rule::RuleMatcher::Domain("example.com".into()),
                    action: dnet_core::rule::RuleAction::Tunnel,
                },
            ];

            // Being made, then up: both refuse.
            for phase in ["probing", "connected"] {
                for request in &during {
                    match svc.dispatch(request) {
                        Err(IpcError::InvalidRequest { detail }) => {
                            assert!(
                                detail.contains("disconnect"),
                                "{phase} {request:?}: {detail}"
                            );
                            // Shown to the person as it is: one sentence, no run of spaces.
                            assert!(!detail.contains("  "), "{detail:?}");
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

    // ------------------------------------------------------------------ T160: held changes

    /// A service built the way the real one is (changes that redirect traffic are held), with a
    /// store to save into.
    fn holding_configurable_service() -> (DnetService, Arc<MemoryStateFile>) {
        let (configurator, file) = memory_configurator();
        (holding_service().with_configurator(configurator), file)
    }

    /// The id a held change waits under, from the refusal that says so.
    fn held_id(reply: Result<String, IpcError>) -> String {
        match reply {
            Err(IpcError::ApprovalRequired { id, .. }) => id,
            other => panic!("expected the change to be held, got {other:?}"),
        }
    }

    fn pending_ids(svc: &DnetService) -> Vec<String> {
        json_of(svc.dispatch(&Request::ListPending))["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap().to_string())
            .collect()
    }

    fn add_home() -> Request {
        Request::AddEndpoint(Box::new(new_endpoint("home")))
    }

    #[test]
    fn a_new_server_is_held_not_applied_and_the_person_is_told_what_waits() {
        let (svc, file) = holding_configurable_service();
        match svc.dispatch(&add_home()) {
            Err(IpcError::ApprovalRequired { id, what }) => {
                assert!(what.contains("home"), "{what}");
                assert!(what.contains("Adding the server"), "{what}");
                assert!(!id.is_empty());
            }
            other => panic!("expected the change to be held, got {other:?}"),
        }
        // Nothing was applied and nothing was saved.
        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        assert!(listed["endpoints"].as_array().unwrap().is_empty());
        assert!(file.bytes().is_none(), "something was saved");
        assert_eq!(pending_ids(&svc).len(), 1);
    }

    #[test]
    fn approving_applies_exactly_the_held_change_once() {
        let (svc, file) = holding_configurable_service();
        let id = held_id(svc.dispatch(&add_home()));

        let reply = json_of(svc.dispatch(&Request::ApproveChange { id: id.clone() }));
        assert!(reply["endpoint"].is_string(), "{reply}");
        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        assert_eq!(listed["endpoints"][0]["label"], "home");
        let saved = dnet_config::persist::decode(&file.bytes().expect("saved")).unwrap();
        assert_eq!(saved.endpoints.len(), 1);
        assert!(pending_ids(&svc).is_empty());

        // The same approval again finds nothing: a change is applied once.
        match svc.dispatch(&Request::ApproveChange { id }) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("no change is waiting"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_withdrawn_change_is_never_applied() {
        let (svc, file) = holding_configurable_service();
        let id = held_id(svc.dispatch(&add_home()));
        assert_eq!(
            svc.dispatch(&Request::RejectChange { id: id.clone() })
                .unwrap(),
            APPLIED
        );
        assert!(pending_ids(&svc).is_empty());
        assert!(matches!(
            svc.dispatch(&Request::ApproveChange { id }),
            Err(IpcError::InvalidRequest { .. })
        ));
        assert!(file.bytes().is_none());
        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        assert!(listed["endpoints"].as_array().unwrap().is_empty());
    }

    #[test]
    fn asking_again_for_the_same_change_does_not_add_a_second_one() {
        let (svc, _file) = holding_configurable_service();
        let first = held_id(svc.dispatch(&add_home()));
        let again = held_id(svc.dispatch(&add_home()));
        assert_eq!(first, again);
        assert_eq!(pending_ids(&svc).len(), 1);
    }

    #[test]
    fn changes_that_can_only_tighten_things_are_applied_without_waiting() {
        let (svc, _file) = holding_configurable_service();
        let id = held_id(svc.dispatch(&add_home()));
        let added = json_of(svc.dispatch(&Request::ApproveChange { id }));
        let endpoint = id_in(&added);

        // Turning a server off, removing one, and tunnelling more are not held ...
        assert_eq!(
            svc.dispatch(&Request::SetEndpointEnabled {
                endpoint,
                enabled: false,
            })
            .unwrap(),
            APPLIED
        );
        json_of(svc.dispatch(&Request::AddRule {
            matcher: RuleMatcher::Domain("example.com".into()),
            action: RuleAction::Tunnel,
        }));
        assert_eq!(
            svc.dispatch(&Request::RemoveEndpoint { endpoint }).unwrap(),
            APPLIED
        );
        // ... and none of them left anything waiting.
        assert!(pending_ids(&svc).is_empty());
    }

    #[test]
    fn turning_a_server_on_waits_and_names_it() {
        let (svc, _file) = holding_configurable_service();
        let id = held_id(svc.dispatch(&add_home()));
        let endpoint = id_in(&json_of(svc.dispatch(&Request::ApproveChange { id })));
        svc.dispatch(&Request::SetEndpointEnabled {
            endpoint,
            enabled: false,
        })
        .unwrap();

        let turn_on = Request::SetEndpointEnabled {
            endpoint,
            enabled: true,
        };
        match svc.dispatch(&turn_on) {
            Err(IpcError::ApprovalRequired { id, what }) => {
                assert!(what.contains("Turning on"), "{what}");
                assert!(what.contains("home"), "{what}");
                json_of(svc.dispatch(&Request::ApproveChange { id }));
            }
            other => panic!("{other:?}"),
        }
        let listed = json_of(svc.dispatch(&Request::ListEndpoints));
        assert_eq!(listed["endpoints"][0]["enabled"], true);
    }

    #[test]
    fn turning_on_a_server_that_does_not_exist_is_not_held() {
        let (svc, _file) = holding_configurable_service();
        let reply = svc.dispatch(&Request::SetEndpointEnabled {
            endpoint: EndpointId::new(),
            enabled: true,
        });
        // The store says why; no prompt is raised for something that cannot happen.
        assert!(
            !matches!(reply, Err(IpcError::ApprovalRequired { .. })),
            "{reply:?}"
        );
        assert!(pending_ids(&svc).is_empty());
    }

    #[test]
    fn a_rule_that_goes_around_the_tunnel_waits_and_one_that_does_not_does_not() {
        let (svc, _file) = holding_configurable_service();
        let around = Request::AddRule {
            matcher: RuleMatcher::Domain("example.com".into()),
            action: RuleAction::Bypass,
        };
        match svc.dispatch(&around) {
            Err(IpcError::ApprovalRequired { what, .. }) => {
                assert!(what.contains("example.com"), "{what}");
                assert!(what.contains("around the tunnel"), "{what}");
            }
            other => panic!("{other:?}"),
        }
        let rules_before = json_of(svc.dispatch(&Request::ListRules));
        assert!(!rules_before.to_string().contains("example.com"));
        // The control: the same domain through the tunnel is applied at once.
        json_of(svc.dispatch(&Request::AddRule {
            matcher: RuleMatcher::Domain("example.com".into()),
            action: RuleAction::Tunnel,
        }));
        assert!(json_of(svc.dispatch(&Request::ListRules))
            .to_string()
            .contains("example.com"));
    }

    #[test]
    fn an_imported_feed_and_a_server_from_the_guide_wait_too() {
        let (svc, _file) = holding_configurable_service();
        let import = Request::ImportFeed(FeedImport::new(Some("{}".to_string()), None).unwrap());
        match svc.dispatch(&import) {
            Err(IpcError::ApprovalRequired { what, .. }) => {
                assert!(what.contains("Importing"), "{what}")
            }
            other => panic!("{other:?}"),
        }
        let finish = Request::FinishServer {
            label: "from the guide".into(),
            host: "203.0.113.9".into(),
            report: "{}".into(),
        };
        match svc.dispatch(&finish) {
            Err(IpcError::ApprovalRequired { what, .. }) => {
                assert!(what.contains("from the guide"), "{what}");
                assert!(what.contains("203.0.113.9"), "{what}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A change that fails when approved stays held, so the person need not ask for it again.
    #[test]
    fn a_change_that_fails_when_approved_stays_waiting() {
        let (svc, _file) = holding_configurable_service();
        let first = held_id(svc.dispatch(&add_home()));
        json_of(svc.dispatch(&Request::ApproveChange { id: first }));
        // Another server under the same name cannot be added; it is held all the same, and approving
        // it fails with the store's reason.
        let other = Request::AddEndpoint(Box::new(new_endpoint("home")));
        let second = held_id(svc.dispatch(&other));
        assert!(matches!(
            svc.dispatch(&Request::ApproveChange { id: second.clone() }),
            Err(IpcError::InvalidRequest { .. })
        ));
        assert_eq!(pending_ids(&svc), [second]);
    }

    #[test]
    fn only_so_many_changes_wait() {
        let (svc, _file) = holding_configurable_service();
        for n in 0..crate::approval::MAX_HELD {
            held_id(
                svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint(&format!(
                    "server{n}"
                ))))),
            );
        }
        match svc.dispatch(&Request::AddEndpoint(Box::new(new_endpoint(
            "one-too-many",
        )))) {
            Err(IpcError::InvalidRequest { detail }) => {
                assert!(detail.contains("too many changes"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(pending_ids(&svc).len(), crate::approval::MAX_HELD);
    }

    #[test]
    fn what_waits_is_listed_without_the_credentials_it_would_install() {
        let (svc, _file) = holding_configurable_service();
        held_id(svc.dispatch(&add_home()));
        let text = svc.dispatch(&Request::ListPending).unwrap();
        for word in ["credentials", "password", "private", "secret"] {
            assert!(!text.to_lowercase().contains(word), "{word} in {text}");
        }
        assert!(text.contains("home"));
    }

    #[test]
    fn a_label_with_control_characters_is_cleaned_before_it_reaches_a_prompt() {
        assert_eq!(shown("ho\u{7}me\nx"), "homex");
        let long = "a".repeat(200);
        assert!(shown(&long).chars().count() <= 67);
    }
}
