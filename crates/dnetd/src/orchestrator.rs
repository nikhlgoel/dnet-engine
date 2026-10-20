//! T126 — the Connect orchestrator: the layer that runs the connection engine.
//!
//! `dnet_core::engine::Engine` decides (it is pure: no I/O, no clock). Nothing before this module
//! *ran* it. The orchestrator owns one engine and is the only thing that talks to it:
//!
//! ```text
//!   IPC Connect/Disconnect ─┐                         ┌─▶ events ─▶ EventBus ─▶ subscribers
//!                           ├─▶ actor ─▶ Engine::step ┤
//!   results of background ──┘     ▲                   └─▶ work ─▶ executor ─▶ Effects (OS)
//!   work, tagged with an         └─────── reports ◀────────────────────┘
//!   attempt number
//! ```
//!
//! **One loop owns the state.** Every input (a request, a race result, a tunnel coming up, a live
//! check) is a message to the actor, which feeds the engine and carries out what it asks. Nothing
//! else touches the engine, so there are no locks around it and no interleavings to reason about.
//!
//! **Stale results are dropped, by construction.** The engine's own documentation lists this as the
//! known limit of its design: it gates late results by phase only. Every step that starts background
//! work takes a new *attempt number*, the work reports under it, and the actor ignores any report
//! whose number is not the current one. A race the user abandoned, a tunnel that was replaced, a
//! monitor from a connection that has ended: their results are discarded, not misapplied.
//!
//! **Work runs in order.** The engine sometimes asks for `StopTunnel` then `StartTunnel` in one step
//! (moving to another endpoint), and the order is what keeps traffic from leaking in between. One
//! executor performs the work of a step one item at a time, so that order is preserved. A race is
//! the exception: it is started in the background and can be cancelled while it runs.
//!
//! **What the OS does is behind [`Effects`].** This module has no routes, processes or sockets, so
//! all of the above is tested against a scripted fake on any machine. The real effects (probing
//! through the prober, starting the cores, installing routes) implement the same trait.
//!
//! The state shown to clients is derived from the engine after every message and is always
//! internally consistent: the wire encoder refuses an inconsistent snapshot, and a test checks that
//! every state the engine reaches encodes.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dnet_core::endpoint::Endpoint;
use dnet_core::engine::{Action, Engine, Environment, Input, Phase};
use dnet_core::failure::Reach;
use dnet_core::health::ProbeOutcome as EndpointProbeOutcome;
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::posture::RoutingPosture;
use dnet_core::probe::{ProfileProbe, RaceDecision};
use dnet_core::profile::ProfileKind;
use dnet_core::reprobe::LiveCheck;
use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;
use dnet_ipc::protocol::{
    ActiveEndpoint, ActiveProfile, ConnectionStatus, IpcError, StateSnapshot, Warning,
};
use dnet_ipc::wire::EventBus;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// The result of a race: the decision and what each probe that reported saw.
pub type RaceOutcome = (RaceDecision, Vec<(ProfileId, ProfileProbe)>);

/// Everything the orchestrator does to the machine and the network. The engine decides; this does.
///
/// The methods return `impl Future + Send` rather than being plain `async fn`: the orchestrator
/// runs them on spawned tasks, and the compiler can only see that a trait method's future is
/// `Send` if the trait says so. An implementation still writes ordinary `async fn`s.
pub trait Effects: Send + Sync + 'static {
    /// Facts about the machine the engine cannot observe itself (privilege, usable paths, portal).
    fn environment(&self) -> Environment;

    /// Whether each endpoint answers a plain reachability check made outside any profile, in the
    /// order given.
    fn reach(&self, endpoints: &[Endpoint]) -> impl Future<Output = Vec<Reach>> + Send;

    /// Race `profiles` against `endpoint`. Returns the decision, or `None` if `cancel` fired first.
    fn race(
        &self,
        profiles: Vec<ProfileId>,
        endpoint: EndpointId,
        cancel: CancellationToken,
    ) -> impl Future<Output = Option<RaceOutcome>> + Send;

    /// Bring `profile` up against `endpoint`: routes first, then the tunnel (R4). `Err` says why it
    /// could not be, as one of the seven user-facing causes.
    fn start_tunnel(
        &self,
        profile: &ProfileId,
        endpoint: EndpointId,
    ) -> impl Future<Output = Result<(), FailureCause>> + Send;

    /// Take the tunnel down and undo what bringing it up did. Idempotent.
    fn stop_tunnel(&self) -> impl Future<Output = ()> + Send;

    /// One check that the carrying profile still moves traffic.
    fn live_check(&self, profile: &ProfileId) -> impl Future<Output = LiveCheck> + Send;

    /// One health probe of `endpoint`.
    fn probe_endpoint(
        &self,
        endpoint: EndpointId,
    ) -> impl Future<Output = EndpointProbeOutcome> + Send;
}

/// How often a connected tunnel is checked.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Between live checks of the carrying profile.
    pub live_check_every: Duration,
    /// Between health probes of the endpoint in use. Each is made on a live-check tick.
    pub endpoint_probe_every: Duration,
    /// How long the direct reachability check may take before the answer is "unknown".
    pub reach_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            live_check_every: Duration::from_secs(5),
            endpoint_probe_every: Duration::from_secs(15),
            reach_timeout: Duration::from_secs(3),
        }
    }
}

// ------------------------------------------------------------------ messages

enum Msg {
    Connect {
        profile: Option<ProfileId>,
    },
    Disconnect,
    /// The service is stopping: disconnect, and say when the work that took has finished.
    Shutdown {
        done: oneshot::Sender<()>,
    },
    /// A result of background work, valid only if `attempt` is still current.
    Report {
        attempt: u64,
        input: Input,
    },
}

struct Work {
    attempt: u64,
    kind: WorkKind,
}

enum WorkKind {
    Reach(Vec<Endpoint>),
    StartRace {
        profiles: Vec<ProfileId>,
        endpoint: EndpointId,
    },
    CancelRace,
    StartTunnel {
        profile: ProfileId,
        endpoint: EndpointId,
    },
    StopTunnel,
    /// Everything queued before this has been carried out.
    Barrier(oneshot::Sender<()>),
}

// ------------------------------------------------------------------ the handle

/// What the IPC layer holds: a way to ask, and the latest state to answer with.
#[derive(Clone)]
pub struct Handle {
    messages: mpsc::Sender<Msg>,
    state: Arc<Mutex<StateSnapshot>>,
    /// A connect has been accepted and the actor has not yet published the state it led to. The
    /// published state alone cannot answer "is a connect already under way?": it lags the request
    /// by however long the actor takes, and two quick connects would both see "disconnected".
    connecting: Arc<AtomicBool>,
}

impl Handle {
    /// Ask to connect, optionally with one named profile. Progress arrives on the event stream, not
    /// here (contract §Connect).
    ///
    /// `ServiceBusy` (retryable) if a connection is already being made or is up: the engine ignores
    /// a connect in those phases, and a request that silently did nothing would be a defect.
    pub fn connect(&self, profile: Option<ProfileId>) -> Result<(), IpcError> {
        // Claim the connect first. Only one request can hold it, so a second one is refused rather
        // than accepted and then ignored by the engine.
        if self
            .connecting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(IpcError::ServiceBusy);
        }
        // The stored state, not `snapshot()`: that one reads as connecting while this very request
        // is pending, which would make every connect refuse itself.
        if matches!(
            self.stored().status,
            ConnectionStatus::Probing | ConnectionStatus::Connected
        ) {
            self.connecting.store(false, Ordering::SeqCst);
            return Err(IpcError::ServiceBusy);
        }
        self.messages
            .try_send(Msg::Connect { profile })
            .map_err(|_| {
                self.connecting.store(false, Ordering::SeqCst);
                IpcError::ServiceBusy
            })
    }

    /// Ask to disconnect. `NotConnected` if nothing is connected or being connected; a failed
    /// attempt may be disconnected, which clears it.
    pub fn disconnect(&self) -> Result<(), IpcError> {
        if self.snapshot().status == ConnectionStatus::Disconnected {
            return Err(IpcError::NotConnected);
        }
        self.messages
            .try_send(Msg::Disconnect)
            .map_err(|_| IpcError::ServiceBusy)
    }

    /// Disconnect for good, and return once the work that took has been carried out: the tunnel is
    /// stopped, or the start that was under way has finished and its tunnel been stopped. After
    /// this nothing can connect. For the service stopping, which must not leave a tunnel behind
    /// (SUP-04).
    pub async fn shutdown(&self) {
        let (done, finished) = oneshot::channel();
        if self.messages.send(Msg::Shutdown { done }).await.is_err() {
            // Already shut down.
            return;
        }
        // An error means the orchestrator ended without answering; there is nothing left to wait for.
        let _ = finished.await;
    }

    /// The state as the actor last published it.
    fn stored(&self) -> StateSnapshot {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The current state. Always internally consistent.
    ///
    /// A connect that has been accepted but not yet taken up by the actor is already *connecting*:
    /// until the actor publishes the state it led to, the stored state is the one before the
    /// request, and a client that asked and looked straight back would be told the connection it
    /// just requested had not started, or (after an earlier failure) had failed. So while a connect
    /// is pending the state reads `Probing`, which is consistent for any state it replaces.
    pub fn snapshot(&self) -> StateSnapshot {
        let mut state = self.stored();
        if self.connecting.load(Ordering::SeqCst)
            && matches!(
                state.status,
                ConnectionStatus::Disconnected | ConnectionStatus::Failed
            )
        {
            state = StateSnapshot {
                status: ConnectionStatus::Probing,
                active_profile: None,
                active_endpoint: None,
                failure: None,
                warnings: Vec::new(),
                posture: RoutingPosture::FailClosed,
            };
        }
        state
    }
}

// ------------------------------------------------------------------ starting it

/// Start the orchestrator on the current runtime. Returns the handle the IPC layer uses.
pub fn spawn<E: Effects>(engine: Engine, effects: Arc<E>, bus: EventBus, timing: Timing) -> Handle {
    let (message_tx, message_rx) = mpsc::channel::<Msg>(64);
    // Work is never awaited by the actor, so the actor can never block on the executor while the
    // executor blocks on reporting back to the actor.
    let (work_tx, work_rx) = mpsc::unbounded_channel::<Work>();
    let current = Arc::new(AtomicU64::new(0));
    let connecting = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(snapshot_of(&engine)));

    tokio::spawn(execute(
        Arc::clone(&effects),
        work_rx,
        message_tx.clone(),
        timing,
    ));
    let actor = Actor {
        engine,
        effects,
        bus,
        timing,
        work: work_tx,
        reports: message_tx.clone(),
        attempt: 0,
        current,
        connecting: Arc::clone(&connecting),
        state: Arc::clone(&state),
    };
    tokio::spawn(actor.run(message_rx));

    Handle {
        messages: message_tx,
        state,
        connecting,
    }
}

// ------------------------------------------------------------------ the actor

struct Actor<E: Effects> {
    engine: Engine,
    effects: Arc<E>,
    bus: EventBus,
    timing: Timing,
    work: mpsc::UnboundedSender<Work>,
    reports: mpsc::Sender<Msg>,
    /// The number of the latest step that started background work.
    attempt: u64,
    /// `attempt`, readable by background tasks so they can tell they have been superseded.
    current: Arc<AtomicU64>,
    /// See [`Handle`]: cleared once the state a connect led to has been published.
    connecting: Arc<AtomicBool>,
    state: Arc<Mutex<StateSnapshot>>,
}

impl<E: Effects> Actor<E> {
    async fn run(mut self, mut messages: mpsc::Receiver<Msg>) {
        while let Some(message) = messages.recv().await {
            let was_connect = matches!(message, Msg::Connect { .. });
            match message {
                Msg::Connect { profile } => self.connect(profile),
                Msg::Disconnect => self.step(Input::Disconnect, false),
                Msg::Shutdown { done } => {
                    self.step(Input::Disconnect, false);
                    // Queued behind whatever that asked for, and behind any start still under way,
                    // so it fires only when all of it has been carried out.
                    let _ = self.work.send(Work {
                        attempt: self.attempt,
                        kind: WorkKind::Barrier(done),
                    });
                    self.publish_state();
                    // Nothing after this is accepted: a connect now would start what the process
                    // is about to leave behind.
                    return;
                }
                Msg::Report { attempt, input } => {
                    if attempt == self.attempt {
                        self.step(input, false);
                    } else {
                        tracing::debug!(attempt, current = self.attempt, "dropped a stale report");
                    }
                }
            }
            self.publish_state();
            if was_connect {
                // After the state is published, never before: while this flag is clear, the
                // published state is what a new request is judged against.
                self.connecting.store(false, Ordering::SeqCst);
            }
        }
    }

    fn connect(&mut self, profile: Option<ProfileId>) {
        // A new connect starts a new story: the previous session's events are not replayed to it.
        self.bus.begin_session();
        self.engine
            .step(Input::Environment(self.effects.environment()), now());
        self.step(Input::Connect { profile }, true);
    }

    /// Feed the engine one input and carry out what it asks. `check_reach` queues a direct
    /// reachability check ahead of the step's other work: the engine wants it before a race result.
    fn step(&mut self, input: Input, check_reach: bool) {
        let was_connected = matches!(self.engine.phase(), Phase::Connected { .. });
        let actions = self.engine.step(input, now());

        let mut work = Vec::new();
        for action in actions {
            match action {
                Action::Emit(event) => {
                    if let Err(e) = self.bus.publish(&event) {
                        // A producer without a real `because` is a defect; say so, keep going.
                        tracing::error!(error = %e, ?event, "an event could not be published");
                    }
                }
                Action::StartRace { profiles, endpoint } => {
                    work.push(WorkKind::StartRace { profiles, endpoint })
                }
                Action::CancelRace => work.push(WorkKind::CancelRace),
                Action::StartTunnel { profile, endpoint } => {
                    work.push(WorkKind::StartTunnel { profile, endpoint })
                }
                Action::StopTunnel => work.push(WorkKind::StopTunnel),
                // Shown to the user through the snapshot's warnings, not as work.
                Action::WarnTier2 { .. } => {}
            }
        }

        if !work.is_empty() {
            // Everything this step starts shares one attempt number; whatever the previous step
            // started is now stale.
            self.attempt += 1;
            self.current.store(self.attempt, Ordering::SeqCst);
            if check_reach {
                work.insert(0, WorkKind::Reach(self.engine.endpoints().to_vec()));
            }
            for kind in work {
                let _ = self.work.send(Work {
                    attempt: self.attempt,
                    kind,
                });
            }
        }

        if !was_connected {
            if let Phase::Connected { profile, endpoint } = self.engine.phase().clone() {
                self.start_monitor(profile, endpoint);
            }
        }
    }

    /// Watch a connection that has just come up: live checks, and health probes of its endpoint.
    /// It ends by itself when the attempt it belongs to is replaced.
    fn start_monitor(&self, profile: ProfileId, endpoint: EndpointId) {
        let (effects, reports, current, timing) = (
            Arc::clone(&self.effects),
            self.reports.clone(),
            Arc::clone(&self.current),
            self.timing,
        );
        let attempt = self.attempt;
        let probe_every = (timing.endpoint_probe_every.as_millis()
            / timing.live_check_every.as_millis().max(1))
        .max(1) as u64;
        tokio::spawn(async move {
            let mut tick: u64 = 0;
            loop {
                tokio::time::sleep(timing.live_check_every).await;
                if current.load(Ordering::SeqCst) != attempt {
                    return;
                }
                tick += 1;
                let mut inputs = vec![Input::Environment(effects.environment())];
                inputs.push(Input::LiveCheck(effects.live_check(&profile).await));
                if tick % probe_every == 0 {
                    inputs.push(Input::EndpointProbe {
                        endpoint,
                        outcome: effects.probe_endpoint(endpoint).await,
                    });
                }
                for input in inputs {
                    if current.load(Ordering::SeqCst) != attempt {
                        return;
                    }
                    if reports.send(Msg::Report { attempt, input }).await.is_err() {
                        return;
                    }
                }
            }
        });
    }

    fn publish_state(&self) {
        let snapshot = snapshot_of(&self.engine);
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = snapshot;
    }
}

fn now() -> std::time::Instant {
    // Tokio's clock, so a test that pauses time controls the engine's notion of it too.
    tokio::time::Instant::now().into_std()
}

// ------------------------------------------------------------------ the executor

async fn execute<E: Effects>(
    effects: Arc<E>,
    mut work: mpsc::UnboundedReceiver<Work>,
    reports: mpsc::Sender<Msg>,
    timing: Timing,
) {
    let mut race: Option<CancellationToken> = None;
    while let Some(Work { attempt, kind }) = work.recv().await {
        match kind {
            WorkKind::Reach(endpoints) => {
                let answer = tokio::time::timeout(timing.reach_timeout, effects.reach(&endpoints))
                    .await
                    .unwrap_or_else(|_| vec![Reach::Unknown; endpoints.len()]);
                let _ = reports
                    .send(Msg::Report {
                        attempt,
                        input: Input::Reach(answer),
                    })
                    .await;
            }
            WorkKind::StartRace { profiles, endpoint } => {
                if let Some(previous) = race.take() {
                    previous.cancel();
                }
                let token = CancellationToken::new();
                race = Some(token.clone());
                let (effects, reports) = (Arc::clone(&effects), reports.clone());
                tokio::spawn(async move {
                    let outcome = effects.race(profiles, endpoint, token.clone()).await;
                    // A cancelled race reports nothing: its result would be for a connect that no
                    // longer exists.
                    if let (Some((decision, results)), false) = (outcome, token.is_cancelled()) {
                        let _ = reports
                            .send(Msg::Report {
                                attempt,
                                input: Input::RaceFinished { decision, results },
                            })
                            .await;
                    }
                });
            }
            WorkKind::CancelRace => {
                if let Some(token) = race.take() {
                    token.cancel();
                }
            }
            WorkKind::StartTunnel { profile, endpoint } => {
                if let Some(token) = race.take() {
                    token.cancel();
                }
                let input = match effects.start_tunnel(&profile, endpoint).await {
                    Ok(()) => Input::TunnelUp,
                    Err(cause) => Input::StartFailed(cause),
                };
                let _ = reports.send(Msg::Report { attempt, input }).await;
            }
            WorkKind::StopTunnel => effects.stop_tunnel().await,
            WorkKind::Barrier(done) => {
                let _ = done.send(());
            }
        }
    }
}

// ------------------------------------------------------------------ what clients see

/// The wire name of a profile kind (`ListProfiles` uses the same words).
fn kind_name(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::AmneziaWg => "AmneziaWg",
        ProfileKind::Hysteria2 => "Hysteria2",
        ProfileKind::VlessReality => "VlessReality",
    }
}

/// The state a client is shown, derived from the engine. Always consistent: the wire encoder
/// refuses a snapshot that contradicts itself, and a test pins that every phase encodes.
pub fn snapshot_of(engine: &Engine) -> StateSnapshot {
    let carrying = match engine.phase() {
        Phase::Connected { profile, endpoint } => {
            let profile = engine.profiles().iter().find(|p| p.id() == profile);
            let endpoint = engine.endpoints().iter().find(|e| e.id() == *endpoint);
            profile.zip(endpoint)
        }
        _ => None,
    };
    let status = match engine.phase() {
        Phase::Idle => ConnectionStatus::Disconnected,
        Phase::Probing | Phase::Starting { .. } | Phase::Recovering => ConnectionStatus::Probing,
        Phase::Connected { .. } => ConnectionStatus::Connected,
        Phase::Failed(_) => ConnectionStatus::Failed,
    };
    let failure = match engine.phase() {
        Phase::Failed(cause) => Some(cause.clone()),
        _ => None,
    };

    let (active_profile, active_endpoint, warnings, posture) = match (status, carrying) {
        (ConnectionStatus::Connected, Some((profile, endpoint))) => {
            let tier = profile.tier();
            let mut warnings = Vec::new();
            if tier == FailoverTier::Tier2 {
                warnings.push(Warning::Tier2ProfileActive);
            }
            if profile.brutal().is_some() {
                warnings.push(Warning::BrutalEnabled);
            }
            (
                Some(ActiveProfile {
                    id: profile.id().as_str().to_owned(),
                    kind: kind_name(profile.kind()).to_owned(),
                    tier,
                }),
                Some(ActiveEndpoint {
                    id: endpoint.id().to_string(),
                    label: endpoint.label().to_owned(),
                }),
                warnings,
                RoutingPosture::Tunnelled { tier },
            )
        }
        // Not carrying anything. If the engine says "connected" but names a profile or endpoint it
        // does not have, that is a defect, and showing "probing" with the fail-closed posture is
        // the safe way to be wrong.
        _ => (None, None, Vec::new(), RoutingPosture::FailClosed),
    };
    let status = if status == ConnectionStatus::Connected && active_profile.is_none() {
        ConnectionStatus::Probing
    } else {
        status
    };

    StateSnapshot {
        status,
        active_profile,
        active_endpoint,
        failure,
        warnings,
        posture,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;

    use dnet_core::credential::CredentialRef;
    use dnet_core::endpoint::{EndpointAddress, EndpointOrigin};
    use dnet_core::profile::{ConnectionProfile, ProfileParams};
    use dnet_ipc::protocol::encode_state_snapshot;
    use dnet_ipc::wire::decode_event_view;

    use super::*;

    // ---------------------------------------------------------------- fixtures

    fn profile(id: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new(id), kind, ProfileParams::new())
    }

    fn profiles() -> Vec<ConnectionProfile> {
        vec![
            profile("awg-default", ProfileKind::AmneziaWg),
            profile("hy2-default", ProfileKind::Hysteria2),
            profile("reality-default", ProfileKind::VlessReality),
        ]
    }

    fn endpoint(label: &str) -> Endpoint {
        Endpoint::new(
            EndpointId::new(),
            label,
            EndpointAddress::new("203.0.113.10", 51820).unwrap(),
            EndpointOrigin::Manual,
            CredentialRef::new(format!("endpoint-{label}")),
        )
        .unwrap()
    }

    fn id(name: &str) -> ProfileId {
        ProfileId::new(name)
    }

    fn selected(name: &str) -> RaceOutcome {
        (
            RaceDecision::Selected {
                profile: id(name),
                tier: FailoverTier::Tier2,
                bits_per_sec: 12_000_000,
            },
            vec![(
                id(name),
                ProfileProbe::Transferred {
                    bytes: 1_000_000,
                    elapsed: Duration::from_secs(1),
                },
            )],
        )
    }

    /// What the fake does, scripted per call, and what it was asked to do, in order.
    struct Script {
        environment: Mutex<Environment>,
        races: Mutex<VecDeque<Option<RaceOutcome>>>,
        tunnels: Mutex<VecDeque<Result<(), FailureCause>>>,
        checks: Mutex<VecDeque<LiveCheck>>,
        calls: Mutex<Vec<String>>,
        /// A race waits for cancellation before answering, to let a test act while it runs.
        hold_race: AtomicBool,
        race_cancelled: AtomicBool,
        /// Stopping takes this long, so a start that wrongly overtook it would show.
        stop_delay: Mutex<Duration>,
        /// Starting a tunnel takes this long, and cannot be cancelled once begun.
        start_delay: Mutex<Duration>,
        /// What the direct reachability check finds, and how long it takes to find it.
        reach_answer: Mutex<Reach>,
        reach_delay: Mutex<Duration>,
        /// Health probes of this endpoint fail.
        failing_endpoint: Mutex<Option<EndpointId>>,
    }

    impl Script {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                environment: Mutex::new(Environment::default()),
                races: Mutex::new(VecDeque::new()),
                tunnels: Mutex::new(VecDeque::new()),
                checks: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
                hold_race: AtomicBool::new(false),
                race_cancelled: AtomicBool::new(false),
                stop_delay: Mutex::new(Duration::ZERO),
                start_delay: Mutex::new(Duration::ZERO),
                reach_answer: Mutex::new(Reach::Reachable),
                reach_delay: Mutex::new(Duration::ZERO),
                failing_endpoint: Mutex::new(None),
            })
        }
        fn record(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Effects for Script {
        fn environment(&self) -> Environment {
            self.environment.lock().unwrap().clone()
        }
        async fn reach(&self, endpoints: &[Endpoint]) -> Vec<Reach> {
            let delay = *self.reach_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            self.record("reach");
            vec![*self.reach_answer.lock().unwrap(); endpoints.len()]
        }
        async fn race(
            &self,
            profiles: Vec<ProfileId>,
            _endpoint: EndpointId,
            cancel: CancellationToken,
        ) -> Option<RaceOutcome> {
            self.record(format!(
                "race[{}]",
                profiles
                    .iter()
                    .map(ProfileId::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            if self.hold_race.load(Ordering::SeqCst) {
                cancel.cancelled().await;
                self.race_cancelled.store(true, Ordering::SeqCst);
                return None;
            }
            self.races.lock().unwrap().pop_front().flatten()
        }
        async fn start_tunnel(
            &self,
            profile: &ProfileId,
            _endpoint: EndpointId,
        ) -> Result<(), FailureCause> {
            self.record(format!("start[{profile}]"));
            let delay = *self.start_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            self.tunnels.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
        async fn stop_tunnel(&self) {
            let delay = *self.stop_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            self.record("stop");
        }
        async fn live_check(&self, _profile: &ProfileId) -> LiveCheck {
            self.record("check");
            self.checks
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(LiveCheck::Passed)
        }
        async fn probe_endpoint(&self, endpoint: EndpointId) -> EndpointProbeOutcome {
            self.record("probe-endpoint");
            if *self.failing_endpoint.lock().unwrap() == Some(endpoint) {
                return EndpointProbeOutcome::Failed;
            }
            EndpointProbeOutcome::Ok {
                rtt: Duration::from_millis(40),
                loss: false,
            }
        }
    }

    fn timing() -> Timing {
        Timing {
            live_check_every: Duration::from_secs(1),
            endpoint_probe_every: Duration::from_secs(3),
            reach_timeout: Duration::from_secs(1),
        }
    }

    struct Rig {
        handle: Handle,
        script: Arc<Script>,
        bus: EventBus,
    }

    fn rig_with(script: Arc<Script>, endpoints: Vec<Endpoint>) -> Rig {
        let bus = EventBus::new();
        let handle = spawn(
            Engine::new(profiles(), endpoints),
            Arc::clone(&script),
            bus.clone(),
            timing(),
        );
        Rig {
            handle,
            script,
            bus,
        }
    }

    fn rig() -> Rig {
        rig_with(Script::new(), vec![endpoint("home")])
    }

    /// Wait (in paused time, so instantly) until the state satisfies `done`, checking on the way
    /// that every state seen is one a client could be sent.
    async fn until(handle: &Handle, done: impl Fn(&StateSnapshot) -> bool) -> StateSnapshot {
        for _ in 0..2000 {
            let snapshot = handle.snapshot();
            encode_state_snapshot(&snapshot).unwrap_or_else(|e| {
                panic!("an inconsistent snapshot was exposed: {e}: {snapshot:?}")
            });
            if done(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the state never became what the test waits for; last: {:?}",
            handle.snapshot()
        );
    }

    fn event_names(bus: &EventBus) -> Vec<String> {
        bus.subscribe()
            .unwrap()
            .backlog
            .iter()
            .map(|frame| {
                decode_event_view(frame)
                    .expect("every event carries a real because")
                    .event
            })
            .collect()
    }

    // ---------------------------------------------------------------- the happy path

    #[tokio::test(start_paused = true)]
    async fn a_connect_races_selects_starts_and_connects() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));

        rig.handle.connect(None).unwrap();
        let connected = until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;

        let profile = connected
            .active_profile
            .expect("a connected state names its profile");
        assert_eq!(profile.id, "hy2-default");
        assert_eq!(profile.kind, "Hysteria2");
        assert_eq!(connected.active_endpoint.unwrap().label, "home");
        assert!(matches!(
            connected.posture,
            RoutingPosture::Tunnelled { .. }
        ));
        // Every profile is Tier 2 until HV-07 is recorded, and the user is told.
        assert!(connected.warnings.contains(&Warning::Tier2ProfileActive));

        let calls = rig.script.calls();
        let first = |name: &str| calls.iter().position(|c| c.starts_with(name)).unwrap();
        assert!(
            first("reach") < first("race"),
            "reach is checked before the race: {calls:?}"
        );
        assert!(
            first("race") < first("start"),
            "the race decides before a tunnel starts: {calls:?}"
        );
        assert_eq!(calls.iter().filter(|c| c.starts_with("start")).count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn every_event_explains_itself() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;

        // `event_names` decodes each frame with the client rules: a real `because`, never blank.
        let names = event_names(&rig.bus);
        assert!(names.contains(&"ProbeStarted".to_string()), "{names:?}");
        assert!(names.contains(&"ProfileSelected".to_string()), "{names:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_posture_is_fail_closed_until_a_tunnel_is_up() {
        let rig = rig();
        assert_eq!(rig.handle.snapshot().posture, RoutingPosture::FailClosed);
        rig.script.hold_race.store(true, Ordering::SeqCst);
        rig.handle.connect(None).unwrap();
        let probing = until(&rig.handle, |s| s.status == ConnectionStatus::Probing).await;
        assert_eq!(probing.posture, RoutingPosture::FailClosed);
        assert!(probing.active_profile.is_none() && probing.active_endpoint.is_none());
    }

    // ---------------------------------------------------------------- failure

    #[tokio::test(start_paused = true)]
    async fn when_nothing_is_usable_the_failure_says_why() {
        let rig = rig();
        rig.script.races.lock().unwrap().push_back(Some((
            RaceDecision::NoneUsable,
            vec![
                (id("hy2-default"), ProfileProbe::HandshakeFailed),
                (id("reality-default"), ProfileProbe::HandshakeFailed),
            ],
        )));
        // AmneziaWG is the last resort once the raced profiles fail; it fails to start too.
        rig.script
            .tunnels
            .lock()
            .unwrap()
            .push_back(Err(FailureCause::AllProfilesBlocked));

        rig.handle.connect(None).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;

        assert_eq!(failed.failure, Some(FailureCause::AllProfilesBlocked));
        assert_eq!(failed.posture, RoutingPosture::FailClosed);
        assert!(failed.active_profile.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_tunnel_that_cannot_start_is_a_failure_not_a_retry() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.script
            .tunnels
            .lock()
            .unwrap()
            .push_back(Err(FailureCause::CoreFailedPersistently {
                core: dnet_core::profile::CoreBinding::PrimaryCore,
            }));

        rig.handle.connect(None).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;

        assert!(matches!(
            failed.failure,
            Some(FailureCause::CoreFailedPersistently { .. })
        ));
        let starts = rig
            .script
            .calls()
            .iter()
            .filter(|c| c.starts_with("start"))
            .count();
        assert_eq!(
            starts, 1,
            "a failure to start is reported, not retried on another profile"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_named_profile_that_does_not_exist_fails_with_a_message_that_names_it() {
        let rig = rig();
        rig.handle.connect(Some(id("nonesuch"))).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;
        match failed.failure {
            Some(FailureCause::ConfigurationInvalid { detail }) => {
                assert!(detail.contains("nonesuch"), "{detail}")
            }
            other => panic!("expected ConfigurationInvalid, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn without_privilege_nothing_is_attempted() {
        let script = Script::new();
        script.environment.lock().unwrap().privileged = false;
        let rig = rig_with(script, vec![endpoint("home")]);
        rig.handle.connect(None).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;
        assert_eq!(failed.failure, Some(FailureCause::InsufficientPrivilege));
        let calls = rig.script.calls();
        assert!(
            calls
                .iter()
                .all(|c| !c.starts_with("race") && !c.starts_with("start")),
            "no probe or tunnel may start without privilege: {calls:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_endpoint_configured_it_fails_at_once_and_says_what_to_do() {
        let rig = rig_with(Script::new(), vec![]);
        rig.handle.connect(None).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;
        match failed.failure {
            Some(FailureCause::ConfigurationInvalid { detail }) => {
                assert!(detail.contains("add one"), "{detail}")
            }
            other => panic!("expected an actionable ConfigurationInvalid, got {other:?}"),
        }
        assert!(
            rig.script
                .calls()
                .iter()
                .all(|c| !c.starts_with("race") && !c.starts_with("start")),
            "nothing may be attempted with no endpoint"
        );
    }

    // ---------------------------------------------------------------- disconnect and stale results

    #[tokio::test(start_paused = true)]
    async fn disconnecting_during_a_race_cancels_it_and_ignores_its_late_result() {
        let rig = rig();
        rig.script.hold_race.store(true, Ordering::SeqCst);
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Probing).await;

        rig.handle.disconnect().unwrap();
        let idle = until(&rig.handle, |s| s.status == ConnectionStatus::Disconnected).await;

        assert!(idle.active_profile.is_none());
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            rig.script.race_cancelled.load(Ordering::SeqCst),
            "the race must be cancelled"
        );
        assert_eq!(rig.handle.snapshot().status, ConnectionStatus::Disconnected);
        assert!(
            rig.script.calls().iter().all(|c| !c.starts_with("start")),
            "no tunnel may start for a connect that was abandoned"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disconnecting_a_live_tunnel_stops_it_and_ends_the_monitoring() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            rig.script.calls().iter().any(|c| c == "check"),
            "a connected tunnel is checked"
        );

        rig.handle.disconnect().unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Disconnected).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(rig.script.calls().iter().any(|c| c == "stop"));
        let checks_after_stop = rig.script.calls().iter().filter(|c| *c == "check").count();
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            rig.script.calls().iter().filter(|c| *c == "check").count(),
            checks_after_stop,
            "a disconnected tunnel must not keep being checked"
        );
    }

    // ---------------------------------------------------------------- shutting down

    /// The service stopping must not leave a tunnel behind (SUP-04): shutdown returns only once
    /// the stop has actually been carried out, however long that takes.
    #[tokio::test(start_paused = true)]
    async fn shutting_down_a_live_tunnel_waits_for_it_to_be_stopped() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
        *rig.script.stop_delay.lock().unwrap() = Duration::from_secs(5);

        rig.handle.shutdown().await;

        assert!(
            rig.script.calls().iter().any(|c| c == "stop"),
            "shutdown returned before the tunnel was stopped: {:?}",
            rig.script.calls()
        );
        assert_eq!(rig.handle.snapshot().status, ConnectionStatus::Disconnected);
    }

    /// A tunnel that is still being started cannot be interrupted, so shutdown waits for it and
    /// then stops what it produced: stopping first would leave the new tunnel running.
    #[tokio::test(start_paused = true)]
    async fn shutting_down_during_a_start_stops_the_tunnel_that_start_produces() {
        let rig = rig();
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        *rig.script.start_delay.lock().unwrap() = Duration::from_secs(5);
        rig.handle.connect(None).unwrap();
        while !rig.script.calls().iter().any(|c| c.starts_with("start")) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        rig.handle.shutdown().await;

        let calls = rig.script.calls();
        let start = calls.iter().position(|c| c.starts_with("start")).unwrap();
        let stop = calls.iter().position(|c| c == "stop");
        assert!(
            stop.is_some_and(|stop| stop > start),
            "the tunnel the start produced is stopped: {calls:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn after_shutdown_nothing_can_connect() {
        let rig = rig();

        rig.handle.shutdown().await;

        assert_eq!(rig.handle.connect(None), Err(IpcError::ServiceBusy));
    }

    #[tokio::test(start_paused = true)]
    async fn shutting_down_when_idle_returns_without_stopping_anything() {
        let rig = rig();

        rig.handle.shutdown().await;

        assert!(rig.script.calls().is_empty(), "{:?}", rig.script.calls());
    }

    #[tokio::test(start_paused = true)]
    async fn connect_and_disconnect_answer_honestly_about_the_state() {
        let rig = rig();
        assert_eq!(rig.handle.disconnect(), Err(IpcError::NotConnected));

        rig.script.hold_race.store(true, Ordering::SeqCst);
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Probing).await;
        assert_eq!(rig.handle.connect(None), Err(IpcError::ServiceBusy));
    }

    /// Asked and looked straight back, before the actor has run: the connection just requested is
    /// being made, not "not started". Found by the first client that polled right after Connect.
    #[tokio::test(start_paused = true)]
    async fn a_connect_that_was_just_accepted_already_reads_as_connecting() {
        let rig = rig();
        rig.handle.connect(None).unwrap();

        let straight_away = rig.handle.snapshot();

        assert_eq!(straight_away.status, ConnectionStatus::Probing);
        encode_state_snapshot(&straight_away)
            .expect("the interim state is one a client can be sent");
        // And it settles into whatever the connect really led to.
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
    }

    /// The same window after a failed attempt: a retry must not read as the old failure.
    #[tokio::test(start_paused = true)]
    async fn a_retry_after_a_failure_does_not_read_as_the_old_failure() {
        let rig = rig_with(Script::new(), vec![]);
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;

        rig.handle.connect(None).unwrap();

        assert_eq!(rig.handle.snapshot().status, ConnectionStatus::Probing);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_attempt_can_be_cleared_and_tried_again() {
        let rig = rig();
        rig.handle.connect(Some(id("nonesuch"))).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;

        rig.handle.disconnect().unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Disconnected).await;

        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
    }

    // ---------------------------------------------------------------- a connection that is blocked

    #[tokio::test(start_paused = true)]
    async fn a_blocked_tunnel_is_stopped_before_another_profile_is_found() {
        let rig = rig();
        {
            let mut races = rig.script.races.lock().unwrap();
            races.push_back(Some(selected("hy2-default")));
            races.push_back(Some(selected("reality-default")));
            // Three failed checks in a row is a block (FR-005).
            let mut checks = rig.script.checks.lock().unwrap();
            checks.extend([LiveCheck::Failed, LiveCheck::Failed, LiveCheck::Failed]);
        }
        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| {
            s.active_profile
                .as_ref()
                .is_some_and(|p| p.id == "reality-default")
        })
        .await;

        let calls = rig.script.calls();
        let stop = calls
            .iter()
            .position(|c| c == "stop")
            .expect("the blocked tunnel was stopped");
        let second_race = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| c.starts_with("race"))
            .nth(1)
            .map(|(i, _)| i)
            .expect("another race was run");
        assert!(
            stop < second_race,
            "stop before the replacement is sought: {calls:?}"
        );
        let names = event_names(&rig.bus);
        assert!(names.contains(&"ProfileBlocked".to_string()), "{names:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn moving_to_another_endpoint_stops_the_old_tunnel_fully_before_starting_the_new_one() {
        // Two endpoints; the one in use stops answering its health probes. The engine then asks
        // for StopTunnel and StartTunnel in a single step, and the order is what keeps traffic
        // from leaking in between. A slow stop makes a start that overtook it visible.
        let first = endpoint("first");
        let script = Script::new();
        *script.stop_delay.lock().unwrap() = Duration::from_millis(700);
        *script.failing_endpoint.lock().unwrap() = Some(first.id());
        script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        let rig = rig_with(script, vec![first, endpoint("second")]);

        rig.handle.connect(None).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
        // Health ticks until the first endpoint is declared unreachable and the tunnel moves.
        for _ in 0..600 {
            if rig
                .script
                .calls()
                .iter()
                .filter(|c| c.starts_with("start"))
                .count()
                >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let calls = rig.script.calls();
        let starts: Vec<usize> = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| c.starts_with("start"))
            .map(|(i, _)| i)
            .collect();
        assert!(
            starts.len() >= 2,
            "the connection never moved to the other endpoint: {calls:?}"
        );
        let stop = calls
            .iter()
            .position(|c| c == "stop")
            .expect("the old tunnel was stopped");
        assert!(
            stop < starts[1],
            "the old tunnel must be fully stopped before the new one starts: {calls:?}"
        );
        let names = event_names(&rig.bus);
        assert!(names.contains(&"EndpointMigrated".to_string()), "{names:?}");
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_tunnel_that_finished_starting_for_an_abandoned_attempt_is_not_taken_for_the_new_one()
    {
        // Starting a tunnel cannot be cancelled once begun. So: connect (the race picks a profile
        // and a slow start begins), disconnect, then connect again to a profile that is started
        // directly. When the FIRST start finally reports "tunnel up", the engine is in the phase
        // that accepts one (Starting), so only the attempt number tells the two apart. The new
        // tunnel has not come up yet; the state must not claim it has.
        let rig = rig();
        *rig.script.start_delay.lock().unwrap() = Duration::from_secs(5);
        rig.script
            .races
            .lock()
            .unwrap()
            .push_back(Some(selected("hy2-default")));
        rig.handle.connect(None).unwrap();
        // The slow start of the first attempt is under way.
        for _ in 0..200 {
            if rig.script.calls().iter().any(|c| c.starts_with("start")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rig
            .script
            .calls()
            .iter()
            .any(|c| c.starts_with("start[hy2-default]")));

        rig.handle.disconnect().unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Disconnected).await;
        rig.handle.connect(Some(id("awg-default"))).unwrap();
        until(&rig.handle, |s| s.status == ConnectionStatus::Probing).await;

        // The first start finishes (at about 5 s) while the second has not even begun: the
        // executor is still busy with the first, then has to stop it, then start the second.
        tokio::time::sleep(Duration::from_millis(5_300)).await;
        assert_ne!(
            rig.handle.snapshot().status,
            ConnectionStatus::Connected,
            "the old attempt's tunnel was taken for the new attempt's"
        );
        // And the new attempt does go on to connect when its own tunnel is up.
        until(&rig.handle, |s| s.status == ConnectionStatus::Connected).await;
        let connected = rig.handle.snapshot();
        assert_eq!(connected.active_profile.unwrap().id, "awg-default");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_endpoint_is_reported_as_unreachable_not_as_blocked_profiles() {
        // The engine can only tell "the endpoint is down" from "the network blocks every profile"
        // if the direct reachability answer reaches it BEFORE the race's result. The check is made
        // slow here so that a wrong order would let the race's result arrive first.
        let rig = rig();
        *rig.script.reach_answer.lock().unwrap() = Reach::Unreachable;
        *rig.script.reach_delay.lock().unwrap() = Duration::from_millis(500);
        rig.script.races.lock().unwrap().push_back(Some((
            RaceDecision::NoneUsable,
            vec![
                (id("hy2-default"), ProfileProbe::HandshakeFailed),
                (id("reality-default"), ProfileProbe::HandshakeFailed),
            ],
        )));

        rig.handle.connect(None).unwrap();
        let failed = until(&rig.handle, |s| s.status == ConnectionStatus::Failed).await;

        assert_eq!(
            failed.failure,
            Some(FailureCause::NoEndpointReachable),
            "the endpoint is down; saying the profiles are blocked would send the user the wrong way"
        );
    }

    // ---------------------------------------------------------------- what clients see

    #[test]
    fn every_phase_the_engine_can_be_in_encodes_as_a_consistent_snapshot() {
        // Idle and Failed need no running; the others are reached by feeding the engine inputs.
        let mut engine = Engine::new(profiles(), vec![endpoint("home")]);
        let t = std::time::Instant::now();
        let mut seen = vec![snapshot_of(&engine)];
        engine.step(Input::Connect { profile: None }, t);
        seen.push(snapshot_of(&engine)); // Probing
        let race = selected("hy2-default");
        engine.step(
            Input::RaceFinished {
                decision: race.0,
                results: race.1,
            },
            t,
        );
        seen.push(snapshot_of(&engine)); // Starting
        engine.step(Input::TunnelUp, t);
        seen.push(snapshot_of(&engine)); // Connected
        engine.step(Input::Disconnect, t);
        engine.step(
            Input::Connect {
                profile: Some(id("nonesuch")),
            },
            t,
        );
        seen.push(snapshot_of(&engine)); // Failed

        let statuses: Vec<ConnectionStatus> = seen.iter().map(|s| s.status).collect();
        assert_eq!(
            statuses,
            [
                ConnectionStatus::Disconnected,
                ConnectionStatus::Probing,
                ConnectionStatus::Probing,
                ConnectionStatus::Connected,
                ConnectionStatus::Failed
            ]
        );
        for snapshot in &seen {
            encode_state_snapshot(snapshot).unwrap_or_else(|e| panic!("{e}: {snapshot:?}"));
        }
    }

    #[test]
    fn nothing_is_tunnelled_until_connected() {
        let engine = Engine::new(profiles(), vec![endpoint("home")]);
        let idle = snapshot_of(&engine);
        assert_eq!(idle.posture, RoutingPosture::FailClosed);
        assert_eq!(idle.status, ConnectionStatus::Disconnected);
    }
}
