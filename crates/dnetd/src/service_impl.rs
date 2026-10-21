//! `DnetService` — the daemon's implementation of the IPC `Service` seam.
//!
//! Bridges authorized IPC requests to the in-memory domain store. Reached only after
//! `dnet-ipc` has authorized the request against the captured client identity, so this
//! never re-checks identity — but it also performs no privileged action beyond what the
//! request's class permits.
//!
//! The read-only queries are served from the domain store. With a connection orchestrator
//! attached (T126), `Connect`, `Disconnect` and `GetState` are served by it; without one they
//! answer honestly that connecting is not available. The configuration mutations are recognized
//! but return the same honest answer, because the request wire types do not yet carry mutation
//! payloads (that arrives with the tray, Phase 9). The privilege boundary and the read path are
//! real now.

use std::sync::Mutex;

use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::protocol::{encode_state_snapshot, IpcError, Request, RequestClass};
use dnet_ipc::service::Service;
use dnet_ipc::wire::{EventBus, Subscription};

use crate::domain::DomainState;
use crate::orchestrator::Handle;
use crate::recovery::{Recovered, RecoveryError};

/// The reply to a request the orchestrator took on. Progress follows on the event stream.
const ACCEPTED: &str = r#"{"accepted":true}"#;

/// How the service learns who the interactive console user is.
///
/// Boxed so tests can inject a fixed answer instead of querying the OS.
pub type ConsoleResolver = Box<dyn Fn() -> Option<ConsoleSession> + Send + Sync>;

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
    /// available and `GetState` reports the idle state.
    orchestrator: Option<Handle>,
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
            orchestrator: None,
        }
    }

    /// Attach the connection orchestrator. It must publish to [`DnetService::events`], so that a
    /// subscriber sees what it does.
    pub fn with_orchestrator(mut self, handle: Handle) -> Self {
        self.orchestrator = Some(handle);
        self
    }

    /// The orchestrator, for whoever must shut it down when the service stops.
    pub fn orchestrator_handle(&self) -> Option<Handle> {
        self.orchestrator.clone()
    }

    /// Attach the orchestrator with the real effects (T126), if the service is in a state to
    /// connect: start-up recovery succeeded, and the saved configuration was accepted. Otherwise
    /// the service is returned as it is, and every connect answers that connecting is unavailable,
    /// for the reason already logged. Must be called with a Tokio runtime current.
    #[cfg(windows)]
    pub fn with_production_orchestrator(self) -> Self {
        use std::sync::Arc;

        use dnet_config::persist::default_secrets_dir;
        use dnet_config::secret_store::machine_secret_store;
        use dnet_core::engine::Engine;

        use crate::effects::{Layout, RealEffects};
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
        let (profiles, endpoints, rules) = {
            let state = self.state.lock().expect("domain state mutex poisoned");
            (
                state.profiles().to_vec(),
                state.endpoints().to_vec(),
                state.rules().to_vec(),
            )
        };
        let secrets = Arc::new(machine_secret_store(default_secrets_dir()));
        let (effects, profiles, usable) =
            RealEffects::new(profiles, &endpoints, rules, secrets, undo, layout);
        // Only endpoints that can be used, and profiles they can serve, are known to the engine,
        // so it never chooses one that would fail after a race.
        let engine = Engine::new(profiles, usable);
        let timing = Timing {
            // A refused connection takes Windows about two seconds to report.
            reach_timeout: std::time::Duration::from_secs(4),
            ..Timing::default()
        };
        let handle = orchestrator::spawn(engine, Arc::new(effects), self.events.clone(), timing);
        self.with_orchestrator(handle)
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
        use crate::domain::StartupConfig;
        use dnet_config::persist::{default_config_path, ConfigStore, TrustedStateFile};

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
        Self::new(
            state,
            Box::new(crate::console::active_console_session),
            recovery,
        )
        .with_config_refusal(refusal)
    }

    fn not_available(what: &str) -> Result<String, IpcError> {
        Err(IpcError::InternalError {
            detail: format!(
                "{what} is not available in this build yet; the transport engine \
                 (Phases 4-6) and request payloads (Phase 9) are still to land"
            ),
        })
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
        let state = self.state.lock().expect("domain state mutex poisoned");
        match request {
            // The dispatch in `dnet-ipc` answers this before the service is asked (T132); the same
            // answer here keeps the match complete and any other caller of `dispatch` honest.
            Request::GetVersion => Ok(dnet_ipc::version::reply()),
            // Fully served now.
            Request::GetState => match &self.orchestrator {
                Some(orchestrator) => encode_state_snapshot(&orchestrator.snapshot()),
                None => Ok(state.state_snapshot_json()),
            },
            Request::GetSession => Ok(state.session_json()),
            Request::ListEndpoints => Ok(state.endpoints_json()),
            Request::ListProfiles => Ok(state.profiles_json()),
            Request::ListRules => Ok(state.rules_json()),
            Request::GetDiagnostics => Ok(state.session_json()), // placeholder bundle; T112 fills it

            Request::Connect {
                profile, endpoint, ..
            } => match &self.orchestrator {
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
            Request::Disconnect => match &self.orchestrator {
                Some(orchestrator) => {
                    orchestrator.disconnect()?;
                    Ok(ACCEPTED.to_string())
                }
                None => Self::not_available("disconnecting"),
            },

            // Recognized, authorized, but not yet actionable.
            Request::AddEndpoint
            | Request::RemoveEndpoint
            | Request::SetEndpointEnabled
            | Request::AddRule
            | Request::RemoveRule
            | Request::SetProfileParams
            | Request::EnableBrutal
            | Request::SetEncryptedDnsHandling
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
    use super::*;
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
    fn connect_reports_it_is_not_available_yet_with_an_actionable_detail() {
        let svc = service();
        match svc.dispatch(&Request::Connect {
            acknowledge_tier2: false,
            profile: None,
            endpoint: None,
        }) {
            Err(IpcError::InternalError { detail }) => {
                assert!(!detail.trim().is_empty());
                assert!(detail.contains("Phases 4-6"));
            }
            other => panic!("expected a not-available InternalError, got {other:?}"),
        }
    }

    #[test]
    fn config_mutations_report_not_available_rather_than_pretending() {
        let svc = service();
        assert!(matches!(
            svc.dispatch(&Request::AddEndpoint),
            Err(IpcError::InternalError { .. })
        ));
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
            Request::AddEndpoint,
            Request::RemoveEndpoint,
            Request::SetEndpointEnabled,
            Request::AddRule,
            Request::RemoveRule,
            Request::SetProfileParams,
            Request::EnableBrutal,
            Request::SetEncryptedDnsHandling,
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
}
