//! `DnetService` — the daemon's implementation of the IPC `Service` seam.
//!
//! Bridges authorized IPC requests to the in-memory domain store. Reached only after
//! `dnet-ipc` has authorized the request against the captured client identity, so this
//! never re-checks identity — but it also performs no privileged action beyond what the
//! request's class permits.
//!
//! Scope at this phase: the read-only queries are fully served from the domain store.
//! Connect/Disconnect and the config mutations are recognized but return an honest
//! "not available yet" error, because tunnel establishment lands in Phases 4–6 and the
//! request wire types do not yet carry mutation payloads (that arrives with the tray,
//! Phase 9). The privilege boundary and the read path are real now.

use std::sync::Mutex;

use dnet_ipc::authz::ConsoleSession;
use dnet_ipc::protocol::{IpcError, Request, RequestClass};
use dnet_ipc::service::Service;

use crate::domain::DomainState;
use crate::recovery::{Recovered, RecoveryError};

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
        }
    }

    /// The production service: a seeded store and the real OS console lookup.
    #[cfg(windows)]
    pub fn production(recovery: Result<Recovered, RecoveryError>) -> Self {
        Self::new(
            DomainState::seeded(),
            Box::new(crate::console::active_console_session),
            recovery,
        )
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
        }
        let state = self.state.lock().expect("domain state mutex poisoned");
        match request {
            // Fully served now.
            Request::GetState => Ok(state.state_snapshot_json()),
            Request::GetSession => Ok(state.session_json()),
            Request::ListEndpoints => Ok(state.endpoints_json()),
            Request::ListProfiles => Ok(state.profiles_json()),
            Request::ListRules => Ok(state.rules_json()),
            Request::GetDiagnostics => Ok(state.session_json()), // placeholder bundle; T112 fills it

            // Recognized, authorized, but not yet actionable.
            Request::Connect { .. } | Request::Disconnect => Self::not_available("connecting"),
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

            // Streaming is handled by the connection loop, not one-shot dispatch.
            Request::Subscribe => Err(IpcError::InvalidRequest {
                detail: "Subscribe is a streaming request, not a one-shot dispatch".to_string(),
            }),
        }
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
    fn console_resolver_is_consulted() {
        let svc = service();
        assert_eq!(svc.console_session().unwrap().session_id, 1);
    }

    fn mutating_requests() -> Vec<Request> {
        let all = vec![
            Request::Connect {
                acknowledge_tier2: false,
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
}
