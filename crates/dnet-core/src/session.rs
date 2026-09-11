//! Connection sessions and how they end (data-model §5).
//!
//! A `ConnectionSession` is one period of being connected, recorded append-only: state
//! changes are events, not overwrites, so the whole history is available to both the
//! UI's current view and diagnostics.

use std::time::Instant;

use crate::ids::{EndpointId, InterfaceId, ProfileId, SessionId};
use crate::profile::CoreBinding;
use crate::tier::FailoverTier;

/// Why a connection failed.
///
/// Each variant is distinguishable, and there is deliberately **no `Unknown`**: a
/// generic error reaching the user is a defect (FR-039, SC-020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureCause {
    /// No configured endpoint answered.
    NoEndpointReachable,
    /// The network is blocking every connection profile.
    AllProfilesBlocked,
    /// A captive portal is intercepting traffic until the user logs in.
    CaptivePortalUnsatisfied,
    /// The service lacks the privilege it needs.
    InsufficientPrivilege,
    /// A supervised core kept failing and restarts have stopped.
    CoreFailedPersistently {
        /// The process that failed.
        core: CoreBinding,
    },
    /// No network interface can carry traffic.
    NoUsablePath,
    /// The configuration cannot be used as written.
    ConfigurationInvalid {
        /// What is wrong, stated so the user can act on it.
        detail: String,
    },
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutcome {
    /// The user pressed disconnect.
    UserDisconnected,
    /// The connection failed and could not be recovered.
    Failed(FailureCause),
    /// The service stopped (shutdown, uninstall).
    ServiceStopped,
}

/// A recorded change during a session.
///
/// Every *automatic* change carries a `because`, so the UI can always answer "why did
/// it do that?" without consulting logs (data-model §5.1, FR-037).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Probing of the configured profiles began.
    ProbeStarted,
    /// A profile was selected to carry traffic.
    ProfileSelected { profile: ProfileId, because: String },
    /// A profile stopped working on this network.
    ProfileBlocked { profile: ProfileId, reason: String },
    /// Traffic moved to a different endpoint.
    EndpointMigrated {
        from: EndpointId,
        to: EndpointId,
        because: String,
    },
    /// The carrying interface changed.
    PathChanged {
        from: Option<InterfaceId>,
        to: InterfaceId,
        /// The failover tier in effect at the time, which decides whether established
        /// connections survived (data-model §5.1).
        tier_at_time: FailoverTier,
    },
    /// A supervised core was restarted.
    CoreRestarted { core: CoreBinding, attempt: u32 },
    /// The session failed.
    Failed { cause: FailureCause },
}

/// One period of being connected. Append-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSession {
    id: SessionId,
    started_at: Instant,
    ended_at: Option<Instant>,
    active_profile: ProfileId,
    active_endpoint: EndpointId,
    carrying_path: Option<InterfaceId>,
    events: Vec<ConnectionEvent>,
    outcome: Option<SessionOutcome>,
}

impl ConnectionSession {
    /// Start a session with the profile and endpoint initially selected.
    pub fn start(
        id: SessionId,
        started_at: Instant,
        active_profile: ProfileId,
        active_endpoint: EndpointId,
    ) -> Self {
        Self {
            id,
            started_at,
            ended_at: None,
            active_profile,
            active_endpoint,
            carrying_path: None,
            events: Vec::new(),
            outcome: None,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    pub fn ended_at(&self) -> Option<Instant> {
        self.ended_at
    }

    pub fn active_profile(&self) -> &ProfileId {
        &self.active_profile
    }

    pub fn active_endpoint(&self) -> EndpointId {
        self.active_endpoint
    }

    pub fn carrying_path(&self) -> Option<InterfaceId> {
        self.carrying_path
    }

    pub fn events(&self) -> &[ConnectionEvent] {
        &self.events
    }

    pub fn outcome(&self) -> Option<&SessionOutcome> {
        self.outcome.as_ref()
    }

    /// Whether the session is still running (has not ended).
    pub fn is_active(&self) -> bool {
        self.outcome.is_none()
    }

    /// Record an event, keeping the projected current state in step: a selected
    /// profile, a migrated endpoint, and a path change update the corresponding
    /// fields, so the session's current view matches its history.
    pub fn record(&mut self, event: ConnectionEvent) {
        match &event {
            ConnectionEvent::ProfileSelected { profile, .. } => {
                self.active_profile = profile.clone();
            }
            ConnectionEvent::EndpointMigrated { to, .. } => {
                self.active_endpoint = *to;
            }
            ConnectionEvent::PathChanged { to, .. } => {
                self.carrying_path = Some(*to);
            }
            _ => {}
        }
        self.events.push(event);
    }

    /// End the session with an outcome. Idempotent-ish: the first outcome wins, and a
    /// `Failed` outcome also appends a `Failed` event for the history.
    pub fn end(&mut self, at: Instant, outcome: SessionOutcome) {
        if self.outcome.is_some() {
            return;
        }
        if let SessionOutcome::Failed(cause) = &outcome {
            self.events.push(ConnectionEvent::Failed {
                cause: cause.clone(),
            });
        }
        self.ended_at = Some(at);
        self.outcome = Some(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn session() -> ConnectionSession {
        ConnectionSession::start(
            SessionId::new(),
            Instant::now(),
            ProfileId::new("awg-default"),
            EndpointId::new(),
        )
    }

    #[test]
    fn a_new_session_is_active_with_no_carrying_path() {
        let s = session();
        assert!(s.is_active());
        assert_eq!(s.carrying_path(), None);
        assert!(s.events().is_empty());
        assert_eq!(s.outcome(), None);
    }

    #[test]
    fn profile_selection_updates_the_current_profile_and_is_recorded() {
        let mut s = session();
        s.record(ConnectionEvent::ProfileSelected {
            profile: ProfileId::new("hy2-default"),
            because: "AmneziaWG probe timed out; Hysteria 2 carried 1.2 Mbit/s".into(),
        });
        assert_eq!(s.active_profile(), &ProfileId::new("hy2-default"));
        assert_eq!(s.events().len(), 1);
    }

    #[test]
    fn endpoint_migration_updates_the_active_endpoint() {
        let mut s = session();
        let to = EndpointId::new();
        s.record(ConnectionEvent::EndpointMigrated {
            from: s.active_endpoint(),
            to,
            because: "oracle-mumbai unreachable".into(),
        });
        assert_eq!(s.active_endpoint(), to);
    }

    #[test]
    fn path_change_updates_the_carrying_path() {
        let mut s = session();
        let iface = InterfaceId::new(7);
        s.record(ConnectionEvent::PathChanged {
            from: None,
            to: iface,
            tier_at_time: FailoverTier::Tier1,
        });
        assert_eq!(s.carrying_path(), Some(iface));
    }

    #[test]
    fn ending_records_outcome_and_stops_the_session() {
        let mut s = session();
        let end = s.started_at() + Duration::from_secs(60);
        s.end(end, SessionOutcome::UserDisconnected);
        assert!(!s.is_active());
        assert_eq!(s.ended_at(), Some(end));
        assert_eq!(s.outcome(), Some(&SessionOutcome::UserDisconnected));
    }

    #[test]
    fn a_failed_outcome_appends_a_failed_event() {
        let mut s = session();
        s.end(
            Instant::now(),
            SessionOutcome::Failed(FailureCause::AllProfilesBlocked),
        );
        assert!(matches!(
            s.events().last(),
            Some(ConnectionEvent::Failed {
                cause: FailureCause::AllProfilesBlocked
            })
        ));
    }

    #[test]
    fn the_first_outcome_wins() {
        let mut s = session();
        s.end(Instant::now(), SessionOutcome::UserDisconnected);
        s.end(Instant::now(), SessionOutcome::ServiceStopped);
        assert_eq!(s.outcome(), Some(&SessionOutcome::UserDisconnected));
    }
}
