//! Request and response types, the error model, and wire-level validators.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.
//! These are the skeleton types the T022 contract tests are written against; the
//! behaviour lands in T033.

use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;

/// Authorization class of a request (contract §Request classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClass {
    /// Needs an authenticated caller.
    ReadOnly,
    /// Needs the interactive console user.
    Mutating,
    /// Needs an authenticated caller.
    Stream,
}

/// Every request the service accepts.
///
/// In the contract, `Connect` also carries optional endpoint and profile selectors.
/// Those are added together with the domain identifier types in T024 and T026.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetState,
    GetSession,
    ListEndpoints,
    ListProfiles,
    ListRules,
    GetDiagnostics,
    Connect {
        /// Explicit consent to a Tier 2 profile (FR-016b).
        acknowledge_tier2: bool,
    },
    Disconnect,
    AddEndpoint,
    RemoveEndpoint,
    SetEndpointEnabled,
    AddRule,
    RemoveRule,
    SetProfileParams,
    EnableBrutal,
    SetEncryptedDnsHandling,
    StartProvisioning,
    CancelProvisioning,
    Subscribe,
}

impl Request {
    /// The authorization class this request belongs to.
    pub fn class(&self) -> RequestClass {
        todo!("T033: map each request to its contract class")
    }
}

/// Error model (contract §Error model).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpcError {
    #[error("unauthorized: {reason}")]
    Unauthorized {
        /// Why the request was refused. Never empty: silent refusal is a defect.
        reason: String,
    },
    #[error("invalid request: {detail}")]
    InvalidRequest { detail: String },
    /// Tier 2 selected while a Tier 1 profile is viable. The contract also names the
    /// profile, which is added with `ProfileId` in T026.
    #[error("a {tier:?} profile requires explicit consent")]
    TierDowngradeRequiresConsent { tier: FailoverTier },
    /// Retryable. The contract also lists alternative regions, added in T091.
    #[error("capacity unavailable")]
    CapacityUnavailable,
    #[error("not connected")]
    NotConnected,
    #[error("service busy")]
    ServiceBusy,
    #[error("internal error: {detail}")]
    InternalError {
        /// Still actionable; a bare internal error reaching the UI is a defect.
        detail: String,
    },
}

/// Connection status reported in a `StateSnapshot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Probing,
    Connected,
    Failed,
}

/// The profile currently carrying traffic.
///
/// `tier` is not optional: the UI must be able to show it without a second request
/// (FR-016b, IPC-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProfile {
    pub id: String,
    pub kind: String,
    pub tier: FailoverTier,
}

/// Response to `GetState` (contract §Core messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub status: ConnectionStatus,
    pub active_profile: Option<ActiveProfile>,
}

/// Decode a `StateSnapshot` from its wire JSON.
pub fn decode_state_snapshot(_json: &str) -> Result<StateSnapshot, IpcError> {
    todo!("T033: decode StateSnapshot")
}

/// Encode a `FailureCause` in its wire form: `{ "cause": ..., "detail": ... }`.
pub fn encode_failure_cause(_cause: &FailureCause) -> String {
    todo!("T033: encode FailureCause")
}

/// Decode a `FailureCause`. `"Unknown"` is not a permitted value (FR-039, SC-020).
pub fn decode_failure_cause(_wire: &str) -> Result<FailureCause, IpcError> {
    todo!("T033: decode FailureCause")
}

/// Refuse a Tier 2 selection made while a Tier 1 profile is viable, unless the client
/// has explicitly acknowledged it (contract §Connect, FR-016b).
pub fn check_tier_consent(
    _selected: FailoverTier,
    _tier1_viable: bool,
    _acknowledged: bool,
) -> Result<(), IpcError> {
    todo!("T033: enforce Tier 2 consent")
}

/// A `because` must explain the event. It may not be empty, and it may not simply
/// restate the event name (contract §Subscribe).
pub fn validate_because(_event_name: &str, _because: &str) -> Result<(), IpcError> {
    todo!("T033: validate ConnectionEvent explanations")
}

/// What a diagnostic bundle is built from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiagnosticInput {
    /// Session event lines.
    pub events: Vec<String>,
    /// Destinations the session visited.
    pub destinations: Vec<String>,
    /// Whether the user explicitly enabled destination logging for this session.
    pub destination_logging_enabled: bool,
}

/// Build the diagnostic bundle. Destinations are excluded unless explicitly enabled
/// (FR-035, IPC-07).
pub fn build_diagnostic_bundle(_input: &DiagnosticInput) -> String {
    todo!("T112: build the diagnostic bundle")
}
