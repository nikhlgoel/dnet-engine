//! Request and response types, the error model, and wire-level validators.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.
//! The pure decision and codec layer is implemented here (T033); wiring it to a real
//! pipe and dispatching requests is T034.
//!
//! Wire encoding is done by hand against `serde_json::Value` rather than derived, so
//! that `dnet-core`'s domain types carry no wire-format concern and the exact contract
//! shape — including which strings are *rejected* — is explicit and testable.

use dnet_core::profile::CoreBinding;
use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;
use serde_json::{json, Value};

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
/// Those are added with the domain identifier types in T024 and T026.
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
    /// The authorization class this request belongs to (contract §Request classes).
    pub fn class(&self) -> RequestClass {
        use Request::*;
        match self {
            GetState | GetSession | ListEndpoints | ListProfiles | ListRules | GetDiagnostics => {
                RequestClass::ReadOnly
            }
            Subscribe => RequestClass::Stream,
            Connect { .. }
            | Disconnect
            | AddEndpoint
            | RemoveEndpoint
            | SetEndpointEnabled
            | AddRule
            | RemoveRule
            | SetProfileParams
            | EnableBrutal
            | SetEncryptedDnsHandling
            | StartProvisioning
            | CancelProvisioning => RequestClass::Mutating,
        }
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

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
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

// ------------------------------------------------------------------ FailureCause

fn core_binding_str(core: &CoreBinding) -> &'static str {
    match core {
        CoreBinding::PrimaryCore => "PrimaryCore",
        CoreBinding::AmneziaWgCore => "AmneziaWgCore",
    }
}

fn core_binding_from_str(s: &str) -> Result<CoreBinding, IpcError> {
    match s {
        "PrimaryCore" => Ok(CoreBinding::PrimaryCore),
        "AmneziaWgCore" => Ok(CoreBinding::AmneziaWgCore),
        other => Err(invalid(format!("unknown core binding {other:?}"))),
    }
}

/// Encode a `FailureCause` in its wire form: `{ "cause": ..., <fields> }`.
pub fn encode_failure_cause(cause: &FailureCause) -> String {
    let value = match cause {
        FailureCause::NoEndpointReachable => json!({ "cause": "NoEndpointReachable" }),
        FailureCause::AllProfilesBlocked => json!({ "cause": "AllProfilesBlocked" }),
        FailureCause::CaptivePortalUnsatisfied => json!({ "cause": "CaptivePortalUnsatisfied" }),
        FailureCause::InsufficientPrivilege => json!({ "cause": "InsufficientPrivilege" }),
        FailureCause::CoreFailedPersistently { core } => {
            json!({ "cause": "CoreFailedPersistently", "core": core_binding_str(core) })
        }
        FailureCause::NoUsablePath => json!({ "cause": "NoUsablePath" }),
        FailureCause::ConfigurationInvalid { detail } => {
            json!({ "cause": "ConfigurationInvalid", "detail": detail })
        }
    };
    value.to_string()
}

/// Decode a `FailureCause`. `"Unknown"` is not a permitted value (FR-039, SC-020).
pub fn decode_failure_cause(wire: &str) -> Result<FailureCause, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let cause = value
        .get("cause")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing `cause`"))?;

    match cause {
        "NoEndpointReachable" => Ok(FailureCause::NoEndpointReachable),
        "AllProfilesBlocked" => Ok(FailureCause::AllProfilesBlocked),
        "CaptivePortalUnsatisfied" => Ok(FailureCause::CaptivePortalUnsatisfied),
        "InsufficientPrivilege" => Ok(FailureCause::InsufficientPrivilege),
        "NoUsablePath" => Ok(FailureCause::NoUsablePath),
        "CoreFailedPersistently" => {
            let core = value
                .get("core")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("CoreFailedPersistently requires `core`"))?;
            Ok(FailureCause::CoreFailedPersistently {
                core: core_binding_from_str(core)?,
            })
        }
        "ConfigurationInvalid" => {
            let detail = value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Ok(FailureCause::ConfigurationInvalid { detail })
        }
        // Explicitly rejects "Unknown" and any other unrecognised cause.
        other => Err(invalid(format!("unknown failure cause {other:?}"))),
    }
}

// ------------------------------------------------------------------ StateSnapshot

fn status_from_str(s: &str) -> Result<ConnectionStatus, IpcError> {
    match s {
        "Disconnected" => Ok(ConnectionStatus::Disconnected),
        "Probing" => Ok(ConnectionStatus::Probing),
        "Connected" => Ok(ConnectionStatus::Connected),
        "Failed" => Ok(ConnectionStatus::Failed),
        other => Err(invalid(format!("unknown status {other:?}"))),
    }
}

fn tier_from_str(s: &str) -> Result<FailoverTier, IpcError> {
    match s {
        "Tier1" => Ok(FailoverTier::Tier1),
        "Tier2" => Ok(FailoverTier::Tier2),
        other => Err(invalid(format!("unknown tier {other:?}"))),
    }
}

/// Decode a `StateSnapshot` from its wire JSON.
///
/// An active profile MUST carry a valid `tier`; a missing, null, or unknown tier is
/// rejected (FR-016b, IPC-05).
pub fn decode_state_snapshot(json: &str) -> Result<StateSnapshot, IpcError> {
    let value: Value = serde_json::from_str(json).map_err(|e| invalid(e.to_string()))?;

    let status = status_from_str(
        value
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing `status`"))?,
    )?;

    let active_profile = match value.get("active_profile") {
        None | Some(Value::Null) => None,
        Some(profile) => {
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("active profile missing `id`"))?
                .to_owned();
            let kind = profile
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("active profile missing `kind`"))?
                .to_owned();
            let tier = tier_from_str(
                profile
                    .get("tier")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("active profile missing `tier`"))?,
            )?;
            Some(ActiveProfile { id, kind, tier })
        }
    };

    Ok(StateSnapshot {
        status,
        active_profile,
    })
}

// ------------------------------------------------------------------ validators

/// Refuse a Tier 2 selection made while a Tier 1 profile is viable, unless the client
/// has explicitly acknowledged it (contract §Connect, FR-016b).
pub fn check_tier_consent(
    selected: FailoverTier,
    tier1_viable: bool,
    acknowledged: bool,
) -> Result<(), IpcError> {
    if selected == FailoverTier::Tier2 && tier1_viable && !acknowledged {
        return Err(IpcError::TierDowngradeRequiresConsent {
            tier: FailoverTier::Tier2,
        });
    }
    Ok(())
}

/// A `because` must explain the event. It may not be empty, and it may not simply
/// restate the event name (contract §Subscribe, IPC-06).
pub fn validate_because(event_name: &str, because: &str) -> Result<(), IpcError> {
    let trimmed = because.trim();
    if trimmed.is_empty() {
        return Err(invalid("ConnectionEvent `because` must not be empty"));
    }
    if trimmed.eq_ignore_ascii_case(event_name.trim()) {
        return Err(invalid(
            "`because` must explain the event, not restate its name",
        ));
    }
    Ok(())
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
/// (FR-035, IPC-07). Credential material never enters this input in the first place.
pub fn build_diagnostic_bundle(input: &DiagnosticInput) -> String {
    let mut out = String::new();
    out.push_str("# DNet Engine diagnostics\n\n## Session events\n");
    for event in &input.events {
        out.push_str(event);
        out.push('\n');
    }
    if input.destination_logging_enabled {
        out.push_str("\n## Destinations (logging explicitly enabled)\n");
        for destination in &input.destinations {
            out.push_str(destination);
            out.push('\n');
        }
    }
    out
}

// ------------------------------------------------------------------ request wire

/// Decode a request from its wire JSON: `{ "request": "<Name>", <fields> }`.
///
/// Every field is validated server-side; the caller is treated as hostile input
/// (Principle V). Unknown request names are rejected rather than ignored.
pub fn decode_request(wire: &str) -> Result<Request, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let name = value
        .get("request")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing `request`"))?;

    let request = match name {
        "GetState" => Request::GetState,
        "GetSession" => Request::GetSession,
        "ListEndpoints" => Request::ListEndpoints,
        "ListProfiles" => Request::ListProfiles,
        "ListRules" => Request::ListRules,
        "GetDiagnostics" => Request::GetDiagnostics,
        "Connect" => Request::Connect {
            acknowledge_tier2: value
                .get("acknowledge_tier2")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "Disconnect" => Request::Disconnect,
        "AddEndpoint" => Request::AddEndpoint,
        "RemoveEndpoint" => Request::RemoveEndpoint,
        "SetEndpointEnabled" => Request::SetEndpointEnabled,
        "AddRule" => Request::AddRule,
        "RemoveRule" => Request::RemoveRule,
        "SetProfileParams" => Request::SetProfileParams,
        "EnableBrutal" => Request::EnableBrutal,
        "SetEncryptedDnsHandling" => Request::SetEncryptedDnsHandling,
        "StartProvisioning" => Request::StartProvisioning,
        "CancelProvisioning" => Request::CancelProvisioning,
        "Subscribe" => Request::Subscribe,
        other => return Err(invalid(format!("unknown request {other:?}"))),
    };
    Ok(request)
}

/// The stable wire code for an error (contract §Error model).
fn error_code(error: &IpcError) -> &'static str {
    match error {
        IpcError::Unauthorized { .. } => "Unauthorized",
        IpcError::InvalidRequest { .. } => "InvalidRequest",
        IpcError::TierDowngradeRequiresConsent { .. } => "TierDowngradeRequiresConsent",
        IpcError::CapacityUnavailable => "CapacityUnavailable",
        IpcError::NotConnected => "NotConnected",
        IpcError::ServiceBusy => "ServiceBusy",
        IpcError::InternalError { .. } => "InternalError",
    }
}

/// Encode an error in its wire form (contract §Error model). The `detail` is always
/// actionable; a bare error reaching the UI is a defect. Never leaks credential
/// material — `IpcError` carries none.
pub fn encode_ipc_error(error: &IpcError) -> String {
    let retryable = matches!(error, IpcError::CapacityUnavailable | IpcError::ServiceBusy);
    json!({
        "error": error_code(error),
        "detail": error.to_string(),
        "retryable": retryable,
    })
    .to_string()
}
