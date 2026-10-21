//! Request and response types, the error model, and wire-level validators.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.
//! The pure decision and codec layer is implemented here (T033); wiring it to a real
//! pipe and dispatching requests is T034.
//!
//! Wire encoding is done by hand against `serde_json::Value` rather than derived, so
//! that `dnet-core`'s domain types carry no wire-format concern and the exact contract
//! shape — including which strings are *rejected* — is explicit and testable.

use dnet_core::failure::explain;
use dnet_core::ids::{EndpointId, ProfileId};
use dnet_core::profile::CoreBinding;
use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// The routing posture, as the engine decided it. Re-exported because it is part of the wire
/// contract; the type has no direct-fallback variant, so a response cannot express one.
pub use dnet_core::posture::RoutingPosture;

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
/// `Connect` carries optional profile and endpoint selectors (contract §Connect); both `None`
/// means "choose for me", the single-control path (FR-036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The protocol versions the service speaks (T132). Answered by the dispatch itself.
    GetVersion,
    GetState,
    GetSession,
    ListEndpoints,
    ListProfiles,
    ListRules,
    GetDiagnostics,
    Connect {
        /// Explicit consent to a Tier 2 profile (FR-016b).
        acknowledge_tier2: bool,
        /// Connect with this profile only. It is tried alone; no other is substituted.
        profile: Option<ProfileId>,
        /// Connect to this endpoint. Validated here, but the engine cannot honour a named
        /// endpoint yet: the daemon refuses one with a reason rather than ignoring it.
        endpoint: Option<EndpointId>,
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
            GetVersion | GetState | GetSession | ListEndpoints | ListProfiles | ListRules
            | GetDiagnostics => RequestClass::ReadOnly,
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
    /// Racing profiles, bringing a tunnel up, or finding another after a block.
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

/// The endpoint currently carrying traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveEndpoint {
    pub id: String,
    pub label: String,
}

/// A state the user consented to, or should not forget (contract §GetState).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    Tier2ProfileActive,
    BrutalEnabled,
    EncryptedDnsOverridden,
}

/// Response to `GetState` (contract §Core messages).
///
/// The path fields of the contract (`carrying_path`, `standby_paths`) are deliberately absent
/// until Phase 7 produces them: an empty list would assert that there is no standby path, which
/// nothing knows yet.
///
/// `posture` is the posture the engine **decided** (`dnet_core::posture`). It is not proof that
/// the OS drops traffic: no component enforces the kill switch yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub status: ConnectionStatus,
    pub active_profile: Option<ActiveProfile>,
    pub active_endpoint: Option<ActiveEndpoint>,
    pub failure: Option<FailureCause>,
    pub warnings: Vec<Warning>,
    pub posture: RoutingPosture,
}

// ------------------------------------------------------------------ FailureCause

pub(crate) fn core_binding_str(core: &CoreBinding) -> &'static str {
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

fn failure_cause_value(cause: &FailureCause) -> Value {
    match cause {
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
    }
}

/// A failure cause with the words to show for it: its own fields plus `title`, `detail` and
/// `action`, so a client can present a failure without a second request (FR-039, SC-020).
pub(crate) fn failure_value_with_words(cause: &FailureCause) -> Value {
    let mut value = failure_cause_value(cause);
    let words = explain(cause);
    if let Some(object) = value.as_object_mut() {
        object.insert("title".into(), Value::String(words.title));
        object.insert("detail".into(), Value::String(words.detail));
        object.insert("action".into(), Value::String(words.action));
    }
    value
}

/// Encode a `FailureCause` in its wire form: `{ "cause": ..., <fields> }`.
pub fn encode_failure_cause(cause: &FailureCause) -> String {
    failure_cause_value(cause).to_string()
}

fn failure_cause_from_value(value: &Value) -> Result<FailureCause, IpcError> {
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

/// Decode a `FailureCause`. `"Unknown"` is not a permitted value (FR-039, SC-020).
pub fn decode_failure_cause(wire: &str) -> Result<FailureCause, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    failure_cause_from_value(&value)
}

// ------------------------------------------------------------------ StateSnapshot

fn status_str(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Disconnected => "Disconnected",
        ConnectionStatus::Probing => "Probing",
        ConnectionStatus::Connected => "Connected",
        ConnectionStatus::Failed => "Failed",
    }
}

fn status_from_str(s: &str) -> Result<ConnectionStatus, IpcError> {
    match s {
        "Disconnected" => Ok(ConnectionStatus::Disconnected),
        "Probing" => Ok(ConnectionStatus::Probing),
        "Connected" => Ok(ConnectionStatus::Connected),
        "Failed" => Ok(ConnectionStatus::Failed),
        other => Err(invalid(format!("unknown status {other:?}"))),
    }
}

pub(crate) fn tier_str(tier: FailoverTier) -> &'static str {
    match tier {
        FailoverTier::Tier1 => "Tier1",
        FailoverTier::Tier2 => "Tier2",
    }
}

fn tier_from_str(s: &str) -> Result<FailoverTier, IpcError> {
    match s {
        "Tier1" => Ok(FailoverTier::Tier1),
        "Tier2" => Ok(FailoverTier::Tier2),
        other => Err(invalid(format!("unknown tier {other:?}"))),
    }
}

fn warning_str(warning: Warning) -> &'static str {
    match warning {
        Warning::Tier2ProfileActive => "Tier2ProfileActive",
        Warning::BrutalEnabled => "BrutalEnabled",
        Warning::EncryptedDnsOverridden => "EncryptedDnsOverridden",
    }
}

fn warning_from_str(s: &str) -> Result<Warning, IpcError> {
    match s {
        "Tier2ProfileActive" => Ok(Warning::Tier2ProfileActive),
        "BrutalEnabled" => Ok(Warning::BrutalEnabled),
        "EncryptedDnsOverridden" => Ok(Warning::EncryptedDnsOverridden),
        other => Err(invalid(format!("unknown warning {other:?}"))),
    }
}

/// What must hold between the fields of a snapshot, in both directions.
///
/// A snapshot that breaks one of these says two things at once (connected, yet nothing is
/// carrying; failed, yet no cause), so it is refused when produced and when read. The tray
/// treats the daemon's answers as untrusted, and the daemon must not send a contradiction.
fn check_consistency(snapshot: &StateSnapshot) -> Result<(), &'static str> {
    let has_active = snapshot.active_profile.is_some() || snapshot.active_endpoint.is_some();
    match snapshot.status {
        ConnectionStatus::Connected => {
            let profile = snapshot
                .active_profile
                .as_ref()
                .ok_or("a connected snapshot needs an active profile")?;
            if snapshot.active_endpoint.is_none() {
                return Err("a connected snapshot needs an active endpoint");
            }
            if snapshot.failure.is_some() {
                return Err("a connected snapshot cannot carry a failure");
            }
            match snapshot.posture {
                RoutingPosture::Tunnelled { tier } if tier == profile.tier => Ok(()),
                RoutingPosture::Tunnelled { .. } => {
                    Err("the posture tier differs from the active profile's tier")
                }
                RoutingPosture::FailClosed => Err("a connected snapshot cannot be fail-closed"),
            }
        }
        ConnectionStatus::Failed => {
            if snapshot.failure.is_none() {
                return Err("a failed snapshot needs a cause");
            }
            if has_active {
                return Err("a failed snapshot cannot name an active profile or endpoint");
            }
            fail_closed_only(snapshot)
        }
        ConnectionStatus::Disconnected | ConnectionStatus::Probing => {
            if snapshot.failure.is_some() {
                return Err("only a failed snapshot carries a failure");
            }
            if has_active {
                return Err("nothing is carrying traffic, so no profile or endpoint is active");
            }
            fail_closed_only(snapshot)
        }
    }
}

fn fail_closed_only(snapshot: &StateSnapshot) -> Result<(), &'static str> {
    match snapshot.posture {
        RoutingPosture::FailClosed => Ok(()),
        RoutingPosture::Tunnelled { .. } => Err("only a connected snapshot can be tunnelled"),
    }
}

/// Encode a `StateSnapshot` (contract §GetState).
///
/// Refuses a self-contradictory snapshot with an `InternalError`: that is a defect in the
/// producer, and the daemon must not send it on.
pub fn encode_state_snapshot(snapshot: &StateSnapshot) -> Result<String, IpcError> {
    check_consistency(snapshot).map_err(|why| IpcError::InternalError {
        detail: format!("refusing to send an inconsistent state snapshot: {why}"),
    })?;

    let active_profile = snapshot
        .active_profile
        .as_ref()
        .map(|p| json!({ "id": p.id, "kind": p.kind, "tier": tier_str(p.tier) }));
    let active_endpoint = snapshot
        .active_endpoint
        .as_ref()
        .map(|e| json!({ "id": e.id, "label": e.label }));
    let failure = snapshot.failure.as_ref().map(failure_value_with_words);
    let posture = match snapshot.posture {
        RoutingPosture::Tunnelled { tier } => {
            json!({ "posture": "Tunnelled", "tier": tier_str(tier) })
        }
        RoutingPosture::FailClosed => json!({ "posture": "FailClosed" }),
    };
    let warnings: Vec<&str> = snapshot.warnings.iter().copied().map(warning_str).collect();

    Ok(json!({
        "status": status_str(snapshot.status),
        "active_profile": active_profile,
        "active_endpoint": active_endpoint,
        "failure": failure,
        "warnings": warnings,
        "routing_posture": posture,
    })
    .to_string())
}

/// A field that may be absent or `null`; `None` for both.
fn optional<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    match value.get(key) {
        None | Some(Value::Null) => None,
        Some(present) => Some(present),
    }
}

fn required_str<'v>(value: &'v Value, key: &str, what: &str) -> Result<&'v str, IpcError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} missing `{key}`")))
}

/// Decode a `StateSnapshot` from its wire JSON.
///
/// An active profile MUST carry a valid `tier`; a missing, null, or unknown tier is rejected
/// (FR-016b, IPC-05). Every other field is required too, and a snapshot that contradicts itself
/// is refused (see `check_consistency`): the caller of this function is a client reading the
/// daemon's answer, and treats it as untrusted.
pub fn decode_state_snapshot(json: &str) -> Result<StateSnapshot, IpcError> {
    let value: Value = serde_json::from_str(json).map_err(|e| invalid(e.to_string()))?;

    let status = status_from_str(required_str(&value, "status", "snapshot")?)?;

    let active_profile = match optional(&value, "active_profile") {
        None => None,
        Some(profile) => Some(ActiveProfile {
            id: required_str(profile, "id", "active profile")?.to_owned(),
            kind: required_str(profile, "kind", "active profile")?.to_owned(),
            tier: tier_from_str(required_str(profile, "tier", "active profile")?)?,
        }),
    };

    let active_endpoint = match optional(&value, "active_endpoint") {
        None => None,
        Some(endpoint) => Some(ActiveEndpoint {
            id: required_str(endpoint, "id", "active endpoint")?.to_owned(),
            label: required_str(endpoint, "label", "active endpoint")?.to_owned(),
        }),
    };

    let failure = match optional(&value, "failure") {
        None => None,
        Some(failure) => Some(failure_cause_from_value(failure)?),
    };

    let warnings = match value.get("warnings") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| invalid("a warning must be a string"))
                    .and_then(warning_from_str)
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(invalid("snapshot missing `warnings`")),
    };

    let posture_value = value
        .get("routing_posture")
        .ok_or_else(|| invalid("snapshot missing `routing_posture`"))?;
    let posture = match required_str(posture_value, "posture", "routing posture")? {
        "Tunnelled" => RoutingPosture::Tunnelled {
            tier: tier_from_str(required_str(posture_value, "tier", "tunnelled posture")?)?,
        },
        "FailClosed" => RoutingPosture::FailClosed,
        other => return Err(invalid(format!("unknown routing posture {other:?}"))),
    };

    let snapshot = StateSnapshot {
        status,
        active_profile,
        active_endpoint,
        failure,
        warnings,
        posture,
    };
    check_consistency(&snapshot).map_err(|why| invalid(format!("inconsistent snapshot: {why}")))?;
    Ok(snapshot)
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

/// The longest profile id accepted from a client. Bundled ids are short; the limit only bounds
/// what a hostile client can make the daemon hold and log.
pub const MAX_PROFILE_ID_LEN: usize = 64;

/// A profile id from a client: 1 to 64 of `a-z`, `0-9` and `-`, neither starting nor ending with
/// `-`. Everything else (case, whitespace, separators, control characters, non-ASCII) is refused
/// before the id can reach a lookup, a log line or a file name.
fn parse_profile_id(raw: &str) -> Result<ProfileId, IpcError> {
    let ok_chars = raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let ok = !raw.is_empty()
        && raw.len() <= MAX_PROFILE_ID_LEN
        && ok_chars
        && !raw.starts_with('-')
        && !raw.ends_with('-');
    if ok {
        Ok(ProfileId::new(raw))
    } else {
        Err(invalid(
            "`profile` must be 1 to 64 lowercase letters, digits or hyphens, not starting or \
             ending with a hyphen",
        ))
    }
}

/// An endpoint id from a client: a UUID in its canonical hyphenated form, nothing else (no
/// braces, no `urn:` prefix, no bare hex).
fn parse_endpoint_id(raw: &str) -> Result<EndpointId, IpcError> {
    if raw.len() == 36 {
        if let Ok(uuid) = Uuid::parse_str(raw) {
            return Ok(EndpointId::from_uuid(uuid));
        }
    }
    Err(invalid("`endpoint` must be a UUID in its hyphenated form"))
}

/// A selector that is absent or `null` means "not given"; any other non-string is a client defect.
fn optional_string<'v>(value: &'v Value, key: &str) -> Result<Option<&'v str>, IpcError> {
    match optional(value, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(invalid(format!("`{key}` must be a string"))),
    }
}

/// A flag that is absent or `null` is `false`; anything but a boolean is refused, because a
/// consent flag silently read as `false` would hide a client defect.
fn optional_flag(value: &Value, key: &str) -> Result<bool, IpcError> {
    match optional(value, key) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(invalid(format!("`{key}` must be true or false"))),
    }
}

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
        "GetVersion" => Request::GetVersion,
        "GetState" => Request::GetState,
        "GetSession" => Request::GetSession,
        "ListEndpoints" => Request::ListEndpoints,
        "ListProfiles" => Request::ListProfiles,
        "ListRules" => Request::ListRules,
        "GetDiagnostics" => Request::GetDiagnostics,
        "Connect" => Request::Connect {
            acknowledge_tier2: optional_flag(&value, "acknowledge_tier2")?,
            profile: optional_string(&value, "profile")?
                .map(parse_profile_id)
                .transpose()?,
            endpoint: optional_string(&value, "endpoint")?
                .map(parse_endpoint_id)
                .transpose()?,
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

/// Encode a request in its wire form. The client half of [`decode_request`]: a request that
/// encodes here decodes to the same value.
pub fn encode_request(request: &Request) -> String {
    let name = match request {
        Request::GetVersion => "GetVersion",
        Request::GetState => "GetState",
        Request::GetSession => "GetSession",
        Request::ListEndpoints => "ListEndpoints",
        Request::ListProfiles => "ListProfiles",
        Request::ListRules => "ListRules",
        Request::GetDiagnostics => "GetDiagnostics",
        Request::Connect { .. } => "Connect",
        Request::Disconnect => "Disconnect",
        Request::AddEndpoint => "AddEndpoint",
        Request::RemoveEndpoint => "RemoveEndpoint",
        Request::SetEndpointEnabled => "SetEndpointEnabled",
        Request::AddRule => "AddRule",
        Request::RemoveRule => "RemoveRule",
        Request::SetProfileParams => "SetProfileParams",
        Request::EnableBrutal => "EnableBrutal",
        Request::SetEncryptedDnsHandling => "SetEncryptedDnsHandling",
        Request::StartProvisioning => "StartProvisioning",
        Request::CancelProvisioning => "CancelProvisioning",
        Request::Subscribe => "Subscribe",
    };
    let mut object = Map::new();
    object.insert("request".into(), Value::String(name.into()));
    if let Request::Connect {
        acknowledge_tier2,
        profile,
        endpoint,
    } = request
    {
        object.insert("acknowledge_tier2".into(), Value::Bool(*acknowledge_tier2));
        object.insert(
            "profile".into(),
            profile
                .as_ref()
                .map_or(Value::Null, |p| Value::String(p.as_str().to_owned())),
        );
        object.insert(
            "endpoint".into(),
            endpoint
                .as_ref()
                .map_or(Value::Null, |e| Value::String(e.to_string())),
        );
    }
    Value::Object(object).to_string()
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
