//! Request and response types, the error model, and wire-level validators.
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.
//! The pure decision and codec layer is implemented here (T033); wiring it to a real
//! pipe and dispatching requests is T034.
//!
//! Wire encoding is done by hand against `serde_json::Value` rather than derived, so
//! that `dnet-core`'s domain types carry no wire-format concern and the exact contract
//! shape — including which strings are *rejected* — is explicit and testable.

use crate::server_setup::ServerKind;
use dnet_config::credentials::EndpointCredentials;
use dnet_config::persist::MAX_BRUTAL_MBPS;
use dnet_core::failure::explain;
use dnet_core::ids::{EndpointId, ProfileId, RuleId};
use dnet_core::profile::{CoreBinding, BRUTAL_WARNING_REVISION};
use dnet_core::rule::{IpCidr, RoutingRule, RuleAction, RuleMatcher};
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
    /// Needs an elevated client in the console session (T160): approving a held change. The person
    /// answers a Windows elevation prompt for it; a program running as the same user cannot.
    Approval,
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
    /// The networks the computer has, which one carries the connection, and how good each is
    /// (T144). A service that predates it answers `InvalidRequest`: a client treats that as "this
    /// service cannot say", not as an empty list.
    GetPaths,
    /// What the product did during this connection (T144). Same note as `GetPaths`.
    GetStats,
    /// Every part of the connection with its state, the reason, and when it last changed (T170). Read-only,
    /// and it carries no endpoint label, address or network name. Same note as `GetPaths`: a service that
    /// predates it answers `InvalidRequest`, which a client reads as "this service cannot say".
    GetComponents,
    /// Whether the kill switch is on and whether a firewall guard is in now (T161). Read-only; it names no address,
    /// program or account. A service that predates it answers `InvalidRequest`, which a client reads as "this
    /// service cannot say".
    GetGuard,
    ListEndpoints,
    ListProfiles,
    ListRules,
    GetDiagnostics,
    /// The changes held for approval (T160), with what each would do. Read-only.
    ListPending,
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
    /// Add an endpoint the person already runs, with the credentials to reach it (FR-010). The
    /// credentials cross the control pipe in clear: the pipe is local and its access is checked, and the
    /// service seals them before they touch the disk.
    AddEndpoint(Box<NewEndpoint>),
    RemoveEndpoint {
        endpoint: EndpointId,
    },
    SetEndpointEnabled {
        endpoint: EndpointId,
        enabled: bool,
    },
    /// Add a person's rule (T108). The precedence is the service's to give: after every built-in rule,
    /// so no request can put one ahead of DNS capture or the endpoint bypass.
    AddRule {
        matcher: RuleMatcher,
        action: RuleAction,
    },
    RemoveRule {
        rule: RuleId,
    },
    SetProfileParams,
    /// Turn Brutal congestion control on for a Hysteria 2 profile (FR-006, T105). Brutal ignores loss
    /// and so takes capacity from everyone else on the access point; it is off unless a person turns it
    /// on having been shown why that matters. `warning_revision` is the revision of the warning they
    /// were shown, and only the warning in force counts. The time of acceptance is the service's.
    EnableBrutal {
        profile: ProfileId,
        up_mbps: u32,
        down_mbps: u32,
        warning_revision: u32,
    },
    /// Turn Brutal off again (back to BBR, the default).
    DisableBrutal {
        profile: ProfileId,
    },
    /// The person's choice about encrypted DNS (FR-025, FR-025a): `block: true` makes programs fall back
    /// to the system resolver (the default); `block: false` is the single-action opt-out, and its reply
    /// states the consequence.
    SetEncryptedDnsHandling {
        block: bool,
    },
    /// The person's choice about the kill switch (T161, ADR-0006 §5a): `enabled: true` makes the service keep
    /// a firewall guard in while a connection is up, so a crash or a stopped service leaves no way out around
    /// the tunnel; `false` (the default) leaves the guard out. The reply says what it did and whether a guard is
    /// in now. Turning it off takes a guard that is in out at once.
    SetKillSwitch {
        enabled: bool,
    },
    /// Take the firewall guard out now, whatever else is going on (T161, ADR-0006 §5a condition 3): the way out
    /// for a person whose connection is down and who needs the network back. It removes only the guard's own
    /// rules; removing what is not there is not an error.
    ReleaseGuard,
    /// Hand the service signed profile-feed documents it did not fetch itself (an offline import,
    /// ADR-0002 §7). The service runs exactly the checks a fetched document gets; this grants no
    /// privilege, because an import can only install what the signing keys already authorised.
    ImportFeed(FeedImport),
    /// Check for updated connection-method definitions now, because the person asked (ADR-0002 §7, D2).
    /// While a tunnel carries traffic the check goes through it; while disconnected it goes directly
    /// over the physical network, which is the one flow that bypasses the fail-closed posture and so
    /// is only ever the result of this explicit request. Takes no field: what to fetch and from where
    /// are compiled in. The reply says the check began; its result arrives as an event.
    FetchFeed,
    /// Begin setting up the person's own server (T150): the service makes the keys that stay on this
    /// computer and answers with the script to run on the server and the ports to open. `arch` is the
    /// kind of processor the server has.
    PrepareServer {
        arch: ServerKind,
    },
    /// Finish it: `report` is what the script printed on the server, pasted back. The service checks it
    /// against what it asked for and, if it matches, adds the server under `label` at `host`.
    FinishServer {
        label: String,
        host: String,
        report: String,
    },
    /// A friend's device asks to join someone's server (T188): the service makes a key that stays on this
    /// computer and answers with the text to send to the owner (a name and the public half of the key).
    /// `name` is what the owner will see for this device.
    RequestJoin {
        name: String,
    },
    /// The owner's invite, pasted (T188). The service checks it, puts this computer's own key in it, and, once
    /// a person has approved, adds the server. `label` names the server here; without it the invite's name is
    /// used.
    AcceptInvite {
        invite: String,
        label: Option<String>,
    },
    /// The owner adds a friend's device to one of their servers (T188): `request` is the text the friend sent.
    /// The answer is the script to run on that server.
    PrepareDevice {
        endpoint: EndpointId,
        request: String,
    },
    /// Finish it: `report` is what the script printed on the server. The service checks it against the request
    /// it prepared and answers with the invite to send to the friend.
    FinishDevice {
        endpoint: EndpointId,
        request: String,
        report: String,
    },
    StartProvisioning,
    CancelProvisioning,
    /// Apply a held change (T160). Only an elevated client in the console session may ask; the change
    /// is exactly the one held under `id`, which the caller cannot alter.
    ApproveChange {
        id: String,
    },
    /// Drop a held change without applying it (T160). Anyone who may make changes may withdraw one.
    RejectChange {
        id: String,
    },
    Subscribe,
}

/// Signed feed documents to import: the keys document, the feed, or both (keys are taken first, so
/// a feed signed under new keys can travel with them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedImport {
    keys: Option<String>,
    feed: Option<String>,
}

impl FeedImport {
    /// Check and make an import. Each envelope is bounded by the size cap every source is held to.
    /// Nothing is parsed here: the envelope is attacker-controlled until the service verifies it, and
    /// the service is the only place that interprets it.
    pub fn new(keys: Option<String>, feed: Option<String>) -> Result<Self, IpcError> {
        if keys.is_none() && feed.is_none() {
            return Err(invalid("give `keys`, `feed`, or both"));
        }
        for (name, text) in [("keys", &keys), ("feed", &feed)] {
            if text
                .as_ref()
                .is_some_and(|t| t.len() > dnet_core::feed::ENVELOPE_MAX_BYTES)
            {
                return Err(invalid(format!(
                    "`{name}` is larger than {} bytes, which no signed document is",
                    dnet_core::feed::ENVELOPE_MAX_BYTES
                )));
            }
        }
        Ok(Self { keys, feed })
    }

    pub fn keys(&self) -> Option<&str> {
        self.keys.as_deref()
    }

    pub fn feed(&self) -> Option<&str> {
        self.feed.as_deref()
    }
}

/// A new endpoint, as a client asks for it. Valid by construction: the label, the address and the
/// credentials have all been checked, by the same rules the saved configuration applies when it is
/// read back, so what is accepted here can always be saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEndpoint {
    label: String,
    host: String,
    credentials: EndpointCredentials,
}

/// The longest label accepted: the same limit every endpoint label has.
pub const MAX_LABEL_CHARS: usize = dnet_core::endpoint::MAX_LABEL_LEN;
/// The longest host accepted (a DNS name is at most 253 characters).
pub const MAX_HOST_CHARS: usize = 253;

/// The rules for a server's name. Every message names the field and never repeats its value.
pub fn check_label(label: &str) -> Result<&str, IpcError> {
    let label = label.trim();
    if label.is_empty()
        || label.chars().count() > MAX_LABEL_CHARS
        || !label.bytes().all(|b| (0x20..0x7F).contains(&b))
    {
        return Err(invalid(format!(
            "`label` must be 1 to {MAX_LABEL_CHARS} printable ASCII characters"
        )));
    }
    Ok(label)
}

/// The rules for a server's address: an IPv4 address a server can have, and nothing else (for now).
///
/// What the connection will refuse is refused here, not at the first connect (`dnetd`'s plan, `dialled`). A host name
/// would have to be looked up on whatever network the computer is on, before the tunnel exists, and that network can
/// answer with an address of its own choosing. An IPv6 address is not supported yet. A saved file from before may
/// still hold either; it loads, and the connect refuses it with its own reason.
pub fn check_host(host: &str) -> Result<&str, IpcError> {
    let host = host.trim();
    if host.len() > MAX_HOST_CHARS || !dnet_config::persist::host_is_acceptable(host) {
        return Err(invalid(
            "`host` must be an IPv4 address, with no scheme, port or path",
        ));
    }
    let ip = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip,
        Ok(std::net::IpAddr::V6(_)) => {
            return Err(invalid(
                "`host` must be an IPv4 address for now: IPv6 servers are not supported yet",
            ))
        }
        Err(_) => {
            return Err(invalid(
                "`host` must be an IPv4 address for now, not a host name: a name would be looked up on the network this computer is on, before the tunnel exists, and that network could answer with an address of its own",
            ))
        }
    };
    if !dnet_config::persist::address_could_be_a_server(std::net::IpAddr::V4(ip)) {
        return Err(invalid("`host` is not an address a server can have"));
    }
    Ok(host)
}

/// The rules for the text a person pastes back from their server.
fn check_report(report: &str) -> Result<(), IpcError> {
    check_pasted("report", report, crate::server_setup::MAX_REPORT_CHARS).map_err(|_| {
        invalid(format!(
            "`report` must be the text the server printed, up to {} characters, with no control characters",
            crate::server_setup::MAX_REPORT_CHARS
        ))
    })
}

/// The rules for any text a person pastes: not empty, not longer than `max` characters, and no control or
/// direction characters other than line breaks and tabs. What the text means is decided by whoever reads it.
fn check_pasted(field: &str, text: &str, max: usize) -> Result<(), IpcError> {
    let bad = |c: char| crate::netview::is_hostile(c) && !matches!(c, '\n' | '\r' | '\t');
    if text.trim().is_empty() || text.chars().count() > max || text.chars().any(bad) {
        return Err(invalid(format!(
            "`{field}` must be pasted text of up to {max} characters, with no control characters"
        )));
    }
    Ok(())
}

/// The rules for the name a friend's device gives itself.
fn check_device_name(name: &str) -> Result<&str, IpcError> {
    if !dnet_config::invite::valid_name(name) {
        return Err(invalid(format!(
            "`name` must be 1 to {} letters, digits, spaces, dots, dashes or underscores",
            dnet_config::invite::MAX_NAME_LEN
        )));
    }
    Ok(name)
}

impl NewEndpoint {
    /// Check and make a new endpoint. Every message names the field and never repeats its value.
    pub fn new(
        label: &str,
        host: &str,
        credentials: EndpointCredentials,
    ) -> Result<Self, IpcError> {
        let label = check_label(label)?;
        let host = check_host(host)?;
        if credentials.is_empty() {
            return Err(invalid("`credentials` holds no connection method"));
        }
        // What cannot be stored cannot be accepted: the generators' own rules, applied now.
        credentials
            .to_plaintext_json()
            .map_err(|e| invalid(format!("`credentials` {e}")))?;
        Ok(Self {
            label: label.to_owned(),
            host: host.to_owned(),
            credentials,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn credentials(&self) -> &EndpointCredentials {
        &self.credentials
    }

    /// Take the credentials out, to be sealed.
    pub fn into_credentials(self) -> EndpointCredentials {
        self.credentials
    }
}

impl Request {
    /// The authorization class this request belongs to (contract §Request classes).
    pub fn class(&self) -> RequestClass {
        use Request::*;
        match self {
            GetVersion | GetState | GetSession | GetPaths | GetStats | GetComponents | GetGuard
            | ListEndpoints | ListProfiles | ListRules | GetDiagnostics | ListPending => {
                RequestClass::ReadOnly
            }
            Subscribe => RequestClass::Stream,
            Connect { .. }
            | Disconnect
            | AddEndpoint(_)
            | RemoveEndpoint { .. }
            | SetEndpointEnabled { .. }
            | AddRule { .. }
            | RemoveRule { .. }
            | SetProfileParams
            | EnableBrutal { .. }
            | DisableBrutal { .. }
            | SetEncryptedDnsHandling { .. }
            | SetKillSwitch { .. }
            | ReleaseGuard
            | ImportFeed(_)
            | FetchFeed
            | PrepareServer { .. }
            | FinishServer { .. }
            | RequestJoin { .. }
            | AcceptInvite { .. }
            | PrepareDevice { .. }
            | FinishDevice { .. }
            | StartProvisioning
            | CancelProvisioning
            | RejectChange { .. } => RequestClass::Mutating,
            ApproveChange { .. } => RequestClass::Approval,
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
    /// The change redirects traffic, so it is held until an elevated client approves it (T160). The
    /// service applied nothing. `what` names the change in the person's words and `id` is how to
    /// approve it.
    #[error(
        "{what} waits for approval (change {id}). Approve it with `dnetctl approve {id}` and answer \
         the Windows prompt; it is dropped after ten minutes"
    )]
    ApprovalRequired { id: String, what: String },
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
/// The longest program path a rule may name (the Windows `MAX_PATH`).
const MAX_PROGRAM_PATH: usize = 260;

/// A rule a person can make: what it matches, from the kinds a person may use, and `tunnel` or
/// `bypass`. Checked by the rule model itself (`RoutingRule::user`), so a pattern it would refuse is
/// refused here. Errors name the field, never the value.
fn personal_rule(
    kind: &str,
    value: &str,
    action: &str,
) -> Result<(RuleMatcher, RuleAction), IpcError> {
    let matcher = match kind {
        "domain" => RuleMatcher::Domain(value.to_owned()),
        "domain_suffix" => RuleMatcher::DomainSuffix(value.to_owned()),
        "ip_cidr" => RuleMatcher::IpCidr(
            IpCidr::parse(value)
                .map_err(|_| invalid("`value` must be an address range such as 198.51.100.0/24"))?,
        ),
        "application" => {
            let printable = value.chars().all(|c| {
                !c.is_control() && !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            });
            if value.trim().is_empty() || value.chars().count() > MAX_PROGRAM_PATH || !printable {
                return Err(invalid(format!(
                    "`value` must be a program path of 1 to {MAX_PROGRAM_PATH} printable characters"
                )));
            }
            RuleMatcher::Application(value.to_owned())
        }
        _ => {
            return Err(invalid(
                "`kind` must be domain, domain_suffix, ip_cidr or application",
            ))
        }
    };
    let action = match action {
        "tunnel" => RuleAction::Tunnel,
        "bypass" => RuleAction::Bypass,
        _ => return Err(invalid("`action` must be tunnel or bypass")),
    };
    // The precedence here is a stand-in; the service gives the real one. The checks do not depend on it.
    RoutingRule::user(
        matcher.clone(),
        action,
        dnet_core::doh_block::USER_RULES_START,
    )
    .map_err(|_| invalid("`value` is not a pattern this kind of rule can match"))?;
    Ok((matcher, action))
}

/// A rule's matcher as the `kind` and `value` of the wire.
pub fn rule_wire(matcher: &RuleMatcher) -> (&'static str, String) {
    match matcher {
        RuleMatcher::Domain(d) => ("domain", d.clone()),
        RuleMatcher::DomainSuffix(d) => ("domain_suffix", d.clone()),
        RuleMatcher::IpCidr(c) => ("ip_cidr", c.to_string()),
        RuleMatcher::Application(p) => ("application", p.clone()),
        RuleMatcher::DnsPort => ("dns_port", "53".to_owned()),
        RuleMatcher::EncryptedDnsPort => (
            "encrypted_dns_port",
            dnet_core::doh_block::ENCRYPTED_DNS_PORT.to_string(),
        ),
    }
}

fn parse_rule_id(raw: &str) -> Result<RuleId, IpcError> {
    if raw.len() == 36 {
        if let Ok(uuid) = Uuid::parse_str(raw) {
            return Ok(RuleId::from_uuid(uuid));
        }
    }
    Err(invalid("`rule` must be a UUID in its hyphenated form"))
}

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

/// A field a request cannot do without.
fn field<'v>(value: &'v Value, key: &str) -> Result<&'v Value, IpcError> {
    match value.get(key) {
        None | Some(Value::Null) => Err(invalid(format!("`{key}` is required"))),
        Some(v) => Ok(v),
    }
}

fn field_str<'v>(value: &'v Value, key: &str) -> Result<&'v str, IpcError> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| invalid(format!("`{key}` must be a string")))
}

/// A Brutal bandwidth, in Mbit/s: a whole number from 1 to the bound the saved configuration holds.
/// Zero on either side would half-enable Brutal (CC-04).
fn field_mbps(value: &Value, key: &str) -> Result<u32, IpcError> {
    field(value, key)?
        .as_u64()
        .filter(|n| (1..=u64::from(MAX_BRUTAL_MBPS)).contains(n))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            invalid(format!(
                "`{key}` must be a whole number of Mbit/s from 1 to {MAX_BRUTAL_MBPS}"
            ))
        })
}

fn field_bool(value: &Value, key: &str) -> Result<bool, IpcError> {
    field(value, key)?
        .as_bool()
        .ok_or_else(|| invalid(format!("`{key}` must be true or false")))
}

/// A request that changes the configuration carries exactly the fields it names. A field it does not
/// know is refused, never ignored: a misspelt `enabled` that silently defaulted would change the wrong
/// thing, and these are the requests where that matters.
fn only_fields(value: &Value, allowed: &[&str]) -> Result<(), IpcError> {
    if let Some(object) = value.as_object() {
        if object.keys().any(|k| !allowed.contains(&k.as_str())) {
            // The unknown name is the client's text and is not repeated: it is said what the request
            // does take, which is both safer and more use than echoing a typo back.
            let takes: Vec<&str> = allowed
                .iter()
                .copied()
                .filter(|k| *k != "request")
                .collect();
            return Err(invalid(format!(
                "unknown field; this request takes only: {}",
                takes.join(", ")
            )));
        }
    }
    Ok(())
}

/// The longest a held change's name may be on the wire.
pub const CHANGE_ID_MAX: usize = 32;

/// A held change's id: short, lower-case letters and digits, so it can be typed and never carries
/// anything else. It names a change; it is not a secret, because approval needs elevation, not the id.
fn parse_change_id(text: &str) -> Result<String, IpcError> {
    let good = !text.is_empty()
        && text.len() <= CHANGE_ID_MAX
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if good {
        Ok(text.to_owned())
    } else {
        Err(invalid(
            "`id` must be 1 to 32 lower-case letters and digits, as shown with the change",
        ))
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
        "GetPaths" => Request::GetPaths,
        "GetStats" => Request::GetStats,
        "GetComponents" => Request::GetComponents,
        "GetGuard" => Request::GetGuard,
        "ListEndpoints" => Request::ListEndpoints,
        "ListProfiles" => Request::ListProfiles,
        "ListRules" => Request::ListRules,
        "GetDiagnostics" => Request::GetDiagnostics,
        "ListPending" => Request::ListPending,
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
        "AddEndpoint" => {
            only_fields(&value, &["request", "label", "host", "credentials"])?;
            // The credentials are the same strict form the service stores them in: an unknown field, a
            // wrong version or a value a generator would refuse is `InvalidRequest`. The error names a
            // place, never a value.
            let credentials_value = field(&value, "credentials")?;
            if !credentials_value.is_object() {
                return Err(invalid("`credentials` must be an object"));
            }
            let credentials = EndpointCredentials::from_plaintext_json(
                &serde_json::to_vec(credentials_value)
                    .map_err(|_| invalid("`credentials` could not be read"))?,
            )
            .map_err(|e| invalid(format!("`credentials`: {e}")))?;
            Request::AddEndpoint(Box::new(NewEndpoint::new(
                field_str(&value, "label")?,
                field_str(&value, "host")?,
                credentials,
            )?))
        }
        "RemoveEndpoint" => {
            only_fields(&value, &["request", "endpoint"])?;
            Request::RemoveEndpoint {
                endpoint: parse_endpoint_id(field_str(&value, "endpoint")?)?,
            }
        }
        "SetEndpointEnabled" => {
            only_fields(&value, &["request", "endpoint", "enabled"])?;
            Request::SetEndpointEnabled {
                endpoint: parse_endpoint_id(field_str(&value, "endpoint")?)?,
                enabled: field_bool(&value, "enabled")?,
            }
        }
        "AddRule" => {
            only_fields(&value, &["request", "kind", "value", "action"])?;
            let (matcher, action) = personal_rule(
                field_str(&value, "kind")?,
                field_str(&value, "value")?,
                field_str(&value, "action")?,
            )?;
            Request::AddRule { matcher, action }
        }
        "RemoveRule" => {
            only_fields(&value, &["request", "rule"])?;
            Request::RemoveRule {
                rule: parse_rule_id(field_str(&value, "rule")?)?,
            }
        }
        "SetProfileParams" => Request::SetProfileParams,
        "EnableBrutal" => {
            only_fields(
                &value,
                &[
                    "request",
                    "profile",
                    "up_mbps",
                    "down_mbps",
                    "warning_revision",
                ],
            )?;
            let profile = parse_profile_id(field_str(&value, "profile")?)?;
            let up_mbps = field_mbps(&value, "up_mbps")?;
            let down_mbps = field_mbps(&value, "down_mbps")?;
            let warning_revision = field(&value, "warning_revision")?
                .as_u64()
                .and_then(|r| u32::try_from(r).ok())
                .filter(|r| *r == BRUTAL_WARNING_REVISION)
                .ok_or_else(|| {
                    invalid(
                        "`warning_revision` is not the warning in force; show the current \
                         warning and send the revision that was shown",
                    )
                })?;
            Request::EnableBrutal {
                profile,
                up_mbps,
                down_mbps,
                warning_revision,
            }
        }
        "DisableBrutal" => {
            only_fields(&value, &["request", "profile"])?;
            Request::DisableBrutal {
                profile: parse_profile_id(field_str(&value, "profile")?)?,
            }
        }
        "SetEncryptedDnsHandling" => {
            only_fields(&value, &["request", "block"])?;
            Request::SetEncryptedDnsHandling {
                block: field_bool(&value, "block")?,
            }
        }
        "SetKillSwitch" => {
            only_fields(&value, &["request", "enabled"])?;
            Request::SetKillSwitch {
                enabled: field_bool(&value, "enabled")?,
            }
        }
        "ReleaseGuard" => {
            only_fields(&value, &["request"])?;
            Request::ReleaseGuard
        }
        "ImportFeed" => {
            only_fields(&value, &["request", "keys", "feed"])?;
            Request::ImportFeed(FeedImport::new(
                optional_string(&value, "keys")?.map(str::to_owned),
                optional_string(&value, "feed")?.map(str::to_owned),
            )?)
        }
        "FetchFeed" => {
            only_fields(&value, &["request"])?;
            Request::FetchFeed
        }
        "PrepareServer" => {
            only_fields(&value, &["request", "arch"])?;
            let arch = field_str(&value, "arch")?;
            Request::PrepareServer {
                arch: ServerKind::parse(arch)
                    .ok_or_else(|| invalid("`arch` must be `amd64` or `arm64`"))?,
            }
        }
        "FinishServer" => {
            only_fields(&value, &["request", "label", "host", "report"])?;
            let label = check_label(field_str(&value, "label")?)?.to_owned();
            let host = check_host(field_str(&value, "host")?)?.to_owned();
            let report = field_str(&value, "report")?;
            check_report(report)?;
            Request::FinishServer {
                label,
                host,
                report: report.to_owned(),
            }
        }
        "RequestJoin" => {
            only_fields(&value, &["request", "name"])?;
            Request::RequestJoin {
                name: check_device_name(field_str(&value, "name")?)?.to_owned(),
            }
        }
        "AcceptInvite" => {
            only_fields(&value, &["request", "invite", "label"])?;
            let invite = field_str(&value, "invite")?;
            check_pasted("invite", invite, crate::devices::MAX_INVITE_CHARS)?;
            let label = match optional_string(&value, "label")? {
                Some(label) => Some(check_label(label)?.to_owned()),
                None => None,
            };
            Request::AcceptInvite {
                invite: invite.to_owned(),
                label,
            }
        }
        "PrepareDevice" => {
            only_fields(&value, &["request", "endpoint", "text"])?;
            let text = field_str(&value, "text")?;
            check_pasted("text", text, crate::devices::MAX_REQUEST_CHARS)?;
            Request::PrepareDevice {
                endpoint: parse_endpoint_id(field_str(&value, "endpoint")?)?,
                request: text.to_owned(),
            }
        }
        "FinishDevice" => {
            only_fields(&value, &["request", "endpoint", "text", "report"])?;
            let text = field_str(&value, "text")?;
            check_pasted("text", text, crate::devices::MAX_REQUEST_CHARS)?;
            check_report(field_str(&value, "report")?)?;
            Request::FinishDevice {
                endpoint: parse_endpoint_id(field_str(&value, "endpoint")?)?,
                request: text.to_owned(),
                report: field_str(&value, "report")?.to_owned(),
            }
        }
        "StartProvisioning" => Request::StartProvisioning,
        "CancelProvisioning" => Request::CancelProvisioning,
        "ApproveChange" => {
            only_fields(&value, &["request", "id"])?;
            Request::ApproveChange {
                id: parse_change_id(field_str(&value, "id")?)?,
            }
        }
        "RejectChange" => {
            only_fields(&value, &["request", "id"])?;
            Request::RejectChange {
                id: parse_change_id(field_str(&value, "id")?)?,
            }
        }
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
        Request::GetPaths => "GetPaths",
        Request::GetStats => "GetStats",
        Request::GetComponents => "GetComponents",
        Request::GetGuard => "GetGuard",
        Request::ListEndpoints => "ListEndpoints",
        Request::ListProfiles => "ListProfiles",
        Request::ListRules => "ListRules",
        Request::GetDiagnostics => "GetDiagnostics",
        Request::ListPending => "ListPending",
        Request::Connect { .. } => "Connect",
        Request::Disconnect => "Disconnect",
        Request::AddEndpoint(_) => "AddEndpoint",
        Request::RemoveEndpoint { .. } => "RemoveEndpoint",
        Request::SetEndpointEnabled { .. } => "SetEndpointEnabled",
        Request::AddRule { .. } => "AddRule",
        Request::RemoveRule { .. } => "RemoveRule",
        Request::SetProfileParams => "SetProfileParams",
        Request::EnableBrutal { .. } => "EnableBrutal",
        Request::DisableBrutal { .. } => "DisableBrutal",
        Request::SetEncryptedDnsHandling { .. } => "SetEncryptedDnsHandling",
        Request::SetKillSwitch { .. } => "SetKillSwitch",
        Request::ReleaseGuard => "ReleaseGuard",
        Request::ImportFeed(_) => "ImportFeed",
        Request::FetchFeed => "FetchFeed",
        Request::PrepareServer { .. } => "PrepareServer",
        Request::FinishServer { .. } => "FinishServer",
        Request::RequestJoin { .. } => "RequestJoin",
        Request::AcceptInvite { .. } => "AcceptInvite",
        Request::PrepareDevice { .. } => "PrepareDevice",
        Request::FinishDevice { .. } => "FinishDevice",
        Request::StartProvisioning => "StartProvisioning",
        Request::CancelProvisioning => "CancelProvisioning",
        Request::ApproveChange { .. } => "ApproveChange",
        Request::RejectChange { .. } => "RejectChange",
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
    match request {
        Request::AddEndpoint(new) => {
            object.insert("label".into(), Value::String(new.label.clone()));
            object.insert("host".into(), Value::String(new.host.clone()));
            // Valid by construction (`NewEndpoint::new` stored it once already), so this cannot fail.
            let credentials = new
                .credentials
                .to_plaintext_json()
                .expect("credentials were checked when the request was made");
            object.insert(
                "credentials".into(),
                serde_json::from_slice(&credentials).expect("the stored form is JSON"),
            );
        }
        Request::RemoveEndpoint { endpoint } => {
            object.insert("endpoint".into(), Value::String(endpoint.to_string()));
        }
        Request::SetEndpointEnabled { endpoint, enabled } => {
            object.insert("endpoint".into(), Value::String(endpoint.to_string()));
            object.insert("enabled".into(), Value::Bool(*enabled));
        }
        Request::SetEncryptedDnsHandling { block } => {
            object.insert("block".into(), Value::Bool(*block));
        }
        Request::SetKillSwitch { enabled } => {
            object.insert("enabled".into(), Value::Bool(*enabled));
        }
        Request::PrepareServer { arch } => {
            object.insert("arch".into(), Value::String(arch.as_str().to_owned()));
        }
        Request::FinishServer {
            label,
            host,
            report,
        } => {
            object.insert("label".into(), Value::String(label.clone()));
            object.insert("host".into(), Value::String(host.clone()));
            object.insert("report".into(), Value::String(report.clone()));
        }
        Request::RequestJoin { name } => {
            object.insert("name".into(), Value::String(name.clone()));
        }
        Request::AcceptInvite { invite, label } => {
            object.insert("invite".into(), Value::String(invite.clone()));
            if let Some(label) = label {
                object.insert("label".into(), Value::String(label.clone()));
            }
        }
        Request::PrepareDevice { endpoint, request } => {
            object.insert("endpoint".into(), Value::String(endpoint.to_string()));
            object.insert("text".into(), Value::String(request.clone()));
        }
        Request::FinishDevice {
            endpoint,
            request,
            report,
        } => {
            object.insert("endpoint".into(), Value::String(endpoint.to_string()));
            object.insert("text".into(), Value::String(request.clone()));
            object.insert("report".into(), Value::String(report.clone()));
        }
        Request::EnableBrutal {
            profile,
            up_mbps,
            down_mbps,
            warning_revision,
        } => {
            object.insert("profile".into(), Value::String(profile.as_str().to_owned()));
            object.insert("up_mbps".into(), Value::from(*up_mbps));
            object.insert("down_mbps".into(), Value::from(*down_mbps));
            object.insert("warning_revision".into(), Value::from(*warning_revision));
        }
        Request::AddRule { matcher, action } => {
            let (kind, value) = rule_wire(matcher);
            object.insert("kind".into(), Value::String(kind.to_owned()));
            object.insert("value".into(), Value::String(value));
            object.insert(
                "action".into(),
                Value::String(
                    match action {
                        RuleAction::Tunnel => "tunnel",
                        // `personal_rule` makes nothing else; a request built in code that holds
                        // another action is refused when it is decoded at the other end.
                        RuleAction::Bypass => "bypass",
                        RuleAction::Capture => "capture",
                        RuleAction::Reject => "reject",
                    }
                    .to_owned(),
                ),
            );
        }
        Request::RemoveRule { rule } => {
            object.insert("rule".into(), Value::String(rule.to_string()));
        }
        Request::ApproveChange { id } | Request::RejectChange { id } => {
            object.insert("id".into(), Value::String(id.clone()));
        }
        Request::DisableBrutal { profile } => {
            object.insert("profile".into(), Value::String(profile.as_str().to_owned()));
        }
        Request::ImportFeed(import) => {
            if let Some(keys) = import.keys() {
                object.insert("keys".into(), Value::String(keys.to_owned()));
            }
            if let Some(feed) = import.feed() {
                object.insert("feed".into(), Value::String(feed.to_owned()));
            }
        }
        _ => {}
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
        IpcError::ApprovalRequired { .. } => "ApprovalRequired",
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
