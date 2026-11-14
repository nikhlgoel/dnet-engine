// SPDX-License-Identifier: GPL-3.0-or-later
//! The event stream's wire form and its fan-out (T125).
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md` §Subscribe. Every
//! event carries a `because` that explains it (IPC-06); this module is where that is made true for
//! every `ConnectionEvent`, including the ones whose domain form has no `because` of its own.
//!
//! [`EventBus`] is the daemon's side: it numbers events, keeps the current session's events
//! (bounded) so a late subscriber starts with the story so far, and fans new events out to
//! subscribers without ever letting a slow one hold the daemon's memory.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use dnet_core::degraded::NoMove;
use dnet_core::failure::{core_description, explain};
use dnet_core::quality::QualityBand;
use dnet_core::session::{CheckFailure, ConnectionEvent, DefinitionsChange};
use dnet_core::tier::FailoverTier;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::protocol::{
    core_binding_str, failure_value_with_words, tier_str, validate_because, IpcError,
};

/// How many events of the current session a late subscriber is replayed. Older ones are dropped:
/// `GetSession` is the full history, the stream is the live view.
pub const SESSION_BACKLOG: usize = 256;

/// How many clients may hold a subscription at once. `Subscribe` needs only an authenticated
/// caller, so any logged-on user could otherwise open them without limit.
pub const MAX_SUBSCRIBERS: usize = 16;

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
}

// ------------------------------------------------------------------ event encoding

/// What a degradation says: how poor the path is, and why the connection is staying on it. Each
/// reason is told differently, and none claims a move: the whole point of the notice is that there
/// was none (FR-019).
fn degraded_because(band: QualityBand, staying: NoMove) -> Result<String, IpcError> {
    let how = match band {
        QualityBand::Poor => "the network carrying your connection is slow or dropping packets",
        QualityBand::Unusable => "the network carrying your connection is dropping most packets",
        // Degraded means below good. A producer that says otherwise has a bug; send nothing.
        QualityBand::Good => return Err(invalid("a degradation cannot be of a good network")),
    };
    let why = match staying {
        NoMove::OnlyPath => "it is the only network available, so there is nothing to switch to",
        NoMove::NoBetterPath => "the other networks are no better, so the connection stays where it is",
        NoMove::Proving => {
            "a better network exists but has not yet proven stable, so the connection has not moved"
        }
        NoMove::Dwell => "the connection was moved a moment ago and waits before moving again",
        NoMove::Budget => {
            "the limit on moves in ten minutes has been reached, so the connection stays where it is"
        }
    };
    Ok(format!("{how}, and {why}"))
}

fn band_str(band: QualityBand) -> &'static str {
    match band {
        QualityBand::Good => "Good",
        QualityBand::Poor => "Poor",
        QualityBand::Unusable => "Unusable",
    }
}

/// The machine-readable name of why a connection is staying on a poor network.
pub(crate) fn staying_name(staying: NoMove) -> &'static str {
    match staying {
        NoMove::OnlyPath => "OnlyPath",
        NoMove::NoBetterPath => "NoBetterPath",
        NoMove::Proving => "Proving",
        NoMove::Dwell => "Dwell",
        NoMove::Budget => "Budget",
    }
}

fn path_change_because(tier: FailoverTier, first_path: bool) -> &'static str {
    // The first path the connection is seen on is not a move, and saying "changed ... the move" about it told a
    // person who had just connected that their network had changed. It happens at every connect, and again each time a
    // transport process is started again.
    if first_path {
        return "the connection is now carried by this network";
    }
    match tier {
        FailoverTier::Tier1 => {
            "the network connection carrying your traffic changed; this profile is Tier 1, so              established connections should survive the move"
        }
        FailoverTier::Tier2 => {
            "the network connection carrying your traffic changed; this profile is Tier 2, so              established connections will not survive the move"
        }
    }
}

/// A 64-bit interface id as a decimal string: a JSON number loses bits above 2^53.
fn interface_str(id: dnet_core::ids::InterfaceId) -> String {
    id.luid().to_string()
}

/// The JSON object for an event, without its sequence number.
///
/// Fails if a producer supplied an empty or restating `because`/`reason`: that is a defect in the
/// producer, surfaced instead of sent as a blank.
fn event_value(event: &ConnectionEvent) -> Result<Value, IpcError> {
    let (name, mut fields, because): (&str, Value, String) = match event {
        ConnectionEvent::ProbeStarted => (
            "ProbeStarted",
            json!({}),
            "a connection was requested, so each configured profile is being tested for usable \
             throughput"
                .to_string(),
        ),
        ConnectionEvent::ProfileSelected { profile, because } => (
            "ProfileSelected",
            json!({ "profile": profile.as_str() }),
            because.clone(),
        ),
        ConnectionEvent::ProfileBlocked { profile, reason } => (
            "ProfileBlocked",
            json!({ "profile": profile.as_str() }),
            reason.clone(),
        ),
        ConnectionEvent::EndpointMigrated { from, to, because } => (
            "EndpointMigrated",
            json!({ "from": from.to_string(), "to": to.to_string() }),
            because.clone(),
        ),
        ConnectionEvent::PathChanged {
            from,
            to,
            tier_at_time,
        } => (
            "PathChanged",
            json!({
                "from": from.map(interface_str),
                "to": interface_str(*to),
                "tier_at_time": tier_str(*tier_at_time),
            }),
            path_change_because(*tier_at_time, from.is_none()).to_string(),
        ),
        ConnectionEvent::Degraded {
            path,
            band,
            staying,
        } => (
            "Degraded",
            json!({
                "path": interface_str(*path),
                "quality": band_str(*band),
                "staying": staying_name(*staying),
            }),
            degraded_because(*band, *staying)?,
        ),
        ConnectionEvent::Recovered { path } => (
            "Recovered",
            json!({ "path": interface_str(*path) }),
            "the network carrying your connection is working normally again".to_string(),
        ),
        ConnectionEvent::CoreRestarted { core, attempt } => (
            "CoreRestarted",
            json!({ "core": core_binding_str(core), "attempt": attempt }),
            format!(
                "{} stopped unexpectedly and was restarted (attempt {attempt})",
                core_description(core)
            ),
        ),
        ConnectionEvent::DefinitionsChanged { change } => (
            "DefinitionsChanged",
            definitions_fields(*change),
            definitions_because(*change),
        ),
        ConnectionEvent::Failed { cause } => (
            "Failed",
            json!({ "failure": failure_value_with_words(cause) }),
            explain(cause).detail,
        ),
    };

    validate_because(name, &because)?;

    if let Some(object) = fields.as_object_mut() {
        object.insert("event".into(), Value::String(name.into()));
        object.insert("because".into(), Value::String(because));
    }
    Ok(fields)
}

fn definitions_fields(change: DefinitionsChange) -> Value {
    match change {
        DefinitionsChange::Updated {
            sequence,
            endpoint_updates,
        } => json!({
            "change": "Updated",
            // A sequence is a 64-bit number: a JSON number would lose bits above 2^53.
            "sequence": sequence.to_string(),
            "endpoint_updates": endpoint_updates,
        }),
        DefinitionsChange::Evicted => json!({ "change": "Evicted" }),
        DefinitionsChange::OutOfDate => json!({ "change": "OutOfDate" }),
        DefinitionsChange::Discarded => json!({ "change": "Discarded" }),
        DefinitionsChange::CheckFailed { reason } => json!({
            "change": "CheckFailed",
            "reason": match reason {
                CheckFailure::Unreachable => "Unreachable",
                CheckFailure::Refused => "Refused",
            },
        }),
    }
}

fn definitions_because(change: DefinitionsChange) -> String {
    match change {
        DefinitionsChange::Updated {
            sequence,
            endpoint_updates: 0,
        } => format!("connection method definitions updated (sequence {sequence})"),
        DefinitionsChange::Updated {
            sequence,
            endpoint_updates,
        } => format!(
            "connection method definitions updated (sequence {sequence}); {endpoint_updates} of              them also propose a change to your server, which waits for your approval"
        ),
        DefinitionsChange::Evicted => "a newer set of signing keys no longer includes the key              that signed the last update, so the built-in definitions are back in use"
            .to_string(),
        DefinitionsChange::OutOfDate => "the connection method definitions have not been              refreshed lately and may be out of date; the last ones are still in use"
            .to_string(),
        DefinitionsChange::Discarded => "the saved update could not be checked again and was              set aside, so the built-in definitions are in use"
            .to_string(),
        DefinitionsChange::CheckFailed {
            reason: CheckFailure::Unreachable,
        } => "the place connection method updates are published could not be reached, so the              definitions in use are unchanged"
            .to_string(),
        DefinitionsChange::CheckFailed {
            reason: CheckFailure::Refused,
        } => "an update was found but did not pass verification, so it was not used and the              definitions in use are unchanged"
            .to_string(),
    }
}

/// Encode an event in its wire form (no sequence number; [`EventBus::publish`] adds one).
pub fn encode_event(event: &ConnectionEvent) -> Result<String, IpcError> {
    event_value(event).map(|v| v.to_string())
}

/// The notice sent in place of events a slow subscriber missed. It carries a `because` like any
/// other event, and no `seq`: the next real event's number shows how far the stream moved.
pub fn events_lost(missed: u64) -> String {
    json!({
        "event": "EventsLost",
        "missed": missed,
        "because": format!(
            "this client read events too slowly, so {missed} were dropped; request the session \
             for the full history"
        ),
    })
    .to_string()
}

/// What a client needs from an event frame, read defensively.
#[derive(Debug, Clone, PartialEq)]
pub struct EventView {
    /// The event's name.
    pub event: String,
    /// Why it happened, in words. Never empty, never the event's name.
    pub because: String,
    /// The whole frame, for fields specific to the event.
    pub value: Value,
}

/// Read an event frame the way a client must: untrusted, and with the `because` rule enforced.
pub fn decode_event_view(wire: &str) -> Result<EventView, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|e| invalid(e.to_string()))?;
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("an event needs a name"))?
        .to_owned();
    let because = value
        .get("because")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("an event needs a `because`"))?
        .to_owned();
    validate_because(&event, &because)?;
    Ok(EventView {
        event,
        because,
        value,
    })
}

// ------------------------------------------------------------------ the bus

struct BusState {
    next_seq: u64,
    backlog: VecDeque<String>,
}

struct Inner {
    state: Mutex<BusState>,
    live: broadcast::Sender<String>,
    subscribers: AtomicUsize,
}

/// Releases a subscriber slot when the subscription ends, however it ends.
struct Slot(Arc<Inner>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.subscribers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One client's view of the stream: the session so far, then everything new.
///
/// Dropping it frees the subscriber slot.
pub struct Subscription {
    /// Events already published in the current session, oldest first.
    pub backlog: Vec<String>,
    /// Events published from now on. Follows `backlog` with no gap and no repeat.
    pub live: broadcast::Receiver<String>,
    _slot: Slot,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("backlog", &self.backlog.len())
            .finish_non_exhaustive()
    }
}

/// Numbers events, remembers the current session's, and fans them out.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<Inner>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (live, _) = broadcast::channel(SESSION_BACKLOG);
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(BusState {
                    next_seq: 1,
                    backlog: VecDeque::with_capacity(SESSION_BACKLOG),
                }),
                live,
                subscribers: AtomicUsize::new(0),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BusState> {
        // The state is two plain fields; a panic elsewhere cannot leave it half-updated.
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// A new connection attempt begins: forget the previous session's events. Numbering carries
    /// on, so a sequence number is never reused within one run of the daemon.
    pub fn begin_session(&self) {
        self.state().backlog.clear();
    }

    /// Number an event, remember it, and send it to every subscriber.
    ///
    /// Fails, recording nothing, if the event has no real `because`. Having no subscriber is not
    /// a failure.
    pub fn publish(&self, event: &ConnectionEvent) -> Result<(), IpcError> {
        let mut value = event_value(event)?;
        let mut state = self.state();
        let seq = state.next_seq;
        state.next_seq += 1;
        if let Some(object) = value.as_object_mut() {
            object.insert("seq".into(), json!(seq));
        }
        let frame = value.to_string();
        if state.backlog.len() == SESSION_BACKLOG {
            state.backlog.pop_front();
        }
        state.backlog.push_back(frame.clone());
        // Sent while the lock is held, so a subscriber that takes its backlog under the same lock
        // sees each event exactly once: in the backlog or on the channel, never both, never neither.
        let _ = self.inner.live.send(frame);
        Ok(())
    }

    /// Start a subscription, or `ServiceBusy` (retryable) if [`MAX_SUBSCRIBERS`] are already held.
    pub fn subscribe(&self) -> Result<Subscription, IpcError> {
        let held = self.inner.subscribers.fetch_add(1, Ordering::SeqCst);
        let slot = Slot(Arc::clone(&self.inner));
        if held >= MAX_SUBSCRIBERS {
            // `slot` is dropped on return and gives the slot back.
            return Err(IpcError::ServiceBusy);
        }
        let state = self.state();
        let live = self.inner.live.subscribe();
        let backlog = state.backlog.iter().cloned().collect();
        drop(state);
        Ok(Subscription {
            backlog,
            live,
            _slot: slot,
        })
    }
}
