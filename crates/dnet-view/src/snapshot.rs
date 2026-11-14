// SPDX-License-Identifier: GPL-3.0-or-later
//! T100 — the state of the connection as the window draws it.
//!
//! The service answers three questions separately (`GetState`, `GetPaths`, `GetStats`); the window wants one
//! picture. This puts them together, in the field names the window's parser reads (`model.ts`), without
//! adding, rounding or smoothing anything: a number the service did not measure stays absent, and a network
//! with no measurement stays marked as not measured.

use dnet_core::failure::explain;
use dnet_core::posture::RoutingPosture;
use dnet_core::session::FailureCause;
use dnet_core::tier::FailoverTier;
use dnet_ipc::netview::{DegradedReply, Kind, PathReply, PathsReply, Quality, Role, StatsReply};
use dnet_ipc::protocol::{ConnectionStatus, StateSnapshot, Warning};
use serde_json::{json, Value};

use crate::text::plain;

/// Put the three replies, and the latest thing the service said it did, into one view.
///
/// `paths` and `stats` are `None` when the service could not answer them (an older service, T144). The view
/// then says nothing is being watched and nothing is being counted, which the window shows as "not measured".
/// `last_because` is the `because` of the latest event, in the service's words; the window shows it as the
/// reason for the state it is looking at.
#[must_use]
pub fn view(
    state: &StateSnapshot,
    paths: Option<&PathsReply>,
    stats: Option<&StatsReply>,
    last_because: Option<&str>,
    now_ms: u64,
) -> Value {
    json!({
        "status": status(state.status),
        "activeProfile": state.active_profile.as_ref().map(|p| json!({
            "id": plain(&p.id, 64),
            "kind": plain(&p.kind, 32),
            "tier": tier(p.tier),
        })),
        "activeEndpoint": state.active_endpoint.as_ref().map(|e| json!({
            "id": plain(&e.id, 64),
            "label": plain(&e.label, 64),
        })),
        "failure": state.failure.as_ref().map(failure),
        "warnings": state.warnings.iter().map(|w| warning(*w)).collect::<Vec<_>>(),
        "posture": posture(state.posture),
        "paths": paths_view(paths, now_ms),
        "stats": stats_view(stats),
        "lastBecause": last_because.map(|b| plain(b, 400)),
    })
}

fn status(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Disconnected => "Disconnected",
        ConnectionStatus::Probing => "Probing",
        ConnectionStatus::Connected => "Connected",
        ConnectionStatus::Failed => "Failed",
    }
}

fn tier(tier: FailoverTier) -> &'static str {
    match tier {
        FailoverTier::Tier1 => "Tier1",
        FailoverTier::Tier2 => "Tier2",
    }
}

fn warning(warning: Warning) -> &'static str {
    match warning {
        Warning::Tier2ProfileActive => "Tier2ProfileActive",
        Warning::BrutalEnabled => "BrutalEnabled",
        Warning::EncryptedDnsOverridden => "EncryptedDnsOverridden",
    }
}

fn posture(posture: RoutingPosture) -> Value {
    match posture {
        RoutingPosture::Tunnelled { tier: t } => json!({ "kind": "Tunnelled", "tier": tier(t) }),
        RoutingPosture::FailClosed => json!({ "kind": "FailClosed" }),
    }
}

/// The room a failure's words get. Longer than any of the seven causes needs, so nothing is ever cut short
/// (a test holds the real words to it); the window's parser accepts the same lengths.
pub const TITLE_MAX: usize = 200;
/// See [`TITLE_MAX`].
pub const DETAIL_MAX: usize = 600;
/// See [`TITLE_MAX`]: the action is a sentence of advice, not a button label.
pub const ACTION_MAX: usize = 400;

/// A failure with its words: the same title, detail and action `dnetctl` shows. Seven causes, each with its
/// own, and no "unknown" (FR-039, SC-020).
fn failure(cause: &FailureCause) -> Value {
    let name = match cause {
        FailureCause::NoEndpointReachable => "NoEndpointReachable",
        FailureCause::AllProfilesBlocked => "AllProfilesBlocked",
        FailureCause::CaptivePortalUnsatisfied => "CaptivePortalUnsatisfied",
        FailureCause::InsufficientPrivilege => "InsufficientPrivilege",
        FailureCause::CoreFailedPersistently { .. } => "CoreFailedPersistently",
        FailureCause::NoUsablePath => "NoUsablePath",
        FailureCause::ConfigurationInvalid { .. } => "ConfigurationInvalid",
    };
    let words = explain(cause);
    json!({
        "cause": name,
        "title": plain(&words.title, TITLE_MAX),
        "detail": plain(&words.detail, DETAIL_MAX),
        "action": plain(&words.action, ACTION_MAX),
    })
}

fn paths_view(paths: Option<&PathsReply>, now_ms: u64) -> Value {
    let Some(paths) = paths else {
        // The service cannot say. Nothing is being watched, as far as anyone knows.
        return json!({ "asOfMs": now_ms, "watching": false, "paths": [], "degraded": null });
    };
    json!({
        "asOfMs": paths.as_of_unix_ms,
        "watching": paths.watching,
        "paths": paths.paths.iter().map(path).collect::<Vec<_>>(),
        "degraded": paths.degraded.as_ref().map(degraded),
    })
}

fn path(path: &PathReply) -> Value {
    json!({
        "id": plain(&path.id, 24),
        "kind": match path.kind {
            Kind::Wifi => "Wifi",
            Kind::Cellular => "Cellular",
            Kind::Ethernet => "Ethernet",
            Kind::Other => "Other",
        },
        "name": path.name.as_deref().map(|n| plain(n, 64)),
        "role": match path.role {
            Role::Carrying => "Carrying",
            Role::Standby => "Standby",
            Role::Unusable => "Unusable",
        },
        "measured": path.measured,
        "rttMs": path.rtt_ms,
        "jitterMs": path.jitter_ms,
        "loss": path.loss,
        "traceMs": path.trace_ms,
        "typicalMs": path.typical_ms.map(|(low, high)| [low, high]),
    })
}

fn degraded(degraded: &DegradedReply) -> Value {
    json!({
        "path": plain(&degraded.path, 24),
        "quality": match degraded.quality {
            Quality::Unusable => "Unusable",
            // `Good` is never sent in a degradation (the decoder refuses it); `Poor` is the only other.
            Quality::Poor | Quality::Good => "Poor",
        },
        "staying": plain(&degraded.staying, 16),
    })
}

fn stats_view(stats: Option<&StatsReply>) -> Value {
    match stats {
        None | Some(StatsReply::NotConnected) => json!({ "connected": false }),
        Some(StatsReply::Connected {
            connected_for_s,
            network_changes,
            changes_that_drop_connections,
            method_switches,
            endpoint_switches,
            degraded_periods,
            longest_degraded_s,
        }) => json!({
            "connected": true,
            "connectedForS": connected_for_s,
            "networkChanges": network_changes,
            "changesThatDropConnections": changes_that_drop_connections,
            "methodSwitches": method_switches,
            "endpointSwitches": endpoint_switches,
            "degradedPeriods": degraded_periods,
            "longestDegradedS": longest_degraded_s,
        }),
    }
}
