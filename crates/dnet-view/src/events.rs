//! T100 — the service's events as lines of the Activity view.
//!
//! Every event carries a `because` that is neither empty nor the event's own name (contract §Subscribe), and
//! the decoder enforces it; a frame that fails is skipped, never drawn, because a line with no reason would
//! break principle 3. The stream is one-way after `Subscribe`: this only reads.

use dnet_ipc::client::{ClientError, Connection, Reply};
use dnet_ipc::protocol::Request;
use dnet_ipc::wire::{decode_event_view, EventView};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::text::plain;

/// One event as an Activity line: its sequence number (a gap means events were missed), its name, and why.
#[must_use]
pub fn activity(event: &EventView) -> Value {
    json!({
        "seq": event.value.get("seq").and_then(Value::as_u64),
        "event": plain(&event.event, 48),
        "because": plain(&event.because, 400),
    })
}

/// The service holds at most this many events of a session (contract §Subscribe).
const REPLAY_MAX: u64 = 256;

/// How following the stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The service closed the stream (it stopped, or dropped a reader that was too slow).
    Closed,
    /// The caller asked to stop.
    Stopped,
    /// The service would not start the stream, and said why (at most 16 subscribers exist).
    Refused { detail: String },
}

/// Subscribe, and hand each event to `on_item` as an Activity line until it returns `false`, the service
/// closes the stream, or reading fails. The second argument is `true` for the events the service replays (the
/// ones it still holds of the current session, which the subscription's reply counts) and `false` for the live
/// ones, so a caller that already showed the replayed ones does not show them twice after a reconnect.
///
/// The service sends the events it still holds for the current session first, then live ones with no gap and
/// no repeat, so a window that opens late shows what happened before it did.
pub async fn follow<S, F>(
    connection: &mut Connection<S>,
    mut on_item: F,
) -> Result<Ended, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Value, bool) -> bool,
{
    let mut replaying: u64;
    match connection.call(&Request::Subscribe).await? {
        Reply::Done(reply) => {
            // The service says how many of the frames that follow are replay. A reply that does not say, or says
            // something absurd, means none: every event is then treated as live, which can only show one twice.
            replaying = reply
                .get("backlog")
                .and_then(Value::as_u64)
                .map_or(0, |n| n.min(REPLAY_MAX));
        }
        Reply::Refused(refusal) => {
            return Ok(Ended::Refused {
                detail: plain(&refusal.detail, 400),
            })
        }
    }
    while let Some(frame) = connection.next_frame().await? {
        let replay = replaying > 0;
        replaying = replaying.saturating_sub(1);
        // A frame this program cannot read is skipped. It is a newer service's event or a defect; either
        // way a line with no reason must not be shown.
        if let Ok(event) = decode_event_view(&frame) {
            if !on_item(activity(&event), replay) {
                return Ok(Ended::Stopped);
            }
        }
    }
    Ok(Ended::Closed)
}
