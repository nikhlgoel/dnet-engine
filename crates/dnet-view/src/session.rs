//! T100, T101 — the rules the shell lives by, written as plain values so they can be tested without a window.
//!
//! The shell is thin glue around the operating system's windows; what it decides is here:
//!
//! - **What the window missed.** The tray runs all day and the window only sometimes, so the events the
//!   service reports are kept here (a bounded number), and a window that opens shows the session, not only
//!   its own lifetime.
//! - **When the web view goes away (ADR-0007 R2).** Closing the window hides it; after a grace period the web
//!   view is destroyed, unless the window was opened again in the meantime. A web view that is not on screen
//!   still costs memory, which is why it is not kept for good.
//! - **How often to ask the service.** Often while a person is looking, rarely while only the tray is there.

use std::collections::VecDeque;
use std::time::Duration;

use serde_json::Value;

/// The events kept. The service holds at most this many of the current session (contract §Subscribe), so
/// keeping more would only keep what the service has already let go of.
pub const ACTIVITY_KEPT: usize = 256;

/// How long the web view is kept after the window is closed, so that opening it again at once is instant
/// (ADR-0007 R2).
pub const GRACE: Duration = Duration::from_secs(120);

/// How often the service is asked for the state, by whether anyone is looking at the window.
#[must_use]
pub fn poll_interval(window_visible: bool) -> Duration {
    if window_visible {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(15)
    }
}

/// The events of the current session, oldest first, and the reason of the latest.
#[derive(Debug, Default)]
pub struct Backlog {
    items: VecDeque<Value>,
    last_because: Option<String>,
}

impl Backlog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep one more event, letting the oldest go if there are too many.
    pub fn push(&mut self, line: Value) {
        if let Some(because) = line.get("because").and_then(Value::as_str) {
            self.last_because = Some(because.to_owned());
        }
        if self.items.len() == ACTIVITY_KEPT {
            self.items.pop_front();
        }
        self.items.push_back(line);
    }

    /// Forget the events, for a new subscription: the service replays the session it still holds, so keeping
    /// the old copy as well would show everything twice. The latest reason is kept, because it is still the
    /// latest thing anyone said until the replay says something newer.
    pub fn restart(&mut self) {
        self.items.clear();
    }

    /// The events, oldest first.
    #[must_use]
    pub fn items(&self) -> Vec<Value> {
        self.items.iter().cloned().collect()
    }

    /// Why the state is what it is: the `because` of the latest event.
    #[must_use]
    pub fn last_because(&self) -> Option<&str> {
        self.last_because.as_deref()
    }
}

/// The web view's life after the window closes. Opening and closing each take a token; a destroy that was
/// scheduled with an older token than the latest is stale and does nothing.
#[derive(Debug, Default)]
pub struct Grace {
    latest: u64,
}

impl Grace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The window is shown. Anything scheduled before now is cancelled.
    pub fn window_opened(&mut self) {
        self.latest += 1;
    }

    /// The window was closed; destroy the web view `GRACE` from now if `still_current(token)` then.
    pub fn window_closed(&mut self) -> u64 {
        self.latest += 1;
        self.latest
    }

    /// Whether nothing has opened or closed the window since `token` was given.
    #[must_use]
    pub fn still_current(&self, token: u64) -> bool {
        self.latest == token
    }
}
