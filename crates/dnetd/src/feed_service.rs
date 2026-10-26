//! T066a — the profile feed inside the service: keep what was accepted, offer what arrives, apply what
//! may be applied (ADR-0002 §4 to §6).
//!
//! `dnet_core::feed` decides, purely, whether a document is acceptable and what state follows. This is
//! the part that remembers and acts:
//!
//! - **Restore at start.** The two stored envelopes are read back and **verified again from their
//!   bytes** (`restore`), never trusted in parsed form. A stored document that no longer verifies is
//!   treated as absent and reported; the bundled defaults are always a safe floor, so a bad feed state
//!   never locks the service.
//! - **Offer.** A keys document or a feed, from a fetch or an offline import, goes through the same
//!   acceptance. A feed is also **trial-generated** for every profile before it is kept (step 8): a
//!   feed one profile of which would produce a configuration the cores refuse is refused whole.
//! - **Persist before commit.** The envelope bytes are written first; only if that succeeds does the
//!   in-memory state change. A failed write leaves the service exactly as it was.
//! - **Apply.** The client-section parameters go into [`SharedDefinitions`], which the connection code
//!   reads when it generates a configuration: a tunnel already up is never regenerated. The
//!   endpoint-section proposals are only staged (`staged_endpoint_updates`): they are never applied by
//!   the client alone.
//!
//! What this does not do: fetch (T066b), choose when (the schedule), or hold the root keys, which are
//! the owner's ceremony (T066d). Without a trust anchor the service has no feed machinery at all.

use std::sync::{Arc, Mutex, PoisonError};

use dnet_config::persist::StateFile;
use dnet_core::feed::{
    accept_feed, accept_keys_document, restore, staged_endpoint_updates, ClientDefinitions,
    Document, FeedDocument, FeedError, FeedOutcome, FeedState, FeedStatus, FeedTrust, KeysOutcome,
    StagedEndpointUpdate,
};

/// The client-section parameters in effect, shared with the code that generates configurations.
pub type SharedDefinitions = Arc<Mutex<ClientDefinitions>>;

/// Something worth telling the person (and the log) about, after an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedNote {
    /// A stored document no longer verified at start-up (or could not be read) and was dropped: the
    /// bundled definitions are in effect for what it covered.
    Discarded { document: Document, reason: String },
    /// A feed was accepted and its client section is now in effect for the next connection.
    /// `endpoint_updates` is how many profiles also propose a change to the endpoint, which waits for
    /// the person's consent.
    Updated {
        sequence: u64,
        endpoint_updates: usize,
    },
    /// A new keys document no longer lists a key the applied feed depended on, so the feed was
    /// dropped (rule R) and the bundled definitions are back in effect.
    Evicted,
    /// The applied feed has expired. Its definitions stay in use; they are out of date.
    OutOfDate,
}

/// Why a document was not taken. Nothing has changed when one of these is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedRefusal {
    /// The document failed verification or the checks that follow it.
    Rejected(FeedError),
    /// The document verified, but one of the profiles it covers would not produce a configuration the
    /// cores accept. The feed is refused whole.
    TrialFailed(String),
    /// It was acceptable but could not be saved.
    Storage(String),
}

impl std::fmt::Display for FeedRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedRefusal::Rejected(error) => write!(f, "{error}"),
            FeedRefusal::TrialFailed(detail) => write!(
                f,
                "a profile in the feed would not produce a working configuration ({detail}); \
                 the feed was refused whole"
            ),
            FeedRefusal::Storage(detail) => {
                write!(
                    f,
                    "the feed could not be saved ({detail}); nothing was changed"
                )
            }
        }
    }
}

impl std::error::Error for FeedRefusal {}

/// The profile feed as the service holds it.
pub struct FeedService {
    trust: FeedTrust,
    keys_file: Box<dyn StateFile>,
    feed_file: Box<dyn StateFile>,
    state: FeedState,
    definitions: SharedDefinitions,
    /// Out-of-date has been reported for the feed now applied; it is reported once.
    reported_out_of_date: bool,
}

impl FeedService {
    /// Read back what was stored, verify it again, and put the result into effect.
    pub fn start(
        trust: FeedTrust,
        keys_file: Box<dyn StateFile>,
        feed_file: Box<dyn StateFile>,
        definitions: SharedDefinitions,
    ) -> (Self, Vec<FeedNote>) {
        let mut notes = Vec::new();
        let keys = read_or_note(keys_file.as_ref(), Document::Keys, &mut notes);
        let feed = read_or_note(feed_file.as_ref(), Document::Feed, &mut notes);
        let restored = restore(&trust, keys.as_deref(), feed.as_deref());
        for (document, discarded) in [
            (Document::Keys, restored.keys_discarded),
            (Document::Feed, restored.feed_discarded),
        ] {
            if let Some(error) = discarded {
                notes.push(FeedNote::Discarded {
                    document,
                    reason: error.to_string(),
                });
            }
        }
        let service = Self {
            trust,
            keys_file,
            feed_file,
            state: restored.state,
            definitions,
            reported_out_of_date: false,
        };
        service.publish_definitions();
        (service, notes)
    }

    /// Offer a keys document. `Ok` with no notes if it is the one already held.
    pub fn offer_keys(&mut self, envelope: &[u8], now: u64) -> Result<Vec<FeedNote>, FeedRefusal> {
        match accept_keys_document(&self.trust, &self.state, envelope, now)
            .map_err(FeedRefusal::Rejected)?
        {
            KeysOutcome::Unchanged => Ok(Vec::new()),
            KeysOutcome::Accepted {
                state,
                feed_evicted,
            } => {
                self.keys_file
                    .write(envelope)
                    .map_err(FeedRefusal::Storage)?;
                self.state = *state;
                self.reported_out_of_date = false;
                self.publish_definitions();
                // The evicted feed's file is left as it is: at the next start `restore` verifies it
                // against the keys now held and drops it again, for the same reason.
                Ok(if feed_evicted {
                    vec![FeedNote::Evicted]
                } else {
                    Vec::new()
                })
            }
        }
    }

    /// Offer a feed. `trial` is feed step 8: it is called with the document and must accept it by
    /// generating a configuration for every profile the feed covers; an `Err` refuses the feed whole.
    pub fn offer_feed(
        &mut self,
        envelope: &[u8],
        now: u64,
        trial: &dyn Fn(&FeedDocument) -> Result<(), String>,
    ) -> Result<Vec<FeedNote>, FeedRefusal> {
        match accept_feed(&self.state, envelope, now).map_err(FeedRefusal::Rejected)? {
            FeedOutcome::Unchanged => Ok(Vec::new()),
            FeedOutcome::Accepted(next) => {
                let document = next
                    .feed()
                    .map(|applied| applied.document())
                    .expect("an accepted feed is applied");
                trial(document).map_err(FeedRefusal::TrialFailed)?;
                let note = FeedNote::Updated {
                    sequence: document.sequence,
                    endpoint_updates: staged_endpoint_updates(document).len(),
                };
                self.feed_file
                    .write(envelope)
                    .map_err(FeedRefusal::Storage)?;
                self.state = *next;
                self.reported_out_of_date = false;
                self.publish_definitions();
                Ok(vec![note])
            }
        }
    }

    /// Whether the definitions in effect come from a current feed, an expired one, or none.
    pub fn status(&self, now: u64) -> FeedStatus {
        self.state.status(now)
    }

    /// `Some(OutOfDate)` the first time the applied feed is found expired, and then not again until
    /// something new is accepted. The definitions stay in use: reverting would only substitute older
    /// ones.
    pub fn check_staleness(&mut self, now: u64) -> Option<FeedNote> {
        if self.status(now) == FeedStatus::Stale && !self.reported_out_of_date {
            self.reported_out_of_date = true;
            return Some(FeedNote::OutOfDate);
        }
        None
    }

    /// What the applied feed proposes for the endpoint, waiting for the person's consent.
    // Read by the interface's "endpoint update available" once the provisioning wizard lands (T107).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn staged_endpoint_updates(&self) -> Vec<StagedEndpointUpdate> {
        self.state
            .feed()
            .map(|applied| staged_endpoint_updates(applied.document()))
            .unwrap_or_default()
    }

    /// The keys version and feed sequence in effect, for diagnostics: `(keys_version, sequence)`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn versions(&self) -> (Option<u64>, Option<u64>) {
        (
            self.state.keys().map(|k| k.document().keys_version),
            self.state.feed().map(|f| f.document().sequence),
        )
    }

    /// Put the client section of the feed now applied (or the bundled defaults, if none) where the
    /// connection code reads it.
    fn publish_definitions(&self) {
        let definitions = self
            .state
            .feed()
            .map(|applied| ClientDefinitions::from_feed(applied.document()))
            .unwrap_or_default();
        *self
            .definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = definitions;
    }
}

/// The stored bytes of one document, or `None` with a note if they cannot be read at all.
fn read_or_note(
    file: &dyn StateFile,
    document: Document,
    notes: &mut Vec<FeedNote>,
) -> Option<Vec<u8>> {
    match file.read() {
        Ok(bytes) => bytes,
        Err(error) => {
            notes.push(FeedNote::Discarded {
                document,
                reason: format!("it could not be read ({error})"),
            });
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
