//! T066b — fetching the signed profile feed (ADR-0002 §7).
//!
//! `dnet_core::feed::fetch` fixes the decisions: where the two files live, which hosts may be reached,
//! how many redirects, how long, and which network a fetch may use. This does the fetching, and holds
//! to them.
//!
//! **Nothing here is trusted, and nothing here needs to be.** Every byte is verified by the signature
//! checks in `dnet_core::feed` before it is used; TLS gives confidentiality, not authenticity. What the
//! rules below limit is *where the service connects and when*:
//!
//! - every URL, the first and each redirect target, is checked with `is_allowed_url` **before** it is
//!   requested (HTTPS, the default port, no credentials, a host on the allowlist);
//! - redirects are followed **by this code, one at a time**, never by the HTTP library, at most
//!   [`MAX_REDIRECTS`];
//! - a body is read in pieces and refused past the size cap, so a hostile server cannot make the service
//!   read without limit; a request has [`FETCH_TIMEOUT_SECS`] in all;
//! - the request carries no cookie, no identifier, and a fixed `User-Agent`, and ignores any proxy
//!   setting of the machine, which is not this program's to follow with a request of this kind.
//!
//! **When.** A scheduled fetch runs only while a tunnel carries traffic (start-up, then every six hours
//! with jitter); it never goes over the physical network. A fetch the person asks for (`FetchFeed`) goes
//! through the tunnel if there is one and directly if there is not, which is the one flow that bypasses
//! the fail-closed posture, and exists only because they asked (D2).
//!
//! A failure of a *scheduled* fetch is only logged: before the publisher has published anything every
//! one would fail, and a notice every six hours that nothing is there helps nobody. A failure of a
//! *requested* one is announced, because the person is waiting for the answer.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dnet_core::feed::fetch::{
    asset_url, fetch_route, is_allowed_url, FetchRoute, FetchTrigger, FEED_ASSET,
    FETCH_INTERVAL_SECS, FETCH_JITTER_MAX_SECS, FETCH_TIMEOUT_SECS, KEYS_ASSET, MAX_REDIRECTS,
};
use dnet_core::feed::ENVELOPE_MAX_BYTES;
use dnet_core::posture::RoutingPosture;
use dnet_core::session::CheckFailure;

use crate::feed_service::{FeedNote, FeedRefusal, FeedService};
use crate::feed_trial::trial_generate;

/// What one request came to. The transport has already refused a body over the size cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Body(Vec<u8>),
    /// A redirect, with the target exactly as the server gave it. Not followed by the transport.
    Redirect(String),
    /// Any other answer.
    Status(u16),
}

/// Why a request produced no reply. Coarse on purpose: what the library says about a failed request
/// can include the address, and none of it is anything a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Network,
    TooLarge,
}

/// Makes one HTTP GET, following nothing. The real one is [`HttpTransport`]; tests use a fake.
pub trait Transport: Send + Sync + 'static {
    fn get(&self, url: &str) -> impl Future<Output = Result<Reply, TransportError>> + Send;
}

/// Why an asset could not be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailure {
    /// A URL (the first or a redirect target) is not one a fetch may reach.
    NotAllowed,
    TooManyRedirects,
    Status(u16),
    Network,
    TooLarge,
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchFailure::NotAllowed => f.write_str("a redirect led somewhere a fetch may not go"),
            FetchFailure::TooManyRedirects => f.write_str("too many redirects"),
            FetchFailure::Status(code) => write!(f, "the server answered {code}"),
            FetchFailure::Network => f.write_str("the server could not be reached"),
            FetchFailure::TooLarge => f.write_str("the answer was larger than any signed document"),
        }
    }
}

/// Fetch one asset of the feed release, following redirects by the rules above.
pub async fn fetch_asset<T: Transport>(
    transport: &T,
    asset: &str,
) -> Result<Vec<u8>, FetchFailure> {
    let mut url = asset_url(asset);
    for redirects in 0..=MAX_REDIRECTS {
        // Checked before every request, not once: a redirect target is the server's word.
        if !is_allowed_url(&url) {
            return Err(FetchFailure::NotAllowed);
        }
        match transport.get(&url).await {
            Err(TransportError::Network) => return Err(FetchFailure::Network),
            Err(TransportError::TooLarge) => return Err(FetchFailure::TooLarge),
            Ok(Reply::Body(body)) if body.len() > ENVELOPE_MAX_BYTES => {
                return Err(FetchFailure::TooLarge)
            }
            Ok(Reply::Body(body)) => return Ok(body),
            Ok(Reply::Status(code)) => return Err(FetchFailure::Status(code)),
            Ok(Reply::Redirect(_)) if redirects == MAX_REDIRECTS => {
                return Err(FetchFailure::TooManyRedirects)
            }
            Ok(Reply::Redirect(next)) => url = next,
        }
    }
    unreachable!("the loop returns on its last turn")
}

// ------------------------------------------------------------------ the real transport

/// HTTPS through `reqwest` with rustls: no redirects followed, no proxy, no cookie jar, one fixed
/// `User-Agent`, HTTPS only, a timeout, and a body read in pieces up to the size cap.
pub struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
            .user_agent("dnet-engine")
            .build()?;
        Ok(Self { client })
    }
}

impl Transport for HttpTransport {
    async fn get(&self, url: &str) -> Result<Reply, TransportError> {
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| TransportError::Network)?;
        let status = response.status();
        if status.is_redirection() {
            return Ok(
                match response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                {
                    Some(location) => Reply::Redirect(location.to_owned()),
                    None => Reply::Status(status.as_u16()),
                },
            );
        }
        if !status.is_success() {
            return Ok(Reply::Status(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > ENVELOPE_MAX_BYTES as u64)
        {
            return Err(TransportError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(piece) = response
            .chunk()
            .await
            .map_err(|_| TransportError::Network)?
        {
            if body.len() + piece.len() > ENVELOPE_MAX_BYTES {
                return Err(TransportError::TooLarge);
            }
            body.extend_from_slice(&piece);
        }
        Ok(Reply::Body(body))
    }
}

// ------------------------------------------------------------------ one check

/// Why a check produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    Fetch(FetchFailure),
    Refused(FeedRefusal),
}

impl CheckError {
    /// The coarse reason a person is told.
    pub fn reason(&self) -> CheckFailure {
        match self {
            CheckError::Fetch(_) => CheckFailure::Unreachable,
            CheckError::Refused(_) => CheckFailure::Refused,
        }
    }
}

/// What a check did: the changes it made, and why it stopped early, if it did. The keys document can be
/// taken and the feed then refused, so both can be present.
#[derive(Debug, Default)]
pub struct Checked {
    pub notes: Vec<FeedNote>,
    pub error: Option<CheckError>,
}

/// Fetch both documents (holding no lock while the network is slow), then offer them: keys first.
pub async fn check_once<T: Transport>(
    transport: &T,
    feed: &Mutex<FeedService>,
    now: u64,
) -> Checked {
    let fetched = async {
        let keys = fetch_asset(transport, KEYS_ASSET).await?;
        let document = fetch_asset(transport, FEED_ASSET).await?;
        Ok::<_, FetchFailure>((keys, document))
    }
    .await;
    let (keys, document) = match fetched {
        Ok(both) => both,
        Err(failure) => {
            return Checked {
                notes: Vec::new(),
                error: Some(CheckError::Fetch(failure)),
            }
        }
    };
    let mut feed = feed.lock().unwrap_or_else(PoisonError::into_inner);
    let mut checked = Checked::default();
    match feed.offer_keys(&keys, now) {
        Ok(notes) => checked.notes.extend(notes),
        Err(refusal) => {
            checked.error = Some(CheckError::Refused(refusal));
            return checked;
        }
    }
    match feed.offer_feed(&document, now, &trial_generate) {
        Ok(notes) => checked.notes.extend(notes),
        Err(refusal) => checked.error = Some(CheckError::Refused(refusal)),
    }
    checked
}

// ------------------------------------------------------------------ when

/// How the schedule paces itself.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    /// Before the first check after start-up, so the service is not busy with it while starting.
    pub first_delay: Duration,
    /// Between looks at whether a tunnel is up, while none is.
    pub wait_for_tunnel: Duration,
    pub interval: Duration,
    pub jitter_max: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(60),
            wait_for_tunnel: Duration::from_secs(300),
            interval: Duration::from_secs(FETCH_INTERVAL_SECS),
            jitter_max: Duration::from_secs(FETCH_JITTER_MAX_SECS),
        }
    }
}

/// A random fraction of `max`, for spreading checks out. Not a security matter: it only keeps every
/// install from asking at the same second.
fn jitter(max: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    if max.is_zero() {
        return Duration::ZERO;
    }
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    Duration::from_millis(random % u64::try_from(max.as_millis().max(1)).unwrap_or(u64::MAX))
}

/// The pieces the service supplies, so this stays free of the service itself.
type Posture = Arc<dyn Fn() -> RoutingPosture + Send + Sync>;
type Announce = Arc<dyn Fn(&[FeedNote], Option<CheckFailure>) + Send + Sync>;
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A check is already under way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy;

/// Fetches the feed, on a schedule and when asked.
pub struct Fetcher<T: Transport> {
    transport: Arc<T>,
    feed: Arc<Mutex<FeedService>>,
    busy: Arc<AtomicBool>,
    posture: Posture,
    announce: Announce,
    clock: Clock,
}

impl<T: Transport> Clone for Fetcher<T> {
    fn clone(&self) -> Self {
        Self {
            transport: Arc::clone(&self.transport),
            feed: Arc::clone(&self.feed),
            busy: Arc::clone(&self.busy),
            posture: Arc::clone(&self.posture),
            announce: Arc::clone(&self.announce),
            clock: Arc::clone(&self.clock),
        }
    }
}

/// Holds the "a check is under way" flag; releases it however the check ends.
struct Claim(Arc<AtomicBool>);

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl<T: Transport> Fetcher<T> {
    pub fn new(
        transport: Arc<T>,
        feed: Arc<Mutex<FeedService>>,
        posture: Posture,
        announce: Announce,
        clock: Clock,
    ) -> Self {
        Self {
            transport,
            feed,
            busy: Arc::new(AtomicBool::new(false)),
            posture,
            announce,
            clock,
        }
    }

    fn claim(&self) -> Result<Claim, Busy> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Claim(Arc::clone(&self.busy)))
            .map_err(|_| Busy)
    }

    /// The person asked: check now. Returns at once with which network the check will use; the result
    /// arrives as events. Must be called with a Tokio runtime current.
    pub fn request(&self) -> Result<FetchRoute, Busy> {
        let claim = self.claim()?;
        let route = fetch_route(FetchTrigger::UserRequested, (self.posture)());
        let this = self.clone();
        tokio::spawn(async move {
            let _claim = claim;
            let checked = check_once(&*this.transport, &this.feed, (this.clock)()).await;
            // A requested check says how it went, success or not.
            let failure = checked.error.as_ref().map(CheckError::reason);
            if let Some(error) = &checked.error {
                tracing::info!(?error, "a requested check for updated definitions failed");
            }
            (this.announce)(&checked.notes, failure);
        });
        Ok(route)
    }

    /// Start the schedule: once after a short delay, then every interval plus jitter, while a tunnel
    /// carries traffic. Runs until the runtime ends. Must be called with a Tokio runtime current.
    pub fn spawn_schedule(&self, pace: Pace) {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(pace.first_delay).await;
            loop {
                match fetch_route(FetchTrigger::Scheduled, (this.posture)()) {
                    FetchRoute::ThroughTunnel => {
                        if let Ok(_claim) = this.claim() {
                            let checked =
                                check_once(&*this.transport, &this.feed, (this.clock)()).await;
                            if let Some(error) = &checked.error {
                                // Logged, not announced: see the module documentation.
                                tracing::info!(
                                    ?error,
                                    "a scheduled check for updated definitions found nothing"
                                );
                            }
                            (this.announce)(&checked.notes, None);
                        }
                        tokio::time::sleep(pace.interval + jitter(pace.jitter_max)).await;
                    }
                    // Never over the physical network on the schedule; look again later.
                    FetchRoute::PhysicalNetwork | FetchRoute::NotAllowed => {
                        tokio::time::sleep(pace.wait_for_tunnel).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
