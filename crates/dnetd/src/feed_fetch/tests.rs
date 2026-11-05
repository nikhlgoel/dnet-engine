//! The fetch rules against a fake transport that records every URL it is asked for, so what is asserted
//! is what the service would have *requested*, not only what it ended up with.

use std::collections::HashMap;

use dnet_config::persist::MemoryStateFile;
use dnet_core::feed::fetch::{asset_url, FEED_ASSET, KEYS_ASSET};
use dnet_core::tier::FailoverTier;
use tokio::sync::Notify;

use super::*;
use crate::feed_service::tests::{feed_envelope, feed_value_at, keys_envelope_at, signer, trust};
use crate::feed_service::SharedDefinitions;

const NOW: u64 = 1_760_000_000;

// ------------------------------------------------------------------ the fake

/// Answers by URL, and remembers every URL it was asked for, in order.
struct Fake {
    answers: Mutex<HashMap<String, Result<Reply, TransportError>>>,
    asked: Mutex<Vec<String>>,
    /// If set, a request waits for this before answering, to hold a check open.
    gate: Option<Arc<Notify>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            answers: Mutex::default(),
            asked: Mutex::default(),
            gate: None,
        }
    }

    fn answering(self, url: impl Into<String>, answer: Result<Reply, TransportError>) -> Self {
        self.answers.lock().unwrap().insert(url.into(), answer);
        self
    }

    fn held_by(mut self, gate: &Arc<Notify>) -> Self {
        self.gate = Some(Arc::clone(gate));
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl Transport for Fake {
    async fn get(&self, url: &str) -> Result<Reply, TransportError> {
        self.asked.lock().unwrap().push(url.to_owned());
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        self.answers
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .unwrap_or(Ok(Reply::Status(404)))
    }
}

const ASSETS: &str =
    "https://release-assets.githubusercontent.com/github-production-release-asset/1";

fn body(bytes: &[u8]) -> Result<Reply, TransportError> {
    Ok(Reply::Body(bytes.to_vec()))
}

fn redirect(to: &str) -> Result<Reply, TransportError> {
    Ok(Reply::Redirect(to.to_owned()))
}

// ------------------------------------------------------------------ fetching one asset

#[tokio::test]
async fn an_asset_is_fetched_from_the_compiled_in_address_and_nowhere_else() {
    let url = asset_url(KEYS_ASSET);
    let fake = Fake::new().answering(&url, body(b"signed"));
    assert_eq!(fetch_asset(&fake, KEYS_ASSET).await.unwrap(), b"signed");
    assert_eq!(fake.asked(), [url]);
}

#[tokio::test]
async fn a_redirect_to_the_release_asset_host_is_followed() {
    let first = asset_url(FEED_ASSET);
    let fake = Fake::new()
        .answering(&first, redirect(ASSETS))
        .answering(ASSETS, body(b"signed"));
    assert_eq!(fetch_asset(&fake, FEED_ASSET).await.unwrap(), b"signed");
    assert_eq!(fake.asked(), [first, ASSETS.to_owned()]);
}

#[tokio::test]
async fn a_redirect_anywhere_else_is_never_requested() {
    for target in [
        "https://evil.example/profile-feed",
        "http://github.com/x",
        "https://github.com:8443/x",
        "https://user@github.com/x",
        "https://github.com.evil.example/x",
        "https://objects.githubusercontent.com/x",
        "/relative/path",
        "file:///c:/windows/win.ini",
        "",
    ] {
        let first = asset_url(FEED_ASSET);
        let fake = Fake::new().answering(&first, redirect(target));
        assert_eq!(
            fetch_asset(&fake, FEED_ASSET).await,
            Err(FetchFailure::NotAllowed),
            "{target:?}"
        );
        assert_eq!(fake.asked(), [first], "{target:?} was requested");
    }
}

#[tokio::test]
async fn at_most_two_redirects_are_followed() {
    let first = asset_url(FEED_ASSET);
    let a = "https://github.com/a";
    let b = "https://github.com/b";
    let c = "https://github.com/c";
    // Two redirects then a body: fine.
    let fake = Fake::new()
        .answering(&first, redirect(a))
        .answering(a, redirect(b))
        .answering(b, body(b"ok"));
    assert_eq!(fetch_asset(&fake, FEED_ASSET).await.unwrap(), b"ok");
    // A third is refused, and its target is not requested.
    let fake = Fake::new()
        .answering(&first, redirect(a))
        .answering(a, redirect(b))
        .answering(b, redirect(c))
        .answering(c, body(b"too late"));
    assert_eq!(
        fetch_asset(&fake, FEED_ASSET).await,
        Err(FetchFailure::TooManyRedirects)
    );
    assert_eq!(fake.asked().len(), 3);
    assert!(!fake.asked().contains(&c.to_owned()));
}

#[tokio::test]
async fn a_redirect_loop_ends() {
    let first = asset_url(FEED_ASSET);
    let fake = Fake::new().answering(&first, redirect(&first));
    assert_eq!(
        fetch_asset(&fake, FEED_ASSET).await,
        Err(FetchFailure::TooManyRedirects)
    );
}

#[tokio::test]
async fn other_answers_are_failures_that_say_what_happened_without_the_servers_words() {
    let url = asset_url(KEYS_ASSET);
    assert_eq!(
        fetch_asset(&Fake::new(), KEYS_ASSET).await,
        Err(FetchFailure::Status(404))
    );
    let down = Fake::new().answering(&url, Err(TransportError::Network));
    assert_eq!(
        fetch_asset(&down, KEYS_ASSET).await,
        Err(FetchFailure::Network)
    );
    let big = Fake::new().answering(&url, Err(TransportError::TooLarge));
    assert_eq!(
        fetch_asset(&big, KEYS_ASSET).await,
        Err(FetchFailure::TooLarge)
    );
    for failure in [
        FetchFailure::NotAllowed,
        FetchFailure::TooManyRedirects,
        FetchFailure::Status(500),
        FetchFailure::Network,
        FetchFailure::TooLarge,
    ] {
        let text = failure.to_string();
        assert!(!text.contains("http"), "{text}");
    }
}

#[tokio::test]
async fn the_size_cap_is_enforced_here_too_not_only_by_the_transport() {
    let url = asset_url(KEYS_ASSET);
    let at = Fake::new().answering(&url, Ok(Reply::Body(vec![b' '; ENVELOPE_MAX_BYTES])));
    assert_eq!(
        fetch_asset(&at, KEYS_ASSET).await.unwrap().len(),
        ENVELOPE_MAX_BYTES
    );
    let over = Fake::new().answering(&url, Ok(Reply::Body(vec![b' '; ENVELOPE_MAX_BYTES + 1])));
    assert_eq!(
        fetch_asset(&over, KEYS_ASSET).await,
        Err(FetchFailure::TooLarge)
    );
}

// ------------------------------------------------------------------ one check

fn feed_service() -> Arc<Mutex<FeedService>> {
    let (service, _) = FeedService::start(
        trust(),
        Box::new(MemoryStateFile::default()),
        Box::new(MemoryStateFile::default()),
        SharedDefinitions::default(),
    );
    Arc::new(Mutex::new(service))
}

fn published(keys: Vec<u8>, feed: Vec<u8>) -> Fake {
    Fake::new()
        .answering(asset_url(KEYS_ASSET), Ok(Reply::Body(keys)))
        .answering(asset_url(FEED_ASSET), Ok(Reply::Body(feed)))
}

fn good_documents(sequence: u64) -> (Vec<u8>, Vec<u8>) {
    (
        keys_envelope_at(NOW, 1, &[&signer(1)]),
        feed_envelope(&feed_value_at(NOW, 1, sequence), &signer(1)),
    )
}

#[tokio::test]
async fn published_documents_are_fetched_keys_first_and_applied() {
    let (keys, feed) = good_documents(4);
    let fake = published(keys, feed);
    let service = feed_service();

    let checked = check_once(&fake, &service, NOW).await;

    assert!(checked.error.is_none(), "{:?}", checked.error);
    assert!(matches!(
        checked.notes.as_slice(),
        [FeedNote::Updated { sequence: 4, .. }]
    ));
    assert_eq!(
        fake.asked(),
        [asset_url(KEYS_ASSET), asset_url(FEED_ASSET)],
        "keys before the feed signed under them"
    );
    assert_eq!(service.lock().unwrap().versions(), (Some(1), Some(4)));
}

#[tokio::test]
async fn a_feed_that_cannot_be_fetched_leaves_the_keys_unapplied_too() {
    let (keys, _) = good_documents(4);
    let fake = Fake::new().answering(asset_url(KEYS_ASSET), Ok(Reply::Body(keys)));
    let service = feed_service();

    let checked = check_once(&fake, &service, NOW).await;

    assert_eq!(
        checked.error,
        Some(CheckError::Fetch(FetchFailure::Status(404)))
    );
    assert!(checked.notes.is_empty());
    assert_eq!(
        service.lock().unwrap().versions(),
        (None, None),
        "both are fetched before either is offered"
    );
}

#[tokio::test]
async fn documents_that_fail_verification_are_refused_and_say_so() {
    // The feed is signed by a key the keys document does not delegate.
    let keys = keys_envelope_at(NOW, 1, &[&signer(1)]);
    let feed = feed_envelope(&feed_value_at(NOW, 1, 4), &signer(2));
    let service = feed_service();

    let checked = check_once(&published(keys, feed), &service, NOW).await;

    let error = checked.error.expect("refused");
    assert_eq!(error.reason(), CheckFailure::Refused);
    assert_eq!(service.lock().unwrap().versions(), (Some(1), None));
}

#[tokio::test]
async fn a_fetched_feed_that_parses_but_would_not_generate_is_refused_whole() {
    // jmin alone is within its own bounds, and above the bundled jmax it leaves no room: only the trial
    // generation can see that.
    let keys = keys_envelope_at(NOW, 1, &[&signer(1)]);
    let mut value = feed_value_at(NOW, 1, 4);
    value["profiles"][0]["client"] = serde_json::json!({ "jmin": 100 });
    let service = feed_service();

    let checked = check_once(
        &published(keys, feed_envelope(&value, &signer(1))),
        &service,
        NOW,
    )
    .await;

    let error = checked.error.expect("refused");
    assert_eq!(error.reason(), CheckFailure::Refused);
    assert!(matches!(
        error,
        CheckError::Refused(FeedRefusal::TrialFailed(_))
    ));
    assert_eq!(service.lock().unwrap().versions(), (Some(1), None));
}

#[tokio::test]
async fn garbage_from_the_server_is_refused_not_trusted() {
    let service = feed_service();
    let checked = check_once(
        &published(b"SENTINEL".to_vec(), b"SENTINEL".to_vec()),
        &service,
        NOW,
    )
    .await;
    let error = checked.error.expect("refused");
    assert_eq!(error.reason(), CheckFailure::Refused);
    assert!(!format!("{error:?}").contains("SENTINEL"), "{error:?}");
}

// ------------------------------------------------------------------ when

type Announced = Arc<Mutex<Vec<(Vec<FeedNote>, Option<CheckFailure>)>>>;

struct Rig {
    fetcher: Fetcher<Fake>,
    fake: Arc<Fake>,
    announced: Announced,
    posture: Arc<Mutex<RoutingPosture>>,
}

fn rig(fake: Fake) -> Rig {
    let fake = Arc::new(fake);
    let announced: Announced = Arc::default();
    let posture = Arc::new(Mutex::new(RoutingPosture::FailClosed));
    let (p, a) = (Arc::clone(&posture), Arc::clone(&announced));
    let fetcher = Fetcher::new(
        Arc::clone(&fake),
        feed_service(),
        Arc::new(move || *p.lock().unwrap()),
        Arc::new(move |notes, failure| a.lock().unwrap().push((notes.to_vec(), failure))),
        Arc::new(|| NOW),
    );
    Rig {
        fetcher,
        fake,
        announced,
        posture,
    }
}

fn tunnelled() -> RoutingPosture {
    RoutingPosture::Tunnelled {
        tier: FailoverTier::Tier2,
    }
}

fn nothing_published() -> Fake {
    Fake::new()
}

/// Let spawned work run to a standstill under the paused clock.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_requested_check_says_which_network_it_uses() {
    let rig = rig(nothing_published());

    *rig.posture.lock().unwrap() = RoutingPosture::FailClosed;
    assert_eq!(rig.fetcher.request(), Ok(FetchRoute::PhysicalNetwork));
    settle().await;

    *rig.posture.lock().unwrap() = tunnelled();
    assert_eq!(rig.fetcher.request(), Ok(FetchRoute::ThroughTunnel));
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn a_requested_check_that_finds_nothing_is_announced_as_such() {
    let rig = rig(nothing_published());
    rig.fetcher.request().unwrap();
    settle().await;
    assert_eq!(
        *rig.announced.lock().unwrap(),
        [(Vec::new(), Some(CheckFailure::Unreachable))]
    );
}

#[tokio::test(start_paused = true)]
async fn a_requested_check_that_finds_an_update_announces_it() {
    let (keys, feed) = good_documents(9);
    let rig = rig(published(keys, feed));
    rig.fetcher.request().unwrap();
    settle().await;
    let announced = rig.announced.lock().unwrap();
    assert_eq!(announced.len(), 1);
    assert!(matches!(
        announced[0].0.as_slice(),
        [FeedNote::Updated { sequence: 9, .. }]
    ));
    assert_eq!(announced[0].1, None);
}

#[tokio::test(start_paused = true)]
async fn a_second_request_while_one_is_under_way_is_refused_and_a_third_after_it_is_not() {
    let gate = Arc::new(Notify::new());
    let rig = rig(Fake::new().held_by(&gate));

    rig.fetcher.request().unwrap();
    settle().await;
    assert_eq!(rig.fetcher.request(), Err(Busy));

    // The held request is answered (its fetch fails with a 404); the claim is released.
    gate.notify_waiters();
    settle().await;
    assert_eq!(rig.fetcher.request(), Ok(FetchRoute::PhysicalNetwork));
}

#[tokio::test(start_paused = true)]
async fn the_schedule_never_goes_out_while_no_tunnel_carries_traffic() {
    let rig = rig(nothing_published());
    rig.fetcher.spawn_schedule(Pace::default());

    // A day with the tunnel down: not one request, and no announcement.
    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    assert!(rig.fake.asked().is_empty(), "{:?}", rig.fake.asked());
    assert!(rig.announced.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_schedule_checks_once_the_tunnel_is_up_and_then_at_the_interval() {
    let (keys, feed) = good_documents(3);
    let rig = rig(published(keys, feed));
    let pace = Pace {
        first_delay: Duration::from_secs(60),
        wait_for_tunnel: Duration::from_secs(300),
        interval: Duration::from_secs(6 * 3600),
        jitter_max: Duration::ZERO,
    };
    rig.fetcher.spawn_schedule(pace);

    // Down at first.
    tokio::time::sleep(Duration::from_secs(1000)).await;
    assert!(rig.fake.asked().is_empty());

    // Up: found within one look.
    *rig.posture.lock().unwrap() = tunnelled();
    tokio::time::sleep(Duration::from_secs(400)).await;
    assert_eq!(rig.fake.asked().len(), 2, "keys and feed");
    assert!(matches!(
        rig.announced.lock().unwrap()[0].0.as_slice(),
        [FeedNote::Updated { sequence: 3, .. }]
    ));

    // Not again before the interval, and again after it.
    tokio::time::sleep(Duration::from_secs(5 * 3600)).await;
    assert_eq!(rig.fake.asked().len(), 2);
    tokio::time::sleep(Duration::from_secs(2 * 3600)).await;
    assert_eq!(rig.fake.asked().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_scheduled_check_that_finds_nothing_is_not_announced() {
    let rig = rig(nothing_published());
    *rig.posture.lock().unwrap() = tunnelled();
    rig.fetcher.spawn_schedule(Pace {
        jitter_max: Duration::ZERO,
        ..Pace::default()
    });
    tokio::time::sleep(Duration::from_secs(120)).await;

    assert!(!rig.fake.asked().is_empty(), "it did look");
    let announced = rig.announced.lock().unwrap();
    assert!(
        announced
            .iter()
            .all(|(notes, failure)| notes.is_empty() && failure.is_none()),
        "a failed scheduled check is only logged: {announced:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_tunnel_that_goes_down_stops_the_schedule_going_out() {
    let rig = rig(nothing_published());
    *rig.posture.lock().unwrap() = tunnelled();
    let pace = Pace {
        first_delay: Duration::from_secs(1),
        wait_for_tunnel: Duration::from_secs(60),
        interval: Duration::from_secs(600),
        jitter_max: Duration::ZERO,
    };
    rig.fetcher.spawn_schedule(pace);
    tokio::time::sleep(Duration::from_secs(5)).await;
    let before = rig.fake.asked().len();
    assert!(before > 0);

    *rig.posture.lock().unwrap() = RoutingPosture::FailClosed;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    // The next one was due after the tunnel went down, and it was not made: never over the physical
    // network on the schedule.
    assert_eq!(rig.fake.asked().len(), before);
}

#[test]
fn jitter_is_below_its_maximum_and_zero_when_there_is_none() {
    assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    for _ in 0..200 {
        assert!(jitter(Duration::from_secs(30 * 60)) < Duration::from_secs(30 * 60));
    }
}

// ------------------------------------------------------------------ the address rules against a real parser

/// Many hostile variations of the real asset addresses: every character a URL parser treats specially, put at every
/// position, and put in place of every character.
fn hostile_variations() -> Vec<String> {
    let bases = [
        asset_url(FEED_ASSET),
        asset_url(KEYS_ASSET),
        "https://release-assets.githubusercontent.com/github-production-release-asset/1?sig=a"
            .to_owned(),
    ];
    let specials = [
        "\\",
        "@",
        ":",
        "\t",
        "\n",
        "\r",
        " ",
        "%",
        "%40",
        "%2e",
        ".",
        "#",
        "?",
        "/",
        "[",
        "]",
        "..",
        "//",
        "\\\\",
        "\u{ff0e}",
        "\u{2024}",
        "\u{3002}",
        "\u{0}",
        "\u{a0}",
        "@evil.example",
        ":443",
        ".evil.example",
        "\\@evil.example/",
        "@evil.example\\",
    ];
    let mut out = Vec::new();
    for base in &bases {
        let mut boundaries: Vec<usize> = base.char_indices().map(|(at, _)| at).collect();
        boundaries.push(base.len());
        for (n, &at) in boundaries.iter().enumerate() {
            for special in specials {
                // Put in ...
                out.push(format!("{}{}{}", &base[..at], special, &base[at..]));
                // ... and put in place of the character there.
                if let Some(&next) = boundaries.get(n + 1) {
                    out.push(format!("{}{}{}", &base[..at], special, &base[next..]));
                }
            }
        }
    }
    out
}

/// How many of `hostile_variations` the check accepted, and how many of those a real URL parser (the HTTP
/// library's own) reads as something other than HTTPS, an allowed host, no credentials and no port.
fn disagreements(accepts: impl Fn(&str) -> bool) -> (usize, usize) {
    use dnet_core::feed::fetch::ALLOWED_HOSTS;
    let (mut accepted, mut wrong) = (0, 0);
    for candidate in hostile_variations() {
        if !accepts(&candidate) {
            continue;
        }
        accepted += 1;
        // A candidate the parser refuses is a request that fails, not one that goes astray.
        if let Ok(url) = reqwest::Url::parse(&candidate) {
            let host = url.host_str().unwrap_or_default();
            let fine = url.scheme() == "https"
                && ALLOWED_HOSTS.contains(&host)
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none();
            if !fine {
                wrong += 1;
            }
        }
    }
    (accepted, wrong)
}

#[test]
fn whatever_the_address_rules_accept_a_real_url_parser_reads_the_same_way() {
    let checked = hostile_variations().len();
    assert!(
        checked > 5_000,
        "{checked} variations is too few to mean anything"
    );
    let (accepted, wrong) = disagreements(is_allowed_url);
    assert_eq!(
        wrong, 0,
        "the rules accepted an address the parser reads as somewhere else"
    );
    // Some variations are harmless (the character lands in the path or query) and must still be accepted, or the
    // rules would be refusing everything and this test would prove nothing.
    assert!(accepted > 100, "only {accepted} of {checked} accepted");
}

#[test]
fn the_same_test_catches_a_check_that_only_looks_at_the_start_of_the_address() {
    // A negative control: the obvious, wrong way to write the rule. If this found nothing, the test above could
    // not find anything either.
    let (_, wrong) = disagreements(|url| url.starts_with("https://github.com"));
    assert!(wrong > 0, "the harness failed to catch a prefix check");
    let (_, wrong) = disagreements(|url| url.contains("github.com") && url.starts_with("https://"));
    assert!(wrong > 0, "the harness failed to catch a substring check");
}
