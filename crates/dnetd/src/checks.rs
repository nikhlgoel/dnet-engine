//! T126 step 2 — the three questions the orchestrator asks the network, and how each is answered.
//!
//! - **Reach** (before connecting, outside any profile): does the endpoint's host answer at all?
//! - **Live check** (while connected): does the tunnel still move traffic?
//! - **Endpoint probe** (while connected): how long does a round trip through the tunnel take?
//!
//! None of these is sure of more than it can see, and each says so:
//!
//! **Reach is conservative, and quiet.** It tries a TCP connection only to ports that carry TCP (the
//! REALITY port; see `plan::reach_ports`), never to a UDP-only profile's port: that tells nothing
//! and is a burst of unusual traffic to the endpoint that could identify this software before any
//! tunnel hides anything. A connection that opens, *or is refused*, proves the host is there (a
//! refusal is the host answering). A timeout proves nothing: a firewall that drops the packets looks
//! the same as a host that is down. So the answer is `Reachable` or `Unknown`, never `Unreachable`,
//! and with no TCP port to try it is `Unknown` without sending anything. The engine reads
//! `Unreachable` as "migrate to another endpoint", which is the wrong response to a block. Where it
//! matters, the race result is what decides.
//!
//! **The other two go through the tunnel.** While connected, the measurement origin is reachable
//! only through the tunnel (there is no host route to it), so a transfer from it proves the tunnel
//! carries traffic, and the time to open the connection is a round trip through it. That is
//! evidence about the endpoint in use that a TCP connect to the endpoint itself could not give,
//! because a UDP-only server has no TCP port to connect to.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use dnet_core::failure::Reach;
use dnet_core::health::ProbeOutcome as EndpointProbeOutcome;
use dnet_core::origin::Origin;
use dnet_core::probe::{judge, ProfileProbe, Verdict, USABLE_MIN_BYTES};
use dnet_core::reprobe::LiveCheck;
use dnet_probe::measure::{measure_direct, MeasureConfig};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// What a live check asks of the tunnel: enough data, quickly enough, to be judged usable by the
/// same rule that chose the profile.
pub fn live_check_config() -> MeasureConfig {
    MeasureConfig {
        connect_timeout: Duration::from_secs(4),
        transfer_timeout: Duration::from_secs(5),
        // Twice the least that can be judged, so one slow packet does not fail a healthy tunnel.
        bytes: USABLE_MIN_BYTES * 2,
    }
}

/// How much a connection that has just been made is asked for, from each method at once, when they race:
/// three times the least that can be judged. At the slowest link still judged usable that is about six
/// seconds of transfer, well inside the race's allowance, and a quarter of what it used to be.
pub const RACE_BYTES: u64 = USABLE_MIN_BYTES * 3;
/// How long one method may take over that transfer in a race.
pub const RACE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(12);

/// What an ordinary check of a healthy tunnel asks for: enough to show that data comes back through it,
/// not enough to measure anything. It was a full 128 KiB every five seconds.
pub const LIGHT_BYTES: u64 = 1024;
/// How often the tunnel's throughput is checked in full while it stays healthy.
pub const DEEP_EVERY: Duration = Duration::from_secs(600);

/// The checks of the tunnel in use: a sliver every time, a full measurement on a slow clock and whenever the
/// sliver comes up short. The same judgement as before (the rule that chose the profile) decides every
/// failure, so nothing is missed that a full check every time would have caught within a clock tick, except
/// a tunnel that moves a kilobyte but too slowly to move a hundred; that is caught at the next full check,
/// ten minutes at most, and the people it would affect notice it in use first.
pub struct LiveChecker {
    deep_every: Duration,
    last_deep: std::sync::Mutex<Option<std::time::Instant>>,
}

impl LiveChecker {
    pub fn new(deep_every: Duration) -> Self {
        Self {
            deep_every,
            last_deep: std::sync::Mutex::new(None),
        }
    }

    /// A full transfer just showed the tunnel working (the race that chose it): the clock starts now.
    pub fn proved(&self, now: std::time::Instant) {
        *self
            .last_deep
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now);
    }

    /// A new connection starts with nothing proved.
    pub fn forget(&self) {
        *self
            .last_deep
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub async fn check(&self, origin: &Origin, now: std::time::Instant) -> LiveCheck {
        let due = match *self
            .last_deep
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            None => true,
            Some(then) => now.saturating_duration_since(then) >= self.deep_every,
        };
        if !due && light_check(origin).await {
            return LiveCheck::Passed;
        }
        // Due, or the sliver came up short: the full measurement decides.
        let result = live_check(origin).await;
        if result == LiveCheck::Passed {
            self.proved(now);
        }
        result
    }
}

/// Whether a sliver comes back through the tunnel.
async fn light_check(origin: &Origin) -> bool {
    let config = MeasureConfig {
        connect_timeout: Duration::from_secs(4),
        transfer_timeout: Duration::from_secs(3),
        bytes: LIGHT_BYTES,
    };
    matches!(
        measure_direct(origin, &config).await.probe,
        ProfileProbe::Transferred { bytes, .. } if bytes >= LIGHT_BYTES
    )
}

/// How long the connection of an endpoint probe may take.
pub const ENDPOINT_PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Whether the host at `ip` answers on any of `ports`. See the module notes for why this is never
/// `Unreachable`. The ports are tried at once and the first answer ends the check.
pub async fn reach_host(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Reach {
    let mut attempts = JoinSet::new();
    for port in ports.iter().copied() {
        attempts.spawn(async move {
            let address = SocketAddr::from((ip, port));
            match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
                Ok(Ok(_)) => true,
                Ok(Err(error)) => error.kind() == std::io::ErrorKind::ConnectionRefused,
                Err(_) => false,
            }
        });
    }
    // Dropping the set at the return aborts the attempts still running.
    while let Some(finished) = attempts.join_next().await {
        if finished.unwrap_or(false) {
            return Reach::Reachable;
        }
    }
    Reach::Unknown
}

/// One live check of the tunnel: a transfer from the origin, judged by the rule that chose the
/// profile. A tunnel that moves too little, too slowly or nothing has failed the check.
pub async fn live_check(origin: &Origin) -> LiveCheck {
    let seen = measure_direct(origin, &live_check_config()).await;
    match judge(seen.probe) {
        Verdict::Usable { .. } => LiveCheck::Passed,
        Verdict::Unusable(reason) => {
            tracing::debug!(?reason, "live check failed");
            LiveCheck::Failed
        }
    }
}

/// One health probe of the endpoint in use: the time to open a connection to the origin through the
/// tunnel. An origin that cannot be reached in time reads as a failed probe.
pub async fn endpoint_probe(origin: &Origin) -> EndpointProbeOutcome {
    let config = MeasureConfig {
        connect_timeout: ENDPOINT_PROBE_TIMEOUT,
        transfer_timeout: Duration::from_secs(1),
        bytes: 1,
    };
    match measure_direct(origin, &config).await.connect {
        Some(rtt) => EndpointProbeOutcome::Ok { rtt, loss: false },
        None => EndpointProbeOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const SHORT: Duration = Duration::from_millis(300);

    /// A port nothing listens on: bound, noted, dropped.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// An origin that answers one request with `body_len` bytes, or with `status`.
    async fn origin(status: &'static str, body_len: usize) -> Origin {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let _ = stream
                        .write_all(format!("HTTP/1.0 {status}\r\n\r\n").as_bytes())
                        .await;
                    let _ = stream.write_all(&vec![b'x'; body_len]).await;
                });
            }
        });
        Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()
    }

    // ------------------------------------------------------------------ reach

    #[tokio::test]
    async fn a_host_with_an_open_port_is_reachable() {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(reach_host(LOCAL, &[port], SHORT).await, Reach::Reachable);
    }

    /// A refusal is the host answering. Only a silence is unknown. Windows reports a refused
    /// connection after about two seconds (it retries the SYN first), so the wait is generous.
    #[tokio::test]
    async fn a_refused_connection_still_shows_the_host_is_there() {
        let port = closed_port().await;
        assert_eq!(
            reach_host(LOCAL, &[port], Duration::from_secs(10)).await,
            Reach::Reachable
        );
    }

    /// The open port answers at once; the closed one is still being refused when the check ends,
    /// and is abandoned rather than waited for.
    #[tokio::test]
    async fn one_answering_port_is_enough() {
        let open = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let ports = [closed_port().await, open.local_addr().unwrap().port()];
        let started = std::time::Instant::now();
        assert_eq!(
            reach_host(LOCAL, &ports, Duration::from_secs(10)).await,
            Reach::Reachable
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited for the slow port"
        );
    }

    /// 192.0.2.0/24 is documentation space: nothing answers, and with no route the connect fails
    /// outright. Either way no host answered, and that is not proof of anything.
    #[tokio::test]
    async fn silence_is_unknown_never_unreachable() {
        let silent = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            reach_host(silent, &[443, 8443], Duration::from_millis(200)).await,
            Reach::Unknown
        );
    }

    #[tokio::test]
    async fn no_ports_to_try_is_unknown() {
        assert_eq!(reach_host(LOCAL, &[], SHORT).await, Reach::Unknown);
    }

    // ------------------------------------------------------------------ live check

    #[tokio::test]
    async fn a_tunnel_that_moves_enough_data_passes() {
        let origin = origin("200 OK", 200_000).await;
        assert_eq!(live_check(&origin).await, LiveCheck::Passed);
    }

    #[tokio::test]
    async fn an_origin_that_answers_with_an_error_fails_the_check() {
        let origin = origin("503 Service Unavailable", 100).await;
        assert_eq!(live_check(&origin).await, LiveCheck::Failed);
    }

    #[tokio::test]
    async fn too_little_data_fails_the_check() {
        // The origin sends well under the least that can be judged, then closes.
        let origin = origin("200 OK", 1000).await;
        assert_eq!(live_check(&origin).await, LiveCheck::Failed);
    }

    #[tokio::test]
    async fn an_origin_that_cannot_be_reached_fails_the_check() {
        let port = closed_port().await;
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(live_check(&origin).await, LiveCheck::Failed);
    }

    /// The data a check asks for, moved at the slowest rate the check allows, is still judged
    /// usable; and one byte less than the least that can be judged never is. The check is held to
    /// the rule that chose the profile, not to a rule of its own.
    #[test]
    fn a_live_check_asks_for_enough_to_be_judged_usable() {
        let config = live_check_config();
        assert!(config.bytes > USABLE_MIN_BYTES);
        let fast_enough = ProfileProbe::Transferred {
            bytes: config.bytes,
            elapsed: Duration::from_secs(2),
        };
        assert!(matches!(judge(fast_enough), Verdict::Usable { .. }));
        let too_little = ProfileProbe::Transferred {
            bytes: USABLE_MIN_BYTES - 1,
            elapsed: Duration::from_secs(1),
        };
        assert!(matches!(judge(too_little), Verdict::Unusable(_)));
    }

    // ------------------------------------------------------------------ endpoint probe

    #[tokio::test]
    async fn an_origin_that_answers_gives_a_round_trip_time() {
        let origin = origin("200 OK", 10).await;
        match endpoint_probe(&origin).await {
            EndpointProbeOutcome::Ok { rtt, loss } => {
                assert!(rtt > Duration::ZERO && rtt < ENDPOINT_PROBE_TIMEOUT);
                assert!(!loss);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_origin_that_cannot_be_reached_is_a_failed_probe() {
        let port = closed_port().await;
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(endpoint_probe(&origin).await, EndpointProbeOutcome::Failed);
    }

    // ------------------------------------------------------------------ what checking costs

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// An origin that serves exactly what `/bytes/n` asks for, counts what it served and how many
    /// requests it answered, and can be switched to refuse or to answer too little.
    struct Counting {
        origin: Origin,
        served: Arc<AtomicU64>,
        requests: Arc<AtomicU64>,
        mode: Arc<std::sync::atomic::AtomicU8>,
    }

    const SERVE: u8 = 0;
    const STARVE: u8 = 1; // answers 100 bytes whatever is asked: a tunnel that moves too little
    const SLAM: u8 = 2; // closes the connection

    async fn counting_origin() -> Counting {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(AtomicU64::new(0));
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(SERVE));
        let (s, r, m) = (served.clone(), requests.clone(), mode.clone());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (s, r, m) = (s.clone(), r.clone(), m.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    r.fetch_add(1, Ordering::SeqCst);
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let asked: usize = text
                        .split_whitespace()
                        .nth(1)
                        .and_then(|p| p.strip_prefix("/bytes/"))
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                    let n = match m.load(Ordering::SeqCst) {
                        SLAM => return,
                        STARVE => 100.min(asked),
                        _ => asked,
                    };
                    let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await;
                    let _ = stream.write_all(&vec![b'x'; n]).await;
                    s.fetch_add(n as u64, Ordering::SeqCst);
                });
            }
        });
        Counting {
            origin: Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
            served,
            requests,
            mode,
        }
    }

    /// While the tunnel is healthy, a check is a few hundred bytes, not a download. At one check every five
    /// seconds the old check (128 KiB each) came to about 92 MB an hour for a connection nobody was using.
    #[tokio::test]
    async fn a_healthy_tunnel_is_checked_with_a_sliver_not_a_download() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        for tick in 1..=60u64 {
            // Sixty checks, five seconds apart: five minutes less one tick, all within the deep interval.
            let at = start + Duration::from_secs(5 * tick - 1).min(Duration::from_secs(298));
            assert_eq!(checker.check(&origin.origin, at).await, LiveCheck::Passed);
        }
        let bytes = origin.served.load(Ordering::SeqCst);
        assert_eq!(origin.requests.load(Ordering::SeqCst), 60);
        assert!(bytes <= 60 * LIGHT_BYTES, "{bytes} bytes for 60 checks");
        assert!(
            bytes < USABLE_MIN_BYTES,
            "all sixty together are less than one old check ({bytes})"
        );
    }

    /// Throughput is still verified, but on a slow clock: one full check per interval, never one per tick.
    #[tokio::test]
    async fn the_full_check_happens_once_per_interval_and_not_before() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(299))
                .await,
            LiveCheck::Passed
        );
        assert!(
            origin.served.load(Ordering::SeqCst) < USABLE_MIN_BYTES,
            "not yet"
        );
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(300))
                .await,
            LiveCheck::Passed
        );
        assert!(
            origin.served.load(Ordering::SeqCst) >= live_check_config().bytes,
            "the full check ran"
        );
        // And the clock restarts from it.
        let after = origin.served.load(Ordering::SeqCst);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(301))
                .await,
            LiveCheck::Passed
        );
        assert!(origin.served.load(Ordering::SeqCst) - after <= LIGHT_BYTES);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(600))
                .await,
            LiveCheck::Passed
        );
        assert!(origin.served.load(Ordering::SeqCst) - after >= live_check_config().bytes);
    }

    /// A connection that has just been made was proved by a full transfer (the race); the first checks
    /// do not repeat it. A checker that has never been told starts with a full one.
    #[tokio::test]
    async fn a_new_checker_starts_with_the_full_check() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let now = std::time::Instant::now();
        assert_eq!(checker.check(&origin.origin, now).await, LiveCheck::Passed);
        assert!(origin.served.load(Ordering::SeqCst) >= live_check_config().bytes);
    }

    /// A sliver that comes up short is not taken as a failure on its own, and not as a pass either: the
    /// full check decides, at once.
    #[tokio::test]
    async fn a_short_answer_to_the_sliver_is_settled_by_the_full_check() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        origin.mode.store(STARVE, Ordering::SeqCst);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(5))
                .await,
            LiveCheck::Failed
        );
        assert_eq!(
            origin.requests.load(Ordering::SeqCst),
            2,
            "the sliver, then the full check"
        );
        // Recovered: the next sliver passes without another full check.
        origin.mode.store(SERVE, Ordering::SeqCst);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(10))
                .await,
            LiveCheck::Passed
        );
    }

    #[tokio::test]
    async fn a_tunnel_that_answers_nothing_fails_and_a_refused_origin_fails() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        origin.mode.store(SLAM, Ordering::SeqCst);
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(5))
                .await,
            LiveCheck::Failed
        );
        let closed = Origin::parse(&format!("http://127.0.0.1:{}", closed_port().await)).unwrap();
        assert_eq!(
            checker
                .check(&closed, start + Duration::from_secs(10))
                .await,
            LiveCheck::Failed
        );
    }

    /// Whatever the origin answers with, the sliver is never more than asked for: a hostile or broken origin
    /// that sends a flood is read only up to the bound.
    #[tokio::test]
    async fn a_flood_from_the_origin_is_not_read_past_the_bound() {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await;
                    let chunk = vec![b'x'; 65536];
                    for _ in 0..4096 {
                        if stream.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        let began = std::time::Instant::now();
        assert_eq!(
            checker.check(&origin, start + Duration::from_secs(5)).await,
            LiveCheck::Passed
        );
        assert!(began.elapsed() < Duration::from_secs(3));
    }

    // ------------------------------------------------------------------ what a race costs

    /// A race fetches this much from each method at once. It must be enough to be judged and no more than a
    /// barely usable link can move in the time the race allows, or a link that is just good enough fails.
    #[test]
    fn the_race_asks_for_enough_to_judge_and_no_more_than_the_slowest_usable_link_can_carry_in_time(
    ) {
        use dnet_core::probe::USABLE_MIN_BITS_PER_SEC;
        // Checked when this is compiled, so a change that breaks the relation does not build.
        const {
            assert!(RACE_BYTES > USABLE_MIN_BYTES, "enough to be judged usable");
            assert!(RACE_BYTES <= USABLE_MIN_BYTES * 4, "not a download");
            assert!(
                RACE_BYTES * 8 / USABLE_MIN_BITS_PER_SEC < RACE_TRANSFER_TIMEOUT.as_secs(),
                "a link at the floor must finish inside the race's allowance"
            );
        }
    }

    /// What an idle, connected tunnel costs, from the constants themselves, so a change that makes it
    /// dearer fails here and has to say why: at most 2 MB an hour for checking.
    #[test]
    fn an_idle_connection_costs_at_most_two_megabytes_an_hour_to_check() {
        let every_second_check = 3600 / 5;
        let light = every_second_check * LIGHT_BYTES;
        let deep = (3600 / DEEP_EVERY.as_secs()) * live_check_config().bytes;
        let total = light + deep;
        assert!(total <= 2_000_000, "{total} bytes an hour");
    }

    /// The numbers that decide what checking costs are pinned, so a slip in arithmetic cannot change them
    /// quietly: each is a multiple of the least that can be judged, not a sum with it.
    #[test]
    fn the_sizes_are_exactly_what_they_are_documented_to_be() {
        assert_eq!(USABLE_MIN_BYTES, 65_536);
        assert_eq!(live_check_config().bytes, 131_072);
        assert_eq!(RACE_BYTES, 196_608);
        assert_eq!(LIGHT_BYTES, 1024);
        assert_eq!(DEEP_EVERY, Duration::from_secs(600));
    }

    /// A new connection must not inherit what an old one proved: after `forget` the next check is the full one.
    #[tokio::test]
    async fn after_forgetting_the_next_check_is_the_full_one() {
        let origin = counting_origin().await;
        let checker = LiveChecker::new(Duration::from_secs(300));
        let start = std::time::Instant::now();
        checker.proved(start);
        checker.forget();
        assert_eq!(
            checker
                .check(&origin.origin, start + Duration::from_secs(1))
                .await,
            LiveCheck::Passed
        );
        assert!(origin.served.load(Ordering::SeqCst) >= live_check_config().bytes);
    }
}
