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
use dnet_core::probe::{judge, Verdict, USABLE_MIN_BYTES};
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

    use dnet_core::probe::ProfileProbe;
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
}
