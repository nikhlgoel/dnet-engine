//! One measured transfer through a probe's SOCKS proxy (FR-004, HV-12).
//!
//! The outcome is expressed in `dnet_core::probe::ProfileProbe` terms, and the mapping is the
//! point of this module:
//!
//! - the proxy cannot connect onward, or cannot be reached: **`HandshakeFailed`**. The profile's
//!   transport did not come up.
//! - the connection was set up but not a single body byte arrived (stalled, reset, or the
//!   origin answered with an error): **`HandshakeOnly`**. A handshake alone is not success.
//! - body bytes arrived: **`Transferred { bytes, elapsed }`** with what *actually* arrived and
//!   how long that took, even when the transfer stalled or was cut short. That is what lets a
//!   throttled link be judged *slow* (HV-12) rather than merely *dead*: 150 KB in 12 s is a
//!   rate, and `dnet_core::probe::judge` decides it is too low.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dnet_core::probe::ProfileProbe;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5;

pub use dnet_core::origin::{Origin, OriginError};

/// How a transfer is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasureConfig {
    /// Time allowed for the proxy to connect onward (the handshake).
    pub connect_timeout: Duration,
    /// Time allowed for the transfer, from the request being sent.
    pub transfer_timeout: Duration,
    /// Body size to ask the origin for (`/bytes/<n>`). Anything under
    /// `dnet_core::probe::USABLE_MIN_BYTES` can never be judged usable.
    pub bytes: u64,
}

/// Fetch `/bytes/<n>` from `origin` through the SOCKS proxy at `proxy`, and report what happened.
pub async fn measure_via_proxy(
    proxy: SocketAddr,
    origin: &Origin,
    config: &MeasureConfig,
    auth: Option<&socks5::Credentials>,
) -> ProfileProbe {
    let mut attempt = 1;
    let mut stream = loop {
        match socks5::connect(
            proxy,
            origin.host(),
            origin.port(),
            config.connect_timeout,
            auth,
        )
        .await
        {
            Ok(stream) => break stream,
            // The core's interface monitor can report "network changed" in its first moments;
            // the proxy relays that as "general failure". Retry only that reply, a few times.
            Err(socks5::SocksError::Refused(GENERAL_FAILURE)) if attempt < SETTLE_ATTEMPTS => {
                tracing::debug!(attempt, "probe core still settling; retrying the connect");
                attempt += 1;
                tokio::time::sleep(SETTLE_DELAY).await;
            }
            Err(error) => {
                tracing::debug!(%error, "probe handshake failed");
                return ProfileProbe::HandshakeFailed;
            }
        }
    };

    transfer(&mut stream, origin, config).await
}

/// What a direct measurement saw: how long the connection took to open, if it did, and the
/// transfer judged in the same terms as a proxied one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectMeasurement {
    /// Time to open the connection, or `None` if it could not be opened in time.
    pub connect: Option<Duration>,
    pub probe: ProfileProbe,
}

/// Fetch `/bytes/<n>` from `origin` over an ordinary connection, which the operating system routes
/// wherever its routing table says. Used while a tunnel is up, when "where the table says" is the
/// tunnel: the origin is reachable only through it, so a transfer that completes proves the tunnel
/// carries traffic, and the time to open the connection is a round trip through it.
pub async fn measure_direct(origin: &Origin, config: &MeasureConfig) -> DirectMeasurement {
    let started = Instant::now();
    let address = format!("{}:{}", origin.host(), origin.port());
    let mut stream = match tokio::time::timeout(
        config.connect_timeout,
        tokio::net::TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(%error, "direct connect failed");
            return DirectMeasurement {
                connect: None,
                probe: ProfileProbe::HandshakeFailed,
            };
        }
        Err(_) => {
            return DirectMeasurement {
                connect: None,
                probe: ProfileProbe::HandshakeFailed,
            }
        }
    };
    let connect = started.elapsed().max(Duration::from_micros(1));
    DirectMeasurement {
        connect: Some(connect),
        probe: transfer(&mut stream, origin, config).await,
    }
}

/// The request and the measurement of its answer, over a connection already open to the origin.
async fn transfer<S>(stream: &mut S, origin: &Origin, config: &MeasureConfig) -> ProfileProbe
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = format!(
        "GET /bytes/{} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        config.bytes,
        origin.host(),
        origin.port()
    );
    let started = Instant::now();
    if stream.write_all(request.as_bytes()).await.is_err() {
        return ProfileProbe::HandshakeOnly;
    }

    let deadline = tokio::time::Instant::now() + config.transfer_timeout;
    let mut head: Vec<u8> = Vec::new();
    let mut in_body = false;
    let mut body: u64 = 0;
    let mut cut_short = false;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            // Reset or closed before the deadline with the body incomplete. A mid-stream cut is
            // what interference looks like, so it is not usable traffic, however fast the part
            // that arrived was.
            Ok(_) => {
                cut_short = true;
                break;
            }
            // Stalled until the deadline: stop with what arrived. A throttled link looks like
            // this, and what it moved is a rate that can be judged slow.
            Err(_) => break,
        };
        if in_body {
            body += n as u64;
        } else {
            head.extend_from_slice(&buf[..n]);
            match find(&head, b"\r\n\r\n") {
                Some(end) => {
                    if !is_success(&head[..end]) {
                        return ProfileProbe::HandshakeOnly;
                    }
                    in_body = true;
                    body = (head.len() - (end + 4)) as u64;
                    head = Vec::new();
                }
                None if head.len() > MAX_HEAD => return ProfileProbe::HandshakeOnly,
                None => {}
            }
        }
        if body >= config.bytes {
            break;
        }
    }

    if body == 0 || cut_short {
        ProfileProbe::HandshakeOnly
    } else {
        ProfileProbe::Transferred {
            bytes: body,
            // Never zero: a transfer too quick to time is still a measurement, not an error.
            elapsed: started.elapsed().max(Duration::from_micros(1)),
        }
    }
}

/// SOCKS5 reply code "general failure" (RFC 1928 §6), which the core uses for any dial error.
const GENERAL_FAILURE: u8 = 1;
/// Connect attempts when the proxy answers "general failure" while the core settles.
const SETTLE_ATTEMPTS: u32 = 3;
/// Pause between those attempts.
const SETTLE_DELAY: Duration = Duration::from_millis(200);

/// More header than this is not an origin we asked for.
const MAX_HEAD: usize = 16 * 1024;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether a response head's status line is a 2xx.
fn is_success(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let mut parts = line.split(|b| *b == b' ');
    matches!(
        (parts.next(), parts.next()),
        (Some(version), Some(status)) if version.starts_with(b"HTTP/") && status.first() == Some(&b'2')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::net::{TcpListener, TcpStream};

    const GREETING_AND_REQUEST: usize = 3 + 4 + 4 + 2; // for an IPv4 literal origin

    fn origin() -> Origin {
        Origin::parse("http://203.0.113.80:8080").unwrap()
    }

    fn config(bytes: u64) -> MeasureConfig {
        MeasureConfig {
            connect_timeout: Duration::from_secs(2),
            transfer_timeout: Duration::from_millis(400),
            bytes,
        }
    }

    /// A SOCKS proxy that accepts the connect and then plays the origin with `behave`. Returns the
    /// request head the client sent, for inspection.
    async fn proxy_and_origin<F, Fut>(
        reply_code: u8,
        behave: F,
    ) -> (SocketAddr, tokio::task::JoinHandle<String>)
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; GREETING_AND_REQUEST];
            // greeting (3) -> answer, then the 10-byte IPv4 request.
            s.read_exact(&mut hello[..3]).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            s.read_exact(&mut hello[3..]).await.unwrap();
            s.write_all(&[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            if reply_code != 0 {
                return String::new();
            }
            // Read the HTTP request head.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut byte).await.is_err() {
                    break;
                }
                head.push(byte[0]);
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            behave(s).await;
            text
        });
        (addr, task)
    }

    #[tokio::test]
    async fn a_full_transfer_reports_the_bytes_and_the_time() {
        let (addr, task) = proxy_and_origin(0, |mut s| async move {
            s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
            s.write_all(&vec![b'x'; 100_000]).await.unwrap();
        })
        .await;
        let probe = measure_via_proxy(addr, &origin(), &config(100_000), None).await;
        match probe {
            ProfileProbe::Transferred { bytes, elapsed } => {
                assert_eq!(bytes, 100_000);
                assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
            }
            other => panic!("expected a transfer, got {other:?}"),
        }
        let head = task.await.unwrap();
        assert!(head.starts_with("GET /bytes/100000 HTTP/1.0\r\n"), "{head}");
        assert!(head.contains("Host: 203.0.113.80:8080\r\n"), "{head}");
        assert!(head.contains("Connection: close\r\n"), "{head}");
    }

    #[tokio::test]
    async fn a_refusal_by_the_proxy_means_the_handshake_failed() {
        let (addr, _task) = proxy_and_origin(5, |_s| async {}).await;
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1000), None).await,
            ProfileProbe::HandshakeFailed
        );
    }

    /// A SOCKS proxy that answers its n-th connection with `codes[n]` (0 = connect and serve
    /// 1000 bytes of HTTP), then keeps answering with the last code. Counts the connections.
    async fn proxy_sequence(
        codes: Vec<u8>,
    ) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let code = *codes.get(n).or(codes.last()).unwrap();
                tokio::spawn(async move {
                    let mut hello = [0u8; GREETING_AND_REQUEST];
                    s.read_exact(&mut hello[..3]).await.unwrap();
                    s.write_all(&[5, 0]).await.unwrap();
                    s.read_exact(&mut hello[3..]).await.unwrap();
                    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    if code == 0 {
                        let mut byte = [0u8; 1];
                        let mut head = Vec::new();
                        while !head.ends_with(b"\r\n\r\n") {
                            if s.read_exact(&mut byte).await.is_err() {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
                        s.write_all(&[b'x'; 1000]).await.unwrap();
                    }
                });
            }
        });
        (addr, count)
    }

    /// The core's interface monitor can report "network changed" during its first moments, which
    /// the proxy relays as "general failure". That is not a block, and must not be read as one.
    #[tokio::test]
    async fn a_general_failure_in_the_first_moments_is_retried_and_can_succeed() {
        let (addr, count) = proxy_sequence(vec![1, 1, 0]).await;
        match measure_via_proxy(addr, &origin(), &config(1000), None).await {
            ProfileProbe::Transferred { bytes, .. } => assert_eq!(bytes, 1000),
            other => panic!("expected a transfer after the retries, got {other:?}"),
        }
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// The retry is bounded: a profile that really cannot connect still fails, and quickly.
    #[tokio::test]
    async fn a_persistent_general_failure_gives_up_after_a_few_attempts() {
        let (addr, count) = proxy_sequence(vec![1]).await;
        let started = Instant::now();
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1000), None).await,
            ProfileProbe::HandshakeFailed
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A definite refusal is not retried: it is the answer, not a start-up artefact.
    #[tokio::test]
    async fn a_connection_refused_is_not_retried() {
        let (addr, count) = proxy_sequence(vec![5]).await;
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1000), None).await,
            ProfileProbe::HandshakeFailed
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_proxy_that_is_not_listening_means_the_handshake_failed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1000), None).await,
            ProfileProbe::HandshakeFailed
        );
    }

    /// FR-004: connected, but nothing comes through.
    #[tokio::test]
    async fn a_connection_that_never_delivers_is_a_handshake_only() {
        let (addr, _task) = proxy_and_origin(0, |s| async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(s);
        })
        .await;
        let started = Instant::now();
        let probe = measure_via_proxy(addr, &origin(), &config(1000), None).await;
        assert_eq!(probe, ProfileProbe::HandshakeOnly);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "must stop at the transfer timeout"
        );
    }

    /// HV-12: a throttled link delivers a little and then crawls. It must be reported as the
    /// little it delivered, so it can be judged slow.
    #[tokio::test]
    async fn a_stalled_transfer_reports_what_arrived_and_when_it_gave_up() {
        let (addr, _task) = proxy_and_origin(0, |mut s| async move {
            s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
            s.write_all(&[b'x'; 150]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(s);
        })
        .await;
        match measure_via_proxy(addr, &origin(), &config(1_000_000), None).await {
            ProfileProbe::Transferred { bytes, elapsed } => {
                assert_eq!(bytes, 150);
                assert!(
                    elapsed >= Duration::from_millis(350),
                    "waited out the timeout: {elapsed:?}"
                );
            }
            other => panic!("expected a partial transfer, got {other:?}"),
        }
    }

    /// A mid-stream cut is what interference looks like. It must not read as a working profile.
    #[tokio::test]
    async fn a_connection_cut_part_way_is_not_a_usable_transfer() {
        let (addr, _task) = proxy_and_origin(0, |mut s| async move {
            s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
            s.write_all(&[b'x'; 5000]).await.unwrap();
            // dropped: the peer hangs up
        })
        .await;
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1_000_000), None).await,
            ProfileProbe::HandshakeOnly
        );
    }

    #[tokio::test]
    async fn an_error_status_from_the_origin_is_not_a_transfer() {
        let (addr, _task) = proxy_and_origin(0, |mut s| async move {
            s.write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\nbusy")
                .await
                .unwrap();
        })
        .await;
        assert_eq!(
            measure_via_proxy(addr, &origin(), &config(1000), None).await,
            ProfileProbe::HandshakeOnly,
            "a 503 body is not the traffic that was asked for"
        );
    }

    #[tokio::test]
    async fn headers_split_across_packets_are_still_parsed() {
        let (addr, _task) = proxy_and_origin(0, |mut s| async move {
            s.write_all(b"HTTP/1.0 2").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(b"00 OK\r\nX: y\r").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(b"\n\r\n").await.unwrap();
            s.write_all(&[b'x'; 2000]).await.unwrap();
        })
        .await;
        match measure_via_proxy(addr, &origin(), &config(2000), None).await {
            ProfileProbe::Transferred { bytes, .. } => assert_eq!(bytes, 2000),
            other => panic!("expected a transfer, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------ direct

    /// An origin on loopback that plays `behave` for one connection.
    async fn direct_origin<F, Fut>(behave: F) -> Origin
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut byte).await.is_err() {
                    return;
                }
                head.push(byte[0]);
            }
            behave(s).await;
        });
        Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()
    }

    #[tokio::test]
    async fn a_direct_transfer_reports_the_connect_time_and_the_bytes() {
        let origin = direct_origin(|mut s| async move {
            s.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
            s.write_all(&vec![b'x'; 100_000]).await.unwrap();
        })
        .await;

        let seen = measure_direct(&origin, &config(100_000)).await;

        assert!(seen.connect.is_some());
        assert!(
            matches!(seen.probe, ProfileProbe::Transferred { bytes: 100_000, .. }),
            "{:?}",
            seen.probe
        );
    }

    #[tokio::test]
    async fn a_direct_connect_that_is_refused_has_no_connect_time() {
        // Bind and drop, so the port is closed.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();

        let seen = measure_direct(&origin, &config(1000)).await;

        assert_eq!(seen.connect, None);
        assert_eq!(seen.probe, ProfileProbe::HandshakeFailed);
    }

    #[tokio::test]
    async fn a_direct_origin_that_answers_with_an_error_is_connected_but_moves_nothing() {
        let origin = direct_origin(|mut s| async move {
            s.write_all(b"HTTP/1.0 404 Not Found\r\n\r\nnope")
                .await
                .unwrap();
        })
        .await;

        let seen = measure_direct(&origin, &config(1000)).await;

        assert!(seen.connect.is_some());
        assert_eq!(seen.probe, ProfileProbe::HandshakeOnly);
    }
}
