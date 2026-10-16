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

/// The known origin a probe fetches from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    host: String,
    port: u16,
}

/// Why an origin URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    #[error("the origin must be an http:// URL")]
    NotHttp,
    #[error("the origin has no host")]
    NoHost,
    #[error("the origin port is not valid")]
    BadPort,
    #[error("the origin must be just scheme, host and port, with no path or credentials")]
    Extra,
}

impl Origin {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Parse `http://host[:port][/]`. The port defaults to 80. Anything else in the URL (a path,
    /// a query, credentials) is refused so a probe cannot be pointed somewhere unexpected.
    pub fn parse(url: &str) -> Result<Origin, OriginError> {
        let rest = url.strip_prefix("http://").ok_or(OriginError::NotHttp)?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) {
            return Err(OriginError::Extra);
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(OriginError::BadPort)?;
                (host, port)
            }
            None => (rest, 80),
        };
        if host.is_empty() {
            return Err(OriginError::NoHost);
        }
        // Letters, digits, dots and hyphens only. That excludes an IPv6 literal (a probe does not
        // take one) and, more to the point, anything that could add a header line to the request
        // the host is written into: CR, LF, spaces, NUL.
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(OriginError::Extra);
        }
        Ok(Origin {
            host: host.to_string(),
            port,
        })
    }
}

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

    #[test]
    fn origin_urls_parse_to_host_and_port() {
        let o = Origin::parse("http://203.0.113.80:8080").unwrap();
        assert_eq!((o.host(), o.port()), ("203.0.113.80", 8080));
        assert_eq!(Origin::parse("http://example.net/").unwrap().port(), 80);
        assert_eq!(
            Origin::parse("http://example.net").unwrap().host(),
            "example.net"
        );
    }

    /// The host is written into a request line, so it must not be able to add a header.
    #[test]
    fn a_host_that_could_inject_a_header_is_refused() {
        for bad in [
            "http://a b.net",
            "http://a\r\nX-Evil: 1.net",
            "http://a\nb",
            "http://a\0b",
            "http://under_score.net",
            "http://[::1]:80",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn origin_urls_with_anything_else_are_refused() {
        assert_eq!(
            Origin::parse("https://example.net"),
            Err(OriginError::NotHttp)
        );
        assert_eq!(Origin::parse("example.net:80"), Err(OriginError::NotHttp));
        assert_eq!(Origin::parse("http://"), Err(OriginError::NoHost));
        assert_eq!(Origin::parse("http://:80"), Err(OriginError::NoHost));
        assert_eq!(
            Origin::parse("http://example.net:0"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net:99999"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net:abc"),
            Err(OriginError::BadPort)
        );
        assert_eq!(
            Origin::parse("http://example.net/bytes/1"),
            Err(OriginError::Extra)
        );
        assert_eq!(
            Origin::parse("http://user@example.net"),
            Err(OriginError::Extra)
        );
        assert_eq!(
            Origin::parse("http://example.net?x=1"),
            Err(OriginError::Extra)
        );
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
}
