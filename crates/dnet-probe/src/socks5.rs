//! The smallest SOCKS5 client that can run a probe: no authentication, `CONNECT` only.
//!
//! A probe asks its loopback proxy to open a connection to the origin. If the proxy replies
//! "succeeded", the profile's transport carried that connection setup, which is the strongest
//! thing a handshake can show; whether it then carries *data* is `measure`'s question.
//!
//! The proxy is the core's own SOCKS inbound on `127.0.0.1`. The client never offers a
//! username or password, so a proxy that demands one is reported as such rather than guessed at.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Why a SOCKS5 connect did not produce a stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SocksError {
    /// The TCP connection to the proxy itself failed.
    #[error("could not reach the local proxy: {0}")]
    Proxy(String),
    /// The proxy answered with something that is not SOCKS5.
    #[error("the local proxy did not speak SOCKS5")]
    Protocol,
    /// The proxy wants authentication, which a probe never offers.
    #[error("the local proxy requires authentication")]
    Auth,
    /// The proxy could not connect onward. This is how a blocked or dead profile shows up.
    #[error("the proxy could not connect onward: {}", reason(*.0))]
    Refused(u8),
    /// The username or password is longer than RFC 1929's 255 bytes.
    #[error("the proxy username or password is longer than 255 bytes")]
    CredentialsTooLong,
    /// No answer in time.
    #[error("no answer from the proxy within {0:?}")]
    Timeout(Duration),
    /// A host name longer than SOCKS5's 255-byte limit.
    #[error("the host name is longer than 255 bytes")]
    HostTooLong,
    /// A read or write failed part-way.
    #[error("i/o error talking to the proxy: {0}")]
    Io(String),
}

/// The username and password a probe's proxy demands (RFC 1929). The password is redacted from
/// `Debug`, so a logged error or struct cannot leak it.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Ask the SOCKS5 proxy at `proxy` to connect to `host:port`, within `timeout` overall. On
/// success the returned stream is the tunnelled connection.
pub async fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
    auth: Option<&Credentials>,
) -> Result<TcpStream, SocksError> {
    if host.parse::<IpAddr>().is_err() && host.len() > 255 {
        return Err(SocksError::HostTooLong);
    }
    match tokio::time::timeout(timeout, handshake(proxy, host, port, auth)).await {
        Ok(result) => result,
        Err(_) => Err(SocksError::Timeout(timeout)),
    }
}

fn io(e: std::io::Error) -> SocksError {
    SocksError::Io(e.to_string())
}

/// The reason a SOCKS5 reply code (RFC 1928 §6) gives for failing.
pub fn reason(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "connection not allowed",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown reply code",
    }
}

async fn handshake(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<&Credentials>,
) -> Result<TcpStream, SocksError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| SocksError::Proxy(e.to_string()))?;

    // Greeting: version 5, one method. With credentials only username/password is offered:
    // a proxy that would let us in without them is not the proxy we configured.
    let offered = if auth.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, offered]).await.map_err(io)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(io)?;
    if chosen[0] != 5 {
        return Err(SocksError::Protocol);
    }
    if chosen[1] == 0xff {
        return Err(SocksError::Auth);
    }
    if chosen[1] != offered {
        return Err(SocksError::Protocol);
    }
    if let Some(credentials) = auth {
        let (user, pass) = (
            credentials.username.as_bytes(),
            credentials.password.as_bytes(),
        );
        if user.len() > 255 || pass.len() > 255 {
            return Err(SocksError::CredentialsTooLong);
        }
        let mut sub = vec![1, user.len() as u8];
        sub.extend_from_slice(user);
        sub.push(pass.len() as u8);
        sub.extend_from_slice(pass);
        stream.write_all(&sub).await.map_err(io)?;
        let mut verdict = [0u8; 2];
        stream.read_exact(&mut verdict).await.map_err(io)?;
        if verdict[0] != 1 {
            return Err(SocksError::Protocol);
        }
        if verdict[1] != 0 {
            return Err(SocksError::Auth);
        }
    }

    // Request: CONNECT, with the target as an address when it is a literal.
    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.push(3);
            request.push(host.len() as u8); // checked <= 255 by the caller
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(io)?;

    // Reply: version, code, reserved, address type, then the bound address and port, which
    // must be consumed so they are not mistaken for tunnelled data.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != 5 {
        return Err(SocksError::Protocol);
    }
    if head[1] != 0 {
        return Err(SocksError::Refused(head[1]));
    }
    let bound_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io)?;
            usize::from(len[0])
        }
        _ => return Err(SocksError::Protocol),
    };
    let mut rest = vec![0u8; bound_len + 2];
    stream.read_exact(&mut rest).await.map_err(io)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    const T: Duration = Duration::from_secs(5);

    /// Run `script` against the first connection to a fresh loopback listener.
    async fn fake_proxy<F, Fut, R>(script: F) -> (SocketAddr, JoinHandle<R>)
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = R> + Send,
        R: Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            script(stream).await
        });
        (addr, task)
    }

    /// Read the greeting, answer "no authentication", read `request_len` more bytes, and answer
    /// `reply`. Returns the greeting and the request as the client sent them.
    async fn handshake(
        mut s: TcpStream,
        request_len: usize,
        reply: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, TcpStream) {
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        s.write_all(&[5, 0]).await.unwrap();
        let mut request = vec![0u8; request_len];
        s.read_exact(&mut request).await.unwrap();
        s.write_all(&reply).await.unwrap();
        (greeting.to_vec(), request, s)
    }

    const OK_V4: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    #[tokio::test]
    async fn a_domain_is_sent_as_a_domain_and_the_stream_is_usable() {
        let (addr, task) = fake_proxy(|s| async move {
            let (g, r, mut s) = handshake(s, 4 + 1 + 11 + 2, OK_V4.to_vec()).await;
            s.write_all(b"hi").await.unwrap();
            (g, r)
        })
        .await;
        let mut stream = connect(addr, "example.com", 80, T, None).await.unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");

        let (greeting, request) = task.await.unwrap();
        assert_eq!(greeting, [5, 1, 0], "one method offered: no authentication");
        let mut expected = vec![5, 1, 0, 3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(request, expected);
    }

    #[tokio::test]
    async fn an_ipv4_literal_is_sent_as_an_address_not_a_name() {
        let (addr, task) =
            fake_proxy(|s| async move { handshake(s, 4 + 4 + 2, OK_V4.to_vec()).await.1 }).await;
        connect(addr, "203.0.113.80", 8080, T, None).await.unwrap();
        let mut expected = vec![5, 1, 0, 1, 203, 0, 113, 80];
        expected.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(task.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn an_ipv6_literal_is_sent_as_an_address() {
        let (addr, task) =
            fake_proxy(|s| async move { handshake(s, 4 + 16 + 2, OK_V4.to_vec()).await.1 }).await;
        connect(addr, "2001:db8::1", 443, T, None).await.unwrap();
        let request = task.await.unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &request[4..20],
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[tokio::test]
    async fn a_reply_carrying_a_domain_bound_address_is_parsed_to_its_end() {
        let mut reply = vec![5, 0, 0, 3, 3];
        reply.extend_from_slice(b"abc");
        reply.extend_from_slice(&[0, 80]);
        let (addr, task) = fake_proxy(move |s| async move {
            let (_, _, mut s) = handshake(s, 4 + 4 + 2, reply).await;
            s.write_all(b"X").await.unwrap();
        })
        .await;
        let mut stream = connect(addr, "198.51.100.1", 80, T, None).await.unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(
            &byte, b"X",
            "the bound address must not be left in the stream"
        );
        task.await.unwrap();
    }

    /// A blocked or dead profile shows up as the proxy failing to connect onward.
    #[tokio::test]
    async fn a_refusal_from_the_proxy_is_reported_with_its_reason() {
        for (code, reason) in [
            (1u8, "general failure"),
            (3, "network unreachable"),
            (4, "host unreachable"),
            (5, "connection refused"),
            (6, "TTL expired"),
        ] {
            let reply = vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0];
            let (addr, task) =
                fake_proxy(move |s| async move { handshake(s, 4 + 4 + 2, reply).await.0 }).await;
            let err = connect(addr, "203.0.113.80", 80, T, None)
                .await
                .unwrap_err();
            assert_eq!(err, SocksError::Refused(code), "code {code}");
            assert!(err.to_string().contains(reason), "{err}");
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn something_that_is_not_socks5_is_a_protocol_error() {
        let (addr, task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[4, 0x5a]).await.unwrap();
        })
        .await;
        assert_eq!(
            connect(addr, "example.com", 80, T, None).await.unwrap_err(),
            SocksError::Protocol
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_proxy_that_wants_authentication_is_reported_as_such() {
        let (addr, task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 0xff]).await.unwrap();
        })
        .await;
        assert_eq!(
            connect(addr, "example.com", 80, T, None).await.unwrap_err(),
            SocksError::Auth
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_proxy_that_is_not_listening_is_reported_without_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = connect(addr, "example.com", 80, T, None).await.unwrap_err();
        assert!(matches!(err, SocksError::Proxy(_)), "{err:?}");
    }

    fn creds() -> Credentials {
        Credentials {
            username: "probe".into(),
            password: "s3cret".into(),
        }
    }

    /// RFC 1929: with credentials only username/password is offered, and they are sent in the
    /// sub-negotiation. A proxy that would let us in without them is not the one we configured.
    #[tokio::test]
    async fn credentials_are_the_only_method_offered_and_are_sent_per_rfc_1929() {
        let (addr, task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 2]).await.unwrap();
            let mut sub = [0u8; 14];
            s.read_exact(&mut sub).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
            let mut request = [0u8; 10];
            s.read_exact(&mut request).await.unwrap();
            s.write_all(&OK_V4).await.unwrap();
            (greeting, sub)
        })
        .await;
        connect(addr, "203.0.113.80", 80, T, Some(&creds()))
            .await
            .unwrap();
        let (greeting, sub) = task.await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        let mut expected = vec![1, 5];
        expected.extend_from_slice(b"probe");
        expected.push(6);
        expected.extend_from_slice(b"s3cret");
        assert_eq!(sub.to_vec(), expected);
    }

    #[tokio::test]
    async fn wrong_credentials_are_reported_as_an_authentication_failure() {
        let (addr, task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 2]).await.unwrap();
            let mut sub = [0u8; 14];
            s.read_exact(&mut sub).await.unwrap();
            s.write_all(&[1, 1]).await.unwrap();
        })
        .await;
        let err = connect(addr, "203.0.113.80", 80, T, Some(&creds()))
            .await
            .unwrap_err();
        assert_eq!(err, SocksError::Auth);
        task.await.unwrap();
    }

    /// We asked for authentication, so a proxy that picks "none" is not the proxy we configured.
    #[tokio::test]
    async fn a_proxy_that_skips_the_authentication_we_asked_for_is_refused() {
        let (addr, task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
        })
        .await;
        let err = connect(addr, "203.0.113.80", 80, T, Some(&creds()))
            .await
            .unwrap_err();
        assert_eq!(err, SocksError::Protocol);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn credentials_over_255_bytes_are_refused() {
        let (addr, _task) = fake_proxy(|mut s| async move {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[5, 2]).await.unwrap();
        })
        .await;
        let long = Credentials {
            username: "u".repeat(256),
            password: "p".into(),
        };
        let err = connect(addr, "203.0.113.80", 80, T, Some(&long))
            .await
            .unwrap_err();
        assert_eq!(err, SocksError::CredentialsTooLong);
    }

    #[test]
    fn the_password_never_appears_in_debug_output() {
        let shown = format!("{:?}", creds());
        assert!(shown.contains("probe"));
        assert!(!shown.contains("s3cret"), "{shown}");
    }

    #[tokio::test]
    async fn a_silent_proxy_times_out() {
        let (addr, _task) = fake_proxy(|s| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        })
        .await;
        let wait = Duration::from_millis(150);
        let started = std::time::Instant::now();
        let err = connect(addr, "example.com", 80, wait, None)
            .await
            .unwrap_err();
        assert_eq!(err, SocksError::Timeout(wait));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_host_name_over_255_bytes_is_refused_before_connecting() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let long = "a".repeat(256);
        assert_eq!(
            connect(addr, &long, 80, T, None).await.unwrap_err(),
            SocksError::HostTooLong
        );
    }
}
