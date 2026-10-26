//! T077/T078 wiring — asking the network whether a captive portal is in the way.
//!
//! `dnet_core::portal` decides what a response means; this makes the request. It fetches the two small
//! pages the operating system itself fetches, over plain HTTP (a portal can only intercept what it can
//! read), through the physical network: the probe hosts are exempt from the tunnel by the built-in
//! rules, which is what lets this work before a tunnel exists and while one is up.
//!
//! **What comes back is hostile.** Whoever runs the network chose it. So the read is bounded in time and
//! in size (a head of at most [`MAX_HEAD`] bytes, a body of at most [`MAX_BODY`]), nothing is followed
//! (a redirect is *reported*, never fetched: the login address is offered to the person's own browser,
//! `portal::login_url`), and anything that is not an HTTP reply is `Inconclusive`, never a guess.
//!
//! The request carries nothing about the person or the machine: a fixed path on a fixed host, a fixed
//! `User-Agent`, no cookie, no identifier.

use std::net::SocketAddr;
use std::time::Duration;

use dnet_core::portal::{classify, combine, PortalState, Probe, Response};
use dnet_core::portal_expiry::{PortalWatch, Recognised};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The most of a reply's head (status line and headers) that is read.
pub const MAX_HEAD: usize = 8 * 1024;
/// The most of a reply's body that is kept; the expected pages are about 20 bytes.
pub const MAX_BODY: usize = 512;

/// The request for `probe`: plain HTTP/1.1, closing the connection after one reply.
pub fn request_for(probe: Probe) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: dnet-engine\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        probe.path(),
        probe.host()
    )
}

/// Read what came back into the shape `portal::classify` takes. Anything that is not an HTTP reply
/// becomes a status of 0, which classifies as `Inconclusive`: it answered, but not as a web server.
pub fn parse_response(bytes: &[u8]) -> Response {
    let head_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| (at, at + 4));
    let (head, body) = match head_end {
        Some((at, body_at)) => (&bytes[..at], &bytes[body_at..]),
        // No blank line: the head never finished (cut off, or not HTTP). Nothing of it is a body.
        None => (bytes, &[][..]),
    };
    let head = String::from_utf8_lossy(&head[..head.len().min(MAX_HEAD)]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| {
            let mut parts = line.split(' ');
            match (parts.next(), parts.next()) {
                (Some(version), Some(code)) if version.starts_with("HTTP/") => code.parse().ok(),
                _ => None,
            }
        })
        .unwrap_or(0);
    let location = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("location")
            .then(|| value.trim().to_owned())
    });
    let body = String::from_utf8_lossy(&body[..body.len().min(MAX_BODY)]).into_owned();
    Response::Http {
        status,
        location,
        body,
    }
}

/// Fetch `probe` from `target`. `NoAnswer` if nothing could be connected to or nothing came back
/// within `timeout`; a reply that is cut off is parsed as far as it got.
pub async fn fetch(target: SocketAddr, probe: Probe, timeout: Duration) -> Response {
    let attempt = async {
        let mut stream = TcpStream::connect(target).await.ok()?;
        stream.write_all(request_for(probe).as_bytes()).await.ok()?;
        let mut received = Vec::new();
        let mut chunk = [0u8; 1024];
        while received.len() < MAX_HEAD + MAX_BODY {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        }
        Some(received)
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Some(bytes)) if !bytes.is_empty() => parse_response(&bytes),
        _ => Response::NoAnswer,
    }
}

/// The two probes' addresses, as the system resolver gives them. `None` for a host that does not
/// resolve: on a network with no working name service the probe cannot be made, which is
/// `Unreachable`, not a portal.
async fn resolve(probe: Probe) -> Option<SocketAddr> {
    let found: Vec<SocketAddr> = tokio::net::lookup_host((probe.host(), 80))
        .await
        .ok()?
        .collect();
    found
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| found.first().copied())
}

/// One reading from both probes at known addresses, combined by `portal::combine`.
pub async fn detect_at(
    connect_test: SocketAddr,
    ncsi: SocketAddr,
    timeout: Duration,
) -> PortalState {
    let (first, second) = tokio::join!(
        fetch(connect_test, Probe::ConnectTest, timeout),
        fetch(ncsi, Probe::Ncsi, timeout)
    );
    combine(
        &classify(Probe::ConnectTest, &first),
        &classify(Probe::Ncsi, &second),
    )
}

/// One reading of the network the machine is on now. Resolving the probe hosts and fetching them
/// share `timeout`, so the whole reading is bounded by it: a caller that waits for this alongside
/// something else (the endpoint reachability check) is never held up longer than that.
pub async fn detect(timeout: Duration) -> PortalState {
    let read = async {
        let (a, b) = tokio::join!(resolve(Probe::ConnectTest), resolve(Probe::Ncsi));
        match (a, b) {
            (Some(a), Some(b)) => detect_at(a, b, timeout).await,
            (Some(a), None) => classify(
                Probe::ConnectTest,
                &fetch(a, Probe::ConnectTest, timeout).await,
            ),
            (None, Some(b)) => classify(Probe::Ncsi, &fetch(b, Probe::Ncsi, timeout).await),
            (None, None) => PortalState::Unreachable,
        }
    };
    // Resolution has no timeout of its own; the whole reading does.
    tokio::time::timeout(timeout, read)
        .await
        .unwrap_or(PortalState::Unreachable)
}

/// What the service believes about a captive portal on the network it is on.
///
/// Two kinds of reading feed it, and they are held to different standards. At **connect**, one reading
/// is enough: the belief is used only to explain a connection that is failing anyway, and "this network
/// wants a login" is the most useful thing to say about one that intercepts. While **connected**, a
/// reading comes only after a failed live check, and `PortalWatch` wants two in a row (or one, once the
/// person has signed in on this network), because one odd reply on a flaky link is not a portal.
#[derive(Debug, Default)]
pub struct PortalMemory {
    watch: PortalWatch,
}

impl PortalMemory {
    /// A connect is starting: what was true of the last network says nothing about this one.
    ///
    /// An interception at connect is taken as confirmed by that one reading, so the watch knows this
    /// network was a portal. When the person signs in and the connection later loses its way because
    /// the portal forgot them, one reading is then enough to say so (US6-3).
    pub fn connecting(&mut self, reading: &PortalState) {
        self.watch.new_network();
        if matches!(reading, PortalState::Intercepted { .. }) {
            // `observe` needs this many in a row to declare a portal; here one reading is the whole
            // evidence there will be, and the second is the same fact.
            let _ = self.watch.observe(reading);
            let _ = self.watch.observe(reading);
        }
    }

    /// A reading taken while connected. Returns what it changed, if anything.
    pub fn observed(&mut self, reading: &PortalState) -> Option<Recognised> {
        self.watch.observe(reading)
    }

    /// Whether the network is believed to be a portal now: `Environment::captive_portal`.
    pub fn is_portal(&self) -> bool {
        self.watch.is_portal()
    }
}

#[cfg(test)]
mod tests;
