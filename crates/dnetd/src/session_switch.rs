//! T157 — move the session to another carrier and make sure it follows (ADR-0008;
//! `docs/research/2026-10-31-solutions.md` §1.3 to 1.5).
//!
//! Three small parts, each testable without the core:
//!
//! - the **control secret and port**: random per run, loopback only. The pinned core's control API has no Host
//!   check, listens on TCP only, and an empty secret switches authentication off, so the secret is the protection
//!   and it is never shorter than `dnet_config::session::MIN_CONTROL_SECRET_LEN`;
//! - [`ControlClient`], the one request the service makes of that API (`PUT /proxies/<selector>` with the leaf to
//!   use), written by hand so no HTTP library comes near a secret and the reply is read with a bound;
//! - the **nudge**: right after a switch the far end keeps sending to the old path until it hears from the new
//!   one, so small connection attempts go through the session every 250 ms until one succeeds or five seconds
//!   pass. Measured on the pinned core (`testing/spike-carrier`): without it the largest stall was 12.6 s, with it
//!   0.02 s for a planned switch.
//!
//! **Not wired yet.** Nothing starts a session until the server profile (T158) and the per-device credentials
//! (T159) exist, so this module is used only by its tests.
//!
//! **Required before wiring (security review, 2026-11-01).** [`pick_control_port`] returns a port that is free
//! now; the core binds it a moment later. Another local program could bind it in between (on Windows a second
//! bind can succeed when the other program asks for address reuse), and [`ControlClient`] would send the
//! secret to it. So the caller must first confirm that the process listening on the port is the core it started
//! (the owning process id from `GetExtendedTcpTable` equals the core's), and only then call `select`. Classifying the two benign "closed pipe" log lines each
//! switch writes belongs to the Registry.

#![allow(dead_code)] // wired by T158/T159; see above

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use dnet_config::secret::Secret;
use dnet_config::session::{CarrierKind, CARRIER_TAG, MIN_CONTROL_SECRET_LEN};
use dnet_core::origin::Origin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep_until, timeout, Instant};
use zeroize::Zeroizing;

/// The longest one request to the control API may take, from connecting to the first line of the reply.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// The most of a reply that is read. The first line is all that is used; a core that never ends it is refused.
const MAX_REPLY: usize = 4096;
/// The longest tag accepted. Tags come from the generator (`hy2`, `reality`, `carrier`), never from outside, but
/// they are put into a request line, so they are checked anyway.
const MAX_TAG: usize = 32;
/// How long one nudge attempt may take. Short on purpose: an attempt sends its packets at once whether or not it
/// completes, and a long wait would destroy the cadence.
const NUDGE_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(300);

/// Why a switch did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwitchError {
    /// A tag was empty, too long, or held something other than letters, digits, `-` and `_`.
    #[error("the carrier name is not usable")]
    BadTag,
    /// The secret was shorter than the minimum or held a character that cannot go in a header.
    #[error("the control secret is not usable")]
    BadSecret,
    #[error("the control port is zero")]
    BadPort,
    #[error("the operating system gave no randomness")]
    NoRandomness,
    #[error("the control API did not answer in time")]
    Timeout,
    #[error("the control API could not be reached ({0:?})")]
    Unreachable(std::io::ErrorKind),
    #[error("the control API refused the secret")]
    Unauthorized,
    #[error("the control API refused the switch (status {0})")]
    Refused(u16),
    #[error("the control API gave a reply that could not be read")]
    BadReply,
}

/// The control secret as the service holds it.
///
/// `dnet_config::secret::Secret` is for credentials that reach a core's configuration file and nowhere else, and
/// only that crate can read its text. The service must also put this one secret in a request header, so it keeps
/// its own wrapper with the same properties: wiped when dropped, never printed, and checked once when made. It
/// gives the configuration generator a `Secret` through [`ControlSecret::for_config`].
#[derive(Clone)]
pub struct ControlSecret(Zeroizing<String>);

impl ControlSecret {
    /// A secret from text: at least [`MIN_CONTROL_SECRET_LEN`] characters, all printable ASCII without spaces
    /// (so it can go in a header and in a JSON string unchanged).
    pub fn new(text: impl Into<String>) -> Result<Self, SwitchError> {
        let text = Zeroizing::new(text.into());
        if text.len() < MIN_CONTROL_SECRET_LEN || !text.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SwitchError::BadSecret);
        }
        Ok(Self(text))
    }

    /// A fresh secret: 32 random bytes as 64 hexadecimal characters. Made once per run.
    pub fn generate() -> Result<Self, SwitchError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| SwitchError::NoRandomness)?;
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in bytes.iter() {
            text.push_str(&format!("{byte:02x}"));
        }
        Self::new(text.as_str())
    }

    /// The same secret for the configuration generator, which writes it to the core's restricted file.
    pub fn for_config(&self) -> Secret {
        Secret::new(self.0.as_str())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ControlSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlSecret(<redacted>)")
    }
}

impl fmt::Display for ControlSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A loopback port nothing is using at this moment. The core binds it a moment later, so another program could
/// take it in between; the caller then picks again when the core fails to start.
pub fn pick_control_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// The client for the core's control API. It connects to the loopback address and to nothing else.
#[derive(Clone)]
pub struct ControlClient {
    port: u16,
    secret: ControlSecret,
}

impl fmt::Debug for ControlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ControlClient {{ port: {}, secret: <redacted> }}",
            self.port
        )
    }
}

impl ControlClient {
    pub fn new(port: u16, secret: ControlSecret) -> Result<Self, SwitchError> {
        if port == 0 {
            return Err(SwitchError::BadPort);
        }
        Ok(Self { port, secret })
    }

    /// Make the selector `selector` use the leaf `leaf`. A reply in the 200s is success.
    pub async fn select(&self, selector: &str, leaf: &str) -> Result<(), SwitchError> {
        check_tag(selector)?;
        check_tag(leaf)?;
        timeout(REQUEST_TIMEOUT, self.exchange(selector, leaf))
            .await
            .map_err(|_| SwitchError::Timeout)?
    }

    async fn exchange(&self, selector: &str, leaf: &str) -> Result<(), SwitchError> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|e| SwitchError::Unreachable(e.kind()))?;

        let body = format!("{{\"name\":\"{leaf}\"}}");
        // The request holds the secret, so it is wiped when it goes out of scope.
        let request = Zeroizing::new(format!(
            "PUT /proxies/{selector} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Authorization: Bearer {secret}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {length}\r\n\
             Connection: close\r\n\r\n{body}",
            port = self.port,
            secret = self.secret.as_str(),
            length = body.len(),
        ));
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| SwitchError::Unreachable(e.kind()))?;

        // Only the status line is used. Read until it is complete, but never more than MAX_REPLY.
        let mut reply = Vec::with_capacity(256);
        let mut chunk = [0u8; 256];
        loop {
            if let Some(end) = reply.windows(2).position(|w| w == b"\r\n") {
                return status(&reply[..end]);
            }
            if reply.len() >= MAX_REPLY {
                return Err(SwitchError::BadReply);
            }
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| SwitchError::Unreachable(e.kind()))?;
            if n == 0 {
                return Err(SwitchError::BadReply);
            }
            reply.extend_from_slice(&chunk[..n]);
        }
    }
}

fn check_tag(tag: &str) -> Result<(), SwitchError> {
    let fine = !tag.is_empty()
        && tag.len() <= MAX_TAG
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if fine {
        Ok(())
    } else {
        Err(SwitchError::BadTag)
    }
}

/// `HTTP/1.1 204 No Content` to a result.
fn status(line: &[u8]) -> Result<(), SwitchError> {
    let line = std::str::from_utf8(line).map_err(|_| SwitchError::BadReply)?;
    let mut parts = line.split(' ');
    let version = parts.next().unwrap_or_default();
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(SwitchError::BadReply)?;
    if !version.starts_with("HTTP/1.") {
        return Err(SwitchError::BadReply);
    }
    match code {
        200..=299 => Ok(()),
        401 | 403 => Err(SwitchError::Unauthorized),
        other => Err(SwitchError::Refused(other)),
    }
}

/// Something that sends a few packets through the session and says whether they got an answer.
pub trait SessionProbe {
    async fn attempt(&self) -> bool;
}

/// A connection attempt to the measurement origin, which only the session can reach. The attempt sends its first
/// packet immediately, which is what teaches the far end the new path; it succeeds when the origin answers.
pub struct OriginProbe<'a>(pub &'a Origin);

impl SessionProbe for OriginProbe<'_> {
    async fn attempt(&self) -> bool {
        let target = format!("{}:{}", self.0.host(), self.0.port());
        matches!(
            timeout(NUDGE_ATTEMPT_TIMEOUT, TcpStream::connect(target)).await,
            Ok(Ok(_))
        )
    }
}

/// [`OriginProbe`] that owns its origin, for a task that outlives the call that made it.
pub struct OwnedOriginProbe(pub Origin);

impl SessionProbe for OwnedOriginProbe {
    async fn attempt(&self) -> bool {
        OriginProbe(&self.0).attempt().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NudgePlan {
    /// Between the starts of two attempts.
    pub every: Duration,
    /// After this long without an answer, give up.
    pub within: Duration,
}

impl Default for NudgePlan {
    fn default() -> Self {
        Self {
            every: Duration::from_millis(250),
            within: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NudgeOutcome {
    /// The session answered `after` the first attempt, on the `attempts`th.
    Recovered { attempts: u32, after: Duration },
    /// Nothing answered within the plan.
    GaveUp { attempts: u32 },
}

/// Attempt at once, then on a fixed schedule (so a slow attempt does not stretch the window), until one answers
/// or the plan's time is up.
pub async fn nudge(probe: &impl SessionProbe, plan: NudgePlan) -> NudgeOutcome {
    let start = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if probe.attempt().await {
            return NudgeOutcome::Recovered {
                attempts,
                after: start.elapsed(),
            };
        }
        let next = start + plan.every * attempts;
        if next >= start + plan.within || Instant::now() >= start + plan.within {
            return NudgeOutcome::GaveUp { attempts };
        }
        sleep_until(next).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchReport {
    pub to: String,
    pub nudge: NudgeOutcome,
}

/// Switch, then nudge. A switch that did not happen is not followed by a nudge.
pub async fn switch_carrier(
    api: &ControlClient,
    probe: &impl SessionProbe,
    selector: &str,
    leaf: &str,
    plan: NudgePlan,
) -> Result<SwitchReport, SwitchError> {
    api.select(selector, leaf).await?;
    let nudge = nudge(probe, plan).await;
    tracing::info!(
        to = leaf,
        ?nudge,
        "the session was moved to another carrier"
    );
    Ok(SwitchReport {
        to: leaf.to_string(),
        nudge,
    })
}

/// [`switch_carrier`] for the generator's own names.
pub async fn switch_to(
    api: &ControlClient,
    probe: &impl SessionProbe,
    kind: CarrierKind,
    plan: NudgePlan,
) -> Result<SwitchReport, SwitchError> {
    switch_carrier(api, probe, CARRIER_TAG, kind.tag(), plan).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    // ------------------------------------------------------------------ a stand-in for the core's control API

    enum Reply {
        Line(&'static str),
        Silent,
        Endless,
    }

    struct FakeCore {
        port: u16,
        requests: Arc<Mutex<Vec<String>>>,
        connections: Arc<AtomicUsize>,
    }

    async fn fake_core(reply: Reply) -> FakeCore {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (seen, count) = (requests.clone(), connections.clone());
        let reply = Arc::new(reply);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let (seen, reply) = (seen.clone(), reply.clone());
                tokio::spawn(async move {
                    // The request: headers, then as many body bytes as Content-Length says.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 512];
                    loop {
                        let n = stream.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(head_end) = text.find("\r\n\r\n") {
                            let length = text
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length: "))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if buf.len() >= head_end + 4 + length {
                                break;
                            }
                        }
                    }
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf).to_string());
                    match &*reply {
                        Reply::Line(line) => {
                            let _ = stream.write_all(line.as_bytes()).await;
                        }
                        Reply::Silent => std::future::pending::<()>().await,
                        Reply::Endless => loop {
                            if stream.write_all(&[b'x'; 512]).await.is_err() {
                                break;
                            }
                        },
                    }
                });
            }
        });
        FakeCore {
            port,
            requests,
            connections,
        }
    }

    fn secret() -> ControlSecret {
        ControlSecret::new("s".repeat(64)).unwrap()
    }

    fn client(core: &FakeCore) -> ControlClient {
        ControlClient::new(core.port, secret()).unwrap()
    }

    // ------------------------------------------------------------------ the request

    #[tokio::test]
    async fn the_switch_is_exactly_the_request_the_core_expects() {
        let core = fake_core(Reply::Line("HTTP/1.1 204 No Content\r\n\r\n")).await;
        client(&core).select("carrier", "reality").await.unwrap();
        let request = core.requests.lock().unwrap()[0].clone();
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next(), Some("PUT /proxies/carrier HTTP/1.1"));
        assert!(request.contains(&format!("Host: 127.0.0.1:{}\r\n", core.port)));
        assert!(request.contains(&format!("Authorization: Bearer {}\r\n", "s".repeat(64))));
        assert!(request.contains("Content-Type: application/json\r\n"));
        let body = "{\"name\":\"reality\"}";
        assert!(request.ends_with(&format!("\r\n\r\n{body}")));
        assert!(request.contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    #[tokio::test]
    async fn replies_are_told_apart() {
        for (line, expected) in [
            ("HTTP/1.1 204 No Content\r\n\r\n", Ok(())),
            ("HTTP/1.1 200 OK\r\n\r\n", Ok(())),
            (
                "HTTP/1.1 401 Unauthorized\r\n\r\n",
                Err(SwitchError::Unauthorized),
            ),
            (
                "HTTP/1.1 403 Forbidden\r\n\r\n",
                Err(SwitchError::Unauthorized),
            ),
            (
                "HTTP/1.1 400 Bad Request\r\n\r\n",
                Err(SwitchError::Refused(400)),
            ),
            (
                "HTTP/1.1 500 Internal Server Error\r\n\r\n",
                Err(SwitchError::Refused(500)),
            ),
            ("gibberish\r\n\r\n", Err(SwitchError::BadReply)),
            ("HTTP/1.1 abc\r\n\r\n", Err(SwitchError::BadReply)),
            ("SPDY/3 200 OK\r\n\r\n", Err(SwitchError::BadReply)),
        ] {
            let core = fake_core(Reply::Line(line)).await;
            assert_eq!(
                client(&core).select("carrier", "hy2").await,
                expected,
                "{line:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_tag_that_could_change_the_request_is_refused_before_connecting() {
        let core = fake_core(Reply::Line("HTTP/1.1 204 No Content\r\n\r\n")).await;
        let api = client(&core);
        let long = "x".repeat(MAX_TAG + 1);
        for bad in [
            "",
            "a b",
            "a/b",
            "a\r\nX-Injected: 1",
            "carrier?x=1",
            "..",
            "naïve",
            long.as_str(),
        ] {
            assert_eq!(
                api.select(bad, "hy2").await,
                Err(SwitchError::BadTag),
                "{bad:?}"
            );
            assert_eq!(
                api.select("carrier", bad).await,
                Err(SwitchError::BadTag),
                "{bad:?}"
            );
        }
        assert_eq!(core.connections.load(Ordering::SeqCst), 0, "it connected");
    }

    #[tokio::test]
    async fn an_unreachable_core_is_an_error_not_a_hang() {
        let port = pick_control_port().unwrap();
        let api = ControlClient::new(port, secret()).unwrap();
        assert!(matches!(
            api.select("carrier", "hy2").await,
            Err(SwitchError::Unreachable(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_core_that_never_answers_times_out() {
        let core = fake_core(Reply::Silent).await;
        assert_eq!(
            client(&core).select("carrier", "hy2").await,
            Err(SwitchError::Timeout)
        );
    }

    #[tokio::test]
    async fn a_reply_that_never_ends_its_first_line_is_refused() {
        let core = fake_core(Reply::Endless).await;
        assert_eq!(
            client(&core).select("carrier", "hy2").await,
            Err(SwitchError::BadReply)
        );
    }

    #[tokio::test]
    async fn the_secret_never_reaches_an_error_or_debug_output() {
        let core = fake_core(Reply::Line("HTTP/1.1 401 Unauthorized\r\n\r\n")).await;
        let api = client(&core);
        let error = api.select("carrier", "hy2").await.unwrap_err();
        let shown = format!("{error} {error:?} {api:?}");
        assert!(!shown.contains(&"s".repeat(16)), "{shown}");
        assert!(format!("{api:?}").contains("redacted"));
        let s = secret();
        assert!(!format!("{s:?}{s}").contains(&"s".repeat(16)));
        // The configuration generator's copy prints nothing either.
        assert!(!format!("{:?}", s.for_config()).contains(&"s".repeat(16)));
    }

    #[test]
    fn a_weak_or_unusable_secret_is_refused_and_so_is_port_zero() {
        for text in [
            String::new(),
            "s".repeat(MIN_CONTROL_SECRET_LEN - 1),
            format!("{} {}", "s".repeat(20), "s".repeat(20)),
            format!("{}\r\nX: y", "s".repeat(40)),
            format!("{}é", "s".repeat(40)),
        ] {
            assert_eq!(
                ControlSecret::new(text).unwrap_err(),
                SwitchError::BadSecret
            );
        }
        assert!(ControlSecret::new("s".repeat(MIN_CONTROL_SECRET_LEN)).is_ok());
        assert_eq!(
            ControlClient::new(0, secret()).unwrap_err(),
            SwitchError::BadPort
        );
    }

    #[test]
    fn the_secret_is_long_random_and_new_every_time() {
        let (a, b) = (
            ControlSecret::generate().unwrap(),
            ControlSecret::generate().unwrap(),
        );
        assert_eq!(a.as_str().len(), 64);
        assert!(a.as_str().bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.as_str(), b.as_str());
        assert!(a.as_str().len() >= MIN_CONTROL_SECRET_LEN);
        assert!(ControlClient::new(29090, a).is_ok());
    }

    #[test]
    fn what_the_generator_writes_is_what_the_client_sends() {
        // The core is configured with `for_config` and the client authenticates with the same text.
        let s = ControlSecret::generate().unwrap();
        let written = serde_json::to_string(&s.for_config()).unwrap();
        assert_eq!(written, format!("\"{}\"", s.as_str()));
        assert!(s.for_config() == Secret::new(s.as_str()));
    }

    #[test]
    fn a_control_port_is_a_free_loopback_port() {
        let port = pick_control_port().unwrap();
        assert_ne!(port, 0);
        // Nothing listens there now.
        assert!(std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }

    // ------------------------------------------------------------------ the nudge

    /// A probe that answers on a given attempt, and takes `each` to say so.
    struct Scripted {
        succeed_on: Option<u32>,
        each: Duration,
        calls: AtomicU32,
    }

    impl Scripted {
        fn new(succeed_on: Option<u32>, each: Duration) -> Self {
            Self {
                succeed_on,
                each,
                calls: AtomicU32::new(0),
            }
        }
    }

    impl SessionProbe for Scripted {
        async fn attempt(&self) -> bool {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if !self.each.is_zero() {
                tokio::time::sleep(self.each).await;
            }
            self.succeed_on == Some(n)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_at_once_ends_the_nudge_at_once() {
        let probe = Scripted::new(Some(1), Duration::ZERO);
        assert_eq!(
            nudge(&probe, NudgePlan::default()).await,
            NudgeOutcome::Recovered {
                attempts: 1,
                after: Duration::ZERO
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_go_every_quarter_second_until_one_answers() {
        let probe = Scripted::new(Some(4), Duration::ZERO);
        assert_eq!(
            nudge(&probe, NudgePlan::default()).await,
            NudgeOutcome::Recovered {
                attempts: 4,
                after: Duration::from_millis(750)
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_nudge_gives_up_after_five_seconds() {
        let probe = Scripted::new(None, Duration::ZERO);
        let start = Instant::now();
        let outcome = nudge(&probe, NudgePlan::default()).await;
        // Attempts at 0, 0.25, ... 4.75 seconds.
        assert_eq!(outcome, NudgeOutcome::GaveUp { attempts: 20 });
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(5) - Duration::from_millis(250)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_attempt_does_not_stretch_the_window() {
        let probe = Scripted::new(None, Duration::from_millis(400));
        let start = Instant::now();
        let outcome = nudge(&probe, NudgePlan::default()).await;
        assert_eq!(outcome, NudgeOutcome::GaveUp { attempts: 13 });
        // The last attempt began before the five seconds were up and may finish after.
        assert!(start.elapsed() < Duration::from_secs(5) + Duration::from_millis(400));
    }

    #[tokio::test]
    async fn the_real_probe_succeeds_against_a_listening_origin_and_fails_without_one() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.is_ok() });
        assert!(OriginProbe(&origin).attempt().await);
        assert!(accepted.await.unwrap());
        // The listener is gone; nothing answers now.
        let silent = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        assert!(!OriginProbe(&silent).attempt().await);
    }

    // ------------------------------------------------------------------ the switch

    /// A probe that records whether the core had already been told to switch when it was first used.
    struct AfterSwitch {
        core_requests: Arc<Mutex<Vec<String>>>,
        saw_request_first: AtomicBool,
        calls: AtomicU32,
    }

    impl SessionProbe for AfterSwitch {
        async fn attempt(&self) -> bool {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.saw_request_first.store(
                    !self.core_requests.lock().unwrap().is_empty(),
                    Ordering::SeqCst,
                );
            }
            true
        }
    }

    #[tokio::test]
    async fn the_core_is_told_first_and_only_then_is_the_session_nudged() {
        let core = fake_core(Reply::Line("HTTP/1.1 204 No Content\r\n\r\n")).await;
        let probe = AfterSwitch {
            core_requests: core.requests.clone(),
            saw_request_first: AtomicBool::new(false),
            calls: AtomicU32::new(0),
        };
        let report = switch_to(
            &client(&core),
            &probe,
            CarrierKind::Reality,
            NudgePlan::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.to, "reality");
        assert!(matches!(
            report.nudge,
            NudgeOutcome::Recovered { attempts: 1, .. }
        ));
        assert!(probe.saw_request_first.load(Ordering::SeqCst));
        assert!(core.requests.lock().unwrap()[0].starts_with("PUT /proxies/carrier "));
    }

    #[tokio::test]
    async fn a_switch_that_failed_is_not_followed_by_a_nudge() {
        let core = fake_core(Reply::Line("HTTP/1.1 400 Bad Request\r\n\r\n")).await;
        let probe = Scripted::new(Some(1), Duration::ZERO);
        let result = switch_to(
            &client(&core),
            &probe,
            CarrierKind::Hysteria2,
            NudgePlan::default(),
        )
        .await;
        assert_eq!(result, Err(SwitchError::Refused(400)));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0, "it nudged anyway");
    }

    /// Real clock and a short plan: this test makes a real connection, and a paused clock jumps over the request
    /// timeout while the connection is still being made.
    #[tokio::test]
    async fn a_session_that_does_not_come_back_is_reported_not_hidden() {
        let core = fake_core(Reply::Line("HTTP/1.1 204 No Content\r\n\r\n")).await;
        let probe = Scripted::new(None, Duration::ZERO);
        let plan = NudgePlan {
            every: Duration::from_millis(10),
            within: Duration::from_millis(100),
        };
        let report = switch_to(&client(&core), &probe, CarrierKind::Reality, plan)
            .await
            .unwrap();
        assert!(matches!(report.nudge, NudgeOutcome::GaveUp { attempts } if attempts >= 2));
        assert_eq!(report.to, "reality");
    }

    // ------------------------------------------------------------------ against the real core

    /// A stand-in only proves the client matches our idea of the API. This starts the **vendored core** with a
    /// selector over two leaves and the control API (no tunnel, so no privilege), switches with the real client,
    /// and reads back which leaf the core reports. Skipped, loudly, where the core has not been fetched.
    #[tokio::test]
    async fn the_real_core_follows_the_switch_and_refuses_a_wrong_secret() {
        let exe = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/primary-core/primary-core.exe");
        if !(cfg!(windows) && exe.is_file()) {
            eprintln!(
                "SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)"
            );
            return;
        }
        let secret = ControlSecret::generate().unwrap();
        let port = pick_control_port().unwrap();
        let config = serde_json::json!({
            "log": {"level": "warn"},
            "outbounds": [
                {"type": "direct", "tag": "hy2"},
                {"type": "direct", "tag": "reality"},
                {"type": "selector", "tag": CARRIER_TAG, "outbounds": ["hy2", "reality"],
                 "default": "hy2", "interrupt_exist_connections": false}
            ],
            "experimental": {"clash_api": {
                "external_controller": format!("127.0.0.1:{port}"),
                "secret": secret.as_str(),
                "access_control_allow_origin": [dnet_config::session::CONTROL_ORIGIN]
            }}
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.json");
        std::fs::write(&path, config.to_string()).unwrap();
        let mut core = std::process::Command::new(&exe)
            .args(["run", "-c"])
            .arg(&path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("starting the vendored core");
        // Kill the core however the test ends.
        struct Kill(std::process::Child);
        impl Drop for Kill {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = Kill(core.try_wait().ok().flatten().map_or_else(
            || core,
            |status| panic!("the core exited at once: {status}"),
        ));

        // Wait for the API to listen.
        let mut up = false;
        for _ in 0..100 {
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(up, "the core's control API never started listening");

        let api = ControlClient::new(port, secret.clone()).unwrap();
        assert_eq!(now_selected(port, &secret).await, "hy2");
        api.select(CARRIER_TAG, "reality").await.unwrap();
        assert_eq!(now_selected(port, &secret).await, "reality");
        api.select(CARRIER_TAG, "hy2").await.unwrap();
        assert_eq!(now_selected(port, &secret).await, "hy2");

        // A leaf the selector does not have is refused by the core, and says so.
        let result = api.select(CARRIER_TAG, "nonesuch").await;
        assert!(matches!(result, Err(SwitchError::Refused(_))), "{result:?}");
        assert_eq!(now_selected(port, &secret).await, "hy2");

        // The wrong secret is refused, and the selection is unchanged.
        let wrong = ControlClient::new(port, ControlSecret::generate().unwrap()).unwrap();
        assert_eq!(
            wrong.select(CARRIER_TAG, "reality").await,
            Err(SwitchError::Unauthorized)
        );
        assert_eq!(now_selected(port, &secret).await, "hy2");
    }

    /// Ask the real core which leaf the selector uses (`GET /proxies/<selector>`, field `now`).
    async fn now_selected(port: u16, secret: &ControlSecret) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = format!(
            "GET /proxies/{CARRIER_TAG} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            secret.as_str()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        let text = String::from_utf8_lossy(&reply).to_string();
        let body = text.split("\r\n\r\n").nth(1).expect("a reply body");
        let json: serde_json::Value = serde_json::from_str(body.trim()).expect("a JSON body");
        json["now"].as_str().expect("a `now` field").to_string()
    }

    // ------------------------------------------------------------------ what the mutation run showed was not pinned

    #[test]
    fn the_control_secret_prints_as_redacted_in_every_form_and_never_as_itself() {
        let secret = ControlSecret::new("s3cret-value-".repeat(5)).unwrap();
        assert_eq!(format!("{secret:?}"), "ControlSecret(<redacted>)");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert_eq!(format!("{secret:#?}"), "ControlSecret(<redacted>)");
        for shown in [format!("{secret:?}"), secret.to_string()] {
            assert!(!shown.contains("s3cret"), "{shown}");
        }
    }

    #[test]
    fn the_control_port_is_a_real_unused_loopback_port_that_can_be_bound_straight_away() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let port = pick_control_port().unwrap();
            assert!(port >= 1024, "{port} is a privileged or reserved port");
            // Nothing is using it: it can be bound right now, which is what the core does a moment later.
            let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port));
            assert!(taken.is_ok(), "port {port} was not free");
            seen.insert(port);
        }
        assert!(
            seen.len() > 1,
            "eight picks were all the same port: {seen:?}"
        );
    }

    #[test]
    fn a_tag_is_letters_digits_dashes_and_underscores_up_to_the_limit_and_nothing_else() {
        for good in [
            "a",
            "A9",
            "hy2-main",
            "reality_1",
            "a-b_c",
            &"x".repeat(MAX_TAG),
        ] {
            assert!(check_tag(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "a b",
            "a/b",
            "a.b",
            "a:b",
            "a\nb",
            "é",
            "a\0b",
            "../x",
            &"x".repeat(MAX_TAG + 1),
        ] {
            assert!(
                matches!(check_tag(bad), Err(SwitchError::BadTag)),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_owned_probe_says_yes_for_an_origin_that_answers_and_no_for_one_that_does_not() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let answering =
            OwnedOriginProbe(Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap());
        assert!(answering.attempt().await);
        drop(listener);
        let closed = OwnedOriginProbe(Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap());
        assert!(!closed.attempt().await, "nothing listens there now");
    }
}
