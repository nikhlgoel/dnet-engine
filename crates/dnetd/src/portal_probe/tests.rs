// SPDX-License-Identifier: GPL-3.0-or-later
//! The probe against a local listener standing in for whatever the network does. No real network.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

const SHORT: Duration = Duration::from_millis(400);

/// A listener that answers every connection with `reply` and records what it was asked.
async fn serve(reply: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&asked);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (reply, log) = (reply.clone(), Arc::clone(&log));
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).into_owned());
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, asked)
}

fn http(status: &str, headers: &[&str], body: &str) -> Vec<u8> {
    let mut text = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        text.push_str(header);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    text.push_str(body);
    text.into_bytes()
}

async fn read(reply: Vec<u8>, probe: Probe) -> PortalState {
    let (address, _) = serve(reply).await;
    classify(probe, &fetch(address, probe, SHORT).await)
}

// ------------------------------------------------------------------ what each kind of network does

#[tokio::test]
async fn an_unchanged_page_is_an_open_network() {
    for probe in [Probe::ConnectTest, Probe::Ncsi] {
        let reply = http(
            "200 OK",
            &["Content-Type: text/plain"],
            probe.expected_body(),
        );
        assert_eq!(read(reply, probe).await, PortalState::Open, "{probe:?}");
    }
}

#[tokio::test]
async fn a_redirect_is_a_portal_and_its_login_address_is_kept_but_not_followed() {
    // The redirect points at a second listener. If the probe followed it, that listener would hear.
    let (login, heard) = serve(http("200 OK", &[], "sign in here")).await;
    let to = format!("http://{login}/login");
    let reply = http(
        "302 Found",
        &[&format!("Location: {to}"), "Content-Length: 0"],
        "",
    );

    let state = read(reply, Probe::ConnectTest).await;

    assert_eq!(state, PortalState::Intercepted { login: Some(to) });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        heard.lock().unwrap().is_empty(),
        "the login address is for the person's browser; it is never requested here"
    );
}

#[tokio::test]
async fn a_header_name_is_matched_whatever_its_case() {
    let reply = http("302 Found", &["lOcAtIoN: http://portal.example/login"], "");
    assert_eq!(
        read(reply, Probe::Ncsi).await,
        PortalState::Intercepted {
            login: Some("http://portal.example/login".into())
        }
    );
}

#[tokio::test]
async fn a_login_address_that_is_not_plain_http_is_not_offered() {
    for hostile in [
        "javascript:alert(1)",
        "file:///c:/windows/system32",
        "http://user:pass@portal.example/",
        "http://portal.example/a b",
    ] {
        let reply = http("302 Found", &[&format!("Location: {hostile}")], "");
        assert_eq!(
            read(reply, Probe::ConnectTest).await,
            PortalState::Intercepted { login: None },
            "{hostile}"
        );
    }
}

#[tokio::test]
async fn a_page_served_in_place_of_the_probe_is_a_portal_without_a_login_address() {
    let reply = http(
        "200 OK",
        &["Content-Type: text/html"],
        "<html>Welcome. Sign in.</html>",
    );
    assert_eq!(
        read(reply, Probe::ConnectTest).await,
        PortalState::Intercepted { login: None }
    );
}

#[tokio::test]
async fn nothing_listening_is_an_unreachable_network_not_a_portal() {
    let address = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    assert_eq!(
        classify(
            Probe::ConnectTest,
            &fetch(address, Probe::ConnectTest, SHORT).await
        ),
        PortalState::Unreachable
    );
}

#[tokio::test]
async fn a_server_that_never_answers_is_given_up_on() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let started = std::time::Instant::now();
    assert_eq!(fetch(address, Probe::Ncsi, SHORT).await, Response::NoAnswer);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn bytes_that_are_not_http_prove_nothing() {
    for junk in [
        b"SSH-2.0-OpenSSH_9.0\r\n".to_vec(),
        vec![0u8, 159, 146, 150, 255, 254],
        b"HTTP/1.1 999 Nonsense\r\n\r\n".to_vec(),
        b"HTTP/1.1 abc\r\n\r\n".to_vec(),
        // A valid code and the very page that was asked for, from something that is not a web server.
        b"ICY 200 OK\r\n\r\nMicrosoft Connect Test".to_vec(),
    ] {
        assert_eq!(
            read(junk.clone(), Probe::ConnectTest).await,
            PortalState::Inconclusive,
            "{junk:?}"
        );
    }
}

#[tokio::test]
async fn a_reply_without_a_body_is_not_the_expected_page() {
    let state = read(http("204 No Content", &[], ""), Probe::ConnectTest).await;
    assert_eq!(state, PortalState::Inconclusive);
}

// ------------------------------------------------------------------ bounds

#[tokio::test]
async fn an_enormous_reply_is_cut_off_not_read_whole() {
    let reply = http("200 OK", &[], &"x".repeat(2 * 1024 * 1024));
    let (address, _) = serve(reply).await;
    match fetch(address, Probe::ConnectTest, SHORT).await {
        Response::Http { status, body, .. } => {
            assert_eq!(status, 200);
            assert!(body.len() <= MAX_BODY, "{} bytes kept", body.len());
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_reply_that_never_ends_is_cut_off_not_waited_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut ignored = [0u8; 512];
        let _ = stream.read(&mut ignored).await;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        // Then keep talking, without ever finishing.
        let filler = [b'x'; 4096];
        while stream.write_all(&filler).await.is_ok() {}
    });
    // Within the time allowed it answers, from what it read before the limit, rather than reading on.
    match fetch(address, Probe::ConnectTest, Duration::from_secs(5)).await {
        Response::Http { status, body, .. } => {
            assert_eq!(status, 200);
            assert!(body.len() <= MAX_BODY);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_head_that_never_ends_is_not_mistaken_for_a_body() {
    let mut endless = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
    endless.extend(std::iter::repeat_n(b'a', 100_000));
    match parse_response(&endless) {
        Response::Http { body, .. } => assert!(body.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn no_cut_off_of_a_real_reply_panics_or_misreads_it_as_open() {
    let whole = http(
        "302 Found",
        &["Location: http://portal.example/login", "Content-Length: 0"],
        "body",
    );
    for end in 0..=whole.len() {
        let state = classify(Probe::ConnectTest, &parse_response(&whole[..end]));
        assert_ne!(state, PortalState::Open, "cut at {end}");
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    // A cheap stand-in for a fuzzer: every byte value in every position of a short head.
    let template = b"HTTP/1.1 302 Found\r\nLocation: x\r\n\r\nb";
    for at in 0..template.len() {
        for byte in 0..=255u8 {
            let mut bytes = template.to_vec();
            bytes[at] = byte;
            let _ = parse_response(&bytes);
        }
    }
    let _ = parse_response(&[]);
}

// ------------------------------------------------------------------ the request

#[tokio::test]
async fn the_request_names_only_the_fixed_page_and_carries_nothing_about_the_person() {
    for probe in [Probe::ConnectTest, Probe::Ncsi] {
        let (address, asked) = serve(http("200 OK", &[], probe.expected_body())).await;
        fetch(address, probe, SHORT).await;
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0], request_for(probe));
        let lower = asked[0].to_ascii_lowercase();
        for forbidden in ["cookie", "authorization", "x-forwarded", "referer"] {
            assert!(!lower.contains(forbidden), "{forbidden}: {lower}");
        }
        assert!(asked[0].starts_with(&format!("GET {} HTTP/1.1\r\n", probe.path())));
        assert!(asked[0].contains(&format!("Host: {}\r\n", probe.host())));
    }
}

// ------------------------------------------------------------------ the two probes together

#[tokio::test]
async fn a_portal_that_lets_one_probe_host_through_is_still_an_open_network() {
    // Some portals whitelist one of the operating system's two probe hosts; the other still intercepts.
    let (open_connect_test, _) =
        serve(http("200 OK", &[], Probe::ConnectTest.expected_body())).await;
    let (open_ncsi, _) = serve(http("200 OK", &[], Probe::Ncsi.expected_body())).await;
    let (portal, _) = serve(http("302 Found", &["Location: http://p.example/"], "")).await;
    // Either probe may be the one that gets through.
    assert_eq!(
        detect_at(open_connect_test, portal, SHORT).await,
        PortalState::Open
    );
    assert_eq!(detect_at(portal, open_ncsi, SHORT).await, PortalState::Open);
}

#[tokio::test]
async fn two_intercepted_probes_are_a_portal_and_keep_a_login_address() {
    let (a, _) = serve(http("200 OK", &[], "<html>login</html>")).await;
    let (b, _) = serve(http("302 Found", &["Location: http://p.example/login"], "")).await;
    assert_eq!(
        detect_at(a, b, SHORT).await,
        PortalState::Intercepted {
            login: Some("http://p.example/login".into())
        }
    );
}

#[tokio::test]
async fn two_dead_probes_are_an_unreachable_network() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    assert_eq!(detect_at(dead, dead, SHORT).await, PortalState::Unreachable);
}

// ------------------------------------------------------------------ what the service believes

fn intercepted() -> PortalState {
    PortalState::Intercepted { login: None }
}

#[test]
fn one_intercepted_reading_at_connect_is_believed() {
    let mut memory = PortalMemory::default();
    memory.connecting(&intercepted());
    assert!(memory.is_portal());
}

#[test]
fn nothing_else_at_connect_is_a_portal() {
    for reading in [
        PortalState::Open,
        PortalState::Unreachable,
        PortalState::Inconclusive,
    ] {
        let mut memory = PortalMemory::default();
        memory.connecting(&reading);
        assert!(!memory.is_portal(), "{reading:?}");
    }
}

#[test]
fn a_new_connect_forgets_the_last_network() {
    let mut memory = PortalMemory::default();
    memory.connecting(&intercepted());
    memory.connecting(&PortalState::Open);
    assert!(!memory.is_portal());
}

#[test]
fn while_connected_one_odd_reading_is_not_a_portal_but_two_in_a_row_are() {
    let mut memory = PortalMemory::default();
    memory.connecting(&PortalState::Open);
    assert_eq!(memory.observed(&intercepted()), None);
    assert!(!memory.is_portal(), "a flaky link can truncate one reply");
    assert!(memory.observed(&intercepted()).is_some());
    assert!(memory.is_portal());
}

#[test]
fn an_unchanged_page_clears_a_portal_believed_at_connect() {
    let mut memory = PortalMemory::default();
    memory.connecting(&intercepted());
    let _ = memory.observed(&PortalState::Open);
    assert!(!memory.is_portal());
}

#[test]
fn a_dead_network_neither_makes_nor_clears_a_portal() {
    let mut memory = PortalMemory::default();
    memory.connecting(&intercepted());
    let _ = memory.observed(&PortalState::Unreachable);
    assert!(
        memory.is_portal(),
        "a portal that stops answering is still the portal"
    );

    let mut memory = PortalMemory::default();
    memory.connecting(&PortalState::Open);
    for _ in 0..5 {
        let _ = memory.observed(&PortalState::Unreachable);
    }
    assert!(!memory.is_portal(), "a dead network is not a portal");
}

#[test]
fn a_sign_in_on_one_network_does_not_make_the_next_one_quick_to_be_called_a_portal() {
    let mut memory = PortalMemory::default();
    // Signed in on the first network: a portal, then open.
    memory.connecting(&intercepted());
    assert_eq!(
        memory.observed(&PortalState::Open),
        Some(Recognised::Cleared)
    );
    // A different network: a single odd reading is not yet a portal, as on any new network.
    memory.connecting(&PortalState::Open);
    assert_eq!(memory.observed(&intercepted()), None);
    assert!(!memory.is_portal());
}

#[test]
fn a_portal_that_forgets_a_person_who_signed_in_is_recognised_at_once() {
    // The whole flow of US6-3: a portal at connect, a sign-in, then the portal's session ends.
    let mut memory = PortalMemory::default();
    memory.connecting(&intercepted());
    assert!(memory.is_portal());
    assert_eq!(
        memory.observed(&PortalState::Open),
        Some(Recognised::Cleared)
    );
    assert!(!memory.is_portal());

    // One reading is enough now: this network was open a moment ago.
    assert!(matches!(
        memory.observed(&intercepted()),
        Some(Recognised::SessionExpired { .. })
    ));
    assert!(memory.is_portal());
}

// ------------------------------------------------------------------ the limits, pinned

#[test]
fn the_limits_are_eight_kibibytes_of_head_and_half_a_kibibyte_of_body() {
    assert_eq!(MAX_HEAD, 8_192);
    assert_eq!(MAX_BODY, 512);
}

/// A connection that is opened and closed without a word proves nothing: no answer, not a reply that says nothing.
#[tokio::test]
async fn a_connection_that_closes_without_a_word_is_no_answer() {
    let (address, _) = serve(Vec::new()).await;
    assert_eq!(
        fetch(address, Probe::ConnectTest, SHORT).await,
        Response::NoAnswer
    );
    assert_eq!(
        classify(Probe::ConnectTest, &Response::NoAnswer),
        PortalState::Unreachable
    );
}

/// A long head (many headers) followed by the real page is still read as the real page: the read goes on past the
/// head to the body, up to the limit of both together.
#[tokio::test]
async fn a_long_head_followed_by_the_expected_page_is_still_the_expected_page() {
    let filler: Vec<String> = (0..138)
        .map(|i| format!("X-Padding-{i}: {}", "a".repeat(40)))
        .collect();
    let headers: Vec<&str> = filler.iter().map(String::as_str).collect();
    let reply = http("200 OK", &headers, Probe::ConnectTest.expected_body());
    assert!(
        reply.len() > 7_680 && reply.len() < MAX_HEAD + MAX_BODY,
        "{}",
        reply.len()
    );
    assert_eq!(read(reply, Probe::ConnectTest).await, PortalState::Open);
}

/// A reply that does not stop is read no further than the two limits together (with the one chunk read past it),
/// and the connection is let go.
#[tokio::test]
async fn a_reply_that_never_stops_is_read_only_as_far_as_the_limits_allow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&sent);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request).await;
        let block = [b'x'; 1024];
        while stream.write_all(&block).await.is_ok() {
            counted.fetch_add(block.len(), std::sync::atomic::Ordering::SeqCst);
            if counted.load(std::sync::atomic::Ordering::SeqCst) > 4 * 1024 * 1024 {
                break;
            }
        }
    });
    let _ = fetch(address, Probe::Ncsi, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sent = sent.load(std::sync::atomic::Ordering::SeqCst);
    // The kernel buffers some of what was written after the reader stopped; far less than the four mebibytes that
    // an unbounded read would have taken.
    assert!(
        sent < 2 * 1024 * 1024,
        "{sent} bytes were taken from a reply that does not stop"
    );
}
