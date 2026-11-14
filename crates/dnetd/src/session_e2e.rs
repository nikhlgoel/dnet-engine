// SPDX-License-Identifier: GPL-3.0-or-later
//! T158 — the whole session, composed, on loopback (ADR-0008).
//!
//! Nothing here is a stand-in for the product's own code. The **server** is the configuration the bootstrap
//! script would write (`dnet_provision::bootstrap::script`, its configuration block filled in with real keys
//! and a real certificate) running in the vendored core. The **client** is the configuration
//! `dnet_config::session::generate_session_config` produces, in a second copy of the core. The carriers are the
//! real Hysteria 2 and VLESS+REALITY inbounds and outbounds. The switch and the nudge are `session_switch`'s.
//!
//! What it changes in those configurations, and nothing else, so that it needs no privilege and no network:
//! - the client's tunnel inbound is replaced by a loopback proxy (a tunnel needs administrator rights);
//! - `auto_detect_interface` is dropped (it would bind loopback dials to the physical adapter);
//! - the servers listen on loopback, and the REALITY handshake is forwarded to a local TLS server instead of a
//!   real site;
//! - the exit gets one extra rule that maps a second address to a throttled test stream, so that a transfer is
//!   long enough to switch carriers under. The rules under test are untouched and still come first.
//!
//! It proves, with the pinned core: the measurement origin is reached through the session; the exit refuses the
//! server's own loopback services, a cloud-metadata address, private addresses and a name that resolves to
//! loopback; and one open transfer survives a switch to the REALITY carrier and back, with the nudge.
//! Skipped, loudly, where the vendored core, Python or OpenSSL is missing. Loopback has no delay or loss, so the
//! timings are a lower bound. The negative control for the refusals is `testing/spike-carrier` (`harden`: the
//! same probes reach the service when the rules are absent); the control inside this test is the origin, which
//! must be reachable by the same path.

#![cfg(test)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use dnet_config::endpoint_bypass::ActiveEndpointBypass;
use dnet_config::hysteria2::{
    BbrProfile, Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams,
    Hysteria2Obfs, Hysteria2Settings, Hysteria2Transport,
};
use dnet_config::primary::{to_json, FakeIpHalf, PrimaryTransport};
use dnet_config::reality::{
    RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::session::{
    generate_session_config, Carrier, CarrierKind, ControlApi, SessionInput,
};
use dnet_config::tls::ServerTrust;
use dnet_core::builtin_rules::builtin_rules_for;
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::EndpointAddress;
use dnet_provision::bootstrap::{
    script, session_device_address, BootstrapPlan, CorePin, Ports, ServerArch, ServerCores,
    SessionPlan, ORIGIN_PORT, SESSION_ORIGIN, SESSION_PORT,
};
use dnet_provision::client_keys::{random_obfuscation, ClientKeys, SessionKeys};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::session_switch::{
    pick_control_port, switch_to, ControlClient, ControlSecret, NudgeOutcome, NudgePlan,
    SessionProbe,
};

const SITE: &str = "www.example.com";
const SNI: &str = "edge.example.net";
const HY2_AUTH: &str = "auth-secret-0123456789abcdef";
const HY2_OBFS: &str = "obfs-secret-0123456789abcdef";
const REALITY_UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
const REALITY_SHORT: &str = "0123456789abcdef";
/// Where the carriers listen and are dialled. **Not** `127.0.0.1`: the client bypasses the whole host of its
/// active endpoint (a real one is a public address), so with the carriers on `127.0.0.1` a probe of the
/// server's loopback services would be bypassed by the client and never enter the session. On `127.0.0.2` the
/// server's `127.0.0.1` is only reachable through the session, which is what the refusals are about.
const CARRIER_HOST: &str = "127.0.0.2";
/// A second port inside the session that the test maps to a throttled stream (test-only; see the header).
const STREAM_PORT_INSIDE: u16 = 8081;

fn find_program(names: &[&str], probe_args: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|name| {
            Command::new(name)
                .args(probe_args)
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .map(|name| (*name).to_owned())
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port this test can really use: free for TCP and for UDP, on both loopback addresses it uses. Asking only for a free
/// TCP port is not enough: Windows reserves ranges of UDP ports for itself (Hyper-V and Docker take several, and they
/// move), and a carrier given one of those cannot bind, which failed this test at random.
fn free_port() -> u16 {
    use std::net::{TcpListener, UdpSocket};
    for _ in 0..500 {
        let port = pick_control_port().expect("a free loopback port");
        let usable = ["127.0.0.1", CARRIER_HOST].iter().all(|host| {
            UdpSocket::bind((*host, port)).is_ok() && TcpListener::bind((*host, port)).is_ok()
        });
        if usable {
            return port;
        }
    }
    panic!("no port that is free for both TCP and UDP on the loopback addresses");
}

fn run(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{program}: {e}"));
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn pin(name: &str, tag: char) -> CorePin {
    CorePin {
        name: name.to_owned(),
        version: "v1.14.0".to_owned(),
        url: format!("https://example.test/{name}"),
        sha256: tag.to_string().repeat(64),
        licence: "GPL-3.0-or-later".to_owned(),
        source: "https://example.test/source".to_owned(),
    }
}

fn key_pair(core: &Path, kind: &str) -> (String, String) {
    let text = String::from_utf8(run(core.to_str().unwrap(), &["generate", kind], None)).unwrap();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
            .unwrap()
    };
    (field("PrivateKey:"), field("PublicKey:"))
}

// ------------------------------------------------------------------ a proxy client

/// A SOCKS5 CONNECT through the client's loopback proxy. `Ok` is the connected stream (the exit connected);
/// `Err` carries the SOCKS reply code, or 255 for a failure to talk to the proxy at all.
async fn socks_connect(proxy: u16, host: &str, port: u16) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .map_err(|_| 255u8)?;
    s.write_all(&[5, 1, 0]).await.map_err(|_| 255u8)?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await.map_err(|_| 255u8)?;
    let mut request = vec![5, 1, 0];
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.push(3);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).await.map_err(|_| 255u8)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(|_| 255u8)?;
    if head[1] != 0 {
        return Err(head[1]);
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        _ => return Err(255),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await.map_err(|_| 255u8)?;
    Ok(s)
}

/// `GET path` through the proxy, as HTTP/1.0: the head and the body, or `None` when nothing came back.
async fn http_get(proxy: u16, host: &str, port: u16, path: &str) -> Option<(String, Vec<u8>)> {
    let mut s = timeout(Duration::from_secs(8), socks_connect(proxy, host, port))
        .await
        .ok()?
        .ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .ok()?;
    let mut raw = Vec::new();
    let _ = timeout(Duration::from_secs(8), s.read_to_end(&mut raw)).await;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    Some((head, raw[split..].to_vec()))
}

/// What came of trying to reach something through the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// It answered with data.
    Answered,
    /// The exit closed the connection at once, with nothing: a refusal.
    Refused,
    /// Nothing happened within the time: a request left hanging is not a refusal (it may be a connection
    /// attempt that simply has not failed yet).
    Hung,
}

/// Try `GET /bytes/10` on `host:port` through the session. The proxy answers a connection request before the
/// exit has decided anything, so a refusal shows as the connection closing with no data, quickly.
async fn probe(proxy: u16, host: &str, port: u16) -> Probe {
    let mut s = match timeout(Duration::from_secs(5), socks_connect(proxy, host, port)).await {
        Err(_) => return Probe::Hung,
        Ok(Err(_)) => return Probe::Refused,
        Ok(Ok(s)) => s,
    };
    if s.write_all(b"GET /bytes/10 HTTP/1.0\r\nHost: x\r\n\r\n")
        .await
        .is_err()
    {
        return Probe::Refused;
    }
    let mut buf = vec![0u8; 512];
    match timeout(Duration::from_secs(3), s.read(&mut buf)).await {
        Err(_) => Probe::Hung,
        Ok(Ok(0)) | Ok(Err(_)) => Probe::Refused,
        Ok(Ok(_)) => Probe::Answered,
    }
}

/// Whether the origin answered `200` through the session.
async fn reaches(proxy: u16, host: &str, port: u16) -> bool {
    matches!(
        http_get(proxy, host, port, "/bytes/10").await,
        Some((head, body)) if head.contains(" 200 ") && body.len() == 10
    )
}

/// The product's nudge needs something that goes through the session. In the product that is a connection to the
/// origin through the tunnel; here the tunnel is the loopback proxy.
struct ThroughTheProxy {
    proxy: u16,
}

impl SessionProbe for ThroughTheProxy {
    async fn attempt(&self) -> bool {
        timeout(
            Duration::from_millis(300),
            socks_connect(self.proxy, &SESSION_ORIGIN.to_string(), ORIGIN_PORT),
        )
        .await
        .is_ok_and(|r| r.is_ok())
    }
}

/// One long transfer, read in pieces: how many bytes came, how long it took, and the longest silence.
async fn long_transfer(
    proxy: u16,
    bytes: usize,
    bps: usize,
) -> Result<(usize, Duration, Duration), String> {
    let mut s = timeout(
        Duration::from_secs(10),
        socks_connect(proxy, &SESSION_ORIGIN.to_string(), STREAM_PORT_INSIDE),
    )
    .await
    .map_err(|_| "no connection".to_owned())?
    .map_err(|c| format!("socks reply {c}"))?;
    s.write_all(
        format!("GET /stream?bytes={bytes}&bps={bps} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let (start, mut last) = (Instant::now(), Instant::now());
    let (mut got, mut worst, mut header_done, mut head) =
        (0usize, Duration::ZERO, false, Vec::new());
    let mut buf = vec![0u8; 65536];
    loop {
        let n = timeout(Duration::from_secs(30), s.read(&mut buf))
            .await
            .map_err(|_| format!("stalled for 30 s after {got} bytes"))?
            .map_err(|e| format!("{e} after {got} bytes"))?;
        if n == 0 {
            break;
        }
        worst = worst.max(last.elapsed());
        last = Instant::now();
        if header_done {
            got += n;
        } else {
            head.extend_from_slice(&buf[..n]);
            if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                header_done = true;
                got += head.len() - (i + 4);
            }
        }
    }
    Ok((got, start.elapsed(), worst))
}

/// This machine's own address on a private network, if it has one (found by asking the operating system which
/// address it would use to reach a public one; nothing is sent).
fn private_lan_address() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() && !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

async fn wait_for_tcp(host: &str, port: u16) -> Option<()> {
    for _ in 0..80 {
        if TcpStream::connect((host, port)).await.is_ok() {
            return Some(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

// ------------------------------------------------------------------ the test

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_composed_from_the_products_own_generators_carries_a_transfer_across_carrier_switches(
) {
    // ---- what is needed
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/primary-core/primary-core.exe");
    let python = find_program(&["python3", "python"], &["-c", "pass"]);
    let openssl = find_program(&["openssl"], &["version"]);
    let (python, openssl) = match (cfg!(windows) && core.is_file(), python, openssl) {
        (true, Some(p), Some(o)) => (p, o),
        _ => {
            eprintln!("SKIPPED: needs the vendored core (fetch-vendor), python and openssl");
            return;
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("primary");
    std::fs::create_dir(&state).unwrap();
    let path = |name: &str| state.join(name);
    let to = |p: &Path| p.to_string_lossy().replace('\\', "/");

    // ---- the server's certificate, made the way the script makes it (ECDSA P-256), and its pin
    run(
        &openssl,
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            &to(&path("server.key")),
        ],
        None,
    );
    run(
        &openssl,
        &[
            "req",
            "-new",
            "-x509",
            "-key",
            &to(&path("server.key")),
            "-out",
            &to(&path("server.crt")),
            "-days",
            "2",
            "-subj",
            &format!("/CN={SNI}"),
            "-addext",
            &format!("subjectAltName=DNS:{SNI}"),
        ],
        None,
    );
    let public_pem = run(
        &openssl,
        &["x509", "-in", &to(&path("server.crt")), "-pubkey", "-noout"],
        None,
    );
    let der = run(
        &openssl,
        &["pkey", "-pubin", "-outform", "DER"],
        Some(&public_pem),
    );
    let digest = run(&openssl, &["dgst", "-sha256", "-binary"], Some(&der));
    let spki: [u8; 32] = digest.try_into().expect("a SHA-256 digest");

    // ---- keys: the server's, and this device's (only its public half goes into the plan)
    let (reality_private, reality_public) = key_pair(&core, "reality-keypair");
    let (session_private, session_public) = key_pair(&core, "wg-keypair");
    let device = SessionKeys::generate().unwrap();

    // ---- the plan, and the configuration its script would write
    let (hy2_port, reality_port, target_port, socks_port) =
        (free_port(), free_port(), free_port(), free_port());
    let (origin_port, stream_port, control_port) = (free_port(), free_port(), free_port());
    let plan = BootstrapPlan {
        cores: ServerCores {
            arch: ServerArch::Amd64,
            primary_core: pin("primary-core", 'a'),
            amneziawg: pin("amneziawg-go", 'b'),
        },
        ports: Ports {
            amneziawg_udp: free_port(),
            hysteria2_udp: hy2_port,
            reality_tcp: reality_port,
        },
        awg_client_public_hex: ClientKeys::generate().unwrap().public_hex().to_owned(),
        obfuscation: random_obfuscation().unwrap(),
        hysteria2_server_name: SNI.to_owned(),
        reality_target: TargetDomain::parse(SITE).unwrap(),
        session: SessionPlan {
            device_public_keys: vec![device.public_b64().to_owned()],
        },
    };
    let text = script(&plan).expect("a valid plan");
    let template = text
        .split("<<CONFIG_EOF\n")
        .nth(1)
        .and_then(|rest| rest.split("\nCONFIG_EOF").next())
        .expect("a configuration block");
    let filled = template
        .replace("$STATE", &to(dir.path()))
        .replace("$HY2_OBFS", HY2_OBFS)
        .replace("$HY2_AUTH", HY2_AUTH)
        .replace("$REALITY_UUID", REALITY_UUID)
        .replace("$REALITY_PRIVATE", &reality_private)
        .replace("$REALITY_SHORT", REALITY_SHORT)
        .replace("$SESSION_PRIVATE", &session_private)
        // A fresh server's list holds the setup key, at the first address: what the server's own program prints.
        .replace(
            "$SESSION_PEERS",
            &format!(
                "        {{ \"public_key\": \"{}\", \"allowed_ips\": [ \"{}/32\" ] }}",
                device.public_b64(),
                dnet_config::session::session_device_address(0)
            ),
        );
    assert!(
        !filled.contains('$'),
        "a variable was left in the configuration"
    );
    let mut server: Value = serde_json::from_str(&filled).expect("the configuration is JSON");

    // The test-only changes (see the header).
    for inbound in server["inbounds"].as_array_mut().unwrap() {
        inbound["listen"] = json!(CARRIER_HOST);
    }
    server["inbounds"][1]["tls"]["reality"]["handshake"] =
        json!({ "server": "127.0.0.1", "server_port": target_port });
    {
        let rules = server["route"]["rules"].as_array_mut().unwrap();
        let at = rules
            .iter()
            .position(|r| r.get("override_address").is_some())
            .expect("the origin rule");
        rules[at]["override_port"] = json!(origin_port);
        let mut stream_rule = rules[at].clone();
        stream_rule["port"] = json!([STREAM_PORT_INSIDE]);
        stream_rule["override_port"] = json!(stream_port);
        // Right after the origin rule, before names are resolved and private addresses refused.
        rules.insert(at + 1, stream_rule);
    }
    std::fs::write(dir.path().join("server.json"), server.to_string()).unwrap();

    // ---- the helpers the server side needs: a TLS site for REALITY to forward to, the production origin,
    // and a throttled stream (test only)
    let tls_site = format!(
        "import ssl, socket, threading, time\n\
         c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n\
         c.load_cert_chain(r'{crt}', r'{key}')\n\
         c.set_alpn_protocols(['h2', 'http/1.1'])\n\
         l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         l.bind(('127.0.0.1', {target_port})); l.listen(16)\n\
         def one(s):\n\
         \x20   try:\n\
         \x20       t = c.wrap_socket(s, server_side=True); time.sleep(0.5); t.close()\n\
         \x20   except Exception: pass\n\
         while True:\n\
         \x20   a, _ = l.accept(); threading.Thread(target=one, args=(a,), daemon=True).start()\n",
        crt = to(&path("server.crt")),
        key = to(&path("server.key")),
    );
    let stream_origin = format!(
        "import re, time\n\
         from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n\
         class H(BaseHTTPRequestHandler):\n\
         \x20   def log_message(self, *a): pass\n\
         \x20   def do_GET(self):\n\
         \x20       m = re.search(r'bytes=(\\d+)&bps=(\\d+)', self.path); n, bps = int(m.group(1)), int(m.group(2))\n\
         \x20       self.send_response(200); self.send_header('Content-Length', str(n)); self.end_headers()\n\
         \x20       sent, t0 = 0, time.time()\n\
         \x20       try:\n\
         \x20           while sent < n:\n\
         \x20               k = min(16384, n - sent); self.wfile.write(b'x' * k); sent += k\n\
         \x20               ahead = sent / bps - (time.time() - t0)\n\
         \x20               if ahead > 0: time.sleep(ahead)\n\
         \x20       except Exception: pass\n\
         ThreadingHTTPServer(('127.0.0.1', {stream_port}), H).serve_forever()\n"
    );
    // A service on this machine's own private address: what a device must not be able to reach through the exit.
    let lan_ip = private_lan_address();
    let lan_port = free_port();
    let plain_service = r#"import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '10')
        self.end_headers()
        self.wfile.write(b'x' * 10)

ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), H).serve_forever()
"#
    .to_owned();
    // The production origin program, exactly as the script installs it, on the port the exit maps to.
    let production_origin = text
        .split("cat > \"$BIN/dnet-origin\" <<'ORIGIN_EOF'\n")
        .nth(1)
        .and_then(|rest| rest.split("\nORIGIN_EOF").next())
        .expect("the origin program")
        .replace(&ORIGIN_PORT.to_string(), &origin_port.to_string());
    for (name, body) in [
        ("tls_site.py", tls_site),
        ("stream_origin.py", stream_origin),
        ("origin.py", production_origin),
        ("plain.py", plain_service),
    ] {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

    // ---- start the server side
    let quiet = |name: &str| {
        let file = std::fs::File::create(dir.path().join(name)).unwrap();
        (Stdio::from(file.try_clone().unwrap()), Stdio::from(file))
    };
    let spawn_python = |script: &str, args: &[&str], log: &str| {
        let (out, err) = quiet(log);
        Kill(
            Command::new(&python)
                .arg(dir.path().join(script))
                .args(args)
                .stdout(out)
                .stderr(err)
                .spawn()
                .unwrap(),
        )
    };
    let mut guards = vec![
        spawn_python("tls_site.py", &[], "tls_site.log"),
        spawn_python("stream_origin.py", &[], "stream_origin.log"),
        spawn_python("origin.py", &["127.0.0.1"], "origin.log"),
    ];
    if let Some(ip) = lan_ip {
        guards.push(spawn_python(
            "plain.py",
            &[&ip.to_string(), &lan_port.to_string()],
            "plain.log",
        ));
    }
    let spawn_core = |config: &str, log: &str| {
        let (out, err) = quiet(log);
        Kill(
            Command::new(&core)
                .args(["run", "-c"])
                .arg(dir.path().join(config))
                .stdout(out)
                .stderr(err)
                .spawn()
                .unwrap(),
        )
    };
    guards.push(spawn_core("server.json", "server.log"));
    let logs = || {
        ["server.log", "client.log", "origin.log", "tls_site.log"]
            .iter()
            .map(|n| {
                let text = std::fs::read_to_string(dir.path().join(n)).unwrap_or_default();
                format!(
                    "--- {n}\n{}",
                    text.lines().rev().take(12).collect::<Vec<_>>().join("\n")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    wait_for_tcp(CARRIER_HOST, reality_port)
        .await
        .unwrap_or_else(|| panic!("the carrier port never opened\n{}", logs()));
    for port in [origin_port, stream_port, target_port] {
        wait_for_tcp("127.0.0.1", port)
            .await
            .unwrap_or_else(|| panic!("port {port} never opened\n{}", logs()));
    }
    // The service a device must not reach has to be really there, or its probe proves nothing (an earlier
    // version of this test had a broken service and passed without noticing).
    if let Some(ip) = lan_ip {
        wait_for_tcp(&ip.to_string(), lan_port)
            .await
            .unwrap_or_else(|| panic!("the LAN service never started\n{}", logs()));
    }

    // ---- the client: the product's generator, with the test-only changes
    let hy2 = Hysteria2Transport {
        settings: Hysteria2Settings {
            client: Hysteria2ClientParams {
                bbr_profile: BbrProfile::Conservative,
                chrome_parrot: true,
            },
            endpoint: Hysteria2EndpointParams {
                obfs: Hysteria2Obfs::Salamander,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: SNI.to_owned(),
                    spki_sha256: spki,
                },
            },
        },
        credentials: Hysteria2Credentials {
            auth_password: Secret::new(HY2_AUTH),
            obfs_password: Secret::new(HY2_OBFS),
        },
    };
    let reality = RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams {
                utls_fingerprint: UtlsFingerprint::Chrome,
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse(SITE).unwrap(),
                public_key: RealityPublicKey::parse(&reality_public).unwrap(),
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new(REALITY_UUID),
            short_id: Secret::new(REALITY_SHORT),
        },
    };
    let hy2_at = EndpointAddress::new(CARRIER_HOST, hy2_port).unwrap();
    let reality_at = EndpointAddress::new(CARRIER_HOST, reality_port).unwrap();
    let (hy2_bypass, reality_bypass) = (
        ActiveEndpointBypass::new(&hy2_at),
        ActiveEndpointBypass::new(&reality_at),
    );
    let carriers = [
        Carrier {
            transport: PrimaryTransport::Hysteria2(&hy2),
            endpoint: &hy2_bypass,
            brutal: None,
        },
        Carrier {
            transport: PrimaryTransport::VlessReality(&reality),
            endpoint: &reality_bypass,
            brutal: None,
        },
    ];
    let rules = builtin_rules_for(Some(&hy2_at), Policy::Block);
    let device_private = Secret::new(device.private_b64());
    let control_secret = ControlSecret::generate().unwrap();
    let config_secret = control_secret.for_config();
    let device_address = format!("{}/32", session_device_address(0));
    let generated = generate_session_config(SessionInput {
        carriers: &carriers,
        active: CarrierKind::Hysteria2,
        rules: &rules,
        fakeip: FakeIpHalf::Low,
        device_private_key: &device_private,
        server_public_key: &session_public,
        device_address: &device_address,
        session_port: SESSION_PORT,
        control: ControlApi {
            port: control_port,
            secret: &config_secret,
        },
    })
    .expect("the product's session configuration");
    let mut client: Value = serde_json::from_str(&to_json(&generated)).unwrap();
    client["inbounds"] = json!([{
        "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": socks_port
    }]);
    client["route"]
        .as_object_mut()
        .unwrap()
        .remove("auto_detect_interface");
    // The client sends private ranges and link-local addresses straight to the local network, by design. This
    // test is about what the **server's exit** does with them, so the client's bypasses are taken out: every
    // probe below must enter the session.
    client["route"]["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|rule| !(rule["outbound"] == "direct" && rule.get("ip_cidr").is_some()));
    std::fs::write(dir.path().join("client.json"), client.to_string()).unwrap();
    guards.push(spawn_core("client.json", "client.log"));
    for port in [socks_port, control_port] {
        wait_for_tcp("127.0.0.1", port)
            .await
            .unwrap_or_else(|| panic!("client port {port} never opened\n{}", logs()));
    }

    // ---- 1. the measurement origin is reached through the session (and so the session works at all)
    let origin = SESSION_ORIGIN.to_string();
    let mut reached = false;
    for _ in 0..40 {
        if reaches(socks_port, &origin, ORIGIN_PORT).await {
            reached = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        reached,
        "the origin was not reachable through the session\n{}",
        logs()
    );
    let (head, body) = http_get(socks_port, &origin, ORIGIN_PORT, "/bytes/100000")
        .await
        .expect("an answer");
    assert!(head.contains(" 200 "), "{head}");
    assert_eq!(body.len(), 100_000, "the origin gave a short answer");

    // ---- 2. the exit refuses the machine it runs on
    //
    // Loopback is stopped twice: the server's user-space network stack drops a packet addressed to loopback
    // before any rule sees it ("Martian packet dropped", in the server log), and the exit's rule refuses it.
    // The stack's drop shows as silence, so for loopback the requirement is only that nothing ever answers.
    // The addresses that only the **rule** can stop (private ranges, link-local such as a cloud metadata
    // address, and a service on the machine's own LAN address) must be refused at once.
    for (label, host, port) in [
        ("the server's own loopback origin", "127.0.0.1", origin_port),
        ("the server's loopback stream", "127.0.0.1", stream_port),
        ("a name that resolves to loopback", "localhost", origin_port),
    ] {
        let outcome = probe(socks_port, host, port).await;
        assert_ne!(
            outcome,
            Probe::Answered,
            "a device reached {label} ({host}:{port})
{}",
            logs()
        );
    }
    let lan = lan_ip.map(|ip| ip.to_string());
    let mut by_the_rule_alone: Vec<(String, String, u16)> = vec![
        (
            "a cloud metadata address".into(),
            "169.254.169.254".into(),
            80,
        ),
        ("a private address".into(), "10.1.2.3".into(), 80),
    ];
    match &lan {
        Some(ip) => by_the_rule_alone.push((
            "a service on the server's own private address".into(),
            ip.clone(),
            lan_port,
        )),
        None => eprintln!("NOTE: no private LAN address on this machine; that probe was not run"),
    }
    for (label, host, port) in &by_the_rule_alone {
        let outcome = probe(socks_port, host, *port).await;
        assert_eq!(
            outcome,
            Probe::Refused,
            "the exit did not refuse {label} ({host}:{port}) at once: {outcome:?}
{}",
            logs()
        );
    }

    // ---- 2b. a carrier credential on its own reaches nothing
    //
    // Someone who has only the Hysteria 2 credential (a laptop that was lost, a configuration that leaked) can
    // talk to the carrier, but the carrier forwards only to the session port. A third client uses the carrier
    // directly, with no session, and tries the same things.
    let thief_port = free_port();
    let mut thief = client.clone();
    thief["inbounds"][0]["listen_port"] = json!(thief_port);
    thief["endpoints"] = json!([]);
    thief["route"] = json!({ "rules": [], "final": "hy2" });
    thief.as_object_mut().unwrap().remove("experimental");
    std::fs::write(dir.path().join("thief.json"), thief.to_string()).unwrap();
    guards.push(spawn_core("thief.json", "thief.log"));
    wait_for_tcp("127.0.0.1", thief_port)
        .await
        .unwrap_or_else(|| {
            panic!(
                "the carrier-only client never started
{}",
                logs()
            )
        });
    let mut targets: Vec<(String, u16, &str)> = vec![
        (
            "127.0.0.1".into(),
            origin_port,
            "the server's loopback origin",
        ),
        (
            "127.0.0.1".into(),
            stream_port,
            "the server's loopback stream",
        ),
        ("169.254.169.254".into(), 80, "a cloud metadata address"),
        ("10.1.2.3".into(), 80, "a private address"),
    ];
    if let Some(ip) = &lan {
        targets.push((
            ip.clone(),
            lan_port,
            "a service on the server's own private address",
        ));
    }
    for (host, port, label) in &targets {
        let outcome = probe(thief_port, host, *port).await;
        assert_ne!(
            outcome,
            Probe::Answered,
            "a carrier credential on its own reached {label} ({host}:{port})
{}",
            logs()
        );
    }

    // ---- 3. one transfer survives switches to the other carrier and back
    let api = ControlClient::new(control_port, control_secret.clone()).unwrap();
    let probe = ThroughTheProxy { proxy: socks_port };
    let transfer = tokio::spawn(long_transfer(socks_port, 14_000_000, 1_000_000));
    tokio::time::sleep(Duration::from_secs(3)).await;
    let first = switch_to(&api, &probe, CarrierKind::Reality, NudgePlan::default())
        .await
        .expect("the switch to the TCP carrier");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let second = switch_to(&api, &probe, CarrierKind::Hysteria2, NudgePlan::default())
        .await
        .expect("the switch back to the QUIC carrier");
    for (which, report) in [("to REALITY", &first), ("back to Hysteria 2", &second)] {
        assert!(
            matches!(report.nudge, NudgeOutcome::Recovered { .. }),
            "the session did not come back {which}: {report:?}\n{}",
            logs()
        );
    }
    let (got, took, worst) = transfer
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("the transfer broke: {e}\n{}", logs()));
    assert_eq!(got, 14_000_000, "the transfer was cut short\n{}", logs());
    assert!(
        worst < Duration::from_secs(4),
        "the longest silence was {worst:?} (took {took:?})\n{}",
        logs()
    );
    eprintln!(
        "session e2e: 14 MB in {took:?}, longest silence {worst:?}, nudges {first:?} / {second:?}"
    );
    drop(guards);
}

#[test]
fn the_test_device_key_is_a_real_key_in_the_cores_form() {
    // Cheap guard for the e2e's key handling: the same encoding the plan validation accepts.
    let keys = SessionKeys::generate().unwrap();
    assert_eq!(STANDARD.decode(keys.public_b64()).unwrap().len(), 32);
    assert_eq!(STANDARD.decode(keys.private_b64()).unwrap().len(), 32);
}
