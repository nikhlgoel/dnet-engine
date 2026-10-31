"""Spike S1/S2 of ADR-0008: a WireGuard session carried over replaceable carriers, all on localhost.

Needs a core built from the pinned commit with the extra build tag `with_wireguard` (see README.md). No network
beyond loopback is touched. Keys and the certificate are throwaway and generated into SPIKE_WORK on first use.

    SPIKE_CORE=path/to/core.exe python run.py smoke switch killA plain-killA   (names: see S below)
    SPIKE_CORE=path/to/core.exe python run.py harden
"""
import json, os, re, socket, subprocess, sys, tempfile, threading, time, pathlib, http.server, socketserver, urllib.request

B = os.environ.get("SPIKE_CORE")
if not B or not pathlib.Path(B).is_file():
    sys.exit("set SPIKE_CORE to a core built with -tags with_wireguard (see testing/spike-carrier/README.md)")
HERE = pathlib.Path(os.environ.get("SPIKE_WORK") or pathlib.Path(tempfile.gettempdir()) / "dnet-spike-carrier")
HERE.mkdir(parents=True, exist_ok=True)
P = HERE.as_posix()


def core(*args):
    return subprocess.run([B, *args], capture_output=True, text=True, check=True).stdout


def prepare():
    """Throwaway keys and a certificate, made by the core itself, once per work directory."""
    for name, cmd in (("wgc.txt", ("generate", "wg-keypair")), ("wgs.txt", ("generate", "wg-keypair")),
                      ("reality.txt", ("generate", "reality-keypair"))):
        if not (HERE / name).exists():
            (HERE / name).write_text(core(*cmd))
    if not (HERE / "c.pem").exists():
        out = core("generate", "tls-keypair", "edge.example.net")
        for text in re.findall(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", out, re.S):
            (HERE / ("k.pem" if "PRIVATE" in text.splitlines()[0] else "c.pem")).write_text(text + "\n")


def keys(f):
    t = (HERE / f).read_text()
    return re.search(r"PrivateKey: (\S+)", t).group(1), re.search(r"PublicKey: (\S+)", t).group(1)


prepare()
CPRIV, CPUB = keys("wgc.txt")
SPRIV, SPUB = keys("wgs.txt")
RPRIV, RPUB = keys("reality.txt")
REALITY = [False]
RUUID = "11111111-1111-4111-8111-111111111111"


def reality_server():
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "vless", "tag": "reality-in", "listen": "127.0.0.1", "listen_port": 24445,
                          "users": [{"name": "t", "uuid": RUUID, "flow": "xtls-rprx-vision"}],
                          "tls": {"enabled": True, "server_name": "edge.example.net",
                                  "reality": {"enabled": True, "private_key": RPRIV, "short_id": ["0123456789abcdef"],
                                              "handshake": {"server": "127.0.0.1", "server_port": 24500}}}}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct", **({"rules": LOCK_RULES} if LOCKED[0] else {})}}


def tls_target():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(P + "/c.pem", P + "/k.pem")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 24500))
    ls.listen(16)

    def one(c):
        try:
            t = ctx.wrap_socket(c, server_side=True)
            time.sleep(0.5)
            t.close()
        except Exception:
            pass

    def loop():
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls
TLS = {"enabled": True, "server_name": "edge.example.net", "certificate_path": P + "/c.pem"}


LOCKED = [False]
LOCK_RULES = [{"ip_cidr": ["127.0.0.1/32"], "port": [25182], "network": ["udp"], "action": "route", "outbound": "direct"},
              {"action": "reject"}]


def hy2_server(port, plain=False):
    route = {"final": "direct"}
    if plain:  # control: user streams end at the origin, so redirect them there
        route["rules"] = [{"inbound": ["hy2-in"], "action": "route-options",
                           "override_address": "127.0.0.1", "override_port": 28081}]
    if LOCKED[0]:  # the carrier may only forward to the one session port, nothing else
        route["rules"] = LOCK_RULES
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": port,
                          "users": [{"name": "t", "password": "pw"}],
                          "tls": {**TLS, "key_path": P + "/k.pem"}}],
            "outbounds": [{"type": "direct", "tag": "direct"}], "route": route}


WGSRV = {"log": {"level": "warn"},
         "endpoints": [{"type": "wireguard", "tag": "wg-srv", "system": False, "address": ["10.9.0.1/32"],
                        "private_key": SPRIV, "listen_port": 25182,
                        "peers": [{"public_key": CPUB, "allowed_ips": ["10.9.0.2/32"]}]}],
         "outbounds": [{"type": "direct", "tag": "direct"}],
         "route": {"rules": [{"inbound": ["wg-srv"], "action": "route-options",
                              "override_address": "127.0.0.1", "override_port": 28081}], "final": "direct"}}


KEEPALIVE = [5]


def client(mode):
    outs = [{"type": "hysteria2", "tag": t, "server": "127.0.0.1", "server_port": p, "password": "pw", "tls": TLS}
            for t, p in (("hy2-a", 24443), ("hy2-b", 24444))]
    members = ["hy2-a", "hy2-b"]
    if REALITY[0]:
        outs.append({"type": "vless", "tag": "vless-c", "server": "127.0.0.1", "server_port": 24445, "uuid": RUUID,
                     "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                     "tls": {"enabled": True, "server_name": "edge.example.net",
                             "utls": {"enabled": True, "fingerprint": "chrome"},
                             "reality": {"enabled": True, "public_key": RPUB, "short_id": "0123456789abcdef"}}})
        members.append("vless-c")
    outs += [{"type": "selector", "tag": "carrier", "outbounds": members, "default": "hy2-a",
              "interrupt_exist_connections": False},
             {"type": "direct", "tag": "direct"}]
    c = {"log": {"level": "warn"},
         "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 21080}],
         "outbounds": outs,
         "experimental": {"clash_api": {"external_controller": "127.0.0.1:29090", "secret": "spike-secret",
                                        "access_control_allow_origin": ["https://dnet.invalid"]}}}
    if mode == "wg":
        c["endpoints"] = [{"type": "wireguard", "tag": "wg", "system": False, "address": ["10.9.0.2/32"],
                           "private_key": CPRIV, "detour": "carrier",
                           "peers": [{"address": "127.0.0.1", "port": 25182, "public_key": SPUB,
                                      "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive_interval": KEEPALIVE[0]}]}]
        c["route"] = {"rules": [{"inbound": ["in"], "action": "route", "outbound": "wg"}], "final": "wg"}
    else:  # the current shape: user streams ride the carrier directly
        c["route"] = {"rules": [{"inbound": ["in"], "action": "route", "outbound": "carrier"}], "final": "carrier"}
    return c


class Origin(http.server.BaseHTTPRequestHandler):
    log = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        m = re.search(r"bytes=(\d+)&bps=(\d+)", self.path)
        n, bps = int(m.group(1)), int(m.group(2))
        Origin.log.append((time.time(), "open"))
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        sent = 0
        t0 = time.time()
        try:
            while sent < n:
                k = min(16384, n - sent)
                self.wfile.write(b"x" * k)
                sent += k
                ahead = sent / bps - (time.time() - t0)
                if ahead > 0:
                    time.sleep(ahead)
            Origin.log.append((time.time(), "done %d" % sent))
        except Exception as e:
            Origin.log.append((time.time(), "error after %d: %s" % (sent, type(e).__name__)))


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def wait_port(port, t=20):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def reader(nbytes, bps, result):
    s = socket.create_connection(("127.0.0.1", 21080), 10)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.50") + (28081).to_bytes(2, "big"))
    r = s.recv(10)
    if r[1] != 0:
        result.update(error="socks reply %d" % r[1])
        return
    s.sendall(("GET /stream?bytes=%d&bps=%d HTTP/1.0\r\nHost: x\r\n\r\n" % (nbytes, bps)).encode())
    s.settimeout(30)
    got = 0
    hdr = b""
    hdr_done = False
    last = time.time()
    t0 = last
    gaps = []
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            now = time.time()
            gaps.append((now - last, now - t0))
            last = now
            if not hdr_done:
                hdr += d
                i = hdr.find(b"\r\n\r\n")
                if i >= 0:
                    hdr_done = True
                    got += len(hdr) - (i + 4)
            else:
                got += len(d)
        result.update(got=got, want=nbytes, secs=round(time.time() - t0, 1),
                      max_gap=round(max(g for g, _ in gaps), 2), gap_at=round(max(gaps)[1], 1))
    except Exception as e:
        result.update(error=type(e).__name__, got=got, want=nbytes, secs=round(time.time() - t0, 1),
                      max_gap=round(max(g for g, _ in gaps), 2) if gaps else None)


def api_switch(tag):
    req = urllib.request.Request("http://127.0.0.1:29090/proxies/carrier", data=json.dumps({"name": tag}).encode(),
                                 method="PUT",
                                 headers={"Authorization": "Bearer spike-secret", "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).read()
        return "ok"
    except Exception as e:
        return "ERR %s" % e


def nudge(seconds=5.0, every=0.25):
    """Send tiny connection attempts through the session so the far end hears from the new path at once."""
    end = time.time() + seconds
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", 21080), 1)
            s.settimeout(0.2)
            s.sendall(b"\x05\x01\x00")
            s.recv(2)
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.50") + (28081).to_bytes(2, "big"))
            s.recv(10)
            s.close()
        except Exception:
            pass
        time.sleep(every)


def scenario(name, mode, events, nbytes=20_000_000, bps=1_000_000, nudging=False, keepalive=5, reality=False, locked=False):
    KEEPALIVE[0] = keepalive
    REALITY[0] = reality
    LOCKED[0] = locked
    procs = {}
    cfgs = {"a": hy2_server(24443, mode != "wg"), "b": hy2_server(24444, mode != "wg")}
    if mode == "wg":
        cfgs["s"] = WGSRV
    if reality:
        cfgs["r"] = reality_server()
        target = tls_target()
    cfgs["c"] = client(mode)
    for k, cfg in cfgs.items():
        f = HERE / ("cfg-%s.json" % k)
        f.write_text(json.dumps(cfg, indent=1))
        chk = subprocess.run([B, "check", "-c", str(f)], capture_output=True, text=True)
        if chk.returncode != 0:
            print(name, "CONFIG REJECTED", k, chk.stdout[-300:], chk.stderr[-300:])
            return
    srv = TS(("127.0.0.1", 28081), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Origin.log.clear()
    try:
        for k in ("a", "b") + (("s",) if mode == "wg" else ()) + (("r",) if reality else ()):
            procs[k] = subprocess.Popen([B, "run", "-c", str(HERE / ("cfg-%s.json" % k))],
                                        stdout=open(HERE / ("log-%s.txt" % k), "w"), stderr=subprocess.STDOUT)
        time.sleep(1.5)
        procs["c"] = subprocess.Popen([B, "run", "-c", str(HERE / "cfg-c.json")],
                                      stdout=open(HERE / "log-c.txt", "w"), stderr=subprocess.STDOUT)
        assert wait_port(21080) and wait_port(29090), "client not up"
        res = {}
        th = threading.Thread(target=reader, args=(nbytes, bps, res))
        t0 = time.time()
        th.start()
        for at, what in events:
            time.sleep(max(0, at - (time.time() - t0)))
            if what.startswith("switch:"):
                print("  t=%.1f switch ->" % (time.time() - t0), what[7:], api_switch(what[7:]))
                if nudging:
                    threading.Thread(target=nudge, daemon=True).start()
            elif what.startswith("kill:"):
                procs[what[5:]].kill()
                print("  t=%.1f killed server" % (time.time() - t0), what[5:])
        th.join(60)
        print(name, "RESULT", res, "| origin:", [(round(t - t0, 1), e) for t, e in Origin.log])
    finally:
        srv.shutdown()
        for p in procs.values():
            try:
                p.kill()
            except Exception:
                pass
        time.sleep(1)


def combined_server():
    """The proposed server profile: one process, both carriers locked to the session port, per-device session key,
    and an exit that refuses private destinations except the measurement origin."""
    carriers = ["hy2-in", "reality-in"]
    srv = reality_server()
    srv["dns"] = {"servers": [{"type": "local", "tag": "local"}]}
    srv["inbounds"] = [hy2_server(24443)["inbounds"][0]] + srv["inbounds"]
    srv["endpoints"] = WGSRV["endpoints"]
    srv["route"] = {"default_domain_resolver": "local", "final": "direct", "rules": [
        {"inbound": carriers, "ip_cidr": ["127.0.0.1/32"], "port": [25182], "network": ["udp"], "action": "route", "outbound": "direct"},
        {"inbound": carriers, "action": "reject"},
        {"inbound": ["wg-srv"], "ip_cidr": ["192.0.2.50/32"], "port": [28081], "action": "route", "outbound": "direct",
         "override_address": "127.0.0.1", "override_port": 28081},
        {"inbound": ["wg-srv"], "action": "resolve", "strategy": "prefer_ipv4"},
        {"inbound": ["wg-srv"], "ip_is_private": True, "action": "reject"}]}
    return srv


def combined():
    REALITY[0] = True
    LOCKED[0] = False
    KEEPALIVE[0] = 25
    cfgs = {"x": combined_server(), "c": client("wg")}
    for k, c in cfgs.items():
        f = HERE / ("cfg-%s.json" % k)
        f.write_text(json.dumps(c, indent=1))
        chk = subprocess.run([B, "check", "-c", str(f)], capture_output=True, text=True)
        if chk.returncode != 0:
            print("CONFIG REJECTED", k, chk.stdout[-500:], chk.stderr[-500:])
            return
    web = TS(("127.0.0.1", 28081), Origin)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    Origin.log.clear()
    tls_target()
    procs = [subprocess.Popen([B, "run", "-c", str(HERE / "cfg-x.json")], stdout=open(HERE / "log-x.txt", "w"), stderr=subprocess.STDOUT)]
    time.sleep(1.5)
    procs.append(subprocess.Popen([B, "run", "-c", str(HERE / "cfg-c.json")], stdout=open(HERE / "log-c.txt", "w"), stderr=subprocess.STDOUT))
    try:
        assert wait_port(21080) and wait_port(29090)
        print("COMBINED SERVER, what a device with a valid session key can reach through the exit:")
        for label, host, port in (("origin (the one exemption)", "192.0.2.50", 28081), ("server loopback 127.0.0.1", "127.0.0.1", 28081),
                                  ("cloud metadata 169.254.169.254", "169.254.169.254", 80), ("name that resolves to loopback", "localhost", 28081)):
            print("   %-40s %s" % (label, socks_try(host, port)))
        res = {}
        th = threading.Thread(target=reader, args=(20_000_000, 1_000_000, res))
        t0 = time.time()
        th.start()
        for at, tag in ((5, "vless-c"), (11, "hy2-a")):
            time.sleep(max(0, at - (time.time() - t0)))
            print("  t=%.1f switch ->" % (time.time() - t0), tag, api_switch(tag))
            threading.Thread(target=nudge, daemon=True).start()
        th.join(60)
        print("combined RESULT", res, "| origin:", [(round(t - t0, 1), e) for t, e in Origin.log])
    finally:
        web.shutdown()
        for p in procs:
            p.kill()
        time.sleep(1)


def socks_try(host, port):
    """Ask the client SOCKS proxy to connect somewhere; return the SOCKS reply code (0 = connected)."""
    s = socket.create_connection(("127.0.0.1", 21080), 5)
    s.settimeout(6)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    try:
        ip = socket.inet_pton(socket.AF_INET, host)
        req = b"\x05\x01\x00\x01" + ip
    except OSError:
        try:
            ip = socket.inet_pton(socket.AF_INET6, host)
            req = b"\x05\x01\x00\x04" + ip
        except OSError:
            req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode()
    s.sendall(req + port.to_bytes(2, "big"))
    t0 = time.time()
    try:
        s.recv(10)
        s.sendall(b"GET /stream?bytes=10&bps=1000 HTTP/1.0\r\nHost: x\r\n\r\n")
        s.settimeout(3)
        data = s.recv(100)
        took = time.time() - t0
        if data.startswith(b"HTTP/1.0 200"):
            return "REACHED the service (HTTP 200)"
        return "closed after %.1fs" % took if not data else "other reply %r" % data[:20]
    except socket.timeout:
        return "no answer in 3s (unreachable)"
    except Exception as e:
        return "%s after %.1fs" % (type(e).__name__, time.time() - t0)
    finally:
        s.close()


def harden(kind):
    hardened = kind == "hard"
    rules = [{"ip_cidr": ["192.0.2.50/32"], "port": [28081], "action": "route", "outbound": "direct",
              "override_address": "127.0.0.1", "override_port": 28081}]
    if hardened:
        rules += [{"action": "resolve", "strategy": "prefer_ipv4"}, {"ip_is_private": True, "action": "reject"}]
    LOCKED[0] = False
    srv = hy2_server(24443)
    if kind == "locked":
        rules = LOCK_RULES
    srv["dns"] = {"servers": [{"type": "local", "tag": "local"}]}
    srv["route"] = {"default_domain_resolver": "local", "rules": rules, "final": "direct"}
    cfg = client("plain")
    cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != "hy2-b"]
    for o in cfg["outbounds"]:
        if o.get("type") == "selector":
            o["outbounds"] = ["hy2-a"]
    files = {"a": srv, "c": cfg}
    for k, c in files.items():
        f = HERE / ("cfg-%s.json" % k)
        f.write_text(json.dumps(c, indent=1))
        chk = subprocess.run([B, "check", "-c", str(f)], capture_output=True, text=True)
        if chk.returncode != 0:
            print("CONFIG REJECTED", k, chk.stdout[-400:], chk.stderr[-400:])
            return
    web = TS(("127.0.0.1", 28081), Origin)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    procs = [subprocess.Popen([B, "run", "-c", str(HERE / "cfg-a.json")], stdout=open(HERE / "log-a.txt", "w"), stderr=subprocess.STDOUT)]
    time.sleep(1.5)
    procs.append(subprocess.Popen([B, "run", "-c", str(HERE / "cfg-c.json")], stdout=open(HERE / "log-c.txt", "w"), stderr=subprocess.STDOUT))
    try:
        assert wait_port(21080)
        print({"open": "OPEN (control)", "hard": "HARDENED (reject private)", "locked": "LOCKED (only the session port)"}[kind])
        for label, host, port in (("origin via exemption", "192.0.2.50", 28081), ("server loopback 127.0.0.1", "127.0.0.1", 28081),
                                  ("cloud metadata 169.254.169.254", "169.254.169.254", 80), ("private 10.1.2.3", "10.1.2.3", 80),
                                  ("name that resolves to loopback (localhost)", "localhost", 28081), ("IPv6 loopback ::1", "::1", 28081)):
            print("   %-46s socks reply: %s" % (label, socks_try(host, port)))
    finally:
        web.shutdown()
        for p in procs:
            p.kill()
        time.sleep(1)


if __name__ == "__main__":
    if sys.argv[1:2] == ["combined"]:
        combined()
        sys.exit(0)
    if sys.argv[1:2] == ["harden"]:
        for k in ("open", "hard", "locked"):
            harden(k)
        sys.exit(0)
    S = {
        "smoke-locked": ("wg", [], 2_000_000, 1_000_000, False, 5, False, True),
        "switch-locked": ("wg", [(5, "switch:hy2-b"), (11, "switch:hy2-a")], 20_000_000, 1_000_000, True, 5, False, True),
        "tcp-locked": ("wg", [(5, "switch:vless-c"), (11, "switch:hy2-a")], 20_000_000, 1_000_000, True, 5, True, True),
        "tcp-carrier": ("wg", [(5, "switch:vless-c"), (11, "switch:hy2-a")], 20_000_000, 1_000_000, True, 5, True),
        "speed-tcp": ("wg", [(0.05, "switch:vless-c")], 300_000_000, 4_000_000_000, True, 5, True),
        "speed-wg": ("wg", [], 300_000_000, 4_000_000_000),
        "speed-plain": ("plain", [], 300_000_000, 4_000_000_000),
        "smoke": ("wg", [], 2_000_000, 1_000_000),
        "switch": ("wg", [(5, "switch:hy2-b"), (11, "switch:hy2-a")], 20_000_000, 1_000_000),
        "killA": ("wg", [(5, "kill:a"), (7, "switch:hy2-b")], 20_000_000, 1_000_000),
        "plain-killA": ("plain", [(5, "kill:a"), (7, "switch:hy2-b")], 20_000_000, 1_000_000),
        "switch-nudge": ("wg", [(5, "switch:hy2-b"), (11, "switch:hy2-a")], 20_000_000, 1_000_000, True, 5),
        "killA-nudge": ("wg", [(5, "kill:a"), (7, "switch:hy2-b")], 20_000_000, 1_000_000, True, 5),
        "switch-ka1": ("wg", [(5, "switch:hy2-b"), (11, "switch:hy2-a")], 20_000_000, 1_000_000, False, 1),
    }
    for n in (sys.argv[1:] or list(S)):
        m, ev, nb, bps, *rest = S[n]
        scenario(n, m, ev, nb, bps, *rest)
