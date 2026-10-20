#!/bin/bash
# T055 lab: bring up the AmneziaWG harness endpoint inside the WSL distro, then hold the VM alive.
#
# Run by testing/spike-r4/Invoke-WslLab.ps1 as root inside the `dnet-endpoint` distro (an export of
# the harness endpoint image). Everything here lives in the VM's memory: WSL discards it when the
# VM idles down, which is why setup and keep-alive are one long-lived process and not two steps.
#
#   usage: wsl-endpoint.sh <endpoint-ip> <hold-seconds> [all]
#                                                         set up, print READY <eth0-ip>, hold.
#                                                         With `all`, Hysteria 2 (udp/44443) and
#                                                         VLESS+REALITY (tcp/8443) are served too,
#                                                         for the T126 gate that drives the daemon.
#          wsl-endpoint.sh diag                           print what the VM saw (after a run)
#
# Prints exactly one line "READY <eth0-ip>" on stdout when the server is up. Anything else on
# stdout/stderr is diagnostic. Exits non-zero, printing "FAILED <why>", if setup does not complete.
#
# How the endpoint appears off-subnet: the Windows client is told to reach <endpoint-ip> through
# its DEFAULT route (the VM is made the gateway). The VM answers for that address with a DNAT in
# the nat PREROUTING chain to its own eth0 address. The gate refuses an endpoint that is on-link
# or loopback on the Windows side (VACUOUS), so this address must never be on the vEthernet (WSL)
# subnet.
#
# Why DNAT and not an address on lo plus SNAT (the first version): replies to an INBOUND flow
# belong to the flow's existing conntrack entry and never traverse the nat table, so an SNAT rule
# on them does nothing. The server then replied from its eth0 address, and a Windows firewall
# treats a reply from a different address than the one the client sent to as unsolicited. With
# DNAT, conntrack rewrites every reply's source back to <endpoint-ip> by itself.
set -euo pipefail

STATE=/opt/state
PORT=51820
SNIFF_LOG=$STATE/sniff.log

if [ "${1:-}" = "diag" ]; then
  echo "== time: $(date +%T)"
  echo "== packets on udp/$PORT seen on eth0 (newest 60; 'head' is the first 4 payload bytes):"
  tail -n 60 "$SNIFF_LOG" 2>/dev/null || echo "(no sniff log)"
  echo "== PREROUTING nat rules with packet counts:"
  iptables -t nat -nvx -L PREROUTING 2>&1 || true
  echo "== HTTP origin (the transfer's target) listening?"
  pgrep -af /opt/origin.py || echo "NOT RUNNING"
  echo "== UDP counters (InDatagrams NoPorts InErrors OutDatagrams):"
  grep '^Udp:' /proc/net/snmp 2>/dev/null || true
  echo "== server log, worker start-up lines removed (newest 80):"
  grep -v -E 'Routine: (encryption|decryption|handshake) worker|Routine: (TUN reader|event worker|receive incoming)'     $STATE/awg-server.log 2>/dev/null | tail -n 80 || echo "(no server log)"
  echo "== Hysteria 2 / REALITY server logs (newest 15 each):"
  tail -n 15 "$STATE/hy2-server.log" 2>/dev/null || echo "(no Hysteria 2 server log)"
  tail -n 15 "$STATE/reality-server.log" 2>/dev/null || echo "(no REALITY server log)"
  echo "== server's view of the peer:"
  python3 - <<'PY' 2>&1 || true
import re, socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/run/amneziawg/awg0.sock")
s.sendall(b"get=1\n\n")
time.sleep(0.5)
s.settimeout(1)
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
text = data.decode()
text = re.sub(r"(private_key|public_key|preshared_key)=\w+", r"\1=<redacted>", text)
print(text)
PY
  exit 0
fi

ENDPOINT_IP="${1:-}"
HOLD="${2:-}"
SERVE="${3:-awg}"
[ "$SERVE" = "awg" ] || [ "$SERVE" = "all" ] || fail_early=1

fail() { echo "FAILED $*"; exit 1; }
[ -z "${fail_early:-}" ] || fail "third argument must be 'all' or absent, got '$SERVE'"

[[ "$ENDPOINT_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "endpoint ip '$ENDPOINT_IP' is not a dotted quad"
[[ "$HOLD" =~ ^[0-9]+$ ]] && [ "$HOLD" -ge 60 ] || fail "hold seconds '$HOLD' must be an integer >= 60"

ETH0_IP="$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
[ -n "$ETH0_IP" ] || fail "eth0 has no IPv4 address"
[ "$ETH0_IP" != "$ENDPOINT_IP" ] || fail "endpoint ip equals the VM's own eth0 address"

dnat_rule=(PREROUTING -d "$ENDPOINT_IP" -j DNAT --to-destination "$ETH0_IP")
selftest_rule=(OUTPUT -d "$ENDPOINT_IP" -p udp --dport 51899 -j DNAT --to-destination "$ETH0_IP:51899")

cleanup() {
  pkill -x amneziawg-go 2>/dev/null || true
  pkill -x primary-core 2>/dev/null || true
  pkill -f /opt/reality-target.py 2>/dev/null || true
  pkill -f /opt/lab-sniff.py 2>/dev/null || true
  pkill -f /opt/origin.py 2>/dev/null || true
  iptables -t nat -D "${dnat_rule[@]}" 2>/dev/null || true
  iptables -t nat -D "${selftest_rule[@]}" 2>/dev/null || true
  # Remove the rules of the previous (lo + SNAT) version of this script, if a VM still has them.
  ip addr del "${ENDPOINT_IP}/32" dev lo 2>/dev/null || true
  iptables -t nat -D POSTROUTING -p udp --sport "$PORT" -j SNAT --to-source "$ENDPOINT_IP" 2>/dev/null || true
}
trap cleanup EXIT

# Start from a known state: a previous run of this script may have left its pieces behind.
cleanup
ip link del awg0 2>/dev/null || true
rm -f /var/run/amneziawg/awg0.sock "$SNIFF_LOG"
# awg-server.sh adds the origin address with `ip addr add`, which fails (and `set -e` aborts it)
# if it is already there.
ip addr del 203.0.113.80/32 dev lo 2>/dev/null || true

[ -c /dev/net/tun ] || fail "/dev/net/tun is absent; amneziawg-go cannot create awg0"

# The VM answers for the endpoint address by translating it to its own. Replies are rewritten back
# by conntrack, so they leave with <endpoint-ip> as their source.
iptables -t nat -A "${dnat_rule[@]}"

# NAT self-test, before anything depends on it: a plain UDP echo on another port, reached through a
# DNAT of the same shape, from a CONNECTED socket. A connected socket only accepts a reply whose
# source is the address it sent to, so it passes only if the reply's source was rewritten back.
iptables -t nat -A "${selftest_rule[@]}"
python3 - "$ENDPOINT_IP" "$ETH0_IP" <<'PY' || { iptables -t nat -D "${selftest_rule[@]}" 2>/dev/null || true; fail "NAT self-test failed: this kernel did not rewrite a reply's source back to the endpoint address"; }
import socket, sys, threading
endpoint, eth0 = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind((eth0, 51899))
srv.settimeout(3)
def echo():
    try:
        data, addr = srv.recvfrom(2048)
        srv.sendto(b"echo:" + data, addr)
    except Exception:
        pass
t = threading.Thread(target=echo, daemon=True)
t.start()
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cli.settimeout(3)
cli.connect((endpoint, 51899))
cli.send(b"ping")
reply = cli.recv(2048)
sys.exit(0 if reply == b"echo:ping" else 1)
PY
iptables -t nat -D "${selftest_rule[@]}"

# Record what reaches the VM and what leaves it on the endpoint port. Windows-side counters cannot
# show a reply from an unexpected address; this can.
cat > /opt/lab-sniff.py <<'PY'
import socket, struct, sys, time
port, seconds = int(sys.argv[1]), int(sys.argv[2])
end, limit, n = time.time() + seconds, 600, 0
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.bind(("eth0", 0))
s.settimeout(1)
while time.time() < end and n < limit:
    try:
        pkt, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    if len(pkt) < 42 or pkt[12:14] != b"\x08\x00" or pkt[23] != 17:
        continue
    ihl = (pkt[14] & 0xF) * 4
    sport, dport, length = struct.unpack("!HHH", pkt[14 + ihl:14 + ihl + 6])
    if port not in (sport, dport):
        continue
    src, dst = socket.inet_ntoa(pkt[26:30]), socket.inet_ntoa(pkt[30:34])
    head = pkt[14 + ihl + 8:14 + ihl + 12].hex()
    print(f"{time.strftime('%H:%M:%S')} {src}:{sport} -> {dst}:{dport} payload={length - 8} head={head}", flush=True)
    n += 1
PY
python3 /opt/lab-sniff.py "$PORT" "$HOLD" > "$SNIFF_LOG" 2>&1 &

# The harness endpoint's own Profile A script: generates (or reuses) test keys, starts the pinned
# amneziawg-go on awg0, configures it over UAPI and writes /opt/state/awg-client.json. Its stdin is
# closed so nothing it spawns can wait on the caller. Debug logging shows each handshake message.
LOG_LEVEL=debug /opt/awg-server.sh < /dev/null || fail "/opt/awg-server.sh exited non-zero (see /opt/state/awg-server.log)"

[ -s /opt/state/awg-client.json ] || fail "awg-client.json was not written"

# The other two transports, served by the pinned primary core, when asked. Each script generates
# (or reuses) test keys, validates its configuration with the core's own `check` and writes the
# client parameters beside awg-client.json.
if [ "$SERVE" = "all" ]; then
  /opt/hy2-server.sh < /dev/null > "$STATE/hy2-setup.log" 2>&1 || fail "/opt/hy2-server.sh failed: $(tail -n 3 "$STATE/hy2-setup.log" | tr '\n' ' ')"
  /opt/reality-server.sh < /dev/null > "$STATE/reality-setup.log" 2>&1 || fail "/opt/reality-server.sh failed: $(tail -n 3 "$STATE/reality-setup.log" | tr '\n' ' ')"
  [ -s /opt/state/hy2-client.json ] || fail "hy2-client.json was not written"
  [ -s /opt/state/reality-client.json ] || fail "reality-client.json was not written"
fi

# The HTTP origin the runner downloads from THROUGH the tunnel (203.0.113.80:8080, an address the
# server script put on lo). The Docker image's entrypoint starts it; this script replaces that
# entrypoint, so it must too. Without it the tunnel works and every transfer is reset by a host with
# nothing listening, which looks exactly like a broken tunnel (found in the second live run).
python3 /opt/origin.py > "$STATE/origin.log" 2>&1 &
python3 - <<'PY' || fail "the HTTP origin did not answer on 203.0.113.80:8080 from inside the VM"
import time, urllib.request
deadline = time.time() + 10
while True:
    try:
        body = urllib.request.urlopen("http://203.0.113.80:8080/", timeout=2).read()
        raise SystemExit(0 if body.startswith(b"dnet-harness-origin") else 1)
    except SystemExit:
        raise
    except Exception:
        if time.time() > deadline:
            raise SystemExit(1)
        time.sleep(0.3)
PY

# Self-check before announcing READY: the things the Windows side cannot see.
pgrep -x amneziawg-go > /dev/null || fail "amneziawg-go is not running"
PORT_HEX="$(printf '%04X' "$PORT")"
grep -qi ":${PORT_HEX} " /proc/net/udp /proc/net/udp6 || fail "nothing is listening on udp/${PORT}"
iptables -t nat -C "${dnat_rule[@]}" || fail "the DNAT rule is missing"
pgrep -f /opt/lab-sniff.py > /dev/null || fail "the packet recorder is not running"
pgrep -f /opt/origin.py > /dev/null || fail "the HTTP origin is not running"
if [ "$SERVE" = "all" ]; then
  # 44443 = 0xAD9B (udp, Hysteria 2); 8443 = 0x20FB (tcp, REALITY).
  grep -qi ":AD9B " /proc/net/udp /proc/net/udp6 || fail "nothing is listening on udp/44443 (Hysteria 2)"
  grep -qi ":20FB " /proc/net/tcp /proc/net/tcp6 || fail "nothing is listening on tcp/8443 (REALITY)"
fi

echo "READY ${ETH0_IP}"
# Hold the VM alive for the whole run. `exec` would skip the EXIT trap, so keep the shell.
sleep "$HOLD"
