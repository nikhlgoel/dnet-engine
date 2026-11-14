#!/bin/sh
# Runs the server's firewall script (dnet-net-up, rendered from the bootstrap template) against REAL iptables and
# watches what it lets through and what it refuses. It needs root and network namespaces: run it in a throwaway
# privileged container, never on a machine you care about (testing/server-firewall/Invoke-ServerFirewallCheck.ps1
# does that). It changes the firewall of the machine it runs on.
#
#   sh check.sh /work/dnet-net-up
#
# Topology, all inside this one machine:
#   peer  --(awg0 10.66.0.1/24)--  the server  --(up0 198.51.100.1/24)--  world
#   The peer is a device on the AmneziaWG tunnel. The world holds a "public" host (198.51.100.10, and 50 more
#   addresses next to it), a "private" host (10.99.0.5, standing for the cloud's own network), a resolver the server
#   uses (10.99.0.9) and IPv6 twins. The server is this machine's own namespace; the account the carriers run as is
#   `dnet`.
#
# Two phases. A: no firewall script, an open firewall. Everything the script is meant to stop must get through here,
# or the checks in B prove nothing (a negative control). B: an image-like firewall (everything but ssh rejected,
# forwarding rejected, as a cloud image ships it), then the script, twice.
set -u
NETUP=${1:?the rendered dnet-net-up script}
fail=0
ok() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }

DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iproute2 python3 iputils-ping util-linux >/dev/null 2>&1 \
  || { echo "could not install the tools this check needs"; exit 2; }
id dnet >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dnet
# IPTABLES_MODE=legacy runs everything on the older kind of iptables (many images still have it); the default is the
# nftables-backed one of this image.
if [ "${IPTABLES_MODE:-nft}" = legacy ]; then
  { update-alternatives --set iptables /usr/sbin/iptables-legacy && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
      && iptables -S >/dev/null 2>&1; } >/dev/null 2>&1 \
    || { echo "SKIP  legacy iptables is not usable in this kernel"; exit 0; }
fi
echo "using: $(iptables --version)"
# Some kernels have no IPv6 filtering (the older iptables on this one has no filter table for it). The IPv6 checks
# then cannot mean anything and are skipped, and the script is expected to start all the same.
if ip6tables -S >/dev/null 2>&1; then V6=1; else V6=0; echo "NOTE  no IPv6 filtering in this kernel: the IPv6 checks are skipped"; fi
v6() { [ "$V6" = 1 ] && "$@"; }

cat > /tmp/conn.py <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
s.settimeout(2)
sys.exit(0 if s.connect_ex((host, port)) == 0 else 1)
PY
cat > /tmp/listen.py <<'PY'
import socket, sys, threading, time
def serve(family, addr, port):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(4096)
    while True:
        c, _ = s.accept()
        c.close()
for spec in sys.argv[1:]:
    addr, port = spec.rsplit(":", 1)
    addr = addr.strip("[]")
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    threading.Thread(target=serve, args=(family, addr, int(port)), daemon=True).start()
time.sleep(10**6)
PY
# flood.py <host,host,...> <port> <how many> <seconds to wait>: starts that many connections at once, round robin over
# the hosts, and prints how many had completed after the wait.
cat > /tmp/flood.py <<'PY'
import resource, socket, sys, time
resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
hosts, port, total, window = sys.argv[1].split(","), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
socks = []
for i in range(total):
    host = hosts[i % len(hosts)]
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    s.setblocking(False)
    s.connect_ex((host, port))
    socks.append(s)
time.sleep(window)
done = 0
for s in socks:
    try:
        s.getpeername()  # only a connection that has completed has a peer
        done += 1
    except OSError:
        pass
print(done)
PY

# ---- the topology
ip netns add peer
ip netns add world
ip link add awg0 type veth peer name p0
ip link set p0 netns peer
ip addr add 10.66.0.1/24 dev awg0
ip link set awg0 up
ip netns exec peer ip addr add 10.66.0.2/24 dev p0
ip netns exec peer ip link set p0 up
ip netns exec peer ip link set lo up
ip netns exec peer ip route add default via 10.66.0.1
ip link add up0 type veth peer name w0
ip link set w0 netns world
ip addr add 198.51.100.1/24 dev up0
ip -6 addr add fd00:98::1/64 dev up0 nodad
ip -6 addr add 2001:db8:98::1/64 dev up0 nodad
ip link set up0 up
ip netns exec world ip addr add 198.51.100.10/24 dev w0
i=11
while [ "$i" -le 60 ]; do ip netns exec world ip addr add "198.51.100.$i/24" dev w0; i=$((i + 1)); done
ip netns exec world ip addr add 10.99.0.5/32 dev w0
ip netns exec world ip addr add 10.99.0.9/32 dev w0
ip netns exec world ip -6 addr add fd00:98::5/64 dev w0 nodad
ip netns exec world ip -6 addr add 2001:db8:98::5/64 dev w0 nodad
ip netns exec world ip link set w0 up
ip netns exec world ip link set lo up
ip netns exec world ip route add 10.66.0.0/24 via 198.51.100.1
ip route replace default via 198.51.100.10 dev up0
ip route replace 10.99.0.5/32 via 198.51.100.10 dev up0
ip route replace 10.99.0.9/32 via 198.51.100.10 dev up0
sysctl -qw net.ipv4.ip_forward=1 >/dev/null
sysctl -qw net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
MULTI=$(seq -s, 11 60 | sed 's/[0-9][0-9]*/198.51.100.&/g')

# What the "public internet" and the "cloud's private network" answer on (port 80 on every address, port 53 on every
# address: the resolver and the others), and what the server itself listens on (its ssh on its public address, a
# service on its public IPv6 address, the origin on the tunnel address and on its own loopback, another loopback port).
ip netns exec world python3 /tmp/listen.py 0.0.0.0:80 0.0.0.0:53 198.51.100.10:25 \
  "[fd00:98::5]:80" "[2001:db8:98::5]:80" &
python3 /tmp/listen.py 10.66.0.1:8080 0.0.0.0:22 0.0.0.0:8443 0.0.0.0:9999 127.0.0.1:18080 \
  "[2001:db8:98::1]:2222" &
# The session's origin, as the account that really runs it: its replies are what the "replies are never refused" rule
# is for.
setpriv --reuid=dnet --regid=dnet --clear-groups python3 /tmp/listen.py 127.0.0.1:8080 &
sleep 1

# conn <host|peer|world> <root|dnet> <address> <port>: succeeds if the connection opens.
conn() {
  prefix=""
  [ "$1" != host ] && prefix="ip netns exec $1"
  who=""
  [ "$2" = dnet ] && who="setpriv --reuid=dnet --regid=dnet --clear-groups"
  $prefix $who python3 /tmp/conn.py "$3" "$4"
}
# flood <peer|world|host> <root|dnet> <hosts> <how many> [port]: how many of the new connections completed in half a
# second (port 80 unless given).
flood() {
  prefix=""
  [ "$1" != host ] && prefix="ip netns exec $1"
  who=""
  [ "$2" = dnet ] && who="setpriv --reuid=dnet --regid=dnet --clear-groups"
  $prefix $who python3 /tmp/flood.py "$3" "${5:-80}" "$4" 0.5
}
expect() { # expect open|closed <label> <command...>
  want=$1; label=$2; shift 2
  if "$@"; then got=open; else got=closed; fi
  if [ "$got" = "$want" ]; then ok "$label ($got)"; else bad "$label: wanted $want, got $got"; fi
}
between() { # between <label> <low> <high> <got>
  if [ "$4" -ge "$2" ] && [ "$4" -le "$3" ]; then ok "$1: $4 got through"; else bad "$1: $4 got through (wanted $2 to $3)"; fi
}
reset_firewall() {
  for t in iptables ip6tables; do
    $t -P INPUT ACCEPT; $t -P FORWARD ACCEPT; $t -P OUTPUT ACCEPT
    $t -F; $t -X
  done
  iptables -t nat -F
}
# Packets of protocol 47 (GRE) the "public" host has seen. A GRE tunnel from the peer stands for any protocol that is
# not TCP, UDP or ICMP: IP-in-IP and GRE to a public host, sent from the server's address, are a known way to have a
# server's address reported for reflected attacks.
send_gre() {
  ip netns exec world iptables -F INPUT
  ip netns exec world iptables -I INPUT -p 47
  ip netns exec peer ip tunnel add g0 mode gre local 10.66.0.2 remote 198.51.100.10 ttl 64 2>/dev/null || return 1
  ip netns exec peer ip link set g0 up
  ip netns exec peer ip addr add 172.30.0.1/30 dev g0
  ip netns exec peer ping -c2 -W1 172.30.0.2 >/dev/null 2>&1
  ip netns exec peer ip tunnel del g0
  # A rule with no target leaves that column empty, so look for the protocol in any column.
  ip netns exec world iptables -nvxL INPUT | awk '{ for (i = 3; i <= 5; i++) if ($i == "47" || $i == "gre") { print $1; exit } }'
}

echo "== A. the control: no firewall script, an open firewall. Every one of these must get through."
reset_firewall
expect open "A peer reaches a public host" conn peer root 198.51.100.10 80
expect open "A peer reaches the cloud's private network" conn peer root 10.99.0.5 80
expect open "A peer sends to a mail port" conn peer root 198.51.100.10 25
expect open "A peer reaches the server's ssh from inside the tunnel" conn peer root 10.66.0.1 22
expect open "A peer reaches the server's ssh by its public address" conn peer root 198.51.100.1 22
expect open "A the carriers' account reaches the private network" conn host dnet 10.99.0.5 80
expect open "A the carriers' account reaches the private network on port 53" conn host dnet 10.99.0.5 53
expect open "A the carriers' account reaches a mail port" conn host dnet 198.51.100.10 25
expect open "A the carriers' account reaches the server's own ssh by its public address" conn host dnet 198.51.100.1 22
v6 expect open "A the carriers' account reaches a service on the server's public IPv6 address" conn host dnet 2001:db8:98::1 2222
v6 expect open "A the carriers' account reaches the private IPv6 network" conn host dnet fd00:98::5 80
if n=$(send_gre); then
  gre_available=1
  if [ "${n:-0}" -gt 0 ]; then ok "A a GRE tunnel from the peer reaches the public host: $n packets"; else bad "A no GRE got through, so the check could not fail"; fi
else
  gre_available=0
  echo "SKIP  A/B GRE: this kernel has no GRE tunnel support"
fi
between "A an uncapped flood from a device, to many addresses" 1400 1500 "$(flood peer root "$MULTI" 1500)"
sleep 2
between "A an uncapped flood from a device, to one address" 1400 1500 "$(flood peer root 198.51.100.10 1500)"
sleep 2
between "A an uncapped flood from the carriers' account, to many addresses" 1400 1500 "$(flood host dnet "$MULTI" 1500)"
sleep 2
v6 between "A an uncapped flood from the carriers' account, to one IPv6 address" 1400 1500 "$(flood host dnet 2001:db8:98::5 1500)"
sleep 2
between "A an uncapped flood of 300 at the REALITY door from one address" 280 300 "$(flood world root 198.51.100.1 300 8443)"
sleep 2

echo "== B. an image-like firewall (everything but ssh rejected, forwarding rejected), then the script, twice."
reset_firewall
printf 'nameserver 10.99.0.9\n' > /etc/resolv.conf   # the one resolver this server uses
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
expect closed "B before the script, the image's own rules stop the exit" conn peer root 198.51.100.10 80

if ! out=$(sh "$NETUP" 2>&1); then bad "the script failed:"; echo "$out" | head -20; fi
# The rules as saved, without the comment lines (which carry the time) and the packet counters that iptables-save puts
# on a chain's policy line.
rules() { (iptables-save; ip6tables-save) | grep -v '^#' | sed 's/ \[[0-9]*:[0-9]*\]$//' | sort; }
rules > /tmp/rules.first
sh "$NETUP" || bad "the script failed the second time"
rules > /tmp/rules.second
if cmp -s /tmp/rules.first /tmp/rules.second; then ok "running the script twice changes nothing"; else bad "the second run changed the rules:"; diff /tmp/rules.first /tmp/rules.second | head -20; fi

echo "-- the public side is as it was"
expect open "B the internet reaches ssh" conn world root 198.51.100.1 22
expect open "B the internet reaches the REALITY port" conn world root 198.51.100.1 8443
expect closed "B the internet does not reach any other port" conn world root 198.51.100.1 9999
SP=$(sed -n 's/.*rule jump INPUT ! -i lo -p udp --dport \([0-9][0-9]*\) -j DROP.*/\1/p' "$NETUP" | head -1)
if [ -n "$SP" ] && iptables -S INPUT | grep -q -- "--dport $SP -j DROP" && { [ "$V6" = 0 ] || ip6tables -S INPUT | grep -q -- "--dport $SP -j DROP"; }; then
  ok "B the session's own UDP port ($SP) is dropped from outside, IPv4 and IPv6"
else
  bad "B the session's own UDP port is not dropped from outside"
fi

echo "-- a device on the tunnel"
expect open "B peer reaches a public host" conn peer root 198.51.100.10 80
expect closed "B peer cannot reach the cloud's private network" conn peer root 10.99.0.5 80
expect closed "B peer cannot send to a mail port" conn peer root 198.51.100.10 25
expect open "B peer reaches the measurement origin" conn peer root 10.66.0.1 8080
expect closed "B peer cannot reach the server's ssh" conn peer root 10.66.0.1 22
expect closed "B peer cannot reach the server's ssh by its public address" conn peer root 198.51.100.1 22
expect closed "B peer cannot reach the public ports from inside" conn peer root 10.66.0.1 8443
if ip netns exec peer ping -c1 -W2 10.66.0.1 >/dev/null 2>&1; then ok "B peer can ping the tunnel address"; else bad "B peer cannot ping the tunnel address"; fi
if ip netns exec peer ping -c1 -W2 198.51.100.10 >/dev/null 2>&1; then ok "B peer can ping a public host"; else bad "B peer cannot ping a public host"; fi
if [ "$gre_available" -eq 1 ]; then
  n=$(send_gre)
  if [ "${n:-0}" -eq 0 ]; then ok "B a GRE tunnel from the peer is dropped: 0 packets reach the public host"; else bad "B $n GRE packets reached the public host"; fi
fi

echo "-- the account the carriers run as"
expect open "B dnet reaches a public host" conn host dnet 198.51.100.10 80
expect closed "B dnet cannot reach the cloud's private network" conn host dnet 10.99.0.5 80
expect closed "B dnet cannot reach the private network on port 53 either" conn host dnet 10.99.0.5 53
expect open "B dnet reaches the one resolver this server uses" conn host dnet 10.99.0.9 53
expect closed "B dnet cannot send to a mail port" conn host dnet 198.51.100.10 25
expect closed "B dnet cannot reach the server's own ssh by its public address" conn host dnet 198.51.100.1 22
v6 expect closed "B dnet cannot reach a service on the server's public IPv6 address" conn host dnet 2001:db8:98::1 2222
expect open "B dnet reaches the origin on the server's own loopback (the session's)" conn host dnet 127.0.0.1 8080
expect closed "B dnet cannot reach any other port on the loopback" conn host dnet 127.0.0.1 18080
v6 expect open "B dnet reaches a public IPv6 host" conn host dnet 2001:db8:98::5 80
v6 expect closed "B dnet cannot reach the private IPv6 network" conn host dnet fd00:98::5 80
expect open "B everyone else on the server is not affected (root, private network)" conn host root 10.99.0.5 80
expect open "B everyone else on the server is not affected (root, its own public address)" conn host root 198.51.100.1 22
v6 expect open "B everyone else on the server is not affected (root, private IPv6 network)" conn host root fd00:98::5 80

echo "-- floods are capped, per address and overall, on both ways out, and ordinary use is not"
sleep 7
between "B a device, 1500 at once to many addresses (overall cap)" 150 700 "$(flood peer root "$MULTI" 1500)"
sleep 7
between "B a device, 1500 at once to one address (per-address cap)" 30 200 "$(flood peer root 198.51.100.10 1500)"
sleep 7
between "B the carriers' account, 1500 at once to many addresses (overall cap)" 150 700 "$(flood host dnet "$MULTI" 1500)"
sleep 7
between "B the carriers' account, 1500 at once to one address (per-address cap)" 30 200 "$(flood host dnet 198.51.100.10 1500)"
sleep 7
v6 between "B the carriers' account, 1500 at once to one IPv6 address (per-address cap)" 30 200 "$(flood host dnet 2001:db8:98::5 1500)"
sleep 7
between "B 300 at once at the REALITY door from one address (per-source limit)" 10 80 "$(flood world root 198.51.100.1 300 8443)"
sleep 7
expect open "B afterwards the REALITY door still answers an ordinary visitor" conn world root 198.51.100.1 8443
expect open "B afterwards an ordinary connection works (device)" conn peer root 198.51.100.10 80
expect open "B afterwards an ordinary connection works (carriers' account)" conn host dnet 198.51.100.10 80

echo "== C. a kernel that cannot do everything: what the script does when a rule cannot be made."
# A copy of iptables that fails for any call whose arguments contain a word named in SHIM_FAIL, as a kernel without
# that module would.
mkdir -p /tmp/shim
for tool in iptables ip6tables; do
  cat > "/tmp/shim/$tool" <<SHIM
#!/bin/sh
for bad in \$SHIM_FAIL; do
  case " \$* " in *" \$bad "*) echo "simulated: \$bad is not supported by this kernel" >&2; exit 2;; esac
done
exec /usr/sbin/$tool "\$@"
SHIM
  chmod 755 "/tmp/shim/$tool"
done
image_like() {
  reset_firewall
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
  iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
}
sleep 7

# C1: no owner match: the account's rules cannot be made, so the server must not start without them.
image_like
out=$(PATH=/tmp/shim:$PATH SHIM_FAIL="owner" sh "$NETUP" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q "not starting"; then ok "C without the owner match the script refuses to start (exit $rc) and says why"; else bad "C without the owner match the script went on (exit $rc)"; fi

# C2: no REJECT target: every refusal becomes a DROP, and the server still starts and still refuses.
image_like
out=$(PATH=/tmp/shim:$PATH SHIM_FAIL="REJECT" sh "$NETUP" 2>&1); rc=$?
rejects=$(iptables -S DNET-OUT | grep -c -- '-j REJECT')
drops=$(iptables -S DNET-OUT | grep -c -- '-j DROP')
if [ "$rc" -eq 0 ] && [ "$rejects" -eq 0 ] && [ "$drops" -gt 0 ]; then ok "C without REJECT the refusals are drops ($drops) and the script starts"; else bad "C without REJECT: exit $rc, $rejects rejects, $drops drops"; fi
expect closed "C without REJECT the private network is still refused (device)" conn peer root 10.99.0.5 80
expect closed "C without REJECT the private network is still refused (carriers' account)" conn host dnet 10.99.0.5 80

# C3: no limit modules: the caps cannot be made, and that must not become a block of everything.
image_like
out=$(PATH=/tmp/shim:$PATH SHIM_FAIL="limit hashlimit" sh "$NETUP" 2>&1); rc=$?
if [ "$rc" -eq 0 ]; then ok "C without the limit modules the script starts (exit $rc)"; else bad "C without the limit modules the script failed (exit $rc): $out"; fi
expect open "C without the limit modules ordinary traffic still works (device)" conn peer root 198.51.100.10 80
expect open "C without the limit modules ordinary traffic still works (carriers' account)" conn host dnet 198.51.100.10 80
expect closed "C without the limit modules the private network is still refused" conn peer root 10.99.0.5 80

echo
if [ "$fail" -eq 0 ]; then echo "ALL SERVER FIREWALL CHECKS PASSED"; else echo "SOME SERVER FIREWALL CHECKS FAILED"; fi
exit "$fail"
