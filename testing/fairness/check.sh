#!/bin/sh
# T189 - does the fairness helper protect a small download from a greedy one, on a real kernel?
#
# Runs inside a throwaway privileged Linux container (network namespaces need it) (see Invoke-FairnessCheck.ps1). One "server" and two "friends" sit
# on a bridge. The server's card is shaped by the helper exactly as a real server's would be. One friend is sent an
# unresponsive UDP stream as fast as the link allows (what a loss-ignoring carrier does); the other, an ordinary
# TCP download. Fair sharing means the ordinary download still gets about half of the shaped rate. The same run
# with a plain queue in place of the shared one is the negative control: there the ordinary download is starved,
# so a result that cannot fail proves nothing.
#
# Usage: check.sh <helper.sh>   (the helper is printed by `cargo run -p dnet-provision --example fairness_helper`)
set -eu

HELPER="$1"
RATE=40
SECONDS_EACH=10

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 iperf3 jq >/dev/null 2>&1

ip netns add srv
ip netns add c1
ip netns add c2
ip link add br0 type bridge
ip link set br0 up
n=1
for ns in srv c1 c2; do
  ip link add "v-$ns" type veth peer name eth0 netns "$ns"
  ip link set "v-$ns" master br0
  ip link set "v-$ns" up
  ip -n "$ns" addr add "10.77.0.$n/24" dev eth0
  ip -n "$ns" link set eth0 up
  ip -n "$ns" link set lo up
  n=$((n + 1))
done
# The server reaches "the internet" through its card: a default route, as on a real server.
ip -n srv route add default via 10.77.0.200 dev eth0 onlink

ip netns exec c1 iperf3 -s -D >/dev/null 2>&1
ip netns exec c2 iperf3 -s -D >/dev/null 2>&1
sleep 1

# Both downloads at once; prints the ordinary (TCP) one's received rate in megabits a second.
run() {
  ip netns exec srv iperf3 -c 10.77.0.2 -u -b 1000M -l 1400 -t "$SECONDS_EACH" >/dev/null 2>&1 &
  hog=$!
  sleep 1
  out=$(ip netns exec srv iperf3 -c 10.77.0.3 -t "$SECONDS_EACH" -J 2>&1 || true)
  wait "$hog" 2>/dev/null || true
  tcp=$(printf '%s' "$out" | jq '.end.sum_received.bits_per_second / 1000000 | floor' 2>/dev/null || true)
  if [ -z "$tcp" ] || [ "$tcp" = "null" ]; then
    echo "iperf3 gave no result: $(printf '%s' "$out" | jq -r '.error // empty' 2>/dev/null || printf '%s' "$out" | head -c 300)" >&2
    tcp=0
  fi
  echo "$tcp"
}

echo "== no shaping at all"
free=$(run)
echo "ordinary download: ${free} Mbit/s"

echo "== a plain queue held to ${RATE} Mbit/s (negative control: the unresponsive stream takes it)"
ip netns exec srv tc qdisc replace dev eth0 root handle 1: htb default 10
ip netns exec srv tc class replace dev eth0 parent 1: classid 1:10 htb rate "${RATE}mbit" ceil "${RATE}mbit" quantum 1514
ip netns exec srv tc qdisc replace dev eth0 parent 1:10 handle 10: pfifo limit 1000
plain=$(run)
echo "ordinary download: ${plain} Mbit/s"
ip netns exec srv tc qdisc del dev eth0 root

echo "== the helper: ${RATE} Mbit/s shared fairly between connections"
ip netns exec srv sh "$HELPER" apply "$RATE"
ip netns exec srv tc qdisc show dev eth0
fair=$(run)
echo "ordinary download: ${fair} Mbit/s"
ip netns exec srv sh "$HELPER" remove
if ip netns exec srv tc qdisc show dev eth0 | grep -q htb; then
  echo "FAIL: the helper did not remove its queue"
  exit 1
fi

# The numbers are the contract. Half of the rate is the fair share; allow for what a short test measures.
HALF=$((RATE / 2))
FLOOR=$((RATE * 35 / 100))
echo "== result: fair=${fair} plain=${plain} free=${free}; the fair share is about ${HALF}, the floor ${FLOOR}"
if [ "$fair" -lt "$FLOOR" ]; then
  echo "FAIL: the ordinary download got ${fair} Mbit/s with fair sharing, under ${FLOOR}"
  exit 1
fi
if [ "$fair" -le "$plain" ]; then
  echo "FAIL: fair sharing was no better than a plain queue (${fair} against ${plain})"
  exit 1
fi
if [ "$fair" -gt "$((RATE + 2))" ]; then
  echo "FAIL: the rate was not held (${fair} Mbit/s over a ${RATE} limit)"
  exit 1
fi
echo "PASS: with fair sharing the ordinary download kept ${fair} of ${RATE} Mbit/s while an unresponsive stream ran; a plain queue left it ${plain}"
