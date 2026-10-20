#!/bin/bash
# T055 lab: bring up the AmneziaWG harness endpoint inside the WSL distro, then hold the VM alive.
#
# Run by testing/spike-r4/Invoke-WslLab.ps1 as root inside the `dnet-endpoint` distro (an export of
# the harness endpoint image). Everything here lives in the VM's memory: WSL discards it when the
# VM idles down, which is why setup and keep-alive are one long-lived process and not two steps.
#
#   usage: wsl-endpoint.sh <endpoint-ip> <hold-seconds>
#
# Prints exactly one line "READY <eth0-ip>" on stdout when the server is up. Anything else on
# stdout/stderr is diagnostic. Exits non-zero, printing "FAILED <why>", if setup does not complete.
#
# Why the endpoint address sits on the loopback interface: the Windows client is told to reach
# <endpoint-ip> through its DEFAULT route (the VM is made the gateway). The VM then owns that
# address locally, so it answers as an off-subnet host would. The gate refuses an endpoint that
# is on-link or loopback on the Windows side (VACUOUS), so this address must never be on the
# vEthernet (WSL) subnet.
set -euo pipefail

ENDPOINT_IP="${1:-}"
HOLD="${2:-}"
PORT=51820

fail() { echo "FAILED $*"; exit 1; }

[[ "$ENDPOINT_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "endpoint ip '$ENDPOINT_IP' is not a dotted quad"
[[ "$HOLD" =~ ^[0-9]+$ ]] && [ "$HOLD" -ge 60 ] || fail "hold seconds '$HOLD' must be an integer >= 60"

cleanup() {
  pkill -x amneziawg-go 2>/dev/null || true
  ip addr del "${ENDPOINT_IP}/32" dev lo 2>/dev/null || true
  iptables -t nat -D POSTROUTING -p udp --sport "$PORT" -j SNAT --to-source "$ENDPOINT_IP" 2>/dev/null || true
}
trap cleanup EXIT

# Start from a known state: a previous run of this script may have left its pieces behind.
pkill -x amneziawg-go 2>/dev/null || true
ip link del awg0 2>/dev/null || true
rm -f /var/run/amneziawg/awg0.sock
# awg-server.sh adds these with `ip addr add`, which fails (and `set -e` aborts it) if present.
ip addr del 203.0.113.80/32 dev lo 2>/dev/null || true
ip addr del "${ENDPOINT_IP}/32" dev lo 2>/dev/null || true
iptables -t nat -D POSTROUTING -p udp --sport "$PORT" -j SNAT --to-source "$ENDPOINT_IP" 2>/dev/null || true

[ -c /dev/net/tun ] || fail "/dev/net/tun is absent; amneziawg-go cannot create awg0"
ETH0_IP="$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
[ -n "$ETH0_IP" ] || fail "eth0 has no IPv4 address"
[ "$ETH0_IP" != "$ENDPOINT_IP" ] || fail "endpoint ip equals the VM's own eth0 address"

ip addr add "${ENDPOINT_IP}/32" dev lo
# Replies must leave with the endpoint address as their source. A WireGuard peer follows the
# source it hears from, so a reply from the VM's eth0 address would make the client's peer roam
# onto an on-link address and silently remove the route under test.
iptables -t nat -A POSTROUTING -p udp --sport "$PORT" -j SNAT --to-source "$ENDPOINT_IP"

# The harness endpoint's own Profile A script: generates (or reuses) test keys, starts the pinned
# amneziawg-go on awg0, configures it over UAPI and writes /opt/state/awg-client.json.
# Its stdin is closed so nothing it spawns can wait on the caller.
/opt/awg-server.sh < /dev/null || fail "/opt/awg-server.sh exited non-zero (see /opt/state/awg-server.log)"

[ -s /opt/state/awg-client.json ] || fail "awg-client.json was not written"

# Self-check before announcing READY: the three things the Windows side cannot see.
ip -4 -o addr show lo | grep -q " ${ENDPOINT_IP}/32" || fail "${ENDPOINT_IP} is not on lo"
pgrep -x amneziawg-go > /dev/null || fail "amneziawg-go is not running"
PORT_HEX="$(printf '%04X' "$PORT")"
grep -qi ":${PORT_HEX} " /proc/net/udp /proc/net/udp6 || fail "nothing is listening on udp/${PORT}"
iptables -t nat -C POSTROUTING -p udp --sport "$PORT" -j SNAT --to-source "$ENDPOINT_IP" || fail "SNAT rule is missing"

echo "READY ${ETH0_IP}"
# Hold the VM alive for the whole run. `exec` would skip the EXIT trap, so keep the shell.
sleep "$HOLD"
