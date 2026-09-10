#!/bin/bash
# Simulated UTM appliance.
#
# Forwards the published profile ports through to the endpoint and hosts the
# condition scripts. Traffic is proxied in userspace by socat rather than routed,
# so this needs only NET_ADMIN (for tc and iptables) and never CAP_SYS_ADMIN.
set -euo pipefail

ENDPOINT=172.32.0.20
STATE=/opt/state
mkdir -p "$STATE"
rm -f "$STATE/ready"

# Resolve the transit-facing interface by subnet rather than assuming a name.
# Docker does not guarantee that the second network lands on eth1.
TRANSIT_IFACE="$(ip -o -4 addr show | awk '$4 ~ /^172\.32\./ {print $2; exit}')"
if [[ -z "$TRANSIT_IFACE" ]]; then
    echo "[utm] FATAL: could not find the transit interface (172.32.0.0/24)" >&2
    ip -o -4 addr show >&2
    exit 1
fi
echo "$TRANSIT_IFACE" > /run/dnet-iface   # container-local, NOT the shared volume
echo "$TRANSIT_IFACE" > "$STATE/transit-iface"  # informational only
echo "[utm] transit interface: $TRANSIT_IFACE"

# ip_forward is set declaratively in docker-compose.yml. Verify rather than
# write: with NET_ADMIN but not full privilege, writing the key is denied.
FORWARD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
echo "[utm] net.ipv4.ip_forward=$FORWARD"

echo "[utm] forwarding published ports to $ENDPOINT"
socat UDP4-LISTEN:51820,fork,reuseaddr UDP4:$ENDPOINT:51820 &
socat UDP4-LISTEN:44443,fork,reuseaddr UDP4:$ENDPOINT:44443 &
socat TCP4-LISTEN:8443,fork,reuseaddr  TCP4:$ENDPOINT:8443  &
socat TCP4-LISTEN:8080,fork,reuseaddr  TCP4:$ENDPOINT:8080  &

# Ground-truth reporting (HN-03).
socat TCP4-LISTEN:9090,fork,reuseaddr EXEC:/opt/conditions/report.sh &

# A dedicated chain so conditions can be flushed without touching base rules.
iptables -N DNET_COND 2>/dev/null || true
iptables -F DNET_COND
iptables -C FORWARD -j DNET_COND 2>/dev/null || iptables -I FORWARD 1 -j DNET_COND
iptables -C OUTPUT -j DNET_COND 2>/dev/null || iptables -I OUTPUT 1 -j DNET_COND

echo "[utm] ready"
touch "$STATE/ready"
tail -f /dev/null
