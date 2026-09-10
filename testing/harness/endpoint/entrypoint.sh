#!/bin/bash
# Mock exit node.
set -euo pipefail
STATE=/opt/state
mkdir -p "$STATE"
rm -f "$STATE/endpoint-ready"

# Record the transit-facing interface so condition scripts can shape egress.
TRANSIT_IFACE="$(ip -o -4 addr show | awk '$4 ~ /^172\.32\./ {print $2; exit}')"
echo "${TRANSIT_IFACE:-eth0}" > /run/dnet-iface   # container-local, NOT the shared volume
echo "${TRANSIT_IFACE:-eth0}" > "$STATE/endpoint-iface"  # informational only
echo "[endpoint] transit interface: ${TRANSIT_IFACE:-eth0}"

echo "[endpoint] starting HTTP origin on :8080"
python3 /opt/origin.py &

echo "[endpoint] ready"
touch "$STATE/endpoint-ready"
tail -f /dev/null
