#!/bin/bash
# T016 - H7 (path loss/restore) and H8 (endpoint address blocklisted).
#
# H7 serves SC-005 and the Tier 1 / Tier 2 distinction (HV-07, HV-08).
# H8 serves SC-008 and US4: a blocklisted endpoint must trigger migration.
#
# NOTE ON H7: this drops the utm's transit link, simulating the *path* failing.
# It does not detach a Windows NIC. Host-side interface failover is exercised
# separately - see HARNESS-NOTES.md.
set -euo pipefail
# Shared helpers. Conditions are applied on the transit-facing interface, so the
# host's own connectivity is never touched.
#
# The interface name is resolved at container start (Docker does not guarantee
# that the second network lands on eth1) and recorded by the entrypoint.
IFACE="$(cat /run/dnet-iface 2>/dev/null || echo eth0)"
COND_CHAIN=DNET_COND

qdisc_clear() { tc qdisc del dev "$IFACE" root 2>/dev/null || true; }
say() { echo "[cond] $*"; }

case "${1:-}" in
  H7-down)
    say "H7: transit path DOWN"
    ip link set "$IFACE" down
    ;;
  H7-up)
    say "H7: transit path UP"
    ip link set "$IFACE" up
    ;;
  H8)
    TARGET="${2:-172.32.0.20}"
    say "H8: blocklisting endpoint $TARGET"
    iptables -A "$COND_CHAIN" -d "$TARGET" -j DROP -m comment --comment "H8-endpoint-block"
    ;;
  clear)
    ip link set "$IFACE" up 2>/dev/null || true
    iptables -F "$COND_CHAIN"
    say "path conditions cleared"
    ;;
  *)
    echo "usage: path.sh {H7-down|H7-up|H8 [ip]|clear}" >&2
    exit 2
    ;;
esac
