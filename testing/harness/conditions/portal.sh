#!/bin/bash
# T015 - H6: captive portal intercepting all traffic until login is satisfied.
#
# Serves US6 and FR-026. Also covers US6-3: once the portal session expires, the
# product must report a captive portal rather than a generic failure.
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
  H6)
    say "H6: captive portal active - traffic intercepted until login"
    mkdir -p /opt/state
    rm -f /opt/state/portal-authenticated
    python3 /opt/conditions/portal.py &
    echo $! > /opt/state/portal.pid
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8081 \
      -m comment --comment "H6-portal"
    iptables -A "$COND_CHAIN" -p udp -j DROP -m comment --comment "H6-portal-udp"
    ;;
  login)
    curl -fsS -X POST http://127.0.0.1:8081/login >/dev/null
    say "portal login satisfied; releasing traffic"
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8081 2>/dev/null || true
    iptables -D "$COND_CHAIN" -p udp -j DROP -m comment --comment "H6-portal-udp" 2>/dev/null || true
    ;;
  clear)
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8081 2>/dev/null || true
    if [[ -f /opt/state/portal.pid ]]; then
      kill "$(cat /opt/state/portal.pid)" 2>/dev/null || true
      rm -f /opt/state/portal.pid
    fi
    rm -f /opt/state/portal-authenticated
    say "portal cleared"
    ;;
  *)
    echo "usage: portal.sh {H6|login|clear}" >&2
    exit 2
    ;;
esac
