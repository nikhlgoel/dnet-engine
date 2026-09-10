#!/bin/bash
# T014 - H5: hijack port 53 and return forged answers.
#
# Serves FR-020 and HV-10. The important case is a browser using encrypted DNS:
# its queries never reach a local resolver, which silently defeats naive
# FakeIP implementations (FR-025). This condition is how that gets caught.
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
  H5)
    export FORGED_IP="${2:-10.99.99.99}"
    say "H5: hijacking port 53, forging every answer to $FORGED_IP"
    mkdir -p /opt/state
    python3 /opt/conditions/forge_dns.py &
    echo $! > /opt/state/forge.pid
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 \
      -m comment --comment "H5-dns-hijack"
    ;;
  clear)
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true
    if [[ -f /opt/state/forge.pid ]]; then
      kill "$(cat /opt/state/forge.pid)" 2>/dev/null || true
      rm -f /opt/state/forge.pid
    fi
    say "DNS hijack cleared"
    ;;
  *)
    echo "usage: dns-hijack.sh {H5 [forged-ip]|clear}" >&2
    exit 2
    ;;
esac
