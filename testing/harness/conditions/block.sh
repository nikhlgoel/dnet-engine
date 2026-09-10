#!/bin/bash
# T012 - H2 (total outbound UDP block) and H4 (selective per-profile block).
#
# H2 serves SC-002 and FR-002: with all UDP gone, the TCP-carrier profile must
# still work. H4 serves SC-001 and SC-004: blocking the profile currently in
# use must force an automatic switch, unattended.
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

# Profile ports, matching docker-compose.yml.
declare -A PORT=( [A]=51820 [B]=44443 [C]=8443 )
declare -A PROTO=( [A]=udp [B]=udp [C]=tcp )

case "${1:-}" in
  H2)
    say "H2: dropping ALL outbound UDP"
    iptables -A "$COND_CHAIN" -p udp -j DROP -m comment --comment "H2-udp-block"
    ;;
  H4)
    P="${2:-}"
    if [[ -z "${PORT[$P]:-}" ]]; then
      echo "usage: block.sh H4 {A|B|C}" >&2
      exit 2
    fi
    say "H4: blocking profile $P (${PROTO[$P]}/${PORT[$P]})"
    iptables -A "$COND_CHAIN" -p "${PROTO[$P]}" --dport "${PORT[$P]}" -j DROP \
      -m comment --comment "H4-profile-$P"
    ;;
  clear)
    iptables -F "$COND_CHAIN"
    say "block rules cleared"
    ;;
  *)
    echo "usage: block.sh {H2|H4 <A|B|C>|clear}" >&2
    exit 2
    ;;
esac
