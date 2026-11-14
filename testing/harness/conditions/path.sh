#!/bin/bash
# T016 - H7 (path loss/restore) and H8 (endpoint address blocklisted); H10 (MTU black hole).
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
  H10)
    # An MTU black hole: a narrow link in the middle whose router never says so. Full-size packets vanish and the
    # sender is not told (no ICMP "fragmentation needed"), so a connection's small handshake packets get through,
    # it looks alive, and the first full-size data packet stalls it. Modelled as the kernel models a real narrow
    # link: the utm's transit interface gets the smaller MTU (a packet from the endpoint that does not fit is
    # dropped by the virtual link with no reply, a packet to the endpoint that does not fit is dropped when
    # forwarded), and the ICMP answers are dropped. A length match on the firewall would also drop the merged
    # super-packets a virtual NIC hands up, which no real wire carries (measured: ~5.7 KB each).
    LIMIT="${2:-1280}"
    say "H10: path MTU $LIMIT with no ICMP, on $IFACE"
    ip link set dev "$IFACE" mtu "$LIMIT"
    iptables -A "$COND_CHAIN" -p icmp --icmp-type fragmentation-needed       -j DROP -m comment --comment "H10-no-icmp-frag-needed"
    ip6tables -A "$COND_CHAIN" -p icmpv6 --icmpv6-type packet-too-big       -j DROP -m comment --comment "H10-no-icmp6-too-big" 2>/dev/null || true
    ;;
  clear)
    ip link set "$IFACE" up 2>/dev/null || true
    ip link set dev "$IFACE" mtu 1500 2>/dev/null || true
    iptables -F "$COND_CHAIN"
    ip6tables -F "$COND_CHAIN" 2>/dev/null || true
    say "path conditions cleared"
    ;;
  *)
    echo "usage: path.sh {H7-down|H7-up|H8 [ip]|H10 [bytes]|clear}" >&2
    exit 2
    ;;
esac
