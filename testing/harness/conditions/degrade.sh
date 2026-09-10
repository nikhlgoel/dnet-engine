#!/bin/bash
# T011 - H1 (latency + loss) and H9 (bandwidth ceiling).
#
# H1 serves SC-006: usable for >=95% of an hour at 150ms +/-50ms with 20% loss.
# H9 serves FR-004: a profile that completes a handshake but is throttled to
# unusability must be judged NOT working.
set -euo pipefail
# Shared helpers. Conditions are applied on the transit-facing interface, so the
# host's own connectivity is never touched.
#
# The interface name is resolved at container start (Docker does not guarantee
# that the second network lands on eth1) and recorded by the entrypoint.
# Shaping runs in BOTH containers: netem's `root` qdisc is egress-only, so the
# utm shapes the upload path and the endpoint shapes the download path. Shaping
# only one side leaves bulk transfers essentially undegraded.
#
# /run/dnet-iface is written by each container's own entrypoint and is NOT on the
# shared volume, so a script always gets the interface of the container it is
# actually running in. Docker does not guarantee that the second network lands
# on eth1, so the name must be discovered rather than assumed.
IFACE="$(cat /run/dnet-iface 2>/dev/null || echo eth0)"
COND_CHAIN=DNET_COND

qdisc_clear() { tc qdisc del dev "$IFACE" root 2>/dev/null || true; }
say() { echo "[cond] $*"; }

case "${1:-}" in
  H1)
    qdisc_clear
    say "H1: 150ms +/-50ms delay, 20% loss on $IFACE"
    tc qdisc add dev "$IFACE" root netem delay 150ms 50ms distribution normal loss 20%
    ;;
  H9)
    RATE="${2:-256kbit}"
    qdisc_clear
    say "H9: bandwidth ceiling $RATE on $IFACE"
    tc qdisc add dev "$IFACE" root tbf rate "$RATE" burst 32kbit latency 400ms
    ;;
  H1+H9)
    RATE="${2:-256kbit}"
    qdisc_clear
    say "H1+H9: $RATE ceiling with 150ms +/-50ms delay and 20% loss"
    tc qdisc add dev "$IFACE" root handle 1: tbf rate "$RATE" burst 32kbit latency 400ms
    tc qdisc add dev "$IFACE" parent 1: handle 10: netem delay 150ms 50ms distribution normal loss 20%
    ;;
  clear)
    qdisc_clear
    say "traffic shaping cleared"
    ;;
  *)
    echo "usage: degrade.sh {H1|H9 [rate]|H1+H9 [rate]|clear}" >&2
    exit 2
    ;;
esac
