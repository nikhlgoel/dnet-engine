#!/bin/bash
# T013 - H3: signature-based dropping of standard WireGuard handshakes.
#
# THIS IS THE CONDITION THAT MAKES THE OBFUSCATION CLAIM TESTABLE. A harness
# that only degrades quality proves nothing about DPI evasion. H3 drops packets
# carrying the *unobfuscated* WireGuard signature, so that:
#
#   - an AmneziaWG profile with header randomisation still connects, and
#   - a deliberately unobfuscated control MUST fail.
#
# Both halves are required. See HV-03 and the Phase 0 exit gate.
#
# Signature detail: a WireGuard handshake initiation is a 148-byte UDP payload
# beginning 01 00 00 00 (type 1, then three reserved zero bytes); the response
# begins 02 00 00 00. AmneziaWG's H1..H4 parameters replace exactly those bytes,
# and its junk packets (Jc/Jmin/Jmax) break the fixed length - which is what the
# third rule below keys on.
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
  H3)
    say "H3: dropping unobfuscated WireGuard handshake signatures"
    # u32 offsets: 0>>22&0x3C skips the IP header, @8 reaches the UDP payload.
    iptables -A "$COND_CHAIN" -p udp -m u32 \
      --u32 "0>>22&0x3C@8>>16=0x0100 && 0>>22&0x3C@8&0xFFFF=0x0000" \
      -j DROP -m comment --comment "H3-wg-init"
    iptables -A "$COND_CHAIN" -p udp -m u32 \
      --u32 "0>>22&0x3C@8>>16=0x0200 && 0>>22&0x3C@8&0xFFFF=0x0000" \
      -j DROP -m comment --comment "H3-wg-resp"
    # Fixed-size initiation. NOTE: `-m length` matches the TOTAL IP packet
    # length, not the UDP payload: 20 (IP) + 8 (UDP) + 148 (payload) = 176.
    # Using 156 silently matches nothing - measured, not assumed.
    iptables -A "$COND_CHAIN" -p udp -m length --length 176 \
      -j DROP -m comment --comment "H3-wg-fixed-len"
    ;;
  clear)
    iptables -F "$COND_CHAIN"
    say "DPI rules cleared"
    ;;
  *)
    echo "usage: dpi.sh {H3|clear}" >&2
    exit 2
    ;;
esac
