# BUG-002: iptables length match used the wrong packet size

**Status**: Fixed
**Severity**: **High** — the DPI detection rule matched nothing
**Found**: 2026-09-10, while diagnosing why HV-03 reported a rule miss
**Area**: `testing/harness/conditions/dpi.sh` — condition H3
**Fixed in**: `cb46844`

## Symptom

Condition H3 installs three rules to drop unobfuscated WireGuard handshakes: two `u32` header
signature matches and one fixed-length match. With H3 active and a genuine 148-byte handshake sent
through the simulated UTM, the rule counters stayed at zero.

`iptables -L DNET_COND -v -n` showed the rule installed and syntactically valid.

## Root cause

The rule used `-m length --length 156`, derived from 148 bytes of WireGuard payload plus the 8-byte
UDP header.

**`iptables -m length` matches the total IP packet length**, which includes the 20-byte IPv4 header:

```
20 (IPv4 header) + 8 (UDP header) + 148 (WireGuard payload) = 176
```

At 156 the rule described a packet size that never occurs, so it matched nothing.

## Why it was dangerous

H3 is the condition that makes the entire obfuscation claim testable. Its whole purpose is to drop
recognisable WireGuard so that an obfuscated profile proves it *is* obfuscated by surviving, and a
deliberately unobfuscated control proves the test works by failing.

A silently non-matching length rule weakens that discrimination. Combined with BUG-003, H3 detected
nothing at all while appearing correctly installed — so any later "AmneziaWG evaded DPI" result would
have been unearned.

## Resolution

Corrected to `--length 176`, with the arithmetic written into the script so the next reader does not
have to rediscover it:

```bash
# Fixed-size initiation. NOTE: `-m length` matches the TOTAL IP packet
# length, not the UDP payload: 20 (IP) + 8 (UDP) + 148 (payload) = 176.
# Using 156 silently matches nothing - measured, not assumed.
iptables -A "$COND_CHAIN" -p udp -m length --length 176 \
  -j DROP -m comment --comment "H3-wg-fixed-len"
```

## Prevention

- `Invoke-Hv03.ps1` is now a gate: it sends a real 148-byte handshake and **asserts the rule counter
  increments**. A non-matching rule fails the Phase 0 exit gate rather than passing quietly.
- Ground-truth reporting (`harness.ps1 report`) exposes per-rule packet counts, so a test can
  distinguish "the traffic evaded the rule" from "the rule never fired".
- `HARNESS-NOTES.md` records the standing rule: **always read `report` before trusting a negative
  result.**
