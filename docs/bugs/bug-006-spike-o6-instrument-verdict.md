# BUG-006: SPIKE-O6 instrument printed a verdict it could not support

**Status**: Fixed (instrument v2). The cause of run 1's 0.5% figure is pending run 2.
**Severity**: **High** — produced a FAIL that would have cut FR-023 from v1
**Found**: 2026-09-10, while analysing run 1's output before acting on it
**Area**: `crates/dnet-etw/examples/spike_cost.rs`
**Fixed in**: the commit that adds ADR-0001

## Symptom

Run 1 ran elevated under realistic load and printed:

```
Cost      0.007 % of a 16-core machine  PASS (SC-014 <1%)
Coverage  0.5 %  FAIL (<95%)
SPIKE-O6 FAILS. Per-process routing (FR-023) is CUT from v1
```

It observed 1 ambient connect event in 30 s, and attributed 1 of 200 ground-truth connections.

## Root cause

The instrument had four defects. Each one is confirmed, and each is enough on its own to
invalidate the verdict — whatever the underlying cause of the 0.5% turns out to be.

1. **Loopback-only ground truth.** Every connection went to `127.0.0.1`, the traffic class
   most likely to be special-cased and the one the product does not route.
2. **No port-independent count.** It matched by source port but never counted events carrying
   its own PID regardless of port. So it could not tell "the provider emitted nothing" apart
   from "events arrived, but the ports didn't match".
3. **Unverified byte order.** It read `sport` with ferrisetw's native-endian decoder
   (`from_ne_bytes`). The provider manifest declares the field as `win:UInt16` with no
   `outType`, so nothing converts it. If the kernel writes network order, only byte-palindromic
   ports can match — about 0.39% of ephemeral ports, which predicts ~0.8 matches in 200.
   Run 1 got 1.
4. **No validity precondition.** It printed PASS or FAIL unconditionally, including a cost PASS
   computed from a single event.

**Refuted along the way:** an unset keyword mask. Microsoft documents that
`MatchAnyKeyword = 0` enables all keywords for manifest-based providers. See ADR-0001.

## Why it was dangerous

The gate's rule was registered in advance: a coverage failure cuts FR-023. Applied
mechanically, that rule would have removed a feature because of a defect in the
**measurement**, not the provider.

It is the mirror image of BUG-001 to BUG-003. Those bugs produced *passes* that proved nothing;
this one produced a *failure* that proved nothing. A gate that can only answer PASS or FAIL
has no way to say "I did not measure this" — so an instrument defect comes out as a verdict.

## Resolution

Instrument v2:

- Measures **loopback** and **remote** ground truth as separate classes. The verdict uses
  remote traffic.
- Counts connect events carrying our PID **independently of port**, and prints an
  interpretation for each class: provider did not emit, attributed correctly, or a parsing
  problem.
- Matches ports in **both byte orders**, and reports a finding when the byte-swapped order
  dominates.
- Runs a **liveness check** first, using a histogram of every event id delivered, and refuses
  to measure if the session is silent.
- Reports cost as **not established** when fewer than 50 events arrive in the window.
- Adds exit code **2 — INSTRUMENT INVALID** (no verdict), alongside 0 PASS and 1 FAIL.

## Prevention

- **Every gate must be able to return INVALID.** A binary PASS/FAIL gate turns an instrument
  defect into a false verdict.
- **Every ground-truth comparison reports its intermediate counts.** When a match fails, the
  report must show which stage lost the data.
- Recorded in ADR-0001 so run 2 is read against these rules, not against run 1's printed verdict.
