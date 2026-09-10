# ADR-0001: ETW connect-time process attribution (SPIKE-O6)

**Status**: Proposed — run 1 inconclusive, decision pending run 2
**Date**: 2026-09-10
**Task**: T021 (SPIKE-O6)
**Decides**: FR-023 (per-process routing) and whether T074–T076 exist
**Instrument**: `crates/dnet-etw/examples/spike_cost.rs`

---

## Context

FR-023 routes traffic by application. With no kernel driver in scope, the only viable
mechanism is an ETW real-time consumer on `Microsoft-Windows-Kernel-Network`, reading the
PID from the `TcpIpConnect` payload at connect time (research.md §R7).

The gate was registered **before** measuring, so the result could not be argued into a pass:

| Metric | Threshold | Source |
|---|---|---|
| CPU cost | < 1% of the machine | SC-014 |
| Coverage | ≥ 95% of connections attributed to the correct PID | tasks.md T021 |
| On failure | FR-023 is cut; only destination rules ship | tasks.md T021 |

Coverage is measured against **ground truth**. The instrument opens known connections and
counts how many come back from ETW with its own PID and the matching source port.

---

## Run 1 — 2026-09-10, elevated, under realistic load

Host: 16 cores, 354 processes, 154 established TCP connections, Brave + WSL + Defender active.

| Measurement | Result |
|---|---|
| Wall time | 30.0 s |
| CPU consumed | 0.031 s |
| CPU, 16-core machine | **0.007 %** |
| Ambient connect events | **1** in 30 s |
| Parsed with PID | 1 |
| Ground-truth connections | 200 (all to 127.0.0.1) |
| Attributed to us | **1** |
| Coverage | **0.5 %** |
| Printed verdict | Cost PASS · Coverage FAIL → "FR-023 is CUT" |

---

## Analysis

### Read literally against the thresholds

Cost passes (0.007% < 1%). Coverage fails (0.5% < 95%). Under the pre-registered rule,
FR-023 would be cut.

### Why the run cannot support that verdict

A gate is only as good as the instrument that feeds it. On inspection, run 1's instrument
had defects, each of which is enough on its own to make the coverage figure uninterpretable:

**1. Loopback-only ground truth.** All 200 connections went to `127.0.0.1`. Loopback is the
traffic class most likely to be handled specially by the network stack, and it is not what
the product routes. A provider can cover remote traffic well and loopback not at all.

**2. No port-independent count.** Run 1 matched connections by source port but never counted
how many connect events carried our PID *regardless of port*. That single number separates
"the provider did not emit events" from "events arrived, but the ports didn't match". Without
it, a parsing error and a real coverage gap look identical.

**3. Port byte order was assumed, not established.**
- *Verified*: ferrisetw decodes `u16` with `from_ne_bytes` (`parser.rs:356`), which is native
  little-endian on x86-64.
- *Verified*: the provider manifest declares `sport` as `inType="win:UInt16"` with **no
  `outType`**, so nothing in the decoding chain converts byte order.
- *Unverified*: whether the kernel writes the port in network byte order. The manifest does
  not say.

If the kernel writes network order, reading natively misses every port except
byte-palindromes. That is 64 of the 16,384 ephemeral ports (0.39%), so across 200
connections we'd expect **~0.8 matches**. Run 1 observed **1**. The fit is suggestive, not
proof: loopback-only ground truth could produce the same number.

**4. The cost figure describes an idle session.** Only one event arrived in the cost window,
so 0.007% measures a session with almost nothing to do. It establishes neither a pass nor a
fail for attribution **under load**, which is what SC-014 is about.

### Hypothesis refuted during analysis

*An unset keyword mask suppressed events.* ferrisetw's `Provider::by_guid` defaults to
`MatchAnyKeyword = 0`, and the provider gates connect events behind
`KERNEL_NETWORK_KEYWORD_IPV4` (`0x10`) and `KERNEL_NETWORK_KEYWORD_IPV6` (`0x20`). But
Microsoft's EnableTraceEx2 documentation states: *"When used with modern (manifest-based or
TraceLogging) providers, a MatchAnyKeyword value of `0` is treated the same as a
MatchAnyKeyword value of `0xFFFFFFFFFFFFFFFF`, i.e. it enables all event keywords."* This
provider is manifest-based, so this was **not** the cause. It is recorded here so nobody
re-investigates it.

### Not diagnostic

One ambient connect event in 30 seconds looked suspicious, but on reflection it is plausible.
A browser reuses long-lived HTTP/2 connections and carries much of its traffic over QUIC,
which is UDP and never produces a `TcpIpConnect`. A low count of *new* TCP connections does
not show that the session was broken.

---

## Decision

> **FR-023 is retained provisionally. It is NOT cut on run-1 evidence.**
>
> The pre-registered rule stands unchanged. Only the invalid data is excluded. SPIKE-O6
> remains an open gate, and **T074–T076 stay blocked** until run 2 settles it. "Provisionally
> retained" permits no implementation work.

Run 2 uses instrument v2, which separates the explanations above in a single run and
**can report INVALID instead of a verdict** when it cannot have measured what it claims to.

### Rule for run 2

| Instrument v2 result | Disposition |
|---|---|
| Exit 2, **INSTRUMENT INVALID** | No decision. Fix the instrument and re-run. |
| Exit 1, remote coverage < 95%, interpreted as *"provider did not emit connect events"* | **FR-023 is cut.** T074–T076 are removed. |
| Exit 1, remote coverage < 95%, interpreted as *"events arrived but ports did not match"* | **Not cut.** This is a parser defect: fix T075's port decoding, then re-run. |
| Exit 1, cost ≥ 1% under representative load | **FR-023 is cut.** |
| Exit 2, coverage passes but cost not established | Re-run the cost window under heavier traffic. |
| Exit 0 | **FR-023 is retained**, labelled best-effort (Principle VI). |

The verdict uses **remote** traffic. Loopback is reported for information only.

---

## Alternatives considered

**A. Cut FR-023 now, on run 1's printed verdict.** Rejected *as a measurement conclusion*: the
run did not measure provider coverage. It remains fully available *as a product decision*.
FR-023 is P3 and best-effort by design, and destination rules via FakeIP were always the
load-bearing routing mechanism, so cutting it costs v1 relatively little. The project owner
can take this option at any time, without run 2.

**B. Accept run 1's cost figure as a PASS.** Rejected: one event is not load.

**C. Re-run with an instrument that can separate the explanations.** **Adopted.**

---

## Consequences

- Instrument v2 is committed. It adds: separate loopback and remote classes, a histogram of
  every event id, a liveness check before measuring, matching in both byte orders, a
  port-independent PID count, and exit code 2 for INVALID.
- **Regardless of the outcome, T075 must not assume native byte order** for `sport` or
  `dport`. Run 2 establishes the correct order empirically; the implementation must use it.
- The instrument defect is recorded as **BUG-006**. It is the mirror image of BUG-001 to
  BUG-003: those produced passes that proved nothing, and this produced a failure that proved
  nothing. Either way, a gate must be able to say "I could not measure this."

---

## Run 2

*Pending.* To run it, from an elevated PowerShell with normal workload active:

```powershell
cd D:\main\projects\personal\dnet-engine
cargo build --release --example spike_cost -p dnet-etw
.\target\release\examples\spike_cost.exe
```

By default this opens 200 outbound TCP connections to `1.1.1.1:443`, 50 ms apart. Use
`--target HOST:PORT` to pick another destination.
