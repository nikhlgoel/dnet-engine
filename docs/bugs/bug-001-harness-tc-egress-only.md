# BUG-001: Traffic shaping applied to only one direction

**Status**: Fixed
**Severity**: **Critical** — invalidated every degraded-network test
**Found**: 2026-09-10, by measuring throughput instead of assuming the condition worked
**Area**: `testing/harness` — condition H1 (latency + loss), H9 (bandwidth ceiling)
**Fixed in**: `cb46844`

## Symptom

With condition H1 applied (150 ms ±50 ms delay, 20% loss), a 2 MB download completed **faster** than
with no condition at all:

| Run | Result |
|---|---|
| Baseline, no conditions | 4,287 ms — 3.73 Mbit/s |
| **Under H1** | **3,102 ms — 5.16 Mbit/s** |

The condition was demonstrably applied: `tc qdisc show` reported the netem qdisc present with the
correct parameters.

## Root cause

`tc qdisc add dev <iface> root netem ...` shapes **egress only**.

The harness applied shaping solely on the UTM container's transit-facing interface. But bulk download
data flows `endpoint -> utm -> host`, which is **ingress** on that interface. Only the small ACKs and
requests travelling in the egress direction were delayed.

The measured speed-up was incidental — TCP behaves slightly differently when ACKs are delayed — but
the important fact is that the payload path was never degraded at all.

## Why it was dangerous

This is the worst class of test bug: **the test passed and proved nothing.**

- SC-006 requires the connection be usable for at least 95% of an hour at 150 ms / 20% loss. That
  criterion would have been "verified" against an undegraded link.
- HV-05 and every future resilience result would have been meaningless.
- The failure was invisible from inside the test — the condition really was installed, `tc` really
  did report it, and the transfer really did succeed. Nothing looked wrong.

Had this shipped, DNet Engine would have carried a measured claim about behaviour under packet loss
that had never once been tested under packet loss.

## Resolution

Shaping is applied in **both** containers:

- the UTM shapes the **upload** path (client to endpoint),
- the endpoint shapes the **download** path (endpoint to client).

`harness.ps1` does this automatically for `degrade.sh` conditions via the `$BIDIRECTIONAL` list, so a
caller cannot apply one-sided shaping by accident. Each container resolves its own interface and
shapes its own egress.

After the fix, over a 64 KB transfer:

| Run | Result |
|---|---|
| Baseline | 3,134 kbit/s |
| **Under H1** | **4.94 kbit/s** |

A **635x** degradation. H1 is severe by design — 20% loss at 150 ms RTT collapses bare TCP
throughput, which is exactly the condition the product exists to survive.

## Prevention

- Bidirectional application is structural, in `harness.ps1`, not a convention a caller must remember.
- The mechanism and the measurement are recorded in `testing/harness/HARNESS-NOTES.md` under
  "Things that were measured, not assumed".
- **General rule adopted**: before trusting a condition, measure that it changes the thing it claims
  to change. A condition that installs cleanly is not a condition that works.
