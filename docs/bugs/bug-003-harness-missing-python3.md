# BUG-003: Test probe failed silently — no interpreter in the container

**Status**: Fixed
**Severity**: **High** — the gate test never executed and reported a false negative
**Found**: 2026-09-10, by inspecting `docker exec` output rather than only the assertion result
**Area**: `testing/harness/utm/Dockerfile`
**Fixed in**: `cb46844`

## Symptom

`Invoke-Hv03.ps1` reported that the H3 rule counter had not incremented, and concluded that H3 failed
to detect WireGuard. Running `dpi.sh H3` by hand worked and exited 0, and the rules were present.

Inspecting the probe step directly revealed the real error:

```
OCI runtime exec failed: exec: "python3": executable file not found in $PATH
```

## Root cause

The UTM container image installed `iproute2`, `iptables`, `socat`, `tcpdump`, `bash`, `curl`, `jq`
and `procps` — but **not `python3`**.

Four things in the harness need it: `report.sh` (ground-truth JSON), `forge_dns.py` (the DNS forger
for H5), `portal.py` (the captive portal for H6), and the HV-03 probe itself.

Because the probe's output was piped to `Out-Null`, the failing `docker exec` produced no visible
error. The probe never sent a packet. The counter was therefore correctly zero — the test simply was
not testing anything.

## Why it was dangerous

The failure mode was **a test reporting a product defect that did not exist**. Left unnoticed, the
plausible next step is to "fix" the H3 rules until the test passes — modifying working detection
logic to satisfy a probe that was never running. That is how correct code gets broken to satisfy a
broken test.

It also silently disabled H5 and H6, so the DNS-hijack and captive-portal conditions would have
appeared to apply while doing nothing.

## Resolution

Added `python3` to the UTM image, with a comment recording every consumer so the dependency is not
dropped in a future slimming pass:

```dockerfile
# iproute2 -> tc/netem/tbf ; iptables -> DPI and block simulation
# socat     -> port forwarding to the endpoint
# tcpdump   -> packet inspection
# python3   -> report.sh, the DNS forger, the captive portal, and test probes
RUN apk add --no-cache \
        iproute2 iproute2-tc iptables ip6tables \
        socat tcpdump bash curl jq procps python3
```

Verified: `python3 --version` reports 3.12.14 in the container, and HV-03 subsequently passed with
the counter incrementing 0 to 1.

## Prevention

- Diagnostic output from failed container commands is now printed rather than swallowed. That change
  surfaced BUG-005 immediately.
- HV-03's two-sided assertion means a probe that fails to send cannot produce a pass: the negative
  control must be **dropped**, not merely "not observed".
- **General rule**: never pipe a test's setup step to `Out-Null`. Failures in setup must be as loud
  as failures in assertion.
