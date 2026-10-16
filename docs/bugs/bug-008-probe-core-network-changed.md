# BUG-008: a healthy profile was reported blocked half the time, right after its probe core started

**Status**: Fixed by a bounded retry. The mechanism below is inferred from the core's log, not read from its source
**Severity**: **High**
**Found**: 2026-10-16, by racing the real profiles against the Docker harness
**Area**: `dnet-probe` (`measure.rs`), and the primary core's interface monitor
**Fixed in**: `feat(probe): race connection profiles through loopback SOCKS probes (T059)`

## Symptom

Racing Hysteria 2 against VLESS+REALITY with no hostile condition applied, so both profiles were
healthy, Hysteria 2 came back `HandshakeFailed` after about 0.1 s in **6 of 12 runs**. Each profile
probed alone succeeded every time. The core's log for a failing probe:

```text
ERROR [1192038908 1ms] connection: open connection to 203.0.113.80:8080
  using outbound/hysteria2[proxy]: network changed
```

The core relayed that to the prober as the SOCKS5 reply "general failure".

## Root cause

**Observed.** The failure is in the first moments after the core prints that its inbound has
started, it affects one profile in a pair of cores started at the same moment, and the error text
is `network changed`.

**Inferred, not verified in the core's source.** The probe configuration keeps
`route.auto_detect_interface` on, so that a probe's own sockets bind to the physical interface
(see `dnet_config::probe`). With it on, the core runs a default-interface monitor, and a connection
attempted before that monitor settles is refused as "network changed".

The 12-run loop was the first time two cores started together, and the readiness marker `started`
matches the *inbound* coming up, which can precede the monitor settling.

## Why it was dangerous

A wrong verdict of exactly the kind this layer exists to prevent: a working profile marked blocked.
In a real run it would send the user to a worse profile, or to `AllProfilesBlocked` when only one
profile worked. Every unit test was green throughout: the fake proxies in `measure`'s tests never
produce this reply at this moment. Only a live race showed it.

## Resolution

`measure_via_proxy` retries the SOCKS connect, up to 3 attempts 200 ms apart, **only** when the
proxy answers "general failure". Nothing else is retried:

- "connection refused", "host unreachable" and the other definite refusals are answers, not
  start-up artefacts, so they fail at once. A test pins that.
- The retry is bounded, so a profile that really cannot connect still fails, and within a second
  or two. A test pins that too.

After the change: 12 of 12 live races ran with no spurious failure, then the whole scenario matrix
(`testing/harness/Invoke-Race.ps1`) matched, including the two cases that must fail a profile.

## Prevention

- `Invoke-Race.ps1` races the real cores on every run, so a regression to this behaviour shows up
  as a baseline that selects nothing.
- Open: read the pinned core's source to confirm the mechanism, and check whether a readiness
  signal later than `started` exists, which would replace the retry with a proper wait.
