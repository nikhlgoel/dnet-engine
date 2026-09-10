# Phase 1 Data Model: DNet Engine v1

**Date**: 2026-09-10 | **Plan**: [plan.md](./plan.md) | **Research**: [research.md](./research.md)

All types below live in `dnet-core` unless noted. `dnet-core` performs no I/O and touches no Windows
API, so every invariant and state transition here is unit-testable without a network, a machine, or
the supervised processes.

---

## 1. Endpoint

A destination the user owns, through which traffic exits.

| Field | Type | Rules |
|---|---|---|
| `id` | `EndpointId` (UUID v4) | Immutable once created |
| `label` | `String` | 1–64 chars, user-supplied, unique among endpoints |
| `address` | `EndpointAddress` | Host (IP or DNS name) + port |
| `origin` | `EndpointOrigin` | `Provisioned { provider, region, resource_ids }` or `Manual` |
| `credentials` | `CredentialRef` | Handle into the secret store — **never the material itself** |
| `health` | `EndpointHealth` | See §1.1 |
| `enabled` | `bool` | User may disable without deleting |

**Invariants**
- `credentials` is a reference. Key material never appears in a domain type, a log, a diagnostic
  bundle, or an IPC message. Enforced by `CredentialRef` having no accessor returning plaintext
  outside `dnet-provision` and `dnet-config`.
- Deleting an `Endpoint` with `origin = Provisioned` prompts about the cloud resources; deleting the
  record never silently orphans them (FR-011, SC-011).
- At least one `enabled` endpoint must exist before a connection attempt is permitted.

### 1.1 EndpointHealth

Full transition table (resolved 2026-09-11; earlier drafts left `Degraded` and the
`Unknown`+failure edge unspecified).

```
                    probe ok (rtt<250ms, no loss)
Unknown ───────────────────────────────────────────▶ Healthy
   │                                                   │  ▲
   │ probe fail (immediately)                          │  │ 3 consecutive good probes
   ▼                                                   ▼  │
Unreachable ◀─── N consecutive failures ─────── Degraded ─┘
   │  ▲                                          ▲
   │  │ N consecutive failures                   │ 2 consecutive probes
   │  └──────────────── (from Healthy) ──────────┘ with rtt>250ms OR loss
   │
   └── probe ok ──▶ Healthy   (recovery; quality re-evaluated from there)
```

| State | Enter when | Leave to |
|---|---|---|
| `Unknown` | initial, never probed | `Healthy` on first ok; **`Unreachable` on first failure** |
| `Healthy` | ok probe, quality good | `Degraded` after 2 consecutive bad-quality probes; `Unreachable` after `N` consecutive failures |
| `Degraded` | 2 consecutive probes with `rtt > 250ms` **or** reported loss | `Healthy` after 3 consecutive good probes; `Unreachable` after `N` consecutive failures |
| `Unreachable` | `N` consecutive failures, **or** a failure from `Unknown` | `Healthy` on any successful probe (recovery) |

| Field | Type | Notes |
|---|---|---|
| `state` | `Unknown \| Healthy \| Degraded \| Unreachable` | |
| `last_probe` | `Option<Instant>` | |
| `consecutive_failures` | `u32` | Threshold `N` is configuration, default 3 |
| `consecutive_bad_quality` | `u32` | Successful-but-slow/lossy probes; `Healthy → Degraded` at 2 |
| `consecutive_good_quality` | `u32` | Successful fast, lossless probes; `Degraded → Healthy` at 3 |
| `rtt_ewma` | `Option<Duration>` | Smoothed RTT; `α = 1/8` (0.125) |
| `rttvar_ewma` | `Option<Duration>` | Smoothed RTT variance; `β = 1/4` (0.25) |

**Constants** (standard TCP smoothing, RFC 6298 / Jacobson-Karels):
`DEGRADED_RTT_THRESHOLD = 250ms` · `DEGRADED_AFTER_BAD = 2` · `HEALTHY_AFTER_GOOD = 3` ·
`RTT_EWMA_ALPHA = 0.125` · `RTTVAR_EWMA_BETA = 0.25`.

**Invariants**
- `Unreachable` is never terminal — a later successful probe returns it to the pool (FR-012, US4-3).
- **A failed probe from `Unknown` transitions immediately to `Unreachable`.** An endpoint we have
  no information about, whose first contact fails, is not used — we do not wait for `N` failures.
- Transition to `Unreachable` on the *active* endpoint must raise a `ConnectionEvent` so the user is
  informed rather than silently migrated (FR-012).
- A failed probe never leaves the RTT estimators changed — a failure measured no round trip.
- A failed probe never resets to a "healthier" state; only a successful probe can move toward
  `Healthy`.

---

## 2. ConnectionProfile

A named way of reaching an endpoint, with the parameters that shape how it appears to an observer.

| Field | Type | Rules |
|---|---|---|
| `id` | `ProfileId` | Stable across updates; used in the update feed |
| `kind` | `ProfileKind` | `AmneziaWg \| Hysteria2 \| VlessReality` |
| `tier` | `FailoverTier` | `Tier1 \| Tier2` — see §2.1 |
| `carrier` | `Carrier` | `Udp \| Tcp` |
| `params` | `ProfileParams` | Kind-specific; opaque to `dnet-core` |
| `viability` | `Viability` | `Untested \| Working { measured_at } \| Blocked { measured_at, reason }` |
| `provided_by` | `CoreBinding` | `PrimaryCore \| AmneziaWgCore` — which supervised process serves it |

**Invariants**
- **`tier` follows measurement, not intention.** A profile whose Tier 1 claim fails SPIKE-R9 is
  demoted to `Tier2` in configuration and in the UI (Principle VI, R9).
- At least one profile with `carrier = Tcp` must exist in any valid profile set — a UDP-only set is
  dead on networks that block UDP (FR-002).
- `Hysteria2` profiles carry `brutal: Option<BandwidthPair>`. `None` is the default and causes
  `dnet-config` to **omit** the bandwidth section entirely, yielding BBR (R2). `Some` requires a
  recorded user acknowledgement of the shared-capacity warning (FR-006).
- `AmneziaWg` profiles have `provided_by = AmneziaWgCore`; all others `PrimaryCore` (R1).

### 2.1 FailoverTier

| Variant | Meaning | Consequence |
|---|---|---|
| `Tier1` | Established connections survive an interface change | Preferred when multiple profiles are viable (FR-016b) |
| `Tier2` | Access only; established connections break and re-establish | User warned before selection (FR-016b) |

---

## 3. NetworkPath

One physical way the machine reaches the internet. Owned by `dnet-netstate`, projected into
`dnet-core`.

| Field | Type | Notes |
|---|---|---|
| `interface_id` | `InterfaceId` | OS interface LUID |
| `kind` | `PathKind` | `Wifi \| Cellular \| Ethernet \| Other` |
| `gateway` | `Option<IpAddr>` | **Required** to install the endpoint host route (R4) |
| `quality` | `PathQuality` | `loss_ewma`, `rtt_ewma`, `jitter_ewma` |
| `role` | `PathRole` | `Carrying \| Standby \| Unusable` |
| `preference` | `i32` | User-assigned; ties broken by quality |

**Invariants**
- Exactly zero or one path holds `role = Carrying`. Zero means disconnected.
- A path with `gateway = None` cannot become `Carrying` while Profile A is active — the endpoint host
  route cannot be installed without a gateway, and proceeding would create the R4 routing loop.
- Quality is EWMA-smoothed; raw samples never drive transitions directly (FR-018, SC-007).

---

## 4. RoutingRule

| Field | Type | Notes |
|---|---|---|
| `id` | `RuleId` | |
| `matcher` | `RuleMatcher` | `Domain(pattern) \| DomainSuffix \| IpCidr \| Application(path)` |
| `action` | `RuleAction` | `Tunnel \| Bypass` |
| `precedence` | `u32` | Lower wins; documented and visible (FR-022) |
| `reliability` | `Reliability` | `Deterministic \| BestEffort` |

**Invariants**
- `Application(_)` matchers are **always** `BestEffort`. Every other matcher is `Deterministic`. This
  is a type-level guarantee, not a convention — construction of a deterministic application rule is
  impossible (Principle VI, FR-023).
- A built-in, non-deletable rule set gives `Bypass` to RFC1918 ranges, link-local, multicast, and the
  captive-portal probe hosts, so local resources and portal login work with no user configuration
  (FR-024, FR-026, SC-018).
- A built-in, non-deletable `Bypass` rule covers the **active endpoint address**, mirroring the host
  route in R4. Rule evaluation and route table must agree or the loop returns.
- Precedence collisions are rejected at configuration time, not resolved arbitrarily.

---

## 5. ConnectionSession

One period of being connected. Append-only; the basis for both the UI's current state and diagnostics.

| Field | Type | Notes |
|---|---|---|
| `id` | `SessionId` | |
| `started_at` / `ended_at` | `Instant` / `Option<Instant>` | |
| `active_profile` | `ProfileId` | Changes recorded as events, not overwrites |
| `active_endpoint` | `EndpointId` | |
| `carrying_path` | `Option<InterfaceId>` | |
| `events` | `Vec<ConnectionEvent>` | See §5.1 |
| `outcome` | `Option<SessionOutcome>` | `UserDisconnected \| Failed(FailureCause) \| ServiceStopped` |

### 5.1 ConnectionEvent

`ProbeStarted` · `ProfileSelected { profile, because }` · `ProfileBlocked { profile, reason }` ·
`EndpointMigrated { from, to, because }` · `PathChanged { from, to, tier_at_time }` ·
`CoreRestarted { core, attempt }` · `Failed { cause }`

**Invariant.** Every automatic change carries a `because`. The UI must always be able to answer "why
did it do that?" without consulting logs (FR-037, FR-039).

### 5.2 FailureCause

Must be *distinguishable* — a generic error is a defect (FR-039, SC-020):

`NoEndpointReachable` · `AllProfilesBlocked` · `CaptivePortalUnsatisfied` ·
`InsufficientPrivilege` · `CoreFailedPersistently { core }` · `NoUsablePath` ·
`ConfigurationInvalid { detail }`

---

## 6. ProvisioningJob

| Field | Type | Notes |
|---|---|---|
| `id` | `JobId` | |
| `stage` | `ProvisioningStage` | See below |
| `created_resources` | `Vec<CloudResourceRef>` | **Recorded before each create call, not after** |
| `outcome` | `Option<Result<EndpointId, ProvisioningError>>` | |

```
CredentialValidation ─▶ CapacityCheck ─▶ InstanceCreate ─▶ NetworkConfigure
     ─▶ ServerBootstrap ─▶ KeepaliveInstall ─▶ ReachabilityVerify ─▶ Done
```

**Invariants**
- `created_resources` is appended **before** issuing the create call, so a crash mid-call still
  leaves a cleanup trail (SC-011). Recording after the call would lose exactly the resources most
  likely to leak.
- `CapacityCheck` failure is a first-class, retryable outcome with alternative regions offered — not
  an error dialog (US2-2, R10).
- `ReachabilityVerify` must pass before an `Endpoint` is created. A job that reaches
  `KeepaliveInstall` but fails verification yields no endpoint (FR-009, US2-1).
- `ProvisioningError` never contains credential material.

---

## 7. Attribution *(dnet-etw)*

| Field | Type | Notes |
|---|---|---|
| `tuple` | `FiveTuple` | From the ETW event payload |
| `pid` | `u32` | **From the event payload, never `EVENT_TRACE_HEADER`** (R7) |
| `observed_at` | `Instant` | Short TTL; stale entries are evicted, not trusted |

**Invariants**
- The type is named to make its nature unmissable at every call site; there is no `Attribution::Exact`.
- A cache miss resolves to "no application rule matched", never to a guess.
- **`sport`/`dport` from `TcpIpConnect` arrive in network byte order (big-endian).** Attribution
  MUST convert them to host order before matching (`.swap_bytes()` on the natively-parsed `u16`).
  Established empirically by SPIKE-O6 run 2 (native match 0/200, byte-swapped 200/200); see
  ADR-0001. Reading them natively misattributes essentially every connection. `pid` is a `u32`
  process id, not a port, and needs no swap. This is a required assertion in T075's tests.

---

## Cross-cutting invariants

1. **Restoration is owed unconditionally.** Every mutation of routing, DNS, or adapter state is
   registered with an undo record before it is applied, so `dnetd` restores prior state on disconnect,
   exit, crash, and uninstall (FR-029, SC-016). Recovery runs at service start, not only at shutdown —
   a crash leaves no one to run the shutdown path.
2. **Endpoint route and bypass rule are one fact in two places.** The R4 host route and the built-in
   endpoint bypass rule must be derived from a single source and changed together. Divergence is the
   routing loop.
3. **Secrets are references in the domain, material only at the boundary.** Only `dnet-provision` and
   `dnet-config` resolve a `CredentialRef`, and neither returns plaintext to a caller.
4. **Nothing claims more than it measured.** `FailoverTier`, `Viability`, and `Reliability` are all
   set from observation and are the values the UI displays (Principle VI).
