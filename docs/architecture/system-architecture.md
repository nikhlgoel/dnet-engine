# System Architecture

**Status**: Authoritative for v1 · **Spec**: [`spec.md`](../../specs/001-network-resilience-client/spec.md) · **Plan**: [`plan.md`](../../specs/001-network-resilience-client/plan.md)

---

## 1. What DNet Engine actually is

An **orchestration and experience layer** over battle-tested transport cores — not a VPN engine.
The cores already implement TUN integration, FakeIP, rule routing, Hysteria 2 and VLESS+REALITY.
DNet Engine's own contributions are:

1. **Exit-node provisioning** into the user's own cloud account
2. **Active transport probing** and automatic profile switching when one is blocked
3. **Interface failover** driven by OS network-change events
4. **Zero-config onboarding**, tray UI, and honest capability labelling
5. **Updatable transport profiles**, so a blocked profile can be replaced without a new release

Naming this plainly is what prevents months spent reimplementing the cores badly (Principle I).

---

## 2. Process and privilege topology

```
   ┌──────────────────────────────┐        ┌─────────────────────────────┐
   │  dnet-tray  (unprivileged)   │        │  NM stub (v2, unprivileged) │
   │  Tauri v2 + Svelte 5         │        │  browser child process      │
   └──────────────┬───────────────┘        └──────────────┬──────────────┘
                  │  authenticated named pipe             │
                  │  \\.\pipe\DNetEngine\control          │
                  └───────────────┬───────────────────────┘
                                  ▼
            ┌───────────────────────────────────────────┐
            │  dnetd  (LocalSystem Windows Service)     │
            │  ─ the ONLY mutator of system state ─     │
            │                                           │
            │  dnet-core      selection / failover FSM   │
            │  dnet-netstate  routes, DNS, undo records  │
            │  dnet-etw       connect-time attribution   │
            │  dnet-config    core configuration         │
            │  dnet-supervisor child lifecycle           │
            └───────┬───────────────────────┬───────────┘
                    │ spawns + configures    │ spawns + UAPI
                    ▼                        ▼
        ┌────────────────────┐   ┌────────────────────────┐
        │  Primary core      │   │  amneziawg-go          │
        │  TUN + FakeIP +    │   │  AmneziaWG tunnel      │
        │  rules + B/C       │   │  own adapter (awg0)    │
        └─────────┬──────────┘   └──────────┬─────────────┘
                  │                          │
                  └──────── wintun.dll ──────┘
```

**The privilege boundary is the named pipe.** An unprivileged process able to rewrite system routing
is a local privilege-escalation vulnerability and is treated as a CRITICAL defect.

---

## 3. Data path

```
application
   │  DNS query
   ▼
FakeIP resolver ──► synthesises 198.18.x.x, records domain↔IP mapping
   │
   │  application connects to the synthetic address
   ▼
TUN adapter (owned by the primary core, for ALL profiles)
   │
   ▼
rule evaluation ──► domain rule (deterministic)
                    IP/CIDR rule (deterministic)
                    application rule (BEST-EFFORT, via ETW)
   │
   ├── Bypass ──► physical interface, direct
   │
   └── Tunnel ──► active profile ──► endpoint ──► internet
```

Routing decisions are made on the **requested domain**, not on a resolved address — which is why
FakeIP is load-bearing rather than an optimisation.

---

## 4. The routing-loop hazard (the riskiest thing in the system)

Both cores want a virtual adapter. Naively running both produces a loop: AmneziaWG's own encrypted
UDP is captured by the primary core's TUN and fed back into the tunnel.

**Resolution.** The primary core **always** owns the capture TUN, FakeIP, and rules — for all three
profiles, so behaviour never depends on which profile is active. When Profile A is selected:

1. `amneziawg-go` creates its own adapter `awg0` and establishes the tunnel.
2. The primary core's active outbound becomes `direct` with `bind_interface: awg0`.
3. `dnet-netstate` installs a **host route for the endpoint address via the physical gateway**, so
   AmneziaWG's encrypted UDP egresses on the physical NIC and is never captured by the TUN.

**Ordering is safety-critical.** The host route is installed *before* the tunnel starts, removed
*after* it stops, and rewritten *before* rebinding on any interface change. A stale gateway silently
reintroduces the loop.

**Failure signature**: successful handshake, zero throughput. Gated by SPIKE-R4; Phase 3 does not
pass without HV-13 showing no packet re-entry.

---

## 5. Connection lifecycle

```
Disconnected
    │  Connect
    ▼
Probing ──────► races configured profiles, judges on USABLE THROUGHPUT
    │            (a completed handshake is not success — FR-004)
    │  prefers a Tier 1 profile when several are viable
    ▼
Connected ──┬── active profile blocked ──► re-probe ──► switch (≤30 s)
            ├── endpoint unreachable ────► migrate to healthy endpoint (≤30 s)
            ├── carrying path degrades ──► failover (≤5 s), hysteresis-damped
            └── user disconnects ────────► restore all state
    │
    ▼
Failed ──► one of seven DISTINGUISHABLE causes, never a generic error
```

Failure causes: `NoEndpointReachable` · `AllProfilesBlocked` · `CaptivePortalUnsatisfied` ·
`InsufficientPrivilege` · `CoreFailedPersistently` · `NoUsablePath` · `ConfigurationInvalid`.

---

## 6. Restoration guarantee

Every mutation of routing, DNS, or adapter state registers an **undo record before it is applied**.
`dnetd` replays outstanding undo records at **service start**, not only at shutdown — a crash leaves
nobody to run the shutdown path. Verified by killing `dnetd` mid-session and asserting networking is
byte-identical to pre-installation (SC-016).

---

## 7. Deliberate limits

| Limit | Consequence |
|---|---|
| No kernel driver | Application routing is **best-effort**, and says so in the UI |
| Obfuscation hides content and protocol, not volume or destination | Documented in README, first-run, and About |
| No shared infrastructure | Every user provisions their own endpoint; onboarding is harder by design |
| Single static endpoint IP is blocklistable | Multi-endpoint health rotation is v1 scope, not v2 |
| Failover tier varies by profile | Tier is shown in the UI and set by **measurement**, not intention |
