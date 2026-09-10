# Module Blueprints

Per-crate responsibility, public surface, and the invariants each one owns.
Types are defined in [`data-model.md`](../../specs/001-network-resilience-client/data-model.md).

---

## dnet-core — pure domain logic

**No I/O. No Windows API. No network.** This is deliberate: it makes profile selection, endpoint
health scoring, and the failover state machine unit-testable without a machine, and it is what makes
the 80% coverage floor reachable in an otherwise integration-shaped system.

| Module | Owns |
|---|---|
| `endpoint` | `Endpoint`, `EndpointId`, `CredentialRef` |
| `health` | `EndpointHealth` state machine, EWMA RTT scoring |
| `profile` | `ConnectionProfile`, `ProfileKind`, `Carrier`, `Viability` |
| `tier` | `FailoverTier` — set from measurement, never inferred from kind |
| `path` | `NetworkPath`, `PathQuality`, `PathRole` |
| `rule` | `RoutingRule`, `RuleMatcher`, `Reliability` |
| `session` | `ConnectionSession`, `ConnectionEvent`, `FailureCause` |
| `probe` | Profile racing; success judged on usable throughput |
| `selection` | Tier 1 preference, Tier 2 consent gating |
| `failover` | Hysteresis-damped path transitions |
| `builtin_rules` | Non-deletable bypass set |

**Invariants**
- `CredentialRef` exposes no accessor returning plaintext.
- Constructing a `Deterministic` application rule is **impossible at the type level**.
- `FailureCause` has exactly seven variants; there is no `Unknown`.
- `Unreachable` endpoint health is never terminal.
- A path with no gateway cannot become `Carrying` while Profile A is active.

---

## dnet-ipc — the privilege boundary

Framing: 4-byte little-endian length prefix, then UTF-8 JSON.

| Module | Owns |
|---|---|
| `frame` | Length-prefixed framing; rejects malformed, oversized, truncated input without panicking |
| `protocol` | Request/response types, seven-variant error model |
| `server` | Pipe creation with explicit SDDL — never a NULL DACL |
| `authz` | Per-connection client identity; mutating ops require the interactive console user |

**Invariant**: every request is treated as hostile input. All paths, patterns, and identifiers are
validated server-side. Rejection is explicit — silent no-ops are a defect.

Contract: [`ipc-protocol.md`](../../specs/001-network-resilience-client/contracts/ipc-protocol.md)

---

## dnet-supervisor — child lifecycle

Applies to **both** cores.

| Module | Owns |
|---|---|
| `child` | Spawn with captured stdio, readiness detection, ready-timeout |
| `restart` | Jittered exponential backoff **with a ceiling and an attempt limit** |
| `reap` | Kills orphans from a prior crashed run before any adapter is created |
| `shutdown` | Terminates both cores and replays undo records on any stop |

**Invariant**: persistent failure terminates in `CoreFailedPersistently` and stops. It never loops
forever. Core stdout is parsed for health, never echoed raw to the user.

---

## dnet-config — core configuration

Generation is a **deterministic pure function** of domain state: identical input yields byte-identical
output, which makes configuration testable.

| Module | Owns |
|---|---|
| `primary` | Primary-core JSON; TUN present for every profile |
| `hysteria2` | **Omits** the bandwidth section unless Brutal is opted into |
| `brutal` | Opt-in path; requires recorded acknowledgement and both up and down |
| `reality` | VLESS+REALITY; borrowed TLS target domain is configuration, not a constant |
| `bind` | Profile A `direct` outbound bound to the AmneziaWG adapter |
| `endpoint_bypass` | Endpoint bypass rule, derived from the **same source** as the host route |
| `uapi` | AmneziaWG control over its named pipe |
| `amneziawg` | Peer **and** obfuscation parameters in one transaction |

**Invariants**
- The endpoint bypass rule and the host route are one fact in two places; divergence is the loop.
- A peer is never configured without its obfuscation parameters — a peer without them is a plain
  WireGuard handshake, exactly the signature the profile exists to avoid.
- Generated config files are ACL-restricted to SYSTEM and Administrators.

Contract: [`core-config.md`](../../specs/001-network-resilience-client/contracts/core-config.md)

---

## dnet-etw — connect-time attribution

Real-time consumer on `Microsoft-Windows-Kernel-Network`, subscribing to `TcpIpConnect` and its IPv6
counterpart.

| Module | Owns |
|---|---|
| `session` | ETW session lifecycle |
| `attribution` | 5-tuple to PID mapping |
| `cache` | Short-TTL cache with eviction |

**Critical constraint**: the PID is read from the **event payload**, never from `EVENT_TRACE_HEADER`.
Microsoft documents the header ProcessId as unreliable for network events because some are logged by
separate threads. Using it produces silently wrong attribution — the worst possible failure for a
routing decision.

**Honesty constraint**: attribution is inherently racy. The type is `Attribution::BestEffort`; there
is no `Exact` variant. A cache miss resolves to "no application rule matched", never to a guess.

Gated by SPIKE-O6: if cost or coverage fail, this module is cut from v1 and only destination rules ship.

---

## dnet-netstate — system state and its undo

| Module | Owns |
|---|---|
| `undo` | Undo record registry — registered **before** any mutation is applied |
| `host_route` | Endpoint host route via the physical gateway |
| `notify` | OS IP-interface change subscription (not polling) |
| `rebind` | Host-route rewrite **before** tunnel rebind, asserted by call ordering |

**Invariant**: restoration is owed unconditionally — on disconnect, exit, crash, and uninstall.
Recovery runs at service start as well as shutdown.

---

## dnet-provision — endpoint provisioning

| Module | Owns |
|---|---|
| `credential` | Rejects root credentials; warns on over-privileged scope |
| `secret` | DPAPI **user**-scope storage; excluded from logs, diagnostics, IPC, errors |
| `stages` | The provisioning stage machine |
| `ledger` | Records each resource **before** its create call is issued |
| `capacity` | Capacity exhaustion as a retryable outcome with alternative regions |
| `cleanup` | Idempotent; reports what it could not remove |
| `bootstrap` | Installs both server-side cores; keys generated on the server |
| `keepalive` | Idle-reclamation keepalive; absence fails the job |
| `verify` | Reachability gate — failure here creates no endpoint |

**Invariant**: recording a resource *after* its create call would lose exactly the resources most
likely to leak. The ledger writes first.

Contract: [`provisioning.md`](../../specs/001-network-resilience-client/contracts/provisioning.md)

---

## xtask — build tooling

Never ships to a user, so it is not a branding surface and is allowlisted by its own linter.

| Task | Enforces |
|---|---|
| `fetch-vendor` | Pins by commit SHA; verifies the fetched tree against the pin; rejects unpinned artifacts |
| `verify-vendor` | No Wintun source anywhere; Authenticode signature valid; licence texts present |
| `lint-branding` | Upstream vendor names confined to attribution surfaces |
