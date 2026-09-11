# Phase 0 Research: DNet Engine v1

**Date**: 2026-09-10 | **Plan**: [plan.md](./plan.md)

Every decision below cites a primary source per Constitution Principle II. The source blueprint's
citation list is not used. Where a question could not be settled from documentation alone, it is
recorded as a **spike** with an explicit gate rather than asserted.

---

## R1 — Transport delegation: two supervised processes, not one

**Decision.** `dnetd` supervises **two** third-party transport processes:
- the **primary core** — provides the TUN inbound, FakeIP, rule-based routing, Hysteria 2, and
  VLESS+REALITY;
- **`amneziawg-go`** — provides AmneziaWG only.

**Rationale.** The primary core does not implement AmneziaWG. Its outbound list contains WireGuard
but no Amnezia obfuscation parameters; the pull request adding support was closed unmerged and the
standing feature requests are closed. Plain WireGuard is not a substitute — it is precisely the
fingerprintable protocol AmneziaWG exists to disguise, and shipping it as the "obfuscated" profile
would breach Constitution Principle VI.

**Alternatives considered.**
- *Switch the primary core to mihomo/Clash.Meta*, which does support AmneziaWG — rejected: replaces a
  settled dependency late for the sake of one profile, and forfeits the primary core's REALITY and
  FakeIP maturity.
- *Drop AmneziaWG* — rejected: leaves a single UDP profile, gutting the premise of D3 that multiple
  independently-fingerprinted UDP options are what survive an unknown appliance.
- *Implement AmneziaWG in Rust* — rejected by Constitution Principle I.

**Source.** Primary core outbound documentation; repository PR #2670 (closed, unmerged).
Recorded as finding C14 in `docs/Research-Critique.md` §6.2.

---

## R2 — Congestion control: BBR by default is a config-emission decision

**Decision.** `dnet-config` omits the `bandwidth` section from the Hysteria 2 profile unless the user
explicitly opts into Brutal. Opting in requires entering measured up/down rates and acknowledging a
warning.

**Rationale.** Hysteria 2 activates Brutal **if and only if** a `bandwidth` section is present;
absent it, the client falls back to `congestion` (default `bbr`, `standard` profile). No patching,
no forking, no runtime override is needed — the default is achieved by writing less configuration.

**Alternatives considered.** Explicitly emitting `congestion: {type: "bbr"}` — harmless but
redundant; omission is the documented mechanism and less likely to break across core versions.

**Source.** Hysteria 2 full client configuration documentation.

---

## R3 — FakeIP ranges

**Decision.** `inet4_range: 198.18.0.0/15`, `inet6_range: fc00::/18`.

**Rationale.** These are exactly the primary core's documented defaults, and `198.18.0.0/15` is the
RFC 2544 benchmarking range — non-routable, so no legitimate destination collides with it.

**Risk retained.** Some security tooling and development servers treat `198.18.0.0/15` as an internal
address and refuse requests to it. Mitigation is to ensure the OS route table sends the range to the
TUN so it is a valid route; if a specific tool still refuses, the range is configurable. This is a
support-documentation concern, not an architectural one.

**Source.** Primary core FakeIP server documentation.

---

## R4 — TUN adapter ownership when AmneziaWG is active *(highest-risk decision)*

**Problem.** Two supervised processes each want a virtual adapter. The primary core creates a TUN for
capture; `amneziawg-go` creates its own Wintun adapter for the AmneziaWG tunnel. Naively running both
produces either a capture conflict or a routing loop in which AmneziaWG's own outbound packets are
captured by the primary core's TUN and fed back into the tunnel.

**Decision.** The primary core **always** owns the capture TUN, FakeIP, and rule evaluation, for all
three profiles. When Profile A (AmneziaWG) is selected:

1. `amneziawg-go` creates its own Wintun adapter, `awg0`, and establishes the tunnel to the endpoint.
2. The primary core's active outbound becomes a `direct` outbound with `bind_interface: "awg0"`.
3. `dnet-netstate` installs a **host route for the endpoint address via the physical gateway** with a
   low metric, so that AmneziaWG's own encrypted UDP egresses on the physical interface and is never
   captured by the primary core's TUN.

This keeps FakeIP and the rule set uniform across all three profiles, which is what makes Tier
labelling, per-domain routing, and probing behave identically regardless of which profile is active.

**Failure mode if step 3 is wrong.** A routing loop: encrypted packets re-enter the tunnel, throughput
collapses to zero, and the symptom presents as a successful handshake with no traffic. This is the
same class of bug as the FakeIP resolution-loopback issues the source blueprint cited. The endpoint
host route must be installed **before** AmneziaWG is started and removed **after** it stops, and its
presence must be asserted in the failover path when the physical interface changes — a new interface
means a new gateway means the host route must be rewritten.

**Alternatives considered.**
- *Let `amneziawg-go` own the only adapter and bypass the primary core entirely for Profile A* —
  rejected: Profile A would lose FakeIP, domain rules, and process attribution, making product
  behaviour depend on which profile happened to be selected. Directly breaches Principle VI.
- *Route into AmneziaWG via a local SOCKS proxy* — rejected: `amneziawg-go` exposes no proxy
  interface; it is a pure L3 tunnel.

**Confirmed available.** `bind_interface` is a documented Dial Field on outbounds ("the network
interface to bind to"), alongside `detour`, `inet4_bind_address`, and `routing_mark`.

**Gate — SPIKE-R4, Phase 3.** Before Phase 3 is accepted, demonstrate inside the harness: traffic
flowing end-to-end via Profile A; zero loop (verified by packet count on `awg0` versus the physical
interface); and correct host-route rewrite across a simulated interface change. Phase 3 does not pass
without this.

**Source.** Primary core dial-fields documentation; `amneziawg-go` architecture documentation.

---

## R5 — Configuring AmneziaWG at runtime

**Decision.** `dnetd` configures `amneziawg-go` over its **UAPI named pipe** at
`\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\<adapter>` (corrected 2026-09-11 from
`WireGuard\awg0` after verifying the pinned core's source), writing text `key=value` lines. Obfuscation
parameters (the header-magic and junk-packet settings) are set through the same channel.

**Rationale.** This is the process's native control interface on Windows and requires no file
watching or restart to change peers or parameters. The pipe's ACL restricts it to Administrators,
which `dnetd` satisfies as LocalSystem and the tray does not — reinforcing Principle V for free.

**Consequence.** `dnetd` must run as LocalSystem or an Administrators-group service account. Recorded
as a constraint on the service installer.

**Source.** `amneziawg-go` IPC implementation (`ipc/uapi_windows.go`); AmneziaWG Windows client
documentation.

---

## R6 — Wintun: bundled signed binary only

**Decision.** `vendor/wintun/` contains the vendor's **signed prebuilt DLL** and its permissive
licence text. No Wintun source is fetched, vendored, or compiled. `xtask verify-vendor` asserts the
Authenticode signature and fails if any Wintun source file is present.

**Rationale.** Wintun's source is GPLv2, which is incompatible with this project's GPLv3. The
prebuilt signed DLLs carry a separate, more permissive licence expressly to permit redistribution,
and the vendor states the signed DLLs are the only supported distribution method. Bundling the binary
therefore both satisfies the licence and follows vendor guidance.

**Note.** `dnetd` links no Wintun bindings itself — both supervised cores load the DLL. This removes
a dependency the source blueprint assumed was necessary.

**Source.** wintun.net licensing and distribution statement. Recorded in `docs/Research-Critique.md`
§6.1 as a binding obligation.

---

## R7 — Process attribution via ETW

**Decision.** A real-time ETW consumer on `Microsoft-Windows-Kernel-Network` subscribes to
`TcpIpConnect` (and its IPv6 counterpart), reading **`PID` from the event payload** together with
`saddr`, `sport`, `daddr`, `dport`, and populating a short-TTL 5-tuple to PID cache that rule
evaluation consults.

**Critical constraint.** The PID **must** be read from the event payload, never from
`EVENT_TRACE_HEADER`. Microsoft documents that the header's ProcessId is unreliable for network
events because some are logged by separate threads. Using it would produce silently wrong
attribution — the worst possible failure for a routing decision.

**Honesty constraint.** Attribution is inherently a race: a connection can be established and closed
between the event and rule evaluation. The domain type is `Attribution::BestEffort`, the UI says so,
and destination rules remain the deterministic path (Principle VI, FR-023).

**Gate — SPIKE-O6, Phase 0.** Measure steady-state CPU cost of the ETW session and the proportion of
connections successfully attributed, on a machine with a realistic socket population. If cost breaches
the idle-CPU budget (SC-014) or coverage is too low to be useful, per-process routing is cut from v1
and only destination rules ship. Decision recorded before Phase 5.

**Source.** Microsoft Learn `TcpIp` ETW class documentation and `TcpIp_TypeGroup1`/`TypeGroup3` field
definitions.

---

## R8 — Privileged/unprivileged split and IPC

**Decision.** `dnetd` runs as a Windows Service (LocalSystem). `dnet-tray` runs unprivileged in the
user session. They communicate over a **named pipe** with an explicit SDDL granting access only to
Authenticated Users, with `dnetd` additionally verifying the connecting client's token per
connection. Mutating operations require the caller to be the interactive console user.

**Rationale.** A named pipe avoids a loopback TCP port, which endpoint-security software on managed
machines frequently blocks — the same reasoning that makes native messaging the right browser channel
in v2. `tokio::net::windows::named_pipe` provides async server and client without extra dependencies.

**Alternatives considered.** Loopback HTTP with a bearer token — rejected: blockable by local
security software, and binds a listening port on a machine whose administrator may notice. COM/RPC —
rejected as disproportionate.

**Contract.** [contracts/ipc-protocol.md](./contracts/ipc-protocol.md).

---

## R9 — Interface change detection and failover tiers

**Decision.** `dnet-netstate` registers for OS IP-interface change notifications rather than polling,
and drives the failover state machine in `dnet-core`. Profiles carry a declared `FailoverTier`:

| Profile | Tier | Basis |
|---|---|---|
| AmneziaWG | **1** — established connections survive | WireGuard-family peers are keyed, not address-bound; the peer endpoint is re-learned on the new path. |
| Hysteria 2 | **1** — established connections survive | QUIC connection migration. |
| VLESS+REALITY | **2** — access only, connections break | Runs over TCP; a change of source address terminates the connection. |

`dnet-core` prefers a Tier 1 profile whenever more than one profile is viable (FR-016b).

**Gate — SPIKE-R9, Phase 6.** Tier 1 survival is a property of the pinned core versions, not merely
of the protocols. Phase 6 does not pass until an open transfer is demonstrated surviving an interface
change on **both** Tier 1 profiles inside the harness. Any profile that fails is demoted to Tier 2 in
configuration and in the UI — the label follows the measurement, not the intention.

**Source.** Hysteria 2 protocol documentation (QUIC migration); WireGuard protocol design (roaming).

---

## R10 — Cloud provisioning with a scoped credential

**Decision.** The wizard provisions via the cloud provider's REST API using an **API signing key
belonging to a dedicated, least-privilege IAM user** that the wizard walks the user through creating.
It never accepts account or tenancy root credentials. The key is stored under DPAPI user scope, is
excluded from all logs and diagnostics, and the wizard offers to delete it once provisioning
completes.

**Rationale.** Full automation is what makes SC-009 (20 minutes, unaided) and SC-010 (90% first-session
success) reachable, but a GPLv3 desktop application holding a credential that can create billable
cloud resources is a genuine target. Scoping the credential to exactly the compute and networking
permissions provisioning requires, and making revocation a single documented step, bounds the damage.

**Provisioning must handle, not merely report:** regional capacity exhaustion for free-tier compute
(retry, then offer alternative regions with their latency cost stated), partial failure (record
created resources so cleanup is possible — FR-011, SC-011), and **idle reclamation** (the provider
reclaims free compute idle below a threshold, so the bootstrap installs a keepalive).

**Alternatives considered.** Guided manual creation in the provider console — safer but misses the
onboarding criteria and pushes cleanup onto the user. Storing a tenancy-wide key — rejected outright.

**Contract.** [contracts/provisioning.md](./contracts/provisioning.md).

---

## Residual unknowns

| ID | Question | Gate | Blocks |
|---|---|---|---|
| **SPIKE-R4** | Does the bind-interface + host-route design carry traffic without a loop? | Phase 3 acceptance | All transport work |
| **SPIKE-O6** | Is ETW attribution affordable and accurate enough to ship? | Phase 0 measurement | FR-023 only |
| **SPIKE-R9** | Do both Tier 1 profiles actually survive an interface change at the pinned versions? | Phase 6 acceptance | FR-016a labelling |
| **O5** | Integrity model for the profile update feed | Phase 4 design | FR-007, FR-008 |
| **O7** | Does the pinned core implement the newer obfuscation layer, or only the older one? | Phase 4 tuning | Profile B tuning only |

All other Technical Context entries are resolved. No `NEEDS CLARIFICATION` markers remain.
