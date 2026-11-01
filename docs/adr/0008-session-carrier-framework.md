# ADR-0008: A session–carrier framework: persistent session, replaceable carriers, an enforced guard, a component registry

**Status**: **Proposed.** Awaiting the owner's decisions in §10. Nothing here is normative until approved; the
constitution, spec and plan still govern, and no code changes follow from this document until the spikes in §6 pass.
**Date**: 2026-10-31
**Evidence**: [`docs/research/2026-10-31-framework-research.md`](../research/2026-10-31-framework-research.md). Weakness numbers
(W1 to W11) and source claims below refer to it.
**Builds on**: ADR-0003 (obfuscation layers), ADR-0006 decision P3 (enforce the kill switch in the operating system, not yet
approved), ADR-0007 (the window).
**Would amend if approved**: `docs/architecture/system-architecture.md` §2 to §5; spec FR-016b (what a tier describes);
the constitution's "v1 transports" sentence (§5 below). The constitution's principles are not weakened.
**Requires**: owner approval and a `docs/Research-Critique.md` entry, per Governance.

---

## 1. Context

The owner's concern (2026-10-31): the project does what similar tools already do by standard methods, and until the
*foundation* is right the product stays limited to standard behaviour. The audit and research found that the foundation is
sound in its parts and weak in its shape (research Part B). The six findings that matter most:

- **W1 + W2:** one tunnel at a time, and the session is welded to the carrier, so any switch of method or network is an outage
  that resets every open connection. Today every profile is Tier 2 for exactly this reason.
- **W3 + W4:** selection restarts from nothing at each connect, from a closed list of three carriers.
- **W6:** fail-closed is a decision, not an enforcement; two published leak classes (TunnelVision, TunnelCrack's ServerIP)
  are unaddressed, and one is only avoided by accident of construction (LocalNet).
- **W8:** the riskiest code (a second core with its own adapter, hence the routing-loop hazard) is the least tested, and its gate has never passed.
- **W9:** no component model, so the service cannot say *which part* failed.

This ADR does not propose a new transport protocol or new cryptography. It proposes a different way of arranging what is
already there.

## 2. Goals (each is testable)

| | Goal | Measured by |
|---|---|---|
| G1 | **Survival.** An open connection survives a change of carrier and a change of network, for *every* carrier | An HV-07-style transfer in the lab, with a negative control that breaks it |
| G2 | **Switch time.** A hot switch is under one second observed; a cold switch is no worse than today's 30 s | Same test, gap measured |
| G3 | **Containment.** With the guard armed, nothing leaves the machine except the carrier to its endpoint and the allowances in §3.5, including at boot, during a switch, and after the service dies | A lab test with packet capture, with the guard disabled as the negative control |
| G4 | **Memory.** A second connect on a known network does not need a full race in the common case; what is remembered is small, local, decays and can be deleted | Scenario tests on the harness; a test that the diagnostics bundle never contains it |
| G5 | **Observability.** Every part has a state, a reason, a time and evidence | A contract test on `GetComponents` against the real service |
| G6 | **No new cryptography or transport code** of our own: encryption, TUN and carriers stay in the supervised core | Review: no new crypto dependency in the workspace |
| G7 | **Honesty.** No claim of concealment, anonymity or security beyond what is measured (FR-033, Principle VI) | The voice tests already in the window and the documents |

## 3. The framework

```text
      window · dnetctl · other clients
                │  control pipe (existing contract, additive changes only)
   ┌────────────▼──────────────────────────────────────────────────┐
   │ dnetd (LocalSystem)                                            │
   │  Conductor    decides: prepare / switch / retire carriers      │
   │  Registry     one state per part, with reason and evidence     │
   │  Memory       what worked on this network (local, bounded)     │
   │  Guard        OS-enforced containment (user-mode WFP filters)  │
   └───────┬─────────────────────────────────────────┬─────────────┘
           │ generates config, drives it (Clash API)  │ installs / removes filters
   ┌───────▼───────────────────────────────┐          │
   │ Primary core (one process, one TUN)    │          │
   │  rules · FakeIP · DNS capture          │          │
   │  SESSION  = a WireGuard endpoint        │ ◄── persists across carrier and path changes
   │  CARRIER  = selector{ leaf, leaf, … }   │ ◄── replaceable: Hysteria 2 · VLESS+REALITY · …
   │  one leaf per (carrier, path), each     │
   │  bound to its interface                 │
   └───────┬───────────────────────────────┘
        PATHS  Wi-Fi · cellular · Ethernet
           ─────────────── network ───────────────
   ┌───────▼───────────────────────────────┐
   │ Gateway (the person's own server)      │
   │  carrier servers → one loopback        │
   │  WireGuard endpoint → the internet     │
   └───────────────────────────────────────┘
```

### 3.1 Session (the new idea, and the old idea of Turbo Tunnel)

The tunnel session is a **WireGuard session inside the core**, identified by keys and not by an address or port, so it
keeps working when the packets beneath it start arriving over a different carrier or network (this roaming is WireGuard's
defining property). Open connections belong to this session. Switching what carries it does not end it. This is the
"inner session over a replaceable carrier" pattern of [Turbo Tunnel](https://www.usenix.org/conference/foci20/presentation/fifield),
reached by configuring components that already exist rather than writing a reliability layer. It also means the inner
protocol is not TLS, which matters because the literature shows encapsulated TLS handshakes are detectable
([USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue)).

### 3.2 Carriers

A carrier is a way to deliver the session's datagrams to the gateway: Hysteria 2 (QUIC, UDP) and VLESS+REALITY (TCP, TLS)
today; others as recipes (§3.7). Each *leaf* is one carrier on one path, bound to that path's interface. The core's
`selector` outbound picks the leaf; it is switched at runtime through the Clash API, and existing connections are kept
unless told otherwise. A carrier is **hot** when its leaf is connected and idle, **cold** when it is only configured.

### 3.3 Conductor (the existing engine, evolved)

`dnet-core`'s engine keeps its state machine, hysteresis, tier warnings and failure causes. Its actions change from
*start a tunnel / stop the tunnel* to **prepare** (bring a leaf up beside the working one), **switch** (move the selector
once the new leaf proves itself) and **retire** (take the old one down). A switch is then make-before-break. Inputs are the
registry's states and the memory's prior order, passed through the existing damping, so the Conductor is still pure
decision code with no I/O.

### 3.4 Memory

Per network, a small record: which carriers succeeded or failed, when, how often. Recorded by a *network key* computed
locally (a salted hash of the gateway's identity and the network's name; the salt never leaves the machine). It orders the
race (try what worked last time first, still verify) and, when a network is known to block a class of carrier, skips it
until a retry interval passes. It is bounded (a fixed number of networks, a fixed number of carriers each), decays, is
shown in Settings with a "forget this network" and "forget all", and is excluded from the diagnostics bundle by
construction. The mechanism is simple on purpose: Psiphon replays what worked per network, and Lantern's bandit per ISP
([sources](../research/2026-10-31-framework-research.md#part-c--what-comparable-systems-do)); Lantern also reported that
early luck can let one choice dominate, so a learned order here never removes a carrier permanently and is always re-verified.

### 3.5 Guard (ADR-0006 P3, made concrete)

A set of **user-mode Windows Filtering Platform filters** owned by one provider, installed by `dnetd`, that blocks all
outbound traffic except: loopback; the carrier process to its endpoint addresses and ports (matched by program, so no other
program can reach the endpoint's address, which closes the ServerIP gap); the tunnel adapter; address configuration (DHCP,
NDP); the control pipe; the built-in local ranges (fixed list, as now); and, only while a captive portal is being
satisfied, the portal's own address. Because a block filter wins over any route, a DHCP-supplied route
([TunnelVision](https://access.redhat.com/security/cve/CVE-2024-3661)) cannot steer traffic around the tunnel.
It follows the person's existing *intent* (T147): armed while the connection is meant to be on, including across a reboot or
a crash of `dnetd`, and removed when the person turns the connection off or uninstalls. This is not a kernel driver
(constitution: no kernel-mode drivers; Research-Critique C4 already notes user-mode WFP can permit and block by program). It
changes system state, so it needs its own undo records, a security review and the lockout-safety design in §9.

### 3.6 Registry

Every part is a component with a kind, an id, a state (`Unknown`, `Off`, `Starting`, `Ok`, `Degraded`, `Blocked`,
`Failed`), a reason in words, the time it changed, and evidence (latency, loss, restarts). Kinds: network path, carrier
leaf, session, endpoint, core process, adapter, routes, DNS handling, guard, captive portal. It is served by a new
read-only request (`GetComponents`, additive, no version bump) and by events. The window's live map of real parts (the
globe) and the diagnostics bundle are built on it, and `dnet-view` keeps its rule that every string is cleaned on both sides.

### 3.7 Recipes

The signed feed (ADR-0002) already carries client parameters. It grows to carry **carrier recipes** and default carrier
order, within bounds the client enforces, so an order or a parameter can change without a release. A carrier that needs a
new *core* still needs a release; the feed cannot change what the cores can do.

### 3.8 Gateway

The server script (`dnet-provision::bootstrap`) already runs the carrier servers and makes the keys on the server; it
would also run one WireGuard endpoint on the loopback interface that every carrier server forwards to. The ports to open
stay the same, and the WireGuard port is not exposed. A second endpoint (a second server) remains the answer to W5 and
should be offered in onboarding after the first works.

## 4. What stays, what changes, what is retired

| Stays | Changes (additive or evolved) | Retired (only after spike S3) |
|---|---|---|
| Constitution principles; privilege boundary; undo-before-apply and every ordering rule in `CLAUDE.md`; FakeIP and rules; signed feed verification; the harness and its negative controls; the window and `dnet-view`; the provisioning flow and its security properties; all existing tests until a requirement changes | `dnet-core` engine actions (prepare/switch/retire); `dnet-config` generation (WireGuard endpoint, selector, several leaves); `dnetd` orchestrator and `plan`; `dnet-netstate` (a `guard` module with undo records); `dnet-ipc` (`GetComponents`, guard state); `dnet-provision` script (loopback WireGuard); window (component map, Settings for memory and guard); tier semantics (below) | `amneziawg-go` as a second process with its own adapter, and the host-route rewrite that exists only for it. Until S3 passes it stays as a separate legacy profile, so nothing that works today is removed on a hope |

**Tier semantics.** Today a tier is a label on a profile. Under this framework survival belongs to the session, so what
is measured and shown is *"an open connection survived a carrier switch / a path change"*, recorded per carrier from
the HV-07-style test. The rule "tier comes from measurement, never from intent" is unchanged.

## 5. Constitution and spec impacts (listed, not assumed)

- **Principle I (non-negotiable)** is intact in letter and spirit: transport, encryption and the adapter remain the core's.
  The ADR records that the WireGuard session is the core's, not ours. If spike S1 shows the core cannot do this, the
  design does not proceed by writing our own session layer (rejected, §8).
- **"v1 transports: three probed profiles"** would read "three carriers (UDP-QUIC, TCP-TLS, and AmneziaWG as a legacy
  profile) carrying one session". The TCP-shaped fallback stays mandatory.
- **Deferred list.** MP-QUIC aggregation stays deferred. A hot standby carries nothing until it is switched to, so it is not
  aggregation; the ADR adds that sentence so the line is not blurred later. The [IETF multipath draft](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath)
  is approved and queued, so nothing here should make it harder later.
- **Proposed new requirements**: FR-041 (OS-enforced containment while the connection is meant to be on), FR-042 (a
  state, reason and evidence for every part), FR-043 (per-network memory: local, bounded, deletable, never in diagnostics),
  FR-044 (a standby carrier's network and battery cost is budgeted, in `docs/network-budget.md`).
- **FR-033 stands, unchanged:** the documentation and window keep saying the tunnel's existence, volume and destination
  remain visible to the network, and nothing here is a claim of anonymity.
- **Resource budget:** standby carriers add idle traffic and a little memory; spike S6 measures it before the budget is amended.

## 6. Spikes: nothing is built until these answer (Principle III: harness only, never a live network)

Each has a pass, a fail, and a negative control (a version of the test that must fail, so the test is known to be able to).

| | Question | Pass | If it fails |
|---|---|---|---|
| **S1** | In the **pinned** core (v1.14.0, tags `with_quic,with_utls,with_clash_api,with_gvisor,with_external_windivert`), can a WireGuard endpoint use a Hysteria 2 outbound as its `detour`, and what build tag, if any, is missing? (The documentation confirms the pieces exist; it does not confirm this combination.) | Traffic flows end to end in the harness; with a wrong carrier key none does | The design in §3.1 is not available with this core: stop, record, and take alternative A (§8) |
| **S2** | Does *switching* the selector actually move a live inner session to the new carrier, and do open connections survive? (Risk R1: the UDP association may stay on the old leaf until it closes.) | A 500 MB transfer completes in one connection across carrier switches in both directions and across a path change; gap measured. Control: the same test against today's architecture breaks the transfer | Try a different switching mechanism; if none, alternative A |
| **S3** | Can inner WireGuard under the carriers replace AmneziaWG under the harness conditions (signature-based dropping of WireGuard handshakes; total UDP block)? | Parity with HV-03 | Keep AmneziaWG as a separate legacy profile (no retirement) |
| **S4** | The guard, on a lab VM: (a) a rogue DHCP server with option 121 cannot divert traffic; (b) killing `dnetd` leaves nothing leaving; (c) boot ordering; (d) the control pipe, uninstall and `guard-release` still work (lockout safety); (e) a program other than the core cannot reach the endpoint address | All five. Control: the guard disabled shows the leak in (a), (b) and (e) | Redesign the filter set; do not ship a guard that can lock a person out |
| **S5** | Memory: does replay shorten a connect in simulated network moves, and is it absent from every diagnostics output? | Faster in the scenarios; absent by test | Memory stays off |
| **S6** | Cost of the extra layer: throughput, CPU, MTU, idle bytes of a hot standby | Within the budget in `docs/network-budget.md`, or the budget is amended by the owner | Standby stays cold |

## 7. Order of work

Ordered so that what helps *whatever* is decided comes first.

1. **P0, baselines.** Run the owner gates that do not depend on this design (T098a against a hand-made VM; the section 5 to 9
   commands of `LOCAL-COMMANDS.md`). S2 needs a baseline from today's architecture.
2. **P1, Registry and the live map** (§3.6): independent of the session change, fixes W9 now, and is the data behind the
   globe the owner described. Replaces nothing.
3. **P2, Guard** (§3.5), after S4 and the owner's approval of P3.
4. **P3, spikes S1, S2, S3, S6**, then a go/no-go recorded here.
5. **P4, session–carrier in generation, orchestrator and server script**; the engine's actions change here.
6. **P5, Memory and hot standby tuning** (S5).
7. **P6, recipes** live, which needs the key ceremony (T066d).

Steps 2 and 3 are worth doing even if step 4 never happens.

## 8. Alternatives considered

- **A. Keep the architecture; add Guard, Registry and Memory only.** Fixes W6, W9 and part of W3. Does not fix W1, W2 or W8.
  *This is the fallback if S1 or S2 fail, and a sound product.*
- **B. Write our own session layer in Rust (a Turbo Tunnel in the project's code).** Rejected for now: new
  reliability and authentication code is exactly what Principle I forbids reimplementing, and it is where the subtle bugs would be.
- **C. Multipath aggregation.** Deferred by the constitution; revisit when the IETF draft is an RFC and there is a library.
- **D. A relay mesh like Tailscale's.** Needs infrastructure the project would operate; the project operates none.
- **E. Replace the core.** No reason found; the core is the part that works.

## 9. Risks, and what would make this wrong

- **R1 (the crux): switching may not move a live inner session.** A selector change might not move a UDP association that is
  already open. S2 exists for this. If it does not move, the design needs a different switching mechanism or does not work with this core.
- **R2: TCP carrying UDP.** The REALITY carrier delivers datagrams over a TCP stream, so loss on it stalls everything behind
  it, and TCP inside TCP behaves badly. It stays the *fallback* carrier and is measured (S6), as Turbo Tunnel's own numbers warn
  (in one test a naive session over a request-response carrier took about 1.5 times as long as the plain carrier).
- **R3: double layer cost.** Two encryptions and less room per packet. Measured in S6.
- **R4: the guard can lock someone out.** Mitigations: it never blocks the control pipe or loopback; every filter carries one
  provider key so one call removes all of them; `dnetctl guard-release` and the uninstaller remove it; it is armed only while the
  person's intent is *on*; and S4(d) is a gate. It needs the project's mandatory security review and an owner lab run.
- **R5: memory is personal data** (it records which networks the person used). Hashed with a local salt, bounded, deletable, never exported.
- **R6: scope.** A large change after a lot was built. Mitigated by the phase gates, by keeping AmneziaWG until S3, and by the fact that P1 and P2 stand alone.

## 10. Decisions for the owner

| ID | Decision | Recommendation |
|---|---|---|
| **F1** | Approve this direction as the plan, meaning spikes S1 to S3 and S6 first, and no code until they answer | Yes |
| **F2** | Approve ADR-0006 P3 (OS-enforced guard), including that it stays armed across reboot and crash while the connection is meant to be on | Yes, after S4 |
| **F3** | AmneziaWG: keep as a legacy profile now; retire only if S3 passes | Keep for now |
| **F4** | Per-network memory: allowed on the terms in §3.4 | Yes |
| **F5** | Approve the constitution and spec wording changes in §5 once the spikes pass | After the spikes |
| **F6** | Whether P0 (the live gates) must pass before P1 starts, or in parallel | In parallel: P1 needs no gate |
| **F7** | The owner's earlier wish that users "stay anonymous" and "secure": this ADR does **not** deliver or claim it, for the reasons in FR-033 and the research (Part C.2, Part D) | Keep FR-033 |

## 11. Addendum (2026-10-31): what the deep audit changes

Evidence and sources: [`docs/research/2026-10-31-framework-deep-audit.md`](../research/2026-10-31-framework-deep-audit.md). It does
not change the direction above; it tightens three sections, adds three spikes and reorders the first steps.

**Tightens §3.5 (Guard).** (a) The filters are **persistent**, not dynamic, because a dynamic object disappears when `dnetd`
dies, which would leave the crash case open. (b) Their provider names the `DNetEngine` Windows service, so that, by the
platform's own rule, a disabled or uninstalled service means the block is not applied at the next start. This is the
lockout-safety mechanism R4 was missing. (c) The allow list is at least the reference one (tunnel adapter, own service matched by
program path **and** user, loopback, DHCP, neighbour discovery) **plus Hyper-V VM-to-VM traffic**, so the lab's Docker and WSL
keep working. (d) The design covers a transaction timeout, a filtering-service restart and third-party firewalls.

**Spikes S1 and S2 are answered** (run 2026-10-31 on the pinned commit, loopback only; evidence and harness in
[`testing/spike-carrier/`](../../testing/spike-carrier/README.md), reasoning in
[the solutions file](../research/2026-10-31-solutions.md)):
- **S1 passes, but only with a build change.** The shipped core has no `with_wireguard` tag and refuses a WireGuard endpoint. With
  the tag added, a WireGuard session whose socket goes through a Hysteria 2 outbound (`detour`) carries traffic. The server core
  needs `with_wireguard` and `with_gvisor` as well. This amends ADR-0004's tag list and the server-core test that forbids `gvisor`.
- **S2 passes.** Switching the selector keeps an open transfer alive in one connection, in both directions, between the QUIC
  and the REALITY (TCP) carriers, and after the carrier server was killed. The control (today's shape) broke. The switch needs one
  addition the earlier text did not have: **a nudge**, small probes through the session right after the switch, which took the
  largest stall from 12.6 s to 0.02 s. Risk R1 is closed for this core; R2 is measured (the REALITY carrier was the faster one on
  loopback; the QUIC datagram leg was the expensive one).
- **Still open:** real round-trip times and loss, the Windows adapter, the guard, and the free server's CPU (S4, S6, S9).

**Tightens §3.1 and §3.3 (switching).** The selector is switched through the core's Clash API, which would be the project's first
local control endpoint. Measured on the pinned build: it has no Host check and a TCP listener only, an empty cross-origin list
means allow-all, and an empty secret disables authentication. So: loopback and a random port, a random per-run secret held by the
service alone (the service refuses an empty one), a cross-origin list naming one impossible origin, and a guard rule that lets only
`dnetd` reach the port (audit E10; solutions §3.1).

**Replaces §3.8 (Gateway) in part.** The server profile becomes one process: both carriers locked to the session port, one
WireGuard peer per device, and an exit that refuses private destinations except the measurement origin. Validated end to end
(`run.py combined`). It fixes audit E1, E2 and E12 together; the unit can run unprivileged because the exit is user space.

**Adds to §5 (impacts).** The control pipe grows a split of read-only detail (console user and administrators only) and a
confirmation for any mutation that changes where traffic goes (audit E3, E4, G5). This touches the IPC boundary: security review.

**New spikes.**

| | Question | Pass | If it fails |
|---|---|---|---|
| **S7** | Do full-size packets get through each profile across a 1280-byte-MTU path, and which tunnel `mtu` and packet stack setting should be the default? | No black-holed transfer; defaults chosen by measurement | Set a conservative `mtu` and record the cost |
| **S8** | Suspend and resume a lab VM while connected, guard on and off: time to a working tunnel, and nothing leaves while it is blocked | Back within the failover target with no leak | Add power-event handling (audit G6) before the guard |
| **S9** | Throughput and CPU of each packet-stack setting on the owner's laptop | Numbers recorded and defaults chosen | Keep the current default and say so |

S4 gains: IPv6-only and dual-stack networks (audit E8), name queries beyond DNS (LLMNR, NetBIOS), and the persistent-filter lifetime
cases (service stopped, disabled, uninstalled, filtering service restarted).

**Reordered start of §7.** Before P1 comes **P0.5: server profile v2** (audit G2: reject private destinations, a credential per
device, automatic security updates, a truthful firewall step) and **control-pipe hardening** (G5). Neither waits for a spike; both
need the mandatory security review and a run on a real server. Then P1 as written.

**New owner decisions.**

| ID | Decision | Recommendation |
|---|---|---|
| **F8** | Make server profile v2 (audit G2) the first code change, under the security review | Yes. **Approved 2026-10-31** (the owner told the session to proceed with the plan that named it). Not started: the build tag (T155) and the configuration generator (T156) came first |
| **F9** | Limit read-only detail to the console user and administrators, and ask for confirmation when a change redirects traffic (G5) | Yes |
| **F10** | Allow a Network Truth report (G3, measured facts about the network, no claims) and an opt-in hostile-network posture (G4, changes system settings, needs its own ADR) | Network Truth yes; posture only after its ADR |
| **F11** | Verification investment (G7): a Windows runner in CI for the elevated tests, a network-weather replay library, fuzz targets | Weather library and fuzz targets yes; the runner is your call on cost |
| **F12** | Add `with_wireguard` to the client core's build tags and `with_wireguard,with_gvisor` to the server core's (amends ADR-0004; changes the pin file, the notices and the installer size) | Yes: S1 and S2 passed with it, and the design does not work without it. **Approved and done 2026-10-31 (T155)**: the rebuilt core is 0.76 MB larger |
| **F13** | Require approval by an elevated (UAC) client for changes that redirect traffic (audit E3; solutions §3.2) | Yes |

## 12. Build status (2026-11-01)

What exists, with the evidence; nothing in it is committed yet. Task numbers are in `specs/001-network-resilience-client/tasks.md`.

| Part | State |
|---|---|
| Core build tags (F12) | Done (T155). The client core is 43,893,248 bytes (+0.76 MB). The server core was not rebuilt (a Linux cross-build) |
| Session configuration and a probe through the session | Done (T156, T169): generated, and accepted by the **real pinned core** |
| Carrier switch and nudge | Done (T157, T169): `session_switch.rs`, used by the real effects; the listener check (T169 d) is in place |
| Live move in the connection layer | Done (T169 e): the orchestrator folds a stop-then-start into a move, tries it live, and falls back to the old stop-then-start |
| Server profile v2 (F8) | Done as far as it can be shown without a real server (T158): the script, the plan, the version-2 report; the real core checks the configuration the script writes |
| Per-device credentials | Done (T159): stored as format version 2 only when a session is present |
| The whole composed on loopback | `crates/dnetd/src/session_e2e.rs`: the script's server configuration and the generator's client configuration in two real cores; the origin is reached, the exit refuses the machine it runs on, a carrier credential alone reaches nothing, and a 14 MB transfer crosses a switch to the TCP carrier and back in one connection (longest silence 0.2 s) |
| Not done | Guard v2 (T161), the Registry and the live map (P1), power and session awareness (T162), the job object for the cores (T163), the hostile-network re-run of the spike (T164), UAC approval (T160), Memory (P5) |

**What building it changed in this ADR's design.** (1) The session's measurement origin cannot be the server's own session address (the
server's network stack answers it); it is `10.9.0.254`. (2) The client's built-in rules sent every private address, including a
measurement origin, around the tunnel; the two origins now have single-address tunnel rules ahead of the private ranges (this also
corrects the existing AmneziaWG origin). (3) A server that serves the session cannot be used by the old per-profile Hysteria 2 and REALITY
configurations, so the client's use of the session had to land with the server profile (T169). (4) The unprivileged account on the server
must not own its directory (root keeps it, group read only). Details: `docs/research/2026-10-31-solutions.md` section 10.

**What is still unproven.** Real delay and loss, the Windows tunnel adapter with a live move, the guard, the script as root on a real
Linux image, the free server's CPU with the user-space exit, and the REALITY handshake against a real site. S4 (guard), S7 to S9 and the
real-server run in `LOCAL-COMMANDS.md` section 8 settle them.
