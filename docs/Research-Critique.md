# DNet Engine — Research Critique & Decision Record

**Status:** Specification phase. No implementation started.
**Date:** 2026-09-10
**Reviews:** `docs/DNet-Engine-Research.md` (unverified source blueprint), `docs/Steps.docx` (Spec Kit + Docker test-rig guide)

This document records (1) a critical review of the source research, (2) the decisions taken to
resolve its open questions, and (3) the corrections applied to those decisions. It is the input to
`.specify/memory/constitution.md` and the forthcoming `/speckit.specify` run.

---

## 1. What DNet Engine Is

**Problem.** On a campus/hostel network the user has two simultaneously inadequate uplinks:

- **Institutional Wi-Fi** — oversubscribed, high jitter, heavy loss from AP contention, filtered by a
  UTM appliance (Sophos XG / Cyberoam / Fortinet class) performing DPI, port blocking, deep NAT, and
  traffic shaping. DNS on port 53 is hijacked and answers are forged.
- **4G/5G cellular** — severely attenuated indoors; drops without warning.

Neither path is individually reliable. Conventional VPNs are fingerprinted and dropped.

**Product.** A Windows background daemon plus tray UI that restores usable connectivity by
tunnelling traffic through an obfuscated transport to a user-owned exit node outside the firewall,
resolving DNS locally via a FakeIP pool, routing per-domain and (best-effort) per-application, and
failing over seamlessly between Wi-Fi and cellular.

**What DNet Engine is *not* (see §4.8).** It is not a from-scratch VPN protocol implementation. The
transport cores already exist and are battle-tested. DNet Engine's value is the **automation and UX
layer** on top of them: zero-config onboarding, automatic exit-node provisioning, active probing of
which transport currently survives the local firewall, automatic profile switching when one is
blocked, seamless interface failover, and a tray-first interface a non-technical user can operate.

---

## 2. Legal & Ethical Position (stated, not hidden)

Every component named here is open-source and legal to write, and network-resilience tooling is a
legitimate engineering domain. Two facts belong in the record anyway:

1. **Use on an institutional network is very likely an AUP violation** with disciplinary
   consequences, independent of whether the traffic is classifiable.
2. **Obfuscation defeats signature DPI, not volume analytics.** Sustained high-entropy UDP to a
   single unfamiliar IP is conspicuous to flow-analytics dashboards even when the protocol cannot be
   identified. The design should assume the *existence* of the tunnel may be inferable; only its
   *contents* are protected.

The project is positioned publicly as a **self-hosted network resilience and tunnel client**, ships
with an AUP warning in the README and first-run flow, and is not marketed as a school-firewall
bypass. This is both accurate and protective of the project.

---

## 3. Critique of the Source Research

### 3.1 What the research got right

- **FakeIP subsystem.** The concept, the `198.18.0.0/15` (RFC 2544) pool choice, and the
  intercept → synthesize → capture-on-TUN → reverse-lookup → route-by-domain sequence are correct
  and match how Clash and sing-box actually work.
- **Rust + Tokio + Wintun with OVERLAPPED I/O** for the packet loop — correct instinct; blocking I/O
  in a TUN read loop is a genuine latency killer.
- **Tauri v2 over Electron** for a tray utility — correct.
- **Chromium Native Messaging as the browser IPC channel** — correct choice, for the right reason
  (loopback ports are frequently blocked by endpoint security), though the process topology
  described is wrong (C8).
- **Docker + `tc netem` local test harness** (from `Steps.docx`) — this is the single best idea in
  the source material and is promoted to a **Phase 0 deliverable**. Nothing gets tested against a
  live institutional network.

### 3.2 Material errors and omissions

| ID | Finding | Severity |
|----|---------|----------|
| **C1** | **No exit node anywhere in the architecture.** The document asserts "entirely self-hosted, no cloud" repeatedly. AmneziaWG and Hysteria 2 are client-to-**server** protocols; the tunnel must terminate outside the firewall. Without a server there is no product. | Blocking |
| **C2** | **MPQUIC is a research project, not an integration.** Multipath QUIC is an IETF draft. `quinn` does not implement it; `quiche` has partial support. Implementing MPQUIC + an ECF scheduler *and* a compatible server is plausibly 60–70% of total effort. The document treats it as a config option. | Blocking (deferred, §4.4) |
| **C3** | **AmneziaWG and MPQUIC are mutually exclusive.** AmneziaWG is WireGuard: one UDP socket, one path, no stream multiplexing. It cannot sit on a multipath QUIC scheduler. Hysteria 2 is also single-path. The document's table presents them as complementary layers; they are alternatives. | High |
| **C4** | **Per-PID split tunnelling on Windows implies a kernel driver.** User-mode WFP can inspect and permit/block by PID; it cannot redirect a flow into a TUN. Reliable per-app routing means a kernel-mode WFP callout, hence an EV cert plus attestation signing. Incompatible with the zero-cost constraint. | High |
| **C5** | **Brutal CC's premise is unevidenced and probably wrong.** The document asserts hostel Wi-Fi loss is radio interference, not congestion. On an AP with hundreds of clients most loss *is* contention. Brutal will amplify collapse, degrade every other user on the AP (including the operator), require manually configured bandwidth, and make the flow highly conspicuous. | High |
| **C6** | **The NTFS sparse-file rationale is factually incorrect.** NTFS does not zero-fill on `SetEndOfFile`; it tracks a *valid data length* and zeroes lazily on read. The instant-preallocation primitive is `SetFileValidData` (requires `SE_MANAGE_VOLUME_NAME`). Worse, sparse files written at random offsets *increase* fragmentation — the opposite of the claim. | Medium (feature deferred) |
| **C7** | **Parallel chunked downloads are largely placebo here.** Range requests only defeat per-connection server-side throttling. If the bottleneck is the uplink or the tunnel, N connections split one pipe N ways and add overhead. | Medium (deferred) |
| **C8** | **No privilege separation, and the Native Messaging topology is wrong.** The NM host is spawned as a *child of the browser* at user privilege — it cannot be the privileged daemon. Correct shape: privileged Windows Service, reached over an authenticated named pipe by an unprivileged Tauri UI and an unprivileged NM stub. Extension ID must be pinned; an unpinned extension able to rewrite system routing is a local privilege-escalation surface. | High |
| **C9** | **No TCP fallback.** Both proposed transports are UDP-only. Many UTM configurations block or throttle arbitrary outbound UDP. Without a TLS-shaped TCP transport the product is dead on those networks. | High (resolved, §4.3) |
| **C10** | **FakeIP edge cases unaddressed:** browsers default to DoH so their queries never reach the local resolver (silently defeating FakeIP for the primary use case); IPv6 and Happy Eyeballs racing; apps with hardcoded IPs; captive-portal probes (`msftconnecttest.com`) needing exemption; the known FakeIP resolution-loopback bug class the document itself cites but does not design around. | High |
| **C11** | **Five-platform scope is unrealistic.** iOS needs a paid Apple Developer account and a Network Extension with a ~50 MB memory ceiling; macOS needs a specific entitlement; Tauri mobile is immature. | Medium (resolved, §4.7) |
| **C12** | **Licensing unverified.** Wintun's prebuilt-binary redistribution terms, and the fact that `amneziawg-go`, Hysteria 2 and Xray-core are all **Go**, not Rust — a Rust-native stack means reimplementing protocols from spec. | High (resolved, §4.8) |
| **C13** | **The citation list does not support the technical claims.** Refs 1–6 and 18–19 are university annual reports, a 5G health blog, and a Scribd blog compilation; ref 15 points to a GitHub issue that appears fabricated. The genuinely authoritative sources are the Hysteria 2 protocol docs, sing-box docs, the Clash wiki, the AmneziaWG repository, and the MPQUIC scheduler papers (refs 28, 32–38). **Every protocol-level claim must be re-verified against primary sources before entering the spec.** | High |

---

## 4. Decisions

Decisions D1–D10 answer the blocking questions. Each records the decision *and* the correction or
caveat applied to it.

### 4.1 D1 — Exit node: Oracle Cloud Always Free

**Decision.** Terminate on an Oracle Cloud Always Free Ampere A1 instance (currently 2 OCPU /
12 GB after the global reduction from 4/24). Vastly overprovisioned for a tunnel endpoint, and the
10 TB/month egress allowance is genuinely generous.

**Corrections applied:**

- **Capacity.** A1 Ampere capacity in Mumbai and Hyderabad is chronically `Out of host capacity`.
  Provisioning must tolerate retry, or fall back to a farther region at an RTT cost. The
  provisioning helper must handle this rather than failing at first attempt.
- **Idle reclamation.** Oracle reclaims Always Free compute idle below roughly 10% CPU over 7 days.
  A personal tunnel endpoint is easily that idle. The server bootstrap must install a keepalive.
- **Single static IP is blocklistable.** Once the UTM blocklists the endpoint IP, the product stops
  working. The client **must** support multiple endpoint entries with health-based selection and
  automatic rotation. This is v1 scope, not v2.
- **⚠ D1 conflicts with D6.** A free personal endpoint works for one operator. It does **not** scale
  to public distribution — one Oracle instance serving unknown third parties is an anonymizing proxy
  service and will get the account terminated. **Resolution:** DNet Engine ships as a *client plus a
  server-provisioning helper*. Every user brings their own endpoint. The project never operates
  shared infrastructure. This makes onboarding harder and puts the provisioning wizard **in v1**.

### 4.2 D2 — Primary success criterion

1. **Primary:** restore reliable access to blocked or broken destinations (defeat DPI and port blocking).
2. **Secondary:** seamless failover — no connection drop when Wi-Fi degrades or the user moves
   between Wi-Fi and cellular.

Throughput maximization, aggregation, and download acceleration are explicitly **not** v1 goals.

### 4.3 D3 — Assume hostile UDP; three transport profiles

Assume UDP faces aggressive throttling, random drops, or outright blocking. Ship three profiles:

| Profile | Transport | Defeats | Failover tier | Notes |
|---|---|---|---|---|
| **A** | AmneziaWG | WireGuard header signature, fixed-MTU distribution | Tier 1 (roams) | UDP. Magic-byte randomization plus junk-packet bursts. **Provided by a second supervised process, `amneziawg-go` — not by sing-box. See §6.2 / C14.** |
| **B** | Hysteria 2 (Salamander, optionally Gecko) | QUIC payload and handshake shape | Tier 1 (QUIC migration) | UDP. **Brutal CC is opt-in only, not default (C5); BBR is the default** — achieved by omitting the `bandwidth` section (§6.2). |
| **C** | **VLESS + REALITY** | Total UDP blocking | **Tier 2 (access only)** | **TCP/TLS.** Resolves C9. Established connections break on interface change. Carries a known uTLS fingerprinting risk (§6.2). |

**Corrections on Profile C:** REALITY borrows a real third-party TLS handshake, so it requires a
plausible target domain (TLS 1.3, X25519, HTTP/2) that is reachable and unremarkable from the
censor's vantage point. Target-domain selection is a first-class config concern, not a constant.
REALITY is Xray-core (Go) — see D8.

**Active probing is a core feature, not a nicety.** On connect, the daemon races all configured
profiles and selects the one that currently survives, re-probing on failure. This is a large part of
what makes the product zero-config, and is the main thing that differentiates it from hand-editing a
sing-box config.

### 4.4 D4 — Failover in v1; aggregation deferred to v2

Seamless Wi-Fi to cellular handover ships in v1 (weeks). Packet-level aggregation via MPQUIC plus
ECF is deferred to its own v2 specification (C2, C3). Failover delivers the great majority of the
perceived benefit for interactive use; aggregation mainly benefits bulk transfer, which is also
deferred (D10).

### 4.5 D5 — No kernel driver; domain-first routing with best-effort per-process

No custom WFP callout driver (C4). Routing keys, in priority order:

1. **Domain rules via FakeIP** — deterministic, reliable, requires no PID lookup. **This is the
   primary and load-bearing mechanism in v1.**
2. **IP/CIDR and GeoIP rules** — deterministic.
3. **Per-process rules** — **best-effort, and advertised as such in the UI.**

**Corrections on the per-process mechanism:**

- `GetExtendedTcpTable` polling is **racy** — short-lived connections can open and close between
  polls and will be misrouted. Polling frequently enough to reduce this materially conflicts with
  the near-zero-idle-CPU requirement.
- **Preferred primitive: an ETW real-time session on the `Microsoft-Windows-Kernel-Network`
  provider**, which delivers PID at connect time as an event rather than requiring a poll. Requires
  Administrator; requires no driver. `GetExtendedTcpTable` is retained as a reconciliation fallback.
- Even with ETW, correlation is a heuristic. The spec must state that per-process routing is
  best-effort and that anything requiring hard guarantees uses domain or IP rules.

**Also resolved here (C10):** the daemon must detect and handle browser DoH — either by blocking
known DoH endpoints so browsers fall back to system DNS, or by documenting that users disable
browser DoH. Without this, FakeIP silently no-ops for browser traffic, which is the primary use case.

### 4.6 D6 — Public distribution; unknown firewalls

Free and open-source, for anyone. Consequences now in scope:

- **No hardcoded endpoints, keys, or campus-specific tuning.** All configuration is user-supplied or
  auto-provisioned.
- **A guided first-run wizard** covering endpoint provisioning (D1), key generation, and profile
  probing.
- **Assume diverse, unknown enterprise firewalls** — which is exactly why active probing (D3) and
  pluggable transports matter. Transport profiles must be updatable **without shipping a new
  release**, so that when a UTM vendor writes a signature for a popular profile, users can switch.
- **⚠ Code signing returns by another route.** We avoided the *driver* cert (D5), but an unsigned
  installer that deploys Wintun and creates a TUN adapter will trigger SmartScreen and plausibly
  Defender heuristics. v1 accepts this and documents it clearly; an OV/EV Authenticode certificate
  is a post-v1 consideration.

### 4.7 D7 — Windows-only for v1

Windows 10 1809+ and Windows 11, x64 and ARM64. Linux second, then Android; macOS and iOS are out of
scope indefinitely (C11). Core logic stays behind platform-abstraction traits so the port is a port
and not a rewrite.

### 4.8 D8 — Reuse existing Go cores, but as a **child process**, not FFI

**The decision to reuse rather than reimplement is correct and is adopted.** The mechanism is
corrected.

**Why not FFI.** Embedding sing-box via cgo `-buildmode=c-archive` puts the Go runtime and GC inside
the Rust process: a roughly 40–70 MB static archive, awkward panic and signal interaction with
Tokio, and a build requiring the Go toolchain linked against MSVC in CI. It also kills the sub-10 MB
binary goal outright.

**Adopted instead: supervised child process.** The Rust daemon owns the lifecycle — it generates
sing-box's JSON configuration, spawns it, supervises and restarts it, and drives it at runtime
through its Clash-compatible control API. This is simpler, more robust, independently debuggable,
and keeps a clean license boundary.

**The consequence the spec must state honestly.** sing-box already implements Wintun integration,
FakeIP, rule-based routing, WireGuard, Hysteria 2, VLESS+REALITY, and process-name routing — that is
most of F1 through F5. **So DNet Engine is an orchestration and experience layer, not a network
engine.** Its actual contributions are:

- automatic exit-node provisioning (D1) — sing-box does not do this;
- active transport probing and automatic profile switching (D3) — sing-box does not do this;
- seamless interface failover driven by OS network-change events (D4) — sing-box does not do this;
- zero-config onboarding, tray UI, and browser control surface (F7, F8);
- updatable transport profiles (D6).

Naming this plainly in the constitution is what prevents six months spent reimplementing sing-box
badly. Subsystems may be replaced with Rust-native implementations post-v1 **only where there is a
specific recorded reason**, captured as an ADR.

**Revised NFR (supersedes N2).** The sub-10 MB binary target is void. New targets: installer at most
60 MB; combined idle RSS at most 150 MB; idle CPU under 1% on a 4-core machine; no measurable impact
on foreground development work.

### 4.9 D9 — Name clearance: **DNet Engine** (adopted)

Checked 2026-09-10.

| Surface | `dnet` | `dnet-engine` / DNet Engine |
|---|---|---|
| crates.io | **taken** (message-passing lib, active) | **free** |
| npm | **taken** | **free** |
| GitHub org/user | **taken** | **free** |
| GitHub repo search | many | **0 results** |
| `dnetengine.com`, `dnet-engine.com` | — | **unregistered** |
| `dnet.dev`, `dnet.app` | **registered** | — |

**Trademark.** No registered US wordmark for `DNET` surfaced in accessible searches. Several
unrelated companies trade as DNet or D-NET in adjacent IT and networking services — DNet Systems
(Nigeria), DNet Solution (Philippines), DNET Security Inc. (US), D-NET (Indonesian ISP). None
appears to be a registered wordmark, but they occupy the same broad class. Risk is **low for a free,
non-commercial open-source tool**; a formal USPTO search is warranted before any commercial use.

**"Dex Engine" is rejected.** `DEX` is severely overloaded — Android DEX bytecode (fatal for a
developer tool), ServiceNow DEX, the "Digital Employee Experience" product category, PCDJ DEX, and
decentralized exchanges.

**Adopted convention:** always the full two-word name **DNet Engine**; crate and repo `dnet-engine`;
service binary `dnetd`; tray binary `dnet-tray`. Never the bare token `dnet`.

### 4.10 D10 — Download accelerator deferred to v2

Parallel-chunk downloading and sparse-file I/O are cut from v1 (C6, C7). When revisited, the
approach is `SetFileValidData`, not `FSCTL_SET_SPARSE`, and the value proposition must first be
demonstrated by measurement.

---

## 5. Revised v1 Scope

**In scope**

- F1 Wintun TUN adapter, system-wide L3 capture (via supervised sing-box)
- F3 FakeIP DNS and domain-based routing, including DoH handling and captive-portal exemptions
- F4 Three transport profiles (AmneziaWG / Hysteria 2 / VLESS+REALITY) with **active probing and automatic switching**
- F5-lite **Failover** across Wi-Fi and cellular on OS network-change events
- F2-lite Domain and IP rules (reliable) plus best-effort per-process rules via ETW
- F7 Tauri v2 tray UI: one Stabilize toggle, plus an advanced panel
- F9 Captive-portal survival
- **NEW** Oracle Cloud Always Free provisioning wizard, server bootstrap, and keepalive
- **NEW** Multi-endpoint configuration with health-based rotation
- **NEW** Privilege-separated architecture: Windows Service reached over an authenticated named pipe
- **NEW** Phase 0: Docker, `tc netem` and `iptables` degraded-network and DPI-simulation harness

**Deferred to v2:** MPQUIC aggregation and ECF (C2, C3); download accelerator (C6, C7); browser
extension F8; Linux and Android ports; Rust-native transport reimplementation; code signing.

**Out of scope indefinitely:** macOS, iOS, kernel-mode drivers, any project-operated shared server.

### Suggested phase order

| Phase | Deliverable | Gate |
|---|---|---|
| 0 | Docker / `tc netem` / `iptables` harness; simulated UTM | Reproducibly reproduces 20% loss, 150±50 ms, UDP block, WireGuard signature drop |
| 1 | Oracle provisioning wizard, server bootstrap, keepalive | One command yields a reachable, surviving endpoint |
| 2 | Privileged service skeleton, named-pipe IPC, authz boundary | Unprivileged client cannot alter routing without authentication |
| 3 | sing-box supervision, config generation, single profile end-to-end | Traffic flows through the tunnel inside the Phase 0 harness |
| 4 | Three profiles, active probing, automatic switching | Recovers when the harness blocks the active profile |
| 5 | FakeIP, domain rules, DoH handling, captive portal | Correct routing for browser traffic specifically |
| 6 | Interface failover on network-change events | No TCP reset when the harness kills the primary interface |
| 7 | Tauri tray UI and first-run wizard | A non-technical user reaches a working tunnel unaided |

---

## 6. Verification Results

### 6.1 O1 — Licence compatibility: **CLOSED, compatible, two binding obligations**

Verified 2026-09-10 against each project's own licence file.

| Component | Licence | GPLv3-compatible | Obligation on DNet Engine |
|---|---|---|---|
| **sing-box** | GPL-3.0-or-later **plus an additional term**: *"no derivative work may use the name or imply association with this application without prior consent"* | **Yes.** This is an additional term expressly permitted by GPLv3 §7(e) (declining to grant trademark rights); it does not make the licence non-free or incompatible. | **Binding: DNet Engine must not use the sing-box name in its branding, product name, or marketing, and must not imply association or endorsement.** Attribution in documentation and an about screen is fine and required; branding is not. Ship its licence text and a source offer. |
| **Wintun** (prebuilt signed DLL) | Source is GPLv2; the **prebuilt signed DLLs carry a separate, more permissive licence** shipped inside the distribution ZIP. wintun.net states the signed DLLs are *"the only supported way of distributing Wintun."* | **Yes, via the prebuilt binary only.** | **Binding: bundle the signed prebuilt DLL only. Never build Wintun from source** — doing so would pull GPLv2 code into a GPLv3 work, and GPLv2 and GPLv3 are incompatible. Ship the permissive licence text from the ZIP. |
| **Xray-core** (only if used, see 6.2) | MPL-2.0 | **Yes.** MPL-2.0 §3.3 expressly permits distribution under a GPL Secondary Licence. | Retain MPL file-level notices. |
| **amneziawg-go** | MIT | **Yes.** | Retain copyright notice. |

**Additional mitigating fact.** All of these run as **separate processes**, not as linked libraries.
That makes the arrangement mere aggregation rather than a combined work, which materially simplifies
compliance. DNet Engine still *distributes* them in its installer, so licence texts and a source
offer are required regardless.

**Verdict: GPLv3 is a sound choice and O1 is not a blocker.** The two binding obligations above are
promoted into the constitution.

### 6.2 O2 — Primary-source verification: **CLOSED, one material refutation**

Verified 2026-09-10 against the Hysteria 2 protocol specification, the sing-box documentation and
repository, Microsoft Learn, and wintun.net. The original blueprint's citation list was not used.

**Confirmed correct**

- **FakeIP ranges.** sing-box documents exactly `inet4_range: 198.18.0.0/15` and
  `inet6_range: fc00::/18`. The blueprint's values are right.
- **Salamander.** BLAKE2b-256 over a randomly generated 8-byte salt appended to a user-supplied
  pre-shared key; the payload is XORed against the cycling 32-byte hash output. *Minor correction to
  the blueprint:* the hash is taken over `salt || pre-shared key`, not over the packet.
- **Gecko.** Real, and as described — it wraps Salamander and fragments long-header QUIC packets into
  2–8 randomly sized, randomly padded segments. (This was the claim most likely to have been
  unsupported; it holds.)
- **REALITY.** sing-box supports it for VLESS, with uTLS fingerprint selection.
- **Brutal vs BBR.** Brutal is activated *if and only if* the `bandwidth` section is present in the
  configuration; omit it and Hysteria 2 falls back to `congestion` (default `bbr`, `standard`
  profile). **This makes D3's "BBR by default, Brutal opt-in" a pure config-emission decision** —
  the daemon simply does not emit a `bandwidth` section unless the user opts in. No patching needed.
- **ETW.** `Microsoft-Windows-Kernel-Network`'s `TcpIpConnect` event carries a `PID` (uint32) field
  alongside `daddr`, `dport`, `saddr`, `sport` — exactly the connect-time correlation D5 requires.
  **Implementation constraint:** read the PID from the **event payload**, never from
  `EVENT_TRACE_HEADER` — Microsoft documents that the header's ProcessId is unreliable for network
  events because some are logged by separate threads.

**Refuted — material**

- **C14 (NEW): sing-box does not support AmneziaWG.** Its outbound list includes WireGuard but no
  Amnezia obfuscation parameters; PR #2670 "Added support for AmneziaWG" was **closed unmerged**, and
  the standing feature requests are closed. Plain WireGuard is not a substitute — it is precisely the
  fingerprintable thing AmneziaWG exists to fix, and shipping it as the "obfuscated" profile would
  violate Principle VI (honest capability claims). **D3's transport set as written is not deliverable
  by sing-box alone.**
- **sing-box has no multipath QUIC**, confirming C2 by omission and confirming that MPQUIC cannot be
  part of v1 under Principle I.

**Resolution adopted (amends D3).** Run **`amneziawg-go` (MIT) as a second supervised child process**
alongside sing-box. This stays within Principle I — orchestration, not reimplementation — costs one
more supervised process in the lifecycle model, and keeps the profile honest. Alternatives considered
and rejected: switching the core to mihomo/Clash.Meta, which does support AmneziaWG but would replace
a settled dependency this late for one profile; and dropping AmneziaWG, which would leave only one UDP
profile and weaken D3's whole premise.

**Risk recorded.** sing-box's own documentation warns that uTLS "has had repeated fingerprinting
vulnerabilities discovered by researchers" and recommends NaiveProxy for circumvention use. The
VLESS+REALITY profile therefore carries a known and evolving fingerprinting risk, which is an
argument for keeping the profile set updatable (D6) rather than for dropping the profile.

### 6.3 O3 — Licence: **CLOSED**

**GPLv3.** Compatible with every bundled dependency (6.1).

### 6.4 O4 — Encrypted-DNS strategy: **CLOSED**

**Block known encrypted-DNS endpoints by default** so that destination-based routing works without
user action, with prominent first-run disclosure and a single-action opt-out that states the
consequence. Specified as FR-025 and FR-025a.

## 7. Remaining Open Items

- **O5** Define the transport-profile update channel and its integrity model — a profile feed that
  can push routing changes is a supply-chain surface and must be signed (D6). *Blocking the profile
  update feature, not the rest of v1.*
- **O6** Confirm ETW connect-time PID correlation is achievable at acceptable CPU cost. The event
  schema is now verified (6.2); what remains is the **cost and coverage** measurement. Prototype in
  Phase 0 before committing to D5's per-process path. *Blocking the per-process routing feature only.*
- **O7 (NEW)** Confirm the pinned sing-box version's Hysteria 2 implementation supports Gecko, not
  only Salamander. Gecko is comparatively recent; the core may lag the protocol specification.
  *Blocking Phase 4 profile tuning, not Phase 3.*
