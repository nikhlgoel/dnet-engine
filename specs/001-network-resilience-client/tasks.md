---
description: "Task list for DNet Engine v1 — Network Resilience Client"
---

# Tasks: DNet Engine v1 — Network Resilience Client

**Input**: Design documents from `/specs/001-network-resilience-client/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/)

**Tests**: TDD is mandatory (Constitution Principle IV). Contract tests are written **before** the implementation they cover, and each is expected to fail first.

**Organization**: Phases follow the eight gated delivery phases in [plan.md](./plan.md) in order, because later phases are hard-blocked by earlier gates. Every task additionally carries its user-story label so story-level progress stays visible. See the traceability table below.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: [US1]–[US6] from [spec.md](./spec.md). Setup, Foundational, Gate, and Polish tasks carry no story label.
- **[GATE]**: A blocking checkpoint. No task in a later phase may start until it passes.

## Path Conventions

Rust workspace per [plan.md](./plan.md) §Project Structure: `crates/<name>/`, `apps/dnet-tray/`, `vendor/`, `testing/harness/`, `installer/`.

## Story → Phase Traceability

| Story | Priority | Delivered in | Independently testable when |
|---|---|---|---|
| **US1** Restore access on a restrictive network | P1 | Phases 3–5 | HV-01, HV-02, HV-03, HV-04, HV-10 pass |
| **US2** Obtain an endpoint without expertise | P1 | Phase 1 + Phase 7 wizard | PRV-01…09 pass; a stranger provisions unaided |
| **US3** Keep working when a connection degrades | P2 | Phase 6 | HV-06, HV-07, HV-08 pass |
| **US4** Survive the endpoint being blocked | P2 | Phase 4 | HV-09 passes |
| **US5** Choose what goes through the tunnel | P3 | Phase 5 | Rule precedence + SC-017 pass |
| **US6** Get online behind a captive portal | P3 | Phase 5 | HV-11 passes |

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace, vendoring, and the two CI checks that enforce the binding licence obligations.

- [x] T001 Create the Rust workspace root `Cargo.toml` with members `crates/dnetd`, `crates/dnet-core`, `crates/dnet-ipc`, `crates/dnet-supervisor`, `crates/dnet-config`, `crates/dnet-etw`, `crates/dnet-netstate`, `crates/dnet-provision`, `crates/xtask`
- [x] T002 [P] Add `LICENSE` (GPLv3 full text) and `THIRD-PARTY-NOTICES.md` at repository root, with attribution sections for the primary transport core, `amneziawg-go`, and Wintun
- [x] T003 [P] Add `.gitignore` covering `target/`, `node_modules/`, `vendor/**/*.dll`, `vendor/**/*.exe`, `dist/`, and `*.pdb`
- [x] T004 [P] Configure `rustfmt.toml` and `clippy.toml`; set `#![deny(warnings)]` policy in CI only, not in source
- [x] T005 Implement `cargo xtask fetch-vendor` in `crates/xtask/src/fetch_vendor.rs` — downloads pinned releases of the primary core, `amneziawg-go`, and the **vendor-signed prebuilt Wintun DLL**, verifying each against a recorded SHA-256. *Extended 2026-09-11:* patches the primary core's DLL loader so it embeds nothing and loads the vendored DLL by digest, and builds with `with_external_windivert` (ADR-0004 Finding 4)
- [x] T006 Implement `cargo xtask verify-vendor` in `crates/xtask/src/verify_vendor.rs` — asserts the Authenticode signature on `vendor/wintun/wintun.dll` and **fails the build if any Wintun source file exists anywhere in the tree** (Constitution licence obligation 2, [research.md](./research.md) §R6). *Extended 2026-09-11:* pins the DLL digest and **fails on any executable image embedded in a vendored core** (Constitution 1.3.0 no-embedded-copies rule)
- [x] T007 Implement `cargo xtask lint-branding` in `crates/xtask/src/lint_branding.rs` — greps UI strings, installer manifests, README, and marketing assets for the primary core's vendor name and fails outside the allowlist (`THIRD-PARTY-NOTICES.md`, the About screen, and `docs/`/`specs/` engineering documents) (Constitution licence obligation 1)
- [x] T008 Add GitHub Actions workflow `.github/workflows/ci.yml` running `verify-vendor`, `lint-branding`, `cargo fmt --check`, `cargo clippy`, and `cargo test --workspace` on `windows-latest`
- [x] T009 [P] Add `cargo llvm-cov` to CI with `--fail-under-lines 80`, excluding `apps/` and `vendor/`

**Checkpoint**: Both licence obligations are mechanically enforced before any code exists that could violate them.

> **Status 2026-09-10 — Phase 1 COMPLETE.** Verified with the real toolchain
> (rustc 1.98.1, MSVC 14.44 + SDK 10.0.26100, Go 1.27.0):
>
> - `cargo build --workspace` — clean, 9 crates
> - `cargo fmt --all --check` — clean
> - `cargo clippy --workspace --all-targets -- -D warnings` — clean
> - `cargo test --workspace` — 6 passed, 0 failed
> - `cargo xtask fetch-vendor` — built both cores from pinned commits
> - `cargo xtask verify-vendor` — OK (signature valid, no Wintun source, licences present)
> - `cargo xtask lint-branding` — OK, **and verified by negative test**: a planted
>   "powered by <core> and Wintun" string in `dnetd` was caught and failed the build
>
> Vendored artifacts: primary core **41.63 MB** (down from 78.03 MB prebuilt, a 47%
> reduction from minimal build tags), `amneziawg-go` 3.36 MB, Wintun DLL 0.41 MB —
> **45.39 MB uncompressed**, comfortably inside SC-012 once installer-compressed.

---

## Phase 2: Foundational — Plan Phase 0: Simulation Harness

**Purpose**: The harness gates every other phase (Constitution Principle III). Built first. Contract: [contracts/harness.md](./contracts/harness.md).

**⚠️ CRITICAL**: No transport work begins until T020 passes.

- [x] T010 Create `testing/harness/docker-compose.yml` with the three-container topology (client under test, simulated UTM, mock endpoint) per [contracts/harness.md](./contracts/harness.md) §2
- [x] T011 [P] Implement conditions H1 (150ms ±50ms, 20% loss) and H9 (bandwidth ceiling) via `tc netem`/`tbf` in `testing/harness/conditions/degrade.sh`
- [x] T012 [P] Implement conditions H2 (total outbound UDP block) and H4 (selective per-port/per-signature block) in `testing/harness/conditions/block.sh`
- [x] T013 [P] Implement condition H3 (drop packets matching the standard WireGuard handshake prefix) in `testing/harness/conditions/dpi.sh` — this is what makes the obfuscation claim testable rather than assumed
- [x] T014 [P] Implement condition H5 (port 53 hijack returning forged answers) in `testing/harness/conditions/dns-hijack.sh`
- [x] T015 [P] Implement condition H6 (captive portal intercepting until login satisfied) in `testing/harness/conditions/portal.sh`
- [x] T016 [P] Implement conditions H7 (interface down/up) and H8 (drop traffic to a specific endpoint address) in `testing/harness/conditions/path.sh`
- [x] T017 Implement `testing/harness/harness.ps1` with `status`, `apply <ID>`, `clear`, and `report` subcommands, applying conditions **at runtime mid-session** without restarting the client (HN-01)
- [ ] T018 Provision the mock endpoint in `testing/harness/endpoint/` running both server-side cores pinned to the same versions the client bundles, plus a plain HTTP origin — **partial 2026-09-11:** the Profile A (AmneziaWG) server is in, built from the client's pinned commit, with an origin on TEST-NET-3 reachable only through the tunnel; the Profile C (VLESS+REALITY) server is also in now (`reality-server.sh`, with a loopback TLS 1.3 target because the harness has no route to a real site). **2026-10-16:** the Profile B (Hysteria 2) server is in (`hy2-server.sh`, the primary core built from the client's pinned commit). Its image builds and the server runs in the container; the client core on Windows carried 5 MB through the published port and the simulated UTM, and wrong-password and wrong-pin controls carried nothing. The TUN path (T055) is still unrun
- [x] T019 Implement ground-truth reporting in `testing/harness/report.ps1` — emits packets dropped and by which rule, so a test can distinguish "obfuscation worked" from "the rule never fired" (HN-03)
- [x] T020 **[GATE] Phase 0 exit**: demonstrate H1–H9 on demand, HN-01…HN-06 hold, and HV-03 runs with a **deliberately unobfuscated control that fails**. A harness where everything passes proves nothing ([contracts/harness.md](./contracts/harness.md) §5)

- [x] T021 **[GATE] SPIKE-O6**: build a throwaway ETW consumer in `crates/dnet-etw/examples/spike_cost.rs`; measure steady-state CPU cost and the proportion of connections attributed on a machine with a realistic socket population. **If cost breaches SC-014 or coverage is too low to be useful, per-process routing is cut from v1 and only destination rules ship.** Record the decision in `docs/adr/0001-etw-attribution.md` ([research.md](./research.md) §R7)
  > **RESOLVED 2026-09-11: SPIKE-O6 PASSES.** Run 2 (instrument v2): remote coverage 100%, cost
  > 0.000%, liveness confirmed (193 events). Run 1's 0.5% was the byte-order parsing defect (BUG-006),
  > confirmed: native match 0/200, byte-swapped 200/200. **FR-023 is permanently retained; T074-T076
  > are UNBLOCKED.** Binding constraint for T075: `sport`/`dport` arrive in network byte order and MUST
  > be swapped to host order before matching. See `docs/adr/0001-etw-attribution.md` (Accepted).

**Checkpoint**: The harness can tell the difference between working and not working. SPIKE-O6 has decided whether FR-023 is in scope.

> **Status 2026-09-10 — T010-T020 COMPLETE; Phase 0 exit gate MET.**
>
> - `.\harness.ps1 verify` — PASSED (baseline reachable; H1, H2, H3, H4, H5, H7, H9 all apply and clear)
> - `.\Invoke-Hv03.ps1` — **PASSED**: unobfuscated WireGuard handshake DROPPED (counter 0→1),
>   obfuscated probe PASSED (1→1). Both halves required.
> - H1 degradation measured at **635x** (4.94 kbit/s vs 3,134 kbit/s baseline over 64 KB).
>
> Five harness bugs were found by measuring rather than assuming, each of which had produced
> a passing-but-meaningless result. All are documented in `testing/harness/HARNESS-NOTES.md`.
>
> **T018 (mock endpoint running the server-side cores) is deferred to Phase 3**, where the real
> handshake is first needed. The HTTP origin is sufficient for every Phase 0 gate.
>
> **T021 (SPIKE-O6) still outstanding** — it needs the host under realistic development and
> browsing load to produce honest CPU and attribution numbers.
>
> **Known limitation affecting Phase 6:** `H7-down` drops the simulated path, not a Windows
> NIC. HV-07 / SPIKE-R9 additionally require a host-side adapter disable. See HARNESS-NOTES.md.

---

## Phase 3: Foundational — Domain Core and Privilege Boundary (Plan Phase 2)

**Purpose**: Pure domain types and the authenticated IPC boundary. Everything downstream depends on these.

### Contract tests first (TDD)

- [x] T022 [P] Write failing contract tests IPC-01…IPC-09 in `crates/dnet-ipc/tests/contract.rs` per [contracts/ipc-protocol.md](./contracts/ipc-protocol.md) §Contract tests
- [x] T023 [P] Write failing property tests for `EndpointHealth` transitions in `crates/dnet-core/tests/health.rs` — including that `Unreachable` is never terminal ([data-model.md](./data-model.md) §1.1)

### Domain types

- [x] T024 [P] [US1] Implement `Endpoint`, `EndpointId`, `EndpointAddress`, `EndpointOrigin`, `CredentialRef` in `crates/dnet-core/src/endpoint.rs` — `CredentialRef` exposes **no accessor returning plaintext** ([data-model.md](./data-model.md) §1)
- [x] T025 [P] [US4] Implement `EndpointHealth` and its state machine in `crates/dnet-core/src/health.rs`
- [x] T026 [P] [US1] Implement `ConnectionProfile`, `ProfileKind`, `Carrier`, `Viability`, `CoreBinding` in `crates/dnet-core/src/profile.rs`
- [x] T027 [P] [US3] Implement `FailoverTier` in `crates/dnet-core/src/tier.rs`, with the invariant that tier is set from measurement and is never inferred from `ProfileKind`
  > **2026-09-12.**
  >
  > - **Model.** `FailoverTier::from_measurement` yields `Tier1` only for
  >   `SurvivalMeasurement::Survived`. `recorded_survival(kind)` holds the HV-07 result for
  >   each kind at the pinned core versions, and every kind is currently `NotMeasured`.
  >   `ConnectionProfile::new` takes its tier from that record.
  > - **Removed.** `ProfileKind::expected_tier` (the inference from kind) and
  >   `demote_to_tier2` (no runtime tier setter).
  > - **Owner decision (2026-09-12): measured only.** Resolves the conflict with data-model §2
  >   and FR-016a, which started AmneziaWG and Hysteria 2 at Tier 1 by design. Until T085:
  >   - every profile shows Tier 2;
  >   - FR-016b has no Tier 1 to prefer;
  >   - `check_tier_consent` requires no downgrade consent, since no Tier 1 is viable;
  >   - the Tier 2 warning still applies.
  > - **Verification.** A test pins "no kind claims Tier 1" and is updated by T085 together
  >   with the evidence. The posture test for Tier 1 preference now uses an explicitly
  >   measured profile, via a `cfg(test)` constructor.
- [x] T028 [P] [US3] Implement `NetworkPath`, `PathKind`, `PathQuality`, `PathRole` in `crates/dnet-core/src/path.rs` — a path with `gateway = None` cannot become `Carrying` ([data-model.md](./data-model.md) §3)
  - Fail-closed kill switch: `crates/dnet-core/src/posture.rs` adds `RoutingPosture` (`Tunnelled { tier } | FailClosed` — **no** direct-fallback variant) and `select_posture`, which returns `FailClosed` whenever no path carries or no profile is `Working`, so lost tunnels drop traffic rather than exposing the physical interface ([data-model.md](./data-model.md) §3).
- [x] T029 [P] [US5] Implement `RoutingRule`, `RuleMatcher`, `RuleAction`, `Reliability` in `crates/dnet-core/src/rule.rs` — make constructing a `Deterministic` application rule **impossible at the type level** ([data-model.md](./data-model.md) §4)
  - DNS-leak protection: added `RuleMatcher::DnsPort` + `RuleAction::Capture` (only constructible together), the built-in `DnsPort → Capture` rule at precedence `0`, and `validate_dns_leak_protection`, so all outbound port-53 traffic is captured into the tunnel and no bypass can outrank it ([data-model.md](./data-model.md) §4).
- [x] T030 [P] [US1] Implement `ConnectionSession`, `ConnectionEvent`, `FailureCause`, `SessionOutcome` in `crates/dnet-core/src/session.rs` — `FailureCause` has exactly the seven variants and no `Unknown`
- [x] T031 [US1] Implement the built-in non-deletable bypass rule set (RFC1918, link-local, multicast, captive-portal probe hosts, active endpoint address) in `crates/dnet-core/src/builtin_rules.rs`
  > **2026-09-12.**
  >
  > - **Module.** The set moved out of `rule.rs` into `builtin_rules.rs`. Order: DNS capture
  >   (precedence 0), then the active endpoint, then RFC1918, link-local and multicast in
  >   both families, then the captive-portal probe domains. Built-in rules can only be
  >   constructed inside `dnet-core` (`RoutingRule::builtin` is `pub(crate)`).
  > - **Non-deletable.** `validate_builtin_rules_present` runs first on every rule-set
  >   mutation in `DomainState`, which now has `remove_rule`. Removing any built-in, or
  >   swapping one for an identical user rule, is refused with `BuiltinRuleMissing`.
  > - **Probe hosts corrected.** They were `www.msftconnecttest.com`, `www.msftncsi.com`,
  >   `connectivitycheck.gstatic.com` and `captive.apple.com`. They are now the suffixes
  >   `msftconnecttest.com` and `msftncsi.com`, per Microsoft Learn KB 4494446: NCSI probes
  >   these, and restricted networks are told to allow `*.msftconnecttest.com` and
  >   `*.msftncsi.com`. The Android and Apple hosts are never probed on Windows, so bypassing
  >   them only sent traffic around the tunnel. Browser-specific portal detectors belong to
  >   T077, where they can be verified.
  > - **FakeIP guard.** IPv6 unique-local `fc00::/7` is deliberately not bypassed because it
  >   contains the FakeIP pool `fc00::/18`. A config contract test asserts that no built-in
  >   bypass overlaps either FakeIP pool (`IpCidr::overlaps`).
  > - **Verification.** 13 new or rewritten `dnet-core` tests, 2 `dnetd` store tests, and 2
  >   config contract tests. The pinned core's own `check` accepts the config.

### IPC and service skeleton

- [x] T032 [US1] Implement named-pipe framing (4-byte LE length prefix + UTF-8 JSON) in `crates/dnet-ipc/src/frame.rs`, rejecting malformed, oversized, and truncated frames without panicking (IPC-08)
- [x] T033 [US1] Implement request/response types and the error model in `crates/dnet-ipc/src/protocol.rs` per [contracts/ipc-protocol.md](./contracts/ipc-protocol.md)
- [x] T034 [US1] Implement pipe creation with explicit SDDL in `crates/dnet-ipc/src/server.rs` — never a NULL DACL (IPC-02)
- [x] T035 [US1] Implement per-connection client identity verification in `crates/dnet-ipc/src/authz.rs` — `ImpersonateNamedPipeClient`, capture token, revert immediately; mutating requests require the interactive console user (IPC-01)
- [x] T036 [US1] Implement the Windows Service lifecycle (SCM registration, start/stop/shutdown handlers) in `crates/dnetd/src/service.rs` using `windows-service`, running as LocalSystem ([research.md](./research.md) §R5)
  > **2026-09-11.** SCM lifecycle in `crates/dnetd/src/svc.rs` (Running/Stop, LocalSystem), plus the
  > `--console` dev entry, both running `run_control_listener`. `DnetService` bridges authorized
  > requests to an in-memory `DomainState`; `console_session()` resolves the real console user via
  > `WTSGetActiveConsoleSessionId` + `WTSQueryUserToken`. Read-only queries (GetState, ListEndpoints,
  > ListProfiles, ListRules, GetSession) are fully served. **Scope boundary:** Connect/Disconnect and
  > config mutations return an honest `InternalError` ("not available in this build") because the
  > transport engine is Phases 4-6 and request payloads arrive with the tray (Phase 9). The SCM path
  > is not CI-testable; the domain store and dispatch are unit-tested (14 dnetd tests).
- [x] T037 [US1] Implement the undo-record registry in `crates/dnet-netstate/src/undo.rs` — every routing, DNS, or adapter mutation registers its undo **before** being applied
  > **2026-09-11.**
  >
  > - **Registry.** `UndoRegistry::apply` is write-ahead: it persists the record, then runs
  >   the mutation. If the record cannot be persisted, the mutation never runs. A failed
  >   mutation, or a target that already existed, withdraws the record.
  > - **One restoration path.** Normal teardown (`undo`) and crash replay (`replay`, newest
  >   first, failures kept) both use the same `UndoExecutor`, so every disconnect exercises
  >   the crash path.
  > - **Journal.** `undo_file.rs` stores it at `%PROGRAMDATA%\DNet Engine\state\undo.json`
  >   using temp-file, flush and rename. It is trusted only if the file is owned by SYSTEM
  >   or Administrators and protected so that only those two have access, checked and read
  >   through one handle. The directory must also be SYSTEM- or Administrators-owned.
  >   Anything malformed is refused whole, never partially loaded.
  > - **Wired in.** The host-route installer records every route before creating it, and
  >   never records a route that already existed. Removal runs `WindowsUndoExecutor`. The
  >   SPIKE-R4 runner replays leftovers at start and in its shutdown hook.
  > - **Scope.** Host routes are the only routing/DNS/adapter mutation that exists today.
  >   The AmneziaWG adapter's address and route are not recorded: they vanish with the
  >   adapter, and SUP-05 reaps a leftover core. New mutation kinds add an `UndoRecord`
  >   variant.
  > - **Verification.** 19 new unprivileged tests. Five elevated `--ignored` tests **passed
  >   elevated on 2026-09-11** against the real routing table: install and remove, crash then
  >   replay, pre-existing route untouched, already-gone reversal, and restricted journal
  >   save/load.
- [x] T038 [US1] Implement restoration-on-start recovery in `crates/dnetd/src/recovery.rs` — replays outstanding undo records at service start, because a crash leaves no one to run the shutdown path ([data-model.md](./data-model.md) §Cross-cutting 1)
  > **2026-09-11.**
  >
  > - **Order.** `recover_at_start` runs first in both entry modes, before the control listener
  >   exists: **kill orphaned cores, then replay the journal.** Cores go first for SUP-04's
  >   reason: removing an endpoint host route while an orphaned tunnel still sends would loop
  >   its packets.
  > - **Strict gate.** Only full success yields `Recovered`, and it is the only holder of the
  >   undo registry every routing mutation needs. A failed recovery therefore cannot
  >   initialise a tunnel. It is triggered by an orphan that cannot be killed, an unreadable or
  >   untrusted journal, or any record that cannot be reversed. `DnetService` then refuses
  >   **every** mutating request with an actionable `InternalError` and keeps answering
  >   read-only queries. There is no automatic retry; restarting the service retries.
  > - **Verification.** 10 unprivileged tests:
  >   - order;
  >   - clean start;
  >   - an irreversible record is kept;
  >   - an unusable journal;
  >   - an unkillable orphan leaves the journal untouched;
  >   - error text;
  >   - an untrusted journal on the real disk;
  >   - the installed layout;
  >   - all 12 mutating requests refused;
  >   - read-only queries still served.
  >
  >   One elevated `--ignored` test covers the routes half of SUP-T2 and **passed elevated on
  >   2026-09-11**.
  > - **Owner decisions (2026-09-11).** Staying up locked (rather than exiting) is approved: it
  >   avoids SCM restart loops and keeps IPC available to surface the failure. The `GetState`
  >   gap is deferred to T112/Phase 9. The fixed core layout is a T114 requirement.
  > - **Contract gap.** `GetState` (ipc-protocol.md) has nowhere to report a failed recovery.
  >   `failure.cause` is limited to the seven session `FailureCause` variants. Until the
  >   contract gains a field (proposed for T112 or the tray in Phase 9), the reason reaches the
  >   user only through the refusal detail and the service log.
- [x] T039 **[GATE] Plan Phase 2 exit**: IPC-01 passes — an unprivileged, non-console client issuing `Connect` receives `Unauthorized` and routing state is unchanged. This is SC-019 verified by explicit attempt
  > **PASSED 2026-09-11.** Real named pipe with the production SDDL; client identity captured by
  > `ImpersonateNamedPipeClient` -> `OpenThreadToken` -> `GetTokenInformation(TokenUser)` ->
  > `ConvertSidToStringSidW`, then revert. `crates/dnet-ipc/tests/attack.rs`: a mutating `Connect`
  > from a non-console captured identity is refused (`Unauthorized`) with the routing-mutation
  > counter unmoved, while a read-only `GetState` from the same real client succeeds — proving
  > capture yields an authenticated principal, so the refusal is a real authorization decision
  > and not blanket denial. SC-019 verified by attack. A cross-process lowered-token variant is
  > recorded as future hardening.

**Checkpoint**: The privilege boundary holds under attack. Domain logic is unit-testable without Windows or a network.

> **Status 2026-09-11 - Phase 3 IPC + health layer GREEN.**
>
> T022 (45 IPC contract tests), T023 (27 health tests), T025 (health state machine), and T032 (frame
> codec) are implemented and passing. The pure/testable cores of T033 (protocol codec + validators),
> T034 (SDDL + connection loop), and T035 (authz decision) are done and turn IPC-01..09 green; their
> OS-level remainders (real named-pipe binding, `ImpersonateNamedPipeClient`, request dispatch) and
> the T039 attack gate are still open. Coverage on dnet-core + dnet-ipc is 91% lines (CI floor 80%,
> scoped to implemented crates). Spec gaps for T025 were resolved in data-model.md §1.1.
>
> Superseded RED note (kept for history):
> **Status 2026-09-10 - T022 and T023 written and verified RED for the right reason.**
> `crates/dnet-ipc/tests/contract.rs`: 45 tests (44 fail, 1 passes on a constant).
> `crates/dnet-core/tests/health.rs`: 19 tests (17 fail, 2 pass on a constant and constructor).
> All 811 panics are `todo!()`; clippy `--all-targets -D warnings` is clean. Spec gaps surfaced for
> T025: `Degraded` has no specified transitions; failed-probe-from-`Unknown` is drawn ambiguously;
> EWMA weight is unspecified. `MAX_FRAME_LEN` (1 MiB) is a chosen default the contract does not fix.
> CI `build-and-test` fails until T024-T035 implement these contracts.

---

## Phase 4: US1 — Single Profile End-to-End (Plan Phase 3) 🎯 MVP core

**Goal**: Traffic flows through the tunnel inside the harness, with no routing loop.

**Independent test**: HV-13 and a manual end-to-end transfer through the mock endpoint.

### Contract tests first

- [x] T040 [P] [US1] Write failing contract tests CFG-01…CFG-07 in `crates/dnet-config/tests/contract.rs` per [contracts/core-config.md](./contracts/core-config.md) §1.2
- [x] T041 [P] [US1] Write failing contract tests AWG-01…AWG-06 in `crates/dnet-config/tests/amneziawg.rs` per [contracts/core-config.md](./contracts/core-config.md) §2.2
- [x] T042 [P] [US1] Write failing contract tests SUP-T1…SUP-T4 in `crates/dnet-supervisor/tests/contract.rs` per [contracts/core-config.md](./contracts/core-config.md) §3.1

### Supervision

- [x] T043 [US1] Implement child process spawn with captured stdio and readiness detection in `crates/dnet-supervisor/src/child.rs` (SUP-01, SUP-06) — readiness combinator (SUP-T4) plus real tokio spawn in `process.rs` (captured stdio → tracing, marker readiness, timeout vs early exit, `CREATE_NO_WINDOW`, kill-on-drop), tested against real processes
- [x] T044 [US1] Implement jittered exponential backoff **with a ceiling and an attempt limit**, terminating in `CoreFailedPersistently` rather than looping forever, in `crates/dnet-supervisor/src/restart.rs` (SUP-03)
- [x] T045 [US1] Implement orphan reaping at service start in `crates/dnet-supervisor/src/reap.rs` — kills cores left by a prior crashed run **before** any new adapter is created (SUP-05) — ordering via the `CoreRuntime` seam (SUP-T3); real discovery in `orphans.rs` (Toolhelp snapshot, **full image path** match, never name-only), tested by reaping a real simulated orphan
- [x] T046 [US1] Implement teardown of both cores plus full undo replay on any `dnetd` stop in `crates/dnet-supervisor/src/shutdown.rs` (SUP-04)

### Configuration generation

- [x] T047 [US1] Implement primary-core configuration generation in `crates/dnet-config/src/primary.rs` — TUN inbound present for **every** profile, FakeIP `198.18.0.0/15` and `fc00::/18`, deterministic output (CC-01, CC-02, CC-09)
- [x] T048 [US1] Implement the always-present active-endpoint bypass rule in `crates/dnet-config/src/endpoint_bypass.rs`, derived from the **same source** as the R4 host route so the two cannot diverge (CC-05, [data-model.md](./data-model.md) §Cross-cutting 2)
- [x] T049 [US1] Restrict the generated config file's ACL to SYSTEM and Administrators in `crates/dnet-config/src/write.rs` (CC-08) — protected inheritable DACL on the run directory **before** any file exists, temp-write + rename, explicit protected file DACL; DACL set/read-back test runs unelevated, full flow is an elevated `--ignored` test

### AmneziaWG integration and the R4 loop hazard

- [x] T050 [US1] Implement the UAPI client (text `key=value` over `\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\<adapter>` — path **corrected** from the spec's `WireGuard\awg0` after verifying the pinned core) in `crates/dnet-config/src/uapi.rs` + `uapi_pipe.rs` ([research.md](./research.md) §R5) — framing and `errno` reply verified against the core's `IpcHandle`; real named-pipe round-trips tested
- [x] T051 [US1] Implement peer plus obfuscation-parameter configuration **in a single UAPI transaction** in `crates/dnet-config/src/amneziawg.rs` — a peer configured without obfuscation is a plain WireGuard handshake, exactly the signature the profile exists to avoid (AW-04)
- [x] T052 [US1] Implement endpoint host-route installation via the physical gateway in `crates/dnet-netstate/src/host_route.rs`, installed **before** the tunnel starts and removed after it stops, including after abnormal stop (AW-02, AW-03) — ordering via the `TunnelBringup` seam (AWG-02/03/04); real `CreateIpForwardEntry2` installer in `win_route.rs` (interface chosen by the route to the *gateway*, owns only rows it created) and `WindowsTunnelBringup` in `win_bringup.rs`; the real install/prefer/remove test is elevated `--ignored`
- [x] T053 [US1] Implement the Profile A outbound as `direct` with `bind_interface` set to the AmneziaWG adapter in `crates/dnet-config/src/bind.rs` (CC-07, [research.md](./research.md) §R4)
- [x] T054 [US1] Enforce that starting Profile A with no gateway available fails cleanly with `NoUsablePath` and starts no tunnel, in `crates/dnet-core/src/profile_start.rs` (AWG-01 — this is the primary loop prevention)

> **Status 2026-09-11 — Phase 4 logic layer GREEN (pre-SPIKE-R4).** The pure generation
> and the safety-critical *orderings* are implemented and unit-tested: CFG-01…07 (10 tests),
> AWG-01…06 (host-route + UAPI, 8 tests), SUP-T1…T4 (11 tests). 181 workspace tests pass,
> clippy `-D warnings` clean. The dangerous orderings (host route before tunnel; rewrite
> before rebind; reap before adapter; kill before undo) are asserted by call order against
> the `TunnelBringup` / `CoreRuntime` seams, exactly as the contract requires. **OS
> remainders** wire the seams to real effects (tokio child spawn + orphan PID discovery,
> `CreateIpForwardEntry2` host routes, the UAPI named-pipe write, T049 config-file ACL);
> these are exercised for the first time by T055, not in CI. **T055 is the live gate.**
>
> **Status 2026-09-11 — OS seams wired; ready for SPIKE-R4.** Every seam now has a real
> implementation: `WindowsCoreRuntime` (tokio spawn + readiness, Toolhelp orphan reaping by
> full image path), `WindowsTunnelBringup` (`CreateIpForwardEntry2` host routes, adapter address
> + adapter-scoped route, UAPI peer/rebind/remove), the UAPI named-pipe client, and the T049 ACL
> writer. Ground-truth verification against the **pinned sources** changed four things:
> (1) the UAPI pipe leaf is `AmneziaWG\<adapter>`, not `WireGuard\awg0`; (2) the primary-core
> config was rewritten for v1.14 — the legacy DNS server format, the `dns`/`block` outbounds, and
> `inet4_address` were all **removed** upstream, so the Phase 4 config would not have started;
> DNS capture is now the native `hijack-dns` action and `route.auto_detect_interface` is on;
> (3) the AmneziaWG core creates its own adapter, so startup is reap → spawn AmneziaWG → await
> adapter → spawn primary; (4) peer endpoints must be IP literals (the Windows core resolves
> hostnames via the OS, which returns FakeIP once the TUN is up). Also: an IP-literal endpoint
> now bypasses by `ip_cidr`, since a `domain` rule never matches raw packets. (5) The Profile A
> config is now validated by the **pinned binary's own `check` command** in the test suite
> (`dnet-config/tests/pinned_core_check.rs`); it caught `default server cannot be fakeip`, so the
> DNS chain now routes A/AAAA to FakeIP by rule, other query types through the tunnel (A) or
> refused (B/C), with a real resolver as the unreachable default.
>
> **Harness:** the Phase 0 harness publishes on `127.0.0.1`, where HV-13 passes vacuously
> (loopback never enters a TUN). T055 therefore runs against an **off-subnet** endpoint via
> `testing/spike-r4/` (runbook in its README), with a negative control that must loop. T018 is
> partially delivered for this: the endpoint container now runs a Profile A server built from the
> same pinned commit (drift guarded by an `xtask` test).
>
> **Licence remediation 2026-09-11 (ADR-0004 Finding 4; extends T005/T006).**
>
> - **Finding.** The pinned primary core was found to embed its own copy of the signed adapter DLL
>   (via `sing-tun`) and the `WinDivert64.sys` kernel driver.
> - **Fix.**
>   - `fetch-vendor` now patches the DLL loader to load the vendored DLL from disk, with a digest
>     check.
>   - It builds with `with_external_windivert`.
>   - `verify-vendor` fails on any executable image embedded in a core.
> - **Verified** by the patch's Go tests, a byte scan of the rebuilt core, and an unelevated runtime
>   check of the missing, official, and tampered DLL cases.
> - **Effect on the T055 runner.** It now stages the DLL beside both cores. A spike run on a binary
>   built before this change still exercises the same DLL version, so its routing results stand.

- [ ] T055 **[GATE] SPIKE-R4 / Plan Phase 3 exit**: run HV-13 — traffic flows end-to-end on Profile A, and packet counts on the tunnel adapter versus the physical interface show **no re-entry**; plus correct host-route rewrite across a simulated interface change. **Phase 5 onward is blocked until this passes.** Failure mode is a silent loop presenting as successful handshake with zero throughput ([research.md](./research.md) §R4). **Requires the harness + fetched vendor binaries (user environment).**
  > **Deferred 2026-09-11 to Phase 8 by the project owner (gate waived at risk).** No off-subnet
  > endpoint is available. A LAN VM cannot stand in for one: the Wi-Fi bridge dropped forwarded
  > traffic and pktmon stopped mid-run (`testing/spike-r4/README.md`). The live run moves to
  > **T098a**, against the provisioned endpoint.
  >
  > **See BUG-007 (2026-10-16):** the one recorded run failed before routing, because the AmneziaWG core cannot create its UAPI pipe from an Administrator shell; run the spike as LocalSystem (`docs/bugs/bug-007-spike-r4-uapi-pipe-owner.md`).
  >
  >
  > **2026-10-20 — a WSL2 lab path exists, not yet run.** `testing/spike-r4/Invoke-WslLab.ps1` makes a
  > WSL2 VM the temporary default gateway and serves the endpoint from its loopback at an off-subnet
  > address, so the gate's own `VACUOUS` check is satisfied without a cloud host (runbook: README
  > section 6). It differs from the failed LAN-bridge attempt in that the counted adapter is the
  > host's `vEthernet (WSL)` NIC, not a Wi-Fi bridge. BUG-007's preflight and error surfacing are in
  > `Invoke-SpikeR4.ps1`.
  >
  > **Lab runs, 2026-10-20 (three elevated runs; the third PASSED).** Run 1 failed on a gate counting
  > defect (it matched the physical adapter by name and missed traffic pktmon filed under the sibling
  > `Host vNic`) and on a lab endpoint whose replies left from the wrong address; run 2 proved the handshake
  > but the lab endpoint had no HTTP origin; run 3 (17:23) returned **PASS**: a 20 MB transfer through
  > Profile A at 144.8 Mbit/s with **0 of 185,297 endpoint packets on a tunnel adapter**, while the control
  > (host route withheld) showed 21,895 re-entering, so the instrument can tell loop from no loop. Server
  > counters agree; restoration left no residue (`testing/spike-r4/README.md` §6).
  >
  > **What the PASS does not cover, so T055 stays open:** (1) the control re-entered but did **not**
  > collapse (its transfer succeeded), so the §R4 failure mode was not reproduced; the result supports
  > "the host route prevents re-entry", not "re-entry is fatal". (2) The required host-route rewrite
  > across a simulated interface change was **SKIPPED** (one path). (3) The path is a virtual NIC on one
  > machine, one run. (4) ~~Hysteria 2 has not been run through the lab~~ **(Hysteria 2 PASSED 2026-10-21 00:31, see below.)** (5) It is not the provisioned
  > endpoint of T098a. **Owner decision pending:** whether this closes T055 or only reduces the risk
  > until T098a is for the owner to say.
  >
  > **Hysteria 2, same lab, run 2026-10-21 00:29-00:31 (`Invoke-WslLab.ps1 -Phase Launch -Transport Hy2`): PASS.** Production
  > configuration: 548.8 Mbit/s, **0 of 98,383 endpoint:44443 packets on a tunnel adapter**. Control (`auto_detect_interface`
  > withheld): **391,218 packets re-entered a tunnel adapter, the transfer failed (0 Mbit/s)**, so for this transport the
  > instrument sees a loop and the §R4 failure mode (re-entry that collapses the transfer) *was* reproduced, unlike
  > Profile A's control. Restoration left no residue. The same limits (3) and (5) apply; Hysteria 2 has no host route, so
  > there is no rewrite across a path change to test for it.
  >
  > **What the logic-level tests cover.** The safety orderings are asserted by call order: host
  > route before tunnel, rewrite before rebind, reap before adapter, kill before undo. A missing
  > gateway fails with `NoUsablePath` and starts no tunnel. The bypass rule and the host route
  > derive from one source. The pinned core's own `check` accepts the Profile A config. An elevated
  > `--ignored` test installs and removes a real host route.
  >
  > **What they do not cover.** Whether the running cores' encrypted packets actually stay off the
  > TUN. Windows route selection with the TUN up, the core's `bind_interface` behaviour and
  > `auto_detect_interface` are only proven by counting packets. The silent-loop failure mode is
  > therefore still open.
  >
  > **Consequence.** This waives the "Phase 5 onward is blocked" rule above. Phases 5–7 may proceed,
  > but anything built on the Profile A transport path is provisional until T098a passes. If T098a
  > fails, the §R4 design (and, per the Implementation Strategy, the dual-core decision) is revisited
  > before that work is accepted. Gate-independent work (T037, T038, T027, T031) goes first.
  > Recorded in `docs/Research-Critique.md` §6.6.

**Checkpoint**: One profile carries real traffic without looping. The riskiest integration is proven.

---

## Phase 5: US1 + US4 — Three Profiles, Probing, and Endpoint Rotation (Plan Phase 4)

**Goal**: The product survives an unknown appliance and a blocklisted endpoint.

**Independent test**: HV-01, HV-02, HV-03, HV-04, HV-09, HV-12.

- [x] T056 [P] [US1] Implement the Hysteria 2 profile generator in `crates/dnet-config/src/hysteria2.rs` — **omit the `bandwidth` section entirely** unless Brutal is explicitly enabled, yielding BBR (CC-03, [research.md](./research.md) §R2)
  > **Done 2026-09-12.** The schema was checked against the pinned core source at `0b89958`.
  > - **Obfuscation is mandatory.** Salamander or Gecko, with a non-empty password different from
  >   the auth password (CC-10). The core would accept an unobfuscated outbound; the type makes one
  >   unrepresentable.
  > - **TLS is verified** by a public CA or a pinned SPKI SHA-256. No `insecure` key exists.
  > - **Defaults:** BBR with an explicit `bbr_profile`, and Chrome QUIC parroting on.
  > - **Credentials** are held in `secret::Secret`: written to the config file, redacted from
  >   `Debug`, `Display` and errors (CFG-11).
  > - **For T093:** with parroting on, the endpoint certificate must be **ECDSA or RSA, never
  >   Ed25519** (pinned core documentation).
  > - **Pinned core `check`** accepts Salamander with a pinned key, Gecko with a public CA, and
  >   Brutal, each for an IP and a hostname endpoint. As a control, it refuses an empty obfuscation
  >   password.
- [x] T057 [P] [US1] Implement Brutal opt-in in `crates/dnet-config/src/brutal.rs` — requires a recorded user acknowledgement and both `up` and `down`; partial configuration fails generation (CC-04, FR-006)
  > **Done 2026-09-12.** The acknowledgement is now a record, not a `bool`:
  > `BrutalAcknowledgement { warning_revision, acknowledged_at_unix }`, kept with the bandwidth in
  > `BrutalOptIn`.
  > - **At enable time,** the domain refuses a record for any revision except
  >   `BRUTAL_WARNING_REVISION`.
  > - **At generation time,** the check runs again, so bumping the revision (T105's warning text)
  >   stops a stored opt-in from producing Brutal.
  > - **A zero on either side** fails generation.
  > - **Order:** the acknowledgement is checked before the bandwidth.
- [x] T058 [P] [US1] Implement the VLESS+REALITY profile generator in `crates/dnet-config/src/reality.rs`, with the borrowed TLS target domain as first-class configuration, not a constant ([docs/Research-Critique.md](../../docs/Research-Critique.md) §4.3)
  > **Done 2026-09-12.**
  > - **Target domain.** `TargetDomain::parse` becomes the ClientHello `server_name`. It refuses:
  >   - IP literals;
  >   - single-label and non-LDH names;
  >   - names under a built-in bypass suffix.
  >
  >   It lower-cases the name.
  > - **uTLS and REALITY are always emitted together.** The pinned core refuses REALITY without
  >   uTLS, which was confirmed by a negative control.
  > - **Fingerprints** are limited to mainstream browsers.
  > - **Validated values:** the public key must be exactly 32 bytes of canonical unpadded URL-safe
  >   base64; the short id must be 1–8 bytes of hex; the user id must be a canonical UUID.
  > - **Flow** is `xtls-rprx-vision` or none.
  > - **Pinned core `check`** accepts both flows for an IP and a hostname endpoint. It refuses a
  >   non-hex short id.
  > - **Credentials** are redacted from `Debug` and from errors.
> **Decision layer done 2026-10-16 (T059–T064): pure logic only.** All six are pure functions
> over measurements, with no I/O and no clock; nothing in `dnetd` calls them yet. The thing that
> measures (runs a probe through a profile, checks an endpoint outside a profile) and the thing
> that acts on the decisions are the Connect orchestration, proposed as T123–T127. Decisions made
> while building them, each reviewable:
> - **Usable** means at least 64 KiB moved at 256 kbit/s or better; a handshake alone is `NoTraffic`.
> - **Race:** the first usable profile wins, but a usable Tier 2 waits up to 3 s for a pending
>   Tier 1. No profile is Tier 1 today, so in practice the first usable one wins at once.
>   Profiles are probed in parallel with a 15 s deadline (SC-003).
> - **Block:** 3 live checks failing in a row; any pass resets the count; reported once.
> - **Re-probe order:** best tier first, then given order; known-blocked profiles wait out a
>   doubling delay (60 s, capped at 900 s). Nothing left means `AllProfilesBlocked`.
> - **Endpoint ranking:** Healthy, then Degraded, then Unknown (known-working beats
>   unmeasured), then lower smoothed RTT, ties in given order. A degraded active endpoint is kept.
> - **Failure classification order:** privilege, configuration (including "no endpoint"), a failed
>   core, no path, captive portal, no endpoint reachable, all profiles blocked. Endpoint versus
>   profile is told apart by a reachability check made outside any profile.
> - **T064 moved** from `crates/dnetd/src/failure.rs` to `crates/dnet-core/src/failure.rs`, so it
>   is under the coverage floor and the tray can reuse the wording.

- [x] T059 [US1] Implement active profile probing in `crates/dnet-core/src/probe.rs` — races configured profiles and selects the first that carries **usable throughput**, not merely a completed handshake (FR-004, HV-12) *(decision layer; 17 tests)*
- [x] T060 [US1] Implement mid-session block detection and automatic re-probe in `crates/dnet-core/src/reprobe.rs` (FR-005, SC-004) *(decision layer; the live checks are not wired)*
- [x] T061 [US1] Implement Tier 1 preference when multiple profiles are viable, and Tier 2 consent gating, in `crates/dnet-core/src/selection.rs` (FR-016b, IPC-04) *(`dnet-ipc`'s `check_tier_consent` is not yet routed through it)*
- [x] T062 [P] [US4] Implement endpoint health probing and EWMA RTT scoring in `crates/dnet-core/src/endpoint_health.rs` *(scoring existed in `health.rs`; this adds the ranking. The probing itself is not wired)*
- [x] T063 [US4] Implement automatic endpoint migration on unreachability, emitting a `ConnectionEvent` so the user is informed rather than silently migrated, in `crates/dnet-core/src/migrate.rs` (FR-012)
- [x] T064 [US1] Implement distinguishable failure reporting for all seven `FailureCause` variants in `crates/dnet-core/src/failure.rs` (FR-039, SC-020) *(moved from `dnetd`; classification and wording)*
- [x] T065 [O5] Design and document the profile update feed integrity model in `docs/adr/0002-profile-update-feed.md` — a feed that can push routing changes is a supply-chain surface and must be signed (FR-007, FR-008, open item O5)
  > **Done 2026-09-12; ADR status Proposed.**
  > - **Mechanism.** Ed25519 in DSSE v1 envelopes. Root keys (2 of 3) are compiled into `dnetd` and
  >   sign a keys document. That document delegates short-lived signing keys, which sign the feed.
  > - **Attack coverage.** Rollback, freeze, fast-forward, mix-and-match and endless-data defences
  >   follow TUF v1.0.36.
  > - **Scope.** Parameters only. The closed schema has nowhere to put routing rules, DNS,
  >   endpoints, credentials, Brutal settings or user-visible text. A compromised signing key can
  >   therefore only weaken obfuscation.
  > - **Endpoint-tied parameters.** Parameters the endpoint must also know (AmneziaWG `s1`/`s2`/
  >   `h1`–`h4`, Hysteria 2 obfuscation, the REALITY target) are staged for re-provisioning. They
  >   are never applied by the client alone.
  > - **Owner decisions D1–D4 approved 2026-09-12**, as recommended:
  >   - D1: files are GitHub Release assets;
  >   - D2: fetching over the physical network while disconnected only on explicit user request;
  >   - D3: root keys 2 of 3, held offline;
  >   - D4: parameters only in v1.
  >
  >   ADR-0002 is Accepted.
- [x] T066 [US1] Implement signed profile feed ingestion in `crates/dnet-core/src/feed.rs` per the ADR from T065
  > **Done 2026-09-12: the verification layer.** Pure, no I/O, under D1–D4.
  > - **Envelope.** DSSE v1 with the PAE; canonical padded standard base64; a 262,144-byte cap
  >   with `read_capped` stopping at cap + 1; 1–8 signatures.
  > - **Signatures.** Strict Ed25519 (`ed25519-dalek` 2.2.0). Distinct keys count once toward a
  >   threshold, and the payload is parsed only after the threshold is met.
  > - **Trust anchor.** `FeedTrust` holds exactly 3 roots with threshold 2 (D3), refuses weak or
  >   repeated roots, and carries the compiled `MIN_KEYS_VERSION` floor.
  > - **Verification order.** Keys and feed documents follow ADR-0002 §4 exactly:
  >   - rollback and equivocation by version and digest, independent of the clock;
  >   - mix-and-match refused by `keys_version`;
  >   - expiry and signing-key windows with 24 h skew;
  >   - rule R evicts feeds from revoked keys, including one at `u64::MAX`;
  >   - `restore` rebuilds state from stored bytes with no time checks;
  >   - `FeedStatus` reports BundledDefaults, Current or Stale.
  > - **Schema.** The closed v1 schema (D4) with the §5.4 bounds, catalogue references, and
  >   `merged_over` rechecking the cross-field rules against the values in effect.
  > - **D1/D2 in `feed::fetch`.** Covers the `profile-feed` release-tag URLs, the two-host
  >   allowlist, and `fetch_route`: the physical network is used only for a `UserRequested` fetch
  >   while `FailClosed`, and a scheduled fetch is never allowed then.
  > - **Shared validators.** Gecko bounds, hostname and target-domain rules, and the BBR and uTLS
  >   enums moved to dnet-core, and the generators now use them. The AmneziaWG bounds stay
  >   feed-only because the harness uses `u32` headers above 2³¹−1.
  > - **Tests.** FEED-01…15 plus role, window, trust-anchor and merge tests. The KAT was
  >   cross-checked with OpenSSL.
  > - **Bug found and fixed.** FEED-09 caught serde ignoring unknown fields on an internally tagged
  >   unit variant (Salamander).
  >
  > **Not yet wired.** Nothing in `dnetd` calls this yet; T066a–T066d below do.
- [ ] T066a [US1] Persist and restore feed state in `dnetd`.
  - Keys and feed envelopes go to `%PROGRAMDATA%\DNet Engine\state\`, using the undo journal's
    durable write and SYSTEM/Administrators DACL check.
  - `restore` runs at start.
  - Before committing a `FeedOutcome::Accepted`, generate a trial config for every bundled profile
    against CC-01…CC-09 and AW-04 (ADR-0002 §4 feed step 8).
  - Raise a `ConnectionEvent` on rule-R eviction and on staleness.
  - Map client parameters into the generators. Stage endpoint parameters for re-provisioning;
    never apply them alone (§6).
- [ ] T066b [US1] Implement feed fetching in `dnetd`, per `dnet_core::feed::fetch`.
  - HTTPS via rustls; every URL checked with `is_allowed_url` **after parsing**; at most 2
    redirects; 30 s timeout; `read_capped`; no cookies or identifiers.
  - Start-up plus a 6 h schedule with jitter, through the tunnel only.
  - The physical network only through a `UserRequested` IPC request while fail-closed (D2).
  - Offline import as a `Mutating` IPC request carrying envelope bytes.
- [ ] T066c [US1] Implement `cargo xtask feed-keygen` and `feed-sign`.
  - Signing runs the payload through `dnet_core::feed` parsing before signing.
  - Must reproduce the FEED-15 known-answer vector.
  - Private keys are never written inside the repository.
- [ ] T066d **[OWNER]** Root key ceremony (D3): generate 3 root keys offline on separate media,
  compile their public keys and `MIN_KEYS_VERSION` into `dnetd`, publish the first keys document
  and feed to the `profile-feed` release. Blocks shipping T066a–T066b.
- [ ] T067 [O7] Verify whether the pinned primary-core version implements the newer obfuscation layer (Gecko) or only Salamander; record in `docs/adr/0003-obfuscation-layers.md` and tune Profile B accordingly (open item O7)
  > **Partial finding 2026-09-12 (T056).** The pinned core accepts `obfs.type = "gecko"`, with
  > `min_packet_size` and `max_packet_size` (`option/hysteria2.go`, `constant/hysteria2.go` at
  > `0b89958`), and its `check` accepts a generated Gecko config. The generator supports both
  > layers. Still open: ADR-0003, choosing the default layer, and tuning.
- [ ] T068 **[GATE] Plan Phase 4 exit**: HV-01, HV-02, HV-03, HV-04, HV-09, HV-12 pass. HV-03 must show the obfuscated profile connecting **and** the unobfuscated control failing

> **Partial evidence 2026-10-16 (not the gate).** `testing/harness/Invoke-Race.ps1` races the real
> Hysteria 2 and VLESS+REALITY profiles through loopback SOCKS probes (`dnet-probe`), against the
> Docker harness, with no elevation. All six scenarios matched:
>
> | Scenario | Result |
> |---|---|
> | no condition | one of the two selected |
> | H2, all UDP dropped | REALITY (TCP) selected, Hysteria 2 failed (**HV-02**) |
> | H4, one profile's port dropped | the other selected, in both directions (**HV-01**, two profiles) |
> | H4 on both ports | nothing usable after 8.3 s |
> | H9, 150 kbit ceiling | both handshakes complete, both measured about 130 kbit/s, both judged too slow, nothing selected (**HV-12**) |
>
> **What this does not cover:** HV-03 (needs AmneziaWG, which cannot be probed through a proxy, and
> the unobfuscated control); HV-04 (a block applied while connected, needs the daemon); HV-09 (an
> endpoint blocklist, needs endpoint migration wired in); and everything that crosses the TUN, since
> a probe has none. The decision logic is `dnet-core` (T059–T064); wiring it into `dnetd` is
> T123–T127. Found on the way: BUG-008, a healthy profile reported blocked half the time.
>
> **Reviewed before publishing.** A security review and a Rust review of the prober found no
> critical issue; their findings (race cancellation leaking core processes, dead probes holding the
> race to its deadline, truncated transfers counted as usable, an unauthenticated loopback proxy,
> predictable credential file names) were all fixed in `fix(probe): harden the prober after
> security and code review`, with tests, and the matrix above was re-run afterwards.

**Checkpoint**: US1 and US4 are independently demonstrable. This is a shippable slice.

---

## Phase 6: US1 + US5 + US6 — Name Resolution, Rules, and Captive Portal (Plan Phase 5)

**Goal**: Browser traffic routes correctly — the case that silently defeats naive implementations.

**Independent test**: HV-10, HV-11, SC-017.

- [ ] T069 [US1] Wire FakeIP synthesis and reverse lookup into rule evaluation in `crates/dnet-core/src/fakeip.rs` (FR-020, FR-021)
- [ ] T070 [US1] Implement encrypted-DNS endpoint blocking so applications fall back to system resolution, in `crates/dnet-core/src/doh_block.rs` (FR-025)
- [ ] T071 [US1] Implement the prominent first-run disclosure and single-action opt-out for encrypted-DNS override, stating the consequence on opt-out, in `crates/dnet-core/src/doh_consent.rs` (FR-025a)
- [ ] T072 [P] [US5] Implement rule precedence evaluation with configuration-time collision rejection in `crates/dnet-core/src/rule_eval.rs` (FR-022)
- [ ] T073 [P] [US5] Implement destination-rule enforcement guaranteeing bypassed traffic never traverses the tunnel, in `crates/dnet-core/src/bypass.rs` (SC-017)
- [ ] T074 [US5] Implement the ETW real-time session on `Microsoft-Windows-Kernel-Network` in `crates/dnet-etw/src/session.rs`, subscribing to `TcpIpConnect` and its IPv6 counterpart — **conditional on SPIKE-O6 (T021) having passed**
- [ ] T075 [US5] Implement 5-tuple to PID attribution reading **`PID` from the event payload, never from `EVENT_TRACE_HEADER`**, in `crates/dnet-etw/src/attribution.rs` ([research.md](./research.md) §R7)
- [ ] T076 [US5] Implement short-TTL attribution caching with eviction, resolving a miss to "no application rule matched" and never to a guess, in `crates/dnet-etw/src/cache.rs`
- [ ] T077 [P] [US6] Implement captive-portal detection and the built-in probe-host exemptions in `crates/dnet-core/src/portal.rs` (FR-026)
- [ ] T078 [US6] Implement portal-expiry recognition so loss of connectivity reports a captive portal rather than a generic failure, in `crates/dnet-core/src/portal_expiry.rs` (US6-3)
- [ ] T079 **[GATE] Plan Phase 5 exit**: HV-10 passes **including for a browser using encrypted DNS**; HV-11 passes; SC-017 verified across 1,000 consecutive connections

**Checkpoint**: Routing is correct for the traffic users actually care about.

---

## Phase 7: US3 — Interface Failover (Plan Phase 6)

**Goal**: The connection survives a degrading or lost interface, and says honestly when it will not.

**Independent test**: HV-06, HV-07, HV-08.

- [ ] T080 [US3] Implement OS IP-interface change notification subscription (not polling) in `crates/dnet-netstate/src/notify.rs` ([research.md](./research.md) §R9)
- [x] T081 [US3] Implement path quality EWMA smoothing so raw samples never drive transitions directly, in `crates/dnet-core/src/quality.rs` (FR-018)
  > **Built 2026-10-21 (not committed). 15 tests.** `PathQuality::observe(sample)` folds one probe (answered with an RTT, or lost) into
  > the smoothed loss, RTT and jitter; RTT and jitter follow RFC 6298 exactly as `health.rs` does for endpoints, loss uses the same
  > 1/8 weight. A lost sample never touches the RTT estimate. `band()` names the result `Good`, `Poor` or `Unusable` (defaults:
  > loss ≥ 15 % or RTT ≥ 300 ms is Poor, loss ≥ 50 % is Unusable; one stray loss reads 12.5 % and is still Good, six in a row make
  > a path Unusable). A band is memoryless on purpose and a signal sitting on a threshold can cross it on noise (a test says so);
  > damping is the failover machine's job, not this module's.
- [x] T082 [US3] Implement the failover state machine with hysteresis and oscillation damping in `crates/dnet-core/src/failover.rs` (FR-016, FR-017, SC-007)
  > **Built 2026-10-21 (not committed). 27 tests, all mutation-checked.** Pure: paths and a time in, new state and a `Decision`
  > (`Stay`, `Move{from,to,reason}`, `NoPath`) out. Nothing here acts on the decision (T083), and there is no way to express a direct route.
  > - *Forced*: a link that is gone (role `Unusable`, or vanished) moves at once, ignoring every limit.
  > - *Voluntary*: the carrying path must stay below Good for 10 s (Unusable: 4 s), the path moved to must have been Good for 30 s
  >   unbroken (FR-017's "remains stable"; waived only when the carrying path is Unusable), 120 s must have passed since the last
  >   move, and no more than 4 moves may have happened in the last 600 s. The last is SC-007 enforced directly, counting forced moves.
  > - Property test: two paths swapping quality at nine different periods for an hour, with the real smoothing in the loop; no
  >   600 s window holds more than 4 moves. **Negative control:** with the dwell and the budget removed the same test fails (120 moves in
  >   10 minutes at a 5 s period). Dropping the stability proof fails 5 tests; making a lost link wait for the dwell fails 6.
  > - Stated limit: a path that is up but dead upstream is a *voluntary* case, so after 4 moves in 10 minutes the machine stays on it
  >   until the budget frees. Not yet done: Tier 2 should probably be more reluctant to move voluntarily than Tier 1, since a move
  >   breaks its connections (FR-016a); decide with the HV-07/HV-08 results in T085, not before.
- [ ] T083 [US3] Implement host-route rewrite **before** tunnel rebind on a carrying-path change, asserted by call ordering rather than timing, in `crates/dnet-netstate/src/rebind.rs` (AW-03, AWG-04)
- [ ] T084 [US3] Implement honest degradation reporting when only one path is available and no move is possible, in `crates/dnet-core/src/degraded.rs` (FR-019, US3-5)
- [ ] T085 **[GATE] SPIKE-R9 / Plan Phase 6 exit**: HV-07 — an open transfer survives an interface change on **both** Tier 1 profiles at the pinned core versions. HV-08 — the Tier 2 profile breaks **and the UI said so beforehand**. **Record each kind's HV-07 result, with the core versions, in `dnet_core::tier::recorded_survival`: only `Survived` makes a profile `Tier1`, and a failure leaves it `Tier2` in configuration and UI. The label follows the measurement, not the intention** ([research.md](./research.md) §R9). A later core pin bump resets the affected kinds to `NotMeasured` until HV-07 is re-run

**Checkpoint**: Failover works, and its limits are labelled truthfully.

---

## Phase 8: US2 — Provisioning (Plan Phase 1 implementation, Plan Phase 7 wizard UI)

**Goal**: A user who has never provisioned a server reaches a verified working endpoint unaided.

**Independent test**: PRV-01…PRV-09 against a mocked provider API; then a real stranger.

### Contract tests first

- [ ] T086 [P] [US2] Write failing contract tests PRV-01…PRV-09 in `crates/dnet-provision/tests/contract.rs` per [contracts/provisioning.md](./contracts/provisioning.md) §5, against a mocked provider API — **no test creates real cloud resources**

### Implementation

- [ ] T087 [US2] Implement credential validation rejecting tenancy/account root credentials and warning on over-privileged scope, in `crates/dnet-provision/src/credential.rs` (PR-01, PR-06)
- [ ] T088 [US2] Implement DPAPI **user-scope** credential storage with exclusion from logs, diagnostics, IPC, and error text, in `crates/dnet-provision/src/secret.rs` (PR-03, PR-04)
- [ ] T089 [US2] Implement the provisioning stage machine in `crates/dnet-provision/src/stages.rs` per [contracts/provisioning.md](./contracts/provisioning.md) §2
- [ ] T090 [US2] Implement `created_resources` recording **before** each create call is issued, never after, in `crates/dnet-provision/src/ledger.rs` (PR-07 — recording after would lose exactly the resources most likely to leak)
- [ ] T091 [US2] Implement capacity-exhaustion handling returning alternative regions with their added RTT, as a retryable outcome rather than an error, in `crates/dnet-provision/src/capacity.rs` (PR-02 stage, US2-2)
- [ ] T092 [US2] Implement idempotent cleanup, reporting unremovable resources with identifying detail, in `crates/dnet-provision/src/cleanup.rs` (PR-08, PR-09, PR-11, SC-011)
- [ ] T093 [US2] Implement server bootstrap installing both server-side cores pinned to the client's bundled versions, generating private keys **on the server**, in `crates/dnet-provision/src/bootstrap.rs` (PR-12, PR-13, PR-14)
  > **Constraint (binding, owner decision 2026-09-12): the Hysteria 2 endpoint certificate MUST use
  > an ECDSA or RSA key, never Ed25519.**
  > - **Why.** The client generator (T056) keeps Chrome QUIC handshake mimicry on by default. Chrome
  >   does not advertise Ed25519 signatures, so the pinned core's documentation says the handshake
  >   fails against an Ed25519 certificate.
  > - **Scope.** Applies to self-signed certificates (pinned by SPKI SHA-256) and to CA-issued
  >   certificates alike.
  > - **Enforcement.** Bootstrap refuses to finish if the generated key is Ed25519.
  > - **Test.** A PRV test asserts the certificate's key algorithm.
- [ ] T094 [US2] Implement idle-reclamation keepalive installation, failing the job if absent, in `crates/dnet-provision/src/keepalive.rs` (PR-15 stage, PRV-09, [research.md](./research.md) §R10)
- [ ] T095 [US2] Implement reachability verification gating `Endpoint` creation — a job failing here yields no endpoint, in `crates/dnet-provision/src/verify.rs` (PR-10)
- [ ] T096 [US2] Implement post-provisioning credential deletion, defaulting to delete, in `crates/dnet-provision/src/revoke.rs` (PR-05)
- [ ] T097 [P] [US2] Implement manual endpoint addition bypassing cloud provisioning entirely, in `crates/dnet-provision/src/manual.rs` (FR-010, US2-5)
- [ ] T098 **[GATE] Plan Phase 1 exit**: one command yields a reachable endpoint that survives idle reclamation; PRV-01…PRV-09 pass
- [ ] T098a **[GATE] Deferred SPIKE-R4 (T055)**: run `testing/spike-r4/Invoke-SpikeR4.ps1` against the endpoint T098 provisioned, which is off-subnet by construction. Exit criteria are T055's own: `PASS` with a looping negative control. `INVALID`, `INCONCLUSIVE` or `VACUOUS` do not satisfy it. On `FAIL`, stop and revisit §R4 before any Phase 5–7 work that depends on the Profile A transport path is accepted

**Checkpoint**: US2 is complete except its UI, which lands in Phase 9.

---

## Phase 9: US1 + US2 — Tray Application and First-Run Wizard (Plan Phase 7)

**Goal**: A non-technical user reaches a working tunnel unaided.

**Independent test**: SC-009 and SC-010, measured on a real stranger with a clean machine.

- [ ] T099 [US1] Scaffold the Tauri v2 + Svelte 5 application in `apps/dnet-tray/`, unprivileged, with no capability to alter system state directly
- [ ] T100 [US1] Implement the IPC client in `apps/dnet-tray/src-tauri/src/ipc.rs` using `dnet-ipc`, treating all responses as untrusted
- [ ] T101 [P] [US1] Implement the tray icon and the single Stabilize toggle in `apps/dnet-tray/src/lib/Tray.svelte` (FR-036)
- [ ] T102 [P] [US1] Implement the status view showing connection state, active profile **and its tier**, active endpoint, and carrying path in `apps/dnet-tray/src/lib/Status.svelte` (FR-037, IPC-05)
- [ ] T103 [P] [US1] Implement distinguishable, actionable failure presentation for all seven causes in `apps/dnet-tray/src/lib/Failure.svelte` (FR-039, SC-020)
- [ ] T104 [US1] Implement the Tier 2 consent dialog warning that established connections will not survive an interface change, in `apps/dnet-tray/src/lib/TierConsent.svelte` (FR-016b)
- [ ] T105 [US1] Implement the Brutal opt-in dialog warning that it degrades every other user on the same access point, in `apps/dnet-tray/src/lib/BrutalConsent.svelte` (FR-006)
- [ ] T106 [US1] Implement the encrypted-DNS override disclosure with one-click opt-out in `apps/dnet-tray/src/lib/DnsConsent.svelte` (FR-025a)
- [ ] T107 [US2] Implement the provisioning wizard, including the guided least-privilege credential creation and revocation instructions **shown before the credential is requested**, in `apps/dnet-tray/src/lib/wizard/` (PR-02, US2-1)
- [ ] T108 [P] [US5] Implement rule management UI labelling application rules **best-effort** in the interface itself, in `apps/dnet-tray/src/lib/Rules.svelte` (FR-023, Principle VI)
- [ ] T109 [P] [US1] Implement the acceptable-use warning shown before first connection in `apps/dnet-tray/src/lib/FirstRun.svelte` (FR-032)
- [ ] T110 [P] [US1] Implement the About screen carrying third-party attribution — **the only UI surface permitted to name the primary transport core** (Constitution licence obligation 1)
- [ ] T111 **[GATE] Plan Phase 7 exit**: a person who has never provisioned a server reaches a verified working endpoint in under 20 minutes unaided (SC-009) and a working connection without documentation beyond the wizard (SC-010)

**Checkpoint**: Feature complete.

---

## Phase 10: Polish & Cross-Cutting Concerns

- [ ] T112 [P] Implement the diagnostic bundle excluding credential material and browsing destinations by default, in `crates/dnetd/src/diagnostics.rs` (FR-035, IPC-07)
- [ ] T113 [P] Add the statement that obfuscation conceals content and protocol but **not** traffic volume or destination, to README, first-run flow, and About screen (FR-033, Principle VI)
- [ ] T114 Build the WiX/NSIS installer in `installer/`, registering `dnetd` as a LocalSystem service and bundling `THIRD-PARTY-NOTICES.md` and every dependency licence text. Install the cores as `primary-core.exe` and `amneziawg-go.exe` **beside `dnetd.exe`**: start-up recovery (T038) reaps orphans by exactly those full paths, so any other layout silently reaps nothing. Place the signed `wintun.dll` **beside each core executable** (the patched primary core loads it only from its own directory, digest-verified; ADR-0004 Finding 4), in an Administrators-only directory; run `cargo xtask verify-vendor` on the staged payload. Create `%PROGRAMDATA%\DNet Engine` (and `run`, `state` beneath it) **owned by SYSTEM or Administrators with a protected DACL**, replacing or refusing a directory that already exists with another owner. Any user can pre-create a `%PROGRAMDATA%` subdirectory and, as its owner, regain rights to replace the generated core config (T049) or the undo journal (T037) inside it
- [ ] T115 Verify installer size at or below 60 MB (SC-012); if exceeded, reduce bundled artifacts before relaxing the target
- [ ] T116 Measure idle RSS at or below 150 MB combined and idle CPU below 1% on a four-core machine (SC-013, SC-014)
- [ ] T117 Verify no measurable slowdown to a concurrent compile, test suite, and editor while connected (SC-015)
- [ ] T118 Run HV-14 and SUP-T2 — after killing `dnetd` mid-session, no core survives, no route or DNS change remains, networking identical to pre-installation (SC-016, FR-029)
- [ ] T119 Confirm coverage at or above 80% outside `apps/` and `vendor/` (SC-022)
- [ ] T120 Audit that zero tests target a live managed network (SC-021, Principle III)
- [ ] T121 [P] Write `README.md` positioning the product as a self-hosted network resilience and tunnel client, never as a firewall bypass, with the acceptable-use warning (FR-032, Constitution Legal posture)
- [ ] T122 Final `cargo xtask lint-branding` and `verify-vendor` audit across the release artifact

### Connect orchestration (added 2026-10-16; proposed, not in the original plan)

T059–T064 decide; nothing yet measures or acts. These tasks join them. They are numbered after the
polish phase only because the original list ended there; by dependency they belong with Phase 5.

- [x] T123 [US1] Implement the connection state machine in `crates/dnet-core/src/engine.rs`: `Engine::step(input, now) -> Vec<Action>` over `Idle`, `Probing`, `Starting`, `Connected`, `Recovering`, `Failed`. Pure; 52 tests *(not wired into `dnetd`)*
  > **Decisions, each reviewable.**
  > - A new connect forgets every earlier viability: a profile blocked on one network may work on the next.
  > - A race includes only profiles that can be probed through a proxy. AmneziaWG needs its own adapter, so it is started directly: when asked for by name, or as the last resort once the raced profiles have failed.
  > - A block stops the tunnel **before** recovery starts, so the posture is fail-closed while another profile is found.
  > - A profile that loses a race because a winner was chosen is **untested**, not blocked; it stays a candidate for recovery. Silent profiles are blocked only when nobody won.
  > - A profile the user names is tried alone; if it fails the connect fails with a message saying so, and no other profile (AmneziaWG included) is substituted.
  > - AmneziaWG is offered only once every raceable profile is blocked.
  > - Before a profile is blamed for failed live checks, the environment (no path, portal, privilege) and the endpoint are ruled out. A dead endpoint is moved in every phase that uses one (starting, racing, recovering, connected).
  > - A connect forgets earlier reach reports; the daemon reports reach after `Connect`.
  > - **Was open, resolved 2026-10-20 by T126 step 1:** late results from cancelled races or tunnels were gated by phase only. The orchestrator now numbers every step that starts background work and drops any report from an older number (`dnetd::orchestrator`); a test shows the engine alone would have accepted such a result.
  > - A failure to bring the chosen tunnel up is reported, not retried on another profile: the cause may be local (privilege, a crashing core), not a block.
  > - A degraded active endpoint is kept; only the probe that makes it unreachable triggers a move.
  > - There is no "acknowledged Tier 2" input: a connect races only the profiles it names or all of them, and the race prefers Tier 1, so the consent case `selection::select` guards cannot arise. Tier 2 is warned about (`WarnTier2`), not refused.
- [x] T124 Add the config store and secret store the orchestrator reads profiles, endpoints and credentials from (`dnet-config`, `dnetd`); credentials never in plain files
  > **Done 2026-10-20 (not committed; security review pending, since it touches credential material).**
  > - **Secret store** (`dnet_config::secret_store`, `credentials`). One bundle per endpoint (AmneziaWG key and
  >   obfuscation, Hysteria 2 passwords with their obfuscation and certificate trust, REALITY id and public
  >   key), validated with the generators' own rules and refused if it has an unknown field, another version or a
  >   value a generator would refuse. Sealed with **DPAPI machine scope**, bound to its own key as DPAPI entropy
  >   (a blob copied under another key does not open), and stored one file per key in a directory only SYSTEM and
  >   Administrators control. `Sealer` and `BlobStorage` are separate traits so Linux can seal with
  >   `systemd-creds` (ADR-0005, T-L10) without touching the rest. Keys are `a-z0-9-` slugs and files carry a
  >   `secret-` prefix, so a key cannot name a path, a stream or a Windows device. Plaintext is wiped after use
  >   (best effort).
  > - **What this does and does not protect.** A blob is useless off this machine and the directory keeps
  >   ordinary users out. Machine-scope DPAPI does not stop an administrator process on this machine.
  > - **Config store** (`dnetd::persist`). `state\config.json`: endpoints (no secrets, only the credential's key) and
  >   per-profile parameters and Brutal opt-in. Read as hostile: strict schema, size and count limits, hosts must
  >   be IP literals or host names, ids are UUIDs, and **one bad entry refuses the whole file**. A profile id
  >   outside the catalogue is refused (ADR-0002 §5.3). Tier and viability are never stored. A Brutal
  >   acknowledgement of an older warning is dropped with a note, not an error (FR-006). Errors never echo the file.
  > - **Start-up.** `DnetService::production` loads it. A refused file leaves the daemon up read-only with the
  >   reason, refuses every mutating request, and nothing may be saved over it (it may be the only copy).
  > - **Shared trust code.** The "owned by SYSTEM/Administrators, protected DACL, read through the same handle"
  >   logic moved from `dnet-netstate::undo_file` to `dnet_config::trusted_file`; the undo journal now uses it.
  >   Behaviour is unchanged and its tests moved with it.
  > - **Verification.** 73 new tests; mutation checks on the key binding, the sealing step, the credential-key
  >   grammar, the stale-acknowledgement rule and the refused-config gate each failed as they should. Real DPAPI
  >   runs in the unelevated tests. **Not run (need an elevated shell):** the three `--ignored` tests that
  >   restrict a directory and read it back (`cargo test -p dnet-config -p dnet-netstate -- --ignored`).
  > - **Not done, and why.** Saving is unused until configuration requests carry payloads (Phase 9), and user
  >   routing rules are not persisted yet (US5, Phase 6). The gap that left T126/T127 with nothing to connect to
  >   is closed by T128.
- [x] T125 Define the IPC payloads for connect, disconnect, status and the event stream, carrying `ConnectionEvent` with its `because` (`dnet-ipc`, IPC-04, IPC-06)
  > **Done 2026-10-20 (not committed; security review pending).** Contract: `ipc-protocol.md`, tests IPC-10…14.
  > - **Connect.** `Request::Connect` carries `profile` and `endpoint`, validated as hostile input
  >   (id grammar, canonical UUID, a consent flag that must be a boolean). `encode_request` is the client half.
  > - **Status.** `StateSnapshot` is complete (endpoint, failure with `title`/`detail`/`action`, warnings,
  >   posture). One consistency rule is applied on both encode and decode. Path fields are omitted, not faked.
  > - **Events.** Every `ConnectionEvent` gets a `because`, including those whose domain form has none.
  >   `EventBus` numbers them, replays the current session (256 max), and caps subscribers (16).
  > - **Stream.** `Subscribe` becomes a one-way, write-timed stream (`server::stream_events`); the real named-pipe
  >   path is tested in `tests/pipe_stream.rs`. Mutation checks on the cap and the encode-side consistency
  >   rule both failed the tests as they should, then were reverted.
  > - **Daemon.** `GetState` is served through the checked encoder; `DnetService` owns an `EventBus`.
  > - **Found, not fixed: nothing enforces the kill switch.** `FailClosed` exists only as a domain value
  >   (T028); no task makes the OS drop traffic when the tunnel is lost, and the constitution rules out the
  >   kernel driver that would do it. A user-mode mechanism (the ADR-0005 table names WFP filters on Windows)
  >   needs its own task and ADR. Until then the snapshot's posture is a decision, and says so.
  > - **Still to do for the endpoint selector:** the engine takes no endpoint. T126 refuses a named one.
- [x] T126 Implement the Connect orchestrator in `crates/dnetd`: feed `Engine` its inputs (race results from `dnet-probe`, live checks, endpoint probes, environment, reach) and perform its actions through the supervisor, route and posture seams
  > **Step 1 done 2026-10-20 (not committed): the orchestrator and its IPC wiring, against a scripted fake.** `crates/dnetd/src/orchestrator.rs`, 19 tests, plus 7 service-level tests in `service_impl.rs`.
  > - **Shape.** One actor owns the engine; every input is a message to it. An executor performs the work of a step
  >   *in order* (the engine asks for `StopTunnel` then `StartTunnel` when it moves to another endpoint; the order is
  >   what keeps traffic from leaking in between). Races run in the background and can be cancelled. Everything the OS
  >   does is behind the `Effects` trait, so every transition is testable on any machine.
  > - **Stale results are dropped by construction** (attempt numbers). The reachability answer is delivered before
  >   the race result, because the engine can only say "endpoint unreachable" instead of the misleading "all profiles
  >   blocked" if it has it first.
  > - **A race found by its own test.** `Handle::connect` judged "already connecting" from the published state, which lags
  >   the request, so two quick connects were both accepted and the second silently ignored. Acceptance now claims
  >   an atomic flag, cleared only after the new state is published.
  > - **What clients see is always consistent**: the snapshot is derived from the engine after every message and a
  >   test checks every reachable phase encodes. Only `Connected` is `Tunnelled`; everything else is `FailClosed`.
  > - **IPC.** `Connect`, `Disconnect` and `GetState` go to the orchestrator when one is attached; otherwise the
  >   old honest "not available". `endpoint` in `Connect` is refused with a reason (the engine cannot honour one
  >   yet). The recovery and configuration gates still come first.
  > - **Mutation checks** on stale-report dropping, ordered execution, snapshot consistency and reach-before-race: the first
  >   round caught two of four, which exposed two weak tests; both were rewritten around scenarios where the wrong
  >   behaviour gives a visibly wrong answer, and all four are now caught.
  > **Step 2 built 2026-10-20 (not committed). Live gate PASSED 2026-10-20 23:42 (AmneziaWG only) and 23:56 (full matrix, below). T126 is done; the caveats listed under it stand.** The real effects, attached to the production
  > `dnetd`. Everything that decides what to do is portable and tested against fakes; the Windows code only carries it out.
  > - `plan.rs` (22 tests): endpoint + profile + stored credentials -> the primary core's configuration, the AmneziaWG peer, the
  >   probe job. **Each profile dials its own stored port on the endpoint's host** (the endpoint's single port is not used to
  >   connect), and the peer address, host route and `direct` rule come from one `ActiveEndpointBypass`. A host *name* and an
  >   IPv6 address are refused with a message that says why (resolving a name before the tunnel exists is a DNS-leak decision,
  >   not a detail). `assess_endpoints` leaves unusable endpoints out of the engine and reports each reason.
  > - `tunnel.rs` (16 tests): composes `start_cores` / `bring_up` / `tear_down` / `shutdown_all`. A failed start leaves nothing
  >   running (and tears the peer down only if bring-up was attempted: a test caught it tearing down a peer never installed);
  >   a second start takes the first down; stop is peer, route, cores, then undo, each step attempted whatever the last did;
  >   the generated configuration (it holds credentials) is deleted as soon as the core has read it.
  > - `checks.rs` (12 tests): reach is `Reachable` or `Unknown`, never `Unreachable` (a TCP connect cannot tell a dead host from
  >   a filtered one, and the engine reads `Unreachable` as "migrate"); live check and endpoint probe go through the tunnel to
  >   the endpoint's measurement origin, judged by the same `judge` rule that chose the profile.
  > - `effects.rs` (Windows only, compiles, **no automated test of its own**): paths, restricted directories, the real runtime and
  >   bring-up objects, credential lookup (read when needed, not kept), elevation check.
  > - `Orchestrator::shutdown` + `main.rs`/`svc.rs`: the service stopping waits for the tunnel to be stopped (SUP-04), and tells
  >   the SCM the stop is pending. Covered by orchestrator tests with fakes; the real SCM stop is not exercised by the lab.
  > - **Decision made here, owner to confirm: the measurement origin.** Probes and live checks need a known HTTP origin reachable
  >   only through the endpoint; nothing defined where production gets one, and this project operates no infrastructure to
  >   default to. It is now stored per endpoint with the credentials (`EndpointCredentials::measure_origin`, optional, validated
  >   with the prober's own rule when stored, moved to `dnet_core::origin`). An endpoint without one is reported unusable.
  > - Known limits: hostname endpoints unsupported; profile-tunable client parameters (BBR profile etc.) not yet read from the
  >   profile; captive portal not detected; a core crash is noticed only through failing live checks (no restart policy yet).
  > - **Gate:** `Invoke-WslLab.ps1 -Gate Connect` (SYSTEM task runs the real `dnetd` with a private %PROGRAMDATA%, user shell
  >   drives it as the console user). **Run 1 (AmneziaWG only), PASS:** idle and FailClosed; connect accepted; a second connect
  >   refused with `ServiceBusy`; Connected in about 10 s; state names `awg-default` and is `Tunnelled`; 5 000 000 of 5 000 000
  >   bytes through the tunnel (170 Mbit/s); disconnect; adapters gone; no host route or adapter left behind; the event stream
  >   carried `ProbeStarted`, two `ProfileBlocked`, `ProfileSelected`, each with a reason.
  > - **Defect the run exposed, fixed:** `hy2-default` and `reality-default` were reported *blocked* ("did not respond in time")
  >   although they were never tried, because the endpoint had no credentials for them. A statement about the user's network
  >   that was false. Profiles no usable endpoint can serve are now not offered to the engine (`plan::served_profiles`), so the
  >   engine says "the only profile configured" instead.
  > - **Matrix run 2026-10-20 23:56, PASS (4 of 4 cases, every step), through the real `dnetd` as SYSTEM:** the lab VM serves
  >   AmneziaWG, Hysteria 2 (udp/44443) and REALITY (tcp/8443). Each case: idle and FailClosed; connect accepted; second connect
  >   refused (`ServiceBusy`); Connected; state names the right profile and is `Tunnelled`; 5 MB through the tunnel; still
  >   Connected after a live check; disconnect; adapters gone; every event has a reason; and at the end no adapter or endpoint
  >   host route left behind.
  >
  >   | case | carried by | time to connect | 5 MB transfer |
  >   |---|---|---|---|
  >   | default (race decides) | `hy2-default` | 4.1 s | 414 Mbit/s |
  >   | `hy2-default` by name | Hysteria 2 | 1.2 s | 777 Mbit/s |
  >   | `reality-default` by name | VLESS+REALITY | 1.3 s | 880 Mbit/s |
  >   | `awg-default` by name | AmneziaWG (started directly, cannot be raced) | 3.7 s | 155 Mbit/s |
  >
  >   The daemon's own log shows each live check reaching the origin about 5 s after its tunnel came up, through the outbound
  >   of the profile that carries it. Throughput here is a loopback-speed virtual link; it says nothing about real networks.
  > - **Finding, not fixed (new task T130):** after a tunnel is stopped and another started, the primary core logs
  >   `router: missing fakeip record, try enable experimental.cache_file` for connections that used a fake address handed out in
  >   the previous session (3 times in 4 cycles, background traffic). FakeIP mappings live in the core's memory and die with it.
  >   Options: persist them (`experimental.cache_file`, `store_fakeip`) or flush the resolver cache when a tunnel stops. Needs a
  >   decision on the cache file's location and lifetime, and a contract change (`contracts/core-config.md`).
  > - **Still not covered by any live run:** the Windows service stop (SCM) path, a core crashing mid-session, a host *name*
  >   endpoint. (The T055 packet-count gate for Hysteria 2 has since passed: see T055.)
  > - **Re-run after the security review's two fixes (2026-10-21 00:27, `-Gate Connect`): PASS, same four cases, no residue.**
  >   The review closed two defects in the new code: private directories were not checked for a pre-planted owner or junction
  >   (now `dnet_config::write::prepare_private_dir`, refused before any change is made), and the reachability check sent TCP
  >   to UDP-only ports, a recognisable burst (now only TCP-carried ports, `plan::reach_ports`).
- [x] T130 FakeIP mappings do not survive a tunnel restart (see the T126 finding). Decide persist vs flush, implement, add a lab step that reconnects and checks the log stays free of `missing fakeip record`
  > **Built and run live 2026-10-21 (`-Gate Connect`): driver PASS, 10 resolver flushes, 0 failed, 1 stale-address connection.**
  > - **Decision: flush, not persist.** `experimental.cache_file` with `store_fakeip` would write every name the user looked up to
  >   a file on disk, which is exactly what the diagnostics rules keep out (FR-035: no browsing destinations). It would also
  >   bring back address-to-name pairs that a fresh pool can hand to a different name. The mappings are meant to die with the
  >   core; what must not outlive it is the system resolver's copy of the fake addresses. No change to `contracts/core-config.md`.
  > - `TunnelHost::flush_resolver_cache`: called after the cores are down on every stop and every failed start (never before:
  >   a live core can still answer with new fake addresses), and before the cores start (a daemon that died mid-session
  >   never flushed). Replacing a running tunnel flushes once, not twice. Nothing is flushed when nothing was started.
  >   Best effort: a failure is a warning and never stops a start or a stop.
  > - Windows: `%SystemRoot%\System32\ipconfig.exe /flushdns` by absolute path (no `PATH` or working-directory lookup from a
  >   SYSTEM service), no console window, killed after 5 s. The underlying call (`DnsFlushResolverCache`) has no binding in
  >   `windows`/`windows-sys`, and loading `dnsapi.dll` by name from a service would add a DLL-search risk, so the supported
  >   command is used instead.
  > - Tests (5 new in `tunnel`, 2 in `effects`): flush after the cores are gone, before any core starts, again after a failed
  >   start, once when replacing a tunnel, never when nothing started. Mutation-checked: flushing before the teardown fails
  >   5 tests, dropping the start-time flush fails 5.
  > - Lab: `Invoke-ConnectGate.ps1` now judges the daemon log after the run. It fails if no flush was logged or any failed (so the
  >   second check cannot pass vacuously), and if `missing fakeip record` appears more than once per four flushes.
  > - **Live result, stated plainly.** The one miss left (`198.18.0.3`, 1.4 s after a flush) was `sync-v2.brave.com` in the
  >   *previous* session; the new session had issued only `.2`. A browser keeps resolved addresses in its own memory, which no
  >   system-wide flush can reach, so this residue is expected and the core's refusal is the safe outcome. **The baseline is too
  >   noisy to claim an effect size:** earlier runs without a flush logged 8, 2 and 0 misses. What is firm is the mechanism: every
  >   flush ran and none failed, and the one miss traces to a program's own cache. The threshold (1 per 4 flushes) is a guard
  >   against the flush silently doing nothing, not a measured improvement.
  > - **Residual risk, not fixed (T131):** every session's pool starts at `198.18.0.2`, so an address a program remembers can
  >   later belong to a *different* name. Over HTTPS the certificate check stops it; over plain HTTP the program would reach the
  >   wrong host, and the name it meant is revealed to it. Alternating the pool between `198.18.0.0/16` and `198.19.0.0/16` per
  >   tunnel would turn that into the same harmless miss. It changes `contracts/core-config.md` (CC-02) and the deterministic
  >   output (CC-09), so it needs its own task and a decision.
- [ ] T131 Stop a remembered fake address from aliasing a different name in the next session: alternate the FakeIP pool between the two /16 halves of `198.18.0.0/15` (and the IPv6 pool) per tunnel start, keeping config generation deterministic for a given input (CC-09). Update `contracts/core-config.md` CC-02, the bypass-overlap guard test, and add a lab check that a stale address from the previous session is refused, not answered with another name
- [x] T132 Give the control protocol a version and make every client check it (IPC-15)
  > **Built 2026-10-21 (not committed). Found while sorting the product shape (ADR-0006): the protocol had no version at all.** A GUI or any other
  > client is updated separately from the service, as with Docker Desktop and Docker Engine, so each must be able to tell whether the other still
  > speaks its language. New read-only `GetVersion`, answered by `dnet-ipc`'s dispatch itself (after authorization, never reaching the service):
  > `{protocol_version, min_protocol_version, service_version}`. A client speaking `c` can talk when `min <= c <= protocol_version`; outside that it stops
  > and says which end to update. `dnet_ipc::version` holds the rule and a strict parser (integers from 1, `min <= newest`, the build string limited to 64
  > plain characters, nothing echoed in errors). `dnet_ipc::client::check_version` judges the reply; a service that answers `InvalidRequest` predates the
  > request and counts as incompatible, not as fine. `dnetctl` now asks first on every command and goes no further on a mismatch (new exit code 6), and
  > has `dnetctl version` / `--version` / `-V` / `--json`, which reports a mismatch instead of stopping at it.
  > - Tests: 8 in `version`, 6 in the client, 3 contract (IPC-15), 9 in `dnetctl`; the fakes that stood in for the daemon now pass the handshake, so the
  >   tests that follow it still test the stage they were written for. **Mutation-checked:** answering before authorizing fails the unauthenticated test;
  >   skipping the check in `dnetctl` fails 4 tests.
  > - Security review: a new read-only request with a constant reply; no state, no privilege, no new input beyond the request name. The one new parse of
  >   untrusted data is the client's reading of the reply, which is strict and bounded.
  > - Not yet run live: the lab's `dnetctl` cycle will exercise it against the real service the next time `-Gate Connect` runs.
- [x] T127 Implement `dnetctl` (connect, disconnect, status, events) so the whole path can be driven and tested before the tray exists
  > **Built 2026-10-21 (not committed); proven against the real daemon unprivileged, live gate run pending.**
  > - `dnet_ipc::client` (12 tests): the client half of the pipe, reusable by the tray. Replies are read as untrusted input
  >   (oversized, non-UTF-8, truncated, not JSON, error without a code: each an error, none echoed, none a panic).
  > - `crates/dnetctl` (49 tests): `status`, `connect [--profile] [--accept-tier2] [--no-wait]`, `disconnect`, `events [-f]`,
  >   `profiles`, `endpoints`, `--json`, `--timeout`. Hand-parsed (no new dependency); an option a command does not take is
  >   refused, never ignored. Waiting is polling `GetState`, not a subscription. Exit codes: 0 done, 1 refused or failed,
  >   2 usage, 3 service unreachable, 4 timed out (the work carries on), 5 unexpected reply. A profile id the service would
  >   refuse is a usage error and nothing is sent. Everything the service sends is stripped of control and bidirectional
  >   characters before it reaches the terminal. The display says the kill switch is "not yet enforced by the system",
  >   because that is true. Tests drive every command against the real server dispatch in memory with the clock paused;
  >   six mutation checks were each caught.
  > - **Run against the real `dnetd --console` over the real pipe, unprivileged:** status, profiles, endpoints, events work;
  >   connect and disconnect are refused with a reason; a bad profile id and an unknown command are exit 2; with the service
  >   stopped it says so (exit 3).
  > - **A daemon defect it exposed, fixed (`Handle::snapshot`):** right after a Connect is accepted, `GetState` still returned
  >   the state before it (`Disconnected`, or the previous `Failed`) until the actor ran. Any client that asked and looked back
  >   was told the connection had not started. A pending connect now reads as connecting. Two tests; removing the fix fails them.
  > - **Lab:** `Invoke-ConnectDriver.ps1 -Dnetctl` runs a last cycle through the real `dnetctl.exe` (status, idle disconnect,
  >   connect waits, second connect refused, status --json, traffic, events, disconnect waits, adapters gone).
  > - **Who is on the other end (found reviewing the client's threat model):** until the real service starts, any local
  >   process can create a pipe named `\\.\pipe\DNetEngine\control`, and a client would show its answers (a spoofed
  >   "Connected") to a user who may rely on them. The client now reads the **owner of the pipe object** and talks only to
  >   one owned by SYSTEM or Administrators (`dnet_ipc::client::Trust::ServiceOwnedOnly`, the default for everyone; the
  >   tray must keep it). The development opt-out is explicit, named for what it risks, and not the default
  >   (`dnetctl --allow-unprivileged-service`). Shown on the real pipe: an unprivileged `dnetd` is refused, naming whose pipe
  >   it is; with the opt-out it is served. Acceptance of a SYSTEM-owned pipe is exercised by the lab's `dnetctl` cycle.
  >   Not covered: a pipe squatter that is itself an administrator (it could do anything already).
  > - Known rough edge, daemon side: a mutating request from a service that cannot look up the console user (any non-SYSTEM
  >   run) is refused with "no interactive console session is active", which blames the session when the cause is privilege.
  > - Not done: the installer must place `dnetctl.exe` (T114); no PATH or shell-completion work.
- [x] T128 `cargo xtask import-harness-endpoint --host <ip> [--dry-run] [--replace] [--label <name>]` puts the simulated harness endpoint (`testing/harness/.state/*.json`) into the saved configuration and the sealed secret store, so T126/T127 have an endpoint to connect to (added 2026-10-20; developer tooling, not a product feature: the product creates endpoints through provisioning T093 and import T097 over IPC)
  > **Done 2026-10-20 (not committed).** `crates/xtask/src/import_harness.rs`, 18 tests.
  > - **Safe by construction.** `--host` has no default (a silent loopback default would make the routing-loop gate
  >   meaningless; loopback is accepted with a warning for the prober). A real run needs an elevated shell and
  >   **refuses before touching anything** otherwise: an unelevated attempt would leave a user-owned state
  >   directory that the service rightly refuses to trust. `--dry-run` validates everything and writes nothing.
  > - **Never destructive.** A refused saved configuration is never overwritten (it may be the only copy). The
  >   secret is written first and the configuration second, so the configuration never names missing
  >   credentials; a failed second write removes a secret that was new. `--replace` keeps the endpoint's id.
  >   Unrelated endpoints and profile settings survive.
  > - **Never prints a secret.** Errors name a file and a field, never a value (serde would otherwise quote one).
  > - **Verified** against the real harness files by `--dry-run` (all three transports parsed and validated by the
  >   same rules the secret store applies); mutation checks on the rollback and the refuse-to-overwrite rule failed
  >   as they should. **Not run:** a real import (needs an elevated shell).
  > - **Spec gap found and closed here.** `data-model.md` gives an endpoint one `host + port`, but a host serves
  >   AmneziaWG (UDP 51820), Hysteria 2 (UDP 44443) and REALITY (TCP 8443) on different ports, and the
  >   provisioning contract already speaks of "the profile ports". Each profile's server port is therefore stored
  >   **with its credentials**, and T126 pairs it with the endpoint's host when it builds each profile's address.
  >   The generators and the host-route logic are unchanged. The port on the `Endpoint` is display-only.

---

## Dependencies

```
Phase 1 (Setup)
   └─▶ Phase 2 (Harness)  ── T020 GATE ──┐
                             T021 GATE ──┤
   └─▶ Phase 3 (Core + IPC) ─ T039 GATE ─┤
                                          ▼
                             Phase 4 (Single profile) ── T055 SPIKE-R4 GATE
                                          │
                            ┌─────────────┴─────────────┐
                            ▼                           ▼
              Phase 5 (Profiles + rotation)   Phase 8 (Provisioning)
                   T068 GATE                       T098 GATE
                            │                           │
                            ▼                           │
              Phase 6 (DNS + rules + portal)             │
                   T079 GATE                            │
                            │                           │
                            ▼                           │
              Phase 7 (Failover) ── T085 SPIKE-R9 GATE   │
                            │                           │
                            └─────────────┬─────────────┘
                                          ▼
                             Phase 9 (Tray + wizard) ── T111 GATE
                                          ▼
                                   Phase 10 (Polish)
```

**Hard blocks**: T020 blocks all transport work. T039 blocks all privileged operations. **T055 (SPIKE-R4) blocks Phases 5–7 entirely.** T021 (SPIKE-O6) determines whether T074–T076 exist at all. T085 (SPIKE-R9) determines final tier labelling.

**Phase 8 is independent of Phases 5–7** and can proceed in parallel once T055 passes.

> **Amended 2026-09-11 (owner waiver, `docs/Research-Critique.md` §6.6).** The live T055 run is
> deferred to **T098a** in Phase 8, so Phases 5–7 are no longer hard-blocked. Work in them that
> depends on the Profile A transport path is provisional until T098a passes.

## Parallel Execution Opportunities

| Phase | Parallel batch |
|---|---|
| 1 | T002, T003, T004, T009 |
| 2 | T011–T016 (six condition scripts, separate files) |
| 3 | T022, T023 (tests); then T024–T030 (seven domain modules) |
| 4 | T040, T041, T042 (three contract test files) |
| 5 | T056, T057, T058 (three profile generators); T062 |
| 6 | T072, T073, T077 |
| 9 | T101, T102, T103, T108, T109, T110 |
| 10 | T112, T113, T121 |

**Largest win**: Phase 3's seven domain modules (T024–T030) are pure, dependency-free, and unit-testable without Windows — the single best parallelisation point in the project.

## Implementation Strategy

**MVP scope**: Phases 1–5 deliver US1 (restore access) and US4 (endpoint rotation) as a working, demonstrable product driven from the command line. That is the smallest slice that solves the stated problem.

**Incremental delivery**:
1. **Phases 1–4** — one profile carries traffic without looping. The riskiest work is proven early, by design.
2. **Phase 5** — three profiles, probing, rotation. Survives an unknown appliance. *Shippable to a technical user.*
3. **Phase 6** — correct browser routing. *Shippable to a careful user.*
4. **Phase 7** — failover. Delivers the second half of the problem statement.
5. **Phases 8–9** — provisioning and UI. *Shippable to anyone.*
6. **Phase 10** — polish and the resource-budget gates.

**Why the risky work is front-loaded**: T055 (SPIKE-R4) is the task most likely to invalidate the architecture. It sits at Phase 4 rather than late, so that if the bind-interface plus host-route design cannot carry traffic without looping, the dual-core decision is revisited after roughly four phases of work rather than nine.
