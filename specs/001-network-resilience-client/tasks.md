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
  > **2026-10-26 (not committed), review fix.** `capture_client_identity` ignored a failed `RevertToSelf`, so a runtime worker thread could go on running as the pipe client; it now aborts the process (Microsoft's documented response). The `TOKEN_USER` buffers here and in `dnetd/src/console.rs` were `Vec<u8>` read through a `TOKEN_USER` reference (alignment not guaranteed; undefined behaviour); now `Vec<u64>`. Windows-only: checked by `cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -D warnings` from Linux (clean), **not run on Windows**.
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
  > **2026-10-26 (not committed), review fix (test-first).** The output forwarder read lines with `while let Ok(Some(line))`, so the first output that was not UTF-8 ended the reading: the marker after it was never seen, and the pipe stopped being drained, so a chatty core would block on a full pipe while still looking alive. Two Linux tests reproduced both (RED), then a bounded, lossy line reader (`for_each_line`, lines cut at 8 KiB) fixed them. Added `unix_tests` (11, `/bin/sh` stand-ins) and `line_tests` (3); `process.rs` line coverage on Linux 0% → 96%, the crate 50% → 95.7%.
- [x] T044 [US1] Implement jittered exponential backoff **with a ceiling and an attempt limit**, terminating in `CoreFailedPersistently` rather than looping forever, in `crates/dnet-supervisor/src/restart.rs` (SUP-03)
- [x] T045 [US1] Implement orphan reaping at service start in `crates/dnet-supervisor/src/reap.rs` — kills cores left by a prior crashed run **before** any new adapter is created (SUP-05) — ordering via the `CoreRuntime` seam (SUP-T3); real discovery in `orphans.rs` (Toolhelp snapshot, **full image path** match, never name-only), tested by reaping a real simulated orphan
- [x] T046 [US1] Implement teardown of both cores plus full undo replay on any `dnetd` stop in `crates/dnet-supervisor/src/shutdown.rs` (SUP-04)

### Configuration generation

- [x] T047 [US1] Implement primary-core configuration generation in `crates/dnet-config/src/primary.rs` — TUN inbound present for **every** profile, FakeIP `198.18.0.0/15` and `fc00::/18`, deterministic output (CC-01, CC-02, CC-09)
- [x] T048 [US1] Implement the always-present active-endpoint bypass rule in `crates/dnet-config/src/endpoint_bypass.rs`, derived from the **same source** as the R4 host route so the two cannot diverge (CC-05, [data-model.md](./data-model.md) §Cross-cutting 2)
  > **2026-10-26 (not committed), review fix in the loop-prevention path (test-first; security review below).** The tunnel's generated core configuration had **no `direct` route rule for the endpoint**: the service holds its rules built with no endpoint (`builtin_rules_for(None, ..)`), and `plan_tunnel` passed those straight to the generator, so only the host route kept the core's packets to the endpoint off the TUN. data-model §4 and CC-05 require both ("rule evaluation and route table must agree or the loop returns"). The old test only checked that the address appeared somewhere in the config, which the outbound's server field satisfied. Fixed by `dnet_core::builtin_rules::with_active_endpoint` (endpoint bypass at precedence 1, right after DNS capture; the other built-in bypasses move down one, keeping ids and order; the encrypted-DNS block and every person's rule keep their numbers; the set is re-validated) and its use in `plan_tunnel`. A new test asserts, for all three profiles, a `direct` rule for `203.0.113.10/32` with only DNS capture ahead of it (RED before the fix); 4 dnet-core tests. **Security review:** routing-rule generation only; the change adds a bypass that matches exactly the address the host route already sends direct, so it cannot route anything around the tunnel that the host route does not; DNS capture still outranks it (port-53 queries to the endpoint stay captured). **Consequence for the live gate:** the 2026-10-20 WSL-lab PASS was measured without this rule, so it shows the host route alone suffices; T098a should be run on a build with it.
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
  > **2026-10-26 (not committed).** Added `crates/dnet-core/tests/feed_untrusted_input.rs`: arbitrary bytes as a keys document, a feed and stored state are refused without panicking; a keys or feed envelope changed in any one byte is refused, or accepted (live or restored) only as exactly the signed document. 6 tests, 256 cases each (signatures are slow in a debug build), ~13 s.
- [x] T066a [US1] Persist and restore feed state in `dnetd`.
  - Keys and feed envelopes go to `%PROGRAMDATA%\DNet Engine\state\`, using the undo journal's
    durable write and SYSTEM/Administrators DACL check.
  - `restore` runs at start.
  - Before committing a `FeedOutcome::Accepted`, generate a trial config for every bundled profile
    against CC-01…CC-09 and AW-04 (ADR-0002 §4 feed step 8).
  - Raise a `ConnectionEvent` on rule-R eviction and on staleness.
  - Map client parameters into the generators. Stage endpoint parameters for re-provisioning;
    never apply them alone (§6).
  > **Built 2026-10-24 (not committed); security review is required before commit** (the profile feed, core configuration generation, key material). Inert until the key ceremony (T066d): with no root keys
  > compiled in (`crates/dnetd/src/feed_trust.rs`, `ROOT_KEYS = None`) the service has no feed machinery and an import answers "not available".
  > - **`dnetd::feed_service`** (21 tests, real signed documents): restore at start re-verifies both stored envelopes from their bytes (a bad one is dropped and reported, never trusted; a file that cannot
  >   be read is reported); an offered keys document or feed goes through `dnet_core::feed`'s acceptance; **the envelope is written before the state changes**, so a failed write changes nothing; rule R
  >   evicts a feed the new keys no longer cover (and a restart agrees); an expired feed stays in use and is reported out of date once, re-armed by the next feed; a restart never drops a feed for being old.
  > - **`dnetd::feed_trial`** (10 tests): feed step 8. A configuration is generated for every bundled profile through `plan_tunnel` and `build_set_device` with the feed's client **and** endpoint values
  >   (each candidate REALITY domain, a Gecko layer, AmneziaWG values merged over the bundled ones, cross-field rules checked on the result). The fixture is in the documentation range (192.0.2.1) with
  >   made-up key material; nothing of the person's setup is read. One profile that will not generate refuses the whole feed (step 9). It catches what the parser cannot: `jmin` alone is in bounds, but
  >   above the bundled `jmax` it leaves no room.
  > - **Applied from the next connection.** `ClientDefinitions` (`dnet_core::feed::applied`, 5 tests) carries the client section; `plan_tunnel` and `probe_job` take it, so **what is raced is what will run**.
  >   Hysteria 2's congestion profile and Chrome parroting and REALITY's TLS fingerprint come from the feed where it speaks, the bundled default where not. A tunnel already up is never regenerated.
  >   The endpoint section is only **staged** (`staged_endpoint_updates`), never applied. **AmneziaWG's junk-packet proposal is validated and kept but not applied:** this client keeps those three numbers in the
  >   endpoint's stored credentials and nothing records whether a person chose them, so a feed could silently overwrite a value someone set.
  > - **Events.** `ConnectionEvent::DefinitionsChanged` (`Updated { sequence, endpoint_updates }`, `Evicted`, `OutOfDate`, `Discarded`), each with a `because`; sent when it happens, and `OutOfDate` is noticed
  >   when a client next asks for the state (the feed needs no timer to keep working). Contract: `ipc-protocol.md`.
  > - **Mutation checks:** 16 of 16 caught (writes not checked, trial skipped, definitions not published or not reset on eviction, stale reported every time or never re-armed, discarded documents unreported,
  >   AmneziaWG device check skipped, proposed layer and domains not tried, import ignoring the trial, the feed's values ignored by the generators).
  > - **Not done:** the person's consent flow for the staged endpoint changes (T107's wizard and `dnet-provision`); the `precedence: user, then feed` rule has no "user" yet (no setting to put there); the
  >   feed is not shown in `GetDiagnostics`.
  > **2026-10-26 (not committed), review fix (test-first).** Rule R eviction was not stored: the evicted feed's file stayed, so a later keys document that listed its signer again would bring it back at the next start, though the running service had dropped it (and until then every start said the stored feed "no longer verifies"). `StateFile` gained `remove`; `offer_keys` removes the feed file after an eviction; a failed removal is a note, not a refusal (the keys are stored, and the next start discards it as before). Two new tests and one tightened; the revival test failed before the fix.
- [x] T066b [US1] Implement feed fetching in `dnetd`, per `dnet_core::feed::fetch`. **Built 2026-10-24 (not committed); the live path has not met the real hosts.**
  - HTTPS via rustls; every URL checked with `is_allowed_url` **after parsing**; at most 2
    redirects; 30 s timeout; `read_capped`; no cookies or identifiers.
  - Start-up plus a 6 h schedule with jitter, through the tunnel only.
  - The physical network only through a `UserRequested` IPC request while fail-closed (D2).
  - Offline import as a `Mutating` IPC request carrying envelope bytes.
  > **Offline import built 2026-10-24 (not committed).** `Request::ImportFeed` (`FeedImport`, IPC-23, 4 tests) and `dnetctl import-feed --keys-file … --feed-file …` (files bounded by the size cap, a Windows byte-order
  > mark tolerated, content never printed, nothing interpreted by the tool). The service runs every check a fetched document gets plus the trial; keys are taken first, and if the feed is then refused the error
  > says the keys were taken. Service-level tests (6): applied and announced, repeated import changes nothing, wrong signing key, a feed that parses but would not generate, garbage not echoed, no trust anchor.
  > **Fetching built 2026-10-24 (not committed; security review required: it is network code in the SYSTEM service).** `dnetd::feed_fetch` (21 tests) and `FetchFeed` (IPC-23), `dnetctl check-updates`.
  > - **The rules are enforced by this code, not by the HTTP library:** every URL, the first and each redirect target, is checked with `is_allowed_url` *before* it is requested; redirects are followed one at a
  >   time by `fetch_asset`, at most two, and a third (or a loop) is refused without its target being requested; a body over the cap is refused (checked in the transport as it is read, and again here). The real
  >   transport (`HttpTransport`, `reqwest` with rustls) follows no redirect, ignores any proxy, keeps no cookie, is HTTPS-only, has a 30 s timeout and a fixed `User-Agent`.
  > - **When (D2).** The schedule (start-up delay, then every 6 h plus up to 30 min of jitter) runs a check **only while a tunnel carries traffic**; otherwise it looks again in 5 minutes and never goes out.
  >   A check the person asks for goes through the tunnel if there is one and directly if not, and the reply says which. A second request while one runs is `ServiceBusy`.
  > - **A check fetches both documents before offering either**, so a feed that cannot be fetched leaves the keys unapplied too; keys go first; the same verification and the trial generation apply.
  >   A requested check that finds nothing is announced (`CheckFailed`, `Unreachable` or `Refused`); a scheduled one is only logged (before the publisher has published anything every one would fail).
  > - **Found while wiring it: a real bug in T146, fixed.** `main` kept the orchestrator handle taken at start-up, but a configuration change replaces the orchestrator, so a stop request after a change would have
  >   shut down the retired one and left a live tunnel up (SUP-04). Both entry modes now ask the service for the orchestrator *at shutdown*; a test pins that the handle it gives out is the live one.
  > - **Mutation checks:** 7 of 9 caught at first (the URL check, redirect limit, size cap, claim release, both announcement rules, fetching both before offering either), the two survivors being one equivalent mutant (the schedule's
  >   match already refuses the physical network, so two layers agree) and one real gap (no fetch test sent a feed that parses but fails the trial), now covered.
  > - **Not covered by any test, and why:** `HttpTransport` itself (its settings cannot be inspected and it needs the real hosts). It is small, and its job is to do nothing the fetch rules do not allow, but the
  >   first live run is where it is proven: `dnetctl check-updates` against a published feed (T066d).
- [x] T066c [US1] Implement `cargo xtask feed-keygen` and `feed-sign`.
  - Signing runs the payload through `dnet_core::feed` parsing before signing.
  - Must reproduce the FEED-15 known-answer vector.
  - Private keys are never written inside the repository.
  > **Built and run for real 2026-10-22 (not committed).** `crates/xtask/src/feed_tool.rs` (24 tests) and, in `dnet-core`, `feed::sign::{rehearse_keys, rehearse_feed}` (4 new tests).
  > - `feed-keygen --out <file>`: a key from the operating system's randomness (`getrandom`, already in the lock), a one-line base64 secret file that **never overwrites** (mode 0600 where the platform has it),
  >   and only the **public** key printed. Refuses a path inside the repository.
  > - `feed-sign --document keys|feed --payload ... --key ... --root-public x3 [--keys-envelope ...] --out ...`: parses the payload with the client's own parser, signs with `feed::sign::seal` (the function
  >   FEED-15 pins to an independently produced known-answer signature; the tool's key derivation is also checked against that vector's public key), then **offers the finished envelope to the client's own
  >   acceptance code as a fresh install would** and writes nothing unless the client would accept it. So it refuses one root (threshold), a root signing a feed, a key the keys document does not list, a feed
  >   under another keys version, an expired document, the same key twice, and a key file inside the repository; it never overwrites its output.
  > - **Run end to end with the real commands** (4 keys, keys document signed by 2 of 3 roots, feed signed by the delegated key, and each refusal above): every refusal fired, no refused run left a file, no
  >   secret was printed. The throwaway keys are in `%TEMP%\feed-smoke-_3a2s9c5`; **delete that directory** (a delete I attempted was held up by a tool gate, so it is still there; it holds only test keys).
  > - Mutation-checked: 10 mutations caught (writing a key in the repository, using one from it, skipping either rehearsal, the same key twice, overwriting, the input cap, echoing a secret in an error, a
  >   lax key file, accepting fewer than three roots). One survivor (a key file with whitespace inside it) got its own test. The envelope-size check I first wrote was unreachable (the rehearsal refuses
  >   an oversized envelope with the client's own rule), so it was removed rather than left as a second rule to drift.
  > - **Security review is still required before commit** (key material). A runbook for the key ceremony (T066d) is `docs/feed-publishing.md`.
- [ ] T066d **[OWNER]** Root key ceremony (D3): generate 3 root keys offline on separate media,
  compile their public keys and `MIN_KEYS_VERSION` into `dnetd`, publish the first keys document
  and feed to the `profile-feed` release. Blocks shipping T066a–T066b.
  > **2026-10-26 (not committed): checklist written around `docs/feed-publishing.md`** (`docs/owner-gates.md`), with pass criteria and four negative checks. Not run.
- [x] T067 [O7] Verify whether the pinned primary-core version implements the newer obfuscation layer (Gecko) or only Salamander; record in `docs/adr/0003-obfuscation-layers.md` and tune Profile B accordingly (open item O7)
  > **Partial finding 2026-09-12 (T056).** The pinned core accepts `obfs.type = "gecko"`, with
  > `min_packet_size` and `max_packet_size` (`option/hysteria2.go`, `constant/hysteria2.go` at
  > `0b89958`), and its `check` accepts a generated Gecko config. The generator supports both
  > layers. Still open: ADR-0003, choosing the default layer, and tuning.
  > **ADR-0003 written and accepted 2026-10-24 (option C: Salamander by default, Gecko an offered endpoint option; owner's decision).** It records what is established (core accepts Gecko; the generator, credentials and feed carry both; both ends must agree; provisioning bootstraps
  > Salamander only) and what is not (no comparison of the two against a real filter, Gecko's cost, tuning), recommends Salamander by default with Gecko as an endpoint option, and lists three questions for the owner.
  > **2026-10-26 (not committed): closed by ADR-0003 as its own Consequences section says (option C needs no code).** Checked against the pinned sources and recorded in ADR-0003: both the client and server sides of the pinned core wire Gecko; 512/1200 are the core's own defaults; the core refuses `min <= 0`, `min > max`, `max > 2048`; only long-header packets are split (2 to 8 chunks). Questions 2 and 3 of ADR-0003 remain the owner's; tuning remains a live-gate measurement.
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

- [x] T069 [US1] Wire FakeIP synthesis and reverse lookup into rule evaluation in `crates/dnet-core/src/fakeip.rs` (FR-020, FR-021)
  > **Built 2026-10-22 (not committed), reinterpreted: the synthesis and the reverse lookup are the primary core's, not ours.** The core answers a lookup with a placeholder from a private pool, keeps the
  > name-to-address table in its own memory (T130: it dies with the core), and routes the next connection by the name. The product cannot read that table and does not need to: rules are evaluated on
  > *names* (`rule_eval`, T072), and the evaluator never matches a named destination with an address range. What the product owns, and now has in one place (`dnet_core::fakeip`, which
  > `dnet_config::primary::FAKEIP_INET4/6` re-state): the pool definition, `is_placeholder` (so anything that shows a destination can say "a name" rather than print an address that means nothing outside
  > the tunnel; IPv4-mapped forms included), and `check_user_range`, which makes `RoutingRule::user` **refuse a range inside the pool** (`RangeInsideFakeIpPool`): nothing real lives there, so such a rule can
  > only be a mistake. A range that merely *contains* the pool (`0.0.0.0/0`, `198.0.0.0/8`) is fine. Whether the real core really skips address rules for a name it resolved from a placeholder is an
  > assumption written down in `rule_agreement.rs`; **T079 checks it.** 6 tests; 5 mutations, all caught.
- [x] T070 [US1] Implement encrypted-DNS endpoint blocking so applications fall back to system resolution, in `crates/dnet-core/src/doh_block.rs` (FR-025)
  > **Built 2026-10-22 (not committed); live check is the T079 gate (HV-10 with a browser using encrypted DNS).** The mechanism is the one browsers document: make their encrypted resolver unreachable
  > and they use the system's. 14 well-known resolver suffixes (the browsers' bundled lists; Firefox's canary name is included so it switches its own encrypted DNS off) are refused as a lookup and as
  > a connection, and port 853 (DNS over TLS and QUIC) is refused. New: `RuleAction::Reject` and `RuleMatcher::EncryptedDnsPort` (port 853, Reject only). Rules are built in at precedences 100–114: after
  > the local-network and portal bypasses (1–9, which therefore still win, so a resolver on the router keeps working) and before every person's rule (200 and up: `USER_RULES_START`).
  > - **Only the product may refuse traffic** (`RejectIsBuiltinOnly`), so a person's rule can never silently black-hole something. **A person's rule cannot undo the block**: the store refuses a user
  >   rule numbered below 200 while the block is in force (`OutranksEncryptedDnsBlock`), and refuses removing a block rule through the rule list (`BuiltinRuleMissing`); only the opt-out (T071) lifts it,
  >   and the opt-out must lift all of it (`EncryptedDnsBlockLeftBehind`).
  > - `builtin_rules_for(endpoint, policy)` is `builtin_rules` plus the block; `builtin_rules` itself is unchanged (it is the *required* set). The generator writes `action: "reject"` routes and, for names,
  >   `reject` DNS rules placed before the FakeIP answer (CFG-13); the DNS chain follows precedence.
  > - **Said plainly, in the module header:** it is a list of names. A resolver not on it, or reached by a bare address, is not blocked and a program using it keeps bypassing destination rules.
  > - Tests: 12 in `doh_block`, 2 in `contract.rs` (CFG-13), 2 properties in `rule_agreement.rs` (no user rule can lift what the built-ins refuse; the claim is not vacuous), 5 in the store. **18
  >   mutations, all caught** (`scratchpad/mut_t070.py`: refusal generated as a bypass, DNS rule missing, wrong port in the evaluator and in the config, user rules allowed to outrank, band collision,
  >   opt-out leaving rules behind, users allowed to add a refusal, port 853 tunnelled, no block in the default set, the rule list able to lift the block, stale refusals after an opt-out, the store
  >   accepting an outranking rule, the canary dropped). One property failed on the way and was a mistake in the property, not the code: the local network and the portal hosts outrank the block *by design*.
  > - **Not done:** the opt-out is not saved (`ConsentState::{to_stored,from_stored}` exist; the saved-configuration format is the IPC/config boundary and needs its own reviewed change), and
  >   `SetEncryptedDnsHandling` is dispatched since T146 (2026-10-24), and the choice is saved. A restart returns to the protective default (block, disclosure shown again). **Security review is still required before this is
  >   committed** (it is routing, DNS and core-configuration generation).
- [x] T071 [US1] Implement the prominent first-run disclosure and single-action opt-out for encrypted-DNS override, stating the consequence on opt-out, in `crates/dnet-core/src/doh_consent.rs` (FR-025a)
  > **Built 2026-10-22 (not committed); the screen is T106.** `disclosure()` (what is overridden, why, how to turn it off; versioned, so a changed text is shown again), `ConsentState`
  > (`needs_disclosure`, `acknowledge_disclosure`, `opt_out` in one call returning the consequence the interface must show — "rules for sites and domains will not apply to traffic from programs that use
  > their own encrypted lookups" —, `restore`, which needs no consent because it only narrows what programs may do). The stored form falls back to the protective default for anything it does not
  > recognise: a damaged record cannot switch the override off. The text names no technology. Wired into the daemon's store (`opt_out_of_encrypted_dns_block`, `restore_encrypted_dns_block`,
  > `acknowledge_encrypted_dns_disclosure`), with no IPC path yet (see T070). 8 tests in the module; 4 of the 18 T070 mutations are in this module (all caught).
- [x] T072 [P] [US5] Implement rule precedence evaluation with configuration-time collision rejection in `crates/dnet-core/src/rule_eval.rs` (FR-022)
  > **Built 2026-10-22 (not committed).** `evaluate` (lowest precedence that matches decides; ties keep the order given; nothing matching is the tunnel), over a `Flow` that is either a *name* or an
  > *address*. A named flow is decided by its name and never by a CIDR rule (a name has no address yet, under FakeIP); an application rule applies only when the program is known, so an unknown program is
  > skipped, never guessed. `normalize_domain` (lower case, one trailing dot dropped, ASCII or `xn--` only, label and length rules), `normalize_application` (case-insensitive, `\\?\` prefix and trailing
  > separators ignored), IPv4-mapped IPv6 turned into the IPv4 address it is (so `::ffff:10.0.0.1` cannot sidestep a `10.0.0.0/8` rule), and `shadowed` (a rule an earlier one always catches, so the
  > interface can say so). `RoutingRule::build` now refuses a domain pattern that cannot be a name, which closed a way for a rule to silently do nothing. Collision rejection at configuration time was
  > already `validate_rule_set`. Pure logic; the tests are in the module.
- [x] T073 [P] [US5] Implement destination-rule enforcement guaranteeing bypassed traffic never traverses the tunnel, in `crates/dnet-core/src/bypass.rs` (SC-017)
  > **Built 2026-10-22 (not committed); the live half is T079.** Not a new `bypass.rs`: the guarantee is that the *generated configuration* and the *evaluator* agree, so it is
  > `crates/dnet-config/tests/rule_agreement.rs` (property tests over generated rule sets and destinations) over `dnet_config::primary::route_rules`, now public. Anything the evaluator calls a bypass is
  > `direct` in the generated routes, never the tunnel; plaintext DNS is always captured; no rule a person adds can lift what the built-ins refuse (T070). **It found a real leak:** a bypass rule written
  > `Example.COM.` was emitted as written and the core compares names as it is given them, so the destination went through the tunnel. Patterns are now written in the normal form. The test states the
  > assumptions it makes about the core (exact, case-insensitive `domain`; suffix `domain_suffix`; `ip_cidr` tested only against a destination given as an address); **they are checked against the real
  > core in the lab, T079, not here.** I deleted `rule_agreement.proptest-regressions` while iterating, which held the seed of the trailing-dot case; the direct test
  > `patterns_are_written_in_the_form_a_connection_arrives_in` covers that fix.
- [x] T074 [US5] Implement the ETW real-time session on `Microsoft-Windows-Kernel-Network` in `crates/dnet-etw/src/session.rs`, subscribing to `TcpIpConnect` and its IPv6 counterpart — **conditional on SPIKE-O6 (T021) having passed**
  > **Built 2026-10-22 (not committed); it has compiled and linted but NOT been run: starting a trace needs an elevated shell.** SPIKE-O6 passed (ADR-0001, run 2), so this is in scope. `EtwSession::start(cache)`
  > subscribes to the provider, and for each IPv4/IPv6 connect event reads `PID`, `saddr`, `daddr`, `sport` and `dport` from the payload, decodes them (T075) and inserts into the cache (T076); `stop`/drop
  > ends the session. Counters only (seen, attributed, undecodable) and **no per-connection logging**, because a line per connection would be the destination log that FR-035 forbids. The callback only
  > decodes and inserts; a panic or a slow consumer cannot touch traffic. Also `process::image_path(pid)` (the path form application rules are written in; least access that works; run here against this
  > process). **Not wired into `dnetd`.**
  > - **Owner, elevated shell:** `cargo test -p dnet-etw -- --ignored --nocapture` runs `live_connects_made_by_this_process_are_attributed_to_it` (50 loopback connections; passes only if ≥ 95 % are
  >   attributed to this process and none is undecodable). ADR-0001 measured 100 % with the spike. **Unverified until then:** that `ferrisetw`'s address parse (raw bytes as the octets) agrees with the
  >   kernel's byte order for `saddr`/`daddr`; ports are verified by the ADR, addresses were not measured by the spike. The live test would show it.
  > **2026-10-26 (not committed), review fix.** A real-time session outlives a crashed process, so the fixed session name stayed taken and every later start failed (`AlreadyExist`) until a reboot. `EtwSession::start` now stops the stale session by name and tries once more. Windows-only, type-checked from Linux; **not run** (the `#[ignore]` live test still needs an elevated shell; to check the fix, kill `dnetd` with the session up and start it again).
- [x] T075 [US5] Implement 5-tuple to PID attribution reading **`PID` from the event payload, never from `EVENT_TRACE_HEADER`**, in `crates/dnet-etw/src/attribution.rs` ([research.md](./research.md) §R7)
  > **Built 2026-10-22 (not committed).** Pure, no ETW type: `decode(RawConnect) -> BestEffortAttribution`. The process id is the payload's; **the ports are swapped into host order in exactly one place** (the
  > binding constraint of ADR-0001, with a test over ports that are not palindromes, and a test that shows reading them as parsed gives the wrong connection); addresses keep the kernel's order; an
  > IPv4-mapped IPv6 spelling is the same connection as the plain one; process 0, a zero port, a family that does not match the event id, and a non-connect event are refused. The type is named
  > `BestEffortAttribution` because there is no exact attribution (a missed event, a reused id, the gap before use).
- [x] T076 [US5] Implement short-TTL attribution caching with eviction, resolving a miss to "no application rule matched" and never to a guess, in `crates/dnet-etw/src/cache.rs`
  > **Built 2026-10-22 (not committed).** TTL 30 s, capacity 4096 (both parameters), time passed in so every behaviour is tested without waiting. An entry at or past its TTL is **not trusted even before it
  > is evicted**; the cache never exceeds its capacity however fast connections arrive (oldest first); a connection seen again replaces the earlier answer and keeps its life (the old record does not evict
  > it); only the **exact** connection (both ends) resolves, with no port-only or nearest match; a miss is `Resolution::NoApplicationRuleMatched`. `SharedCache` survives a poisoned lock.
  > **Mutation-checked: 12 mutations (both ports unswapped, process 0 accepted, zero ports, family unchecked, mapped addresses, the TTL edge, an expired answer trusted, an unbounded cache, a refreshed
  > record evicting its live entry in each of the two places, eviction on insert), all caught.** Builds for the Linux target too (the crate has Windows-only modules behind `cfg`).
- [x] T077 [P] [US6] Implement captive-portal detection and the built-in probe-host exemptions in `crates/dnet-core/src/portal.rs` (FR-026)
  > **Logic built 2026-10-22 (not committed); not wired: `dnetd` makes no probe request yet.** The probe hosts' exemptions already existed (`builtin_rules`, CAPTIVE_PORTAL_PROBE_SUFFIXES). New: `classify`
  > (an unchanged known body from the operating system's own two probes is `Open`; a redirect, any other body or an HTML page where text was expected is `Intercepted`, with the login address when given; a
  > connect failure or timeout is `Unreachable` and **a dead network is never called a portal**; anything it cannot make sense of is `Inconclusive`, never a guess), `combine` (two probes), and
  > `login_url` — the portal's address comes from whoever runs the network, so it is offered for the person's own browser to open, never fetched by the product, and only if it is plain `http(s)`,
  > with no credentials, no control character and a bounded length (`fallback_login_url` otherwise). Pure logic.
  > **Wired 2026-10-24 (not committed; security review required: it makes network requests whose replies are hostile).** `dnetd::portal_probe`: a plain-HTTP fetch of the two pages the operating system itself
  > fetches, through the physical network, bounded in time and size (head 8 KiB, body 512 bytes, overall timeout), **never following** a redirect (the login address is for the person's browser), anything that
  > is not an HTTP reply is `Inconclusive`. The request carries nothing about the person: a fixed path and host, a fixed `User-Agent`, no cookie. `RealEffects::reach` takes a reading beside the endpoint
  > reachability check (within 3 s, so a slow probe never turns an endpoint's answer into "unknown"), and the orchestrator now feeds the engine the environment **after** the check, so a failed connect
  > blames the portal instead of the endpoint. 27 tests against a local listener standing in for each kind of network (open, redirect, page in place, dead, silent, junk, endless, whitelisted-one-host, a
  > redirect not followed). Mutation checks: 9 of 9 caught after three gaps in the tests were closed (an endless reply, a non-HTTP reply with a valid code and the right body, a new network starting over).
  > **Still to do:** an IPC action that opens the checked login address (the failure cannot yet carry it), and a live run on a real portal (HV-11).
  > **2026-10-26 (not committed), review fix (test-first).** `login_url` refused control characters but let through characters that reorder or disguise text (U+202E, U+2066, a zero-width space, Cyrillic look-alikes). The address is shown to a person before they open it, so it is now ASCII only, as a `Location` header is by RFC 9110/3986 (non-ASCII is percent-encoded or punycode). 4 new refused cases.
  > **Proposed, not built: the login address never reaches the window.** `portal::classify` keeps it, but `FailureCause::CaptivePortalUnsatisfied` carries no data, so `GetState` cannot say it and the window's "Open login page" can only say "open any web page". Minimal path: an optional `login_url` beside the failure in `StateSnapshot` (encoder refuses it with any other cause; decoder re-checks it with `login_url`), filled from the last `PortalReading`; the window shows the host and opens it with the shell's default browser only on a click (Windows `ShellExecuteW` "open" on an `http(s)` URL; no new dependency). Needs a security review (an address chosen by the network operator, opened on request).
- [x] T078 [US6] Implement portal-expiry recognition so loss of connectivity reports a captive portal rather than a generic failure, in `crates/dnet-core/src/portal_expiry.rs` (US6-3)
  > **Logic built 2026-10-22; wired 2026-10-24 (see T077).** At connect, one interception counts as the confirmation, so a person who signs in and later loses the portal's session is told so on the next reading (`PortalMemory`); while connected a reading is taken after each failed live check. `PortalWatch::observe` reads the stream of readings: two interceptions in a row make a portal (one odd reply is not one); after
  > a portal has been signed in to on this network, **one** is enough and is reported as `SessionExpired` (a network that was open a moment ago and intercepts again is, overwhelmingly, a portal session that
  > ended); `Unreachable` and `Inconclusive` neither confirm nor clear; `Cleared` only on an unchanged probe; a new network starts over. Each change is announced once.
- [ ] T079 **[GATE] Plan Phase 5 exit**: HV-10 passes **including for a browser using encrypted DNS**; HV-11 passes; SC-017 verified across 1,000 consecutive connections

**Checkpoint**: Routing is correct for the traffic users actually care about.

---

## Phase 7: US3 — Interface Failover (Plan Phase 6)

**Goal**: The connection survives a degrading or lost interface, and says honestly when it will not.

**Independent test**: HV-06, HV-07, HV-08.

- [x] T080 [US3] Implement OS IP-interface change notification subscription (not polling) in `crates/dnet-netstate/src/notify.rs` ([research.md](./research.md) §R9)
  > **Built 2026-10-21 (not committed). 22 new tests (8 debounce, 14 path projection) plus 2 elevated ones not yet run.**
  > - `notify::ChangeSource` (Windows): subscribes to interface, route and address changes for both IP families; each callback does one
  >   non-blocking `try_send` and nothing else. `notify::settled` (portable, paused-time tests) turns a burst into one report: quiet for 750 ms,
  >   or cut off at 5 s for a network that never stops changing. The signal carries no detail; what changed is found by reading the machine.
  >   The callbacks' context is deliberately leaked (one sender per service run) rather than freed after `CancelMibChangeNotify2`: if Windows
  >   were still inside a callback, freeing it would be a use-after-free, and I could not confirm from the documentation that it waits.
  > - `paths::project` (portable) turns the system's interface and IPv4 default-route tables into `dnet-core`'s `NetworkPath`: physical adapters
  >   only (Hyper-V/WSL/VMware/VPN excluded), this product's own `dnet-*` adapters excluded by name as well (a tunnel counted as a way out is
  >   the R4 loop), a down adapter or one with no default route listed as `Unusable` (a lost link, not a vanished one), an on-link route as a
  >   usable path with no gateway, a default preference by kind (wired 20, Wi-Fi 10, cellular 0) so failover can return to a preferred path.
  >   `paths::current()` reads it on Windows.
  > - **Live, unelevated:** `cargo run -p dnet-netstate --example watch_paths` on this machine listed the Wi-Fi as a usable path through the same
  >   gateway as the routing table, two unplugged wired adapters as unusable, and none of the virtual adapters.
  > - **Mutation-checked:** letting own adapters count fails the loop-protection test; counting a down adapter as usable fails its test; the
  >   debounce reporting early fails two.
  > - **Run elevated 2026-10-21, both pass:** a real interface change (the loopback metric, restored after) reaches the channel, and with the source
  >   dropped the same change signals nothing (the negative control: the cancel works). The live `watch_paths` run also showed the first reading of the
  >   Wi-Fi adapter as `Unusable` while it still had its gateway (not yet up, associating), then `Standby` after the change; the live test had asserted
  >   that a gateway means usable, which is wrong in exactly that moment, and was corrected to: a usable path is an adapter that is up. Three further
  >   events produced identical lists, which is why the monitor (T133) reports whether a refresh changed anything.
  > - T083's ordering rule (rewrite the host route, then rebind) already exists and is tested in `host_route::on_carrying_path_change` (T052); what
  >   remains for T083 is calling it from a failover decision, which needs a monitor in `dnetd` and a way to measure each path's quality.
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
- [x] T083 [US3] Implement host-route rewrite **before** tunnel rebind on a carrying-path change, asserted by call ordering rather than timing, in `crates/dnet-netstate/src/rebind.rs` (AW-03, AWG-04)
  > **Done 2026-10-21 (not committed), in `host_route.rs` and `dnetd/src/tunnel.rs` rather than a new `rebind.rs`:** the ordering was already `on_carrying_path_change` (T052). New: `host_route::move_to_gateway`, which does the same two steps in the same order and also returns the route that is *installed afterwards*, because the steps can fail separately: if the rewrite succeeds and the rebind fails the table already holds the new route, and a caller that kept the old one would later remove a route that is not there and leave the new one behind. `Tunnels::carry_over(gateway)` uses it and remembers the installed route. Tests assert call order (`route~` then `rebind`), that a failed rewrite is never followed by a rebind and keeps the old route, that a failed rebind still leaves the stop removing the new route, and that a primary-core tunnel is left alone.
- [x] T084 [US3] Implement honest degradation reporting when only one path is available and no move is possible, in `crates/dnet-core/src/degraded.rs` (FR-019, US3-5)
  > **Built 2026-10-22 (not committed). 35 new tests (13 reporter, 6 explanation, 6 monitor, 3 engine, 3 wire, 3 loop, 1 end-to-end through the orchestrator); 16 mutations, each caught.**
  > - **What it says:** when the carrying path has stayed below `Good` for as long as the failover machine itself waits before leaving a path (10 s), the user is told it is poor and *why the connection is
  >   staying*: `OnlyPath` (nothing else exists), `NoBetterPath`, `Proving` (a better one is not yet proven), `Dwell` (a move was just made), `Budget` (SC-007's limit). It means "it would have moved if
  >   it could": a dip is never announced. `Recovered` follows only a prior `Degraded`, after 10 s of good. No claim is made about a path that is not measured, and a path that has gone quiet is not
  >   "recovered". It is repeated only when it says something new (another reason, or `Poor` to `Unusable`).
  > - **Where:** `degraded.rs` (reporter, pure), `FailoverState::explain_staying` (shares the `is_better` rule with the decision, extracted so the explanation and the decision cannot disagree: the dwell test
  >   proves it, by moving as soon as the dwell the explanation named has passed), `PathMonitor::report`, `ConnectionEvent::{Degraded, Recovered}`, `Input::Connectivity`, the wire encoding
  >   (`quality`, `staying`, a `because` that differs by reason and band and never says "moved"), the watch loop (a second channel, reported after each decision tick) and the orchestrator (one task
  >   forwards both channels).
  > - **Limits, stated:** only a *steered* profile (AmneziaWG) is measured, so only for it can a path be called poor; Hysteria 2 and REALITY are observed and have no quality to report (a probe is a real
  >   packet and nothing would act on the answer). This is not a promise that silence means "fine". The state snapshot (`GetState`) does not carry degradation yet, only the event stream does; making it
  >   first-class state, per-network quality and the network name is T144.
  > - **Security review (IPC boundary):** two additive server-to-client events. No new request, no new input from a client. Every field is an enumeration or a decimal interface id; the `because` strings are
  >   static text chosen by enumeration, so no peer-controlled or personal text (no network names) is in them. A producer error (a `Degraded` of a good network) is refused rather than sent. Nothing here
  >   touches privileged operations, routing, DNS, credentials or the undo path.
  > - **Not proven live:** needs a real network that degrades while it is the only one; T085's hardware (and the lab, which has one path) can show it.
- [ ] T085 **[GATE] SPIKE-R9 / Plan Phase 6 exit**: HV-07 — an open transfer survives an interface change on **both** Tier 1 profiles at the pinned core versions. HV-08 — the Tier 2 profile breaks **and the UI said so beforehand**. **Record each kind's HV-07 result, with the core versions, in `dnet_core::tier::recorded_survival`: only `Survived` makes a profile `Tier1`, and a failure leaves it `Tier2` in configuration and UI. The label follows the measurement, not the intention** ([research.md](./research.md) §R9). A later core pin bump resets the affected kinds to `NotMeasured` until HV-07 is re-run

**Checkpoint**: Failover works, and its limits are labelled truthfully.
  > **2026-10-26 (not committed): runbook written, not run.** No `hv_07`/`hv_08` test exists, although `quickstart.md` names one. The manual procedure and the pass criteria are in `docs/owner-gates.md` (two physical paths, an adapter disabled mid-transfer, three passes per profile, then `recorded_survival`).

---

## Phase 8: US2 — Provisioning (Plan Phase 1 implementation, Plan Phase 7 wizard UI)

**Goal**: A user who has never provisioned a server reaches a verified working endpoint unaided.

**Independent test**: PRV-01…PRV-09 against a mocked provider API; then a real stranger.

### Contract tests first

- [x] T086 [P] [US2] Write failing contract tests PRV-01…PRV-09 in `crates/dnet-provision/tests/contract.rs` per [contracts/provisioning.md](./contracts/provisioning.md) §5, against a mocked provider API — **no test creates real cloud resources**
  > **Written 2026-10-22 (not committed): 32 tests, all nine PRV contracts and the guarantees around them, run through the public API against `dnet_provision::mock::MockProvider`, the only provider the crate
  > ships (it keeps what it is asked to make in a table, so a test sees what *exists* after a crash, not only what the job believes).** Honest about the order: the tests were written *after* the code, not
  > before it, so "failing first" was not shown; **the substitute is mutation testing — 27 mutations across the crate (the intent not written, a ledger failure not stopping a create, a missing keepalive
  > passing, a root credential accepted, cancellation ignored, a failure not cleaning up, provider text not cleaned, Ed25519 accepted, an unchecked checksum, a printing secret, ...), every one caught**
  > (`scratchpad/mut_provision.py`). PRV-04 is parameterised over both create calls and uses a real file ledger across a simulated crash (`catch_unwind` after the resource exists); PRV-02 scans every
  > output of six failure scenarios, with the mock putting the credential into its own error text, and shows the scan is not vacuous.

### Implementation

- [x] T087 [US2] Implement credential validation rejecting tenancy/account root credentials and warning on over-privileged scope, in `crates/dnet-provision/src/credential.rs` (PR-01, PR-06)
  > **Built 2026-10-22 (not committed).** The provider says what a credential *is* (`Inspection`: owner or dedicated user; valid, invalid, expired or revoked; the permissions it holds); this decides. Invalid,
  > expired and revoked are told apart; **a root credential is refused however valid and however much it holds**; missing permissions are named; extra permissions are accepted with a list the person must
  > acknowledge (`Validated::needs_acknowledgement`). Pure logic, 6 tests.
- [x] T088 [US2] Implement DPAPI **user-scope** credential storage with exclusion from logs, diagnostics, IPC, and error text, in `crates/dnet-provision/src/secret.rs` (PR-03, PR-04)
  > **Built 2026-10-22 (not committed); run on this machine (Windows 11).** `Secret` (wipes on drop, prints `<redacted>` from `Debug`, `Display` and `{:#?}`; the only read is `expose_secret`);
  > `CredentialVault` with `MemoryVault` and `DpapiUserVault` (**user scope — no machine-scope flag, which a test scans the source for**; the name is DPAPI entropy, so a blob copied to another name does
  > not open; a changed file does not open; names are `a-z0-9-` so none can mean a path). Plus `Sanitizer`, which removes the credential (and any 8-or-more-character fragment of it, so a truncated echo is
  > caught; linear time, since a signing key is over a thousand characters) and control characters from every provider-originated string. Not run on Linux (the DPAPI vault compiles out there).
  > **2026-10-26 (not committed), review fix (test-first).** `Sanitizer::clean` removed control characters but not bidirectional overrides, isolates and zero-width characters, which can make a provider's error text read as something it does not say in a dialog. It now removes the same set `dnetctl` keeps off a terminal. One test (RED first).
- [x] T089 [US2] Implement the provisioning stage machine in `crates/dnet-provision/src/stages.rs` per [contracts/provisioning.md](./contracts/provisioning.md) §2
  > **Built 2026-10-22 (not committed).** `run(params, services) -> Outcome`: `Provisioned`, `NeedsAcknowledgement`, `CapacityUnavailable` (retryable, nothing created), `Cancelled`, `Failed{stage, reason,
  > cleanup}`. A failure cleans up after itself; cancellation is checked before every stage; progress `Event`s carry stage names only (no provider text), so they can go straight to the IPC stream. The
  > client's AmneziaWG key pair is made here (`client_keys`, X25519 checked against the RFC 7748 vectors) so only its **public** half reaches the server; the obfuscation parameters are fresh per endpoint,
  > inside the feed's bounds. **Not wired into `dnetd`:** `StartProvisioning` carries no payload yet (Phase 9), and there is no concrete provider.
- [x] T090 [US2] Implement `created_resources` recording **before** each create call is issued, never after, in `crates/dnet-provision/src/ledger.rs` (PR-07 — recording after would lose exactly the resources most likely to leak)
  > **Built 2026-10-22 (not committed).** Append-only JSON lines, each flushed (`sync_data`) before the call returns; the in-memory view moves only after the line is on disk. Intent → provider id → removed.
  > **A job that cannot write its intent makes nothing** (`LedgerUnavailable`). A torn last line is ignored and removed; a damaged line anywhere else is refused (nobody can say what exists, and guessing is
  > how things leak). **A real bug was found and fixed by the first run of the tests:** ending a torn line with a newline turned the fragment into a damaged middle line that the next open refused; the
  > tail is now repaired (a complete last event keeps its newline added, a fragment is cut). Not testable: that `sync_data` really reaches the disk.
- [x] T091 [US2] Implement capacity-exhaustion handling returning alternative regions with their added RTT, as a retryable outcome rather than an error, in `crates/dnet-provision/src/capacity.rs` (PR-02 stage, US2-2)
  > **Built 2026-10-22 (not committed).** `Capacity::{Available, Unavailable{alternatives}}`; `rank` puts the nearest first, drops the full region itself, keeps each region once at its smallest added latency,
  > and keeps five. An empty list is a valid answer. Nothing has been created at that point, so there is nothing to clean up.
- [x] T092 [US2] Implement idempotent cleanup, reporting unremovable resources with identifying detail, in `crates/dnet-provision/src/cleanup.rs` (PR-08, PR-09, PR-11, SC-011)
  > **Built 2026-10-22 (not committed).** Works from the ledger, newest first (rules before the machine they belong to). A resource whose id was never recorded is found by its **token** (the name the job
  > chose); one nothing carries was never made. Already-gone is success. Run twice it gives the same report and the second makes no provider call. What cannot be removed is listed with its kind, region, id
  > (or the name to search for) and the provider's reason, with the credential removed — never dropped.
- [x] T093 [US2] Implement server bootstrap installing both server-side cores pinned to the client's bundled versions, generating private keys **on the server**, in `crates/dnet-provision/src/bootstrap.rs` (PR-12, PR-13, PR-14)
  > **Built 2026-10-22 (not committed). The script has not been run on a real server (that is T098); it is checked for what it contains and that it parses.** Modelled on the harness endpoint's three server
  > scripts. `script(plan)` makes one idempotent POSIX shell script from validated values only; `BootstrapReport::parse` reads the one line it prints. **Each core is downloaded over https, hashed, and only
  > then made executable; a mismatch stops everything (PR-12), and the report must name the same checksums and versions the client pinned.** Keys are made on the server (AmneziaWG pair, Hysteria 2
  > certificate, REALITY pair, the shared secrets) **only if their file is absent** and nothing deletes state (PR-14, structurally tested, with `sh -n` run on the real text); the client's private key
  > is not an input (PR-13). The configuration is checked by the core's own `check` before it is put in place. Licence and source of both cores are written beside them (PR-15). **Every value that enters
  > the script is checked against a narrow alphabet first** (the script runs as root): 12 hostile shapes are refused in every field, and the error never repeats the value. The report is read as hostile
  > input (strict schema, no value quoted in an error, secrets redacted from `Debug`).
  > - **Gap, said plainly: nothing builds or publishes Linux server binaries of the two cores.** `xtask fetch-vendor` builds the Windows client cores; `ServerCores` takes pinned URLs and checksums from
  >   the caller, and there are none yet (ADR-0004 notes the cores publish no binaries). That is a release-engineering task (a CI job producing Linux builds as pinned release assets) and blocks T098.
  > - Written for Ubuntu and Oracle Linux style images (apt or dnf; systemd; iptables optional). Not tried on either.
  > **Constraint (binding, owner decision 2026-09-12): the Hysteria 2 endpoint certificate MUST use
  > an ECDSA or RSA key, never Ed25519.**
  > - **Why.** The client generator (T056) keeps Chrome QUIC handshake mimicry on by default. Chrome
  >   does not advertise Ed25519 signatures, so the pinned core's documentation says the handshake
  >   fails against an Ed25519 certificate.
  > - **Scope.** Applies to self-signed certificates (pinned by SPKI SHA-256) and to CA-issued
  >   certificates alike.
  > - **Enforcement.** Bootstrap refuses to finish if the generated key is Ed25519.
  > - **Test.** A PRV test asserts the certificate's key algorithm.
  > **2026-10-26 (not committed).** Added `crates/dnet-provision/tests/untrusted_input.rs` (`proptest` as a dev-dependency): any output and any report line read without panicking; a good report changed in one character, or cut short, is refused or read, and neither the refusal nor the report's `Debug` repeats a secret. 5 tests; no defect found.
- [x] T094 [US2] Implement idle-reclamation keepalive installation, failing the job if absent, in `crates/dnet-provision/src/keepalive.rs` (PR-15 stage, PRV-09, [research.md](./research.md) §R10)
  > **Built 2026-10-22 (not committed); whether it actually keeps an instance from being reclaimed is T098's measurement, not a claim made here.** A systemd timer runs a four-minute idle-priority counter
  > loop every forty (about a tenth of the time, validated between 8 % and 50 %), with no network and no disk. The provider's rule is a property of the provider and changes; the schedule is deliberately
  > not tuned to the edge of any such rule. The job **fails if the keepalive is not installed and running afterwards** (or cannot be checked), and cleans up.
- [x] T095 [US2] Implement reachability verification gating `Endpoint` creation — a job failing here yields no endpoint, in `crates/dnet-provision/src/verify.rs` (PR-10)
  > **Built 2026-10-22 (not committed).** `Reachability` is a trait; `require_one` needs at least one profile to have worked end to end, and nothing tried is not a pass. A failing job returns `Failed`,
  > which has no endpoint to give, and its resources are removed. **The daemon's `Reachability` (the profile prober against the new endpoint's address) is not written.**
- [x] T096 [US2] Implement post-provisioning credential deletion, defaulting to delete, in `crates/dnet-provision/src/revoke.rs` (PR-05)
  > **Built 2026-10-22 (not committed).** `Disposition::default()` is `Delete`; `Keep` is an explicit choice. It removes the stored copy, and `REMINDER` says plainly that the key still exists in the
  > cloud account until the person deletes it there ("deleted" must not be read as "revoked").
- [x] T097 [P] [US2] Implement manual endpoint addition bypassing cloud provisioning entirely, in `crates/dnet-provision/src/manual.rs` (FR-010, US2-5)
  > **Built 2026-10-22 (not committed).** A label, an address and a port make an `Endpoint` with origin `Manual`: no provider, no cloud credential, nothing created, nothing to clean up, and deleting it
  > never offers to remove cloud resources. Refuses an unspecified, multicast or broadcast address, a name that cannot be a host name, a bad label, port 0.
  > **Phase 8, what is not done (and so what blocks T098):** no concrete provider (an Oracle Cloud client with request signing and a way to run the script, by SSH or the provider's own mechanism); the
  > Linux builds of the two cores; the daemon's wiring (`StartProvisioning`/`CancelProvisioning` carry no payload yet; where the vault and the ledger live; the reachability prober); and the wizard UI
  > (T107). **Security review is required before commit** (credential handling, key material, root-run script).
- [ ] T098 **[GATE] Plan Phase 1 exit**: one command yields a reachable endpoint that survives idle reclamation; PRV-01…PRV-09 pass
- [ ] T098a **[GATE] Deferred SPIKE-R4 (T055)**: run `testing/spike-r4/Invoke-SpikeR4.ps1` against the endpoint T098 provisioned, which is off-subnet by construction. Exit criteria are T055's own: `PASS` with a looping negative control. `INVALID`, `INCONCLUSIVE` or `VACUOUS` do not satisfy it. On `FAIL`, stop and revisit §R4 before any Phase 5–7 work that depends on the Profile A transport path is accepted

**Checkpoint**: US2 is complete except its UI, which lands in Phase 9.
  > **2026-10-26 (not committed): runbook written, not run** (`docs/owner-gates.md`). Provisioning has only the mock provider, so "the endpoint T098 provisioned" cannot exist yet; the runbook asks the owner to decide whether a hand-made cloud VM satisfies this gate, and lists the four runs (A, A with `-AltGateway`, Hy2, Hy2 with `-AltGateway`).

---

## Phase 9: US1 + US2 — Tray Application and First-Run Wizard (Plan Phase 7)

**Goal**: A non-technical user reaches a working tunnel unaided.

**Independent test**: SC-009 and SC-010, measured on a real stranger with a clean machine.

- [x] T099 [US1] Scaffold the Tauri v2 + Svelte 5 application in `apps/dnet-tray/`, unprivileged, with no capability to alter system state directly
  > **Acceptance criteria added 2026-10-21 (T142, ADR-0007, accepted 2026-10-24):** R1 the tray icon and menu are native and updated from Rust; R2 the web view is destroyed after a grace period and created hidden, shown on first paint; R3 plain Svelte 5 + Vite SPA (no SvelteKit, no component library), native `<dialog>`; R4 the web view never touches the pipe, minimal Tauri capabilities, CSP `default-src 'self'`; R6 CSS that works in WebKitGTK; R7 colours only from `docs/design/tokens.css`, with CI asserting the 30 contrast pairs. Windows subsystem build (no console host).
  > **Built 2026-10-24 (not committed).** `apps/dnet-tray` (Svelte 5 runes, Vite 8, TypeScript, pnpm with a 14-day `minimumReleaseAge` and no install scripts; strict CSP, no `{@html}`, no inline style) and `apps/dnet-tray/src-tauri` (Tauri 2, **detached from the Cargo workspace** so its dependency tree is not paid for by every other build). R1: the tray and its four-line menu are native (`dnet-view::tray`, words shared with the window through `crates/dnet-view/words.json`). R2: no window at start-up; created hidden, shown on page load, hidden on close and destroyed after a 120 s grace unless reopened (`dnet-view::session::Grace`, tested); nothing is sent to it while hidden. R4: the capability list is exactly the 12 commands in `build.rs` plus event listen/unlisten; **verified in the running window**: `plugin:window|close` and an unknown command are refused by the framework, the page loads only from `tauri.localhost` and `ipc.localhost`, the CSP is applied. R7: a test fails on a colour literal and asserts all 30 contrast pairs in both themes from `tokens.css`. JavaScript is 43 KB gzipped of 150; no fonts shipped (system faces).
  > - **Not done:** an installer (T114, WebView2 prerequisite wording, R5); real icons (the files are the spike's placeholder dot, and the tray shows one icon for every state, so the lamp is not in the tray yet); a single-instance guard; `pnpm build` is not yet run by the shell's own build (CI runs it first); a Linux build of the shell (compile_error on non-Windows, ADR-0005 not approved); the size and memory measurements with the real UI (T116).
- [x] T100 [US1] Implement the IPC client in `apps/dnet-tray/src-tauri/src/ipc.rs` using `dnet-ipc`, treating all responses as untrusted
  > **Built 2026-10-24 (not committed), as `crates/dnet-view` (in the workspace, so it is tested and linted everywhere) rather than `src-tauri/src/ipc.rs`.** `Bridge` is every command the window may give and every question it may ask, over a `Link` (one request, one reply; `PipeLink` is the Windows pipe, trust `ServiceOwnedOnly` unless `--allow-unprivileged-service`, version checked once, T132). Replies are decoded with the typed `dnet-ipc` decoders (which refuse what contradicts itself); a service too old for `GetPaths`/`GetStats` reads as "not measured", never as fine; a refusal is the service's own `detail`, cleaned and bounded; an answer that is not what the contract promises is a refusal, never a success (an opt-out with no stated consequence, a change not confirmed, a check with no route). A mistake in a new endpoint is caught before anything is sent, and the connection file's text is never echoed. 60 tests in `dnet-view` (mutation-checked: 21 mutants, 20 killed, 1 equivalent) plus golden fixtures that the window's own parser reads, plus `dnetd`'s `the_window_can_read_what_the_service_really_says`, which feeds the **real** service replies through `dnet-view` (it exists because the first fixtures said `Reliable` where the service says `Deterministic`; the live run of the window found it, and the test fails if the name regresses).
  > - **Not done:** `dnet-view` has never talked to a *new* `dnetd` over the real pipe (only to the owner's older running one, which lacks `encrypted_dns` in `ListRules`; the window then says so, in the Rules and Settings views). Security review is required before commit: this is a new client of the IPC boundary that sends endpoint credentials.
- [ ] T101 [P] [US1] Implement the tray icon and the single Stabilize toggle in `apps/dnet-tray/src/lib/Tray.svelte` (FR-036)
  > **Built 2026-10-24 (not committed), in Rust (`dnet-view::tray` for the words, `src-tauri/src/shell.rs` for the menu), not `src/lib/Tray.svelte`: R1 says the tray depends on no JavaScript.** Four lines: the state (a failure by its own title), the one control (Stabilize / Turn off / Working…, disabled when there is nothing to press), Open, and "Quit this app (the connection stays up)"; a left click opens it. The tray follows the service every 15 s while the window is hidden and at once when the service reports an event. A refused press (including the Tier 2 consent) opens the window, where the reason and the consent can be shown.
  > - **Not done / unverified:** the tray menu has been built and the shell started, but **nobody has clicked it** (no screen-driving was available); the icon does not change with the state; a refusal from the menu is not shown as text in the menu itself.
  > **One tray per person, and a window when a person starts it, 2026-11-04 (found while thinking about the first run).** The program opened no window at start-up (R2), so starting it from the Start menu or the installer's last page showed only a tray
  > icon, possibly in the overflow area, and starting it while it already ran made a second tray icon (the known "no single-instance guard" gap). Now: the login start (the installer's Run key) passes `--background` and opens no window; any other start opens
  > one; the first copy owns a per-user named pipe (`single.rs`, no new dependency) and a second copy connects to it, which is the whole message, and exits while the first opens its window; a pipe held by something that does not answer is not a reason
  > not to start. 6 tests (`cargo test` on the shell, now in CI), the first-copy rule mutation-checked. **Run for real, with the built program:** `--background` gave one process and no window; a start by hand while it ran gave still one process and the
  > window; a second start by hand, still one; a start with nothing running opened the window. **Not seen:** the installed program started from the Start menu and the installer's last page (the installer was not changed beyond the Run key).
- [x] T102 [P] [US1] Implement the status view showing connection state, active profile **and its tier**, active endpoint, and carrying path in `apps/dnet-tray/src/lib/Status.svelte` (FR-037, IPC-05)
  > **Built 2026-10-24 (not committed), as the home view of the "Orbit" window** (`App.svelte`, `Scene`, `Caption`, `Strip`, `Drawer`; not `Status.svelte`): state in words and in the figure's form (ring, sphere, cube; never colour alone), the method and its **tier** and the carrying network on one line (`Hysteria 2 · Tier 2 · via Hostel-5G`), the endpoint in the reason, every network with its role, and latency/jitter/loss/stability that show "no measurement" and not a number when nothing was measured. 221 tests, axe clean in every view.
  > - **Not done:** a screen-reader pass (T111); a two-network live check (no second real network yet).
- [x] T103 [P] [US1] Implement distinguishable, actionable failure presentation for all seven causes in `apps/dnet-tray/src/lib/Failure.svelte` (FR-039, SC-020)
  > **Built 2026-10-24 (not committed).** All seven causes, each with the service's own title, detail and advice (`dnet_core::failure::explain`, shown whole: a test found the advice being cut at 120 characters, and the bound is now 400 on both sides), one primary action each (`ACTION_FOR_CAUSE`: the window's short label; the service's sentence is shown as advice), announced assertively. Golden fixtures for all seven are read by both the Rust and the TypeScript side.
  > - **Not done:** `CaptivePortalUnsatisfied` offers "Open login page" but the service gives clients no address, so it says what to do instead (see Known gaps in CLAUDE.md).
- [x] T104 [US1] Implement the Tier 2 consent dialog warning that established connections will not survive an interface change, in `apps/dnet-tray/src/lib/TierConsent.svelte` (FR-016b)
  > **Built 2026-10-24 (not committed), as one `Consent` component for every consent** (native `<dialog>`, equal-weight buttons, focus on the safe one, Esc declines, the consequence is a callout before the buttons; each instance has its own label id — a test found duplicates). Asked when the service answers `TierDowngradeRequiresConsent`; declining sends nothing more.
- [x] T105 [US1] Implement the Brutal opt-in dialog warning that it degrades every other user on the same access point, in `apps/dnet-tray/src/lib/BrutalConsent.svelte` (FR-006)
  > **Not built (2026-10-24).** The consent component exists and carries the wording (`en.consent.brutal`), but nothing in the window turns Brutal on: the service answers "not available" for `EnableBrutal`, so a switch would be a fake.
  > **Built 2026-10-26 (not committed), end to end, test-first at each layer; not run on Windows.**
  > - **Protocol (IPC-24):** `EnableBrutal { profile, up_mbps, down_mbps, warning_revision }` and a new `DisableBrutal { profile }` (additive; version unchanged, since `EnableBrutal` had no fields and was always refused). Strict, bounded 1 to 1,000,000 Mbit/s, only the warning revision in force, nothing echoed (`dnet-ipc/tests/brutal.rs`, 6 tests incl. a property test). Contract text added.
  > - **Service:** `Configurator::set_brutal` and `DomainState::set_brutal` (Hysteria 2 only, idle only, saved before applied, restored on a failed save); the acknowledgement time is the service's clock, never the client's. 4 configurator tests, 2 dispatch tests, and the idle-only and gate tests now include both requests. A plan test shows the setting reaching the core (`up_mbps`/`down_mbps`) and absent when off; the generator already did this, so that test passed on first run.
  > - **One warning text:** `dnet_core::profile::brutal_warning()` with its revision; the window's `brutal-warning.json` is pinned to it by a Rust test (RED first), and `dnetctl` prints the same words.
  > - **dnetctl:** `brutal-on <profile> --up N --down N [--accept-warning]` (without the flag it prints the warning, exits 1 and sends nothing) and `brutal-off <profile>`. 3 run tests, 1 parse test.
  > - **Window:** `profiles()` and `setBrutal()` on the bridge (`dnet-view`, Tauri commands `list_profiles`/`set_brutal` added to `build.rs` and the capability file), a Settings card with both speeds, the Consent dialog (equal buttons, focus on "Keep it off"), off needs no consent, locked while connected. 4 component tests (axe clean), 2 Tauri-bridge tests, 4 Rust bridge tests. The Tauri shell passes clippy for the Windows target from Linux; it has not been opened.
  > - **Security review (IPC boundary, core-config generation):** authorization unchanged (Mutating: interactive console user only; refused after a failed recovery or with a refused saved configuration). Every field is validated in `decode_request` before the service sees it; the profile id uses the existing grammar; numbers are bounded `u32` and reach the generated JSON only as numbers. A client cannot backdate or pre-date an acknowledgement, nor accept a warning it was not shown under another revision. Generation still re-checks the revision and both directions (CC-04, CC-12). Residual, accepted: the console user's own process can turn the mode on over the pipe without a dialog; the pipe client is that person's own program, and the state then carries the `BrutalEnabled` warning while connected. No finding blocks.
  > - **To check on Windows:** `LOCAL-COMMANDS.md` section 4.
- [x] T106 [US1] Implement the encrypted-DNS override disclosure with one-click opt-out in `apps/dnet-tray/src/lib/DnsConsent.svelte` (FR-025a)
  > **Built 2026-10-24 (not committed).** The service's own disclosure (`disclosure.json`, pinned to `dnet_core::doh_consent::disclosure()` by a Rust test) is shown once at first run and again in the opt-out consent in Settings, which states the consequence before the button; the switch stays where it was until answered; a setting that could not be read is not offered for change.
- [ ] T107 [US2] Implement the provisioning wizard, including the guided least-privilege credential creation and revocation instructions **shown before the credential is requested**, in `apps/dnet-tray/src/lib/wizard/` (PR-02, US2-1)
  > **2026-10-30: superseded by the guided setup (T149–T151).** The owner chose that the person works in the provider's own pages and the app never holds a cloud credential, so the credential-guidance and revocation screens are not needed; PR-02's purpose (least privilege) is met by there being no credential. The API-key path stays unbuilt and is not planned.
  > **Not built (2026-10-24).** `Wizard.svelte` lists the seven steps (`en.wizard.steps`) and says plainly that setting up a server is not available in this build: `capabilities.provisioning` is false because no provider is connected and `dnetd` does not call `dnet-provision`. The credential-guidance and revocation screens are the work of this task.
- [x] T108 [P] [US5] Implement rule management UI labelling application rules **best-effort** in the interface itself, in `apps/dnet-tray/src/lib/Rules.svelte` (FR-023, Principle VI)
  > **Built 2026-10-24 (not committed), read-only.** The list with the built-in rules marked and "Best effort" said in the row itself. **Adding and removing rules is not built** (the service answers "not available" for them).
  > **2026-10-26 (not committed): adding and removing a person's rules, end to end, test-first at each layer; not run on Windows.**
  > - **Protocol (IPC-25):** `AddRule { kind, value, action }` → `{ rule }`, `RemoveRule { rule }`; `ListRules` now carries `id`, `kind`, `value` (additive). 4 tests incl. a property test (`dnet-ipc/tests/rules.rs`).
  > - **Order (safety):** the service gives the precedence: after every rule and never below `USER_RULES_START` (200), whether or not the encrypted-DNS block is in force (`dnet_core::rule::{next_user_precedence, validate_user_rules_follow_builtins}`, run on every rule-set change). **This tightens an earlier rule** that let a person's rule move to just after the built-ins once the block was off; the old test is rewritten to the new contract. No saved file could hold such a rule (there was no way to add one). Reason: the range below 200 must stay free so the built-ins can make room for the endpoint bypass at connect time (T048 note).
  > - **Saved:** `dnet-config` stores a person's rules with their ids (`encode_with_rules`, `MAX_USER_RULES` = 128); a planted rule gets the checks a new one gets (`RoutingRule::restored_user`, which refuses port matchers, capture and reject), and one that would outrank the built-ins, or shares an id or precedence, refuses the file. Errors never quote the file. 5 tests.
  > - **Service:** `Configurator::{add_rule, remove_rule}` (idle only, saved before applied, restored on failure); **program rules are refused in this build** because `dnetd` does not run the ETW attribution, so such a rule would do nothing (Principle VI). 5 configurator, 5 domain, 1 dispatch test; the idle-only and gate tests include both requests.
  > - **dnetctl:** `rules`, `add-rule --domain|--suffix|--cidr <value> --tunnel|--bypass`, `remove-rule <id>`. 3 run tests, 1 parse test.
  > - **Window:** an "Add a rule" form (site, site and subdomains, address range; through the tunnel or around it), each row saying what it matches, a remove button on the person's own rules only. 3 component tests (axe clean), 1 Tauri-bridge test, 2 Rust bridge tests; the shared `rules.json` fixture now carries `id`, `kind`, `value`, and shows a bidirectional character cleaned out of a value.
  > - **Security review (IPC boundary, routing rules, core-config generation):** Mutating, console user only. Every value goes through `RoutingRule::user` before the service sees it; the service then checks the whole set (built-ins present, DNS capture lowest, block ahead of user rules, user rules after built-ins, no collisions). A person's rule cannot outrank DNS capture or the endpoint bypass, so it cannot open the R4 loop or a DNS leak; at worst it routes the person's own traffic the way they asked. Patterns reach the generated configuration as JSON strings through `serde`. Residual, accepted: rule patterns are readable by any authenticated local user, as endpoint hosts already are; a multi-user machine reveals one user's rules to another. Owner to confirm.
  > - **To check on Windows:** `LOCAL-COMMANDS.md` section 5.
- [x] T109 [P] [US1] Implement the acceptable-use warning shown before first connection in `apps/dnet-tray/src/lib/FirstRun.svelte` (FR-032)
  > **Built 2026-10-24 (not committed).** Shown before anything else on first run; nothing is switched on until it is acknowledged (the control takes the person back to it); the acknowledgement is stored with the time and the exact text shown. Declining changes nothing.
- [x] T110 [P] [US1] Implement the About screen carrying third-party attribution — **the only UI surface permitted to name the primary transport core** (Constitution licence obligation 1)
  > **Built 2026-10-24 (not committed), at `apps/dnet-tray/src/lib/About.svelte` — the one file `lint-branding` allows to name the primary core, Wintun and the other component.** The wording follows `THIRD-PARTY-NOTICES.md`; a test asserts no other source file names them.
- [ ] T111 **[GATE] Plan Phase 7 exit**: a person who has never provisioned a server reaches a verified working endpoint in under 20 minutes unaided (SC-009) and a working connection without documentation beyond the wizard (SC-010)

**Checkpoint**: Feature complete.
  > **2026-10-26 (not committed): runbook written, not run** (`docs/owner-gates.md`). The screen-reader half (Narrator and NVDA) can run now against the built window; the stranger half waits for T107 and a real provider.
  > **Found before the pass, 2026-11-04, fixed test first:** in a window narrower than 760 px the dock shows only the icon of each section it is not on, and hid the
  > words with `display: none`, which also took the link's name away, so a screen reader would have read five unnamed links. Each link now carries its name
  > (`aria-label`); a component test hides the words and asks for every link by name (red before, green after), and a browser check at the window's minimum
  > width (560 px) found the links by name and no sideways scroll in Servers, Rules or the guide. jsdom does not run container queries, which is why axe never saw it.

---

## Phase 10: Polish & Cross-Cutting Concerns

- [x] T112 [P] Implement the diagnostic bundle excluding credential material and browsing destinations by default, in `crates/dnetd/src/diagnostics.rs` (FR-035, IPC-07)
  > **Built 2026-10-22 (not committed); `GetDiagnostics` now returns it instead of the placeholder.** Two layers so that one mistake does not leak. **By construction:** the bundle is made field by field from
  > typed facts; a rule contributes its action, kind and reliability but never its pattern, an endpoint its health and origin but never its address or name, a network its kind and quality but never its
  > name, and credentials are not among the facts. **By redaction:** the service also passes every sensitive value it knows (each endpoint address and label, each user-rule pattern, each network name), and
  > every string in the finished bundle is scrubbed of them, ignoring case, longest first (`<removed>`) — for the text that does pass through (a failure's `detail`) and for the day someone adds a field
  > carelessly. Three extras help a developer and cost privacy, so each is off by default and a separate choice (`Options`): endpoint addresses and names, rule patterns, Wi-Fi names; turning one on
  > takes it off the redaction list. An unmeasured network claims no quality (no numbers at all). Lists are cut at 64 entries with a count of what was left out, so the bundle fits a reply.
  > - Tests (16): IPC-07's own contract test ("a bundle after a session containing a known domain does not contain that domain"), plus: nothing sensitive in the default bundle, nor in the structure before
  >   redaction; case-insensitive, every occurrence; non-ASCII; extras one at a time; never a credential or even the reference to one; bounded under 500 endpoints and rules. **10 of 11 mutations caught**;
  >   the survivor is a last-resort re-check of the finished text, unreachable unless the redaction itself were broken (kept as defence in depth, not testable without a seam).
  > - **Not done:** the options are not reachable by a client (a request carries no payload yet, Phase 9), so every bundle is the default one; the service's own **log files are not part of the bundle**
  >   (there is no log file to attach yet); a bundle is not written to disk or sent anywhere. **Security review is required before commit** (IPC boundary; personal data).
- [x] T113 [P] Add the statement that obfuscation conceals content and protocol but **not** traffic volume or destination, to README, first-run flow, and About screen (FR-033, Principle VI)
  > **2026-10-26 (not committed).** README (Limits, already there) and the first-run acceptable-use consequence (already there) said it; the About screen did not. It now has "What it hides, and what it does not", in the README's terms. One component test (RED first); `lint-branding` passes.
  > **README done (T121).** First-run flow and About screen wait for the UI (T109, T110); the wording to use is the README's first bullet under "Read this before relying on it".
- [ ] T114 Build the WiX/NSIS installer in `installer/`, registering `dnetd` as a LocalSystem service and bundling `THIRD-PARTY-NOTICES.md` and every dependency licence text. Install the cores as `primary-core.exe` and `amneziawg-go.exe` **beside `dnetd.exe`**: start-up recovery (T038) reaps orphans by exactly those full paths, so any other layout silently reaps nothing. Place the signed `wintun.dll` **beside each core executable** (the patched primary core loads it only from its own directory, digest-verified; ADR-0004 Finding 4), in an Administrators-only directory; run `cargo xtask verify-vendor` on the staged payload. Create `%PROGRAMDATA%\DNet Engine` (and `run`, `state` beneath it) **owned by SYSTEM or Administrators with a protected DACL**, replacing or refusing a directory that already exists with another owner. Any user can pre-create a `%PROGRAMDATA%` subdirectory and, as its owner, regain rights to replace the generated core config (T049) or the undo journal (T037) inside it
  > **2026-10-26 (not committed): acceptance checks written** (`docs/owner-gates.md`); WiX or NSIS is still undecided and nothing exists under `installer/`.
  > **2026-10-26, later (not committed): built, not yet run.** NSIS, through the Tauri bundler the window already uses (decision taken
  > without the owner; the task allows either, and this needs no second toolchain and is what winget calls `nullsoft`).
  > - `dnetd install | uninstall [--remove-settings] | stop` (`crates/dnetd/src/install.rs`): install refuses a folder ordinary users
  >   could change (the service's own `verify_programs` check) and a missing primary core; makes `%PROGRAMDATA%\DNet Engine`, `run` and
  >   `state` private (`prepare_private_dir`: a foreign-owned or linked folder is refused, untouched); registers or re-registers an
  >   automatic LocalSystem service depending on `Nsi` and `Tcpip`, restarted by the SCM on failure (5 s, 30 s, 60 s; reset daily). Uninstall
  >   stops it (tunnel down), runs the start-up recovery, and deletes the service **only if the network was restored**; `--remove-settings`
  >   deletes the data folder only if it is a real folder owned by SYSTEM or Administrators. 3 parsing tests; the Windows half type-checks
  >   and passes clippy for `x86_64-pc-windows-msvc`. **Security review (privileged operation, 2026-10-26):** the checks above are the
  >   review's findings applied; the service path is quoted by `windows-service` (shell-escaped), to be confirmed with `sc qc` (gate 1).
  > - `cargo xtask stage-installer`: verify-vendor, release build of `dnetd`/`dnetctl`, then `target/payload/app` (service, CLI, both cores,
  >   the DLL: one folder) and `target/payload/licences`; each copy re-read and compared by SHA-256. 2 tests.
  > - `installer/hooks.nsh` + `installer/tauri.installer.json`, built by `pnpm installer` (adds `@tauri-apps/cli` 2.12.2 as a dev
  >   dependency). Per-machine. The hooks stop an old service before an upgrade, copy the payload, run `dnetd install` (abort on failure),
  >   start the tray at sign-in for every user, and on uninstall run `dnetd uninstall` first and abort if the network could not be restored.
  >   Checked against the NSIS template inside `@tauri-apps/cli` 2.12.2, compiled in a template-shaped harness with `makensis -WX` (NSIS
  >   3.09, Linux), and the merged configuration validated against the CLI's `config.schema.json`. `.nsh` files are now branding-linted.
  > - `installer/winget/*.yaml` (validated against the winget 1.9.0 schemas) and `.github/workflows/release.yml` (actionlint clean): on a
  >   `v*` tag, a **draft** release with the installer, `SHA256SUMS.txt`, a build-provenance attestation and the rendered winget manifests;
  >   fails above 60 MB (SC-012). Nothing is published or submitted.
  > - **Not run:** a real `pnpm installer` and every check in `docs/owner-gates.md` §T114 (`LOCAL-COMMANDS.md` section 7).
  > **Release signing with the project's own key, 2026-11-04 (owner's decision: a purchased certificate is too dear; sign like an Android app, with our own key).** `installer/Sign-Files.ps1` (signs from `DNET_SIGN_THUMBPRINT` or
  > `DNET_SIGN_PFX` and its password; with no key configured it signs nothing and succeeds; with one configured any failure fails, with a retry for the timestamp server), `installer/Test-Signature.ps1` (not signed, changed after
  > signing, or signed by another key: FAIL; a self-made key's "not trusted" is accepted), `installer/New-SigningCertificate.ps1` (the one-time key ceremony: refuses a folder inside the repository and an existing key; RSA 3072, 10
  > years, password of 12 or more characters, never printed), `bundle.windows.signCommand` in `installer/tauri.installer.json`, signing steps in `release.yml` that run only when the repository has the secrets, and
  > `docs/release-signing.md`. Tests first (`crates/xtask/tests/sign_scripts.rs`, 6): a throwaway certificate signs a copy of an executable, the right fingerprint passes, a wrong one, an unsigned file and a file with one byte changed fail,
  > a configured key that cannot sign stops the build; three mutations caught. **A defect found by the mutation checks and fixed:** under `Stop`, Windows PowerShell 5.1 turns the first stderr line of `2>&1` on a native command into a terminating error,
  > so the retry and the script's own message were unreachable (the test passed by that accident). Smoke-tested the ceremony and the key-file-and-password path (the one CI uses) in a temp folder; cleaned up.
  > **Security review (`ecc:security-reviewer`): no way found to pass the check without the pinned key (about 740 bit-flips and several forgeries all failed), no leak of the key or password into an artifact or a third-party
  > action. Fixed from it:** the key is used only on a release tag (a branch build never signs) and the job runs in an environment `release` the owner restricts; CI imports the key as non-exportable, deletes the file at once and signs by
  > thumbprint, so the password is in one step only; the ceremony script removes the key from the store by default, writes the key file as AES-256 and refuses a weak password; a tag without the key warns. **Found by the real build:** Tauri
  > runs `signCommand` from `apps/dnet-tray/src-tauri` (the relative path was one level short). **Accepted and written down:** no timestamp is required by the check; the signing step runs the whole build tree with the key available.
  > **A finding from the real signed build:** Tauri signs the tray program, packs it, then restores the loose copy in the build folder, so that copy reads "not signed" (the installer, `dnetd.exe` and `dnetctl.exe` check out against the key); the copy inside
  > the installer is to be checked on an install (no 7-Zip here to open it), and the workflow no longer checks the loose copy.
  > **Install test on the owner's PC prepared, not run (needs an administrator shell):** `testing/Invoke-InstallTest.ps1` (refuses without admin, with DNet Engine already present, with a development `dnetd.exe` running or the tray open; checks the service account, start mode, crash recovery, folder
  > permissions, the files, the signatures of the installed files against the installer's signer, wintun's vendor signature, that `dnetctl` reaches the service, then uninstalls and compares routes, name servers and adapters before and after). Parse-checked and its refusal run; the rest unrun.
  > **The real key was made on 2026-11-04 (the owner delegated the ceremony):** fingerprint ab484a617207eea3cd885d586c0dbb3cc2db414ca6d017291311e5c8e58f51b1, valid to 2036-11-04; the key file (AES-256) in the owner's cloud-synced documents and a second copy on another drive of the same disk
  > (so it guards against deletion, not a disk failure), the 28-character random password in two restricted files apart from the key and **to be copied into a password manager**; signed and checked from the stored files. The GitHub environment `release`
  > is restricted to `v*.*.*` tags with the owner as required reviewer and holds the two secrets; branch builds run in `release-test`, which has none.
  > **Still not done:** a CI run of the signing steps on a tag (nothing is tagged), and a check of the tray program inside the installer.
  > **(superseded) Not done:** the real key (the owner runs the ceremony), the two repository secrets, the published fingerprint, a CI run of the signing steps (needs the secrets); the workflow YAML has not been parsed locally (no parser here).
  > Windows still shows "unknown publisher": the key is not on its list of authorities (SignPath Foundation or a purchased certificate would remove that; see the runbook).
  > **Install, signing and the release pipeline proven on a clean Windows machine, 2026-11-04 (GitHub's runner, from the release workflow).** `testing/Invoke-InstallTest.ps1` runs in the workflow after the installer is built: install (3 s), the service
  > (`DNetEngine`, LocalSystem, automatic start, running, restarted by the Service Control Manager after a crash: 5 s, 30 s, 60 s), every file present, `C:\Program Files\DNet Engine` and `C:\ProgramData\DNet Engine` not changeable by ordinary users, the tray's Run key,
  > wintun's own vendor signature still valid, `dnetctl status` and `profiles` answering from the installed service, uninstall (6 s: service, files and Run key gone), and **routes, name servers and adapters exactly as before**. The signing rehearsal
  > (a throwaway key, `rehearse_signing`) signed the service, the tool, the tray program and the installer, and the check passed on all of them, **including the installed `dnet-tray.exe`**, which answers the earlier open question (the loose copy in the build folder is
  > unsigned, the packed one is signed). Two problems the first runs found: Windows PowerShell started from PowerShell 7 broke the signature check (fixed, `windows_powershell`); a transient Go module proxy error stopped a core build (now retried, `warm_go_cache`).
  > **Not shown by this:** the same on a person's own computer (its network, its antivirus, an upgrade over an older install), a connection through the installed service, the crash kill test (7.7), restart (7.5, 7.6), sleep (7.10), a second ordinary user (7.9), and a run with the real key on a tag
  > (the release environment waits for the owner's approval). Still open: T114's own acceptance on a VM with a snapshot is replaced here by a runner for the install-and-remove half only.
  > **On the owner's own computer, 2026-11-04 (a restore point was made first):** the installer built from the working tree (14.9 MB, SHA-256 27E1C538…43BE, signed by the project's key; Windows
  > says "unknown publisher", as expected) installed in 4 s with exit 0, and `testing/Invoke-InstallTest.ps1` passed every check: service LocalSystem, automatic, running, crash recovery, folder
  > permissions, the Run key, `dnetd`, `dnetctl` and `dnet-tray` signed by the installer's signer, `wintun.dll` keeping its vendor's signature, `dnetctl` reaching the service. The installed tray,
  > started once with `--background` and twice by hand, left one process and one window. The installed service reported `Failed: endpoint 'harness' has no measurement origin`: a leftover of the
  > development endpoint in `C:\ProgramData\DNet Engine`, not an installer fault. **Not checked on this computer:** uninstall, an upgrade over an older install, antivirus behaviour, a screen reader.
- [ ] T115 Verify installer size at or below 60 MB (SC-012); if exceeded, reduce bundled artifacts before relaxing the target
- [ ] T116 Measure idle RSS at or below 150 MB combined and idle CPU below 1% on a four-core machine (SC-013, SC-014)
  > **Define both states (T142, proposed SC-013 rewording):** idle with the window **closed**, combined **private** memory; and with the window open. Method: `testing/spike-ui/Measure-Footprint.ps1`. Baseline from the spike: 3.5 MB closed, 94 MB open (floor; a real UI adds heap). Proposed limits: ≤ 150 MB closed combined with the cores, ≤ 300 MB open, window open → loaded ≤ 600 ms.
- [ ] T117 Verify no measurable slowdown to a concurrent compile, test suite, and editor while connected (SC-015)
- [ ] T118 Run HV-14 and SUP-T2 — after killing `dnetd` mid-session, no core survives, no route or DNS change remains, networking identical to pre-installation (SC-016, FR-029)
- [x] T119 Confirm coverage at or above 80% outside `apps/` and `vendor/` (SC-022)
  > **Measured 2026-10-24** with `cargo llvm-cov --workspace --summary-only` on the owner's Windows machine, unprivileged, `#[ignore]` tests not run: **90.5% of lines, 89.9% of regions, 90.1% of functions** across the
  > whole workspace (no `apps/` or `vendor/` exist yet). By design the low files are the ones that only a live or elevated run exercises: `dnetd::effects` 18% (the real effects), `dnet-netstate::win_route` 40%,
  > `win_bringup` 0%, `dnet-supervisor::windows_runtime` 0%, `dnet-etw::session` 0%, `dnetd::{main,svc,console}` 0%, `dnetd::winwatch` 36%, and the build tool's `fetch_vendor` 36%, `verify_vendor` 42%,
  > `lint_branding` 0% (the last two are run as commands by CI rather than unit-tested). CI's own coverage step covers four crates; this figure is the whole workspace. Re-run after the elevated tests.
- [x] T120 Audit that zero tests target a live managed network (SC-021, Principle III)
  > **Audited 2026-10-24.** Every hostname in the Rust sources is a reserved example or test name, one of the two feed hosts in `dnet_core::feed::fetch` (constants and negative test inputs, never requested), or the
  > operating system's two captive-portal probe hosts, which only `dnetd::portal_probe::detect` requests, and no test calls `detect` (the tests use `detect_at` against listeners on 127.0.0.1). The harness
  > (`testing/`) addresses only its own Docker network (172.32.0.0/24) and the documentation range (203.0.113.80, the WSL lab). The 14 `#[ignore]` tests touch the local routing table, files and the local ETW
  > session, never a remote host. Method: pattern search of `crates/` and `testing/` for hostnames and non-private addresses, reviewed by hand. Re-run it after adding any network code.
- [x] T121 [P] Write `README.md` positioning the product as a self-hosted network resilience and tunnel client, never as a firewall bypass, with the acceptable-use warning (FR-032, Constitution Legal posture)
  > **Written 2026-10-22 (not committed).** Positions it as a self-hosted tunnel client and resilience layer, states what it is *not* (a firewall bypass, anonymity, a server or service), carries the
  > acceptable-use warning ("Using it responsibly"), the FR-033 statement (obfuscation hides content and protocol, **not** volume or destination), the kill-switch and Tier-2 and best-effort-rule limits,
  > an honest status table, how it is built, how to test it, and the licence. It names no vendor product (`lint-branding` covers `README.md`). Counts as the README half of T113.
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
  > - **Not done, and why.** (Saving is used since T146.) User
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
- [x] T131 Stop a remembered fake address from aliasing a different name in the next session: alternate the FakeIP pool between the two /16 halves of `198.18.0.0/15` (and the IPv6 pool) per tunnel start, keeping config generation deterministic for a given input (CC-09). Update `contracts/core-config.md` CC-02, the bypass-overlap guard test, and add a lab check that a stale address from the previous session is refused, not answered with another name
  > **Built 2026-10-22 (not committed); the lab check is not written (needs a live run).** Decisions (delegated by the owner): the half is an **input** to generation (`FakeIpHalf`, `PrimaryCoreInput.fakeip`),
  > so the output stays a pure function of its input; the daemon alternates it on every start with `FakeIpRotation` (an atomic toggle, so concurrent starts never share a half), taking one even for a start that
  > fails. IPv4 `198.18.0.0/16` / `198.19.0.0/16`; IPv6 `fc00::/19` / `fc00:2000::/19`. The first half after the daemon starts follows the clock's low bit (even odds across a restart). The whole-pool constants
  > stay, so the built-in bypass guard still forbids overlapping the whole pool. `contracts/core-config.md` CC-02 amended; CFG-14 added.
  > - Tests: 3 in `contract.rs` (CFG-14: exact split of both pools; only the ranges differ between halves, each deterministic; the rotation alternates from either start), 1 in `plan.rs` (the plan carries the half it
  >   was given), 1 in `effects.rs`. The pinned core's own `check` now runs on every case in both halves, with and without the encrypted-DNS block (see T070).
  > - **Mutation-checked: 7 caught** (rotation that never alternates, generator ignoring the half for v4 and v6, overlapping halves, a half outside the pool, the plan ignoring the half, a fixed first half).
  >   **One survivor, said plainly:** `RealEffects::start_tunnel` calling `self.fakeip.take()` — replacing it with a constant passes every test, because `start_tunnel` needs the real machine (credentials, files,
  >   cores) and has no unit test. It is one line, and it is what the lab check below exists to prove.
  > - **Still to do in the lab:** connect, note a fake address handed out, disconnect, reconnect, and confirm the old address is refused by the core (`missing fakeip record`) and not answered with another name.
  >   Residual: a daemon restart gives even odds of reusing the half in use before it.
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
- [x] T133 [US3] Hold the machine's paths, their measured quality and the failover state together, in `crates/dnet-core/src/path_monitor.rs`
  > **Built 2026-10-21 (not committed). 15 tests, mutation-checked.** Pure. `paths_changed` replaces the system's list but keeps the quality already measured for
  > every interface still there; `observe` folds in a probe result; `evaluate` returns the failover `Decision` and leaves exactly one path `Carrying`
  > (`validate_paths` holds after every step, including 1,200 s of quality swapping every 7 s). A refresh reports whether anything meaningful changed, ignoring
  > quality and order, because the system raises several events for one change. A new gateway on the *carrying* adapter is reported separately: not a failover
  > move, but the tunnel's host route still points at the old router, which is exactly what T083's rewrite-then-rebind exists for.
  > - **Found and fixed in T082 while integrating:** the 120 s dwell started when a path was merely acquired or adopted, so a first choice that was dead
  >   upstream would have been kept for two minutes. The dwell and the move budget now start only on a real move (2 new failover tests, 1 monitor test).
  > - Next: the probes that feed `observe` (per-interface, through the user's own endpoint), the daemon task that drives this from `ChangeSource`, and the call to
  >   `on_carrying_path_change` on a move or a gateway change (T083).
- [x] T134 [US3] Measure a path's quality by timing a connection to the user's own endpoint through that adapter, in `crates/dnet-netstate/src/probe.rs`
  > **Built 2026-10-21 (not committed). 9 probe tests and 6 new monitor tests; mutation-checked.** Endpoint-based, as decided with the owner: no public or
  > project host is ever contacted. `probe::probe_tcp(adapter, endpoint_addr, timeout)` (Windows) pins a TCP socket to the adapter with `IP_UNICAST_IF` so it leaves
  > through *that* adapter whatever the routing table prefers, then times the connect. `probe::sample_of` (portable): connected or refused (a reset proves host and path)
  > is an answer with its round-trip time; silence, or no route through the adapter, is a loss. A probe that could not be set up (the adapter vanished, the option was
  > refused) is an `Err`, never recorded as a loss, because it measured nothing.
  > - The monitor now says what to probe and when (`PathMonitor::due_probes`): the carrying path every 10 s, any other usable path every 30 s (a probe is a real
  >   connection, and a standby cellular path costs data), a path the system calls unusable never, a path that returns at once, and a refresh does not reset the clock.
  > - **Proven:** the pinned connect works on loopback, a closed port counts as an answer, and a pin to an adapter with no route fails at once (under 1 s) rather than
  >   waiting out the timeout, which is what distinguishes a working pin from a decorative one.
  > - **Not proven, and why:** no probe has run through a real adapter to a real endpoint (none is reachable from this machine outside a lab run), and the *broken-pin*
  >   variant of the pin test was not run, because letting the unpinned connect follow the default route would put a packet on the owner's institutional network, which the
  >   project forbids. That control belongs in the lab, where the default route points at the simulated VM. `cargo run -p dnet-netstate --example probe_path -- <ip:port>`
  >   probes an endpoint through each usable adapter.
  > - **The TCP-only limit is resolved, not carved out (owner: it must work in every condition):** see T135 (which probe to believe, and when) and T136
  >   (the first hop). A UDP-only endpoint is measured at the first hop, and the live tunnel stays the judge after any move.
- [x] T135 [US3] Choose how to measure a path and decide when a probe's silence may be believed, in `crates/dnet-core/src/probe_plan.rs`
  > **Built 2026-10-21 (not committed). 15 tests, 3 mutation-checked.** No probe works against every endpoint on every network, and a probe that fails for a reason
  > unrelated to the path would make a healthy path look dead. Rules: (1) *measure what the tunnel uses*: the endpoint probe is TCP and speaks for a path only when
  > the active profile is TCP-carried; for a UDP profile only the first hop is measured. An authenticated UDP handshake as a probe is rejected on purpose: a
  > WireGuard-style server re-points the peer's endpoint at the source of any valid handshake, so a probe through a standby adapter would move the *live* session
  > onto it. (2) *Silence counts only from a strategy that has been heard*: one that never answered (an endpoint that ignores pings, a gateway that drops echoes) is
  > inapplicable, its silence is no information and the next strategy is tried; once it has answered, silence is a real loss. (3) *Calibration has a scope*: the
  > endpoint's answering is true of the endpoint for every path, a gateway's of that gateway for that path (one gateway answering says nothing of another's); both
  > are forgotten when the thing learned about changes. A path nothing can measure stays unmeasured.
- [x] T136 [US3] Measure the first hop with an echo to the path's gateway, in `crates/dnet-netstate/src/echo.rs`
  > **Built 2026-10-21 (not committed). 2 tests.** `echo::echo_gateway(gateway, timeout)` (Windows): `IcmpSendEcho` on a blocking thread, unprivileged. A gateway is on-link
  > on exactly one adapter, so the echo can only leave through that adapter and needs no pinning. The first hop is where weak Wi-Fi, a saturated access point and a
  > dropped association show first; it cannot say the internet beyond is reachable. No-reply and error-reply are both `Silent`. Proven on loopback only; it has not
  > been run against a real gateway by the agent (the owner's network is institutional); `cargo run -p dnet-netstate --example probe_path` does it on request.
- [x] T137 [US3] Failover decisions need evidence, not the absence of it, and must work when every path is weak (failover.rs, path_monitor.rs, quality.rs)
  > **Built 2026-10-21 (not committed). 8 failover tests, 3 monitor tests, 1 quality test; mutation-checked.** (1) `PathQuality::is_measured`: a path that has seen no sample
  > reads as `Good` (a freshly detected link must not be shunned) but is never *moved to* voluntarily, and the 30 s stability clock starts at its first sample, not when
  > it appeared; a lost link or a dead (`Unusable`) carrying path still takes the best available path, measured or not. (2) Evidence expires: a path whose last sample
  > is older than three probe intervals reads as unmeasured to the decision, and its proof starts again from zero when probes resume (`PathMonitor::observe` now takes
  > the time). (3) Weak conditions: among poor paths, one with at least 0.15 less smoothed loss is worth a move, so a connection where nothing is good does not stay on
  > the worst of them.
- [x] T138 [US3] The daemon task: watch the network while a tunnel is up, measure the paths, and move the tunnel when it should move
  > **Built 2026-10-21 (not committed). 13 loop tests, 5 orchestrator/engine tests, 6 tunnel tests; all behaviours mutation-checked. Not yet run live (see below).**
  > `dnetd/src/netwatch.rs` is the loop; `NetworkWatch` is everything it needs from the machine, so every behaviour is tested against a fake machine with the clock paused.
  > `winwatch.rs` is the Windows machine: `ChangeSource` + `settled` (run on a task of their own, because `settled` counts events as it goes and is not cancel-safe),
  > `paths::current`, `probe_tcp`, `echo_gateway`, `Tunnels::carry_over`. The orchestrator starts the loop when a tunnel comes up and it ends with its attempt, like the live monitor.
  > - *Two kinds of profile.* AmneziaWG can be steered (its endpoint host route is ours): on a lost link, or a better path proven, the host route is rewritten and the tunnel rebound, and the move is
  >   reported. The primary-core profiles bind to whatever path the system uses, and a route pinned against that would fight the core: for them the loop decides nothing, notices which adapter the
  >   tunnel is really on and reports changes (FR-016b: the user is told). *Failover for Hysteria 2 and REALITY is therefore the system's, observed, not ours, until the core is told which interface to use.*
  > - A slow probe never delays a lost link (probes are tasks; the loop only receives results). A failed move is not assumed to have happened: the monitor is put back, nothing is reported, and no
  >   retry for 30 s. The announcements of the system are the fast path; the paths are also read every 30 s as a safety net (a test caught that a first version of its own test passed for the wrong
  >   reason: a *preferred* path proving itself is returned to by itself, which looked like the slow read working; the alternative is now a less preferred path, and the test fails without the feature).
  > - `Input::PathChanged` makes the engine record `ConnectionEvent::PathChanged` with the tier in effect; clients see it on the event stream.
  > - `dnetd --no-path-watch` (development): no watching and no probing, so a test run never sends a probe (a gateway echo, an endpoint connect) to the network it runs on. The Connect lab gate uses it:
  >   without it the daemon would echo the owner's real, institutional gateway every 10 s during a run.
  > - **Not proven live, and why:** failover needs two real, working physical paths, which the WSL lab does not have (its virtual switch is deliberately not a way out). T085 (SPIKE-R9) is the gate:
  >   HV-06/07/08 on real hardware, e.g. Wi-Fi plus a cable or a tethered phone. `watch_paths` and `probe_path` examples show the pieces on a real machine today.
  > - Security review (route rewrite, event stream, probes): see the T138 review note in the session record; nothing a client can send reaches the move (no IPC request names a path), the gateway comes from the
  >   system's own table, and the probes touch only the user's own endpoint and the machine's own gateway.
- [x] T139 Refuse to run programs as SYSTEM from a place ordinary users can change (install trust), in `crates/dnet-config/src/install_trust.rs`
  > **Built 2026-10-21 (not committed). Security audit finding V1.** The service runs the two cores and loads the adapter driver library as SYSTEM, from paths it is given. If the
  > installation folder is writable by an ordinary user, that user replaces a program and is SYSTEM at the next connect. Nothing checked.
  > - The policy is read from the file's real security descriptor (owner and DACL), not guessed from the path: the owner is SYSTEM, Administrators or TrustedInstaller; no untrusted account may
  >   write, delete, change the DACL or take ownership of the program or its folder; on the folders above it only delete, delete-child, WRITE_DAC and WRITE_OWNER matter (renaming the folder away is
  >   as good as replacing the file). Inherit-only entries are ignored (they do not apply to the object); a right the check does not know is treated as every right, so a new flag cannot pass.
  > - `dnetd` checks before every connect and refuses with a message that says what to do (`install_message`, no vendor names). `--allow-untrusted-install` exists for development and the lab gate
  >   only, and says so in the log every time it is used. It is not a setting.
  > - **Not proven:** on a real installed layout (T114 builds the installer). The tests use real security descriptors on real files; the lab gate runs with the flag because its tree is the owner's.
- [x] T140 Keep the control pipe serving while clients misbehave, in `crates/dnet-ipc/src/server.rs`
  > **Built 2026-10-21 (not committed). Security audit finding V2.** The pipe is open to every signed-in user, and the service stops when its listener ends (a stopped service drops the tunnel
  > and lets traffic out). One failed accept ended the listener; a client that connected and said nothing held its slot for ever; a crowd of them held every slot.
  > - `Limits` (32 clients at once; 10 s to send a first byte; 120 s idle). `accept_forever` retries a failed accept with a back-off (100 ms doubling to 5 s) and never returns; a slot is taken
  >   before the next instance of the pipe is created, so instances can never exceed the limit. `run_control_listener_with` takes the limits so a test need not wait for the real ones.
  > - Tests in `server::tests` against a fake acceptor and the paused clock: back-off doubles and is capped; a silent client is let go at the idle limit (and without a limit is kept, so the test
  >   can fail); failed accepts do not end the listener nor spin in a tight loop; no more clients are accepted than the limit. `tests/pipe_limits.rs` on the real pipe: silent clients are let go,
  >   the listener lives, the next client is served. Mutation-checked.
  > - On a non-Windows build these helpers are compiled only for tests (`cfg(any(windows, test))`); the Linux lint caught that they were dead code there.
- [x] T141 Audit sweep: smaller hardening found while reviewing the existing code
  > **2026-10-21 (not committed).**
  > - **Release builds unwind.** `panic = "abort"` is gone from the release profile: with it, a panic in any one task ended the service, and with it the tunnel. A panic now ends a task.
  > - **Secrets are wiped.** `Secret` and the AmneziaWG `PrivateKey` hold `Zeroizing<String>`; a clone's memory is wiped too. (A wipe is not proof against a process that can read this one's memory:
  >   SYSTEM and debuggers can. It limits what a later reader of freed memory finds.)
  > - **Core output is logged at trace,** not at a level that is on by default: a core can print what it was given, and the generated configuration holds credentials.
  > - **Property tests on every parser of outside input:** `dnet-ipc` (10, replies, state, events, requests, versions), `dnet-config` (6, credential bundles, configuration, pins), `dnet-core` (5, origins,
  >   host names), `dnetctl` (5, what it prints and its command line). They assert no panic and, where something is accepted, that it is within the limits the rest of the code relies on.
  >   `dnetctl`'s table printer used to index past its widths for a row longer than its header; it no longer can.
  > - **Orphan reaping (`dnet-supervisor/src/orphans.rs`).** A process that could not be opened for any reason was treated as "gone", so an orphan that could not be opened (access denied) was left
  >   running while the service believed the way was clear. Now only "no such process" is gone; everything else is an error. The check that a process is one of ours and the kill are made through one
  >   handle (a second open by id after the scan could end whatever had been given the id in between). Every orphan is tried; the first failure is returned afterwards. Mutation-checked (2).
  > - **Branding lint:** the adapter library's file name and the vendor-name assertion in `effects.rs` are assembled at run time, as `lint-branding` itself does, so the lint stays strict instead of gaining an exemption.
  > - **Examined and found sound:** process spawns (the only production one, the resolver flush, builds an absolute path from the system's own `SystemRoot`; the other two are tests); no secret reaches
  >   a `tracing` call; every `unsafe` block in `dnet-supervisor/src/orphans.rs` carries its justification.
  > - **Not done, and why:** dependency advisories (run afterwards: see T143); the profile feed parser and its rollback protection do not exist yet
  >   (T066a–d), so there is nothing to audit; the Windows service stop path and undo recovery were reviewed in earlier tasks and have not changed since.
- [x] T142 [US1] Review the UI stack and design before T099: measure the mandated stack, write the design system, record the decision (ADR-0007)
  > **Done 2026-10-21 (not committed). ADR-0007 approved by the owner 2026-10-24; the SC-013 rewording is applied in `spec.md`. D-UI-1…5 in `docs/design/design-system.md` §17 stand as recorded.**
  > - **Measured** (`testing/spike-ui/`, throwaway, detached from the workspace): Tauri 2.12.5 + WebView2 as a tray-resident app is **3.5 MB private with no window**, **94 MB with the window open
  >   (8 processes)**, back to **4.8 MB** one sample after the window is destroyed; a window opens in **~440 ms**. A native toolkit (Slint, software renderer) is 2.9 / 4.9 MB. The stack's "near-zero idle
  >   footprint" is true **only if the web view is destroyed**, so that is now a constraint (R2), and the tray menu must be native (R1) because a web view is too slow to open for a menu.
  > - **Decision:** keep Tauri v2 + Svelte 5 (a two-way door: the UI is a client of the pipe protocol), under eight binding constraints R1–R8 (ADR-0007 §5). Alternatives are compared in §3; only the two
  >   that could realistically win were measured, the rest are marked "not measured".
  > - **Design system v2** (`docs/design/design-system.md`, `tokens.css`, `preview.html`): an "instrument panel" identity (ink surfaces, one paper action colour, four lamp colours used only for state, mono
  >   readouts), shape before colour, a native tray, window lifecycle, WCAG 2.2 mapping, UI safety rules, performance rules. `preview.html` is a working mock of every state in both themes and recomputes the
  >   30 contrast pairs live (the first version checked 22).
  > - **The first run of the contrast check found a real defect in the previous design:** control borders were below the 3:1 non-text floor in both themes (2.25 dark, 2.55 light); fixed in the tokens.
  >   A second defect found in review: the consent dialog's risky choice was styled as the primary action; both now have equal weight and focus starts on the safe choice.
  > - **Version 3 ("Orbit"), same day, from the owner's feedback** that v2 looked like a first scaffold: a rotating dot figure at the centre whose *form* is the state (ring, ring + sweep, sphere,
  >   half-lit sphere, cube) and which is the on/off control; each network a labelled moon with a dotted beam (flowing only on the one carrying traffic); one compact instrument strip (latency, jitter,
  >   loss, stability) plus a drawer; a floating dock instead of a sidebar; a dot-matrix wordmark plate instead of title text; an ambient colour wash; Bahnschrift display face (ships with Windows, no
  >   payload). **The first run of the extended contrast check (30 pairs, ambient wash included) failed in the light theme** (tertiary text 4.29–4.38 : 1); the token was darkened. The scene costs
  >   0.3–1.3 ms per frame at a 30 fps cap (measured in a browser tab; re-measure in the real window, T116).
  > - **Honesty calls in v3:** using several networks at once is aggregation, deferred to v2 by the constitution, so the preview shows it only as a labelled concept; "how much it improved" is shown as
  >   counters of what the product did, never as a percentage. Decisions D-UI-1…4 were delegated to the assistant by the owner and are recorded as made (`design-system.md` §21).
  > - **Not done:** no application code (T099 onward), no screen-reader pass (T111), no measurement with the real UI (T116). The data the new design needs is not yet exposed: see T144.
- [x] T143 Dependency advisories and the Rust 1.83 floor
  > **2026-10-21 (not committed).**
  > - `cargo audit` (advisory database of 2026-10-21) reported **10 advisories in 4 crates**, all in the TLS/QUIC stack that `reqwest` brings into `dnet-provision`: `rustls` 0.23.44 (5), `rustls-webpki`
  >   0.103.15, `webpki-roots` 1.0.9, `quinn-proto` 0.11.17 (3, severity 7.5). Fixed by a compatible lockfile update to 0.23.46 / 0.103.16 / 1.0.10 / 0.11.19; `cargo audit` is now clean; fmt, clippy and all
  >   1,119 tests pass. `quinn` is a reqwest dependency for other targets only: it is not in the Windows or Linux build graph (`cargo tree`), so the three QUIC advisories were not reachable in a shipped binary.
  > - **Finding, not fixed (owner decision): the declared minimum Rust version, 1.83, was already not true.** CI builds only on `stable`, and the committed lockfile contains crates that need edition 2024
  >   (`base64ct` 1.8.3, `cpufeatures` 0.3.1), which Cargo 1.83 cannot even parse. An MSRV-aware lockfile (`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`) does build on 1.83, **but it keeps
  >   `quinn-proto` 0.11.14, the vulnerable one**: the fixed releases need Rust 1.85 and pull in more edition-2024 crates. So the floor and a clean audit cannot both hold on 1.83.
  >   Options: (a) raise the floor to 1.85 (recommended: it is Feb 2025; the ecosystem has moved; nothing enforces 1.83 today); (b) keep 1.83 with the MSRV-aware lock and an audit ignore for the three
  >   unreachable QUIC advisories, justified in `audit.toml`; (c) drop `reqwest`'s transitive QUIC by pinning features. Until decided, the lock is the audited one and CLAUDE.md's "MSRV is Rust 1.83" is not enforced.
  > - **Decided (owner delegated it): the floor is now Rust 1.88.** Checking 1.85 (my first recommendation) showed the current dependency set already needs **1.88** (the `icu_*` crates, through `idna`),
  >   so 1.85 would have been false too. `Cargo.toml`, `CLAUDE.md` and a new CI job (`msrv`, toolchain 1.88, `cargo check --workspace --all-targets`) say 1.88; verified here on 1.88.0 for the
  >   whole workspace on Windows with `RUSTFLAGS=-D warnings`, and for the portable crates on the Linux target. Also added a CI job `linux-portable` (clippy on the portable crates), which CLAUDE.md
  >   required and CI never ran. Neither job has run in CI yet.
  > - Raising the floor changed what clippy asks for: `is_multiple_of` (stable since 1.87) replaced three hand-written `% n == 0` tests (`install_trust.rs`, `reality.rs`, `orchestrator.rs`; behaviour
  >   identical, since the divisor is never zero there).
- [x] T144 [US3] Give the interface the data its design needs: the list of networks, their quality, the session counters, the network name (additive control-protocol change)
  > **Built 2026-10-22 (not committed); live runs pending (see the end of this note).** Every layer: `dnet-core` (`path_monitor` history and snapshot, `degraded` reporter, `telemetry` counters and
  > per-network history, `Degraded`/`Recovered` session events), `dnet-ipc` (`GetPaths`, `GetStats`, the two events, `netview` decoders — contract IPC-12b, IPC-16 —, additive: an older service answers
  > `InvalidRequest` and `dnetctl` says the service is older), `dnetd` (`telemetry`, `netwatch` publishing a board of readings and names, the orchestrator feeding counters), `dnet-netstate::wifi`
  > (the network name from the system's wireless API) and `dnetctl paths` / `dnetctl stats`. What is honest by construction: **only the profile the engine steers is measured**, so every other network
  > reports `measured: false` and the decoder refuses a reply that claims otherwise; a reading older than three probe intervals is labelled last-known with its `as_of`; "typical" appears only after 8
  > answers and is the middle 80 %; "improvement" is **counters of what the product did**, never a percentage; there is no "drops" or "interruption" figure because it is not measured (a network change is
  > counted, and whether it drops connections follows from the tier). **Network names are untrusted** (they are chosen by whoever runs the access point) and are cleaned of control and bidirectional
  > characters on both ends.
  > - Tests across the five crates; the work was mutation-checked in rounds (28 mutations, all caught after one survivor — the name-length clamp — got its own test).
  > - **Finding:** on Windows 11 the network name needs the *Location* permission; without it the system returns an empty name. The code treats that as "name unavailable" and shows the interface kind
  >   instead; it is not an error. Whether the SYSTEM service gets names is **untested** (see the morning checklist).
  > - **Security review is still required before commit** (IPC boundary; SSIDs are personal data). Names are excluded from the diagnostics bundle by default (T112, not built).
  > - **Run by the owner:** `cargo run -p dnet-netstate --example wifi_names` (normal and elevated), then `dnetctl paths` and `dnetctl stats` against a running service.
  > **Proposed 2026-10-21 (design-system §19), as built above.** The engine already models, per network, kind (Wi-Fi, cellular, Ethernet), role (carrying, standby, unusable) and smoothed latency, jitter and loss
  > (`dnet-core::path`, `quality`), but the control protocol sends only the connection state. Needed: (1) `GetPaths` and a path-quality event; (2) the Wi-Fi *name* (a system Wi-Fi query in `dnet-netstate`;
  > a name can reveal location, so it is shown only locally and excluded from the diagnostics bundle by default); (3) a short history in the service (for the 40-sample traces and "typical over 10 min");
  > (4) session counters, which needs **measuring interruptions** (a drop and its length are not measured today; path and method changes already are recorded); (5) an `as_of` timestamp on replies, so the
  > window can say "updated 1 s ago" and never show a stale reading as current. Additive, with the compatibility rule of IPC-15 (a protocol version bump); **security review is mandatory** (it is the IPC
  > boundary, and SSIDs are personal data). Throughput is **not** exposed: it is measured once, at connect.
- [x] T146 [US1] Let a client add, remove, enable and disable endpoints and choose encrypted-DNS handling (`dnet-ipc`, `dnetd`, `dnetctl`; IPC-17 to IPC-22)
  > **Built 2026-10-24 (not committed); security review is required before commit** (IPC boundary, key and credential material, the profile/endpoint inventory the core configuration is generated from,
  > and a change to the encrypted-DNS rules). Contract: `ipc-protocol.md` §Configuration requests.
  > - **Wire (`dnet-ipc`).** `AddEndpoint(NewEndpoint)`, `RemoveEndpoint`, `SetEndpointEnabled`, `SetEncryptedDnsHandling`. Strict: exact fields, nothing defaulted, an unknown field refused **without repeating its
  >   name** (a real leak found by test: the error used to echo the client's text). `NewEndpoint` is valid by construction, by the rules the saved configuration applies on read. There is **no `port`**: each
  >   credential bundle carries its own, and the listing shows the first one the bundle has. 17 tests in `tests/configuration.rs`, IPC-17 to IPC-21.
  > - **Daemon (`dnetd::configure`).** Each change is a transaction over the store, the sealed credentials and the file, restored from a copy on any failure. Add: seal after the file is encoded, write the file
  >   last, forget the sealed credentials if the write fails. Remove: write the file first, forget the credentials second (a stray blob at worst, never an endpoint without credentials). An endpoint holding
  >   cloud resources is **refused** (removing it here would orphan them and leave them billed; that is the provisioning flow's job). Opting out of the encrypted-DNS block returns the consequence to show.
  >   21 tests against a state file and a secret store that can be made to fail.
  > - **Idle only, then rebuilt.** `DnetService` refuses a change while connected or being connected (`Handle::is_idle`), saves it, and replaces the orchestrator with one built from the changed store
  >   (`Handle::retire` stops the old one without waiting; it is idle, so there is nothing to undo). The store lock is held throughout, so no connect can slip between the two. 9 tests, 4 of them with a
  >   real orchestrator.
  > - **`dnetctl`.** `add-endpoint <label> --host <address> (--credentials-file <path> | --credentials-stdin)`, `remove-endpoint`, `enable-endpoint`, `disable-endpoint`, `encrypted-dns block|allow`.
  >   **Credentials are never accepted as an argument** (shell history, process list). The file is read with a size bound, a Windows byte-order mark is tolerated, the content is never printed, and the person
  >   is told to delete the file. Everything is checked with the service's own rules before anything is sent. A reply that is not what was promised (an add without an id, an opt-out without its consequence)
  >   is reported as unexpected, not as success. 25 new tests (7 parsing, 10 end to end against the real server dispatch, 8 for reading credentials).
  > - **Mutation checks.** `mut_configure.py`: 14 mutations, 13 caught at once; the survivor was an up-front duplicate-label check that the store enforces anyway, so it was **removed** rather than kept as dead
  >   defence. `mut_ctl.py`: 8 of 8 caught.
  > - **Not done.** Rules, profile settings, Brutal and provisioning requests are still "not available". Credentials travel over the control pipe, which only the interactive console user may use, and are
  >   sealed on arrival; the pipe's own confidentiality against an administrator is the same as for every other request. The sealed store and the trusted config file are exercised against memory, and
  >   against the real DPAPI/ACL code only by earlier tests: **a live check as the installed service is still the owner's** (`dnetctl add-endpoint` against a running `dnetd`, then `dnetctl endpoints`,
  >   `connect`, restart the service and `endpoints` again).
- [ ] T145 [US1] Build the "Orbit" window against a mock of T144, in `apps/dnet-tray` (after T099/T100)
  > **Proposed 2026-10-21.** The home view, the core figure, the network chips, the strip and drawer, the dock, the plate, per `docs/design/design-system.md` v3 and `preview.html` (the reference). Acceptance:
  > the preview's states in both themes; reduced motion; forced colours; the 30 contrast pairs as a unit test; scene cost ≤ 4 ms/frame in the Tauri window; axe clean; nothing runs while hidden (ADR-0007 R2, R8).
  > **Built 2026-10-24 (not committed), against the mock and then against the real service.** The home view, figure (ring/sphere/cube, 30 fps cap, stops when hidden, one still frame under reduced motion), network chips, strip and drawer, dock, plate and heartbeat, the dark and light themes (looked at in the browser pane and in the real Tauri window), 30 contrast pairs × 2 themes as unit tests, axe clean on every view, nothing running while hidden. 221 tests; 12 + 8 mutants checked.
  > - **Open (acceptance not yet met):** scene cost ≤ 4 ms/frame **measured in the Tauri window** (not measured; the budget logic is in `scene.ts`); forced colours (a stylesheet block exists; no test, not seen) and reduced motion (the attribute is tested; not seen on a screen); window-open memory and cold-open time (T116).
  > **Own frame and two defects, 2026-11-04 (owner's request and screenshot; test first; seen by the owner only).** (1) The window is created without the system frame (`.decorations(false)`) and the page draws the
  > title bar and edge (`TitleBar.svelte`, `lib/chrome.ts`): a labelled "Window" region with the name, Minimize, Maximize or Restore, Close, dragged by pressing on the bar and maximised by a double-click. The page is given five named
  > commands (`window_minimize`, `window_toggle_maximize`, `window_start_drag`, `window_close`, `window_ready`) and **no** general window permission (R4); a test fails if a command is declared, granted or handled in only one of build.rs, the capability
  > file and shell.rs, or if any `core:` permission other than event listening is granted. The Rust side emits `dnet:window` (a boolean) on every resize so the button is right however the window changed. Absent in a browser tab (no Rust side).
  > **Found by the security review and fixed:** a frameless window whose page failed to start would have been blank and impossible to move or close, so the page says `window_ready` once the title bar is drawn and the Rust side gives the system frame
  > back after 10 s if it does not (`watch_page`; not exercised: no test forces a page failure); and a double-click is read from the second press (`detail` 2), because the system's move loop can swallow the release. 16 tests; 300 in all; 0 type errors; 58.8 KB gzipped. **Not seen:** the real window (resize edges and the corner radius on Windows 11 are the framework's; the owner should drag, snap, maximise and close it). (2) The owner's screenshot showed
  > the service's own refusal text ("Approve it with `dnetctl approve ...`") as an error after turning a server on: `Endpoints.svelte` handled a held change when adding a server but not when turning one on, and the card headed "Waiting for
  > your approval" stayed after the change was approved. Fixed (the mock now holds a turn-on as the service does; three tests, one mutation caught). Checked afterwards against `redirects_traffic` in `service_impl.rs`: the service holds only adding a server (by hand or the guide), turning one on, a rule that
  > bypasses the tunnel, and a feed import; Settings' requests (Brutal, encrypted names) are not held **by design** (they can only make the connection stricter or leave it where it is), and the window sends no feed import, so no other
  > view has the gap. That also corrects the earlier note that Brutal "applies without approval" as a finding: it is the rule, not a defect.
  > **Onboarding walked as a new user would see it (built-in browser against the mock), 2026-11-04; four problems fixed, test first, 308 tests.** (1) Every disabled primary button looked live: `.btn.primary` came after `.btn:disabled` with the same weight, so the light fill
  > won (a disabled "Continue" looked like the one thing to press); it now has its own rule, and any disabled button has a quieter edge too. (2) The guide's first screen put the way to start at the bottom of a long comparison; the button is now at the top of each card,
  > and the "not available yet" note appears once, beside its button. (3) The provider cards kept the browser's white button border, so a picked one was hard to tell from the other; the pick now has a "Chosen" badge and a strong edge. (4) Servers, Rules, Settings and the guide
  > said "disconnect first" with no way to do it there; the note now has a **Disconnect now** button (`DisconnectNote`). **Not checked:** the same walk on the real window; the later guide steps (account creation, the script, pasting the result) were not walked.
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


### Zero-touch operation (added 2026-10-26; proposed, not in the original plan)

The product goal stated by the owner on 2026-10-26: install, open, turn on, and nothing else.

- [x] T147 [US1] The connection stays the way the person left it across a reboot, an update or a crash (FR-036, `crates/dnetd/src/intent.rs`)
  > **Built 2026-10-26 (not committed).** An accepted `Connect` is remembered (with its profile, or none for "best"); any `Disconnect` the
  > person sends forgets it, whether or not anything was connected. At start-up, after recovery and only through an orchestrator that
  > recovery allowed to exist, a service left on connects again. A failed attempt, a service stop and a machine shutdown change nothing.
  > The record is `state\connection-intent.json` beside the configuration (`TrustedStateFile`: same owner and DACL check). Anything in it
  > that is not exactly what this build writes reads as off. 11 tests (5 for the file, 6 through the service with a real orchestrator);
  > the 6 service tests failed before the change (no `with_intent`/`resume_if_left_on`).
  > - **Security review (routing mutation at start-up, 2026-10-26).** (1) Who can make the service connect at boot: only a writer of the
  >   state directory, i.e. SYSTEM or Administrators, who can already do anything; a pre-created or re-owned file is refused by the trusted
  >   file check before it is read. (2) Fail closed: an unreadable, malformed, unknown-version or unknown-field record is off; nothing
  >   substitutes "direct". (3) Order: resume runs after start-up recovery and only through the recovery-gated orchestrator, so a journal
  >   that could not be restored still blocks every connect. (4) Consent: a resumed connect is the same request the person made, with the
  >   same profile and no other substituted; Tier 2 handling is unchanged (the engine prefers Tier 1, as for any connect). (5) Nothing new
  >   crosses the IPC boundary. **Residual:** a person who turned it on and then lost the endpoint gets a failed attempt at every boot until
  >   they turn it off; the state says why.
  > - **Also fixed here:** the refusal of a change while connected read "...handling; the" followed by a run of 26 spaces (a broken line
  >   continuation, in master); it now reads "disconnect before changing settings; ..." and a test pins it. The service now accepts the
  >   Shutdown control (it handled it but never told the SCM, so Windows never sent it).
  > - **Not verified:** a real reboot with the installed service (owner step, `LOCAL-COMMANDS.md` 7.5, 7.6).
- [x] T148 [US1] While left on, a connection that failed is tried again (FR-036, spec edge case "sleeps and wakes on a different network"; `crates/dnetd/src/keep_trying.rs`)
  > **Built 2026-10-26 (not committed).** Found while building T147: `Failed` is terminal in the engine ("connect again to retry"), so a
  > start-up resume before Wi-Fi joins (common: per-user Wi-Fi joins after sign-in) would fail and stay failed. Now, while the intent is on
  > and the orchestrator is idle (failed, or down after a configuration change), the service connects again with the same selection:
  > 15 s after it is seen down, then 30 s, 1, 2, 4 and 5 min apart, back to 15 s once connected; a settled network change
  > (`dnet_netstate::notify::ChangeSource`, the one the path watch uses) brings the next attempt forward, but not within 60 s of the last,
  > because a failed attempt's own teardown changes the network. Ten minutes of failure cost 5 attempts. The intent's in-memory value wins
  > over the file, so a disconnect whose file could not be removed is still off in this run.
  > 10 tests: 6 for the pacing (paused clock), 4 through the service with a real orchestrator (keeps trying until it connects; a
  > disconnect stops it for good; nothing is retried unless left on; a healthy connection is only looked at). The 4 service tests failed
  > before the change; two mutations (ignore the intent; never connect) were each caught.
  > - **Security review (routing mutation without a request, 2026-10-26).** Same anchor as T147: it acts only on the person's remembered
  >   connect, through the recovery-gated orchestrator, with the same selection. New here: (1) **ordering against a disconnect** — a retry
  >   reads the intent and connects under the store lock that every request takes, and `Disconnect` forgets under it, so no retry can follow
  >   a disconnect; (2) **bounded work** — at most one attempt per 15 s at the start and one per 5 min after, and network changes cannot
  >   push past one a minute; (3) shutdown: the stopped orchestrator refuses a connect, so a retry cannot race the service stopping.
  > - **Not verified on Windows:** the change source while failed, and a real sleep/wake (owner steps, `LOCAL-COMMANDS.md` 7.6, 7.10).


### Guided server setup (added 2026-10-30; decision of the owner, same day; plan: `docs/plans/2026-10-30-guided-onboarding.md`)

The owner chose: cloud server by default and recommended; the person works in the provider's own pages
(no cloud credential is ever asked for); onboarding offers two options with pros and cons; the window is a
dashboard. This replaces the earlier assumption that the app would hold an API key for the person's cloud
account (T107's credential screens). Nothing in the constitution changes: the endpoint is still the person's
own, made by DNet Engine's wizard on Oracle Cloud Always Free (or any Linux server).

- [x] T149 [US2] Build and publish the Linux server cores (the T093 gap) — `cargo xtask build-server-cores`, `dnet-provision::server_pins`
  > **Built 2026-10-30 (not committed).** From the same pinned commits as the client's cores, for linux amd64 and arm64
  > (`CGO_ENABLED=0`, `-trimpath`, tags `with_quic,with_utls` for the primary core: the server inbounds only). **Run for real here:**
  > both cores, both processors, ELF checked, SHA-256 written to `server-pins.json`; the real file parses with the same strict reader
  > the service uses, and **the real amd64 core's own `check` accepts the server configuration the script writes**. Not run: the arm64
  > core (built, not executed: no Arm machine) and the script on a real server. `server-pins.json` ships beside the service; the
  > release workflow has a `server-cores` job that publishes the files and the list as release assets (static files; the project runs
  > no service). 5 tests in xtask, 5 in `server_pins` (strict shape, every hostile value refused, nothing echoed).
- [x] T150 [US2] Set up the person's own server from a script and a pasted result (IPC-26: `PrepareServer`, `FinishServer`)
  > **Built 2026-10-30 (not committed).** The service makes the client keys (they never leave this computer), keeps them in memory for 6
  > hours, and returns the script and the three ports. The same script comes back if the window is closed and reopened, so a script
  > already run on a server keeps matching. `FinishServer` parses what the server printed as hostile input, checks it against what was
  > asked for, and adds the server under a name and address. 16 new tests in the service (9 module, 4 through dispatch, plus the
  > existing ones adjusted), 9 for the wire (IPC-26, 2,000-case proptests), 6 in `dnet-view`.
  > - **Security review (credential material, IPC boundary, 2026-10-30).** (1) The script holds no secret (tested: the client's private
  >   key is absent, the public key present). (2) The report holds the server's secrets and is bound to **one script** by the client public
  >   key it echoes: a report from an earlier script is refused with a plain sentence instead of being used with the wrong keys (a silent
  >   misconfiguration found while writing this; `Mismatch("the client key")`). (3) A failed save (a name already in use) keeps the keys, so
  >   the person is not made to start over; a success wipes them. (4) Idle only, like every change to the servers. (5) Nothing pasted is
  >   repeated in an error (tested with sentinels in the report, name and address). (6) Every field is bounded and stripped of control and
  >   direction characters at the pipe, before the service sees it. **Residual:** the script and the report cross the local control pipe,
  >   readable by the console user, who is the owner of the keys; the report is pasted through the clipboard.
  > - **The script now also** refuses to run on the wrong kind of processor (before it installs anything; run under `sh` for each case),
  >   installs the keepalive and fails if it is not running (the free-tier idle rule is on CPU **or** network **or** memory: any one above
  >   20% keeps a server), and keeps the server small: core log level `warn`, journald capped at 100 MB and 14 days, package caches cleaned,
  >   a weekly vacuum timer that touches only logs and caches (tested: it names no key, certificate or configuration path).
  > - **Not verified:** the script on a real Ubuntu or Oracle Linux machine; the keepalive against Oracle's live reclamation; that Oracle's
  >   free A1 capacity exists in a given region.
- [x] T151 [US2] The guide, the two-option first screen, the Servers page, Settings categories (`apps/dnet-tray/src/lib/guide.ts`, `views/Wizard.svelte`)
  > **Built 2026-10-30 (not committed).** First screen: "Your own server" (Recommended) beside "Without a server" with good sides, not-so-good
  > sides and what each includes; the second is shown and **not selectable, "Not available in this version yet"** (it would be a different
  > product: it cannot get past a blocking network). Then a provider choice (Oracle Cloud free, or any other Linux server) and eight
  > steps, each with what to do, what you should see, and what to do if it differs. The cost of the free server is said before any step
  > (card for identity checks, home region, 50 Mbps on the small AMD shape, reclaiming); each provider fact carries its date and the
  > provider's page. Window-side helpers are tested: the paste block writes the script to a file and runs it from there (a command that reads
  > input cannot swallow the script), refuses a script holding its own end marker, and builds the connection command only from an address
  > and a name that could be real. The Servers page is rewritten in plain words (nav "Servers"), and Settings is grouped under headings.
  > 28 new web tests (15 guide, 13 wizard, with axe on each screen); 259 in all.
  > - **Provider research, primary sources, 2026-10-30:** Oracle Always Free is the only lasting free option found (card and phone for most
  >   people; trial 30 days; home region; 10 TB out; idle reclamation). Google's free VM has **1 GB a month** outbound, unusable as a tunnel;
  >   AWS's free plan closes after 6 months. **Not verified (the console could not be opened):** Oracle's exact menu and button wording, so the
  >   guide describes what to do and says the wording may differ; the owner checks it against the live console (`docs/owner-gates.md`).
  > - **Not done:** `dnetctl prepare-server` / `finish-server` (the window is the path); the "without a server" mode itself; opening the
  >   provider's page from the window (the window opens no address, R4: it shows the address as text); a tray notice when the server is reclaimed.

- [x] T152 Test hardening sweep, first pass (2026-10-30; plan §7)
  > **Done 2026-10-30 (not committed).** Method: add tests where a defect would be expensive, then **prove they can fail** with seeded defects or
  > `cargo mutants` (v27.1), and say what was found. Not a count target: a count reachable by generating cases proves little.
  > - **Undo registry, model-based** (`crates/dnet-netstate/tests/undo_model.rs`, 1,500 random sequences of add, normal undo, crash and restart,
  >   restore pass, a disk that refuses writes, failing reversals, foreign routes). Holds: every route of ours has a record (write-ahead, whatever
  >   the disk did), a restore pass reverses newest first, ids are unique and in order, nothing of ours is left at the end and nothing foreign is
  >   removed. Two seeded defects (ignore a failed journal write; restore oldest first) were each caught.
  > - **Found, not fixed, said plainly (design limit):** if a reversal succeeds but the journal write that follows it fails, the record stays; a route
  >   that someone else later makes *identical* (same interface, destination and next hop) would be removed by the next restore, because a record
  >   cannot tell whose route it is. It needs a coincidence and an identical host route; the fix (record a tag or the creation time and compare it on
  >   reversal) changes the privileged undo path and wants its own security review. Proposed, not made.
  > - **Mutation testing** of the new modules: `server_pins` 21 mutants, 5 missed on the first run (exact size and file-name limits), all viable ones
  >   caught after one boundary test. The other modules are recorded in the line below if their run finished.
  > - `intent`, `keep_trying`, `server_setup` (63 mutants): 38 caught, 16 unviable, 4 timeouts (a mutant that makes the paused-clock tests spin
  >   forever is detected: the test never finishes), **5 missed**: the six-hour wait written as `6 + 3600` would have been accepted (a real gap; a
  >   test now pins it at 21,600 s), and four in `installed_pins`, which is Windows-only code and is not compiled here, so no test of this
  >   machine can reach it (its read, bound and parse are `server_pins`, which is fully covered; the file read itself is an owner check).
  > - Also from the first pass: tests for the script (processor guard run under `sh`, keepalive ordering, housekeeping bounds, report bound to its
  >   script), wire tests with 2,000-case proptests, 28 web tests.

- [x] T153 A server made by the guide must be usable: it carries the measurement origin (found and fixed 2026-10-30, test-first)
  > **Defect in my own T150, found by auditing what the connection code requires.** `assess_endpoints` refuses any endpoint without a measurement
  > origin ("a connection cannot be tested, and this project provides none"), and the guided flow built credentials with none: **every server made by
  > the guide would have been refused at the first connect.** Red test first (`a_server_made_by_the_guide_is_usable_by_the_connection_code`: seal the
  > guided credentials, run the real assessment, expect no problem and all three methods served). Fix: the script installs a tiny origin
  > (`dnet-origin`) bound to the server's tunnel address `10.66.0.1:8080` and nothing else (private, so a fetch to it is proof of the tunnel), serving
  > exactly `/bytes/n` up to 1 MiB, refusing everything else, starting after the tunnel's address exists and restarting if it stops; it opens no
  > firewall port. The service puts that origin into the credentials. Tests: script content, **the origin run for real under python** (exact byte
  > counts, the cap, eight hostile paths), and the end-to-end assessment above.
  > - **Not verified:** that a fetch to `10.66.0.1` from the client reaches the origin through the Hysteria 2 and REALITY tunnels (it should: the
  >   primary core's direct exit connects to the server's own address). Owner gate: `LOCAL-COMMANDS.md` 9.2.
- [x] T154 Network cost: cheap live checks, smaller race, leak settings pinned (`docs/network-budget.md`)
  > **Done 2026-10-30 (not committed).** Audit of everything the client sends found the largest waste: a connected, idle tunnel fetched 128 KiB every 5 s
  > (about 92 MB an hour, 2.2 GB a day, through the person's connection and their server's allowance). Now `LiveChecker`: a 1 KiB sliver every time, a full
  > check every 10 minutes and at once when a sliver comes up short; a new connection starts from the race that just proved it. About 1 MB an hour idle.
  > The race asks 192 KiB per method, not 512 KiB, with a compile-time check that a link at the slowest usable speed finishes inside the race's allowance
  > (the old size could not: 512 KiB at 256 kbit/s takes 16 s against a 12 s allowance). 10 new tests (a real local origin counts the bytes), mutation run on
  > `checks.rs`: 18 mutants, 3 missed on the first run (exact sizes, `forget`), all viable ones caught after two tests. Cost of the trade: a tunnel that still
  > moves a kilobyte but too slowly to be usable is found at the next full check, up to ten minutes, not within five seconds.
  > - **Leaks:** `leak_01_…` pins `auto_route`, `strict_route`, DNS hijack, no IPv6 address and a non-open fallback for all three methods (seeded defect caught).
  > - **Not done:** treating metered connections differently; measuring any of this on a real wire.

---

### Session–carrier framework (added 2026-10-31; ADR-0008, proposed; the owner approved F8 and F12 the same day by telling the session to proceed; evidence: `docs/research/2026-10-31-solutions.md`, `testing/spike-carrier/`)

> One session (an endpoint of the primary core) over replaceable carriers (Hysteria 2, REALITY), so a carrier can
> be replaced without ending the person's connections. Proven on the pinned core with the extra build tag, on
> loopback only. Every step below that touches the IPC boundary, privileged operations, key material, routing or
> core-configuration generation needs the security review before it is committed.

- [x] T155 [US1] The primary core is built with the session endpoint's tag (ADR-0008 F12; amends ADR-0004) — `crates/xtask/src/fetch_vendor.rs`, `server_cores.rs`
  > Done 2026-10-31, test first. The previous pin refused the endpoint ("not included in this build"). Client core tags gain
  > `with_wireguard`; the server core gets `with_wireguard,with_gvisor` (the endpoint's user-space stack). The test that asserted
  > the exclusion was replaced by one that asserts the endpoint is present. Rebuilt with `fetch-vendor`: 43,097,600 to 43,893,248
  > bytes (+0.76 MB, +1.8%). The installer size is **not** re-measured here (T115). The server core was not rebuilt (needs Go
  > cross-builds; `build-server-cores`).
- [x] T156 [US1] Generate the session configuration (`crates/dnet-config/src/session.rs`; `primary.rs` gains optional, skipped-when-empty parts)
  > Done 2026-10-31, test first. Nine unit tests, each mutation-checked (five mutations of the generator were each caught by the
  > test meant to catch them), plus `session_configs_are_accepted_by_the_pinned_core`, which has the **real** vendored core check
  > the output (12 variants: two encrypted-DNS policies, both FakeIP halves, three carrier sets). The three existing profiles' output is unchanged (a test checks it). The control API requirements
  > are measured facts about the pinned build, not assumptions: no Host check, TCP only, an empty secret disables authentication,
  > an empty cross-origin list means allow-all. The core's endpoint type name is assembled in one constant so the source tree
  > stays free of the trademark (`lint-branding`), as the lint's own source does. Not used by `dnetd` yet (T157).
- [ ] T157 [US1] Switch the carrier and nudge the session (`dnetd`): a control API client, a per-run secret, the switch, then small probes through the session every 250 ms until one succeeds (at most 5 s); the Registry must classify the two benign `closed pipe` log lines per switch
  > Depends on T156. Measured: without the nudge the largest stall was 12.6 s, with it 0.02 s (planned switch) and about 1 s after
  > a dead carrier. Needs the security review (control endpoint, key material).
  > **Built 2026-11-01, not wired** (`crates/dnetd/src/session_switch.rs`, test first, 20 tests): the per-run secret (64 hex characters,
  > wiped, never printed), the control client (hand-written request, bounded reply, tags checked), and the nudge (every 250 ms for at
  > most 5 s; a switch that failed is not followed by one). One test starts the **real vendored core** with a selector and its control
  > API, switches with the real client, and reads back the leaf; it also checks the core refuses an unknown leaf and a wrong secret.
  > Five mutations of the client were each caught. **Used for real by `session_e2e.rs`** (2026-11-01): the client switched real cores to the TCP
  > carrier and back under a live transfer, the nudge recovered the session in 4 to 54 ms, and the transfer finished in one connection. Security review done: **one finding, to fix before wiring**: the port is chosen
  > before the core binds it, so another local program could take it and receive the secret; confirm the listener's process id is the
  > core's before the first request (`GetExtendedTcpTable`). Still open: that check, the Registry classifying the two benign "closed
  > pipe" lines per switch, and the wiring itself, which waits for T158 and T159.
- [x] T158 [US2] Server profile v2 (ADR-0008 F8; audit E1, E2, E5, E12): one core process; both carriers locked to the session port; the exit refuses private destinations except the measurement origin; a session key per device; an unprivileged, sandboxed unit; automatic security updates (`crates/dnet-provision/src/bootstrap.rs`)
  > Done 2026-11-01 as far as it can be shown without a real server, test first. The script now makes the server's session key, writes a
  > configuration **derived** from the keys and the devices (rewritten each run, replaced only after the core's own `check`, service
  > restarted only if it changed), runs the core as an unprivileged `dnet` account with a sandbox (root owns its files, group read only),
  > adds a second origin inside the session, and installs automatic security updates. The plan takes 1 to 8 device public keys; the report is
  > **version 2** with a `session` section checked against the plan (devices, addresses, order). The firewall comment now says only what the
  > step does. Tests: 153 in `dnet-provision`, including **the real core checking the configuration the script writes** (with a control that
  > fails for the right reason), and `crates/dnetd/src/session_e2e.rs`, which runs the script's server configuration and the session generator's
  > client configuration in two real cores: the origin is reached through the session, the exit refuses the machine it runs on (loopback, a
  > metadata address, private addresses, a service on this machine's own LAN address), a carrier credential on its own reaches nothing, and
  > a 14 MB transfer crosses a switch to the REALITY carrier and back in one connection (longest silence 0.2 s). Mutations of the exit rule and
  > of the carrier lock are each caught. Six findings from building it are in `docs/research/2026-10-31-solutions.md` section 10,
  > among them an **existing defect fixed**: the client's built-in rules sent the measurement origin around the tunnel (the existing origin too).
  > **Not done, with reasons (solutions section 10):** a default-deny inbound firewall with a self-reverting timer (E5) and the
  > `iptables` user-id layer. **Needs the owner:** the real-server run (`LOCAL-COMMANDS.md` section 8): `systemd-analyze security`, the
  > script as root on a real image, the free server's CPU with the user-space exit, and an Oracle address that stays put (E13).
  > Security review done: one finding, fixed (the unprivileged account must not own its directory; solutions section 10, finding 6).
- [x] T159 [US2] Session credentials per device: the credential bundle, its stored form, and the guided setup producing it (`dnet-config::credentials`, `dnet-provision`, `dnetd/src/server_setup.rs`)
  > Done 2026-11-01, test first. `SessionBundle` (the device's private key, the server's session public key, the device's address, the port) is
  > part of `EndpointCredentials`; it is stored as **format version 2 only when a session is present**, so every bundle without one is still
  > written as version 1 and read as before; a form that says version 1 cannot hold a session; a session needs a carrier; keys must be 32 bytes
  > of base64; the address must be one of the eight device addresses (not the server's, not the origin's, not another network); errors name the
  > field and never a value; `Debug` never shows the key. Seven tests, four mutations each caught. `report.credentials()` builds it from the
  > device's `SessionKeys` and the server's report; the guided setup passes its pending keys. The shared constants (`SESSION_SERVER`,
  > `SESSION_ORIGIN`, `SESSION_PORT`, `MAX_DEVICES`, `session_device_address`) now live once in `dnet-config::session`. The old text of this task
  > follows for the record.
  > (superseded) Session credentials per device: sealing the device's key pair and the server's session public key, the credential bundle, and the guided setup using the session origin (`dnet-config::credentials`, `dnet-provision`, `dnetd`)
  > Started 2026-11-01: `SessionKeys` (a device's own key pair, base64, wiped on drop, never the AmneziaWG key) exists and the guided setup
  > generates one and puts only its public half in the script; the report's `session_server_public_key()` and `session_device_address()` are
  > there. **Still open:** the bundle in `EndpointCredentials` and its sealing, `credentials()` producing it, `measure_origin` set to
  > `session_measurement_origin()`, and the generator's inputs read from the store (today the session generator is used only by tests).
- [x] T169 [US1] **Use the session in `dnetd`** (ADR-0008; must land with the server profile, because a v2 server's carriers forward only to the session and refuse the old per-profile configuration)
  > Found 2026-11-01 while closing T159. Steps, in order, each test first: (a) `plan_tunnel` builds the session configuration when the profile is
  > Hysteria 2 or REALITY and the credentials have a session (all carriers the endpoint has; the profile chosen is the starting carrier; the control
  > port and secret come from the caller and the plan carries them); (b) the race's probe job does the same, over one carrier with a loopback proxy
  > (a v2 server refuses a probe that uses the carrier directly); (c) the measurement origin for a session-carried profile is
  > `session_measurement_origin()`, and for AmneziaWG stays the stored one; (d) the control API's listener is confirmed to be the core we started
  > before the secret is sent (T157 review finding); (e) the Conductor switches carrier with `switch_to` + nudge instead of restarting the tunnel
  > (ADR-0008 §3.3), and the Registry classifies the two benign "closed pipe" lines; (f) a v1 server (no session) keeps working with the old shape.
  > Needs the security review (key material, the control endpoint, core configuration generation).
  > **Steps (a), (b), (c) done 2026-11-01**, test first, every behaviour mutation-checked (three survivors were found and killed with new tests):
  > `plan_tunnel` builds the session configuration for a Hysteria 2 or REALITY profile whose endpoint has a session (every carrier the endpoint
  > has, the chosen profile as the starting one, Brutal only on the Hysteria 2 carrier and only while it is the chosen profile) and the plan carries
  > a fresh control channel (loopback port, 256-bit secret) for the switch; `probe_job` probes the one carrier under test **through the session**
  > (`dnet-config::session::generate_session_probe_config`, `ProbeJob::new_session`), since a v2 server refuses a probe that uses its carrier directly;
  > the race and the tunnel measure at `origin_for`/`race_origin` (the session's origin `10.9.0.254` for a session profile; the stored origin for
  > AmneziaWG and for an endpoint without a session, planned exactly as before). The real core accepts all of it (`dnet-config` and `dnetd` tests).
  > Security review of (a) to (c): no new finding beyond T157's (the control port is chosen before the core binds it: step d). The secret exists in
  > the plan, the core's restricted file and the control client, is wiped on drop and never printed (tested); a private LAN host that has exactly one of the
  > two origin addresses loses access to it while connected (the price of tunnelling the origins; documented in `builtin_rules`).
  > **Steps (d), (e), (f) done 2026-11-01**, test first, mutation-checked: (d) `listener.rs` asks the system's own table of listening ports who owns
  > the control port and the secret is sent only if **every** socket a loopback connection could reach belongs to the core we started (a pure parser,
  > tested with a buffer that lies about its length, and the real call against this process); (e) the orchestrator folds a `StopTunnel` followed at once by
  > a `StartTunnel` into a *move*; the real effects try it live (same endpoint, a carrier of this session, the listener check, then `switch_to` and the
  > nudge) and on any refusal or failure return `false`, upon which the orchestrator does **exactly the stop and the start it did before** (stop fully
  > before start, tested); a first connection, a disconnect and AmneziaWG never ask for a move; (f) an endpoint without a session is planned and probed
  > exactly as before (tests). Security review of (d) and (e): no open finding. Residual, accepted: the check and the request are a few milliseconds
  > apart, so a core that died and a program that bound its port in that gap could receive the secret, which allows only a carrier switch (a denial of
  > service, no traffic redirected). The already-running network watch keeps its carrier kind until the next connection (the setup is updated for the next).
  > **Not done:** the Registry classifying the two benign "closed pipe" log lines each switch writes (the Registry is ADR-0008 P1); the live move has not
  > been run on Windows with a real tunnel adapter (the composed test `session_e2e.rs` proves the mechanism with real cores on loopback).
- [~] T160 [US1] Control-surface hardening (audit E3, E4; ADR-0008 F13): changes that redirect traffic are held as pending and approved only by an elevated client; read-only detail limited to the console user and administrators
  > Needs the security review. The elevation prompt runs on the secure desktop (Microsoft, "How User Account Control works").
  > **Approval built 2026-11-01 (F13 approved by the owner), test first, mutation-checked; not committed.** `ClientIdentity.elevated` is read from the
  > pipe client's token (`TokenElevation`; unreadable means no); a new request class `Approval` (elevated, console session, any account); `ApproveChange`,
  > `RejectChange`, `ListPending` and the error `ApprovalRequired`; `dnetd/src/approval.rs` holds changes (ten minutes, eight at most, the same change twice
  > is one, ids are not secrets); `DnetService` holds a new server, the setup guide's server, turning a server on, a bypass rule and an imported feed, and
  > approving applies exactly the held request once; `dnetctl pending | approve | reject` (approve opens its own elevated window, shows the change again,
  > applies only on a typed `yes`, has no skip option). Contract `IPC-27`. Tests: 8 contract, 7 authz, 10 for the holding store, 13 in the service, 14 in `dnetctl` (11 behaviour, 3 parsing), 3 for the elevation helper, 1 in `dnet-view`; and mutations
  > (no elevation check; never hold; never remove after approval; accept any answer; skip the elevated hand-over) each failed the suite.
  > **T160b done 2026-11-01 (not committed):** the window lists what waits (`PendingChanges`, in Servers and Rules; read every 4 s) with Approve and Drop. Approve cannot ask the service (the window is not elevated): the shell starts
  > `dnetctl approve <id>` beside the window, which asks Windows and applies only on a typed `yes`; only the checked change name is handed over (`dnet_view::approver`, 6 tests). `dnet-view` reads and drops (golden `pending.json`, 4 tests),
  > the shell has `list_pending`, `reject_change`, `approve_change` (permissions generated; the shell builds), the web side has the parser, bridge, mock and component (4 component tests with axe, 3 bridge tests,
  > 1 fixture test; 267 web tests pass, 55.6 KB of 150). **Not run:** the real window with a real held change and the Windows prompt (needs the new service installed; the owner's click).
  > **(a) done 2026-11-04, test first, hand-mutation-checked.** The installed service holds every new server, so the guide's last step and the Servers form
  > met this on every real install. The window has a fifth code, `ApprovalRequired` (`dnet_view::outcome::code_for` mapped it to `Refused` before). The guide
  > says in plain words that the server waits, shows the Approve list in place, drops its copy of the pasted text (the service holds it with the change), and
  > goes on by itself once the server is listed; a dropped or expired change brings the form back with what to do. It reads the waiting list before the
  > servers (the service adds an approved server before it takes the change off its list), looks every 2 s while shown (approval can come from `dnetctl`) and
  > reads nothing while hidden (R2). Servers and Rules say the change "waits for your approval above" instead of showing the service's command hint as an
  > error. The mock holds as the service does when asked (`holdChanges`; off by default so the rest of the window can be developed) and applies on approval
  > exactly the change it held. Tests: 1 Rust, 1 bridge, 3 component (a held server, a held bypass rule, a tunnel rule not held), 4 wizard (approved in place,
  > dropped, the read order, approved outside the window while hidden); 14 hand mutations each failed the suite. 281 web tests pass, 57.9 KB of 150.
  > **Security review (self):** no new request, wire field or permission; the window shows only what the service listed; the pasted text is dropped as before;
  > the guide's checks read two read-only lists. **Not run:** the real window with the installed service (the owner's click, `LOCAL-COMMANDS.md` 10.8).
  > **Checked before it is held, 2026-11-04, test first, mutation-checked.** The service held a change without checking it, so a wrong paste, a name in
  > use, a program rule or a change asked for while connected reached the Windows prompt and failed only after the person approved it. `hold_change` now
  > refuses at once what applying would refuse now, with the same reason (`refuse_what_cannot_apply`): the configurator's `check_add_endpoint` and
  > `check_add_rule` share their checks with the real adds (`endpoint_for`, `rule_allowed`, `label_taken`) and keep nothing; the guided setup's result is
  > read against the setup waiting (`ServerSetup::finish` changes nothing unless the setup has expired) and its keys dropped; the idle check runs for every
  > held kind. An imported feed is still held unchecked (taking its documents is the check, and it changes the feed's store). Approving checks again. Contract
  > IPC-27 updated. Tests: 4 configurator, 7 service (a name in use, a result that does not match or has nothing to finish, a setup that waited too long,
  > no setup in the build, a program rule, no configurator, three kinds while connected); two older tests now ask for two same-named servers and use a real
  > setup result. Mutation run on the new and moved functions: every mutant caught once the expired-setup test was added (it alone sees the clock); two
  > survivors outside this change are older (`plan_tunnel_with`, and `with_production_orchestrator`, which Linux does not build).
  > **Security review (self):** no new request or field; a client learns at once the reason it would have learned after approval, and nothing more (the
  > reasons never repeat a value or a secret); the check holds no lock across another and takes the state lock only after the orchestrator's is released;
  > a bounded report parse, as applying does; approval stays the only way a held change is applied.
  > **Open:** (b) the read-only detail limit (E4,
  > solutions 3.3); (c) a record of who proposed and approved; (d) the live Windows prompt, the owner's click (`LOCAL-COMMANDS.md` 10.8); (e) the residual in ADR-0008
  > section 12.1: an administrator at the default prompt level can be bypassed by malware that knows how.
  > **Windows run 2026-11-04 (local session, unelevated; the owner was away, so no Windows prompt was answered).** Ran: 1.1 to 1.4, 1.7 (2288 Rust tests
  > pass, 0 fail, 14 ignored; `silence_is_unknown_never_unreachable` passes on Windows; 282 web tests, 0 type errors, 57.9 KB gzipped), 4.1, and against the
  > development service from 4.2: 10.8 (a new server waits, with an id, and the list is unchanged), 10.10 (a made-up id is refused by both commands), a
  > name already in use refused at once with nothing left waiting (10.11's check, with the existing `harness` label), then the test change was dropped.
  > **Not run:** the Windows prompt itself and 10.12 (the window); both need the owner. **Found:** Brutal (`brutal-on --accept-warning`) takes effect at once,
  > it is not held for approval (undone with `brutal-off`); the service reports `Failed: the connection engine is missing from the installation` for a
  > development service run from `target\debug`; `LOCAL-COMMANDS.md` 5.1 used `198.18.0.0/16`, which the fake-IP pool refuses on purpose (now `203.0.113.0/24`)
  > and 7.1 did not say it needs 8.3 first (`target\server-cores\server-pins.json`; now said). Installer (7.1, 7.2): payload 16 files, 53.7 MB; setup 14.9 MB
  > (limit 60), SHA-256 26352F2F893045677F357096FCD84C2F089A852EC0BCB5C1C9C8BF5B2E710E03; not installed (7.3 onwards need the VM).
  > **10.12 and the admin tests, 2026-11-04 (owner present).** 10.12 passed in the real window: the new server waited for approval with no red error, Approve raised
  > the Windows prompt and the second window, `yes` applied it, and it was listed with nothing waiting. **Found:** a development window cannot start Approve unless
  > `dnetctl.exe` sits beside `dnet-tray.exe` (`shell.rs` `run_approver` looks only there; the installed layout has both), and the failure shows only as "could not be
  > started", which does not say where it looked; `remove-endpoint` takes the uuid, not the label. Admin run: 1.5 12 passed; 2.1 passes (the trace session is taken back;
  > the closing `logman query` exits non-zero on purpose); 2.2 failed `t039_unprivileged_client_cannot_alter_routing` while the development service (from 4.2) was running: the test got `{"accepted":true}`, which only a real service on the same pipe name answers. **Correction:** an earlier note here said the cause was the elevated shell; that was a guess, and the later full run (service still up, not elevated) failed the same test, plus three more that share the pipe or a port (`silent_clients_...`, `t125_...`, `session_e2e`). Rerun with the service stopped: pending **Explained:** the `harness` endpoint was disabled by the owner in the Servers list (only a client request can disable one; the service never does).
  > The development service reports `Failed: the connection engine is missing from the installation` because it looks for the cores beside `dnetd.exe` (`Layout::installed`)
  > and a development build has them in `vendor\`; the message is right for an installed copy and misleading in a development folder.
- [ ] T161 [US1] Guard v2 (ADR-0006 P3; `docs/research/2026-10-31-solutions.md` section 4): persistent filters tied to the service, the five yes/no lab checks
  > **P3 approved 2026-11-04 by the owner's delegation (ADR-0006 §5a, seven conditions).** Done: `dnet_core::guard` (pure; the rule set as data: `Guard::build`, `filters`, `leaks`, `verify`; 34 tests, and
  > nine deliberate breaks each made at least one fail; "local" is the built-in bypass list, one source for the guard and the rules). An independent review found that the first version's
  > `leaks` could not see a well-formed permit nobody asked for, and accepted network-share paths and broad accounts: fixed by `verify` (the plan's list against the installed one, both ways),
  > strict paths and accounts, and a `Guard` only a passing plan can make. **Residual, written in the module:** the IPv4 address request and IPv6 neighbour discovery are not scoped by
  > address; the lab measures them. **Not built:** the applier (the
  > Windows firewall engine, a provider tied to the service, `guard-release`, the removal paths) and the five lab checks (S4), which need a virtual machine with a snapshot, not the
  > owner's computer. The task stays open: the site's "not built yet" depends on it (`site_facts.rs`).
- [~] T162 [US1] Power and session awareness (solutions section 6): power events, user-presence setting, tick-gap detector
  > **Tick-gap detector done 2026-11-01** (the ground truth in solutions section 6), test first, mutation-checked, not committed. `dnet_core::tick_gap::TickGap` is pure: it is given a
  > monotonic and a wall reading each tick and reports a gap when either shows more than period + 5 s (the wall clock because the monotonic clock may not count
  > sleep; a clock set backward is never a gap). `dnetd::netwatch::report_gaps` ticks every second and, on a gap, sends the same change the system's network
  > notifications send, so the loop reads the paths and measures them again; `WindowsWatch::start` runs it. 10 tests for the detector, 4 for the task (paused clock),
  > and breaking either clock check or the signal made them fail. **Power messages done (same day, not committed):** the service now accepts the power-event control (`svc.rs`); a resume message calls `resume::announce()`, and each
  > `WindowsWatch` listens (`resume::subscribe()`) and sends the same change, so either signal makes the loop look again; 5 tests on the hub (a wake, none without an announcement, a burst is one wake-up,
  > a late subscriber hears nothing old, every subscriber hears it), breaking the announcement failed 3. The handler itself needs the real service and is not run here. **Open:** the session-change control and the
  > user-presence setting for Modern Standby (not accepted: the tick gap covers it), and marking carrier health stale.
  > **Resume nudge done (same day, not committed):** on a resume (either signal's power-message path) a session connection also sends small connection attempts to its origin through the session every 500 ms for up to 30 s,
  > until one is answered, so a carrier that died in the sleep is made again at once (`resume::forward_resumes`, 5 more tests; removing the nudge failed 2). The tick-gap path re-reads the paths only (it has no session
  > to nudge by itself; a nudge there would repeat on a false alarm). The real test is a suspend and resume, the owner's, with the guard on and off (not run).
- [~] T163 [US1] Run the cores with a job object, then bisect child-process and dynamic-code restrictions (solutions section 5)
  > **Job object done 2026-11-01**, test first, mutation-checked (`dnet-supervisor/src/job.rs`): every spawned core is put in one job with
  > kill-on-close, so the system ends both cores when the service's process ends however it ends (a crash, a kill); before this only a dropped handle
  > ended a core. Best effort: a core that cannot be put in the job still runs, supervised as before, and the failure is logged. Five tests, including the
  > control (a process outside the job is untouched) and that the real `spawn` puts a core in the service's job. **Open:** the two restrictions to bisect
  > (forbid the core creating child processes; forbid dynamic code), which need three elevated runs against a real tunnel (solutions section 5).
- [ ] T164 [US1] Re-run `testing/spike-carrier` against the real build and over the Docker hostile-network lab with delay, loss and UDP blocked (solutions section 9, step 2)

> Proposed 2026-10-31 from the owner's question about adapting to every kind of network
> (`docs/research/2026-10-31-language-and-adaptive-paths.md`). None started; each needs the owner's go-ahead on that document's section 4.

- [~] T165 [US1] Read and show the link's facts (Wi-Fi generation, band, rate, signal; metered or roaming flag) as component evidence — `dnet-netstate`, after the Registry
  > **Reader done 2026-11-01** (`dnet_netstate::wifi::connected_links`, not committed): generation (Wi-Fi 4 to 7, from the system's PHY type; an unknown number is never guessed into one),
  > the negotiated receive and transmit rates, and the signal quality, from the same query that names the network; 5 tests, including one that checks the PHY numbers against the
  > system's own constants. The `wifi_names` example prints them. **On the owner's machine the query returned nothing** from a normal (non-admin) session (the Windows 11 location-access
  > refusal described in the module; not worked around), so it is untested on live data; run it from the service (SYSTEM) or with location access on to see. **Open:** the band (needs the channel,
  > a second query), the metered and roaming flags, and showing them (waits for the Registry).
- [ ] T166 [US1] IPv6-only networks: a path rule that accepts them (today `paths.rs` needs an IPv4 default route) and NAT64 discovery or an IPv6 server address; lab first
- [ ] T167 [US1] Metered-aware and network-aware policy (no hot standby or full race on metered links, measured keepalive on shared-address mobile, TCP carrier first when UDP is blocked); each row behind a measurement
- [ ] T168 [US1] Spike: do the Windows UDP offloads (segmentation since Windows 10 2004, receive coalescing since Windows 11 24H2) help the QUIC path; the pinned QUIC library has offload code for Linux and macOS only
- [x] T171 [US1] Settle the program's identity before the first release (ADR-0009, accepted): which identifiers are permanent, the application identifier, and one place per layer for the display name
  > Done 2026-11-03 from the owner's question about an application id (an Electron application on their laptop had installed under a default id). The application identifier is now `io.github.nikhlgoel.dnet-engine`
  > (no domain; the project lives on GitHub), set in `apps/dnet-tray/src-tauri/tauri.conf.json`; the built shell contains it and not the old `dev.dnet.engine.tray`. The engine's names (service `DNetEngine`, the pipe, the data folder,
  > the executables, the winget id) stay for good; only what people read changes when the program gets its own name. **Open (cheap, not blocking):** one place per layer for the display name (the window's words are mostly in
  > `messages.ts`); the installer built and installed once to see the identifier and product name at work (T114/T115).
- [x] T172 [US1] A one-page website on GitHub Pages: what it is, what it does and does not do, its status (`site/`, `.github/workflows/pages.yml`)
  > Done 2026-11-03 as far as it can be shown before it is published. Static, no scripts, nothing loaded from another site; it uses the app's own design tokens (the workflow copies `docs/design/tokens.css` in). Checked in the browser pane
  > at desktop and phone width and in both themes (no horizontal overflow, no console messages, anchors resolve), and by three negative-control checks (a script, an external load and a forbidden third-party name are each refused).
  > **Upgraded again 2026-11-03 after a second review** (still not good enough): the first screen gains a picture of what the product does, a connection that stays up while it moves from one network to the next as each is blocked or turns lossy (inline SVG, CSS only, one sixteen-second
  > loop, one still frame that still says it under reduced motion), a one-line summary under the big statement, "who can see what" as cards with arrows and the network's hop marked, and larger folded rows. Checked at desktop and phone width, dark and light.
  > **Redesigned the same day after the owner's review** of the first version (a flat bar of buttons and a grid of equal cards had no hierarchy): the page now reads in the order of importance. The name and a spec strip (licence, platform, server, status),
  > then one dominant inverted panel, "It is not a bypass tool", whose five concrete statements are what the tool is, then a picture of who can see what along the path; everything else is folded to one line each (native `details`, so it works by click and keyboard,
  > no script). Rechecked in the browser pane: desktop and phone, dark and light, rows open by click and by Tab and Enter, focus ring visible, no overflow. `lint-branding` now also scans `site/`. **Needs the owner (one time):** Settings > Pages > Source "GitHub Actions", and the site is built from `master` only, so it goes live when `wip` is merged there. Address once live: `https://nikhlgoel.github.io/dnet-engine/`.
- [~] T173 [US1] Make the repository's own CI run for the first time on the branch, and fix what it shows (found 2026-11-03: the last master runs, from October on, were red and nobody had read them)
  > First run read on PR #1 (`gh run view --log-failed`). Two real failures, both explained, neither from the latest work. **(1)** The window job runs on a Windows runner, where checkout turns files into CRLF; `tests/design.test.ts` searches
  > `tokens.css` for a newline, so the whole suite failed at import. Reproduced locally by converting the file to CRLF (same error), fixed by `* text=auto eol=lf` in `.gitattributes` (staging with renormalize changes only that file). **(2)** A Rust test
  > required the owner of a directory to print as `O:S-1-...`; the runner's built-in Administrator account prints as `O:LA`, an account and not a group, so the helper was right and the assertion too strict. Fixed test first (a pure classifier with five
  > cases, red then green, one mutation caught). With both fixed, the jobs that had been skipped behind them ran for the first time and passed (window shell build and clippy, coverage at or above 80%). **Result, run on commit 92daab3: every job green** except
  > the simulated-network job, which the workflow keeps disabled on purpose. PR #1 was merged into `master` the same day (merge commit), which also starts the website's workflow. The "Node.js 20 is deprecated" notice on the checkout action is a warning to act on
  > before the runners force the change (not done).
  > **Node 20 notice acted on, 2026-11-04.** The runner warns that `actions/checkout@v4`, `actions/setup-node@v4` and `pnpm/action-setup@v4` target Node 20 and are forced onto 24. Read `runs.using` in each
  > action's own `action.yml` at its tag (not from memory): checkout v5 to v7, setup-node v5 to v7, pnpm/action-setup v5 and v6, setup-go v6 and v7, upload-artifact v6 and v7, download-artifact v7 and v8, deploy-pages v5,
  > configure-pages v6 are `node24`; v4 of pnpm/action-setup, v5 of setup-go, v4 of deploy-pages and v5 of configure-pages are `node20`; upload-pages-artifact v5 and attest-build-provenance v4 are composites that call
  > upload-artifact v7 and `actions/attest` v4.2.1 (node24); rust-cache v2 is already node24; dtolnay/rust-toolchain and taiki-e/install-action are composites. Moved to: checkout v6, setup-node v6, pnpm/action-setup v5,
  > setup-go v6, upload-artifact v7, download-artifact v8, attest-build-provenance v4, deploy-pages v5, configure-pages v6, upload-pages-artifact v5. **Not yet confirmed:** the PR's CI run on this change (it exercises
  > `ci.yml` and `pages.yml` only; `release.yml` runs on a tag, so its artifact and attestation steps are unexercised until a release).
- [~] T174 [US1] The website's footer and sections, then shrink the known limits (the owner's request, 2026-11-04)
  > Asked after the second website upgrade went live (`https://nikhlgoel.github.io/dnet-engine/`, source in `site/`). **(1) The footer, "Known limits", "Where it stands" and the "what it does" rows still look plain.** Upgrade them: the limits as a short list that says, for each, why it
  > exists, what is being done about it and its state; the status as three visible groups with counts before any detail; a real footer (the project, the documents, the licence, the name note) instead of a line of links. **(2) Make the limits themselves smaller where it can be done,**
  > not only describe them, and find what else the framework needs. The site's own limits and what stands behind each: the kill switch is not a guarantee = T161 Guard v2 (waits on the owner's approval of ADR-0006 P3, decision F2, and the lab checks S4; design in ADR-0008 section 3.5
  > and `docs/research/2026-10-31-solutions.md` section 4); rules by program are best-effort = `dnet-etw` is built and tested but `dnetd` does not call it (ADR-0001); switching networks drops open connections = no profile is Tier 1 until HV-07 is recorded
  > (`dnet_core::tier::recorded_survival`), and the session's carrier switch is proven on loopback only (T157, T169, `session_e2e.rs`).
  > **A read-only audit was started 2026-11-04 and produced nothing:** five readers (one per limit, one for the rest of the framework, one fact-checking the site against the code) all stopped at the account's session limit before reading. Run it again, or do it by hand: for each limit, what exists
  > (file and line), the smallest slice that can be built and verified test first without admin rights, a live network or the owner, and what needs them. **Fact-check the site before adding to it:** for example "Installer: not built" against `installer/` and the draft-release workflow, and "Windows 10 or later"
  > against the winget manifest. **State when this was written:** `wip` and `master` are the same commit, CI is green on it (every job except the simulated-network job, which is disabled), the site is live, T170 steps 2 to 4 are done (see its note), T171 to T173 are done.
  > Rules that apply: nothing touches a live network; fail closed; a security review before any commit on routing, DNS, the undo path or the IPC boundary; one commit per finished task and one pull request per batch, squash-merged.
  > **Progress 2026-11-04.** (1) Fact-check done by test (`site_facts.rs`, T175). (2) Footer, limits and status upgraded: the limits are three cards, each saying why, what is being done and where it stands, with a state tag; the status is three groups
  > with counts (3 works, 7 built and tested, 5 not yet; the counts are tested against the rows); a four-column footer (the project, the documents, licence and notices, the name) with the date checked. Looked at in the browser at 1200 px dark and 390 px light:
  > no overflow, no console message. (3) Audit of the three limits, by hand: **limit 3** reduced as far as it can be without the lab (T175). **Limit 2, rules by program:** `dnet-etw` is built and tested; `dnetd` does not call it, and
  > `configure.rs` refuses a program rule on purpose. Two findings: the core's own `process_path` matching is already emitted by `primary.rs:416`, but the generated `route` has no `find_process` option, and whether the pinned core matches a
  > program on Windows with or without it is **one yes/no lab check** (not answerable on Linux: the core accepts both configurations); and which mechanism wins (ETW after the fact, or the core's own matching) is an ADR-0001 question for the owner,
  > not a slice. **Limit 1, kill switch:** T161 waits on ADR-0006 P3 and five lab checks; a pure model of the filter set could be written and property-tested here (every posture has a permit for the endpoint, loopback and the service; no posture permits
  > general outbound while the tunnel is down) but building it before P3 is approved would decide the design for the owner, so it is proposed, not built.
- [x] T175 [US1] HV-07 results as data: `evidence/survival.json`, read by `dnet-core::survival_evidence`; the site's claims tied to the code (`xtask/src/site_facts.rs`) — part of T174
  > **Done 2026-11-04, no admin rights, live network or owner needed.** Before: recording that a method keeps an open transfer alive meant editing `recorded_survival` by hand, with the evidence elsewhere and nothing
  > tying the claim to the core measured. Now a record (method, the 40-digit commit of the core measured, each run: same connection, bytes expected and received, moved without a disconnect) is compiled in, and the tier follows by rules that fail closed:
  > **Survived** needs at least three runs at the *pinned* commit, every one clean; **one failing run is Broke**; **a record for another commit is ignored**, so bumping a core pin retires every claim by itself (a test in `xtask` compares the commits
  > in `dnet-core` with the ones the cores are built from, so they cannot drift); anything unreadable, unknown, duplicated or out of bounds is `NotMeasured`, nothing it said is echoed, and a test refuses a shipped file that does not parse.
  > 14 tests; mutation run: 49 mutants, first run 5 missed (exact limits, each single fault in a date, what counts as a duplicate), all killed; the one left (`shipped()` replaced by an empty list) is **equivalent while the shipped file is empty** and will stop
  > being so the day a record is added. Reduces the limit "switching networks can drop open connections" only in how the evidence is kept: **no method is Tier 1 until the lab runs** (`docs/owner-gates.md`, T085, now says to add a record, not to edit code).
  > Also: `site_facts.rs`, 10 tests that fail when a sentence on the website stops being true: the platform against the installer manifest, the installer claim against what is in `installer/`, "rules by program" against whether `dnetd` calls `dnet_etw`,
  > "no method measured" against the evidence file, every task and decision the page names, every link into the repository, the counts in the three status groups against their rows, unique ids and resolving anchors, and no script or external load.
  > It found three false statements on the live page, now corrected: "Windows 10 or later" (the installer accepts 1809 and later, x64 only), "Installer: Not built" (it is written, never run), and the server-setup row (it described the plan the owner replaced).
  > **Security review (self, 2026-11-04; no routing, DNS, undo path or IPC code is touched):** the tier decides whether the window warns before connecting (FR-016b), so the risk is over-claiming. Every default is the cautious one (no evidence, too few runs, a stale commit,
  > a parse error all give Tier 2) and the only path to Tier 1 is data a person must add and a test must be changed to state. The pinned commits live in two places on purpose and a test compares them.
- [~] T170 [US1] The Registry and the live map (ADR-0008 §3.6, P1): every part as a component with a state, a reason, the time it changed and its evidence; `GetComponents` (additive); the window's map; the two benign `closed pipe` lines classified (T157)
  > **Model done 2026-11-03** (`dnet_core::registry`, pure, 15 tests; mutations each caught; the roll-up order was decided the same day: Off < Ok < Starting < Unknown < Degraded < Blocked < Failed, pinned by a table test, the owner may overrule): kinds and states as in §3.6, `changed_at` moves only when the state does,
  > a full Registry refuses a new part instead of dropping an old one, snapshots are ordered. **Step 2 built 2026-11-03** (`crates/dnetd/src/components.rs`, pure, test first: 19 tests written and seen failing, then green; four mutations each caught):
  > `readings(StateSnapshot, PathsSnapshot)` gives one reading per part (each network, the connection, the endpoint carrying it, the routing decision, a sign-in page in the way) and `apply` brings a `Registry` in line, returning only what changed and removing
  > parts that are gone. Nothing sensitive reaches a reading (no endpoint label, no network name; a test pins it). The routing reading says it is the service's decision, not enforced by the system. A network nobody has measured is `Unknown`, never fine;
  > a part with no facts (the transport processes, the adapter, name-server handling, the guard, each carrier) is absent, not fabricated. Not wired: the module is `allow(dead_code)` until `GetComponents` calls it.
  > **Security review of step 3 done 2026-11-03** (an independent reviewer, read-only, on the IPC boundary): no high or medium finding, safe to commit. Its low and info findings were fixed the same day, test first: the summary is computed from the parts
  > written and a decoder refuses a mismatch (a hostile service could say Ok over a Failed part); the encoder leaves out a part a decoder would refuse; a test feeds the free text of `ConfigurationInvalid` and `CoreFailedPersistently` through the mapper
  > and asserts it never reaches a reading; the hostile-character list is widened (line and paragraph separators, the soft hyphen, the invisible operators, the tag characters) in both `netview` and `dnetctl`, which now agree.
  > Left as noted, by choice: a warning is logged for every part dropped from a full Registry on each request (a client cannot cause a full Registry; only over 128 real interfaces could); and a read records what it saw, so nothing security-relevant may ever consume the Tracker.
  > **Step 3 built 2026-11-03** (contract `IPC-28`, `ipc-protocol.md`): `Request::GetComponents` (additive, read-only), `dnet_ipc::componentview` (encode, and a strict decoder: unknown kind or state, duplicates, ranges, bounds and hostile text; 10 tests,
  > five mutations each caught), `dnetd::components::Tracker` (one Registry and the clock; answers the request; 4 more tests), the handler in `service_impl.rs` (2 tests), and `dnetctl components` (4 tests, `--json`, an old service told apart from an empty answer).
  > The renderer shows a reason whole. **Step 4 done 2026-11-03 (test first):** the service records readings itself once a second (`keep_components_current`, started where both the console and the Windows service are built, holding the service weakly so it ends with it),
  > so a part's age is the true moment to within a second and not "when someone first asked"; three tests (age counts from the true moment, the control without the task, the task ends with the service), two mutations caught. **Open, in order:** (1) the transport
  > processes, the adapter and DNS where the service has the facts; (2) a golden file for the window and `dnet-view` (the window's map); (3) the log classifier for the two benign lines per switch. Unblocks T165's display.
  > **Step 5 built 2026-11-04 (test first): the window's map.** `dnet-view` gains `Bridge::components()` (read-only `GetComponents`, decoded by the strict decoder of `dnet-ipc`; an older service is `supported: false` and shown as that, never as "no parts" or
  > "fine"; any other refusal or an unreadable answer is an error that repeats nothing; a reason is passed whole and clean; a measurement not taken is absent, not zero), a golden file `components.json` that the window's own parser reads too, the `list_components`
  > command (build list, capability, permission file), `parseComponents` (strict: unknown kind or state, a negative age, a loss over 100%, more than 128 parts, a service that cannot list parts but lists some), the mock, and a **Parts of the system** list at the top of the
  > Activity view: state in words, how long, why, and latency, loss and restarts only when measured; read every 5 s while the view is open and not at all otherwise (ADR-0007 R2). 5 Rust tests, 1 golden, 3 web contract tests, 3 component tests (axe clean). The Windows shell lints clean. The website's row now says the window shows the map, and an eleventh fact test in `site_facts.rs` ties that sentence to whether the Activity view asks for it. **Security review (self; IPC client side):** nothing new crosses the pipe (the request and reply are step 3's, already reviewed); the only parser of the reply is step 3's strict decoder; the window gains one read-only command; nothing sensitive is in a reading (step 2's guarantee).
  > **Finding, said plainly:** open item (3), classifying the two benign `closed pipe` lines, **has nothing to classify today**: the supervisor sends core output to the log at debug level and nothing turns a log line into a part's state, so no false alarm can occur. The classifier belongs
  > with whatever first reads core logs as evidence; building it now would be code for a path that does not exist.
  > **Open item (1), the cores in the live map: done 2026-11-04, test first, not run against the installed service.** Found while reading both files: nothing in the service watches a running core for exit
  > (`RestartPolicy` is used only by its own tests, `has_exited` only by the runtime, and `CoreFailedPersistently` is raised only when a core fails to *start*), so a core that dies mid-session was invisible to the map. Built: `CoreHealth`
  > (`Unknown`, `Running`, `Exited{code}`) and `CoreRuntime::core_health` (default `Unknown`, so a runtime that cannot tell is left out of the map, never shown as fine); `WindowsCoreRuntime` answers from a non-blocking `try_wait` and keeps an
  > ended core in its table so the next reading still says so; `Effects::core_health` (default empty) and a poller in `orchestrator::spawn` (once a second, holds the effects through `Weak`, so a retired orchestrator is freed) publish it into
  > `Telemetry`; `Tunnels::core_health` uses `try_lock`, so while a start or stop holds the tunnel it says nothing rather than be stale (found by review); the map reports `CoreProcess` `primary` and `amneziawg`: `Ok` "is running",
  > `Failed` "stopped unexpectedly (exit code N)" (a crash code is written as 0xC0000005), fixed text, no path, id, port or name of the primary core's vendor. Tests: 10 in `components`, 3 real-process tests in `windows_runtime` (cmd.exe, exit code 3 read back),
  > 3 in `tunnel`, 2 in `orchestrator`; mutations caught. Review: `ecc:rust-reviewer` (found a branding-lint failure in a test literal, the stale reading during start or stop, the signed exit code, a timing-sensitive test; all fixed) and
  > `ecc:security-reviewer` (no findings: the only variable data in a reading is an exit code; nothing can start, stop or signal a core or change routing, DNS or undo; two readings at most; the pipe's trust model is unchanged; one caution: a part is absent while a connect or disconnect is under way, so a client must not read absent as fine). **Still open:** nothing acts on an exited core (no restart, no reconnect): the map now tells the truth, and the response (reconnect through the existing failure path, fail closed) needs a decision;
  > the real window and `dnetctl components` have not shown a core yet (needs the dev service restarted with the cores beside it).
  > **Finding, 2026-11-04, not built because it needs a design choice:** nothing acts on a transport process that has exited (read in the code, not shown against a live crash). It is noticed only through the
  > live checks (every 5 s; a block after 3 failures in a row, so about 15 s), and the engine then treats it as a block: the profile takes the retry wait of `reprobe.rs` (60 s, up to 15 min), and if no other
  > profile is left the connection fails with `AllProfilesBlocked`. Nothing leaks meanwhile (with no core, nothing carries traffic), so this is recovery speed and wording, not safety. The question: a crash
  > is not censorship, so should a core that exits be restarted once on the same endpoint before any profile is called blocked, and after how many exits in how long is it blocked? `CoreRuntime::core_health`
  > already gives the signal (`Exited { code }`); the missing parts are an engine input for it (not a `LiveCheck` variant, which would mark the profile blocked) and that policy, test first, in `dnet-core`.
- [~] T176 [US1] The server's firewall: what the setup script opens, what a device that is let in may and may not reach, and a check of it against real iptables (`docs/security/server-firewall.md`)
  > **Built 2026-11-05.** Read in the script before the change: exactly three ports were opened (kept), but the AmneziaWG exit was forwarded with no filter at all, so a device with the key could reach the cloud's private network
  > and its instance metadata, send mail, and reach the server's own ssh from inside the tunnel; and on an image whose own rules reject forwarded traffic the exit would not forward at all (an imitation of such an image, not a real one).
  > Now `dnet-net-up` adds, after the three ports and the masquerade, one rule at a time (an unsupported rule is a note, never a reason the server does not start, except a refusal, which falls back to a DROP; the firewall's lock is waited
  > for; running it twice changes nothing; a changed script restarts the firewall unit on a running server): for traffic from the tunnel, refusals of private, loopback, link-local and reserved ranges (`EXIT_DENIED_V4/V6`, one list, tested
  > to contain everything the client calls local, the cloud metadata addresses, and no public address), port 25 and every protocol but TCP, UDP and ICMP, then a cap on new connections (30 a second to one address, 60 a second overall after a
  > burst of 300; the drop exists only if its accept was made); for what the tunnel may ask of the server itself, only the measurement origin (at most 64 connections), replies and a ping; and for the account the carriers run as, replies,
  > its own session port and origin, and only the resolvers of `/etc/resolv.conf` first, then the server's own addresses, the private ranges, port 25 and the same caps, IPv4 and IPv6. The session's own UDP port is dropped from outside.
  > The origin now runs as the unprivileged account; the AmneziaWG unit has the lighter sandbox settings. The script **warns**, on the error stream, when ssh takes passwords. The wizard's port step says to keep the ssh rule, open nothing
  > else and leave IPv6 off.
  > **Independent review (2026-11-05)** of the first version found, by reading, nine real problems that the first container check had not tried: the exit could reach the server's own addresses, port 53 bypassed the caps and the refusals,
  > IPv6 had no cap, a stranger hammering the REALITY door could drain the shared cap, IP-in-IP and GRE were forwarded, a refusal the kernel could not install failed open, replies to clients on private addresses were refused, rule
  > changes never reached a running server, and the session's port was not closed to the network. All fixed, test first, and each is now a check in the container. Not taken: swapping chains atomically (the window exists only for a
  > by-hand run with tunnels up), and sandboxing the AmneziaWG program further (needs a real systemd to try).
  > **A second review of the fixes** rated five of the nine closed and found more, all fixed test first: with no iptables installed nothing was made and nothing said so (now installed with the other tools, and the three jumps
  > that carry the protection are checked afterwards: the server does not start without them, IPv6 only if the machine has an IPv6 route); a changed unit file waited for the next reboot (units compared before and after, the services
  > restarted, and every service waited for before the report); the lock wait did not cover the three doors (moved up); the tunnel's forwarding jump now names the interface, a spoofed tunnel-subnet source from elsewhere is
  > dropped; one stranger could still starve the exit through the REALITY door (5 a second per address, burst 20); the stub resolver `127.0.0.53` is always allowed; a REALITY door on the origin's port is refused. Not taken:
  > `addrtype BROADCAST` (the reserved range already covers the limited broadcast).
  > **Found on the way, not a firewall matter:** under `umask 077` the script made `/opt/dnet` and `/opt/dnet/bin` root-only, so the core (which runs as `dnet`) could not execute its program and, with `systemctl enable --now` under
  > `set -e`, the setup would have stopped before printing its report on a fresh server. Fixed (`chmod 755`), with a test; seen only by reading, because no real server run (T098) has happened.
  > **Tests:** 19 on the script text (order, conditionality, the three ports exactly three, the ranges, the units, the directories) and `testing/server-firewall` (entry 8.7 in `LOCAL-COMMANDS.md`): the rendered script in a throwaway container
  > with real iptables and network namespaces, 64 checks on the nftables-backed iptables and 56 on the older kind (`-Mode legacy`; that kernel has no IPv6 filtering for it, so IPv6 is skipped and said to be). The control first (an
  > open firewall lets a device reach private hosts, mail, ssh, a GRE tunnel gets through, the carriers' account reaches the server's own address and port 53 anywhere, floods all get through), then an image-style firewall plus
  > the script, twice, then three kernels that cannot do everything (no owner match: refuses to start; no REJECT: refusals become drops; no limit modules: no caps but nothing blocked).
  > **Not shown, so not claimed:** a real Oracle server or real systemd (the container's kernel is Docker Desktop's, the image's rules were imitated, the units are checked as text); how a scanner sees the three doors; the core's own
  > `ip_is_private` coverage; the REALITY cover site; a provider's own rules.
- [~] T177 [US1] Known vulnerabilities in everything we depend on and ship: audit, fix, and keep watching (`docs/security/dependencies-and-advisories.md`, `.github/workflows/advisories.yml`)
  > **First pass 2026-11-05.** `cargo audit` (workspace, and the window shell's own lock file), `pnpm audit`, the published advisories and the commit history after each pin of the two bundled programs, Tauri, NSIS, Wintun, WebView2 and the Go
  > toolchain. **Fixed:** the primary core was 4 releases behind (v1.14.0, now v1.14.4: 174 commits, including panics and crashes a broken or hostile peer could trigger, spinning read loops, HTTP/2 data races, Hysteria port hopping to another
  > address, and fixes to the selector and WireGuard session endpoint our carrier switching relies on); `tokio` 1.53.1 to 1.53.3 (RUSTSEC-2026-0386; we never used the affected API); `undici` held at the fixed version in the test tools. **Added:** a
  > weekly advisory run (Rust, both lock files; JavaScript; and a warning when a pinned program falls behind its upstream). **Accepted, each with its reason:** `deepmerge` (low, build tool only, no patch exists), `glib` and `proc-macro-error`
  > warnings in Tauri's Linux and compile-time parts, NSIS 3.11 (CVE-2026-42171 needs an installer run as SYSTEM).
  > **The core upgrade, verified:** the build pin and the code pin agree (a test compares them; the recorded survival evidence is empty, so none referred to the old commit); `fetch-vendor` rebuilt both cores from the pinned commits, the driver-loader
  > patch applied (nothing under `internal/wintun` differs between the two `sing-tun` versions, 24 commits compared) and its own test passed against the real Wintun DLL; `verify-vendor` OK (no embedded DLL, signature valid); the real core's own
  > `check` accepted every configuration we generate (6 tests); 999 tests in the four affected crates pass; and the Docker harness, rebuilt from the new commit, matched all six hostile-network scenarios (baseline, UDP dropped, either port dropped,
  > both dropped, 150 kbit ceiling), the two negative controls included. **Checked on this PC:** the service path is quoted, the install folder is not writable by ordinary users, the data folder refuses them even its permissions, the window's
  > Content Security Policy and 28-command capability list are minimal. **Not shown:** that no unknown bug exists (an audit finds only reported ones); the WebView2 runtime's version; advisories published after today (the weekly run).
- [~] T178 [US1] Edge cases and hostile input, measured not guessed: real coverage, the tests that depend on the machine made independent of it, and combination tests for the connection engine
  > **Coverage measured 2026-11-05** (`cargo llvm-cov`): the service crate 84.5% of lines, the control-channel crate 94.3%, the rest mostly 85% and up. What is genuinely thin is the code that only runs elevated against Windows (`effects.rs`, `install.rs`,
  > `winwatch.rs`, `win_route.rs`), covered today by the project's live gates and a real install (see T114), which are owner and virtual-machine work. **Found and fixed:** the three control-pipe tests (among them `t039`, an unprivileged client cannot alter
  > routing) used the real pipe name and so failed, and did not exercise the identity check, whenever the service was installed on the same computer; the server functions now take a pipe name (the real entry points pass the real one, unchanged: security
  > review done, no findings), each test uses a name of its own, and the identity-checking code went from 16% to 87% covered. The end-to-end carrier-switching test picked a port that Windows had reserved for UDP (Hyper-V and Docker reserve moving
  > ranges) and failed at random; it now proves a port is free for TCP and UDP on both loopback addresses. With both, the whole workspace passes with the service installed and running (2,374 tests, none failing).
  > **New tests:** the profile feed's address rules against a real URL parser over 5,000+ hostile variations of the real addresses (whatever the rules accept, the parser must read as HTTPS, an allowed host, no credentials, no port), with a negative control
  > (a prefix check and a substring check are both caught); and `engine_sequences`: 4,000 random sequences of 60 events each (240,000) against the connection engine with different profiles and endpoints, asserting no panic, never two tunnels, the phase and
  > the running tunnel always agreeing (so a disconnect or a failure never leaves a tunnel behind), a disconnect always ending idle, and every failure having words for the person. A first run showed the generator reached the recovering phase only 60 times in
  > 240,000 (it bounced off hostile environments), so the test now requires every phase to be visited at least 2,000 times and the generator mixes the natural next move with chaos; breaking the engine on purpose (a disconnect that forgets to stop the tunnel)
  > is caught at once, with the sequence that does it. **Reviewed and found sound, no change:** the portal probe (30 tests already, including arbitrary bytes), the installer's command-line grammar, the approver's id validation (no option or shell text
  > reaches a command line), the trusted-file reader (security read from the same handle as the contents, so no check-then-open race), the service install (quoted path, folders checked live on this PC).
  > **Not done, said plainly:** the elevated Windows code above; a real-network test of the profile feed fetch (it needs a TLS server); the window shell's Rust tests were not measured; fuzzing is deterministic random, not coverage-guided.
- [~] T179 [US1] A hidden-bug hunt by method: harder property tests, repeated and loaded runs, a panic and `unsafe` audit, and mutation testing of the security-critical code
  > **2026-11-05.** *Property tests at 20 times the case count* (every `with_cases(N)` temporarily `N * 20`, 33 test binaries, 1,514 tests): none failed, no regression file written; the change was reverted. *Repeated runs* (the service,
  > control-channel, supervisor, network and config crates, three normal and four with 96 test threads): one failure in seven, `session_e2e` (the carrier-switching test). Reproduced: it passes 12 of 12 with 6 busy loops on 16 cores and fails every time
  > with 32 (a 4 s silence bound, a switch timeout, the product giving up after 16 attempts, the "refused at once" probe reading a slow close as silence). **Not changed:** this is a test that measures wall-clock time against real transport programs on a
  > starved machine; I found no evidence of a product fault, and loosening a security assertion on a guess would hide one. It is a known sensitivity: run it on its own if a loaded machine fails it. The original failure at line 783 was not reproduced with its message, so which of the outcomes it saw is unverified.
  > **Found and fixed, test first (each test failed before the fix, for the stated reason):** (1) `UndoRegistry` holds its lock across the caller's operating-system call, so a panic there poisoned it and every later `outstanding`, `undo` and `replay`
  > panicked: the code that puts the network back stopped working in the live process. It now takes over a poisoned lock (safe: the record is written before the mutation, the in-memory journal changes only after a successful save, reversal is idempotent).
  > (2) the same in `WindowsRouteInstaller`'s ownership list. (3) `apply_protected_dacl` ignored whether the descriptor had a DACL: a descriptor with none is a NULL DACL, which Windows reads as everyone-full-access; no current caller can reach it (all pass fixed
  > constants) but the function is `pub` and the failure is silent, so it now refuses. **Reviewed, no change:** every other production panic site is on a constant or a checked slice; `unsafe` in the control channel and the file-permission code (aligned buffers,
  > revert-or-abort of impersonation, frees on every path); the window shell (strict content policy, 28-command capability list, the approver resolved beside `current_exe`, not the working directory or PATH); `dnetctl`'s file reads are length-capped.
  > **Mutation testing** (`cargo mutants`, in place; targets: control-channel authorization and framing, the feed's keys, state and envelope, the window's text cleaner; 171 mutants): **19 survived** the existing tests, all boundaries a test never tried. Fixed by tests
  > on both sides of each edge: the exact frame limit (decode and encode), the envelope size cap, 0 / 1 / 8 / 9 signatures, 0 / 1 / 8 / 9 signing keys, the signing threshold, issued-ahead and expiry at exactly the clock skew, a feed's 30-day and a keys document's 366-day maximum lifetime, and
  > the six code points the window's text cleaner could lose without notice (U+2028, U+2029, U+FEFF, U+061C, U+200E, U+200F); that cleaner is now tested over every Unicode code point. Re-run: window text 30 of 30 caught, control channel 0 survivors (7 timeouts: a stubbed `encode` makes a test hang
  > instead of fail, which counts as caught), feed 1 survivor, then caught by the lifetime test. **Independent security review of the diff:** no defect in the three changes (every unwind point under the lock checked); it raised two narrow gaps that were already there, **found, not fixed**
  > (privileged persistence code, to be changed test first and reviewed): (a) in `UndoRegistry::apply`, if a mutation ends `AlreadyPresent` or fails and the write that withdraws its record also fails, the record is dropped from memory but stays on disk, and a crash before the next write
  > lets the start-up replay delete a route someone else created; (b) `TrustedFile::write` renames the new journal into place and only then restricts it, so if that last step errors, `apply` returns an error before the mutation runs but the record is already durable (same replay consequence). Fix ideas: keep a
  > tombstone in memory until the withdrawal is written; restrict the temporary file before the rename. Very narrow (a route that already exists, plus a failed disk write, plus a crash). **Not done:** mutation testing of `guard`, the engine, the supervisor and the service crate (hours); the elevated Windows code (owner and virtual-machine work, `docs/owner-gates.md`).

- [x] T180 [US1] The central figure: no outline on hover, and larger
  > **2026-11-05, owner's request.** Hovering the figure drew a one-pixel circle over its edge, which covered part of a figure that shows live state. The outline (a CSS shadow on the invisible hit area) is gone; the hover is now drawn by the figure itself, a soft lift
  > (`easeHover`: the dots about 22% brighter and 15% larger, the whole about 3.5% bigger, eased, and instant under reduced motion), and the pointer stays a hand. The figure's radius went from 34% of the scene's height (at most 96 px) to 40% (at most 120 px, at least 56). Tests first
  > (`tests/scene.test.ts`: the easing never overshoots or leaves 0 to 1 for any input including NaN and infinity; the figure keeps 48 px clear of the network chips and fits the scene at 560 x 300, 960 x 420 and 1400 x 600). Checked in a browser against the mock: no shadow on hover, the dots lift,
  > the beams and chips are unchanged and clear of the figure at 800 x 600. **Known, not new:** at the smallest window (560 x 420) the scene is pinned at 200 px and the stats strip already overlapped its lower part; the larger figure adds about 12 px to that.

- [x] T181 [US1] One script for the owner's elevated Windows checks
  > **2026-11-05, owner's request** ("give me a script with all the commands, save the output so you can check"). `testing/Invoke-OwnerElevatedChecks.ps1`: one UAC prompt, then: a before picture of routes, DNS and adapters; removal of the leftover `harness` development
  > endpoint from the installed service; the elevated-only tests with the service stopped and always started again; the trace-session check; read-only link facts and the service's own view; an after picture compared with the before one. Everything is saved under
  > `.local-logs/owner-elevated/<time>/` with a `SUMMARY.txt`. **Tested here:** syntax, and `-DryRun` (no elevation, no change) end to end against the real installed service, which found the real `harness` endpoint. **Not run:** the elevated part, since the UAC prompt is the owner's to accept.

- [~] T182 [US1] A transport process that exits on its own is started again before a profile is called blocked (closes the T170 finding)
  > **2026-11-05. Decided here, per the owner's delegation** ("make it more stable"): a crash is not censorship, so a transport process that exits while connected is started again, at most **2 times in 5 minutes**; the third exit in that window is judged a
  > block and takes the road a profile that stopped carrying traffic takes (stop first, so the posture stays fail-closed, then try what is left, then `AllProfilesBlocked`). Before, a crash cost about 15 s to notice and then the retry wait of `reprobe.rs` (60 s growing to 15 min), and
  > with no other profile left, a failed connection. **Built, test first:** `dnet-core/src/crash.rs` (the pure budget: 6 tests, both sides of the 300 s edge, a clock that runs backwards, bounded memory); `Input::CoreExited` and `Engine::core_exited` (6 tests: the restart is a stop then a start of the same
  > profile and endpoint, the reason says the exit code and which restart, a crash does not mark the profile blocked, ignored when not connected, the third exit is a block with the profile marked blocked, a new connect resets the budget, and a lost network is reported as that and not restarted); the live-check block tail
  > became `recover_from_block`, shared by both roads; the random-sequence test now includes the new input (240,000 sequences, invariants unchanged); the service's core watcher reports **only the moment a process turns from running to exited** (`newly_exited`, pure, tested) so a reading that lingers after a restart can never cause
  > a second one, and `Msg::CoreExited` takes it to the engine; end to end against the orchestrator's fakes: one exit gives one more start of the same profile and no other profile is tried, and three exits give three starts and a connection that is no longer up. The restart is told to the person through the existing "why" event.
  > **Independent review (`ecc:rust-reviewer`) found three real defects in the first version, each reproduced by a failing test before it was fixed:** (1) HIGH: the service folds an adjacent stop and start into a "live move", and for a session carrier on the same endpoint the live move answers "already on that carrier" without looking at the process, so the restart did nothing and the dead tunnel stayed shown as connected (my first end-to-end test missed it because the fake's live move was off); a crash restart is now never folded, and the test runs with the live move on; (2) MEDIUM: an exit seen while the tunnel was still starting was reported once, ignored (not yet connected) and never seen again; the watcher now forgets what it saw whenever a connection comes up, so what is dead then is news; (3) MEDIUM: the restart budget was per connection, so the profile that took over after one was given up on started with it used up; it is now reset whenever a profile is started afresh. Left as designed: a process that dies slower than three times in five minutes is restarted for ever (each time with a short outage); a give-up does not try another endpoint first, as a failed live check does. **Not shown:** a real crash of a real transport process (needs a live run with a
  > server: kill `primary-core.exe` while connected and watch it come back; `docs/owner-gates.md`); an exit while a tunnel is still being started is left to `StartFailed`, as before.
- [~] T183 [US1] Mutation testing, second round: the kill-switch model, the connection engine, failover, rule matching, and the permission and credential code
  > **2026-11-05.** `cargo mutants` on `guard.rs`, `engine.rs`, `failover.rs`, `rule_eval.rs` (dnet-core) and `trusted_file.rs`, `install_trust.rs`, `credentials.rs` (dnet-config): 172 + 200 + 105 mutants, **82 survived**. Fixed with tests: each of the four block-everything rules and each family's control-port block individually, and look-alikes that must not stand in for them
  > (direction, family, condition, weight); `Filter`'s words; the shortest and malformed full paths; every dangerous file right alone for each role, the SDDL right names against Windows' documented values, CREATOR OWNER in both spellings, the `\\?\UNC` prefix; a planted file refused by name, a non-file path an error and not "nothing"; the credential size edge, flow `none`, the
  > certificate-pin parser, the error text (kind and position only, never content); DNS name limits (253 / 254, label 63 / 64), what one rule covers of another; the failover window's exact edge and the clearing of timers when every path is lost; the exact throughput wording, "replaces X", and the tier lookups (with one profile, where a wrong lookup finds nothing). **Left, said plainly:** `|`→`^` mutants on disjoint
  > **Re-run after the tests: the kill-switch model 111 mutants, 0 survived (was 8); engine, failover and rule matching 7 survived (was 23); permission and credential code 15 (was 51): 82 down to 22, every one of them in the list that follows.** bits (equivalent: same value), two failover lines behind a redundant second check (`stable()` re-checks measurement), `check_dir_owner` and `remove`'s error arm in `trusted_file.rs` (an ordinary user's folder is always refused first, so only an elevated test reaches them; the elevated run of 2026-11-05 does), and `named_profile_failed`'s reason lookup and `direct_fallback`'s `&&` (equivalent for the standard profile set).

- [x] T184 [US1] Nothing personal or assistant-directed in the public repository
  > **2026-11-05, owner's correction.** Earlier sessions had written the owner's passing remarks into public files: the README and the website said the project was made first for its author and friends, and `tasks.md` mentioned a college portfolio. All three are gone. Three internal files left tracking (`docs/session-rules.md`, `docs/handoff/windows-session.md`, `docs/owner-testing-guide.md`: a personal laptop path, a personal address, an assistant hand-off prompt, where the signing password file lives); they are kept in the local, ignored `.agent/removed-from-repo/` and remain in git history. `LOCAL-COMMANDS.md` and the checks script no longer talk to an assistant. A search of every tracked file for personal paths, names, an address and "friends" wording found nothing else; the GitHub handle in repository URLs is the project's public identity. README installer row updated (it has been installed on a real computer).

- [x] T185 [US1] The pages other than Status, redrawn: one column, one pattern, real controls
  > **2026-11-05, owner's request** (Settings and the other pages were generic and unevenly built). Looked at each page in the running window first: Settings was a stack of default radio buttons and checkboxes in full-width boxes with the same "disconnect first" warning repeated inside three of them, the speed fields were misaligned, and "About" floated alone; Servers put everything at the left of one wide card with its actions below; Rules put a tall form above a table of a different width; Activity was bare lines. **Now:** a shared set of building blocks in `app.css` and five layout tokens in `tokens.css` (the column width, a short field, the switch, a status dot): every page sits in one centred column of the same width; a small capitals heading per group; settings as grouped rows, the name and its reason on the left and the control on the right; a real on/off switch (still a checkbox with role switch, so the keyboard, screen readers and forced colours see what they did) and a segmented control for the theme (still radios); the warning said once at the top of a page; Servers with its actions at the top right and one aligned row per server (lamp, name, address, state, buttons); Rules with the add form on one line and an ordered table in a group; Activity as grouped rows with a lamp and a timeline. The lamps follow what the service reported (a server that was not checked has no lamp). No script logic changed; one heading string was added ("Rules in order"). **Verified:** 312 window tests including the accessibility checks, type-check, the size budget (59.7 of 150 KB), the website's copy of the tokens, each page in dark and light and at the narrowest supported width (no horizontal overflow). **Found on the way:** `overflow: hidden` on a grid item made the group's minimum height zero and the page's grid squeezed it and cut its text off; `overflow: clip` fixes that. The guided setup keeps its layout but its comparison now shows a mark per line (the words stay for screen readers) and Close is set apart from moving through the steps. **Not done:** the first-run page and About keep their old layout; a screen reader has not been run over the new controls (T111).

- [x] T186 [US1] Real application icons (they were 64-pixel placeholders)
  > **2026-11-05.** The window, tray and installer used a 233-byte placeholder. The mark is the website's own favicon (a line ending in a green dot, on the app's dark base), rendered at 1024 pixels and turned into the set Windows uses by Tauri's own icon command: a 512-pixel PNG, a six-size `.ico` (16 to 256), and the 32, 128 and 256 pixel sizes, listed in the shell's bundle config. Built the page and the shell with them (the shell embeds the icon at compile time). **Not done:** looked at in the real tray at 16 pixels, where a thin line may need a bolder variant; the installed program's shortcut and the installer's own icon need the next installer build.

- [x] T187 [US1] The community files a public repository needs
  > **2026-11-05.** `SECURITY.md` (private reporting, what is in scope, what to expect), `CONTRIBUTING.md` (what the project is and is not, where to start, what to run before a pull request), `CODE_OF_CONDUCT.md` and a pull request template had been written on 2026-11-04 and left untracked. Read in full for personal or assistant-directed wording: none. Added to the repository. `SECURITY.md` says there is no release yet and that only `master` is supported; that line is to be changed when the first release is tagged.

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
