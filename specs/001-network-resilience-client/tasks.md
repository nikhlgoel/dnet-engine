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
- [x] T005 Implement `cargo xtask fetch-vendor` in `crates/xtask/src/fetch_vendor.rs` — downloads pinned releases of the primary core, `amneziawg-go`, and the **vendor-signed prebuilt Wintun DLL**, verifying each against a recorded SHA-256
- [x] T006 Implement `cargo xtask verify-vendor` in `crates/xtask/src/verify_vendor.rs` — asserts the Authenticode signature on `vendor/wintun/wintun.dll` and **fails the build if any Wintun source file exists anywhere in the tree** (Constitution licence obligation 2, [research.md](./research.md) §R6)
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

- [ ] T010 Create `testing/harness/docker-compose.yml` with the three-container topology (client under test, simulated UTM, mock endpoint) per [contracts/harness.md](./contracts/harness.md) §2
- [ ] T011 [P] Implement conditions H1 (150ms ±50ms, 20% loss) and H9 (bandwidth ceiling) via `tc netem`/`tbf` in `testing/harness/conditions/degrade.sh`
- [ ] T012 [P] Implement conditions H2 (total outbound UDP block) and H4 (selective per-port/per-signature block) in `testing/harness/conditions/block.sh`
- [ ] T013 [P] Implement condition H3 (drop packets matching the standard WireGuard handshake prefix) in `testing/harness/conditions/dpi.sh` — this is what makes the obfuscation claim testable rather than assumed
- [ ] T014 [P] Implement condition H5 (port 53 hijack returning forged answers) in `testing/harness/conditions/dns-hijack.sh`
- [ ] T015 [P] Implement condition H6 (captive portal intercepting until login satisfied) in `testing/harness/conditions/portal.sh`
- [ ] T016 [P] Implement conditions H7 (interface down/up) and H8 (drop traffic to a specific endpoint address) in `testing/harness/conditions/path.sh`
- [ ] T017 Implement `testing/harness/harness.ps1` with `status`, `apply <ID>`, `clear`, and `report` subcommands, applying conditions **at runtime mid-session** without restarting the client (HN-01)
- [ ] T018 Provision the mock endpoint in `testing/harness/endpoint/` running both server-side cores pinned to the same versions the client bundles, plus a plain HTTP origin
- [ ] T019 Implement ground-truth reporting in `testing/harness/report.ps1` — emits packets dropped and by which rule, so a test can distinguish "obfuscation worked" from "the rule never fired" (HN-03)
- [ ] T020 **[GATE] Phase 0 exit**: demonstrate H1–H9 on demand, HN-01…HN-06 hold, and HV-03 runs with a **deliberately unobfuscated control that fails**. A harness where everything passes proves nothing ([contracts/harness.md](./contracts/harness.md) §5)

- [ ] T021 **[GATE] SPIKE-O6**: build a throwaway ETW consumer in `crates/dnet-etw/examples/spike_cost.rs`; measure steady-state CPU cost and the proportion of connections attributed on a machine with a realistic socket population. **If cost breaches SC-014 or coverage is too low to be useful, per-process routing is cut from v1 and only destination rules ship.** Record the decision in `docs/adr/0001-etw-attribution.md` ([research.md](./research.md) §R7)

**Checkpoint**: The harness can tell the difference between working and not working. SPIKE-O6 has decided whether FR-023 is in scope.

---

## Phase 3: Foundational — Domain Core and Privilege Boundary (Plan Phase 2)

**Purpose**: Pure domain types and the authenticated IPC boundary. Everything downstream depends on these.

### Contract tests first (TDD)

- [ ] T022 [P] Write failing contract tests IPC-01…IPC-09 in `crates/dnet-ipc/tests/contract.rs` per [contracts/ipc-protocol.md](./contracts/ipc-protocol.md) §Contract tests
- [ ] T023 [P] Write failing property tests for `EndpointHealth` transitions in `crates/dnet-core/tests/health.rs` — including that `Unreachable` is never terminal ([data-model.md](./data-model.md) §1.1)

### Domain types

- [ ] T024 [P] [US1] Implement `Endpoint`, `EndpointId`, `EndpointAddress`, `EndpointOrigin`, `CredentialRef` in `crates/dnet-core/src/endpoint.rs` — `CredentialRef` exposes **no accessor returning plaintext** ([data-model.md](./data-model.md) §1)
- [ ] T025 [P] [US4] Implement `EndpointHealth` and its state machine in `crates/dnet-core/src/health.rs`
- [ ] T026 [P] [US1] Implement `ConnectionProfile`, `ProfileKind`, `Carrier`, `Viability`, `CoreBinding` in `crates/dnet-core/src/profile.rs`
- [ ] T027 [P] [US3] Implement `FailoverTier` in `crates/dnet-core/src/tier.rs`, with the invariant that tier is set from measurement and is never inferred from `ProfileKind`
- [ ] T028 [P] [US3] Implement `NetworkPath`, `PathKind`, `PathQuality`, `PathRole` in `crates/dnet-core/src/path.rs` — a path with `gateway = None` cannot become `Carrying` ([data-model.md](./data-model.md) §3)
- [ ] T029 [P] [US5] Implement `RoutingRule`, `RuleMatcher`, `RuleAction`, `Reliability` in `crates/dnet-core/src/rule.rs` — make constructing a `Deterministic` application rule **impossible at the type level** ([data-model.md](./data-model.md) §4)
- [ ] T030 [P] [US1] Implement `ConnectionSession`, `ConnectionEvent`, `FailureCause`, `SessionOutcome` in `crates/dnet-core/src/session.rs` — `FailureCause` has exactly the seven variants and no `Unknown`
- [ ] T031 [US1] Implement the built-in non-deletable bypass rule set (RFC1918, link-local, multicast, captive-portal probe hosts, active endpoint address) in `crates/dnet-core/src/builtin_rules.rs`

### IPC and service skeleton

- [ ] T032 [US1] Implement named-pipe framing (4-byte LE length prefix + UTF-8 JSON) in `crates/dnet-ipc/src/frame.rs`, rejecting malformed, oversized, and truncated frames without panicking (IPC-08)
- [ ] T033 [US1] Implement request/response types and the error model in `crates/dnet-ipc/src/protocol.rs` per [contracts/ipc-protocol.md](./contracts/ipc-protocol.md)
- [ ] T034 [US1] Implement pipe creation with explicit SDDL in `crates/dnet-ipc/src/server.rs` — never a NULL DACL (IPC-02)
- [ ] T035 [US1] Implement per-connection client identity verification in `crates/dnet-ipc/src/authz.rs` — `ImpersonateNamedPipeClient`, capture token, revert immediately; mutating requests require the interactive console user (IPC-01)
- [ ] T036 [US1] Implement the Windows Service lifecycle (SCM registration, start/stop/shutdown handlers) in `crates/dnetd/src/service.rs` using `windows-service`, running as LocalSystem ([research.md](./research.md) §R5)
- [ ] T037 [US1] Implement the undo-record registry in `crates/dnet-netstate/src/undo.rs` — every routing, DNS, or adapter mutation registers its undo **before** being applied
- [ ] T038 [US1] Implement restoration-on-start recovery in `crates/dnetd/src/recovery.rs` — replays outstanding undo records at service start, because a crash leaves no one to run the shutdown path ([data-model.md](./data-model.md) §Cross-cutting 1)
- [ ] T039 **[GATE] Plan Phase 2 exit**: IPC-01 passes — an unprivileged, non-console client issuing `Connect` receives `Unauthorized` and routing state is unchanged. This is SC-019 verified by explicit attempt

**Checkpoint**: The privilege boundary holds under attack. Domain logic is unit-testable without Windows or a network.

---

## Phase 4: US1 — Single Profile End-to-End (Plan Phase 3) 🎯 MVP core

**Goal**: Traffic flows through the tunnel inside the harness, with no routing loop.

**Independent test**: HV-13 and a manual end-to-end transfer through the mock endpoint.

### Contract tests first

- [ ] T040 [P] [US1] Write failing contract tests CFG-01…CFG-07 in `crates/dnet-config/tests/contract.rs` per [contracts/core-config.md](./contracts/core-config.md) §1.2
- [ ] T041 [P] [US1] Write failing contract tests AWG-01…AWG-06 in `crates/dnet-config/tests/amneziawg.rs` per [contracts/core-config.md](./contracts/core-config.md) §2.2
- [ ] T042 [P] [US1] Write failing contract tests SUP-T1…SUP-T4 in `crates/dnet-supervisor/tests/contract.rs` per [contracts/core-config.md](./contracts/core-config.md) §3.1

### Supervision

- [ ] T043 [US1] Implement child process spawn with captured stdio and readiness detection in `crates/dnet-supervisor/src/child.rs` (SUP-01, SUP-06)
- [ ] T044 [US1] Implement jittered exponential backoff **with a ceiling and an attempt limit**, terminating in `CoreFailedPersistently` rather than looping forever, in `crates/dnet-supervisor/src/restart.rs` (SUP-03)
- [ ] T045 [US1] Implement orphan reaping at service start in `crates/dnet-supervisor/src/reap.rs` — kills cores left by a prior crashed run **before** any new adapter is created (SUP-05)
- [ ] T046 [US1] Implement teardown of both cores plus full undo replay on any `dnetd` stop in `crates/dnet-supervisor/src/shutdown.rs` (SUP-04)

### Configuration generation

- [ ] T047 [US1] Implement primary-core configuration generation in `crates/dnet-config/src/primary.rs` — TUN inbound present for **every** profile, FakeIP `198.18.0.0/15` and `fc00::/18`, deterministic output (CC-01, CC-02, CC-09)
- [ ] T048 [US1] Implement the always-present active-endpoint bypass rule in `crates/dnet-config/src/endpoint_bypass.rs`, derived from the **same source** as the R4 host route so the two cannot diverge (CC-05, [data-model.md](./data-model.md) §Cross-cutting 2)
- [ ] T049 [US1] Restrict the generated config file's ACL to SYSTEM and Administrators in `crates/dnet-config/src/write.rs` (CC-08)

### AmneziaWG integration and the R4 loop hazard

- [ ] T050 [US1] Implement the UAPI client (text `key=value` over `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\awg0`) in `crates/dnet-config/src/uapi.rs` ([research.md](./research.md) §R5)
- [ ] T051 [US1] Implement peer plus obfuscation-parameter configuration **in a single UAPI transaction** in `crates/dnet-config/src/amneziawg.rs` — a peer configured without obfuscation is a plain WireGuard handshake, exactly the signature the profile exists to avoid (AW-04)
- [ ] T052 [US1] Implement endpoint host-route installation via the physical gateway in `crates/dnet-netstate/src/host_route.rs`, installed **before** the tunnel starts and removed after it stops, including after abnormal stop (AW-02, AW-03)
- [ ] T053 [US1] Implement the Profile A outbound as `direct` with `bind_interface` set to the AmneziaWG adapter in `crates/dnet-config/src/bind.rs` (CC-07, [research.md](./research.md) §R4)
- [ ] T054 [US1] Enforce that starting Profile A with no gateway available fails cleanly with `NoUsablePath` and starts no tunnel, in `crates/dnet-core/src/profile_start.rs` (AWG-01 — this is the primary loop prevention)

- [ ] T055 **[GATE] SPIKE-R4 / Plan Phase 3 exit**: run HV-13 — traffic flows end-to-end on Profile A, and packet counts on the tunnel adapter versus the physical interface show **no re-entry**; plus correct host-route rewrite across a simulated interface change. **Phase 5 onward is blocked until this passes.** Failure mode is a silent loop presenting as successful handshake with zero throughput ([research.md](./research.md) §R4)

**Checkpoint**: One profile carries real traffic without looping. The riskiest integration is proven.

---

## Phase 5: US1 + US4 — Three Profiles, Probing, and Endpoint Rotation (Plan Phase 4)

**Goal**: The product survives an unknown appliance and a blocklisted endpoint.

**Independent test**: HV-01, HV-02, HV-03, HV-04, HV-09, HV-12.

- [ ] T056 [P] [US1] Implement the Hysteria 2 profile generator in `crates/dnet-config/src/hysteria2.rs` — **omit the `bandwidth` section entirely** unless Brutal is explicitly enabled, yielding BBR (CC-03, [research.md](./research.md) §R2)
- [ ] T057 [P] [US1] Implement Brutal opt-in in `crates/dnet-config/src/brutal.rs` — requires a recorded user acknowledgement and both `up` and `down`; partial configuration fails generation (CC-04, FR-006)
- [ ] T058 [P] [US1] Implement the VLESS+REALITY profile generator in `crates/dnet-config/src/reality.rs`, with the borrowed TLS target domain as first-class configuration, not a constant ([docs/Research-Critique.md](../../docs/Research-Critique.md) §4.3)
- [ ] T059 [US1] Implement active profile probing in `crates/dnet-core/src/probe.rs` — races configured profiles and selects the first that carries **usable throughput**, not merely a completed handshake (FR-004, HV-12)
- [ ] T060 [US1] Implement mid-session block detection and automatic re-probe in `crates/dnet-core/src/reprobe.rs` (FR-005, SC-004)
- [ ] T061 [US1] Implement Tier 1 preference when multiple profiles are viable, and Tier 2 consent gating, in `crates/dnet-core/src/selection.rs` (FR-016b, IPC-04)
- [ ] T062 [P] [US4] Implement endpoint health probing and EWMA RTT scoring in `crates/dnet-core/src/endpoint_health.rs`
- [ ] T063 [US4] Implement automatic endpoint migration on unreachability, emitting a `ConnectionEvent` so the user is informed rather than silently migrated, in `crates/dnet-core/src/migrate.rs` (FR-012)
- [ ] T064 [US1] Implement distinguishable failure reporting for all seven `FailureCause` variants in `crates/dnetd/src/failure.rs` (FR-039, SC-020)
- [ ] T065 [O5] Design and document the profile update feed integrity model in `docs/adr/0002-profile-update-feed.md` — a feed that can push routing changes is a supply-chain surface and must be signed (FR-007, FR-008, open item O5)
- [ ] T066 [US1] Implement signed profile feed ingestion in `crates/dnet-core/src/feed.rs` per the ADR from T065
- [ ] T067 [O7] Verify whether the pinned primary-core version implements the newer obfuscation layer (Gecko) or only Salamander; record in `docs/adr/0003-obfuscation-layers.md` and tune Profile B accordingly (open item O7)
- [ ] T068 **[GATE] Plan Phase 4 exit**: HV-01, HV-02, HV-03, HV-04, HV-09, HV-12 pass. HV-03 must show the obfuscated profile connecting **and** the unobfuscated control failing

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
- [ ] T081 [US3] Implement path quality EWMA smoothing so raw samples never drive transitions directly, in `crates/dnet-core/src/quality.rs` (FR-018)
- [ ] T082 [US3] Implement the failover state machine with hysteresis and oscillation damping in `crates/dnet-core/src/failover.rs` (FR-016, FR-017, SC-007)
- [ ] T083 [US3] Implement host-route rewrite **before** tunnel rebind on a carrying-path change, asserted by call ordering rather than timing, in `crates/dnet-netstate/src/rebind.rs` (AW-03, AWG-04)
- [ ] T084 [US3] Implement honest degradation reporting when only one path is available and no move is possible, in `crates/dnet-core/src/degraded.rs` (FR-019, US3-5)
- [ ] T085 **[GATE] SPIKE-R9 / Plan Phase 6 exit**: HV-07 — an open transfer survives an interface change on **both** Tier 1 profiles at the pinned core versions. HV-08 — the Tier 2 profile breaks **and the UI said so beforehand**. **Any profile failing HV-07 is demoted to `Tier2` in configuration and UI; the label follows the measurement, not the intention** ([research.md](./research.md) §R9)

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
- [ ] T094 [US2] Implement idle-reclamation keepalive installation, failing the job if absent, in `crates/dnet-provision/src/keepalive.rs` (PR-15 stage, PRV-09, [research.md](./research.md) §R10)
- [ ] T095 [US2] Implement reachability verification gating `Endpoint` creation — a job failing here yields no endpoint, in `crates/dnet-provision/src/verify.rs` (PR-10)
- [ ] T096 [US2] Implement post-provisioning credential deletion, defaulting to delete, in `crates/dnet-provision/src/revoke.rs` (PR-05)
- [ ] T097 [P] [US2] Implement manual endpoint addition bypassing cloud provisioning entirely, in `crates/dnet-provision/src/manual.rs` (FR-010, US2-5)
- [ ] T098 **[GATE] Plan Phase 1 exit**: one command yields a reachable endpoint that survives idle reclamation; PRV-01…PRV-09 pass

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
- [ ] T114 Build the WiX/NSIS installer in `installer/`, registering `dnetd` as a LocalSystem service and bundling `THIRD-PARTY-NOTICES.md` and every dependency licence text
- [ ] T115 Verify installer size at or below 60 MB (SC-012); if exceeded, reduce bundled artifacts before relaxing the target
- [ ] T116 Measure idle RSS at or below 150 MB combined and idle CPU below 1% on a four-core machine (SC-013, SC-014)
- [ ] T117 Verify no measurable slowdown to a concurrent compile, test suite, and editor while connected (SC-015)
- [ ] T118 Run HV-14 and SUP-T2 — after killing `dnetd` mid-session, no core survives, no route or DNS change remains, networking identical to pre-installation (SC-016, FR-029)
- [ ] T119 Confirm coverage at or above 80% outside `apps/` and `vendor/` (SC-022)
- [ ] T120 Audit that zero tests target a live managed network (SC-021, Principle III)
- [ ] T121 [P] Write `README.md` positioning the product as a self-hosted network resilience and tunnel client, never as a firewall bypass, with the acceptable-use warning (FR-032, Constitution Legal posture)
- [ ] T122 Final `cargo xtask lint-branding` and `verify-vendor` audit across the release artifact

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
