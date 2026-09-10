# Implementation Plan: DNet Engine v1 — Network Resilience Client

**Branch**: `001-network-resilience-client` | **Date**: 2026-09-10 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-network-resilience-client/spec.md`

**Authority**: `.specify/memory/constitution.md` v1.1.0 and `docs/Research-Critique.md`

## Summary

Deliver a Windows privileged service (`dnetd`) plus an unprivileged tray application (`dnet-tray`)
that restores usable connectivity on DPI-filtered, congested networks and fails over between Wi-Fi
and cellular.

`dnetd` implements **no network transport of its own**. It supervises two third-party transport
processes, generates their configuration, probes which of three connection profiles the current
network permits, and switches between them and between endpoints as conditions change. It owns
system routing, DNS interception via a FakeIP pool, connect-time process attribution via ETW, and
the provisioning of user-owned exit endpoints. `dnet-tray` renders state and collects intent; it
holds no privilege and reaches `dnetd` only through an authenticated named pipe.

The single highest-risk integration is **TUN adapter ownership** when the AmneziaWG profile is
active, because two supervised processes both want a virtual adapter. The chosen resolution and its
failure mode are documented in [research.md](./research.md) §R4 and gated by a spike in Phase 3.

## Technical Context

**Language/Version**: Rust 1.83+ (2021 edition) for `dnetd` and all supporting crates; TypeScript 5.6
with Svelte 5 for the tray UI.

**Primary Dependencies**:
- `tokio` (rt-multi-thread, net, process, sync) — async runtime, child supervision, named pipes
- `windows` / `windows-sys` — Win32: service control, DPAPI, IP Helper, route table
- `windows-service` — Windows Service lifecycle and SCM integration
- `ferrisetw` — ETW real-time consumer for `Microsoft-Windows-Kernel-Network`
- `serde` / `serde_json` — supervised-core configuration generation and IPC framing
- `rustls` + `reqwest` — Oracle Cloud API client, endpoint health probing
- `tauri` v2, `svelte` 5, `vite` — tray application
- **Bundled binaries (not linked)**: primary transport core, `amneziawg-go`, Wintun signed DLL

**Storage**: Local filesystem only. Configuration as JSON under `%PROGRAMDATA%\DNet Engine\`;
secrets under Windows DPAPI machine scope for service-held material and user scope for cloud
credentials. No database.

**Testing**: `cargo test --workspace` for unit and contract tests; `cargo nextest` for the
integration suite; `vitest` for the tray; Docker Compose + `tc netem` + `iptables` harness for every
network-path test (Constitution Principle III).

**Target Platform**: Windows 10 1809+ and Windows 11, x64 and ARM64. No other platform in v1.

**Project Type**: Desktop application — privileged background service plus unprivileged GUI client.

**Performance Goals**: Connect in under 15 s when the first profile works, under 45 s when profiles
must be tried in turn (SC-003). Traffic resumes within 5 s of losing the carrying interface (SC-005).
Endpoint failover within 30 s (SC-008).

**Constraints**: Installer at most 60 MB (SC-012). Combined idle RSS at most 150 MB across all
processes (SC-013). Idle CPU below 1% of a four-core machine (SC-014). No kernel-mode components.
GPLv3 with two binding licence obligations (see Constitution Check below).

**Scale/Scope**: Single machine, single user. Up to ~8 configured endpoints and ~3 connection
profiles. Rule sets up to ~10,000 entries. Roughly 8 Rust crates plus one Tauri application.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| # | Principle | Pre-Phase 0 | Post-Phase 1 | Evidence |
|---|---|---|---|---|
| I | Orchestration, Not Reimplementation | **PASS** | **PASS** | No transport, crypto, or QUIC code is written. `dnet-supervisor` spawns and configures two third-party cores; `dnet-config` emits their configuration. The one place this is load-bearing is R4 (adapter ownership), resolved by configuration rather than by patching either core. |
| II | Verify Against Primary Sources | **PASS** | **PASS** | Every protocol constant in [research.md](./research.md) cites the vendor's own documentation. Blueprint citations are not used. Three residual unknowns (R4, R7, R9) are marked as spikes with explicit gates rather than asserted. |
| III | Simulated Hostile Network Only | **PASS** | **PASS** | Phase 0 is the harness and precedes all transport work. `testing/harness/` is a delivered artifact. No test targets a live managed network. |
| IV | Test-First | **PASS** | **PASS** | Contracts in [contracts/](./contracts/) are written before implementation and become the first failing tests. Coverage floor 80% outside UI and supervised processes. |
| V | Least Privilege by Construction | **PASS** | **PASS** | Only `dnetd` (LocalSystem) mutates routing, DNS, or adapters. Named pipe carries an explicit SDDL restricting access, plus per-connection client identity verification. See [contracts/ipc-protocol.md](./contracts/ipc-protocol.md) §Authorization. |
| VI | Honest Capability Claims | **PASS** | **PASS** | Failover tiers are modelled as data (`FailoverTier`) and surfaced in the IPC contract, not merely documented. Process attribution is typed `Attribution::BestEffort`. |
| VII | Simplicity and Shippability | **PASS** | **PASS** | Eight crates, each with one responsibility. No plugin system, no abstraction over the two cores beyond what R4 requires. Deferred items stay deferred. |

### Binding licence obligations (Constitution §Technology and Scope Constraints)

| Obligation | How the plan enforces it |
|---|---|
| **The primary transport core's name MUST NOT appear in DNet Engine's product name, branding, or marketing.** | The core is referenced in code and configuration only as `primary_core` / `PrimaryCore`. No crate, binary, module, UI string, installer component, or marketing asset carries its name. Attribution appears in `THIRD-PARTY-NOTICES.md` and the About screen only. A CI check (`xtask lint-branding`) greps UI strings, installer manifests, and the README for the vendor name and fails the build outside the allowlisted attribution files. |
| **Wintun MUST be bundled as the vendor-signed prebuilt DLL only, never built from source.** | `vendor/wintun/` contains only the vendor's signed DLL and its permissive licence text. `xtask verify-vendor` asserts the Authenticode signature and rejects the presence of any Wintun source file. No Wintun source is fetched, vendored, or compiled at any point. |

**Result: no violations. Complexity Tracking table is empty and omitted.**

## Project Structure

### Documentation (this feature)

```text
specs/001-network-resilience-client/
├── plan.md              # This file
├── research.md          # Phase 0 output — 10 decisions with sources
├── data-model.md        # Phase 1 output — entities, state machines, invariants
├── quickstart.md        # Phase 1 output — validation scenarios
├── contracts/           # Phase 1 output
│   ├── ipc-protocol.md          # dnet-tray <-> dnetd named-pipe contract
│   ├── core-config.md           # generated configuration contract for both cores
│   ├── provisioning.md          # Oracle Cloud provisioning + bootstrap contract
│   └── harness.md               # Phase 0 network simulation contract
├── checklists/
│   └── requirements.md  # Spec quality checklist (complete)
└── tasks.md             # Phase 2 output — created by /speckit-tasks, not here
```

### Source Code (repository root)

```text
crates/
├── dnetd/               # Privileged Windows Service binary. SCM lifecycle, orchestration root.
├── dnet-core/           # Domain logic: profile selection, endpoint health, failover state machine.
│                        #   Pure, no I/O, no Windows API. The bulk of unit-tested logic.
├── dnet-ipc/            # Named-pipe framing, request/response types, SDDL, client identity check.
│                        #   Shared by dnetd and the tray's Rust side.
├── dnet-supervisor/     # Child process lifecycle: spawn, health, restart policy, backoff ceiling.
├── dnet-config/         # Generates configuration for both supervised cores from domain types.
├── dnet-etw/            # ETW real-time session; TcpIpConnect -> (PID, 5-tuple) attribution cache.
├── dnet-netstate/       # Interface enumeration, route table, DNS settings, change notifications,
│                        #   and restoration-on-exit guarantees.
├── dnet-provision/      # Oracle Cloud API client, server bootstrap, keepalive, cleanup.
└── xtask/               # Build tooling: lint-branding, verify-vendor, package, licence bundling.

apps/
└── dnet-tray/           # Tauri v2 + Svelte 5. Unprivileged. Talks only to dnet-ipc.
    ├── src/             # Svelte UI
    └── src-tauri/       # Tauri Rust shell

vendor/                  # Bundled third-party binaries + their licence texts. No source.
├── wintun/              # Vendor-signed prebuilt DLL only (never built from source)
├── primary-core/        # Pinned transport core release binary
└── amneziawg-go/        # Pinned AmneziaWG release binary

testing/
└── harness/             # Phase 0: Docker Compose, tc/netem profiles, iptables DPI simulation,
                         #   and a mock endpoint server. Prerequisite for all network tests.

installer/               # WiX or NSIS packaging, service registration, THIRD-PARTY-NOTICES.md
```

**Structure Decision**: A Rust workspace of focused crates plus one Tauri application, matching
Constitution Principle VII. `dnet-core` deliberately holds no I/O so that profile selection, endpoint
health scoring, and the failover state machine are testable without Windows, a network, or the
supervised processes — this is what makes the 80% coverage floor achievable given how much of the
system is inherently integration-shaped. `vendor/` is segregated so the licence obligations are
enforceable by a single directory-scoped CI check.

## Phase Gates

Delivery follows the eight-phase order in `docs/Research-Critique.md` §5. Each gate is a demonstrable
behaviour inside the Phase 0 harness, not a review opinion.

| Phase | Deliverable | Gate | Blocked by |
|---|---|---|---|
| 0 | `testing/harness/` | Reproduces 20% loss, 150±50 ms, total UDP block, and WireGuard-signature drop on demand | — |
| 1 | `dnet-provision` | One command yields a reachable endpoint that survives idle reclamation | — |
| 2 | `dnetd` service skeleton, `dnet-ipc` | Unprivileged client cannot alter routing without authentication; verified by explicit attempt | — |
| 3 | `dnet-supervisor`, `dnet-config`, one profile end-to-end | Traffic flows through the tunnel inside the harness; **R4 adapter-ownership spike resolved** | 0, 2 |
| 4 | Three profiles, `dnet-probe`, automatic switching | Recovers when the harness blocks the active profile | 3, O7 |
| 5 | FakeIP, domain rules, encrypted-DNS handling, captive portal | Correct routing for browser traffic specifically | 3 |
| 6 | `dnet-netstate` failover | No TCP reset on Tier 1 profiles when the harness kills the carrying interface | 3, 5 |
| 7 | `dnet-tray`, first-run wizard | A non-technical user reaches a working tunnel unaided | 1, 2, 4, 5 |

**Open items from `docs/Research-Critique.md` §7 and where they land:**
- **O5** (update-feed integrity) — blocks FR-007/FR-008 only. Scheduled inside Phase 4.
- **O6** (ETW cost and coverage) — blocks FR-023 only. Spike in Phase 0, decision recorded before Phase 5.
- **O7** (Gecko support in the pinned core) — blocks Phase 4 profile tuning only.

## Complexity Tracking

No Constitution Check violations. Section intentionally empty.
