# Tech Stack

**Status**: Authoritative for v1 · **Governed by**: [`.specify/memory/constitution.md`](../../.specify/memory/constitution.md) v1.2.0

Deviating from anything here requires a recorded ADR. "It would be cleaner another way" is not a reason.

---

## 1. Runtime components

| Component | Technology | Privilege | Why |
|---|---|---|---|
| `dnetd` | Rust 1.83+ / Tokio | **LocalSystem** (Windows Service) | Only component permitted to alter routing, DNS, or adapter state |
| `dnet-tray` | Tauri v2 + Svelte 5 | Unprivileged (user session) | Native webview rather than a bundled browser; near-zero idle footprint |
| Primary core | Go binary, supervised child | Inherits `dnetd` | Hysteria 2, VLESS+REALITY, TUN, FakeIP, rule routing |
| Secondary core | `amneziawg-go`, supervised child | Inherits `dnetd` | AmneziaWG only — the primary core does not implement it |
| Virtual adapter | Wintun signed prebuilt DLL | Loaded by the cores | `dnetd` itself never links or loads it |

**The two cores are separate processes, never linked.** Embedding Go via cgo would place the Go
runtime and GC inside the Rust process, add ~40–70 MB, and make panics and signals interact badly
with Tokio. See [`research.md` §R1](../../specs/001-network-resilience-client/research.md).

---

## 2. Rust workspace

Nine crates. `dnet-core` deliberately performs **no I/O and touches no Windows API**, which is what
makes the 80% coverage floor achievable in a system that is otherwise integration-shaped.

| Crate | Responsibility |
|---|---|
| `dnetd` | Service lifecycle, orchestration root, recovery replay |
| `dnet-core` | Pure domain logic: profile selection, endpoint health, failover state machine |
| `dnet-ipc` | Named-pipe framing, protocol types, SDDL, client identity verification |
| `dnet-supervisor` | Child process lifecycle, restart policy with a backoff ceiling |
| `dnet-config` | Generates configuration for both cores from domain types |
| `dnet-etw` | ETW real-time session, connect-time PID attribution |
| `dnet-netstate` | Interfaces, routes, DNS, change notification, restoration guarantees |
| `dnet-provision` | Cloud provisioning, server bootstrap, keepalive, cleanup |
| `xtask` | Vendor fetch/verify, branding lint, packaging |

### Key dependencies

`tokio` (rt-multi-thread, net, process, sync) · `windows` / `windows-sys` · `windows-service` ·
`ferrisetw` · `serde` / `serde_json` · `reqwest` + `rustls` · `thiserror` (libraries) /
`anyhow` (binaries) · `tracing` · `proptest`

---

## 3. Transport profiles

| Profile | Transport | Carrier | Failover tier | Served by |
|---|---|---|---|---|
| **A** | AmneziaWG | UDP | Tier 1 — connections survive | Secondary core |
| **B** | Hysteria 2 (Salamander, optionally Gecko) | UDP | Tier 1 — QUIC migration | Primary core |
| **C** | VLESS + REALITY | **TCP/TLS** | Tier 2 — access only | Primary core |

A TCP-carrier profile is **mandatory**: a UDP-only product is dead on networks that block UDP.

**Congestion control**: BBR by default, achieved by *omitting* the bandwidth section from the
generated configuration. Brutal is opt-in and requires acknowledging that it degrades every other
user on the same access point.

---

## 4. Build and verification toolchain

| Tool | Purpose |
|---|---|
| Rust stable MSVC + VS Build Tools + Windows SDK | Compiles the workspace |
| Go 1.27+ | Builds both cores from pinned source |
| Docker + `tc`/`netem`/`iptables` | The simulation harness — **the only place network tests run** |
| `cargo llvm-cov` | 80% floor outside `apps/`, `vendor/`, `crates/xtask/` |
| `cargo xtask verify-vendor` | Rejects vendored Wintun source, asserts Authenticode signature |
| `cargo xtask lint-branding` | Confines upstream vendor names to attribution surfaces |

Both `xtask` checks **fail the build**. They are not advisory.

---

## 5. Vendored artifacts

Fetched at build time, never committed. Licence texts and `BUILD-PROVENANCE.md` **are** committed.

| Artifact | Source | Size |
|---|---|---|
| Primary core | Built from pinned commit, tags `with_quic,with_utls,with_clash_api,with_gvisor` | 41.63 MB |
| `amneziawg-go` | Built from pinned commit, default tags | 3.36 MB |
| Wintun | Signed prebuilt DLL, SHA-256 verified | 0.41 MB |

Sources are pinned by **commit SHA, not tag** — a tag can be moved, a commit cannot — and the fetched
tree is re-checked against the pin before building. `with_wireguard` is deliberately excluded from
the primary core; a unit test asserts it stays out. See [ADR-0004](../adr/0004-vendored-binary-pins.md).

---

## 6. Explicitly rejected

| Rejected | Why |
|---|---|
| cgo / FFI linking of the cores | Go runtime inside the Rust process; kills the size budget |
| Kernel-mode WFP callout driver | EV certificate plus attestation signing, incompatible with a free project |
| Building Wintun from source | Source is GPLv2, incompatible with this project's GPLv3 |
| `GetExtendedTcpTable` polling as the primary attribution path | Racy for short-lived connections; ETW gives connect-time events |
| MPQUIC aggregation in v1 | IETF draft; neither core implements it. Deferred to v2 |
| Loopback HTTP for IPC | Frequently blocked by endpoint security on managed machines |
| macOS / iOS | Paid developer account, entitlements, ~50 MB extension memory ceiling |

---

## 7. Resource budget

Installer ≤ 60 MB · combined idle RSS ≤ 150 MB · idle CPU < 1% of a four-core machine · no
measurable impact on foreground development work.

The original sub-10 MB binary target is void: it was incompatible with supervising real transport
cores, and Principle I chose correctness over that number.
