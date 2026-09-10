# DNet Engine Constitution

DNet Engine is a free, open-source, self-hosted network resilience client for Windows. It restores
usable connectivity on constrained networks by tunnelling traffic through an obfuscated transport to
an exit node the user owns, resolving DNS locally via a FakeIP pool, routing by domain, and failing
over seamlessly between Wi-Fi and cellular.

Authoritative background: `docs/Research-Critique.md` (decisions D1–D10, findings C1–C13, open items
O1–O6). That document supersedes `docs/DNet-Engine-Research.md` wherever the two disagree.

## Core Principles

### I. Orchestration, Not Reimplementation (NON-NEGOTIABLE)

DNet Engine is an orchestration and experience layer over battle-tested transport cores, not a
from-scratch VPN engine. Transport, TUN integration, FakeIP and rule matching are delegated to
`sing-box`, which the Rust daemon runs as a **supervised child process** — never linked via cgo FFI.
The daemon generates its configuration, owns its lifecycle, and drives it through its
Clash-compatible control API.

DNet Engine's own contributions are exactly: exit-node provisioning, active transport probing and
automatic profile switching, interface failover, zero-config onboarding and UI, and updatable
transport profiles.

Replacing a delegated subsystem with a Rust-native implementation requires a recorded ADR naming a
specific reason. "It would be cleaner in Rust" is not a reason. This principle exists because the
alternative is six months spent reimplementing `sing-box` badly.

### II. Verify Against Primary Sources; Never Against the Blueprint

`docs/DNet-Engine-Research.md` is an unverified source blueprint whose citation list does not
support its technical claims (finding C13). It is context, not truth.

Before any protocol-level detail enters a spec, plan, or implementation it must be verified against
a primary source: the Hysteria 2 protocol documentation, the sing-box documentation, the AmneziaWG
repository, the Xray-core REALITY documentation, Microsoft Learn for Windows APIs, or the relevant
RFC or IETF draft. Cite the source in the spec. Where a blueprint claim has been shown false, the
correction in `docs/Research-Critique.md` governs.

### III. Test Against a Simulated Hostile Network — Never a Live One

The Docker plus `tc netem` plus `iptables` harness is **Phase 0** and is built before any transport
work. It must reproduce, on demand: 150 ms ± 50 ms latency with 20% loss; total outbound UDP
blocking; and signature-based dropping of standard WireGuard handshakes.

No feature is complete until it passes inside that harness. **Testing against a live institutional
network is prohibited** — it is both unnecessary and the fastest route to disciplinary consequences.

### IV. Test-First, and Actually Read the Output

Tests are written before implementation. The Red-Green-Refactor cycle is enforced. Verification
means running `cargo test --workspace` (plus the Phase 0 integration harness for anything touching
the network path) and **reading the full output**. Declaring work complete without reading the
output is a defect, not a shortcut. Minimum coverage 80% on non-FFI, non-UI crates.

### V. Least Privilege by Construction

The privileged Windows Service is the only component permitted to alter routing, DNS, or adapter
state. The Tauri tray UI and the Chromium native-messaging stub are unprivileged and reach the
service only over an authenticated named pipe with an explicit authorization boundary. Browser
extension IDs are pinned. No component trusts input from a less-privileged component.

An unprivileged process able to rewrite system routing is a local privilege-escalation vulnerability
and is treated as a CRITICAL defect.

### VI. Honest Capability Claims

Features that are best-effort are labelled best-effort in the UI, the docs, and the code. In
particular: per-process routing via ETW and `GetExtendedTcpTable` is inherently racy and is never
presented as a guarantee — domain and IP rules are the reliable path. Obfuscation defeats signature
DPI, not flow-volume analytics, and the documentation says so. Overstating what the tool does is
treated as a defect.

### VII. Simplicity and Shippability

Start simple; YAGNI. Where a decision trades scope for shipping, take the shipping option and record
the deferral. v1 exists to establish a stable, unrestricted connection — nothing else. Aggregation,
download acceleration, and additional platforms are separate specifications, not stretch goals.

## Technology and Scope Constraints

**Mandated stack.** Rust with Tokio for the daemon. Tauri v2 with Svelte 5 for the UI. `sing-box` as
the primary supervised transport core, plus `amneziawg-go` as a second supervised process (sing-box
does not implement AmneziaWG — verified, finding C14). Wintun for the virtual adapter. Never deviate
without an ADR.

**Licence obligations (binding, verified 2026-09-10).** The project is GPLv3 and every bundled
dependency is compatible. Two obligations follow and are not negotiable:

1. **`sing-box` is GPL-3.0-or-later with an additional term permitted under GPLv3 §7(e): no
   derivative work may use its name or imply association without prior consent.** DNet Engine
   therefore MUST NOT use the sing-box name in its product name, branding, or marketing, and MUST NOT
   imply association or endorsement. Attribution in documentation and an about screen is required.
2. **Wintun MUST be bundled as the vendor-signed prebuilt DLL only, never built from source.** The
   source is GPLv2, which is incompatible with GPLv3; the prebuilt signed binaries carry a separate
   permissive licence and are the vendor's only supported distribution path.

All bundled components run as separate processes, making the arrangement aggregation rather than a
combined work. Licence texts and a source offer ship with the installer regardless.

**v1 platform.** Windows 10 1809+ and Windows 11, x64 and ARM64, only. Core logic sits behind
platform-abstraction traits so Linux and Android are later ports rather than rewrites. macOS and iOS
are out of scope indefinitely.

**v1 transports.** Three probed profiles: AmneziaWG (UDP), Hysteria 2 with Salamander (UDP), and
VLESS+REALITY (TCP/TLS). A TCP-shaped fallback is mandatory — a UDP-only product is dead on networks
that block UDP. Hysteria 2's Brutal congestion control is opt-in only; BBR is the default, because
treating campus AP contention as non-congestive loss harms every other user on the AP.

**Exit node.** User-owned, provisioned by DNet Engine's wizard onto Oracle Cloud Always Free.
**The project never operates shared infrastructure for third parties.** Every user brings their own
endpoint. Multi-endpoint configuration with health-based rotation is v1 scope, because a single
static IP is trivially blocklisted.

**No kernel-mode drivers.** Ever. This rules out WFP callout drivers and the certificate cost they
imply.

**Resource budget.** Installer at most 60 MB. Combined idle RSS at most 150 MB. Idle CPU under 1% on
a 4-core machine. No measurable impact on foreground development work. (The blueprint's sub-10 MB
target is void as a consequence of Principle I.)

**Deferred to v2, not v1:** MPQUIC aggregation and ECF scheduling; the parallel download accelerator
and sparse-file I/O; the browser extension; Linux and Android; code signing.

**Legal posture.** Positioned publicly as a self-hosted network resilience and tunnel client, never
as a school-firewall bypass. An acceptable-use warning ships in the README and the first-run flow.
No hardcoded endpoints, keys, or institution-specific tuning.

## Development Workflow

**Spec-driven.** Every change flows through Spec Kit: constitution, then `/speckit.specify`, then
`/speckit.plan`, then `/speckit.tasks`, then `/speckit.implement`. No implementation begins before
its spec and plan exist. Open items O1–O6 in `docs/Research-Critique.md` gate the phases they name.

**Phase gates.** Phases 0 through 7 in `docs/Research-Critique.md` §5 are ordered and gated. Each
gate is a demonstrable behaviour inside the Phase 0 harness, not a code review opinion.

**Context discipline.** `CLAUDE.md` points at `.specify/memory/constitution.md` and
`docs/Research-Critique.md`; directory-scoped rules carry subsystem detail so the root file stays
small. When context is lost, recover it from these documents rather than from memory or from the
original blueprint.

**Commits.** Never commit without explicit permission. Commit messages are conventional-commit
format, precise about what that specific commit changed, and contain **no `Co-Authored-By` trailer
and no indication of AI involvement of any kind**. This is not negotiable and overrides any tooling
default.

**Security review.** Mandatory before any commit touching the IPC boundary, the service's privileged
operations, key material, routing rules, or the transport-profile update channel.

## Governance

This constitution supersedes all other practices, and supersedes `docs/DNet-Engine-Research.md`
wherever they conflict.

Amendments require an entry in `docs/Research-Critique.md` recording the change and its reason, a
version bump below, and explicit approval from the project owner. Deviations from a mandated
technology, a deferral boundary, or a NON-NEGOTIABLE principle require a written ADR — complexity
and scope expansion must be justified, never assumed.

All plans and reviews verify compliance with these principles before work is accepted.

**Version**: 1.1.0 | **Ratified**: 2026-09-10 | **Last Amended**: 2026-09-10

**Amendment log**

- **1.1.0** — Closed open items O1–O4 against primary sources. Added binding licence obligations for
  sing-box naming and Wintun prebuilt-only bundling. Added `amneziawg-go` as a second supervised
  process following the verified finding that sing-box does not implement AmneziaWG (C14). Recorded
  in `docs/Research-Critique.md` §6.
