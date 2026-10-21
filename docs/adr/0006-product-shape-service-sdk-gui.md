# ADR-0006: Product shape: service and app, a possible integration surface, and optimization

**Status**: **Proposed.** Awaiting owner approval of decisions P1–P6 (§5). Nothing here is normative
until approved. The constitution, spec and plan are unchanged and still govern.
**Date**: 2026-10-21
**Changes if approved**: `plan.md` project structure (where `dnet-tray` lives), a new specification
for connecting the engine into other programs (only if the owner later wants it), and a new
specification for download acceleration. The constitution is not
changed by this ADR: it names the UI stack (Tauri v2 + Svelte 5), not the repository it lives in.
**Requires**: Owner approval and a `docs/Research-Critique.md` entry, per Governance.

---

## 1. Context

On 2026-10-21 the project owner restated what the product is for and where it should go:

- make a college network reachable; make a public Wi-Fi network safer to use; keep the connection
  stable;
- make downloads steadier while the engine is on, instead of spiking up and down;
- make all of it fast and light, because the engine is written in Rust and should be excellent;
- let other people use it as a finished program, **or** build it into their own software as a
  library or SDK (clarified the same day: "SDK" was a loose word; the shape is **Docker Engine and
  Docker Desktop**, a service that does the work and an app that uses it, and plugging the engine
  into other programs is a later idea, to be revisited once the service is polished);
- treat this repository as the engine (the service) and build the user-facing program, with a GUI,
  as a separate piece.

Several of these touch a boundary the constitution already draws. This ADR sorts each idea against
the binding documents so that none is acted on as if it were already decided.

## 2. Each idea, against what is already decided

| # | Idea | Where it stands | What it means for the work |
|---|---|---|---|
| 1 | A college network becomes reachable | **v1 core.** FR-001–FR-005, FR-009–FR-015. Built and run live (T126): the real service connects over all three transports through an off-subnet endpoint. | Continue. No decision needed. |
| 2 | Stable connection through network changes | **v1 core.** FR-016–FR-019. Decision logic exists in `dnet-core`; the OS side (T080–T085) is not built. | Continue. No decision needed. |
| 3 | A public Wi-Fi network is safer to use | **Partly v1.** The traffic is encrypted to the user's own endpoint. Gaps: the kill switch is a decided posture (`RoutingPosture` has no direct fallback) but nothing in the operating system enforces it; the encrypted-DNS handling (T070, T071) is not built; endpoints are IPv4 only. | See §3 for what may be claimed. Enforcement is a decision (P3). |
| 4a | Downloads that are steadier on a lossy link | **v1, as a side effect.** BBR is the default congestion control and the profile is chosen by measured throughput (FR-004, FR-006). Nothing extra is built for this. | Nothing new. Measure it (T116 area), do not promise it. |
| 4b | Faster downloads: parallel ranges, sparse-file I/O, aggregation | **Deferred to v2 by Principle VII and the constitution's "Deferred" list:** "separate specifications, not stretch goals". | **Do not build.** Needs its own specification first (P5). |
| 5 | Excellent performance and low footprint | **Already a requirement, not yet measured.** SC-012–SC-016: installer ≤ 60 MB, idle RSS ≤ 150 MB, idle CPU < 1 % of four cores, no slowdown to foreground work. T115–T117 are open. | See §4. |
| 6 | Connect the engine into other programs, later | **Later, by the owner's decision (2026-10-21), once the service is polished.** In no specification. The seam that already exists is `dnet_ipc::client` plus the protocol types; `dnetctl` is a working reference client. | Needs a specification and decisions (P2, P4). |
| 7 | GUI as a separate piece | **`plan.md` puts it in this workspace** (`apps/dnet-tray`, Tauri v2 + Svelte 5, unprivileged, talks only through `dnet-ipc`). A separate repository is feasible because the GUI is an IPC client by design. | A structure decision (P1). |

### The shape this repository already has

```text
  app (GUI, later)  ──┐
  dnetctl (exists)  ──┼──▶  control pipe  ──▶  dnetd (the engine, a privileged service)
  other programs    ──┘     versioned          ──▶ runs the two transport cores, owns routes
  (a later idea)
```

This is the Docker shape: Docker Engine is the service that does the work, Docker Desktop and the
`docker` command are clients of it, and the engine's API carries a version so a newer client can
tell what an older engine understands. Here `dnetd` is the engine, `dnetctl` is the command-line
client that already works, and the tray app (T099 onward) is the Desktop equivalent.

**How the app behaves (owner, 2026-10-21).** The app opens a main window. Closing the window does
not end the app: it keeps running and stays in the system tray, where the single connect/disconnect
control (FR-036) and the state (T101, T102) are one click away; quitting is a separate, explicit
choice from the tray menu. Because the tunnel belongs to the service, closing the window, and even
quitting the app, never disconnects anything: the same as closing Docker Desktop does not stop the
containers. Whether the app starts with Windows is left to the user as a setting. This matches the
plan (T099 onward, an unprivileged Tauri app) and needs no change to the engine; it only fixes what
"close" means in the UI.

Terms, because they get used loosely: a **service** is a program that runs in the background and
does a job; a **client** talks to it; a **library** (a Rust crate, a Python package) is code a
program links in and runs inside itself; an **SDK** is a library plus documentation, examples and a
promise not to break it, so strangers can build on it. A payment company's SDK is its client for its
own service. For this project the only thing worth offering to outsiders, if ever, is the client
half: the code that speaks to the engine. The engine itself does not move into another program.

## 3. What may be said about it (Principle VI)

"Safer on public Wi-Fi" is true in a narrow sense and false in a broad one. Until the owner decides
otherwise, product text, the README and the About screen say only what the engine does:

- traffic between the machine and the user's own endpoint is encrypted;
- obfuscation conceals content and protocol, **not** traffic volume or destination (FR-033);
- until the kill switch is enforced by the system, a crash or a stopped service is not a guarantee
  that nothing leaves the machine unprotected.

"Secure", "private" and "anonymous" are not claims this project can make. The legal posture is a
self-hosted resilience and tunnel client, never a school-firewall bypass.

## 4. Optimization

Optimization here is a discipline, not a feature, and it comes after the features work:

1. **The targets already exist** (SC-012–SC-016). The release profile is already tuned
   (`opt-level 3`, thin LTO, one codegen unit, stripped, `panic = "abort"`); the service binary is
   about 1.9 MB and the control client about 0.4 MB. No budget has been measured yet.
2. **Measure before changing.** An optimization needs a before and an after number from the same
   measurement. Without one it is not done, whatever it feels like. T115–T117 are the first
   measurements; they come before any tuning.
3. **The cost is mostly outside our code.** The engine supervises two other programs, and they, not
   the Rust service, will dominate memory and CPU while a tunnel carries traffic. A budget that
   cannot be met by tuning our own code is reported as such, not hidden.
4. **Simplicity first (Principle VII).** No cache, pool or special case is added for speed without a
   measurement that shows it is needed.

## 5. Decisions for the owner

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| **P1** | Where does the GUI live? | (a) `apps/dnet-tray` in this workspace, as planned. (b) A separate repository that consumes the engine's protocol. | **(b), but not yet.** Split when the IPC protocol is frozen for v1 and before T099 starts. Until then there is nothing to move and a split now only creates drift between two repositories. Pin the protocol crate by tag, version the wire protocol, and run the engine's own client (`dnetctl`) in this repository's CI as the contract test. |
| **P2** | What would "connecting it into other programs" be? (**Deferred by the owner.**) | (a) The IPC client and protocol types, published as a crate. (b) The engine linked into another program. | **(a) only.** (b) is refused: the engine needs privilege (routes, adapters, process control), and keeping that behind the service boundary is Principle V. A third-party program is then just another unprivileged client, and the service decides what it may do. |
| **P3** | Enforce the kill switch in the operating system? | (a) Yes, with user-mode filtering rules in the Windows firewall engine (no driver). (b) No, keep the posture only. | **(a).** It is the missing half of "safer on public Wi-Fi". It is not a kernel driver, so the "no kernel-mode drivers" rule is not touched, but it changes routing and firewall state and needs its own task, undo records and a security review. |
| **P4** | Licence of that client crate (**Deferred by the owner.**) | (a) GPLv3 like the rest. (b) A more permissive licence for the thin client and protocol crate only. | **Owner's choice, decide before publishing.** With GPLv3, a program that links it must be GPLv3-compatible, which blocks most commercial users. The owner holds the copyright and may license that crate differently, but only while all contributions to it are the owner's. The bundled third-party components are unaffected either way: they run as separate processes. |
| **P5** | Start the download-accelerator specification? | (a) Not now. (b) Write the specification, build nothing. | **(a) until v1's gates pass.** Then (b). It is a separate specification by rule. |
| **P6** | Name | The release name is not decided. | The repository and crate names do not need it. Settle it before any installer, About screen or published crate. |

## 6. What continues now, and what does not

**Continues (no decision needed):** the v1 engine. Next candidates, in this order: failover and
network-change handling (T080–T085); the encrypted-DNS and rule layers (T069–T071); the open
live-coverage gaps (service stop, a core crashing mid-session, a host *name* as endpoint); T131
(FakeIP aliasing across sessions, which changes `contracts/core-config.md` and so needs the owner's
nod).

**Does not happen until the owner decides:**

- no download acceleration, parallel ranges or aggregation code;
- no new repository, and no move of `apps/dnet-tray` (P1);
- no published crate, no integration documentation, no promise of a stable API for outsiders (P2, P4);
- no firewall-enforcement code (P3);
- no marketing or UI text beyond §3.

## 7. If approved

- P1 (b): amend the project structure in `plan.md`; add a protocol version and a compatibility rule
  to `contracts/ipc-protocol.md` (**the protocol has no version today**, neither in the contract nor
  in `dnet-ipc`, so a GUI or SDK built now could not tell a compatible service from an incompatible
  one; this is the first thing a split needs, and it is small); keep the GUI's third-party attribution and branding rules
  (T110, `lint-branding`) in whichever repository it lives.
- P2 (a): a new specification for the SDK surface (supported requests, versioning, error model,
  what an untrusted caller may and may not do).
- P3 (a): a new task and contract for the enforcement rules, with the undo path registered before
  any rule is applied.
- Each: an entry in `docs/Research-Critique.md`.
