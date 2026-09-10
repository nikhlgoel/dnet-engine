# ADR-0004: Vendored binary pins and supply-chain verification

**Status**: Accepted — all three decisions approved and implemented 2026-09-10
**Date**: 2026-09-10
**Task**: T005 (`cargo xtask fetch-vendor`)
**Supersedes in part**: `research.md` §R1 and §R6 characterisations

## Context

`fetch-vendor` refuses any artifact without a pinned SHA-256, because an unpinned
download is a supply-chain hole. Filling those pins required resolving upstream
versions and hashing the actual artifacts. Doing so surfaced three findings that
change earlier decisions.

## Pins (verified 2026-09-10)

| Artifact | Version | SHA-256 | Size |
|---|---|---|---|
| Primary core, `windows-amd64` zip | `v1.14.0` | `3ffb56267da14e287be48bd10cf7e6505260125bad940b75101fbb4d5d58e5d6` | 31.29 MB zip / **78.03 MB extracted** |
| Wintun | `0.14.1` | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` | 0.72 MB zip / 0.41 MB `amd64/wintun.dll` |
| `amneziawg-go` | `v3.1.20260828` (**source tag**) | — see Finding 2 | source only |

Binaries are fetched at build time and gitignored; only licence texts are committed.
Confirmed as the correct approach by the project owner.

---

## Finding 1 — The Wintun prebuilt licence is not permissive *(correction)*

Earlier documents described Wintun's prebuilt-binary licence as "a separate, more
permissive licence," following wintun.net's own summary wording. **Having read the
actual `LICENSE.txt` shipped in the distribution zip, that characterisation was wrong.**

It is a **proprietary end-user licence**, not a FOSS licence. Material terms:

- **§3(d)** forbids redistribution *"without the prior written consent of WireGuard LLC,
  **except insofar as the Software is distributed alongside other software that uses the
  Software only via the Permitted API**."*
- **§3(a)–(b)** forbid reverse engineering, modification, and derivative works, except
  through the documented `wintun.h` API.
- **§3(e)** forbids using the WireGuard LLC, WireGuard project, or Wintun names *"to
  endorse or promote products derived from the Software."*
- **§6** terminates the licence automatically on any non-compliance.

### Does this remain compatible with GPLv3?

**Yes, on the aggregation basis — and the design already supports it, which is fortunate
rather than planned.**

1. **Redistribution is permitted** by the §3(d) exception: DNet Engine distributes the
   DLL alongside software that uses it only through the documented API. Neither supervised
   core modifies or reverse-engineers it.
2. **`dnetd` does not link or load `wintun.dll` at all** (`research.md` §R6). The DLL is a
   dependency of the two *supervised third-party processes*, not of our GPLv3 code. The
   arrangement is aggregation under GPLv3 §5, not a combined work.
3. Had `dnetd` linked Wintun bindings directly — as the original blueprint assumed — this
   analysis would be considerably weaker. The decision to let the cores own the adapter
   removed the problem before it existed.

### New obligation

**§3(e) adds a second naming restriction, parallel to the primary core's.** DNet Engine must
not use the WireGuard, WireGuard LLC, or Wintun names to endorse or promote itself.
Attribution in `THIRD-PARTY-NOTICES.md` and the About screen is not endorsement and is
permitted. `xtask lint-branding` must be extended to cover these names on marketing surfaces.

**Also**: §3(a) forbids extraction from the Software. `fetch-vendor` must take `wintun.dll`
from the official zip **as published**, never from another product's installer.

---

## Finding 2 — `amneziawg-go` publishes no binaries

The repository has **zero releases**; only source tags, latest `v3.1.20260828`. There is no
prebuilt `amneziawg-go` executable to pin.

Options:

| Option | Assessment |
|---|---|
| **A. Build from pinned source in CI** | Adds a Go toolchain to the build pipeline. Licence-clean (MIT). Keeps the supervised-process model intact — we build a binary, we do not link a library, so Principle I holds. **Recommended.** |
| B. Extract the executable from the official Windows client MSI (v3.1.0, 3.6 MB) | Fragile, and the MSI is a full GUI client rather than the tunnel binary. Also sits awkwardly against Wintun §3(a) if any Wintun DLL were taken from it. |
| C. Supervise the official Windows client instead | It is a GUI application, not a headless tunnel process. Wrong shape for a supervised child. |

**Recommendation: Option A.** Note the honest cost — `research.md` §R1 chose supervised
processes partly to avoid a Go toolchain in the build. Building from source reintroduces
it. The distinction that still matters is that we never *link* Go into the Rust process,
which was the expensive part; a build-time toolchain is ordinary CI cost.

---

## Finding 3 — The installer budget is not achievable as currently scoped

**The primary core's Windows executable is 78.03 MB extracted.** SC-012 caps the entire
installer at 60 MB. That single artifact exceeds the budget before `dnetd`, the tray, and
`amneziawg-go` are counted.

| Option | Installer size estimate | Assessment |
|---|---|---|
| **A. Ship compressed; extract on install** | ~31 MB core + ~5 MB awg + ~12 MB ours ≈ **45–50 MB** | Meets SC-012, which caps the *installer*, not the installed footprint. Installed size becomes ~100 MB. Simplest path. |
| **B. Build the core from source with minimal build tags** | Potentially **20–35 MB installed** | The core supports build tags to exclude unused protocols. We need three of roughly twenty. Combined with Finding 2 this is nearly free — the Go toolchain is already required. Also lets us drop protocols we will never probe. Cost: we become the distributor of a modified build and owe a GPLv3 §6 source offer for it, which we owe anyway. |
| C. Raise or drop SC-012 | — | Available, but the budget exists because the product must not feel heavy on a constrained machine. |

**Recommendation: A now, B before v1 ships.** Option A unblocks Phases 2–5 immediately.
Option B is the better end state and becomes cheap once Finding 2 adds Go to the pipeline.

---

## Decisions required

1. **Finding 2** — approve Option A (build `amneziawg-go` from pinned source in CI, adding a
   Go toolchain to the build)?
2. **Finding 3** — approve A-now-B-later, or go straight to B (minimal-build the primary core)?
3. **Finding 1** — no decision needed, but note the correction and the new naming obligation.
   `lint-branding` will be extended to cover the WireGuard and Wintun names on marketing
   surfaces (tracked as an addition to T007).

## Consequences

- `THIRD-PARTY-NOTICES.md` updated to describe the Wintun licence accurately as proprietary
  with a redistribution exception, rather than as permissive.
- `.specify/memory/constitution.md` licence obligation 2 reworded for the same reason, and a
  third naming obligation added.
- T005 stays blocked until decisions 1 and 2 are made; the primary core and Wintun pins above
  are final and can be committed now.

---

## Outcome (2026-09-10)

All three decisions were approved and implemented in `cargo xtask fetch-vendor`.

| Artifact | How obtained | Result |
|---|---|---|
| Primary core | Built from commit `0b89958` with `with_quic,with_utls,with_clash_api,with_gvisor` | **41.63 MB** (was 78.03 MB prebuilt — **47% smaller**) |
| `amneziawg-go` | Built from commit `b5928ef`, default tags | 3.36 MB |
| Wintun | Signed prebuilt DLL, SHA-256 verified | 0.41 MB |
| | | **45.39 MB total, uncompressed** |

**Finding 3 resolved.** Option B (minimal build tags) alone brought the primary core
inside a workable budget; Option A's compression is no longer load-bearing. 45.39 MB
uncompressed becomes roughly 18–20 MB after installer compression, leaving ample room
for `dnetd`, the tray, and the installer itself under SC-012's 60 MB.

`with_wireguard` is deliberately **excluded** from the primary core: AmneziaWG is served
by a separate supervised process (finding C14), so the core needs no WireGuard support.
A unit test asserts this, because silently regaining the tag would inflate the binary for
no benefit.

**Provenance.** Sources are pinned by **commit SHA rather than tag** — a tag can be moved,
a commit cannot — and `fetch-vendor` verifies `git rev-parse HEAD` against the pin after
fetching, failing loudly if the tree is anything other than the pinned commit. Each build
writes `vendor/<name>/BUILD-PROVENANCE.md` recording repository, version, commit, package,
and build tags, so a shipped binary can be traced to its exact source. That is also how the
GPLv3 §6 source offer for the primary core is satisfied.

**Finding 1 implemented.** `lint-branding` now covers the WireGuard and Wintun names
alongside the primary core's. Its allowlist exempts `crates/xtask/` (build tooling that
never ships and whose job is naming what it checks for), `docs/`, `specs/`, vendor licence
and provenance files, and the About screen. A negative test confirms the check still fails
on a planted violation in `dnetd`.
