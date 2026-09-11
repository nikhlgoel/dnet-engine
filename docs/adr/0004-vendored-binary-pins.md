# ADR-0004: Vendored binary pins and supply-chain verification

**Status**: Accepted — all three decisions approved and implemented 2026-09-10; amended
2026-09-11 by Finding 4 (embedded binaries), approved and implemented the same day
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

---

## Finding 4 — The primary core embedded its own adapter DLL and a kernel driver *(2026-09-11)*

The Outcome above verified what we **fetch**. It did not examine what the core's own
dependencies **compile into** the executable. An audit of the pinned source, and of the bytes
of the binary we built, found two embedded images.

### Evidence

| Image | Embedded by | In our `primary-core.exe` | Identity |
|---|---|---|---|
| Adapter DLL (`wintun.dll`) | `sing-tun v0.9.0-beta.4`, `internal/wintun/dll_windows_<arch>.go`: `//go:embed <arch>/wintun.dll`, loaded from memory by `memmod.LoadLibrary`. **No build tag disables it.** | Full 427,552-byte amd64 copy at offset 41,843,488 | All four architecture copies byte-identical to the official 0.14.1 zip (amd64 `e5da8447…`) with a valid WireGuard LLC Authenticode signature |
| Packet-diversion kernel driver (`WinDivert64.sys`) | Core `common/windivert/embed_amd64.go`, `//go:build windows && amd64 && !with_external_windivert` | Full 94,144-byte copy at offset 41,626,560 | `8da08533…`; licence LGPL-3.0 or GPL-2.0 |

`amneziawg-go` embeds neither. It uses `golang.zx2c4.com/wintun`, which loads the DLL from disk
(`LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`).

### Assessment

**Adapter DLL: a breach of Constitution obligation 2 as written; ambiguous under the DLL's own
licence.**

- The copy was unmodified and signed (§3(a)/(c) respected), and used only through the exported
  API (§3(b)). The in-memory loader is WireGuard LLC's own MIT code.
- But obligation 2 permits the DLL only *as the signed prebuilt, taken from the official zip*.
  This copy instead reached the installer **inside a GPL-covered executable that we compile**.
  That makes our object code contain proprietary code whose source cannot be offered, which
  undermines the aggregation basis Finding 1 relies on. Whether an embedded copy counts as
  "distributed alongside" under §3(d) is unclear, and we should not ship on an unclear reading.
- Operationally, two independently versioned DLL copies (one embedded, one vendored) could
  one day contend for the same driver service.

**Packet-diversion driver: no licence breach (LGPLv3 is GPLv3-compatible), but a security
liability.** It was an undocumented, signed kernel driver inside a LocalSystem process. The
core installs it on first use of TLS `spoof` or the bridge protocol. No profile uses either,
so the only thing standing between it and the kernel was the config file's ACL.

### Decision (approved by the project owner 2026-09-11)

| # | Mitigation |
|---|---|
| M1 | Patch `sing-tun`'s loader through a Go module `replace`. Delete the four embed files and their DLL directories. Load the official vendored DLL from beside the executable, by absolute path, only after its SHA-256 matches a per-architecture pin. The file is held open with read-only sharing from hash to load, closing the check-to-load race. |
| M2 | Build the core with `with_external_windivert`. We never ship the driver file, so features that need it fail closed. A config contract test keeps generated configs away from them. |
| M3 | `verify-vendor` scans every vendored core executable for embedded PE images. A byte-identical copy of any official DLL or the driver is named; any other embedded image fails too, since a different build would match no digest. |
| M4 | This finding; `THIRD-PARTY-NOTICES.md`; Constitution 1.3.0 (no-embedded-copies rule). |

### Implementation and verification

- **Patch**: `crates/xtask/patches/sing-tun/internal/wintun/`, applied by `fetch-vendor`.
  - The patch step refuses to build if the pinned core ever requires a different `sing-tun`
    version, or if a listed file is missing; either forces a re-review.
  - It asserts that no `go:embed`, `.dll`, or `.sys` remains in the patched package.
  - It replaces by a **relative** path, so the build machine's directory layout is not recorded
    in the shipped binary's build info.
  - It records the patch digest and a build fingerprint in `BUILD-PROVENANCE.md`. A change to
    the commit, tags, or patch forces a rebuild.
- **Patch tests** (Go, run by `fetch-vendor` against the real vendored DLL):
  - the pinned DLL loads and exports the Permitted API;
  - a one-byte-tampered DLL is refused before loading;
  - a missing DLL and a relative path are refused;
  - the path resolves beside the executable.
- **Pins**: `crates/xtask/src/pins.rs`, cross-checked by a unit test against the Go patch's own
  digest constants.
- **Results**:

  | Check | Result |
  |---|---|
  | `verify-vendor` on the old binary | Fails, naming both images at the audited offsets |
  | Rebuilt core size | 41.63 MB → **41.10 MB** (the two images removed) |
  | `verify-vendor` on the rebuilt binary | OK |
  | Pinned `check` on the Profile A config | Still accepted |

- **Runtime proof on the rebuilt binary**, unelevated, starting a TUN inbound:

  | DLL beside the core | Outcome |
  |---|---|
  | None | Fails to open `<exe dir>\wintun.dll` |
  | Official | Loads, then adapter creation is *Access is denied* (the expected stop without elevation) |
  | One byte flipped | *Does not match the pinned digest* |

### Consequences

- **Deployment**: the signed DLL must sit **beside each core executable** that uses it.
  - The SPIKE-R4 runner stages it into both core directories.
  - The installer (T114) must do the same, or install both cores into one directory.
- **Source offer**: the primary core is now a modified build of `sing-tun`. The patch files are
  part of its GPLv3 Corresponding Source and carry the modification notice required by §5(a).
- **Pin bumps**: raising the primary-core or `sing-tun` pin means re-reviewing the patch. The
  version check makes that unavoidable.
