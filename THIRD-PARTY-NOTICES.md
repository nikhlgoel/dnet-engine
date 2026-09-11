# Third-Party Notices

DNet Engine is licensed under the GNU General Public License v3.0 or later (see `LICENSE`).

It **bundles and executes** the following third-party components as **separate processes**.
They are not linked into DNet Engine; the arrangement is aggregation rather than a combined
work. Their licence texts ship with the installer and are reproduced under `vendor/`.

Every third-party binary ships as its **own separate, pinned file**. No bundled executable
carries an embedded copy of another binary (DLL, driver, or executable); `cargo xtask
verify-vendor` scans the built cores and fails the build if one does.

---

## Primary transport core

- **Licence**: GNU General Public License v3.0 or later, with an additional term
  permitted by GPLv3 §7(e).
- **Additional term**: *"In addition, no derivative work may use the name or imply
  association with this application without prior consent."*
- **Compliance**: DNet Engine does not use this project's name in its product name,
  branding, user interface, installer, or marketing, and does not imply association
  with or endorsement by it. This attribution notice and the application's About screen
  are the only surfaces that name it. Enforced in CI by `cargo xtask lint-branding`.
- **Source**: offered per GPLv3 §6; see `vendor/primary-core/`.
- **Modified build (GPLv3 §5(a) notice)**: the bundled executable is built from the pinned
  upstream commit with one modification, **made by the DNet Engine project on 2026-09-11**.
  The Windows adapter-DLL loader of its TUN library dependency (`sing-tun v0.9.0-beta.4`,
  `internal/wintun`) was patched.
  - Upstream compiled a copy of the DLL into the executable and mapped it from memory.
  - The modified loader embeds nothing. It loads the separately shipped signed DLL (below)
    from beside the executable, after verifying its SHA-256.
  - The patch files are part of the Corresponding Source: `crates/xtask/patches/sing-tun/`.
    `vendor/primary-core/BUILD-PROVENANCE.md` records their digest.
- **Build options**: built **without** the embedded packet-diversion kernel driver
  (`with_external_windivert`); see *Not bundled* below.

## amneziawg-go

- **Licence**: MIT.
- **Compliance**: copyright notice retained in `vendor/amneziawg-go/LICENSE`.

## Wintun

- **Licence**: **proprietary**, not a FOSS licence. The prebuilt signed binaries are
  distributed under the "Prebuilt Binaries License" reproduced in
  `vendor/wintun/LICENSE.txt`, which is distinct from and additional to the GPLv2 that
  covers Wintun's source.
- **Redistribution basis**: §3(d) of that licence forbids redistribution *"without the
  prior written consent of WireGuard LLC, except insofar as the Software is distributed
  alongside other software that uses the Software only via the Permitted API."* DNet Engine
  relies on that exception: the DLL is distributed alongside software that uses it solely
  through the documented `wintun.h` API.
- **Relationship to this project's GPLv3 licence**: DNet Engine's own code neither links
  nor loads `wintun.dll`. The DLL is a dependency of the two supervised third-party
  processes, which run as separate programs. The arrangement is aggregation under GPLv3 §5,
  not a combined work. The DLL is shipped **only as a separate file**, placed beside each
  core that loads it at run time. It is never embedded inside any bundled executable.
- **Compliance**:
  - Only the vendor-signed prebuilt DLL is bundled, taken from the official distribution
    zip as published. Wintun is never built from source (its source is GPLv2, incompatible
    with this project's GPLv3), and the DLL is never extracted from another product
    (forbidden by §3(a)). Enforced in CI by `cargo xtask verify-vendor`.
  - No embedded copies. The primary core's upstream build carried its own embedded copy of
    this DLL. We build it with a patched loader instead (see *Primary transport core*), and
    `verify-vendor` scans the built executables to confirm that no copy remains
    (`docs/adr/0004-vendored-binary-pins.md`, Finding 4).
  - The DLL is not modified, reverse engineered, or derived from.
  - Per §3(e), DNet Engine does not use the WireGuard LLC, WireGuard project, or Wintun
    names to endorse or promote itself. This attribution notice and the About screen are
    not endorsement and are permitted.
- **Licence text**: `vendor/wintun/LICENSE.txt`.

---

## Not bundled

### WinDivert kernel driver

- **Licence**: GNU LGPL v3 or GNU GPL v2, at the recipient's choice.
- **Status**: **not distributed.**
  - The primary core's upstream Windows build embeds this signed kernel driver
    (`WinDivert64.sys`) for its TLS-spoofing and bridge features.
  - DNet Engine builds the core with `with_external_windivert`, so the driver is not
    compiled in, and does not ship the driver file. Features that need it cannot start.
  - No DNet Engine profile uses them, and a config contract test keeps it that way.
  - `cargo xtask verify-vendor` fails the build if the driver reappears inside the core.
- Recorded here because it would otherwise be an undisclosed kernel-mode component of a
  LocalSystem service (`docs/adr/0004-vendored-binary-pins.md`, Finding 4).

---

*Vendor names are recorded in `vendor/*/LICENSE` and in the About screen. This file and
those surfaces satisfy the attribution obligations above.*
