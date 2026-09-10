# Third-Party Notices

DNet Engine is licensed under the GNU General Public License v3.0 or later (see `LICENSE`).

It **bundles and executes** the following third-party components as **separate processes**.
They are not linked into DNet Engine; the arrangement is aggregation rather than a combined
work. Their licence texts ship with the installer and are reproduced under `vendor/`.

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
  not a combined work.
- **Compliance**:
  - Only the vendor-signed prebuilt DLL is bundled, taken from the official distribution
    zip as published. Wintun is never built from source (its source is GPLv2, incompatible
    with this project's GPLv3), and the DLL is never extracted from another product
    (forbidden by §3(a)). Enforced in CI by `cargo xtask verify-vendor`.
  - The DLL is not modified, reverse engineered, or derived from.
  - Per §3(e), DNet Engine does not use the WireGuard LLC, WireGuard project, or Wintun
    names to endorse or promote itself. This attribution notice and the About screen are
    not endorsement and are permitted.
- **Licence text**: `vendor/wintun/LICENSE.txt`.

---

*Vendor names are recorded in `vendor/*/LICENSE` and in the About screen. This file and
those surfaces satisfy the attribution obligations above.*
