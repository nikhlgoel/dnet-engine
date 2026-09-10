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

- **Licence**: the **prebuilt signed binaries** are distributed under a permissive
  licence, distinct from the GPLv2 that covers Wintun's source.
- **Compliance**: DNet Engine bundles **only** the vendor-signed prebuilt DLL and
  never builds Wintun from source. Bundling the GPLv2 source would be incompatible
  with this project's GPLv3 licence. Enforced in CI by `cargo xtask verify-vendor`,
  which fails the build if any Wintun source file is present.
- **Licence text**: `vendor/wintun/LICENSE.txt`.

---

*Vendor names are recorded in `vendor/*/LICENSE` and in the About screen. This file and
those surfaces satisfy the attribution obligations above.*
