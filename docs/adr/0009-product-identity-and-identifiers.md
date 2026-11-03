# ADR-0009: Product identity: which identifiers are permanent, and which change with the product's name

**Status**: **Accepted** 2026-11-03. The owner said the project is free and open source, hosted only on GitHub with
no domain, that the engine's names stay, that only what people see changes when the program is named, and left the
rest to be decided ("decide for yourself"). I1 to I3 below are those decisions, recommendation taken.
**Date**: 2026-11-03
**Task**: T171
**Changes (applied)**: the application identifier in `apps/dnet-tray/src-tauri/tauri.conf.json` is now
`io.github.nikhlgoel.dnet-engine` (it was `dev.dnet.engine.tray`, which §3 explains); the built shell contains the new one
and not the old (`grep -a` on `dnet-tray.exe`, 2026-11-03). The identifiers in §2 are labelled permanent or renamable.

---

## 1. Context

"DNet Engine" is the name of the technology. The product that people install will get its own name, not chosen yet
(`README.md`, working name). Today the engine's name is also the product's name everywhere, including in places that
act as keys on a user's machine. Renaming the product is cheap while nothing is released and expensive afterwards,
so it is worth knowing now which identifiers a rename would touch.

**Does the software have an application ID?** Yes, one: the Tauri bundle identifier `dev.dnet.engine.tray`
(`apps/dnet-tray/src-tauri/tauri.conf.json:5`). Tauri describes it as a reverse-domain string that "must be unique across
applications since it is used in system configurations like the bundle ID and path to the webview data directory"
(from the `config.schema.json` shipped in `@tauri-apps/cli` 2.12.2, read 2026-11-03). Windows does not check it against
a domain; stores and other platforms may.

## 2. Every identifier, and what changing it later costs

Checked in the files named; "after release" means once people have it installed.

| Identifier | Value | Where | What it controls | Change after release |
|---|---|---|---|---|
| Application identifier | `dev.dnet.engine.tray` | `tauri.conf.json:5` | the window's web-view data folder; the bundle id | cheap to moderate: the web-view folder is orphaned (the window keeps its state in the service, not there [unverified]) |
| Product name | `DNet Engine` | `tauri.conf.json:3` | per Tauri: installer names, the installation folder, the Start Menu folder, the `HKCU\Software\<publisher>\<product>` key; also the Run-key value written by `installer/hooks.nsh:45` | **costly**: a new name means a new folder and uninstall entry, so the new installer would not replace the old one in place [inference from Tauri's description; not tested] |
| Publisher | `DNet Engine contributors` | `installer/tauri.installer.json:6`, winget locale file | text shown by Windows; part of the registry key above | cheap, same caveat as the row above |
| Windows service name | `DNetEngine` | `crates/dnetd/src/svc.rs:25` | the machine-wide key of the service | **costly**: needs a migration that stops the old service and restores the network from the old undo journal first |
| Service display name | `DNet Engine` | `crates/dnetd/src/install.rs:79` | what the Services list shows | cheap |
| Control pipe | `\\.\pipe\DNetEngine\control` | `crates/dnet-ipc/src/server.rs:27` | how the window and `dnetctl` find the service | moderate: client and service must change together |
| Data folder | `C:\ProgramData\DNet Engine\{run,state}` | `crates/dnet-config/src/write.rs:26`, `recovery.rs` | generated configuration, the undo journal, sealed credentials | **costly and risky**: the undo journal is what restores the network after a crash |
| Sealed-secret label | `DNet Engine` | `crates/dnet-config/src/secret_store.rs:402` | label on the protected credential blobs | moderate: old blobs must still open |
| Executables | `dnetd`, `dnetctl`, `dnet-tray` | the three `Cargo.toml` files | file names in the install folder | moderate |
| winget package id | `DNetEngine.DNetEngine` | `installer/winget/*.yaml` | the package's identity in winget | **permanent once published**: a new id is a new package |
| Words people read | "DNet Engine" | mostly `apps/dnet-tray/src/lib/messages.ts`, also `mock.ts`, `About.svelte` | window text | cheap: a few files |

## 3. Findings

1. **`dev.dnet.…` reads as the domain `dnet.dev`.** Whether the owner holds that domain is not recorded anywhere
   [unknown]. A reverse-domain id is meant to name a domain the publisher controls. Without a domain the usual
   alternative is the code host: `io.github.<user>.<project>` (a Flathub convention, recalled, not re-checked this session).
2. **The product's display name and the engine's keys are the same words.** The installation folder, the data folder
   and the Run-key value all contain "DNet Engine". That is why a rename is costly: display text and machine keys move
   together.
3. **The expensive parts are the ones the person never sees** (service name, pipe, data folder, winget id). They can
   stay as they are when the product is named, because they name the engine.

## 4. Proposal

- **I1. The engine identity is permanent from the first public release.** Service name, pipe, data folder, sealed-secret
  label, executables and the application identifier stay as they are when the product is named. They name the technology.
- **I2. The product name lives only in the display layer:** the window's words, the installer's title and shortcuts, the
  publisher text, the winget *name* (not its id). To make that one change, put the product's display name in one place per
  layer (`messages.ts`; the two installer files) instead of spread through prose.
- **I3. Settle the application identifier before the first release,** from a domain the owner controls, else
  `io.github.nikhlgoel.dnet-engine` (stable, needs no purchase). It follows the *engine* name, so a later product name does
  not touch it.

**Rename checklist (when the product is named):** change the display strings (§2, last row); the product name, publisher
and winget *name*; the About text; and the README's working-name note. Do **not** change the rows marked costly or
permanent; if the owner wants that anyway, it needs its own ADR with a migration and a test that the old undo journal still
restores a network.

## 5. Decisions for the owner

| ID | Decision | Recommendation |
|---|---|---|
| **I1** | Keep the engine identifiers permanent across the product rename | Yes |
| **I2** | Keep the product name in the display layer only | Yes |
| **I3** | Application identifier base: a domain you control, or `io.github.nikhlgoel.dnet-engine` | **Decided: `io.github.nikhlgoel.dnet-engine`.** The project has no domain and plans none; it lives on GitHub (commits, releases, one Pages site). Applied in `tauri.conf.json` |

## 6. Not verified

Tauri's NSIS template was not available locally, so how the installer uses the identifier and product name beyond
Tauri's own schema text is not read here. Whether Windows toast notifications take the identifier as their application id
is not checked. No installer has been built and installed in this session.
