# ADR-0005: Linux as a v1 platform

**Status**: **Proposed.** Awaiting owner approval of decisions L1–L6 (§6). Nothing here is normative
until approved. The constitution, spec, and plan still say v1 is Windows-only.
**Date**: 2026-09-14
**Changes**: Constitution §Technology and Scope Constraints ("v1 platform", "Deferred to v2"),
spec.md Assumptions and Out of Scope, plan.md Technical Context
**Requires**: Owner approval, a constitution MINOR bump (1.4.0), and a `docs/Research-Critique.md`
entry, per Governance

---

## 1. Context

The constitution fixes the v1 platform as Windows 10 1809+ and Windows 11. It defers Linux to v2 and
requires core logic to sit behind platform-abstraction traits, "so Linux and Android are later ports
rather than rewrites".

On 2026-09-14 the project owner directed that the product target Windows **and Linux** first, with
other systems to follow. Moving a platform across a deferral boundary needs a written ADR. This is
that ADR.

**Where the code stands (verified 2026-09-14 on Fedora 44, kernel 7.2):**

- **Builds and tests on Linux.** The workspace builds on Linux with no warnings. `cargo test
  --workspace` passes 335 tests; the rest are Windows-gated.
  - Portability defects fixed so far: an ungated Win32 call in the `dnet-etw` cost example, two
    imports used only on Windows, and dead-code warnings in `dnetd`.
- **Already portable.** `dnet-core` (pure) and `dnet-config` (generators) have no platform code.
- **Seams exist.** `CoreRuntime` (supervisor), `TunnelBringup` and `UndoExecutor`/`UndoStore`
  (netstate), `Service` (IPC), and `RecoveryOps` (dnetd) take an injected implementation. Each has
  one Windows implementation today.
- **Windows-only implementations:**
  - `dnetd` service entry (SCM);
  - `dnet-ipc` named-pipe transport and console-session authorization;
  - `dnet-netstate` IP Helper routes and adapter bring-up;
  - `dnet-supervisor` Toolhelp orphan discovery and Job Objects;
  - `dnet-config` DACL-restricted writes and the UAPI named pipe;
  - `dnet-etw` attribution.

**The harness is already Linux.** Principle III's harness is Docker, `tc netem` and `iptables`, so a
Linux build of `dnetd` can run inside it natively. A Windows client can only reach it from a VM.

## 2. Decision

**Windows and Linux are both v1 platforms.** Every seam in §1 gains a Linux implementation using the
mechanisms in §3. Core logic stays platform-free. No new trait is introduced unless a second
implementation needs it (YAGNI).

macOS, iOS and Android remain out of v1.

## 3. Mechanism mapping

| Concern | Windows (existing) | Linux (proposed) | Notes |
|---|---|---|---|
| Service host | SCM service, LocalSystem | systemd system unit, dedicated `dnet-engine` user, `AmbientCapabilities=CAP_NET_ADMIN`, `NoNewPrivileges=yes`, `ProtectSystem=strict` | L3. Not root: Principle V. CAP_NET_ADMIN covers TUN, netlink routes and rules, nftables, and `SO_MARK`. |
| Control channel | Named pipe with SDDL and per-connection identity | Unix socket `/run/dnet-engine/control.sock`, mode 0660, group `dnet-engine`. Identity via `SO_PEERCRED`; the console-user check asks logind for the active session on `seat0`. | Same authorization model as `dnet-ipc::authz`, with a different identity source. |
| Tunnel adapter | Wintun DLL loaded by both cores | Kernel TUN (`/dev/net/tun`) opened by both cores | **Wintun is not shipped on Linux.** Licence obligation 2 becomes Windows-only. |
| Routes | IP Helper host routes, undo-journalled | rtnetlink: a host route for the endpoint, plus a policy rule and table for tunnelled traffic, undo-journalled | Reuses the T037 journal and executor seam. |
| Kill switch (fail-closed) | WFP filters (user mode) | A dedicated nftables table `inet dnet_engine`, replaced atomically, dropping egress that is not tunnel, endpoint, LAN bypass or DHCP | Coexists with firewalld: a drop in any table at a hook wins, and an accept elsewhere cannot override it. Removed through the undo journal. |
| DNS leak protection | NRPT | systemd-resolved over D-Bus: `SetLinkDNS`, `SetLinkDomains ["~."]` and `SetLinkDefaultRoute` on the tunnel link; nftables drops port 53/853 egress not bound to that link | L2: resolved is required. No hand-editing of `/etc/resolv.conf`. |
| Service-held secrets | DPAPI machine scope | `systemd-creds`, TPM2-sealed when a TPM is present, else host key; files 0600 under `StateDirectory` | |
| User cloud credentials | DPAPI user scope | Secret Service API (KWallet, GNOME Keyring) from the tray process | Never held by the service. |
| Restricted run directory | Protected DACL, SYSTEM and Administrators | `RuntimeDirectory=dnet-engine`, mode 0700, owned by the service user | Same guarantee as CC-08: no window with broader access. |
| Undo journal | `%PROGRAMDATA%` with DACL check | `StateDirectory=dnet-engine` (`/var/lib/dnet-engine`), ownership and mode checked before trust | |
| Orphaned cores | Toolhelp and image-path match | Cores live in the service's cgroup; `KillMode=control-group` reaps them on any stop or crash. At start, a `/proc/<pid>/exe` match catches survivors, and pidfds are used for supervision. | Stronger than Windows: the kernel enforces containment. |
| Per-app routing (FR-023) | ETW connect-time attribution, best effort (ADR-0001) | cgroup v2: nftables `socket cgroupv2` matches the app's systemd scope, which KDE and GNOME already create per app | L4. **Enforced per packet, not best effort.** Kernel-version floor to be confirmed by a spike (T-L4). |
| Packaging | MSI | RPM and DEB with a systemd unit and a sysusers entry; no Flatpak or Snap, which cannot host a privileged service | L5. |
| Tray | Tauri v2 | Tauri v2 with StatusNotifierItem (KDE native; GNOME needs the AppIndicator extension) | |
| Vendored cores | Built from pinned commits for `windows/amd64` and `arm64` | The same pinned commits built for `linux/amd64` and `arm64` | The loader patch and the external packet-diversion tag only affect Windows. `verify-vendor` gains an ELF scan. |

**"No kernel-mode drivers" on Linux** means no out-of-tree kernel modules: no DKMS, and no AmneziaWG
kernel module (the userspace core is used). It also means no custom eBPF programs. In-tree TUN,
netfilter and routing are OS facilities, just as WFP and IP Helper are on Windows.

## 4. Consequences

- **Constitution 1.4.0:**
  - "v1 platform" becomes Windows 10 1809+/11 and the Linux floor in L2.
  - Linux leaves the "Deferred to v2" list.
  - Licence obligation 2 (Wintun) is scoped to Windows builds.
  - "No kernel-mode drivers" gains the Linux reading in §3.
- **spec.md:** the Assumptions and Out of Scope lines change. FR-023's "best-effort" wording
  becomes per-platform, because Linux can guarantee it.
- **plan.md:**
  - Technical Context gains the Linux dependencies: `rtnetlink`, `nftables` via its JSON API,
    `zbus` for resolved and logind, and `nix` for `SO_PEERCRED` and pidfd.
  - Target Platform lists both platforms.
  - SC-012 (installer size) applies per package.
- **CI:** the `build-and-test` job runs on `ubuntu-latest` as well as `windows-latest`. Coverage is
  collected on both. The simulated-network harness job (T020) runs the Linux client directly.
- **tasks.md:** each Windows OS seam task gains a Linux sibling (§7). No completed task is reopened.
  Core logic and generators need no change.
- **Risk:**
  - Roughly twice the OS surface to test.
  - Distro variance, contained by L2's hard floor.
  - firewalld and NetworkManager interplay, contained by owning a dedicated nftables table and
    marking the tunnel link unmanaged.

## 5. Alternatives considered

- **Keep Windows-only v1 and port later.** Rejected by the owner's direction. It would also leave the
  harness running a client the product does not ship.
- **Run as root on Linux.** Rejected: capabilities give the same reach with less authority
  (Principle V).
- **Manage `/etc/resolv.conf` directly.** Rejected: it races NetworkManager and is not transactional.
- **Let the core manage routes and firewall itself (its auto-route mode).** Rejected: it breaks the
  rule that only `dnetd` mutates routing, and bypasses the undo journal (T037).
- **eBPF for attribution or the kill switch.** Rejected: it is kernel code in all but name, and
  cgroup v2 with nftables already covers both.

## 6. Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| **L1** | Linux in v1: must a release pass the gates on both platforms? | **Yes.** Both platforms are release-gating from 1.0. |
| **L2** | Linux support floor | **systemd ≥ 255 with resolved active, nftables, cgroup v2 only.** Covers Fedora 42+, Ubuntu 24.04+ and Debian 13. Any system without these is refused at install, with a clear message. |
| **L3** | Linux service privilege | **Dedicated `dnet-engine` user with CAP_NET_ADMIN only**, not root. |
| **L4** | Per-app routing on Linux | **cgroup v2 with nftables**, enforced per packet. Windows keeps ADR-0001's best-effort ETW. |
| **L5** | Linux packaging and architectures | **RPM and DEB, x86_64 and aarch64.** No Flatpak or Snap. |
| **L6** | Development host | **Fedora is a supported development host.** Windows code is type-checked from Linux and tested on `windows-latest` CI and a local Windows VM (§8). |

## 7. Tasks this adds (after approval)

- **T-L1**: CI matrix, adding an `ubuntu-latest` build-and-test job next to Windows.
- **T-L2**: Linux `CoreRuntime` (spawn with ambient CAP_NET_ADMIN, pidfd supervision, cgroup
  containment) and `/proc` orphan discovery.
- **T-L3**: Linux `TunnelBringup` and `UndoExecutor` over rtnetlink (host route, policy rule, table).
- **T-L4**: SPIKE, confirming the `socket cgroupv2` match on the L2 kernel floor against KDE and
  GNOME app scopes.
- **T-L5**: nftables kill-switch table, with atomic replace and undo-journal removal.
- **T-L6**: systemd-resolved DNS capture over D-Bus.
- **T-L7**: `dnet-ipc` Unix-socket transport with `SO_PEERCRED` and logind console-user
  authorization. Attack tests IPC-* are ported.
- **T-L8**: `dnetd` systemd entry point, unit file, sysusers and tmpfiles.
- **T-L9**: `fetch-vendor` and `verify-vendor` for Linux targets, including the ELF embedded-image
  scan.
- **T-L10**: `systemd-creds` secret storage, and Secret Service for the tray.
- **T-L11**: RPM and DEB packaging within the SC-012 size budget.

## 8. Development-host requirements (Fedora)

Checked on 2026-09-14.

**Already present:**

| Tool | Status |
|---|---|
| Rust | stable 1.98.1 |
| Windows target | `x86_64-pc-windows-msvc` installed |
| C toolchain | gcc, clang, `clang-cl`, `llvm-lib` |
| nftables | 1.1.6 |
| systemd-resolved | active |
| cgroup v2 | mounted |
| Containers and VMs | podman, docker, qemu, libvirt |
| GitHub CLI | `gh` |

**Missing:**

| Needed for | Missing | Install |
|---|---|---|
| Building the vendored cores (`fetch-vendor`) | Go ≥ 1.25.5 (primary core `go.mod`); `amneziawg-go` needs 1.25.0 | `sudo dnf install golang` (Fedora 44 ships 1.26.8) |
| Type-checking Windows code from Linux | MSVC CRT and Windows SDK headers (`ring`'s build script fails without `assert.h`) | `cargo install cargo-xwin`, which downloads the headers after you accept Microsoft's licence; or `sudo dnf install mingw64-gcc` and check against `x86_64-pc-windows-gnu` |
| Coverage gate (CI parity) | `cargo-llvm-cov` | `cargo install cargo-llvm-cov` and `rustup component add llvm-tools-preview` |
| Dependency audit | `cargo-audit`, `cargo-deny` | `cargo install cargo-audit cargo-deny` |
| Signature check of `wintun.dll` off Windows (optional) | `osslsigncode` | `sudo dnf install osslsigncode` |
| MSRV check | Rust 1.83 toolchain | `rustup toolchain install 1.83` |
| Running Windows-only tests | A Windows VM | libvirt is present; needs a Windows image |
