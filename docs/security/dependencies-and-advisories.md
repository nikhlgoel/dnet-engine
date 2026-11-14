# Dependencies and advisories: what was checked, what was found, what was accepted

A security tool that carries a known vulnerability cannot be trusted to protect anyone, so this page keeps the record.
First full pass: 2026-11-05 (T177). `.github/workflows/advisories.yml` repeats the mechanical part every week and says
when a pinned program has fallen behind; the rest below is done by reading, and is repeated before each release.

## 1. What we depend on

| Kind | What | How it is checked |
|---|---|---|
| Rust code (workspace) | 237 crates | `cargo audit` against the RustSec database |
| Rust code (window shell, Tauri) | 443 crates, its own lock file | `cargo audit --file apps/dnet-tray/src-tauri/Cargo.lock` |
| JavaScript (the window's page) | built into one bundle; the test tools do not ship | `pnpm audit --prod` (what ships), `pnpm audit` (all) |
| Two bundled network programs | the primary core and AmneziaWG, built from pinned commits | release notes, commit history after the pin, published advisories |
| The Go toolchain that builds them | the standard library is inside each program | the release workflow builds with Go `stable`, so every build takes the current standard library |
| Window framework | Tauri (version 2.12.5 here) | its published advisories |
| Windows pieces | the driver DLL (Wintun), the installer toolkit (NSIS), the web view runtime (WebView2) | advisories for each |

## 2. Found and fixed

| Finding | Why it mattered | Fix |
|---|---|---|
| **The primary core was 4 releases behind** (v1.14.0 pinned, v1.14.4 current): 174 commits | Among them fixes for crashes and panics a hostile or broken peer could trigger (an HTTP proxy panic when the upstream answers early, a panic on truncated JSON, a crash on a corrupted cache file, a crash when the interface monitor is missing), read loops that spin on persistent errors, data races in HTTP/2, a Hysteria port-hopping fix (it could connect to a different resolved server address), fixes to the selector and the WireGuard session endpoint that our carrier switching relies on, and a newer Go standard library | Pin moved to v1.14.4 (commit `c005f353…`). The patch that stops the core carrying its own driver DLL still applies: nothing in that part of the `sing-tun` source changed between the two versions (24 commits compared, none in `internal/wintun`), and the build still checks that no embedded DLL remains. See section 4 for how it was verified |
| `tokio` 1.53.1: RUSTSEC-2026-0386, an I/O-safety flaw in `AsyncFd` constructors (patched in 1.53.3) | We never call `AsyncFd` (a Unix API) so we were not exposed, but a warning left standing hides the next real one | Updated to 1.53.3; the workspace audit is clean |
| `undici` (8 advisories, 4 high) | Reached only through `jsdom` in the test tools; `pnpm audit --prod` was already clean. It runs on a developer's machine, though | Held at the fixed version (>= 8.12.2) with an override in `pnpm-workspace.yaml` |
| No Rust audit and no schedule in CI | A new advisory against unchanged code would go unseen | `.github/workflows/advisories.yml`: weekly, and on any dependency change |
| `quinn-udp` 0.5.15: RUSTSEC-2026-0538, a receive loop that can spin after a truncated datagram (fixed in 0.5.16), found 2026-11-14 by the Advisories run on a push, **after** the previous run had been green | It is in the lock file through the HTTP client's QUIC support on non-Windows targets; the Windows build of the service does not compile it, so we were not exposed. A failing audit is a failing audit, and one accepted warning must not hide the next | `cargo update -p quinn-udp --precise 0.5.16`; the local and CI audits are clean apart from the accepted `rustix` warning. This is the first time the weekly watch caught something between releases, which is what it is for |

## 3. Accepted, with the reason (each is rechecked by the weekly run)

| Item | Where | Why it is accepted |
|---|---|---|
| `deepmerge` (low, GHSA-gcqx-w48m-w2h4: prototype poisoning in `mergeObject`), no patched version exists | the page's build tool (`@sveltejs/vite-plugin-svelte`) | Build-time only; it merges the tool's own configuration and never touches input from outside. Not in the shipped page (`pnpm audit --prod` is clean) |
| `glib` 0.18.5 (RUSTSEC-2024-0429, unsound iterator) | window shell; part of Tauri's Linux GTK stack | Not compiled for Windows, the only platform of version 1 |
| `proc-macro-error` (RUSTSEC-2024-0370, unmaintained) | window shell; a build-time macro helper inside Tauri's tool chain | Runs at compile time only; nothing of it is in the program. Leaves with a Tauri update |
| NSIS 3.11 (CVE-2026-42171, local privilege escalation, fixed in 3.12) | the installer toolkit Tauri downloads | The condition is an installer run **as SYSTEM**, which then uses a low-integrity temporary folder. Ours is run by a person from their own account after a UAC prompt. Recheck when the Tauri bundler moves to NSIS 3.12 |

## 4. How the core upgrade was verified

The pin changed in `crates/xtask/src/fetch_vendor.rs`, `crates/dnet-core/src/survival_evidence.rs` (a test compares the
two) and the test harness's server build. The recorded survival evidence is empty, so nothing recorded referred to the
old commit. Then the cores were rebuilt from source (`cargo xtask fetch-vendor`), which fetches the pinned commit,
verifies it, applies the driver-loader patch, refuses if any embedded driver or DLL remains, and builds. After that: the
real core's own `check` run over every configuration we generate (`dnet-config` pinned-core tests), `verify-vendor`, and
the full workspace tests. The results of those runs are in the task note (T177).

## 5. Checked and clean

- **AmneziaWG** (`amneziawg-go`): the pinned commit is the newest on its main branch (0 commits after it); no published
  advisory for the repository was found. Its client applications have had audits; the server-side Go program we bundle
  was part of the 2024 audit scope, with the findings in the client.
- **Wintun**: no vulnerability record found for the driver DLL.
- **Tauri**: 2026 advisories exist (a URL-locality check on Windows, an updater downgrade, a content-security-policy
  nonce bypass, and others, fixed between 2.10 and 2.12). We use 2.12.5, which is at or above every fixed version found,
  and we use neither its updater nor its HTTP plugin. The window's Content Security Policy allows no inline script and no
  remote source, there is no global Tauri object, and the window may call 28 named commands and nothing else (no shell,
  file system or network).
- **The primary core's published advisories**: only an old SOCKS-authentication one (CVE-2023-43644, fixed in 1.4.5, long
  before our pin).
- **REALITY and Hysteria 2**: no vulnerability found. Community reports that a particular network blocks REALITY exist
  (Iran, 2026) but are single-source; they are a reason for the project's several profiles and for measuring, not a flaw.

## 6. Not checked, so not claimed

- Nothing finds a bug nobody has reported. A clean audit means "no known advisory", not "no bug".
- The WebView2 runtime is part of Windows and is updated with it; several Chromium web-view advisories exist for 2026.
  The program does not check the runtime's version. Keeping Windows and Edge updated is the person's part.
- Advisories published after 2026-11-05 are found only by the weekly run.
- Whether the Linux kernel flaw reported in October 2026 by one source (a TCP memory error, root code execution) is real
  could not be confirmed from a second source. The server script already turns on automatic security updates with a
  reboot, which is the right answer to a kernel flaw.

## 7. To repeat this by hand

```powershell
cargo audit
cargo audit --file apps\dnet-tray\src-tauri\Cargo.lock
cd apps\dnet-tray; pnpm audit --prod; pnpm audit
gh api repos/SagerNet/sing-box/releases/latest --jq .tag_name          # is the pin behind?
gh api repos/SagerNet/sing-box/compare/<pinned commit>...<latest tag> --jq '.commits[].commit.message'
```

Sources read on 2026-11-05: [RUSTSEC-2026-0386](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/tokio/RUSTSEC-2026-0386.md),
[CVE-2026-42171 (NSIS)](https://www.sentinelone.com/vulnerability-database/cve-2026-42171/),
[Tauri updater downgrade, CVE-2026-95625](https://osv.dev/vulnerability/CVE-2026-95625),
[Tauri URL check, CVE-2026-42184](https://cveawg.mitre.org/api/cve/CVE-2026-42184),
[sing-box advisory CVE-2023-43644](https://nvd.nist.gov/vuln/detail/CVE-2023-43644),
[the Go release history](https://go.dev/doc/devel/release),
[AmneziaVPN audit summary](https://www.opentech.fund/security-safety-audits/amneziavpn-security-audit-summary/).

## Third-party build actions are pinned by commit

The release workflow builds the signed installer with the signing password in its environment, so a moved tag on
an action it runs would run with that access. Since 2026-11-08 the four actions that are not GitHub's own
(`Swatinem/rust-cache`, `dtolnay/rust-toolchain`, `pnpm/action-setup`, `taiki-e/install-action`) are referenced by
the commit a tag pointed at, with the tag in a comment (GitHub's own `actions/*` stay on a major tag). A commit
does not move, so an update is a decision, not something that arrives on its own. To update one:

```bash
gh api repos/Swatinem/rust-cache/commits/v2 --jq .sha      # the commit the tag points at now
gh api "repos/dtolnay/rust-toolchain/contents/action.yml?ref=<sha>" --jq .content | base64 -d | head -20   # check its inputs
```

`dtolnay/rust-toolchain` takes its toolchain from the branch the commit is on (`stable`, `1.88`), so the commit of the
`1.88` ref is the 1.88 toolchain with no input. `taiki-e/install-action` is given its tool by `with: tool:`.
