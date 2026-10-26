# ADR-0007: The UI stack: keep Tauri v2 + Svelte 5, with eight binding constraints

**Status**: **Accepted** — approved by the owner, 2026-10-24. The mandated stack is *retained*, so no
deviation was needed; the approval also covers the rewording of SC-013 (§6, applied in `spec.md`) and the
WebView2 runtime prerequisite (R5). The decision to ship the standalone runtime installer beside ours is
still T114's.
**Date**: 2026-10-21
**Changes (now applied)**: `docs/design/design-system.md` becomes governing; T099–T111 and T116 gain the
constraints in §5; SC-013 is reworded (§6). The constitution is not changed.
**Required**: owner approval (given 2026-10-24) and a `docs/Research-Critique.md` entry (O8, added the
same day), per Governance.

---

## 1. Context

The constitution mandates "Tauri v2 with Svelte 5 for the UI" (Technology and Scope Constraints) and
`docs/architecture/tech-stack.md` justifies it as "native webview rather than a bundled browser;
near-zero idle footprint". The owner asked (2026-10-21) whether that stack is "the perfect option"
once every factor is weighed, and whether it is properly optimised.

Two things in the existing record were claims, not evidence:

- "near-zero idle footprint" had never been measured; and the one budget that bears on it, SC-013
  (idle RSS ≤ 150 MB combined), does not say in which state, or by which memory metric.
- The design (`design-system.md` v1) treated the tray as a window.

This ADR measures the claim, compares the alternatives on the factors that matter here, and records what
the stack must be *used* like for the claim to hold.

## 2. Evidence

Two throwaway spikes under `testing/spike-ui/` (detached from the workspace; not product code), each a
tray-resident program that starts with no window, opens one 15 s in, and destroys it 45 s in, showing the
same small status page (a card, five rows, a live-updating readout). `Measure-Footprint.ps1` samples the
whole process tree (the program and every process it started, which includes the web view's) about every
3 s and reports the median of each phase.

**Metric.** *Private working set* (`Win32_PerfFormattedData_PerfProc_Process.WorkingSetPrivate`): what
Task Manager calls Memory, and the figure that does not count a shared library once per process. The
summed *working set* is reported beside it because SC-013 says "RSS"; it overstates a tree that shares
pages.

| | Tray only | Window open | After window destroyed | Executable | Window open → page loaded |
|---|---|---|---|---|---|
| **Tauri 2.12.5 + wry 0.57 + WebView2 155.0.4283.62** | **3.5 MB** private · 29.8 MB WS · 2 processes | **93.9 MB** private · 362.6 MB WS · **8 processes** | **4.8 MB** private · 39.7 MB WS · 2 processes | 5.93 MiB | **414–463 ms** (four opens; the first, "cold", is no slower) |
| **Slint 1.18.1 (software renderer) + tray-icon 0.26.1** | 2.9 MB private · 23.8 MB WS | 4.9 MB private · 31.8 MB WS | 3.8 MB private · 30.8 MB WS | 8.65 MiB | not measured |

(The second process at rest is `conhost.exe`, the console host: both spikes were built as console
programs. The product is a windowed program and will not have it, so the resting figures here are
slightly pessimistic, in the same way for both toolkits. The web view's six extra processes appear only
while the window is open.)

**What the numbers say.**

1. With the window **closed**, the mandated stack costs about the same as a native toolkit: 3.5 vs 2.9 MB
   private. The claim "near-zero idle footprint" is **true, but only if the web view is destroyed**, and
   it is: destroying the window returned the tree from 94 MB to 5 MB within one sample.
2. With the window **open**, the web view costs about **90 MB private** more than a native window
   (94 vs 5), in six extra processes. That is a real cost, paid only while someone is reading the window.
3. A cold open takes about **440 ms**. That is fine for a window and far too slow for a tray menu, which
   is why the menu must be native (§5, R1).
4. The native toolkit's *executable* is larger here (8.65 vs 5.93 MiB); neither is near the 60 MB
   installer budget (SC-012), which the two cores (≈ 45 MB) dominate.

**Limits of this evidence.** One machine, Windows 11, one WebView2 version. The page is trivial and plain
HTML, not Svelte: a real UI will add some JavaScript heap, so the window-open figure is a floor, not a
promise (T116 re-measures with the real app). Sampling is coarse (about 3 s). The Slint spike used the
software renderer; a GPU renderer would cost more. The spike does not measure CPU, GPU memory, battery,
or the cost of the tray icon over days. Nothing here measures accessibility or text shaping; those
entries in §3 are reasoned, not measured, and are marked so.

**The centrepiece (added the same day).** The owner asked for a living centrepiece: a rotating figure of dots.
`docs/design/preview.html` draws it (about 520 points, perspective-projected on a 2D canvas, no library, no GPU,
30 fps cap) and reports its own cost: **0.3–1.3 ms per frame on average (1.8 ms worst)**, so at most about 4 % of
one core, and only while the window is open and visible. A 3D library was rejected as a cost far above the need.
This is measured in a browser tab on this machine, not in the Tauri window; T116 re-measures there.

**Reproduce.** `python make_icons.py`; `cargo build --release` in each spike directory (the Tauri one
takes about five minutes cold); then
`powershell -File Measure-Footprint.ps1 -Exe <path to the spike .exe> -Label <name>`.
`SPIKE_SCRIPT=timing` on the Tauri spike prints the open latencies.

## 3. Alternatives

Each is judged on what this product needs: a tray-resident program a person looks at for seconds at a
time, a form-heavy first run (the provisioning wizard), four consent dialogs, a rules editor, a status
view with live numbers, at least English and probably other languages, GPLv3, and a small, auditable,
unprivileged surface.

| Option | Idle (window closed) | Window open | Design freedom | Accessibility | Complex-script text | Form-heavy velocity | Linux (ADR-0005, unapproved) | Verdict |
|---|---|---|---|---|---|---|---|---|
| **Tauri v2 + Svelte 5** (mandated) | 3.5 MB (measured) | 94 MB (measured) | Highest: full CSS, SVG, variable fonts, container queries | The browser's accessibility tree, tested screen readers | The OS/browser shaper | Highest | WebKitGTK: works, rendering and memory differ from WebView2; GNOME has no tray without an extension | **Keep** |
| Slint | 2.9 MB (measured) | 4.9 MB (measured) | Good for a custom look; its own markup, smaller ecosystem | Present; less proven than a browser's | Own text stack: verify per script before relying on it | Lower: every form, dialog and focus order built by hand | Consistent across platforms | Best footprint; loses on the factors the wizard and the consents depend on. **Fallback** (§7) |
| egui / eframe | Not measured | Not measured | Immediate-mode look; custom styling possible | Weak historically; verify | Limited shaping for complex scripts; verify | Low for forms and dialogs | Consistent | Suits tools, not a consent-heavy first-run flow |
| iced | Not measured | Not measured | Good | Immature | Own text stack; verify | Medium | Consistent | Not chosen: smaller ecosystem for the same trade as Slint |
| WinUI 3 / Windows App SDK | Not measured | Not measured | Native Windows look, hard to make distinctive | Excellent | Native | Medium (XAML) | **None** | Locks the UI to one OS and a heavy runtime; contradicts the portability the owner asked for |
| Electron | Not measured | Not measured | Highest | Browser tree | Browser | Highest | Good | Bundles a full browser: the cost the original stack was chosen to avoid (`tech-stack.md`) |
| Flutter | Not measured | Not measured | High, own renderer | Improving | Own text stack | Medium | Good | A second language and runtime for a UI that is mostly forms |
| Qt | Not measured | Not measured | High | Good | Good | Medium (C++/QML) | Good | A large dependency and licensing surface (LGPL linkage, or GPLv3) for a thin client |

"Not measured" is deliberate: the spikes cover the two candidates that could realistically win. The
others are judged on the structural reason in the last column; none was a close call.

**Why not the native option, given it wins on memory?** Because the memory it wins is in a state, *window
open*, that is minutes a day; the stack's idle cost is already equal once the web view is destroyed (§2.1).
Meanwhile the things Tauri wins are used every time: the consent dialogs, which must be correct for
assistive technology and must read in the user's script; the wizard, which is the hardest flow in the
product (SC-009); and the freedom to give the product a real identity. Choosing the other way would pay a
permanent cost in those places to save a transient one in memory.

**The decision is a two-way door.** The UI is an unprivileged client of a versioned pipe protocol
(`dnet-ipc`, ADR-0006), and `dnetctl` already proves the protocol is enough to drive the engine. If the
reversal triggers in §7 fire, the window can be rebuilt in another toolkit without touching the engine.

## 4. Decision

Retain **Tauri v2 + Svelte 5** for `dnet-tray`, used under the constraints in §5. The constitution's
mandated stack stands; no ADR for deviation is needed.

## 5. Binding constraints

**R1: The tray is native; the window is the only web view.** The tray icon and its menu are created and
updated from Rust. A left click opens a native menu with the state, the one control (FR-036), "Open", and
"Quit this app (the connection stays up)". Nothing in the tray depends on JavaScript.

**R2: Destroy the web view when it is not wanted.** After the window closes, keep the web view for a grace
period (proposed 120 s, so a quick re-open is instant), then destroy it. Create it hidden with the theme
background and show it on first paint. No JavaScript timer or event subscription runs while it is hidden.

**R3: Plain Svelte 5 with Vite, as a single-page app; not SvelteKit; no component or animation library.**
The app has about six views and needs no router or server rendering. Use native elements for what they do
well: `<dialog>` for every consent (focus trap, `Esc`, inert background), `<details>`, `<input>`. TypeScript;
a lockfile; `pnpm audit` in CI beside `cargo audit`. Budgets: JavaScript ≤ 150 KB gzipped; fonts ≤ 60 KB.

**R4: The web view never touches the control pipe.** The Rust side owns the `dnet-ipc` client, decodes
replies with the typed protocol, and sends the web view small validated view-models. The Tauri capability
list is the minimum (no shell, no file system, no HTTP; one command to open a URL the Rust side has
checked). Content-Security-Policy `default-src 'self'`; no remote content; developer tools off in release.
Everything from the service is rendered as text and stripped of control and bidirectional characters
(design-system §14).

**R5: Treat WebView2 as a prerequisite and say so.** WebView2 is not bundled (a fixed-version runtime would
break SC-012). It is present on Windows 11 and on current Windows 10; it was installed here
(155.0.4283.62). The installer detects its absence, says plainly that the window needs it, and points to
the standalone runtime installer; the Evergreen *bootstrapper* downloads from the internet and the
product's users may be on a network that blocks it. `dnetctl` and the tray menu (R1) work without it, so
a missing runtime degrades the window, not the connection. Decide at T114 whether to ship the standalone
runtime installer beside ours (its size must be taken from Microsoft's current download, not assumed).

**R6: Write CSS that works in WebKitGTK as well as WebView2.** ADR-0005 (Linux) is not approved, but the
cost of keeping the door open is a rule: use features with support in current WebKitGTK; the preview uses
container queries, `color-mix`, `<dialog>` and logical properties only. Re-check before relying on
anything newer.

**R7: Tokens only.** Every colour, size and duration comes from `docs/design/tokens.css`; CI fails a colour
literal anywhere else, and fails the change if any of the 30 contrast pairs drops below its floor.

**R8: The scene is bounded.** The dot figure draws on a 2D canvas at no more than 30 fps; it stops when the
window is hidden or minimised (`visibilitychange`) and under `prefers-reduced-motion` (one static frame per
state); it never animates something that is not happening (flowing dots only on the network carrying traffic);
if its average frame cost exceeds 4 ms it drops to 15 fps and fewer points. No 3D or animation library.

## 6. Requested amendments

- **SC-013** (idle RSS ≤ 150 MB combined, SC-014 idle CPU) names neither a state nor a metric. Reword to
  "idle, window closed, combined **private** memory ≤ 150 MB", and add "window open ≤ 300 MB private;
  window open → page loaded ≤ 600 ms". Reasons and numbers: §2. (The 300 MB ceiling is a proposal, set
  from the measured 94 MB plus the cores; T116 may tighten it.)
- **T116** measures both states with the method above, on the real app, and the real cores running.
- **tasks.md**: T099–T110 take R1–R7 as acceptance criteria.

## 7. What would reverse this

Any of these, measured on the real app, reopens the decision and moves the window (not the engine) to a
native toolkit, with Slint the leading candidate:

- window-open private memory above 150 MB with the real UI, or a cold open above 600 ms that R2's grace
  period does not hide in practice;
- a material share of the target users without WebView2 and unable to install it;
- an accessibility defect in WebView2 that Narrator or NVDA users hit in the consent dialogs;
- ADR-0005 approved *and* the Linux tray proving unworkable under WebKitGTK on the target distribution.

## 8. Consequences

- The product's resting state is a ~4 MB Rust process with a native icon and menu. Most people will not
  open the window on most days, and the stack costs them nothing.
- The window is a web page: it can have a real, distinctive design and be correct for assistive
  technology, at ~90 MB while it is open.
- Two moving parts are added to the supply chain (an npm tree and the WebView2 runtime); R3 and R5 keep
  them small and visible.

## 9. Implementation status (2026-10-24)

What was built under R1–R8, and how each was checked. "Seen" means observed in the running application on one
machine against a real running service; "tested" means an automated test; neither means a real network.

| | State |
|---|---|
| R1 native tray | Built (`src-tauri/src/shell.rs`, words in `dnet-view::tray`, shared with the window through `words.json`). **Tested:** the words for every state. **Not seen:** nobody has clicked the menu; the icon is one placeholder for every state. |
| R2 web view destroyed when unwanted | Built: created hidden, shown on page load, hidden on close, destroyed after 120 s unless reopened; nothing sent while hidden. **Tested:** the grace logic and the polling interval (`dnet-view::session`). **Seen:** the window opens and fills. **Not measured:** cold-open time and memory (T116). |
| R3 plain Svelte, no component library | Built: Svelte 5 runes, Vite 8, TypeScript; native `<dialog>`; 43 KB of JavaScript gzipped of 150, no fonts. pnpm holds new releases back 14 days and runs no install scripts; `pnpm audit --prod` is clean. |
| R4 web view never touches the pipe | Built. **Seen:** the framework refuses a command outside the list (a window command, an unknown name); the page loads only from its own two hosts; the CSP is applied. **Tested:** no network, file or pipe API in the page's source; every string cleaned on both sides; the shapes pinned by golden files both sides test against. |
| R5 WebView2 as a prerequisite | Not built (installer, T114). |
| R6 CSS for WebKitGTK as well | Followed in the source; **not tried** on WebKitGTK. |
| R7 tokens only | **Tested:** no colour literal anywhere in the page's source; the 30 contrast pairs in both themes computed from `tokens.css`; the `prefers-color-scheme` block cannot drift from `data-theme="light"`. |
| R8 bounded scene | Built (30 fps cap, stops when hidden, one still frame under reduced motion). **Not measured:** the 4 ms per frame budget inside the Tauri window. |

Three things the implementation changed in the plan:

- **The shell's Rust minimum is 1.90, not 1.88.** Tauri 2.12 itself requires it. The shell is detached from the
  workspace, so the engine's 1.88 is unchanged; CI builds the shell on stable.
- **The IPC client is `crates/dnet-view`, in the workspace, not `src-tauri/src/ipc.rs`.** Everything the window
  decides is testable there without a window or a platform; the shell is glue.
- **The service's action text is advice, not a button label.** The window's button is its own short label per
  action; the service's sentence is shown as text, whole (the first design cut it at 120 characters).
