# UI/UX Design System

**Surface**: `dnet-tray` — Tauri v2 + Svelte 5, unprivileged
**Version**: 3 (2026-10-21, "Orbit") · **Status**: Decided by the owner's delegation (2026-10-21), applied when the UI work starts (T099)
**Governed by**: Constitution Principle VI (honest capability claims) and VII (simplicity)
**Source of truth for values**: [`tokens.css`](./tokens.css). **See it, running**: [`preview.html`](./preview.html)
(serve `docs/design` over HTTP, e.g. `python -m http.server --directory docs/design`; it has every state,
both themes, and recomputes the contrast table live). **Stack evidence**: [ADR-0007](../adr/0007-ui-stack.md).

---

## 0. What changed in version 3

Version 2 was correct and not shippable. The owner's verdict: it looked like a first scaffold, "not
minimalism, but a very starting kind of UI". Version 3 keeps everything v2 got right (honesty, the five
states, the consents, the checks) and replaces the *composition*:

| Owner's request | Version 3 |
|---|---|
| A centred control, with a miniature 3D figure made of dots | The **core**: a rotating figure of ~500 dots at the centre of the window. Its *form* is the state (§5) and it is the on/off control |
| Which Wi-Fi is in use; several networks (two Wi-Fi, a phone, a cable) | Every network is a labelled **moon in orbit** round the core, with a dotted beam; the one carrying traffic has dots flowing to the core (§6) |
| Latency, loss, jitter, ping, "how much it improved", less space | One **instrument strip** of four gauges, plus a **drawer** for detail (§7) |
| A sidebar that is not a sidebar, somewhere else | A floating **dock** at the bottom centre (§8) |
| A better place for the name than a plain title | A **dot-matrix wordmark plate** (§9); the title bar carries no text |
| Fonts, palette, out-of-the-box | An instrument identity: ink, one paper action colour, lamps for state, an ambient wash, a dot grid; DIN-style display face (§10, §11) |

Two of those requests need care, and the design says so rather than hiding it:

- **"Using several networks at the same time to boost speed" is aggregation.** The constitution defers
  it to a separate specification (Principle VII; ADR-0006 P5). **v1 carries traffic over one network and
  keeps the others ready to take over.** The design shows exactly that, and shows the multi-network
  "both at once" picture only as a labelled concept (§6).
- **"How much it improved" cannot be a made-up percentage** (Principle VI). §7 says what can be shown
  truthfully and what never is.

---

## 1. Principles

From earlier versions, unchanged:

1. **Minimal works.** The default path is one control. A user who never opens anything else still gets a
   working tunnel.
2. **Honesty is a design constraint, not a disclaimer.** Best-effort features are labelled best-effort in
   the interface. Overstating what the product does is a defect equal to a functional bug.
3. **Every automatic action is explainable.** Every state change carries a `because`, and the UI shows it.
4. **Never imply protection that is not present.** A "connecting" animation that conceals a failure is a
   defect.
5. **Shape before colour.** Every state is distinguishable in greyscale and at 16 px.
6. **Quiet by default, loud only for failure.** No toasts, no celebration, no "You're protected!".
7. **The service decides; the app shows.** The window never computes a state, a tier or a posture.
8. **The window is optional.** See state, connect, disconnect: all possible from the tray menu.

New in version 3:

9. **The figure is the state.** The thing at the centre of the window is not decoration: its form, motion
   and colour *are* the connection state, and the words below it say the same thing.
10. **One glance, then detail on demand.** The home view answers "is it working, over what, how well" in
    one look and uses little space; everything deeper is a tap away in a drawer, not a page.
11. **Beauty is allowed, deception is not.** The dot figure may be lovely; it may never animate as though
    something were happening that is not (no flowing data when nothing flows; no motion when frozen).

---

## 2. Identity: dot matrix, orbit, instrument

A precision instrument for the worst moment (the network is failing and someone needs the truth), made
with the care of a well-designed object rather than a utility.

- **One visual language: the dot.** The wordmark is dot-matrix; the background is a faint dot grid; the
  core is a figure of dots; the beams between networks are dotted lines; the dock's stations are dots.
  Everything the product draws is a dot or a line of them.
- **Ink and paper.** Surfaces are green-black ink (not grey, not blue-black); the single action colour is
  warm paper (the switch's track, filled buttons, the focus ring). In the light theme this inverts to ink
  on bone, never white.
- **The window takes the state's colour.** A faint wash (≤ 6 %) of the current lamp colour tints the
  stage, so a state is felt before it is read: verdigris connected, brass probing, ember degraded,
  vermilion failed. Lamp colours appear **only** as state; never on a button.
- **Readouts** (numbers) are set like a gauge: a tabular monospace.
- **Words first.** Under the figure is a sentence saying what is true, and below it *why*.

Deliberately not: a purple-to-indigo gradient, a bloom-glow orb, a world map of dots, a shield, the word
"secure". (The dot figure is not an orb with a glow: it has no bloom, no gradient fill, and its form
changes with the state.)

**Personality, in four words:** precise · calm · candid · a little beautiful.

---

## 3. Layout: Orbit

Default window 880 × 600 (minimum 640 × 480), remembered per monitor. Native frame (so Windows snap and
resize keep working), themed to follow the app, with **no title text** (§9).

```
┌────────────────────────────────────────────────────────────────────┐
│ ⠿⠿⠿⠿ DNET ENGINE                                  • LIVE · 1 s ago │  plate · heartbeat
│                                                                    │
│  ╭──────────────╮        · · ·  ▄▄▄  · · ·        ╭────────────╮   │
│  │ ◜ Hostel-5G  │ ·······  (  the core  )  ······· │ ▯ Pixel 8  │   │  the scene:
│  │ ● Carrying   │          ( dot figure )          │ ○ Standby  │   │  core + networks
│  │ 43 ms · 2 %  │                                  │ 88 ms      │   │  (moons)
│  ╰──────────────╯                                  ╰────────────╯   │
│                         Connected                                  │
│        Carrying your traffic over Hostel-5G through …             │  the words
│                     ( ◖● Stabilized )                              │  the control
│ ┌ LATENCY ───┬ JITTER ────┬ LOSS ──────┬ STABILITY ───────┬──┐     │
│ │ 43 ms ~~~~ │ 4 ms ~~~~  │ 2 % ~~~~   │ 0 drops          │ ⌃│     │  instrument strip
│ └────────────┴────────────┴────────────┴──────────────────┴──┘     │
│            ( ◉ STATUS · ENDPOINTS · RULES · ACTIVITY · SETTINGS )  │  the dock
└────────────────────────────────────────────────────────────────────┘
```

| Region | Content | Rule |
|---|---|---|
| **Plate** | Dot-matrix wordmark; click opens About | The only place the name is set large |
| **Heartbeat** | "Live · updated 1 s ago" | Never show a stale reading as current (§12) |
| **Scene** | The core and the networks | Decorative canvas + real DOM chips (§5, §6) |
| **Words** | State word (display face), the `because`, the switch | One primary action; failure replaces the words with the cause and its action |
| **Strip** | Latency · Jitter · Loss · Stability, each with a 40-sample trace | One row, ~70 px |
| **Drawer** | Per-network table; session counters | Overlay (no layout shift); opens from the strip's chevron |
| **Dock** | The five destinations | Floating pill, bottom centre |

Responsive: at ≤ 960 px the chips move closer in; at ≤ 760 px the dock shows a label only on the current
destination; at ≤ 720 px the strip becomes two rows of two. Nothing scrolls horizontally down to 320 CSS
px (browser zoom of 400 %).

**Quick switcher.** `Ctrl+K` opens a small command box ("Go to Rules", "Stabilize", "Add endpoint"), so
the dock is never the only way and keyboard users are never slower.

---

## 4. Principles for the home view, applied

Status is the home. Endpoints, Rules, Activity and Settings are full views reached from the dock, entered
with a short cross-fade (≤ 160 ms), each with its own empty state that says what it is for and offers one
action. Advanced options live behind disclosure inside those views, never on Status. First run is the
wizard (Flow 1), then Status. There is no onboarding carousel.

---

## 5. The core: a figure of dots whose form is the state

~520 points on a 2D canvas, projected in perspective, drawn back to front, with size and opacity by depth.
No 3D library (a library such as three.js would cost far more than the figure is worth). When the state
changes the points glide to their new positions, so the change is seen, not cut.

| State | Form | Motion | Colour |
|---|---|---|---|
| Not connected | **Ring**: four dotted tracks in a tilted flat circle, dormant | Almost still | Neutral |
| Probing | The ring, with a bright **scan arc** sweeping round it | Arc travels; the ring turns | Brass |
| Connected | A solid **sphere** (a Fibonacci lattice) | Slow rotation; faint twinkle | Verdigris |
| Degraded | The sphere with **one hemisphere lit**; its edge flickers | Slower; ragged | Ember |
| Failed | A **cube** with gaps and a few dropouts | Tumbles slowly | Vermilion |

The forms are the five lamp silhouettes (ring, ring + arc, disc, half-disc, square) in three dimensions,
so "shape before colour" holds even in a greyscale or forced-colours rendering.

**The control.** The core is clickable (pointer only), but the *accessible* control is the labelled
**switch** below it: a `role="switch"` pill whose word says the state it is in ("Stabilize", "Working…",
"Stabilized"). The canvas and the click target are `aria-hidden`; the networks and the words are real DOM
text. Pressing the switch to stop is immediate (leaving unprotected is the safe default direction).

**Budget and behaviour.**

- Measured in the preview, on this machine: **0.3–1.3 ms per frame** on average (max 1.8) at a
  **30 fps cap**, i.e. **at most about 4 % of one core, and only while the window is open and visible**.
  No GPU. T116 re-measures in the real app; if the average ever exceeds 4 ms the figure drops to 15 fps
  and fewer points, rather than costing the user's battery.
- **Nothing runs while the window is hidden or minimised** (`visibilitychange`), and the web view is
  destroyed after the grace period (ADR-0007 R2).
- **Reduced motion** (`prefers-reduced-motion`): no rotation, no flow, no sweep; each state is a single
  static frame, and the words carry progress ("Trying Hysteria 2 — 6 s of 15 s").
- **Honesty (principle 11).** Dots flow along a beam only for the network that is carrying traffic; the
  beam of a lossy network is drawn ragged; a lost network is a sparse dashed line.

---

## 6. Networks: which one is carrying, and what is ready

Each network the computer has is a **chip** (a labelled card) placed in orbit, with a dotted beam to the
core. A chip shows the kind (Wi-Fi, mobile, cable), the **name** (for Wi-Fi, the network name), a role, and
latency and loss. Roles carry a *shape* as well as words:

| Role | Marker | Words | Beam |
|---|---|---|---|
| Carrying | solid dot, state colour | "Carrying" | Dots flow toward the core |
| Standby | ring | "Standby · ready" | Faint static dots |
| Available (nothing running) | ring | "Available" | Faint static dots |
| Unavailable | ✕, dashed chip | "Unavailable" (e.g. "cable unplugged") | Sparse dashes |

Up to four chips fit; further networks are listed in the drawer.

**What v1 does:** one network carries; the others are measured and kept ready, and if the carrying one
degrades or disappears the engine moves the tunnel to the best standby and the ledger says why (FR-016…019).
That is the "two Wi-Fi and a phone" case, honestly: all three are visible, one works, the others are
insurance.

**What v1 does not do:** use two networks at once to add their speed. That is aggregation: a separate
specification by rule (Principle VII, ADR-0006 P5). The preview contains it as **"Concept: both at once"**,
with a permanent badge "Concept · using several networks at once is not in v1", so the owner can see the
idea realised and nobody mistakes it for a feature. The chip and beam model already supports it (two
carrying chips with a share), which is the reason for choosing this model.

**Privacy.** A Wi-Fi name can reveal where a person is. Names are shown only in the local window, and the
diagnostics bundle (T112) excludes them by default, as it excludes browsing destinations.

---

## 7. Instruments: the strip and the drawer

The strip is one row, four cells; each has a label, a value in the readout face, a unit, a 40-sample trace
and one line of context. It replaces a card per metric, which is where v2 spent its space.

| Cell | Meaning | Context line |
|---|---|---|
| **Latency** (the ping) | Smoothed round-trip time over the carrying network | "10 min typical 40–48" |
| **Jitter** | How much that round-trip time varies | "steady" / "was 4 ms" |
| **Loss** | Fraction of probes lost, smoothed | "typical 1–3" |
| **Stability** | Times the carrying network was poor with no way out, this session | "0 poor spells" / "3 h 12 m · 2 network changes" |

"Ping" and "latency" are the same measurement; the cell is labelled once, **Latency**, with "ping" as its
accessible description, not shown twice. Traces are decoration; the value and its context carry the
meaning, and the cell's accessible name states it ("Latency 43 milliseconds, steady").

The **drawer** (the chevron at the strip's end) is an overlay, so opening it moves nothing. It holds the
per-network table (role, latency, jitter, loss) and the session counters: connected for, network changes,
how many of those were under a Tier 2 profile (which breaks established connections), method switches,
poor spells, and the longest poor spell, counted since the session began. (An earlier draft listed
"connections dropped" and "longest interruption": nothing measures when traffic stopped, so neither can
be shown without guessing; see §19.)

**"How much it improved", said honestly.** There are three classes of statement:

1. **Always true and measured:** what the product *did*: network changes, switches of method and of
   endpoint, poor spells and the longest one, time connected. These are counters of events the engine
   recorded. They are the headline of the Stability cell.
2. **True only when measured on request:** a comparison with *not* using the product (for instance
   latency through the tunnel against the same destination direct). It is an explicit action the user
   starts, labelled with the time and method, and not run in the background. **Not in v1.**
3. **Never:** a marketing figure such as "37 % faster" or "boosted". A tunnel adds overhead; the product's
   value is that the connection *exists* and *stays*, and the interface says so.

The drawer states: "Counted on this computer. Nothing here compares with not using DNet Engine."

---

## 8. Navigation: the dock

A floating pill, bottom centre, five stations on a dotted line: **Status · Endpoints · Rules · Activity ·
Settings**. The current one has a filled outline and a dot above it; the others show an icon and a
label (labels fold to the current one only below 760 px). It replaces the left sidebar for these reasons:
it costs about 56 px of height instead of 188 px of width; the core stays exactly centred; and thumb-reach
and pointer-reach are the same wherever the window is dragged.

Considered and rejected: a **radial menu** round the core (poor keyboard and screen-reader behaviour, and
it would fight the networks for the same space); an **edge scrubber** of dots (labels hidden until hover,
which fails keyboard and touch); a **hamburger** (hides the only navigation). The dock is a real
`<nav>` of links: tab order is left to right, the current page is `aria-current="page"`, and `Ctrl+K`
duplicates it.

---

## 9. The name and the title bar

The title bar carries **no text**: a native title of "DNet Engine" in a bar is the plainest possible
statement of a name, and it is the thing the owner found "way too simple". Instead:

- **Plate.** At the top left, "DNET" is set in a 5 × 7 dot matrix (64 dots) with a small tracked
  "ENGINE" beside it. On first open the dots light in sequence (≈ 0.6 s, once; none under reduced
  motion). Clicking it opens About, the one place vendor names appear (`lint-branding`).
- **Heartbeat.** At the top right, "Live · updated 1 s ago": the freshness of the reading (§12).
- The wordmark is the product's working name and changes only with the release name (ADR-0006 P6).

---

## 10. Colour

Values live in [`tokens.css`](./tokens.css). WCAG 2.2: **4.5 : 1** for text, **3 : 1** for the edge of a
control, a lamp or a focus ring (SC 1.4.3, 1.4.11, 2.4.13). **All 30 checked pairs pass in both themes**,
including the ambient wash; the table is recomputed live in `preview.html`, and the same pairs are
asserted in CI once the app exists.

| Token | Dark | Light | Role |
|---|---|---|---|
| `--c-base` | `#1b2523` | `#f7f5ef` | The page |
| `--c-card` | `#222e2b` | `#fdfcf9` | A panel |
| `--c-raised` | `#2a3834` | `#ffffff` | A menu, a dialog, a hover, the drawer |
| `--c-line` | `#34453f` | `#e6e2d8` | A separator (decoration) |
| `--c-line-strong` | `#71897e` | `#7e8c85` | The edge of anything operable |
| `--c-text` / `-2` / `-3` | `#eef3f0` / `#b8c7c0` / `#9bafa7` | `#16221e` / `#4a5a53` / `#566660` | Body / supporting / labels |
| `--c-paper` / `--c-on-paper` | `#f1ebdd` / `#14201c` | `#14201c` / `#f7f5ef` | The action colour |
| `--c-focus` | `#f1ebdd` | `#14201c` | Focus ring |
| `--c-ok` · `probe` · `warn` · `fail` | `#4fdcb0` · `#ecc95e` · `#f5a55c` · `#ff8478` | `#0a7556` · `#7a5c00` · `#a24e00` · `#b3261e` | Lamps: connected · probing · degraded · failed |

**Ambient wash.** The stage background is the page colour with up to `--ambient-strength` (6 %) of the
current lamp colour, plus a dot grid at 8 % of the text colour, masked to fade at the edges. Words on the
stage keep 4.5 : 1 against the *worst* wash (dark: 5.9 minimum; light: 5.1 minimum). **The first run of
this check in v3 failed in the light theme**: tertiary text was 4.29–4.38 : 1 over the wash. The token
(`--c-text-3`, light) was darkened from `#5b6b64` to `#566660`. That is the check doing its job; do not
"tidy" the value back.

**Lighter, v3.1 (2026-10-22).** The owner found the theme "too heavy". The weight came from near-black
surfaces, an outline on every box, a strong wash, and semibold tracked labels. Changes: the dark theme is
lifted from near-black (`#0e1413`) to a soft charcoal-teal (`#1b2523`); the light theme is airier bone
(`#f7f5ef`); the wash is 6 % (was 9 %) and the dot grid 8 % (was 13 %); the strip, the network chips and
the dock lose their outlines (surface steps and a soft shadow separate them; only controls keep an edge,
as WCAG 1.4.11 requires); display and label weights go from 600 to 500, readouts to 400; the figure's dots
are smaller and fainter. All 30 pairs still pass; the tightest are the control edges (dark 3.3–4.2, light
3.2–3.5), which is why they are the tokens never to "tidy". If dark is still too heavy, the light theme
is the airy option and follows the system setting.

Rules: a lamp colour only ever means state; the paper colour is the only fill that means "press this";
no pure black or white surfaces; forced-colours mode maps tokens to system colours and the shapes carry
state; the theme follows the system unless the user forces one.

---

## 11. Typography

| Voice | Face | Used for |
|---|---|---|
| **Display** | **Bahnschrift** (DIN-style variable face that ships with Windows 10/11), semibold, slightly condensed | The state word, labels, the dock, the plate's "ENGINE", the dialogs' headings |
| **UI** | Segoe UI Variable Text | Sentences, helper text, table cells |
| **Readout** | Cascadia Mono (ships with Windows 11), tabular | Every number: values, time, chips' metrics |

Why these: Bahnschrift is the typeface of dashboards and instrument clusters, which is the identity;
it ships with the OS, so it costs **no payload**, and body text stays in the OS face so every script
(Devanagari, Arabic, CJK) shapes correctly with no bundled font. Elsewhere the stacks fall back to the
system UI face, and the layout is sized by containers, not by glyph widths, so a fallback does not break
it. Scale: 10 (labels, tracked caps) · 12 · 13 · 14 · 16 · 20 · 28/30. Body never below 13; the
state word 30 (20 when it is a failure *sentence*).

*Decision (owner's delegation):* use the system faces above; no font is bundled in v1. If a bundled face
is ever wanted, an OFL monospaced face subset under 30 KB is the limit (licence text in
`THIRD-PARTY-NOTICES.md`, file checksum verified at build; confirm the licence from upstream at that time).

---

## 12. Components and states

Every component defines **rest · hover · active · focus-visible · disabled · busy · error**; focus is a
2 px `--c-focus` ring with a 2 px offset, never removed and never colour-only. Native elements first
(`<dialog>`, `<details>`, `<input>`, `<nav>`), no component library.

| Component | Notes |
|---|---|
| **Switch** (pill) | `role="switch"`, 44 high; the word says the state; busy = hatched track, `aria-busy` |
| **Network chip** | A list item; name in the display face; role marker + words; latency and loss in the readout face; never wider than its text; kept inside the window |
| **Instrument cell** | Label (10 px tracked caps), value, unit, trace, context; the trace is `aria-hidden` |
| **Drawer** | Overlay panel; closes with `Esc`; returns focus to the chevron |
| **Dock** | `<nav>` of links; the current one has `aria-current="page"` |
| **Heartbeat** | Greys and reads "Last update 40 s ago" when the service has been silent past its heartbeat; the figure freezes and the words say "last known" |
| **Notice** | A standing consent with one action; never auto-dismissed |
| **Form field** | Visible label above, error text replacing helper text, never colour-only; 36 px high |
| **Dialog** | §13 |

No toasts. A change is announced through the live region and recorded in the Activity view.

---

## 13. Consent surfaces

Four states require informed consent, each a modal `<dialog>` that states the **consequence**:

| Consent | Why it interrupts | Consequence shown |
|---|---|---|
| **Acceptable use** (FR-032) | Use on a managed network may violate its AUP | The disciplinary risk, stated plainly |
| **Tier 2 profile** (FR-016b) | Established connections will not survive an interface change | "Your downloads and calls will drop when you switch networks." |
| **Brutal congestion control** (FR-006) | Degrades everyone on the same access point | "This makes the Wi-Fi worse for everyone around you, including you." |
| **Encrypted DNS override** (FR-025a) | Overrides the browser's own privacy setting | "Turning this off means per-site rules stop working for your browser." |

Rules: **equal weight** buttons (neither is the filled primary); initial focus on the **safe** choice;
`Esc` declines; the consequence is a callout before the buttons; the buttons are verbs that say what
happens ("Connect anyway", "Don't connect"); standing consents stay visible as a notice and a count; each
is recorded with the time and the exact text the user saw.

---

## 14. Failure presentation and copy

Seven causes, seven distinct messages, one action each (SC-020). On failure the **core becomes the cube**,
the state word becomes the cause as a sentence (20 px), the detail follows, and the action is the one
primary button.

| Cause | Message | Action |
|---|---|---|
| `NoEndpointReachable` | "None of your endpoints are reachable." | Check endpoints / add another |
| `AllProfilesBlocked` | "This network is blocking every connection method." | Retry / update profiles |
| `CaptivePortalUnsatisfied` | "This network needs you to log in first." | Open login page |
| `InsufficientPrivilege` | "DNet Engine needs administrator rights." | How to grant them |
| `CoreFailedPersistently` | "A component keeps failing to start." | View diagnostics |
| `NoUsablePath` | "No usable network connection." | Show adapter state |
| `ConfigurationInvalid` | "Configuration is invalid: {detail}." | Open the offending setting |

**Voice.** Plain, active, present tense, concrete numbers; says what changed and why; never "Oops", an
exclamation mark, or "protected / secure / private / anonymous" (ADR-0006 §3). Protocol names as named;
never the primary core or Wintun outside About. Every sentence is a message template with named
placeholders, not a concatenation.

---

## 15. Accessibility (WCAG 2.2 AA is the floor)

| Criterion | How it is met |
|---|---|
| 1.1.1 Non-text | The canvas is `aria-hidden`; every meaning in it is also text (chips, words, strip) |
| 1.3.x Structure | Landmarks (`header`, `main`, `nav`), one `h1`, the networks as a list, DOM order = reading order |
| 1.4.1 Colour | State = form + words + colour; role = marker + words |
| 1.4.3 / 1.4.11 Contrast | §10; 30 pairs including the ambient wash |
| 1.4.4 / 1.4.10 / 1.4.12 | Reflows to 320 CSS px and 400 % zoom; honours the OS text size; no fixed text heights |
| 2.1.x Keyboard | Everything operable; no trap; `Esc` closes the drawer and dialogs; `Ctrl+K` switcher |
| 2.2.2 Pause, stop, hide | The figure stops when the window is hidden and under reduced motion; no content depends on it |
| 2.4.x Focus | Logical order; a 2 px ring at ≥ 3 : 1; never hidden behind the drawer or dock |
| 2.5.8 Target size | Every target ≥ 36 × 36 |
| 4.1.2 / 4.1.3 | Native roles; a polite live region announces each state change (assertive only for a failure) |

`prefers-reduced-motion` and `forced-colors` are supported. The tray menu is native, so its screen-reader
and keyboard behaviour is the system's. Narrator and NVDA each get a manual pass at T111; axe, contrast
and forced-colours screenshots run in CI from T099.

---

## 16. Internationalisation

All text lives in message files with named placeholders; CSS uses logical properties; layouts allow ~40 %
growth (chips and cells are sized by content, with a minimum); numbers, dates and plurals go through
`Intl`; the dock labels and the 10 px caps labels must remain legible in the target scripts (tracked caps
are applied only to Latin and fall back to normal case elsewhere). v1 ships English only; this keeps the
door open.

---

## 17. Safety rules for the UI

1. **Strings from the service are text** (`textContent` / Svelte's default escaping); `{@html}`,
   `innerHTML` with data, and `eval` are banned by lint. A Wi-Fi name is attacker-influenced text: it is
   handled exactly like the rest.
2. **Strip before show:** control and bidirectional-override characters are removed from any service
   string (the rule `dnetctl` applies in `render::plain`).
3. **The web view never touches the pipe.** The Rust side owns the `dnet-ipc` client, decodes replies with
   the typed protocol, and passes validated view-models; Tauri capabilities are the minimum.
4. **CSP** `default-src 'self'`; no remote origins, no inline script; developer tools off in release.
5. **No claim without a source.** A tier, a path, a role or a figure shown on screen comes from the
   service's reply; the UI never infers one.

---

## 18. Performance

Measured baselines (ADR-0007 §2): tray only **3.5 MB** private; window open **94 MB**; destroyed again
**4.8 MB** within a sample; cold open ≈ **440 ms**. The scene adds ≤ ~4 % of one core while visible (§5).
Rules: destroy the web view after the grace period; no timers or subscriptions while hidden; animate
`transform`/`opacity`/canvas only; JS ≤ 150 KB gzipped; no UI, animation or 3D library; the scene degrades
(15 fps, fewer points) before it costs the user battery.

---

## 19. Data the interface needs, and where it stands

The design asks for more than the control protocol sends today. Honest status, so none of it is built as
if it already existed:

| Needed by | Source | Today |
|---|---|---|
| State word, `because`, profile, tier, endpoint | `GetState`, event stream | **Available** |
| The list of networks: kind, role (carrying / standby / unavailable) | `GetPaths` (T144) | **Available** (built 2026-10-22); only while a tunnel is up |
| Latency, jitter, loss **per network**, and whether it was measured | `GetPaths` | **Available**, for the profile the service steers (AmneziaWG); an observed profile has none, and says `measured: false` |
| The Wi-Fi **name** | The system's WLAN service, via `GetPaths` | **Available when Windows allows it**: recent Windows 11 refuses until location access is on, and the name is then `null` (show the kind) |
| 40-sample traces; "usually 38 to 52 ms" | `GetPaths` (`trace_ms`, `typical_ms`) | **Available** (a ten-minute history per network in the service) |
| Session counters (connected for, network changes, those that break connections, method switches, poor spells, longest poor spell) | `GetStats`, from recorded events | **Available**. "Drops" and "interruption length" are **not** provided: nothing measures when traffic stopped |
| "Updated N s ago" | `as_of_unix_ms` on `GetPaths` | **Available** |
| Degradation as state, not only as an event | `GetPaths.degraded` | **Available** |
| Throughput | The probe race at connect | Measured **once**, at connect; not continuous, so **not shown** |

These became task **T144** (built 2026-10-22: two additive read-only requests, no version bump, a service
that predates them answers "unknown request", security-reviewed because it is the IPC boundary). The UI work (T099…) can be built against a
mock of it, as `dnetctl` was built against the dispatch in memory.

---

## 20. Rejected patterns

Purple-to-indigo gradients · a bloom-glow orb · world maps and shield icons · lone cards floating in
empty space · low-contrast grey body text · oversized blunt shadows · a bare spinner as the only loading
state · toasts · colour as the only carrier of state · a primary-styled button on a risk consent · a
sidebar occupying a fifth of the window for five links · a plain product name in the title bar ·
a made-up "improvement" percentage · flowing dots when nothing flows · best-effort features presented as
guarantees · "secure", "private", "anonymous", "protected".

---

## 21. Decisions

The owner delegated these on 2026-10-21 ("I will leave the decisions to you"); they are recorded as made.

| ID | Decision | Made |
|---|---|---|
| D-UI-1 | The identity of §2 (dot matrix, orbit, ink and paper, lamps) | **Adopted**, in the "Orbit" composition of §3; the owner reviews the running preview and may redirect |
| D-UI-2 | Native tray menu; the window is the only web view | **Adopted** (ADR-0007) |
| D-UI-3 | Fonts | **System faces only** (Bahnschrift, Segoe UI Variable, Cascadia Mono); none bundled in v1 |
| D-UI-4 | SC-013 reworded to name its state and metric | **Adopted, and applied to `spec.md` 2026-10-24**: "idle, window closed, combined private memory ≤ 150 MB"; "window open ≤ 300 MB private; open → loaded ≤ 600 ms" (`spec.md` to be amended with the next spec edit) |
| D-UI-5 | Release name | **Open** (ADR-0006 P6); the wordmark is the working name |
| Rust floor | 1.83 → 1.88 | **Adopted** (T143: 1.85 was proposed, but the dependency set already needed 1.88) |
| Aggregation | Shown only as a labelled concept | **Adopted**; a real feature needs its own specification |

---

## 22. How this is verified

- **Now:** `preview.html` shows every state, both themes, reduced motion, narrow widths, and recomputes
  the 30 contrast pairs live; it also reports the scene's cost per frame.
- **T099 onward (CI):** the 30 pairs as a unit test on `tokens.css`; axe on every view and state;
  forced-colours and reduced-motion screenshots; no colour literal outside `tokens.css`; `lint-branding`.
- **T116:** memory in both states, and the scene's CPU, with the real cores running.
- **T111:** an unfamiliar person reaches a working endpoint unaided (SC-009); Narrator and NVDA pass.
