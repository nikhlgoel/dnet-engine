# UI/UX Design System

**Surface**: `dnet-tray` — Tauri v2 + Svelte 5, unprivileged
**Governed by**: Constitution Principle VI (honest capability claims) and VII (simplicity)

---

## 1. Design principles

**Minimal works.** The default path is one control. Everything else sits behind an explicit
"Advanced" affordance. A user who never opens Advanced must still get a working tunnel.

**Honesty is a design constraint, not a disclaimer.** Best-effort features are labelled best-effort
*in the interface*, not only in documentation. A UI that overstates what the product does is a defect
under Principle VI, equal in severity to a functional bug.

**Every automatic action is explainable.** The user must always be able to answer "why did it do
that?" without reading logs. Every state change carries a `because` string, and the UI surfaces it.

**Never imply protection that is not present.** If no endpoint is reachable, the UI says so plainly.
A "connecting" spinner that conceals a failure is a defect.

---

## 2. Surface architecture

Tray-first. The window is secondary and closes to tray.

```
+---------------------------------+
|  *  DNet Engine                 |   status dot + name
|                                 |
|      +-------------------+      |
|      |    Stabilize      |      |   the single control (FR-036)
|      +-------------------+      |
|                                 |
|  Profile   AmneziaWG   Tier 1   |   tier ALWAYS visible (FR-016b)
|  Endpoint  oracle-mumbai        |
|  Carrying  Wi-Fi - 43 ms - 2%   |
|                                 |
|  !  Encrypted DNS overridden    |   standing consents stay visible
|                                 |
|  Advanced v                     |
+---------------------------------+
```

### Status states

| State | Dot | Meaning |
|---|---|---|
| Disconnected | grey | Idle. Not protected, and says so |
| Probing | amber, pulsing | Racing profiles; names the one being tried |
| Connected | green | Carrying traffic |
| Degraded | amber, static | Connected but the only path is poor — reported, not hidden (FR-019) |
| Failed | red | One of seven distinguishable causes, each with an action |

---

## 3. Typography and colour

System font stack (Segoe UI Variable on Windows 11). Type scale 12/13/15/20 px; tray body at 13 px.
Numerals are **tabular** wherever latency, loss, or throughput appear, so figures do not jitter as
they update.

Surfaces layer rather than float: base, card, elevated — each one step apart, separated by hairline
borders rather than heavy shadows. Colour carries one semantic accent at a time, and status colour is
reserved exclusively for connection state so it never competes with decoration.

| Token | Role |
|---|---|
| `status.connected` | Green — carrying traffic |
| `status.probing` | Amber — transient, animated |
| `status.degraded` | Amber — stable, not animated |
| `status.failed` | Red — actionable failure |
| `accent` | The single interactive accent |
| `text.primary` / `text.secondary` | Body / supporting |

Dark and light are both first-class; the tray follows the OS theme. Contrast floor is WCAG AA (4.5:1)
for **all** text including secondary — a status readout nobody can read is not a status readout.

---

## 4. Motion

Motion communicates state change; it never decorates. Transitions run 120–200 ms, ease-out. The only
continuous animation in the product is the probing pulse, because probing is the only genuinely
indeterminate state. `prefers-reduced-motion` removes all of it.

**No bare spinner as the sole loading indicator.** Probing shows which profile is being tried and for
how long. Indeterminate progress carrying no information is not acceptable.

---

## 5. Consent surfaces

Four states require informed consent. Each is a deliberate interruption rather than a toast, and each
states the *consequence*, not merely the fact.

| Consent | Why it interrupts | Consequence shown |
|---|---|---|
| **Acceptable use** (first run, FR-032) | Use on a managed network may violate its AUP | The disciplinary risk, stated plainly |
| **Tier 2 profile** (FR-016b) | Established connections will not survive an interface change | "Your downloads and calls will drop when you switch networks" |
| **Brutal congestion control** (FR-006) | Degrades everyone on the same access point | "This makes the Wi-Fi worse for everyone around you, including you" |
| **Encrypted DNS override** (FR-025a) | Overrides the browser's own privacy setting | "Turning this off means per-site rules stop working for your browser" |

Standing consents remain visible as warnings in the main view. A consent the user has forgotten
giving is not informed consent.

---

## 6. Honest labelling

| Element | Required label |
|---|---|
| Application rules | **"Best-effort"**, inline — not hidden in a tooltip (FR-023) |
| Domain and IP rules | Shown as reliable, by contrast |
| Active profile | Tier badge, always present |
| Obfuscation | Never claims to hide that a tunnel exists (FR-033) |
| Provisioning credential | Revocation instructions shown **before** the credential is requested |

---

## 7. Failure presentation

Seven causes, seven distinct messages, each with an action. A generic error reaching the UI is a
defect (SC-020).

| Cause | Message | Action |
|---|---|---|
| `NoEndpointReachable` | "None of your endpoints are reachable." | Check endpoints / add another |
| `AllProfilesBlocked` | "This network is blocking every connection method." | Retry / update profiles |
| `CaptivePortalUnsatisfied` | "This network needs you to log in first." | Open login page |
| `InsufficientPrivilege` | "DNet Engine needs administrator rights." | How to grant them |
| `CoreFailedPersistently` | "A component keeps failing to start." | View diagnostics |
| `NoUsablePath` | "No usable network connection." | Show adapter state |
| `ConfigurationInvalid` | "Configuration is invalid: {detail}." | Open the offending setting |

---

## 8. Rejected patterns

Generic purple-to-indigo gradients · lone cards floating in empty space · low-contrast grey body text ·
oversized blunt shadows · bare spinners as the only loading state · static elements lacking hover,
active, and focus-visible states · "connecting..." that conceals a failure · best-effort features
presented as guarantees.
