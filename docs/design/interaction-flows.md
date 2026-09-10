# Interaction Flows

User journeys for `dnet-tray`. Each maps to a user story in
[`spec.md`](../../specs/001-network-resilience-client/spec.md).

---

## Flow 1 — First run (US2, US1)

The hardest flow in the product: someone who has never provisioned a server must reach a working
tunnel unaided in under 20 minutes (SC-009), with no documentation beyond the wizard (SC-010).

```
Install --> service registration (elevation prompt, explained before it appears)
   |
   v
Acceptable-use disclosure --> must be acknowledged, cannot be skipped
   |
   v
"Do you already have a server?"
   +-- Yes --> manual endpoint entry ------------------+
   +-- No  --> provisioning wizard                     |
                 |                                     |
                 +- 1. What this needs, and how to     |
                 |     revoke it afterwards            |
                 |     (shown BEFORE asking)           |
                 +- 2. Guided scoped-credential setup  |
                 +- 3. Region choice, with latency      |
                 +- 4. Provisioning, live progress      |
                 |     +- capacity exhausted? --> alternative regions, retryable
                 +- 5. Server bootstrap                 |
                 +- 6. Reachability verified -----------+   no endpoint exists until this passes
                 +- 7. "Delete the credential?"             defaults to YES
                                                       |
                                                       v
Encrypted-DNS disclosure --> blocked by default, one-click opt-out, consequence stated
   |
   v
Stabilize --> Probing --> Connected
```

**Design rule**: the wizard states what it needs and how to revoke it *before* asking for anything.
Asking first and explaining later is how credential prompts train people into bad habits.

---

## Flow 2 — Everyday connect (US1)

```
Tray click --> Stabilize
   |
   v
Probing - "Trying AmneziaWG..."          <=15 s when the first profile works
   |       names WHICH profile, and for how long
   v
Connected - profile, tier, endpoint, carrying path, live quality
```

If a Tier 2 profile would be selected while a Tier 1 profile is viable, the connection **pauses for
consent** rather than silently accepting weaker failover (IPC-04).

---

## Flow 3 — Automatic recovery (US1, US4)

Entirely unattended. The user's only involvement is being told what happened, afterwards.

```
Connected
   +-- active profile blocked mid-session
   |      +--> "AmneziaWG stopped working - switched to Hysteria 2"     <=30 s
   +-- endpoint unreachable
   |      +--> "oracle-mumbai unreachable - switched to oracle-sg"      <=30 s
   +-- all profiles blocked
          +--> Failed: "This network is blocking every method."  [Retry]
```

Every message names **what changed and why**. A bare "Reconnecting..." is not acceptable.

---

## Flow 4 — Path failover (US3)

```
Carrying: Wi-Fi --> quality degrades --> hysteresis window --> Carrying: Cellular
                                          (prevents flapping, SC-007)
```

- **Tier 1 profile** — a transfer in progress continues. The UI notes the switch without alarm.
- **Tier 2 profile** — connections drop. The UI **warned about this at selection time** and repeats
  it here. A surprise at failure time means the earlier warning failed.
- **Only one path available** — no switch is possible. The UI reports the connection as degraded
  rather than implying a switch occurred (FR-019).

---

## Flow 5 — Captive portal (US6)

```
Connect attempt --> Failed: CaptivePortalUnsatisfied
   |                "This network needs you to log in first."  [Open login page]
   v
Browser opens the portal --> user logs in --> Stabilize --> Connected
```

If the portal session expires mid-session, the failure is reported **as a captive portal**, not as a
generic loss of connectivity (US6-3). Distinguishing those two is the entire point of the flow.

---

## Flow 6 — Split routing (US5)

```
Advanced --> Rules
   +-- Add domain rule       [reliable]
   +-- Add IP/CIDR rule      [reliable]
   +-- Add application rule  [best-effort]  <- labelled inline, not in a tooltip
```

Built-in bypass rules (local networks, printers, captive-portal probes, the active endpoint) are
listed as **non-removable**, so users can see why local resources still work and cannot break them by
accident.

Precedence is shown explicitly, and collisions are rejected at entry rather than resolved arbitrarily.

---

## Flow 7 — Disconnect and uninstall

```
Stabilize (toggle off) --> restore routing, DNS, adapters --> Disconnected
Uninstall              --> stop service --> restore --> remove
Crash                  --> on next service start, replay undo records
```

All three paths converge on the same restoration guarantee. Verified by killing `dnetd` mid-session
and asserting networking matches pre-installation exactly (SC-016).
