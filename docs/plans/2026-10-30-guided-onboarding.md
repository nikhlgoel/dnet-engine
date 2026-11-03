# Plan: guided server setup, onboarding, server housekeeping, test hardening

Written 2026-10-30 from the owner's brief of the same date. Status words follow Principle VI: **built** =
written and tested here; **verified** = run on Windows or a real server. Nothing is verified unless it says so.

## 1. Decisions taken (owner, 2026-10-30)

1. **Cloud server is the default and recommended path.** The program on the person's computer is one
   installed application; the person brings their own server (constitution: the project operates none).
2. Onboarding offers **two options side by side with pros and cons**: "Your own server" (recommended) and
   "Without a server". The second is **not** the tunnel product; see 2.
3. Onboarding is a **step-by-step guide for non-technical people**: which page, what to type, what to click,
   what to copy back. It stays reachable from the Servers page so a person who forgot can add another server.
4. The window is a dashboard (status, networks, bandwidth, activity). Settings is categorised; **About is a
   separate page**, not a Settings category. The Servers page is rewritten in plain words.
5. Free servers must not fill their disk: the server keeps itself small and clean.
6. Tests: a large, *validated* expansion (section 7). Not a number target.

## 2. What "without a server" honestly offers

Everything that gets through a network that blocks or interferes needs the other end of a tunnel. Without a
server there is none. So the second option is shown with its real content, not as a smaller copy of the first:

| | Your own server (recommended) | Without a server |
|---|---|---|
| Keeps working when a network blocks or throttles services | **Yes** (three connection methods, measured per network) | **No** |
| Switches between Wi-Fi, Ethernet, phone tether and survives a drop | Yes | Yes |
| Helps with Wi-Fi login pages (captive portals) | Yes | Yes |
| Restores the network exactly after a crash or uninstall | Yes | Yes |
| Needs | A free or cheap cloud account (card check), ~20 minutes once | Nothing |
| Ongoing cost / dependency | Free tier limits; the provider can change them | None |

Built later and only on the owner's say-so: the "without a server" mode itself (connection switching and
repair without a tunnel). The option is shown in the guide as "available soon" until it exists; it must not
be offered as working (Principle VI).

## 3. Provider research (primary sources, fetched 2026-10-30)

| Provider | Verified facts | Source |
|---|---|---|
| **Oracle Cloud Always Free** | Phone number **and credit card** needed "for most users"; card not charged unless upgraded. Trial $300 for up to 30 days; Always Free resources continue after. **Home region is chosen at sign-up and Always Free compute works only there.** Compute: up to two `VM.Standard.E2.1.Micro` (1 GB RAM, **up to 50 Mbps**) or Arm A1 totalling 2 OCPU / 12 GB (provisioning more disables then deletes the extra after 30 days). **10 TB/month outbound.** Idle instances (7-day p95 CPU < 20% and network < 20%, and memory < 20% on A1) **may be reclaimed**. | docs.oracle.com FreeTier pages; Always Free Resources |
| **Google Cloud** | Free e2-micro only in `us-west1`, `us-central1`, `us-east1`; 30 GB standard disk; **only 1 GB/month outbound** (excluding China, Australia); card required; Google may change limits with 30 days' notice. **1 GB a month is not usable as a tunnel host.** | docs.cloud.google.com free-cloud-features |
| **AWS** | Free plan: up to $200 credits; **account closes after 6 months or when credits run out**. Not a lasting free option. | aws.amazon.com/free |
| Azure, small no-card hosts | **Not verified from primary sources.** Not recommended in the guide. | — |

Consequence, said plainly in the guide: **Oracle Always Free is the only lasting free option found.** It needs a
card for identity checks, it can be short of capacity in a region, and it can reclaim an idle server. Anyone
else can use *any* Ubuntu or Debian server with a public IPv4 address (the "I have a server" guide, paid or
not); the same script runs there.

Not verifiable without the live console, so **marked in the guide as "wording may differ"** and checked by
the owner (section 8): the exact button and field labels in Oracle's console. Where Oracle's documentation
gives no labels the guide says what to look for, not an invented label.

## 4. The flow (what already exists, and the one real gap)

Already built and tested: `bootstrap::script` makes one script with **no secret in it**; the server makes its
own keys and prints one `DNET-BOOTSTRAP-REPORT {json}` line; `BootstrapReport::parse` reads it as hostile
input, `check_against` compares it with what was asked, `credentials` builds the sealed credentials.
`manual.rs` adds a server by address.

**Gap 1 (blocks everything): no Linux server cores are built or published** (tasks.md T093 gap). The script
downloads pinned binaries by URL and SHA-256; none exist. Fix: `xtask build-server-cores` builds linux amd64
and arm64 from the same pinned commits as the client, writes a pin table, and the release workflow publishes
them as assets of the release the client was built from (static files, not a service).

**Gap 2: no way to run the flow from the window.** New requests, service-held pending plan:
`PrepareServer { arch }` → the script text and the ports to open (the same script comes back until the setup is
used or expires, six hours); `FinishServer { label, host, report }` → parses the pasted report, checks it
against the pending plan, seals the credentials, adds the endpoint. Security review done (tasks.md T150).

## 5. The guide the person sees (Oracle path)

1. What you need, and why a card is asked (not charged). 2. Create the account; **choose the home region
carefully** (the free server can only be made there). 3. Choose Arm or AMD (this asks the service for the
script now, so a build that cannot set servers up says so before the person does any work). 4. Create the
server: Ubuntu, the shape, a public IPv4 address, **an SSH key**. 5. Open three ports (a table with the values):
UDP 51820, UDP 44443, TCP 8443. 6. Connect with ssh from PowerShell (the command is built from what the person
types, only from parts that could be real) and paste the block. 7. Paste the result back; the app checks it and
adds the server. 8. Turn it on. (Eight steps; the Oracle path and the "any other server" path share steps 5–8.)
Each step: where to go, what to enter, what to click, what you should see, what to do if you do not.

## 6. Server housekeeping (free-tier safe)

Built into the bootstrap script, each checked by a test on the script text and `sh -n`: core log level `warn`
(not `info`); journald capped at 100 MB and 14 days; package caches cleaned; a weekly timer that vacuums the
journal and caches and names no key, certificate or configuration path. **Found while checking the plan:** the
guided path did not install the keepalive at all (only the API path did), so the "keeps the server from being
reclaimed" claim would have been false; the keepalive is now part of the script and the script fails if it is
not running. Oracle's rule (verified) calls a server idle only when CPU p95 **and** network **and** (Arm) memory
are all under 20%, so one busy measure is enough; the keepalive's duty cycle is about 10% at full CPU, so the p95
is high. Whether that survives a real week is an owner check. Not built, and dropped from the plan: a separate
health timer (systemd already restarts a failed core: `Restart=on-failure`) and anything about swap.

## 7. Test plan (validated, not counted)

A test only counts if it can fail. Rules: every new test is run **red first** where it targets a defect, and each
suite below is checked with **mutation testing** on its crate (`cargo mutants`; surviving mutants are either
killed with a test or explained). Categories, in order of where bugs are most expensive:

| # | Area | Method |
|---|---|---|
| 1 | Everything parsed from outside: report, feed, IPC requests, config files, rule patterns | proptest (arbitrary and structure-aware), size and nesting bounds, no panic, no echo of input |
| 2 | Routing / DNS / undo journal | state-machine properties: any sequence of connect/fail/disconnect/crash ends restored |
| 3 | Rule evaluation and precedence | properties: user rules never outrank built-ins; endpoint bypass first |
| 4 | Service lifecycle (T147/T148) | paused-clock scenario tests: boot ordering, flapping network, disconnect races |
| 5 | Script generation | hostile-value matrix per field; `sh -n`; golden file for the script |
| 6 | Window | component tests per state, a11y (axe), message length limits |
| 7 | Windows-only | owner gates (cannot run here) |

Target in this session: add what can be validated, report the **real number added and bugs found**, and list
what the sweep could not reach. A figure of 10,000 would be reachable only by generating cases, which proves
little; the plan prefers fewer tests that are known to fail when the code is wrong.

## 8. Not verified / owner steps

Live Oracle console labels and capacity; the script on a real Ubuntu/Oracle Linux instance; keepalive vs the
combined idle rule; Windows installer and service (LOCAL-COMMANDS §6–§7); signed installer (deferred by the
constitution). Linux/macOS desktop builds remain a separate decision (ADR-0005; macOS is excluded by the
constitution, a rule the owner may change).

## 9. Order of work

1 plan (this file) → 2 server-core build → 3 housekeeping → 4 `PrepareServer`/`FinishServer` end to end →
5 onboarding, guide, servers page, About separate → 6 test sweep with mutation checks → 7 re-read this plan
against what was built; correct either.

## 10. Status after building (2026-10-30) — plan re-read against the work

| Plan item | Built | Differences found and corrected |
|---|---|---|
| Provider research | yes, §3 | Console wording unverified, said so in the guide |
| Server cores (§4 gap 1) | yes: real build of both cores for both processors; the real amd64 core accepted the script's configuration | script had no processor check and the report was not tied to one script: both added |
| `PrepareServer`/`FinishServer` (§4 gap 2) | yes, end to end through the window's bridge | wait raised to 6 h; same script returned on repeat; keepalive missing from the guided path (§6) |
| Guide, two-option screen, Servers page, Settings groups, About separate | yes | About was already outside Settings' groups (a button and the logo); the Servers page now says what a server is |
| Housekeeping | yes (§6) | two planned items dropped, explained there |
| Tests (§7) | see tasks.md T149–T152; a model-based test of the undo registry (1,500 random sequences) and mutation checks on the new modules | the undo model found a **narrow design limit**, recorded in tasks.md; nothing in the registry was changed |
| "Without a server" mode | **not built**; shown, not selectable | would be a different product; owner decision before it is started |
| Homebrew / macOS / Linux desktop | not started | constitution excludes macOS (a rule the owner may change); Linux is ADR-0005 |
