# Owner gates: what only a Windows machine and a person can close

Written 2026-10-26 from the repository as it stands. Each section says what to run, on what, and what
counts as a pass. None of these has been run for this document; nothing here claims a result. Where a
section depends on an owner decision, the decision is named first.

General rules for every gate:

- Never against an institutional network (Constitution III). Your own home connection, your own phone's
  tether and your own cloud VM are the only networks involved.
- Keep the whole results folder of any run that is not a clean pass, and record the commit (`git rev-parse
  HEAD`) and the core pins (`vendor/*/BUILD-PROVENANCE.md`) next to each result.
- Before any gate, on the Windows machine, from the repository root:

  ```powershell
  cargo run -p xtask -- fetch-vendor
  cargo run -p xtask -- verify-vendor        # expect: verify-vendor: OK
  cargo test --workspace                      # expect: 0 failed
  ```

---

## T098a — the deferred routing-loop gate (SPIKE-R4 / HV-13)

**Decision first.** T098a says "against the endpoint T098 provisioned". Provisioning has a mock provider
only; no real cloud provider is implemented, so T098 cannot produce that endpoint yet. Decide one of:

1. Run T098a now against a cloud VM you create by hand (it is off-subnet by construction, which is what
   the gate needs), and accept that as T098a; or
2. Wait for a real provider and T098.

Separately, whether the 2026-10-20 WSL2-lab PASS counts for anything beyond risk reduction is still yours
(`docs/Research-Critique.md` §6.6).

**Run** (option 1): follow `testing/spike-r4/README.md` §1 (endpoint host), §2 (client, as **LocalSystem**
via PsExec, BUG-007), §3 (reading), §5 (the Hysteria 2 variant), §4 (clean up). Make four runs:

| Run | Arguments | Why |
|---|---|---|
| A1 | `-EndpointIp <vm>` | Profile A, the gate itself |
| A2 | `-EndpointIp <vm> -AltGateway <phone-tether-gateway>` | the host-route rewrite across a real interface change, which every earlier run skipped |
| B1 | `-EndpointIp <vm> -Transport Hy2` | Profile B, never run |
| B2 | `-EndpointIp <vm> -Transport Hy2 -AltGateway <gateway>` | as A2 for Profile B |

**Pass** (each run): exit code 0, verdict `PASS` in `summary.md`, the negative control shows re-entry
(it looped), the physical adapter count is non-zero, the tunnel adapters were found with zero endpoint
packets, the path-change step says `PASS` (A2, B2; `SKIPPED` is not a pass), and nothing is left behind.

**Fail**: exit 1 is a real failure: stop, and per §6.6 revisit research §R4 (and possibly D8) before any
Phase 5–7 work that depends on the transport path is accepted. Exits 2–5 are not results: fix the setup
and run again; a `VACUOUS`, `INVALID` or `INCONCLUSIVE` run never satisfies the gate.

**Then**: tick T055/T098a in `tasks.md` with the four summaries, and close §6.6 in the critique.

---

## T066d — the root key ceremony

The script is `docs/feed-publishing.md` §1–§4; this is the checklist around it.

**Needs**: an offline machine with a Rust toolchain and a checkout of this repository, three separate
encrypted media for the roots and one for the signing key.

1. On the offline machine: `feed-keygen` three roots and one signing key (§1). Write down the four
   **public** keys; nothing else leaves the machine.
2. Online: put the three root public keys in `ROOT_KEYS` and the keys version you will publish in
   `MIN_KEYS_VERSION`, both in `crates/dnetd/src/feed_trust.rs`.
3. Offline: write and sign the keys document (2 of 3 roots) and a first feed (the signing key), §2–§3.
4. On a test machine running a `dnetd` built from step 2: `dnetctl import-feed --keys-file
   keys.envelope --feed-file feed.envelope` (§4).
5. Publish only after step 6 passes.

**Pass**:
- `cargo test -p dnetd` passes with the keys filled in (it checks the anchor is three distinct, valid,
  non-weak points).
- Step 4 exits 0 and names the changes it made (`dnetctl --json import-feed ...` shows
  `"imported": true` and a non-empty `changes`), and the next connection uses the proposed client values
  (visible in the generated core configuration under `%PROGRAMDATA%\DNet Engine\run`).
- Negative checks, each refused with a reason and nothing changed: the keys document signed by one root
  only; the feed signed by a root instead of the signing key; the feed with one byte changed; a keys
  document with a lower version than `MIN_KEYS_VERSION`.
- No private key file exists inside the repository (`git status --ignored` shows none) and none was
  written to the online machine.

**Fail**: anything accepted that should be refused is a defect in the feed code: stop and report it
before anything is published.

---

## T085 — interface-change survival (HV-07, HV-08; SPIKE-R9)

There is no automated `hv_07` test yet (`quickstart.md` names one; it does not exist, see the T085 note).
This is the manual procedure the automated one should later reproduce.

**Needs**: the endpoint from T098a (its harness serves the origin `http://203.0.113.80:8080`, reachable
only through the tunnel), a Windows machine with **two physical paths** (home Wi-Fi and a USB-tethered
phone), `dnetd` installed or running as SYSTEM, and `dnetctl`.

For each of Profile A (`awg-default`) and Profile B (`hy2-default`):

1. Both paths up; Wi-Fi is the default route. `dnetctl connect --profile <id>` and wait for connected.
2. Start a long transfer through the tunnel and keep its output:
   `curl.exe -o big.bin http://203.0.113.80:8080/bytes/524288000` (500 MB; anything that takes at least
   a minute on your connection).
3. About 15 s in: `Disable-NetAdapter -Name "<Wi-Fi adapter>" -Confirm:$false` (elevated).
4. Let it finish. Then `Enable-NetAdapter`, and save `dnetctl events --json` and `dnetctl status --json`.

**Pass (HV-07, per profile)**: curl exits 0 with the full byte count in the **same** transfer (no
restart, no resume); the events show the tunnel moved to the tether without a disconnect; the routing
state afterwards has the host route via the tether's gateway. Repeat three times; all three must pass.

**HV-08, Profile C (`reality-default`)**: before connecting, `dnetctl connect --profile reality-default`
without `--accept-tier2` must be refused with the Tier 2 warning (that is "the UI said so beforehand");
then connect with `--accept-tier2`, repeat steps 2–3. **Pass**: the transfer breaks (expected for TCP),
and the warning was shown first.

**Then** (a code change, test-first, by whoever records it): in `crates/dnet-core/src/tier.rs`, set
`recorded_survival` to `Survived` **only** for a kind that passed all three HV-07 runs, with the core
versions in the doc comment; leave any other at `NotMeasured` (or `Broke` if it failed). The tier label in
configuration and UI follows from that function, never from intent.

---

## T111 — a stranger, and a screen reader

**Blocked on**: the provisioning wizard (T107) and a real cloud provider; SC-009 cannot be measured
against the mock. The screen-reader half can run now against the built window.

**Screen-reader pass (now)**: on Windows 11 with the Tauri window built (`apps/dnet-tray`), once with
Narrator and once with NVDA:

1. Reach every control in the window by Tab alone, in a sensible order, with focus always visible.
2. Each control announces a name, a role and its state (the core figure as a toggle with on/off; each
   network chip with its name and quality; the drawer's open/closed state).
3. A state change while the window is open (connect, disconnect, a failover) is announced without moving
   focus.
4. Turn on reduced motion and a high-contrast theme (forced colours): the figure stops moving, and
   every control is still visible with a border.

**Pass**: every item above, in both readers, with no control that is silent or announced only as
"button" or "group". Record each failure with the reader, the control and what was said.

**Stranger test (later)**: per `quickstart.md` "Phase 7". **Pass**: a working endpoint in under 20
minutes unaided (SC-009) and a working connection with no documentation beyond the wizard (SC-010).
Record where they stalled even on a pass.

---

## T114 — the installer

**Built 2026-10-26, not run.** NSIS through the Tauri bundler (`installer/`, `cargo xtask stage-installer`,
`pnpm installer`; see the T114 note in `tasks.md`). Revisit the choice if you prefer WiX/MSI. Commands:
`LOCAL-COMMANDS.md` section 7, which saves every result to `.local-logs`.

**Pass** (on a clean Windows 11 VM, snapshot first):

1. Install. `sc.exe qc DNetEngine` shows `LocalSystem` and the path of
   `dnetd.exe`.
2. `primary-core.exe` and `amneziawg-go.exe` sit **beside** `dnetd.exe`; `wintun.dll` sits beside each
   core; `cargo xtask verify-vendor` on the staged payload says OK.
3. `icacls "C:\ProgramData\DNet Engine"` and its `run` and `state` subdirectories: owner SYSTEM or
   Administrators, protected (no inherited entries), no grant to Users or Authenticated Users beyond
   what the design allows.
4. Pre-create `C:\ProgramData\DNet Engine` as an ordinary user, then install: the installer replaces it
   or refuses, and never installs into a directory that user owns.
5. `THIRD-PARTY-NOTICES.md` and every licence text are installed; `cargo run -p xtask --
   lint-branding` passes on the release payload (T122).
6. The installer is at most 60 MB (T115).
7. Uninstall: the service, both cores, the adapter and every route and DNS change are gone; the
   network is as before installation (compare `route print` and `Get-DnsClientServerAddress` with the
   snapshot).
8. `sc.exe qc DNetEngine` shows the binary path **in quotes** (it contains a space), `AUTO_START`,
   dependencies `Nsi` and `Tcpip`; `sc.exe qfailure DNetEngine` shows three restarts (5 s, 30 s, 60 s).
9. Stays on (T147): connected, restart Windows, and within a minute of sign-in it is connected again with
   nobody touching it (7.5, 7.6). Turned off, restart: it stays off.
10. Crash: `taskkill /f` on `dnetd.exe`; the SCM restarts it, start-up recovery runs, and it reconnects (7.7).
11. Upgrade: install the same installer again over a connected install; the old service is stopped first,
    the files are replaced, and it comes back connected.
12. winget, after the draft release exists: `winget install --manifest <unzipped winget-manifests>` installs
    it silently with one elevation prompt, and `winget uninstall DNetEngine.DNetEngine` removes it as in 7.

---

## T149–T151 — the guided server setup, against a real server

Written 2026-10-30. Nothing here has been run: the script has only been run under `sh` against a stubbed
`uname`, and the real amd64 core has only checked the configuration. This is the first time a person's
server is made from the window.

**Needs**: a Windows machine with the built window and service (`LOCAL-COMMANDS.md` §8), an Oracle Cloud
account (card and phone), and a release build's `server-pins.json` beside `dnetd.exe` (from the release workflow's
`server-cores` job, or `cargo xtask build-server-cores --base-url <https://…/>` with the files hosted at that address).

**Run** the window's own guide as a stranger would, on the real provider, with a note of every moment you hesitate:

1. Open Servers → "Set up a server for me" → "Use my own server" → "Oracle Cloud, free" → follow every step.
2. **Compare each step with the live console** and write down every button or menu whose wording differs. The
   guide says what to do and warns that wording may differ, but the exact names are unverified.
3. At the script step, copy the block with the Copy button and paste it into PowerShell's ssh session. Note any
   line the terminal mangled.
4. Paste the result back. The server must appear in Servers.
5. Turn the connection on. **Pass:** connected through the new server, `dnetctl status` shows it.

**Also check, on that server** (`ssh` in): `systemctl list-timers` shows `dnet-keepalive.timer` and `dnet-housekeeping.timer`;
`journalctl --disk-usage` is below 100 MB; `df -h /` shows no growth after a week; the core log level is `warn`
(`grep level /var/lib/dnet/primary/server.json`).

**After a week idle**, the server must still be running (the reclamation rule: over 7 days, CPU p95, network and, on Arm,
memory all under 20% means idle). If Oracle reclaimed it, record when, and the keepalive's duty cycle needs raising (T094).

**Negative checks:** run the Arm script on an AMD server (it must stop at once with the processor message and install
nothing); paste a result from an earlier script after starting a new setup (refused with "a different script"); paste text
with no result in it (refused, nothing echoed); close and reopen the window mid-guide and confirm the same script returns.

**Fail**: anything the person had to guess is a defect in the guide, not in the person. Fix the words, test first.
