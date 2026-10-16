# BUG-007: SPIKE-R4 cannot start the AmneziaWG core from an Administrator shell

**Status**: Open. The cause is checked against the pinned source; the workaround has not been run
**Severity**: **High**
**Found**: 2026-10-16, by reading the results folder of the 2026-09-11 22:07 spike run. It was not noticed at the time
**Area**: `testing/spike-r4`, and `dnet-supervisor` (the identity the cores are launched under)
**Fixed in**: not fixed

## Symptom

The 2026-09-11 run of `Invoke-SpikeR4.ps1` never reached the routing measurement. The AmneziaWG core
logged this while starting (ANSI colour codes removed):

```text
ERROR: (dnet-awg0) 2026/09/11 22:07:58 Failed to listen on uapi socket:
open \\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\dnet-awg0:
This security ID may not be assigned as the owner of this object.
```

About 33 seconds later the runner gave up. Its report, `runner-report.json`:

```json
{"mode":"pass","endpoint":"192.0.2.10","gateway":"192.168.1.6","host_route_installed":false,
 "transfer":{"ok":false,"bytes":0,"seconds":0.0,"mbps":0.0,"error":null},
 "path_change":null,"teardown_ok":false,
 "error":"core AmneziaWgCore did not become ready: adapter \"dnet-awg0\" not available: UAPI pipe did not become available within the timeout"}
```

Teardown then also failed: `removing the peer: UAPI response timed out`. The results folder holds
only `pass/` and has no `summary.md`. `testing/spike-r4/results/` is gitignored, so the evidence above
is the only copy that travels with the repository.

## Root cause

**Checked.** The pinned core (`amneziawg-go` v3.1.20260828, commit `b5928efb`, `ipc/uapi_windows.go`)
creates the pipe `\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\<adapter>` with the security
descriptor `O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)`. Its owner (`O:SY`) is SYSTEM.

**Inferred, not reproduced.** Windows only lets a process assign an owner other than itself, or a
group its token marks as an owner, when it holds `SeRestorePrivilege` enabled. An Administrator token
carries that privilege disabled, so creating a pipe whose descriptor names SYSTEM as owner is refused
with the error text above. A process running as LocalSystem owns that SID and passes.

Nothing in the repository enables the privilege or runs the cores as SYSTEM. The runner's own check
(`Invoke-SpikeR4.ps1`, preflight) only requires the Administrators role, so it accepts exactly the
shell that fails.

## Why it was dangerous

- The spike guards the riskiest assumption in the design (research.md R4). From an Administrator
  shell it fails before routing is exercised, so a missing result looked like a missing endpoint.
- The deferral notes (`tasks.md` T055, `Research-Critique.md` §6.6, the runbook) cite the LAN-VM bridge
  and `pktmon`. They do not mention this. Any run from an Administrator shell would probably stop here
  whatever endpoint was used.
- `dnetd --console` runs as the developer's own account. If the inference holds, a Profile A connect
  there hits the same refusal. The installed service runs as LocalSystem and is expected to be fine,
  but that is unverified until something runs as SYSTEM.
- The failure shows up as a generic "core not ready" timeout, with the cause only in a core log line.

## Resolution

None yet. The runbook now says to run the spike as LocalSystem (2026-10-16).

Two ways to get past it, neither run yet:

1. **Run the spike as LocalSystem** (Sysinternals PsExec `-s`, or a scheduled task running as SYSTEM).
   Preferred: it matches the identity the shipped service uses, so the run also exercises production
   conditions.
2. **Enable `SeRestorePrivilege`** in the runner process before it spawns the cores. A child process
   inherits the privilege's enabled state. This changes how the cores are launched, so it would need
   its own review.

Not recommended: patching the core's descriptor. It carries a source patch for a harness-identity
problem and makes the tested binary differ from the shipped one.

## Prevention

Proposed, not done:

- **Preflight.** `Invoke-SpikeR4.ps1` should check for `WindowsIdentity.IsSystem` and stop with exit
  code 2 and a pointer to this bug, instead of accepting any Administrator shell.
- **Verdict text.** A core that never becomes ready should name the core's last error line in
  `summary.md`, so the cause is not left in `runner.log`.
- **Close this bug** when the live run (T055 / T098a) completes under SYSTEM. Record the verdict here
  and in `tasks.md`.
