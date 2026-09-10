# BUG-005: Two PowerShell traps produced false failures

**Status**: Fixed
**Severity**: Medium — the harness control script could not invoke conditions at all
**Found**: 2026-09-10, when `harness.ps1 apply H3` failed while the same command succeeded by hand
**Area**: `testing/harness/harness.ps1`, `Invoke-Hv03.ps1`
**Fixed in**: `cb46844`

## Symptom

`.\harness.ps1 apply H3` failed with `utm command failed`, while running
`docker exec dnet-utm /opt/conditions/dpi.sh H3` directly succeeded and exited 0.

After improving the error reporting, the real error appeared:

```
OCI runtime exec failed: exec: "/opt/conditions/dpi.sh H3": stat /opt/conditions/dpi.sh H3:
no such file or directory
```

The script path and its argument had been concatenated into a single argument.

## Root cause

Two independent PowerShell traps, the second masking the first.

### 1. Operator precedence collapsed the argument array

```powershell
$cmd = @('/opt/conditions/' + $spec[0], $spec[1])
```

PowerShell parses this as `'/opt/conditions/' + ($spec[0], $spec[1])`: the comma operator binds
tighter than `+`, so it builds the array `('dpi.sh','H3')`, then string-concatenates it onto the
prefix — joining the elements with a space. The result is one string, `/opt/conditions/dpi.sh H3`,
not two arguments.

Confirmed by isolating it: `$cmd.Count` was **1**, not 2.

### 2. Native stderr under `$ErrorActionPreference = 'Stop'`

The original wrapper checked `$LASTEXITCODE` immediately after `& docker exec`. Under `'Stop'`,
PowerShell 5.1 converts anything a native executable writes to **stderr** into a terminating
`NativeCommandError` and leaves `$LASTEXITCODE` unreliable. Docker writes routine progress to stderr,
so ordinary successful runs reported failure.

This masked the first bug: the real `exec` error was never displayed, only a generic wrapper message.

## Why it was dangerous

Not a product defect, but it blocked the Phase 0 exit gate and cost real time. More importantly it
demonstrated a diagnostic failure: **the wrapper reported that something failed without reporting
what**. The first fix attempted was to the wrong layer — splatting — because the actual error was
hidden.

## Resolution

**Precedence** — parenthesise the concatenation, with the reason recorded inline:

```powershell
# The concatenation MUST be parenthesised. Without it PowerShell parses
# `'x/' + $spec[0], $spec[1]` as `'x/' + ($spec[0], $spec[1])`, joining
# the array into a single space-separated string.
$cmd = @(('/opt/conditions/' + $spec[0]), $spec[1])
```

**Native commands** — relax the preference around the call, capture the exit code explicitly, and
**print captured output on failure**:

```powershell
function Invoke-Container {
    param([string]$Container, [string[]]$Cmd)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $dockerArgs = @('exec', $Container) + $Cmd
        $output = & docker @dockerArgs 2>&1
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $prev }
    if ($code -ne 0) {
        $output | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw "$Container command failed (exit $code): $($Cmd -join ' ')"
    }
    return $output
}
```

## Prevention

- Native executables are invoked through a single wrapper that handles the stderr behaviour once,
  rather than at each call site.
- **Failed commands print their captured output.** This change immediately surfaced BUG-003 and the
  precedence bug, both of which had been invisible.
- Both traps are recorded in `HARNESS-NOTES.md` under "PowerShell traps that produced false
  failures", since neither is obvious and both will recur in a Windows-first project.
