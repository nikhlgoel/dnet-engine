<#
.SYNOPSIS
  The firewall guard's lab checks (T161, ADR-0006 §5a condition 5), run on the lab VM through `lab.ps1`.

.DESCRIPTION
  Each claim is measured twice: once with the guard off (the negative control, which must show the leak) and once with
  it on. A check that cannot fail proves nothing (`testing/harness/HARNESS-NOTES.md`). The guest's own network is
  QEMU's user-mode network, so "outside" is the real Internet through the host, and "local" is 10.0.0.0/8, where the
  guest's gateway, its DNS and the host's forwarded SSH all live. That is the same list the guard keeps reachable.

  Needs the guest running and its SSH answering (`lab.ps1 status`), and the staged programs in D:\vm\stage\bin.
  Run from the repository root:  powershell -File testing\vm\guard-checks.ps1
#>
[CmdletBinding()]
param([string]$Only)

$ErrorActionPreference = 'Stop'
$Lab = Join-Path $PSScriptRoot 'lab.ps1'
$Stage = if ($env:DNET_VM_DIR) { Join-Path $env:DNET_VM_DIR 'stage\bin' } else { 'D:\vm\stage\bin' }
$Results = [System.Collections.Generic.List[object]]::new()

function Guest([string]$Command) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & $Lab ssh $Command 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = $previous
    ($out -join "`n").Trim()
}

function Record([string]$Name, [bool]$Pass, [string]$Detail) {
    $Results.Add([pscustomobject]@{ Check = $Name; Pass = $Pass; Detail = $Detail })
    $mark = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Host ("{0}  {1}  {2}" -f $mark, $Name, $Detail)
}

# A TCP connection from the guest to an address outside the guard's local ranges, with a short limit (the probe is a
# script copied into the guest, so no quoting has to survive two shells).
$Outside = '1.1.1.1'
function Outside-Reachable { (Guest "powershell -NoProfile -ExecutionPolicy Bypass -File C:\lab\probe-outside.ps1 $Outside 443") -match 'OPEN' }

Write-Host 'Preparing the guest: the programs the plan names, in a folder of its own.'
Guest 'New-Item -ItemType Directory -Force C:\lab\bin | Out-Null' | Out-Null
& $Lab put (Join-Path $PSScriptRoot 'probe-outside.ps1') 'C:\lab\' | Out-Null
foreach ($f in 'guard_lab.exe', 'dnetd.exe') { & $Lab put (Join-Path $Stage $f) 'C:\lab\bin\' | Out-Null }
# The "core" and the "service" the plan names are real programs at the paths it names. A copy of the system's curl
# is the core's stand-in: a program that makes outbound connections, found by its full path.
Guest 'Copy-Item C:\Windows\System32\curl.exe C:\lab\bin\core-standin.exe -Force' | Out-Null
$core = 'C:\lab\bin\core-standin.exe'
$service = 'C:\lab\bin\dnetd.exe'
$planArgs = "--core $core --service $service"

# --------------------------------------------------------------------------------------------- 0, the control
Guest 'C:\lab\bin\guard_lab.exe remove' | Out-Null
Record '0 the guard is off' ((Guest 'C:\lab\bin\guard_lab.exe status') -match 'not installed') ''
Record '0 negative control: with the guard off, an outside address is reachable' (Outside-Reachable) "to $Outside:443"

# --------------------------------------------------------------------------------------------- A, put it in and read it back
$install = Guest "C:\lab\bin\guard_lab.exe install $planArgs"
Record 'A the guard installs and reads back exactly as planned' ($install -match 'read back and verified') ($install -replace "`n", ' | ')
$verify = Guest "C:\lab\bin\guard_lab.exe verify $planArgs"
Record 'A a second, separate read-back agrees with the plan' ($verify -match 'VERIFIED') ($verify -split "`n" | Select-Object -Last 1)

# --------------------------------------------------------------------------------------------- B, it blocks
Record 'B with the guard on, an outside address is no longer reachable' (-not (Outside-Reachable)) "to $Outside:443"
Record 'B the lab itself still answers (the local range and the replies stay open)' ((Guest 'echo alive') -match 'alive') ''

# --------------------------------------------------------------------------------------------- 5, only the core
& $Lab put (Join-Path $PSScriptRoot 'core-run.cmd') 'C:\lab\' | Out-Null
Guest 'Remove-Item C:\lab\core.out -ErrorAction SilentlyContinue; schtasks /Create /F /TN dnetcore /SC ONCE /ST 00:00 /RU SYSTEM /TR C:\lab\core-run.cmd 2>&1 | Out-Null; schtasks /Run /TN dnetcore 2>&1 | Out-Null; Start-Sleep 14; Get-Content C:\lab\core.out -ErrorAction SilentlyContinue' | Out-Null
$asCore = Guest 'Get-Content C:\lab\core.out -ErrorAction SilentlyContinue | Out-String'
Record '5 the core, run as the system account at its own path, is let through' ($asCore -match 'exit=0') ($asCore.Trim())
& $Lab put (Join-Path $PSScriptRoot 'other-run.cmd') 'C:\lab\' | Out-Null
Guest 'Remove-Item C:\lab\other.out -ErrorAction SilentlyContinue; cmd /c C:\lab\other-run.cmd' | Out-Null
$other = Guest 'Get-Content C:\lab\other.out -ErrorAction SilentlyContinue | Out-String'
Record '5 another program (the same curl, at another path) is refused' (($other -match 'exit=[1-9]') -and ($other -notmatch 'exit=0')) ($other -replace "`r?`n", ' ')

# --------------------------------------------------------------------------------------------- removal
Guest 'C:\lab\bin\guard_lab.exe remove' | Out-Null
Record 'R removed: the provider is gone' ((Guest 'C:\lab\bin\guard_lab.exe status') -match 'not installed') ''
Record 'R removed: an outside address is reachable again' (Outside-Reachable) "to $Outside:443"

$failed = @($Results | Where-Object { -not $_.Pass }).Count
Write-Host ''
Write-Host ("{0} checks, {1} failed" -f $Results.Count, $failed)
exit ([int]($failed -gt 0))
