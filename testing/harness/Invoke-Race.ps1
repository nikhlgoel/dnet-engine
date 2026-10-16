<#
.SYNOPSIS
  Races the real connection profiles against the harness under each hostile condition and checks
  that the right profile wins (T059, groundwork for the T068 gate: HV-01, HV-02, HV-12).

.DESCRIPTION
  Needs the harness up (`.\harness.ps1 up`) and the vendored core (`cargo xtask fetch-vendor`).
  Needs no elevation: each probe is a SOCKS-only core on loopback, so nothing touches routing.

  For every scenario it applies the conditions, runs `cargo run -p dnet-probe --example race`,
  reads the `RESULT` line, and compares it with what the scenario requires. Conditions are always
  cleared afterwards, even on failure. The exit code is 0 only if every scenario matched, so
  a harness that cannot fail would be caught: `baseline` must select a profile while `blocked`
  must select none.

  Scenarios (expected result):
    baseline        no condition                 -> some profile is selected
    H2              all UDP dropped              -> reality-default (the TCP profile; HV-02)
    H4-B            Hysteria 2 port dropped      -> reality-default
    H4-C            REALITY port dropped         -> hy2-default
    blocked         both ports dropped           -> none
    H9              150 kbit ceiling, both slow  -> none (connected but unusable; HV-12)

  Not covered here, because it needs the daemon: a block applied *while connected* (HV-04), and
  anything involving AmneziaWG, which cannot be probed through a proxy.

.EXAMPLE
  .\Invoke-Race.ps1
  .\Invoke-Race.ps1 -Only H2, H9
#>
[CmdletBinding()]
param(
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Here '..\..')).Path
$Harness = Join-Path $Here 'harness.ps1'

# Each condition is a hashtable (Id, optional Arg) passed to `harness.ps1 apply`. Hashtables,
# not nested arrays: PowerShell flattens a one-element nested array into its parent.
$Scenarios = @(
    @{ Name = 'baseline'; Expect = 'selected'
       Conditions = @() },
    @{ Name = 'H2'; Expect = 'selected reality-default'
       Conditions = @(@{ Id = 'H2' }) },
    @{ Name = 'H4-B'; Expect = 'selected reality-default'
       Conditions = @(@{ Id = 'H4'; Arg = 'B' }) },
    @{ Name = 'H4-C'; Expect = 'selected hy2-default'
       Conditions = @(@{ Id = 'H4'; Arg = 'C' }) },
    @{ Name = 'blocked'; Expect = 'none'
       Conditions = @(@{ Id = 'H4'; Arg = 'B' }, @{ Id = 'H4'; Arg = 'C' }) },
    @{ Name = 'H9'; Expect = 'none'
       Conditions = @(@{ Id = 'H9'; Arg = '150kbit' }) }
)
if ($Only) { $Scenarios = $Scenarios | Where-Object { $Only -contains $_.Name } }

function Invoke-Harness([string]$Command, [string]$Condition, [string]$Arg) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Harness, $Command)
    if ($Condition) { $a += $Condition }
    if ($Arg) { $a += @('-Arg', $Arg) }
    & powershell.exe @a | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "harness.ps1 $Command $Condition $Arg failed" }
}

function Get-RaceResult {
    Push-Location $Repo
    try {
        $out = cargo run -q -p dnet-probe --example race 2>&1 | Out-String
    } finally { Pop-Location }
    $line = ($out -split "`r?`n" | Where-Object { $_ -like 'RESULT *' } | Select-Object -Last 1)
    if (-not $line) { throw "the race printed no RESULT line:`n$out" }
    return $line.Substring('RESULT '.Length).Trim()
}

$failures = @()
try {
    foreach ($s in $Scenarios) {
        Invoke-Harness 'clear'
        foreach ($c in $s.Conditions) { Invoke-Harness 'apply' $c.Id $c.Arg }
        $got = Get-RaceResult
        # `selected` alone means "any profile"; otherwise the whole line must match.
        $ok = if ($s.Expect -eq 'selected') { $got -like 'selected *' } else { $got -eq $s.Expect }
        '{0,-9} expected {1,-26} got {2,-26} {3}' -f $s.Name, $s.Expect, $got, $(if ($ok) { 'ok' } else { 'FAIL' })
        if (-not $ok) { $failures += $s.Name }
    }
} finally {
    Invoke-Harness 'clear'
}

if ($failures.Count) {
    Write-Host "FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'All scenarios matched.' -ForegroundColor Green
exit 0
