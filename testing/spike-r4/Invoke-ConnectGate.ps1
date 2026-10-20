<#
.SYNOPSIS
    T126 gate, SYSTEM side: runs the production daemon (dnetd) against the WSL lab endpoint and
    keeps it up until the driver has finished.

.DESCRIPTION
    Started by Invoke-WslLab.ps1 -Gate Connect as LocalSystem, after it has made the WSL VM the
    default gateway. This script does not connect anything itself: a Connect request must come
    from the interactive console user (the daemon refuses anyone else), so the client half is
    Invoke-ConnectDriver.ps1, which Launch runs from the person's own elevated shell.

    What this script does:
      1. Stages private copies of dnetd, the two cores and the signed Wintun DLL in one folder
         (the installed layout: the daemon looks for the cores beside itself).
      2. Points the daemon at a private %PROGRAMDATA% (the process's environment only), so the
         endpoint it imports and the state it keeps live under results\ and never touch the
         real DNet Engine configuration.
      3. Imports the lab endpoint (every client file in -ParamsDir) with `xtask import-harness-endpoint` (as SYSTEM, which is what
         seals the credentials to the machine).
      4. Starts `dnetd --console`, signals the driver (ReadyFile), waits for it to finish
         (StopFile), then stops the daemon and checks nothing was left behind.

    The daemon is stopped by killing it, not by a service stop: console mode has no stop signal
    reachable from a scheduled task. The driver disconnects first, so the normal path leaves
    nothing to recover; the graceful-shutdown path is covered by the orchestrator's tests.

    Exit code: 0 the daemon ran and was stopped | 2 setup error | 6 something was left behind.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $EndpointIp,
    # A folder holding the endpoint's client files (awg-client.json, hy2-client.json,
    # reality-client.json), as the harness endpoint writes them. Whichever exist are imported.
    [Parameter(Mandatory)] [string] $ParamsDir,
    [Parameter(Mandatory)] [string] $ReadyFile,
    [Parameter(Mandatory)] [string] $StopFile,
    [ValidateRange(2, 60)] [int] $WaitMinutes = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo    = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Vendor  = Join-Path $Repo 'vendor'
$Results = Join-Path $PSScriptRoot ("results\connect-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$Dnetd   = Join-Path $Repo 'target\release\dnetd.exe'
$Xtask   = Join-Path $Repo 'target\release\xtask.exe'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Say([string]$m) { Write-Host "[connect-gate] $m" }
function Stop-Gate([string]$m, [int]$code) { Write-Host "[connect-gate] $m" -ForegroundColor Red; exit $code }

if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    Stop-Gate 'This must run as LocalSystem (BUG-007; the daemon is a SYSTEM service). Invoke-WslLab.ps1 -Gate Connect does that.' 2
}
foreach ($f in $Dnetd, $Xtask, $ParamsDir,
               (Join-Path $Vendor 'wintun\wintun.dll'),
               (Join-Path $Vendor 'primary-core\primary-core.exe'),
               (Join-Path $Vendor 'amneziawg-go\amneziawg-go.exe')) {
    if (-not (Test-Path $f)) { Stop-Gate "Missing $f" 2 }
}
foreach ($stale in $ReadyFile, $StopFile) { Remove-Item $stale -Force -ErrorAction SilentlyContinue }

# The endpoint must be reached through the default route only, as in the loop gate; a /32 already
# there would make the daemon's own host route meaningless.
if (Get-NetRoute -DestinationPrefix "$EndpointIp/32" -ErrorAction SilentlyContinue) {
    Stop-Gate "A /32 route to $EndpointIp already exists; remove it first." 2
}
if (Get-NetAdapter -Name 'dnet-tun0', 'dnet-awg0' -ErrorAction SilentlyContinue) {
    Stop-Gate 'Adapters dnet-tun0/dnet-awg0 already exist (earlier run?). Reboot or remove them first.' 2
}

# ------------------------------------------------------------------ stage
$stage = Join-Path $Results 'stage'
$files = Join-Path $Results 'harness-files'
$pd    = Join-Path $Results 'programdata'
New-Item -ItemType Directory -Force $stage, $files, $pd | Out-Null
Copy-Item $Dnetd $stage
Copy-Item (Join-Path $Vendor 'primary-core\primary-core.exe') $stage
Copy-Item (Join-Path $Vendor 'amneziawg-go\amneziawg-go.exe') $stage
# Each core loads the signed adapter driver DLL from its own folder; the daemon starts both from here.
Copy-Item (Join-Path $Vendor 'wintun\wintun.dll') $stage
$copied = @()
foreach ($name in 'awg-client.json', 'hy2-client.json', 'reality-client.json') {
    $src = Join-Path $ParamsDir $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $files $name); $copied += $name }
}
if (-not $copied) { Stop-Gate "No client files in $ParamsDir" 2 }
Say "endpoint client files: $($copied -join ', ')"
Say "staged under $stage"

# A private %PROGRAMDATA%, for this script's processes only.
$env:ProgramData = $pd
$env:RUST_LOG = 'info,dnetd=debug,dnet_supervisor=debug,dnet_netstate=debug,dnet_probe=debug'

# ------------------------------------------------------------------ import the lab endpoint
$importLog = Join-Path $Results 'import.log'
& $Xtask import-harness-endpoint --host $EndpointIp --state-dir $files --replace *>&1 |
    Tee-Object -FilePath $importLog | ForEach-Object { Say "import: $_" }
if ($LASTEXITCODE -ne 0) { Stop-Gate "importing the lab endpoint failed (exit $LASTEXITCODE); see $importLog" 2 }

# ------------------------------------------------------------------ the daemon
$exe = Join-Path $stage 'dnetd.exe'
$out = Join-Path $Results 'dnetd.out.log'
$err = Join-Path $Results 'dnetd.err.log'
$daemon = Start-Process -FilePath $exe -ArgumentList '--console' -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError $err
Say "dnetd started (pid $($daemon.Id)); logs: $out"

$code = 0
try {
    Start-Sleep -Seconds 3
    if ($daemon.HasExited) { Stop-Gate "dnetd exited at once (code $($daemon.ExitCode)); see $err" 2 }
    [IO.File]::WriteAllText($ReadyFile, "$Results", $Utf8NoBom)
    Say 'ready; waiting for the driver'

    $until = (Get-Date).AddMinutes($WaitMinutes)
    while (-not (Test-Path $StopFile)) {
        if ($daemon.HasExited) { Say "dnetd exited by itself (code $($daemon.ExitCode)); see $err"; $code = 6; break }
        if ((Get-Date) -gt $until) { Say 'the driver never finished; stopping the daemon'; $code = 6; break }
        Start-Sleep -Milliseconds 500
    }
}
finally {
    if (-not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue; $daemon.WaitForExit(10000) | Out-Null }
    # Cores run from this run's private copies, so a path match cannot hit anything else. They die
    # before anything is judged: removing a route under a core that still sends would loop it.
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Results, 'OrdinalIgnoreCase') } |
        ForEach-Object { Say "stopping leftover $($_.Name) (pid $($_.ProcessId))"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $script:code = 6 }
    Start-Sleep -Seconds 2

    $residue = @()
    if (Get-NetAdapter -Name 'dnet-tun0', 'dnet-awg0' -ErrorAction SilentlyContinue) { $residue += 'a dnet adapter still exists' }
    if (Get-NetRoute -DestinationPrefix "$EndpointIp/32" -ErrorAction SilentlyContinue) { $residue += "a /32 route to $EndpointIp is still installed" }
    if ($residue.Count) {
        $residue | ForEach-Object { Say "RESIDUE: $_" }
        $code = 6
    } else {
        Say 'residue: none (no dnet adapter, no endpoint host route)'
    }
    Say "daemon logs kept in $Results"
}
exit $code
