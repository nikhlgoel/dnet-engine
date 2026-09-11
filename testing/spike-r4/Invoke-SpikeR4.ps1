<#
.SYNOPSIS
    SPIKE-R4 / HV-13 (T055): Profile A carries traffic end-to-end with NO routing re-entry.

.DESCRIPTION
    Runs the real Profile A bring-up twice against a harness endpoint reached through the
    physical default gateway, counting UDP packets to endpoint:51820 per network adapter
    with pktmon:

      PASS    - production sequence. Expected: transfer succeeds, packets to the endpoint
                appear ONLY on the physical adapter, ZERO on the tunnel adapters.
      CONTROL - identical, but the endpoint host route is withheld. Expected: packets to
                the endpoint appear on a tunnel adapter (re-entry). If they do not, the
                measurement cannot tell a loop from no loop and the spike is INVALID.

    Verdict (exit code): 0 PASS | 1 FAIL | 2 setup error | 3 VACUOUS topology |
                         4 INVALID control | 5 INCONCLUSIVE instrument

    Must run in an elevated PowerShell. Never modifies routing outside the run; verifies
    restoration afterwards.

.PARAMETER EndpointIp
    Public IP of the host running the harness endpoint. Must NOT be loopback or on-link.

.PARAMETER ParamsFile
    awg-client.json copied from the endpoint host's testing/harness/.state/ (test keys).

.PARAMETER AltGateway
    Optional gateway of a SECOND physical path (e.g. a USB-tethered phone) to exercise the
    host-route rewrite across a real interface change. Omitted = path change SKIPPED.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $EndpointIp,
    [string] $ParamsFile = (Join-Path $PSScriptRoot '..\harness\.state\awg-client.json'),
    [long]   $Bytes = 20000000,
    [string] $AltGateway,
    [switch] $SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo     = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Vendor   = Join-Path $Repo 'vendor'
$Results  = Join-Path $PSScriptRoot ("results\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$Runner   = Join-Path $Repo 'target\release\examples\spike_r4.exe'
$TunAlias = 'dnet-tun0'
$AwgAlias = 'dnet-awg0'
$Port     = 51820

function Say([string]$m)  { Write-Host "[spike-r4] $m" }
function Stop-Spike([string]$m, [int]$code) { Write-Host "[spike-r4] $m" -ForegroundColor Red; exit $code }

# ------------------------------------------------------------------ 1. preflight
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Spike 'Run this from an elevated PowerShell (Run as Administrator).' 2
}

$staged = @{
    Awg     = Join-Path $Vendor 'amneziawg-go\amneziawg-go.exe'
    Driver  = Join-Path $Vendor 'wintun\wintun.dll'
    Primary = Join-Path $Vendor 'primary-core\primary-core.exe'
}
foreach ($f in $staged.Values) {
    if (-not (Test-Path $f)) { Stop-Spike "Missing $f. Run: cargo run -p xtask -- fetch-vendor" 2 }
}
if (-not (Test-Path $ParamsFile)) {
    Stop-Spike "Missing $ParamsFile. Copy awg-client.json from the endpoint host (see README)." 2
}
$ParamsFile = (Resolve-Path $ParamsFile).Path

# Vacuity guard: loopback/on-link endpoints never enter the TUN, so a loop cannot form.
$addr = [System.Net.IPAddress]::Parse($EndpointIp)
if ([System.Net.IPAddress]::IsLoopback($addr)) {
    Stop-Spike "VACUOUS: $EndpointIp is loopback; no routing loop can form. Run the endpoint on a remote host." 3
}
$route = Find-NetRoute -RemoteIPAddress $EndpointIp | Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
if (-not $route -or $route.DestinationPrefix -ne '0.0.0.0/0' -or $route.NextHop -eq '0.0.0.0') {
    Stop-Spike "VACUOUS: $EndpointIp is not reached via the default gateway (matched $($route.DestinationPrefix) via $($route.NextHop))." 3
}
$phys = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex
Say "physical path : $($phys.Name) [$($phys.InterfaceDescription)] via $($route.NextHop)"

# Clean-state guard: residue from an earlier run would mask the result.
if (Get-NetAdapter -Name $TunAlias, $AwgAlias -ErrorAction SilentlyContinue) {
    Stop-Spike "Adapters $TunAlias/$AwgAlias already exist (earlier run?). Reboot or remove them first." 2
}
if (Get-NetRoute -DestinationPrefix "$EndpointIp/32" -ErrorAction SilentlyContinue) {
    Stop-Spike "A /32 route to $EndpointIp already exists; remove it first (it would mask a loop)." 2
}

if (-not $SkipBuild) {
    Say 'building runner (release)'
    Push-Location $Repo
    try { cargo build --release -p dnet-netstate --example spike_r4 } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Stop-Spike 'runner build failed' 2 }
}
New-Item -ItemType Directory -Force $Results | Out-Null

# ------------------------------------------------------------------ 2. counting
# pktmon's counters JSON is walked generically: any object with a string property EXACTLY
# equal to one of the adapter's names/descriptions contributes its *Packet* counters.
# A zero sum only counts as zero if the adapter was actually found (Hit) — otherwise the
# instrument is blind and the verdict is INCONCLUSIVE, never PASS.
function Measure-Adapter {
    param($Node, [string[]]$Needles, [bool]$InMatch = $false)
    $out = @{ Sum = [long]0; Hit = $false }
    if ($null -eq $Node -or $Node -is [string]) { return $out }
    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($item in $Node) {
            $r = Measure-Adapter $item $Needles $InMatch
            $out.Sum += $r.Sum; $out.Hit = $out.Hit -or $r.Hit
        }
        return $out
    }
    if ($Node -isnot [pscustomobject]) { return $out }
    $self = $InMatch
    foreach ($p in $Node.PSObject.Properties) {
        if ($p.Value -is [string] -and ($Needles -contains $p.Value)) { $self = $true }
    }
    $out.Hit = $self
    foreach ($p in $Node.PSObject.Properties) {
        $isNumber = $p.Value -is [int] -or $p.Value -is [long] -or $p.Value -is [double] -or $p.Value -is [decimal]
        if ($self -and $isNumber -and $p.Name -match 'Packet') {
            $out.Sum += [long]$p.Value
        } elseif ($p.Value -isnot [string] -and -not $isNumber) {
            $r = Measure-Adapter $p.Value $Needles $self
            $out.Sum += $r.Sum; $out.Hit = $out.Hit -or $r.Hit
        }
    }
    return $out
}

function Wait-ForFile([string]$Path, [int]$Seconds, $Proc) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (Test-Path $Path)) {
        if ($Proc.HasExited -or (Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 200
    }
    return $true
}

function Stop-Capture {
    pktmon stop 2>&1 | Out-Null
    pktmon filter remove 2>&1 | Out-Null
}

# ------------------------------------------------------------------ 3. one mode
function Invoke-Mode([string]$Mode) {
    $tag = $Mode.ToLowerInvariant()
    $run = Join-Path $Results $tag
    $awgDir = Join-Path $run 'awg'; $priDir = Join-Path $run 'primary'
    New-Item -ItemType Directory -Force $awgDir, $priDir | Out-Null
    # Private per-run copies: orphan reaping matches these exact paths. The adapter
    # driver DLL is the signed prebuilt, copied unmodified beside the core that loads it.
    Copy-Item $staged.Awg $awgDir
    Copy-Item $staged.Driver $awgDir
    Copy-Item $staged.Primary $priDir

    $report = Join-Path $run 'runner-report.json'
    $runnerArgs = @('--mode', $tag, '--params', $ParamsFile, '--endpoint', $EndpointIp,
        '--awg-exe', (Join-Path $awgDir 'amneziawg-go.exe'),
        '--primary-exe', (Join-Path $priDir 'primary-core.exe'),
        '--run-dir', $run, '--report', $report, '--bytes', "$Bytes")
    if ($AltGateway -and $tag -eq 'pass') { $runnerArgs += @('--alt-gateway', $AltGateway) }
    $quoted = $runnerArgs | ForEach-Object { '"' + $_ + '"' }

    Say "[$Mode] starting runner"
    $proc = Start-Process -FilePath $Runner -ArgumentList $quoted -NoNewWindow -PassThru `
        -RedirectStandardError (Join-Path $run 'runner.log') -RedirectStandardOutput (Join-Path $run 'runner.out')

    $result = [ordered]@{ Mode = $Mode; Error = $null; Runner = $null
        Physical = @{ Sum = 0; Hit = $false }; Tunnel = @{ Sum = 0; Hit = $false } }
    try {
        if (-not (Wait-ForFile (Join-Path $run "$tag.cores-up.ready") 180 $proc)) {
            $result.Error = 'cores never came up (see runner.log)'; return $result
        }
        # Adapters exist, no peer yet: start capture now so pktmon attaches to them.
        $tunnelAdapters = @(Get-NetAdapter -Name $TunAlias, $AwgAlias -ErrorAction SilentlyContinue)
        $tunnelNeedles = @($tunnelAdapters | ForEach-Object { $_.Name; $_.InterfaceDescription })
        $physNeedles = @($phys.Name, $phys.InterfaceDescription)
        pktmon filter remove 2>&1 | Out-Null
        pktmon filter add dnet-spike-r4 -t UDP -i $EndpointIp -p $Port | Out-Null
        pktmon start --capture --comp nics --file-name (Join-Path $run 'capture.etl') | Out-Null
        New-Item -ItemType File (Join-Path $run "$tag.cores-up.go") | Out-Null

        if (-not (Wait-ForFile (Join-Path $run "$tag.measured.ready") 400 $proc)) {
            $result.Error = 'runner never reached the measurement checkpoint (see runner.log)'; return $result
        }
        # Snapshot while the adapters still exist; teardown removes them.
        pktmon counters | Set-Content -Encoding utf8 (Join-Path $run 'counters.txt')
        pktmon list | Set-Content -Encoding utf8 (Join-Path $run 'components.txt')
        $json = (pktmon counters --json --zero | Out-String)
        Set-Content -Encoding utf8 (Join-Path $run 'counters.json') $json
        try {
            $data = $json | ConvertFrom-Json
            $result.Physical = Measure-Adapter $data $physNeedles
            $result.Tunnel = Measure-Adapter $data $tunnelNeedles
        } catch {
            $result.Error = "pktmon counters JSON unreadable: $_"
        }
        New-Item -ItemType File (Join-Path $run "$tag.measured.go") | Out-Null
        if (-not $proc.WaitForExit(180000)) { $result.Error = 'runner did not exit after teardown' }
    } finally {
        Stop-Capture
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        try { pktmon etl2pcap (Join-Path $run 'capture.etl') --out (Join-Path $run 'capture.pcapng') 2>&1 | Out-Null } catch {}
    }
    if (Test-Path $report) { $result.Runner = Get-Content $report -Raw | ConvertFrom-Json }
    return $result
}

# ------------------------------------------------------------------ 4. run + verdict
$pass    = Invoke-Mode 'Pass'
$control = Invoke-Mode 'Control'

# Restoration: nothing from either run may remain (SC-016 spirit).
Start-Sleep -Seconds 3
$residue = @()
if (Get-NetAdapter -Name $TunAlias, $AwgAlias -ErrorAction SilentlyContinue) { $residue += 'tunnel adapter still present' }
if (Get-NetRoute -DestinationPrefix "$EndpointIp/32" -ErrorAction SilentlyContinue) { $residue += 'endpoint /32 route still present' }
if (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($Results, 'OrdinalIgnoreCase') }) {
    $residue += 'a staged core process is still running'
}

$runnerOk = { param($r) $r.Runner -and -not $r.Runner.error -and $r.Runner.teardown_ok }
$verdict = $null; $reasons = @()
if ($pass.Error -or $control.Error) {
    $verdict = 'INCONCLUSIVE'; $reasons += "pass: $($pass.Error)"; $reasons += "control: $($control.Error)"
} elseif (-not ($pass.Physical.Hit -and $pass.Tunnel.Hit -and $control.Tunnel.Hit)) {
    $verdict = 'INCONCLUSIVE'
    $reasons += 'pktmon output did not expose the physical and tunnel adapters; inspect counters.txt / components.txt'
} elseif (-not ($control.Tunnel.Sum -gt 0 -and -not $control.Runner.host_route_installed)) {
    $verdict = 'INVALID'
    $reasons += "control withheld the host route but showed no re-entry (tunnel packets=$($control.Tunnel.Sum)); the measurement cannot detect a loop"
} elseif ((& $runnerOk $pass) -and $pass.Runner.transfer.ok -and $pass.Runner.host_route_installed `
        -and $pass.Physical.Sum -gt 0 -and $pass.Tunnel.Sum -eq 0 -and $residue.Count -eq 0) {
    $verdict = 'PASS'
} else {
    $verdict = 'FAIL'
    if (-not $pass.Runner.transfer.ok) { $reasons += "transfer failed: $($pass.Runner.transfer.error)" }
    if ($pass.Tunnel.Sum -gt 0) { $reasons += "RE-ENTRY: $($pass.Tunnel.Sum) endpoint packets on a tunnel adapter" }
    if ($pass.Physical.Sum -eq 0) { $reasons += 'no endpoint packets on the physical adapter' }
    if (-not $pass.Runner.host_route_installed) { $reasons += 'host route was not installed' }
    if ($pass.Runner.error) { $reasons += "runner: $($pass.Runner.error)" }
    $reasons += $residue
}

$pathChange = if ($AltGateway) {
    if ($pass.Runner -and $pass.Runner.path_change) { "transfer ok=$($pass.Runner.path_change.ok) mbps=$([math]::Round($pass.Runner.path_change.mbps, 2))" } else { 'not reached' }
} else { 'SKIPPED (no -AltGateway: single physical path)' }

$summary = @"
# SPIKE-R4 / HV-13 result: $verdict

| | PASS run | CONTROL run (host route withheld) |
|---|---|---|
| transfer ok | $($pass.Runner.transfer.ok) | $($control.Runner.transfer.ok) |
| throughput (Mbit/s) | $([math]::Round([double]$pass.Runner.transfer.mbps, 2)) | $([math]::Round([double]$control.Runner.transfer.mbps, 2)) |
| host route installed | $($pass.Runner.host_route_installed) | $($control.Runner.host_route_installed) |
| endpoint:$Port packets, physical | $($pass.Physical.Sum) | $($control.Physical.Sum) |
| endpoint:$Port packets, tunnel adapters | **$($pass.Tunnel.Sum)** | **$($control.Tunnel.Sum)** |
| teardown ok | $($pass.Runner.teardown_ok) | $($control.Runner.teardown_ok) |

- Endpoint: $EndpointIp via $($route.NextHop) on $($phys.Name)
- Path change: $pathChange
- Restoration residue: $(if ($residue.Count) { $residue -join '; ' } else { 'none' })
- Reasons: $(if ($reasons.Count) { $reasons -join ' | ' } else { '-' })

Artifacts per run: runner.log, runner-report.json, counters.txt, counters.json, components.txt, capture.pcapng
"@
Set-Content -Encoding utf8 (Join-Path $Results 'summary.md') $summary
Write-Host $summary
Say "results: $Results"

switch ($verdict) {
    'PASS'         { exit 0 }
    'FAIL'         { exit 1 }
    'INVALID'      { exit 4 }
    default        { exit 5 }
}
