<#
.SYNOPSIS
  Watches a connected DNet Engine for a few minutes on a REAL network and writes down what it does: which network
  carries it, whether the internet works, how fast it is, and what happens when you change the networks (T195).

.DESCRIPTION
  Run it AFTER you have turned the connection on (Status, then the switch). It needs no administrator rights. Every
  second it records the service's state and the network carrying the traffic; every five seconds it checks that a website
  loads and which address the world sees; at the start and the end it measures speed.

  Then, while it runs, do the things this test is for, one at a time, and leave about 20 seconds between them:
    1. unplug the Ethernet cable;  2. plug it back in;
    3. turn Wi-Fi off in Windows;  4. turn it back on.
  (If you have a phone to tether, plug it in and out as well.) Do not touch the DNet Engine window.

  The result is written to  "$HOME\Documents\DNet test results\watch-<time>.txt"  and printed. Send that file back:
  it holds network names and addresses of YOUR networks (not the invite or any key), so look at it before sending.

.PARAMETER Minutes   How long to watch. Default 5.
.PARAMETER Mbit      Skip the speed measurement with -NoSpeed.
#>
[CmdletBinding()]
param([int]$Minutes = 5, [switch]$NoSpeed)

$ErrorActionPreference = 'Continue'
$ctl = 'C:\Program Files\DNet Engine\dnetctl.exe'
if (-not (Test-Path $ctl)) { throw 'DNet Engine is not installed here.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dir = Join-Path $HOME 'Documents\DNet test results'
New-Item -ItemType Directory -Force $dir | Out-Null
$file = Join-Path $dir ("watch-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
$lines = New-Object Collections.Generic.List[string]
function Log([string]$text) { $line = '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $text; $lines.Add($line); Write-Host $line }

function First-Line([string]$text) { (($text -split "`n") | Select-Object -First 1).Trim() }
function Exit-Address {
    try { $r = Invoke-WebRequest -Uri 'https://www.cloudflare.com/cdn-cgi/trace' -UseBasicParsing -TimeoutSec 8
          (($r.Content -split "`n") | Where-Object { $_ -match '^(ip|colo)=' }) -join ' ' } catch { 'no answer' }
}
function Speed([string]$label) {
    if ($NoSpeed) { return }
    $sw = [Diagnostics.Stopwatch]::StartNew(); $bytes = 0
    $tasks = 1..4 | ForEach-Object { $w = New-Object Net.WebClient; $w.DownloadDataTaskAsync('https://speed.cloudflare.com/__down?bytes=25000000') }
    foreach ($t in $tasks) { try { if ($t.Wait(60000)) { $bytes += $t.Result.Length } } catch { } }
    Log ("SPEED {0}: {1:N0} MB in {2:N1} s = {3:N0} Mbit/s (4 downloads at once)" -f $label, ($bytes / 1e6), $sw.Elapsed.TotalSeconds, ($bytes * 8 / 1e6 / [Math]::Max($sw.Elapsed.TotalSeconds, 0.1)))
}

Log "windows: $([Environment]::OSVersion.VersionString); watching for $Minutes minutes"
Log ("networks up now: " + ((Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | ForEach-Object { "$($_.Name) [$($_.InterfaceDescription), $($_.LinkSpeed)]" }) -join '; '))
Log ("service: " + (First-Line (& $ctl status 2>&1 | Out-String)))
Log ("version: " + (First-Line (& $ctl version 2>&1 | Out-String)))
Log ("address the world sees: " + (Exit-Address))
Speed 'at the start'

$end = (Get-Date).AddMinutes($Minutes)
$lastState = ''; $lastCheck = Get-Date '2000-01-01'; $dropped = 0; $answered = 0
while ((Get-Date) -lt $end) {
    $status = & $ctl status 2>&1 | Out-String
    $paths = & $ctl paths 2>&1 | Out-String
    $carrying = (($paths -split "`n") | Where-Object { $_ -match 'Carrying|carrying' } | Select-Object -First 1)
    $state = (First-Line $status) + ' | ' + ($carrying -replace '\s+', ' ').Trim()
    if ($state -ne $lastState) {
        Log "STATE $state"
        $adapters = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | ForEach-Object Name) -join ', '
        Log "      physical networks up: $adapters"
        $lastState = $state
    }
    if (((Get-Date) - $lastCheck).TotalSeconds -ge 5) {
        $lastCheck = Get-Date
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $r = Invoke-WebRequest -Uri 'https://www.wikipedia.org' -UseBasicParsing -TimeoutSec 6; if ($r.StatusCode -eq 200) { $answered++ } else { $dropped++ } } catch { $dropped++; Log ("WEB failed after {0:N1} s" -f $sw.Elapsed.TotalSeconds) }
    }
    Start-Sleep -Seconds 1
}
Log ("web checks: {0} answered, {1} failed" -f $answered, $dropped)
Log ("address the world sees now: " + (Exit-Address))
Speed 'at the end'
Log ("last status: " + (First-Line (& $ctl status 2>&1 | Out-String)))
Log "--- what the service says it did (dnetctl stats)"
(& $ctl stats 2>&1 | Out-String).Split("`n") | ForEach-Object { if ($_.Trim()) { Log "  $($_.Trim())" } }
Log "--- the service's own recent events"
(& $ctl events 2>&1 | Out-String).Split("`n") | Select-Object -Last 40 | ForEach-Object { if ($_.Trim()) { Log "  $($_.Trim())" } }
[IO.File]::WriteAllLines($file, $lines)
Write-Host "`nWritten to $file"
