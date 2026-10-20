<#
.SYNOPSIS
    T126 gate, client side: drives the running daemon over its control pipe as the console user.

.DESCRIPTION
    Started by Invoke-WslLab.ps1 -Gate Connect from the person's own elevated shell, while
    Invoke-ConnectGate.ps1 runs the daemon as SYSTEM. A Connect request must come from the
    interactive console user, which is why this half is not run by the SYSTEM task.

    It runs the same cycle several times, once per entry of -Cases, and the cycle is:
      connect -> a second connect is refused (ServiceBusy) -> wait for Connected -> the state is
      consistent and names the profile -> fetch a body from the origin, which is reachable only
      through the tunnel -> disconnect -> Disconnected -> the adapters are gone -> save the events.

    The default cases cover the whole product path through the real daemon:
      (default)          the race decides which profile carries traffic
      hy2-default        Hysteria 2 asked for by name   (raced alone, then started)
      reality-default    VLESS+REALITY asked for by name (raced alone, then started)
      awg-default        AmneziaWG asked for by name    (cannot be raced, started directly)
    A case that fails stops the run and says which step; the gate is always told to stop.

    Exit code: 0 PASS (every case) | 1 FAIL
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ReadyFile,
    [Parameter(Mandatory)] [string] $StopFile,
    [Parameter(Mandatory)] [string] $ResultFile,
    [string] $Origin = 'http://203.0.113.80:8080',
    [long]   $Bytes = 5000000,
    [ValidateRange(10, 600)] [int] $ConnectSeconds = 120,
    # '' is the default connect (no profile named).
    [string[]] $Cases = @('', 'hy2-default', 'reality-default', 'awg-default'),
    # dnetctl.exe (T127). When given, a last cycle is driven through the real command-line client
    # instead of the hand-written pipe client above, so the tool is proven against the live daemon.
    [string] $Dnetctl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$steps = New-Object System.Collections.Generic.List[object]
$cycles = New-Object System.Collections.Generic.List[object]
function Record([string]$name, [bool]$ok, [string]$detail) {
    $steps.Add([ordered]@{ step = $name; ok = $ok; detail = $detail })
    $mark = if ($ok) { 'ok  ' } else { 'FAIL' }
    Write-Host "[connect-driver] $mark $name : $detail"
    if (-not $ok) { throw "step failed: $name" }
}

# ------------------------------------------------------------------ the control pipe
function Connect-Pipe([int]$Milliseconds = 5000) {
    $p = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'DNetEngine\control', [System.IO.Pipes.PipeDirection]::InOut)
    $p.Connect($Milliseconds)
    return $p
}
function Send-Frame($pipe, [string]$json) {
    $body = [Text.Encoding]::UTF8.GetBytes($json)
    $len = [BitConverter]::GetBytes([uint32]$body.Length)
    $pipe.Write($len, 0, 4); $pipe.Write($body, 0, $body.Length); $pipe.Flush()
}
function Read-Exact($pipe, [int]$n) {
    $buf = New-Object byte[] $n; $got = 0
    while ($got -lt $n) {
        $r = $pipe.Read($buf, $got, $n - $got)
        if ($r -le 0) { throw 'the server closed the connection' }
        $got += $r
    }
    return $buf
}
function Read-Frame($pipe) {
    $len = [BitConverter]::ToUInt32((Read-Exact $pipe 4), 0)
    return [Text.Encoding]::UTF8.GetString((Read-Exact $pipe ([int]$len)))
}
function Read-ExactTimed($pipe, [int]$n, [int]$Milliseconds) {
    $buf = New-Object byte[] $n; $got = 0
    while ($got -lt $n) {
        $task = $pipe.ReadAsync($buf, $got, $n - $got)
        if (-not $task.Wait($Milliseconds)) { return $null }
        if ($task.Result -le 0) { return $null }
        $got += $task.Result
    }
    return $buf
}
# A frame, or $null if none arrives in time (or the stream ends).
function Read-FrameTimed($pipe, [int]$Milliseconds) {
    $head = Read-ExactTimed $pipe 4 $Milliseconds
    if ($null -eq $head) { return $null }
    $body = Read-ExactTimed $pipe ([int][BitConverter]::ToUInt32($head, 0)) 5000
    if ($null -eq $body) { return $null }
    return [Text.Encoding]::UTF8.GetString($body)
}
function Ask([string]$json) {
    $p = Connect-Pipe
    try { Send-Frame $p $json; return (Read-Frame $p) | ConvertFrom-Json } finally { $p.Dispose() }
}
function Has([object]$o, [string]$name) { ($null -ne $o) -and ($null -ne $o.PSObject.Properties[$name]) }

function Get-Events {
    $events = @()
    $p = Connect-Pipe
    try {
        Send-Frame $p '{"request":"Subscribe"}'
        [void](Read-Frame $p)   # the acknowledgement
        while ($events.Count -lt 300) {
            $frame = Read-FrameTimed $p 1500
            if ($null -eq $frame) { break }   # nothing more within the wait: the backlog is read
            $events += $frame
        }
    } finally { $p.Dispose() }
    return ,$events
}

# ------------------------------------------------------------------ one cycle
function Invoke-Cycle([string]$Wanted) {
    $label = if ($Wanted) { $Wanted } else { 'default' }
    $profileJson = if ($Wanted) { '"' + $Wanted + '"' } else { 'null' }
    $request = '{"request":"Connect","acknowledge_tier2":false,"profile":' + $profileJson + ',"endpoint":null}'

    $state = Ask '{"request":"GetState"}'
    Record "[$label] idle before connecting" (($state.status -eq 'Disconnected') -and ($state.routing_posture.posture -eq 'FailClosed')) "status=$($state.status) posture=$($state.routing_posture.posture)"

    $reply = Ask $request
    Record "[$label] connect accepted" ((Has $reply 'accepted') -and $reply.accepted) ($reply | ConvertTo-Json -Compress)

    $again = Ask $request
    Record "[$label] second connect refused" ((Has $again 'error') -and $again.error -eq 'ServiceBusy') ($again | ConvertTo-Json -Compress)

    $began = Get-Date
    $deadline = $began.AddSeconds($ConnectSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $state = Ask '{"request":"GetState"}'
    } while ($state.status -eq 'Probing' -and (Get-Date) -lt $deadline)
    $took = [math]::Round(((Get-Date) - $began).TotalSeconds, 1)
    $why = if ((Has $state 'failure') -and $state.failure) { ($state.failure | ConvertTo-Json -Compress) } else { '' }
    Record "[$label] tunnel up" ($state.status -eq 'Connected') "status=$($state.status) after $took s $why"
    $carrying = if ((Has $state 'active_profile') -and $state.active_profile) { $state.active_profile.id } else { '' }
    $wantedOk = (-not $Wanted) -or ($carrying -eq $Wanted)
    Record "[$label] state is consistent" ($wantedOk -and $state.routing_posture.posture -eq 'Tunnelled') `
        "profile=$carrying kind=$($state.active_profile.kind) posture=$($state.routing_posture.posture)"

    $uri = "$Origin/bytes/$Bytes"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(90)
    try { $data = $client.GetByteArrayAsync($uri).GetAwaiter().GetResult() } finally { $client.Dispose() }
    $sw.Stop()
    $mbps = [math]::Round(($data.Length * 8) / 1e6 / [math]::Max($sw.Elapsed.TotalSeconds, 0.001), 1)
    Record "[$label] transfer through the tunnel" ($data.Length -eq $Bytes) "$($data.Length) of $Bytes bytes in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s ($mbps Mbit/s)"

    # A few seconds of monitoring: live checks must keep the tunnel Connected.
    Start-Sleep -Seconds 8
    $state = Ask '{"request":"GetState"}'
    Record "[$label] still connected after the live checks ran" ($state.status -eq 'Connected') "status=$($state.status)"

    $reply = Ask '{"request":"Disconnect"}'
    Record "[$label] disconnect accepted" ((Has $reply 'accepted') -and $reply.accepted) ($reply | ConvertTo-Json -Compress)
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Milliseconds 500; $state = Ask '{"request":"GetState"}' } while ($state.status -ne 'Disconnected' -and (Get-Date) -lt $deadline)
    Record "[$label] disconnected" (($state.status -eq 'Disconnected') -and ($state.routing_posture.posture -eq 'FailClosed')) "status=$($state.status)"
    # The stop is queued behind the state change; give the adapters a moment to go.
    $none = $false
    for ($i = 0; $i -lt 40 -and -not $none; $i++) {
        $none = -not (Get-NetAdapter -Name 'dnet-tun0', 'dnet-awg0' -ErrorAction SilentlyContinue)
        if (-not $none) { Start-Sleep -Milliseconds 500 }
    }
    Record "[$label] adapters removed" $none 'no dnet-tun0 / dnet-awg0 after disconnect'

    $events = Get-Events
    $parsed = @($events | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } | Where-Object { $_ })
    $names = ($parsed | ForEach-Object { if (Has $_ 'event') { $_.event } }) -join ', '
    $unexplained = @($parsed | Where-Object { -not ((Has $_ 'because') -and $_.because) })
    Record "[$label] every event explains itself" (($parsed.Count -gt 0) -and ($unexplained.Count -eq 0)) "$($parsed.Count) event(s): $names"

    $cycles.Add([ordered]@{ case = $label; carried_by = $carrying; seconds_to_connect = $took; mbps = $mbps; events = $events })
}

# ------------------------------------------------------------------ a cycle through dnetctl
function Invoke-Ctl([string[]]$CtlArgs) {
    # Windows PowerShell 5.1 turns a native command's stderr into a terminating error under 'Stop',
    # and dnetctl reports every refusal on stderr with a non-zero exit code. That is the answer being
    # tested here, not a failure of the script: capture it. (Found by the first live run of this cycle.)
    $ErrorActionPreference = 'Continue'
    $out = & $Dnetctl @CtlArgs 2>&1 | ForEach-Object { "$_" }
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($out -join "`n") }
}

function Invoke-CtlCycle {
    $r = Invoke-Ctl @('status')
    Record '[dnetctl] status when idle' (($r.Code -eq 0) -and ($r.Text -match 'Disconnected')) "exit $($r.Code): $($r.Text -replace "`n", ' | ')"

    $r = Invoke-Ctl @('disconnect')
    Record '[dnetctl] disconnect when idle is not a failure' (($r.Code -eq 0) -and ($r.Text -match 'Not connected')) "exit $($r.Code): $($r.Text)"

    $r = Invoke-Ctl @('connect', '--timeout', '90')
    Record '[dnetctl] connect waits until connected' (($r.Code -eq 0) -and ($r.Text -match 'Status:\s+Connected')) "exit $($r.Code): $($r.Text -replace "`n", ' | ')"

    $r = Invoke-Ctl @('connect', '--no-wait')
    Record '[dnetctl] a second connect is refused' (($r.Code -eq 1) -and ($r.Text -match 'busy')) "exit $($r.Code): $($r.Text -replace "`n", ' | ')"

    $r = Invoke-Ctl @('status', '--json')
    $state = $r.Text | ConvertFrom-Json
    Record '[dnetctl] status --json is the service answer' (($r.Code -eq 0) -and ($state.status -eq 'Connected') -and ($state.routing_posture.posture -eq 'Tunnelled')) "profile=$($state.active_profile.id)"

    $sw = [Diagnostics.Stopwatch]::StartNew()
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    try { $data = $client.GetByteArrayAsync("$Origin/bytes/$Bytes").GetAwaiter().GetResult() } finally { $client.Dispose() }
    Record '[dnetctl] traffic flows while it says connected' ($data.Length -eq $Bytes) "$($data.Length) bytes in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s"

    $r = Invoke-Ctl @('events')
    Record '[dnetctl] events lists what happened and why' (($r.Code -eq 0) -and ($r.Text -match 'ProfileSelected') -and ($r.Text -match ': \S')) ($r.Text -replace "`n", ' | ')

    $r = Invoke-Ctl @('disconnect', '--timeout', '60')
    Record '[dnetctl] disconnect waits until disconnected' (($r.Code -eq 0) -and ($r.Text -match 'Disconnected')) "exit $($r.Code): $($r.Text)"

    $none = $false
    for ($i = 0; $i -lt 40 -and -not $none; $i++) {
        $none = -not (Get-NetAdapter -Name 'dnet-tun0', 'dnet-awg0' -ErrorAction SilentlyContinue)
        if (-not $none) { Start-Sleep -Milliseconds 500 }
    }
    Record '[dnetctl] adapters removed' $none 'no dnet-tun0 / dnet-awg0 after dnetctl disconnect'

    $cycles.Add([ordered]@{ case = 'dnetctl'; carried_by = $state.active_profile.id; seconds_to_connect = $null; mbps = $null; events = @() })
}

$verdict = 'FAIL'
try {
    $until = (Get-Date).AddSeconds(150)
    while (-not (Test-Path $ReadyFile)) {
        if ((Get-Date) -gt $until) { Record 'gate ready' $false 'the gate never signalled ready' }
        Start-Sleep -Milliseconds 500
    }
    $ready = $false
    while (-not $ready -and (Get-Date) -lt $until) {
        try { $p = Connect-Pipe 1000; $p.Dispose(); $ready = $true } catch { Start-Sleep -Milliseconds 500 }
    }
    Record 'control pipe' $ready 'accepts connections'

    foreach ($case in $Cases) { Invoke-Cycle $case }
    if ($Dnetctl) { Invoke-CtlCycle }
    $verdict = 'PASS'
}
catch {
    Write-Host "[connect-driver] $_" -ForegroundColor Red
}
finally {
    $result = [ordered]@{ verdict = $verdict; at = (Get-Date -Format o); steps = $steps; cycles = $cycles }
    try { [IO.File]::WriteAllText($ResultFile, ($result | ConvertTo-Json -Depth 6), $Utf8NoBom) } catch { Write-Host "could not write $ResultFile : $_" }
    # Always let the gate stop the daemon, whatever happened.
    try { [IO.File]::WriteAllText($StopFile, 'done', $Utf8NoBom) } catch { Write-Host "could not write $StopFile : $_" }
    Write-Host "[connect-driver] VERDICT: $verdict"
}
if ($verdict -eq 'PASS') { exit 0 } else { exit 1 }
