<#
.SYNOPSIS
  Runs in the lab guest, in the console session (see in-console.ps1): what actually leaves the guest's network card.

.DESCRIPTION
  A claim that "traffic goes through the tunnel" is measured where it cannot be argued with: a capture on the guest's
  physical network card. With the tunnel up, the only thing that should leave that card is the tunnel itself, to the
  server's address and port. A packet to any other destination (the internet, a name server, a ping) is a leak.

  The tunnel's own adapter is no use for this: it accepts a TCP connection to any address locally and then carries it,
  so "the connection opened" says nothing about the path. The first scenario is the control: with no connection, the
  probes must show up on the card, or the capture proves nothing.

  Scenarios (each prints the destinations seen on the card):
    control   disconnected, kill switch off     -> the probes must be visible (the capture can see a leak)
    steady    connected                         -> nothing but the server
    restart   connected, the core killed twice  -> nothing but the server, also while it restarts
    guard     kill switch on, connected, core killed twice -> same, and the guard must be in
  Needs the staged programs in C:\Program Files\DNet Engine, an endpoint imported, and a signed-in console user.
#>
[CmdletBinding()]
param([string]$Server = '10.0.2.2', [string[]]$Only)

$ErrorActionPreference = 'Continue'
$ctl = 'C:\Program Files\DNet Engine\dnetctl.exe'
$work = 'C:\lab\leak'
New-Item -ItemType Directory -Force $work | Out-Null

function Ctl { & $ctl @args 2>&1 | Out-String }
function Status-Line { ((Ctl status) -split "`n" | Select-Object -First 1).Trim() }

# One round of probes, each of which would leave the card if nothing carried it elsewhere.
function Probe-Once {
    $name = 'leak' + (Get-Random -Maximum 99999999) + '.example.com'
    try { [void][System.Net.Dns]::GetHostAddresses($name) } catch { }
    $tcp = New-Object Net.Sockets.TcpClient
    try { $a = $tcp.BeginConnect('1.1.1.1', 443, $null, $null); [void]$a.AsyncWaitHandle.WaitOne(500) } catch { } finally { $tcp.Close() }
    $udp = New-Object Net.Sockets.UdpClient
    try { [void]$udp.Send([byte[]](1, 2, 3, 4), 4, '8.8.8.8', 53) } catch { } finally { $udp.Close() }
    ping.exe -n 1 -w 300 9.9.9.9 | Out-Null
}

function Probe-For([int]$Seconds) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) { Probe-Once; Start-Sleep -Milliseconds 400 }
}

# Capture on the physical card around an action; return what it sent, by destination.
function Capture([scriptblock]$Action) {
    $etl = Join-Path $work 'cap.etl'; $txt = Join-Path $work 'cap.txt'
    Remove-Item $etl, $txt -ErrorAction SilentlyContinue
    pktmon stop 2>&1 | Out-Null
    pktmon filter remove 2>&1 | Out-Null
    $card = ((pktmon list 2>&1 | Out-String) -split "`n" | Where-Object { $_ -match '82574L' } | Select-Object -First 1)
    $id = if ($card -match '^\s*(\d+)\s') { $Matches[1] } else { '2' }
    pktmon start --capture --comp $id --pkt-size 0 --file-name $etl 2>&1 | Out-Null
    & $Action
    pktmon stop 2>&1 | Out-Null
    pktmon etl2txt $etl --out $txt 2>&1 | Out-Null
    $sent = @{}
    $script:dnsAsked = @{}
    if (Test-Path $txt) {
        $direction = ''
        foreach ($line in Get-Content $txt) {
            if ($line -match 'Direction (Tx|Rx)') { $direction = $Matches[1]; continue }
            # The line after a packet's header: "<mac> > <mac>, ethertype IPv4 (0x0800), length N: A.p > B.q: <what>"
            if ($direction -eq 'Tx' -and $line -match 'ethertype IPv4 \(0x0800\), length \d+: (\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?: (\S+)') {
                # Copied out first: the next -match replaces $Matches.
                $destination = $Matches[2]; $port = $Matches[3]; $token = $Matches[4]
                $what = if ($token -match '^(Flags|UDP|ICMP)') { $token.TrimEnd(',') } else { 'ip' }
                $key = '{0}:{1} {2}' -f $destination, $port, $what
                $sent[$key] = 1 + [int]$sent[$key]
                # A name server query also says what was asked: the name is what a leak would give away.
                if ($port -eq '53' -and $line -match ': \d+\+?\S* (\w+)\? (\S+)') { $script:dnsAsked["$($Matches[1]) $($Matches[2])"] = 1 }
                $direction = ''
            }
        }
    }
    $sent
}

function Report([string]$Scenario, $Sent, [bool]$ExpectLeak) {
    $other = $Sent.GetEnumerator() | Where-Object { $_.Key -notlike "$Server`:*" -and $_.Key -notlike '255.255.255.255:*' -and $_.Key -notlike '10.0.2.255:*' }
    $ours = $Sent.GetEnumerator() | Where-Object { $_.Key -like "$Server`:*" }
    '--- {0}' -f $Scenario
    '    to the server : {0} packets' -f (($ours | Measure-Object Value -Sum).Sum)
    if ($other) {
        '    to anything else:'
        $other | Sort-Object Value -Descending | Select-Object -First 12 | ForEach-Object { '      {0,5}  {1}' -f $_.Value, $_.Key }
    } else { '    to anything else: none' }
    if ($script:dnsAsked.Count) { '    names asked of a name server on the card: ' + (($script:dnsAsked.Keys | Sort-Object | Select-Object -First 8) -join ', ') }
    $leaked = [bool]$other
    if ($ExpectLeak) { if ($leaked) { 'RESULT {0}: PASS (the capture sees what leaves; this is the control)' -f $Scenario } else { 'RESULT {0}: FAIL (the control saw nothing, so the capture proves nothing)' -f $Scenario } }
    else { if ($leaked) { 'RESULT {0}: FAIL (traffic left the card outside the tunnel)' -f $Scenario } else { 'RESULT {0}: PASS' -f $Scenario } }
}

function Run([string]$Name) { -not $Only -or ($Only -contains $Name) }

Ctl disconnect | Out-Null; Ctl kill-switch off | Out-Null; Start-Sleep 3

if (Run 'control') {
    $sent = Capture { Probe-For 6 }
    Report 'control (disconnected, switch off)' $sent $true
}

if (Run 'steady') {
    Ctl connect | Out-Null; Start-Sleep 15
    'status: ' + (Status-Line)
    $sent = Capture { Probe-For 12 }
    Report 'steady (connected)' $sent $false
}

if (Run 'restart') {
    if ((Status-Line) -notmatch 'Connected') { Ctl connect | Out-Null; Start-Sleep 15 }
    $sent = Capture {
        foreach ($round in 1, 2) {
            Get-Process primary-core -ErrorAction SilentlyContinue | Stop-Process -Force
            Probe-For 8
        }
    }
    'status: ' + (Status-Line)
    Report 'restart (core killed twice while probing)' $sent $false
}

if (Run 'guard') {
    Ctl disconnect | Out-Null; Start-Sleep 3
    'kill-switch on -> ' + ((Ctl kill-switch on) -replace "\s+", ' ')
    Ctl connect | Out-Null; Start-Sleep 15
    'status: ' + (Status-Line)
    'kill-switch: ' + ((Ctl kill-switch status) -replace "\s+", ' ')
    $sent = Capture {
        foreach ($round in 1, 2) {
            Get-Process primary-core -ErrorAction SilentlyContinue | Stop-Process -Force
            Probe-For 8
        }
    }
    'status: ' + (Status-Line)
    Report 'guard (switch on, core killed twice while probing)' $sent $false
    'disconnect (releases the guard): ' + ((Ctl disconnect) -replace "\s+", ' ')
    Start-Sleep 3
    'kill-switch: ' + ((Ctl kill-switch status) -replace "\s+", ' ')
    Ctl kill-switch off | Out-Null
}

pktmon stop 2>&1 | Out-Null
