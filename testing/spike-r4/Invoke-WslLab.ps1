<#
.SYNOPSIS
    Runs the T055 routing-loop gate against an endpoint that lives in a WSL2 VM and is reached
    through the host's DEFAULT route. No cloud host is needed.

.DESCRIPTION
    The gate (Invoke-SpikeR4.ps1) is only meaningful if the endpoint is reached through the
    default gateway: a loopback or on-link endpoint never enters the TUN, so a loop cannot form.
    A WSL2 VM sits behind its own virtual switch, so this script makes it the host's temporary
    default gateway and uses an endpoint address that is NOT on that switch's subnet.

    Phases (README.md section 6 is the runbook):
      Check     Changes nothing on the host. Runs every preflight, starts the endpoint in the VM
                for a short hold, exports its client parameters and proves the server answers
                inside the VM. Run this first; it needs no elevation.
      Launch    Needs an elevated shell. Preflights, starts the endpoint, then registers two
                SYSTEM tasks (the gate, and a watchdog) and waits for the result.
      Run       (the SYSTEM task) Saves the interface metrics, makes the VM the default gateway,
                checks the endpoint answers, runs Invoke-SpikeR4.ps1, restores networking.
      Watchdog  (the SYSTEM task) After -WatchdogMinutes: stops the gate if it is still running,
                reaps what it left, restores networking, removes both tasks.
      Restore   Manual recovery. Puts the metrics back and removes the temporary routes. Idempotent.

    THE HOST HAS NO INTERNET DURING THE RUN (its default route points at a VM that does not
    forward). That is inherent to the test, not a defect. A run normally takes a few minutes; the
    watchdog bounds the worst case. If networking is ever left broken, from an elevated shell:
        .\Invoke-WslLab.ps1 -Phase Restore

    The "physical" adapter the gate counts is the host's vEthernet (WSL) adapter, a virtual NIC.
    That is what distinguishes this from the unsupported bridged-LAN attempt in README.md, but
    the verdict still stands or falls on the gate's own guards: the control run must loop, and
    pktmon must expose both adapters, or the result is INVALID or INCONCLUSIVE, never PASS.

    Prerequisites:
      - WSL distro $Distro, an export of the harness endpoint image (it holds /opt/awg-server.sh
        and the pinned amneziawg-go). wsl-endpoint.sh is copied into it on every run.
      - target\release\examples\spike_r4.exe built (cargo build --release -p dnet-netstate
        --example spike_r4), and the three vendor binaries (cargo xtask fetch-vendor).
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Launch', 'Run', 'Watchdog', 'Restore')] [string] $Phase = 'Check',
    # TEST-NET-3. Must not be on the vEthernet (WSL) subnet, and must not be the origin address
    # (203.0.113.80) that the endpoint reaches only through the tunnel.
    [string] $EndpointIp = '203.0.113.10',
    [string] $Distro = 'dnet-endpoint',
    # Resolved by Launch (WSL distros are per user, so the SYSTEM task cannot ask wsl.exe).
    [string] $WslIp,
    [ValidateRange(4, 60)] [int] $WatchdogMinutes = 10,
    # Loop: the T055 routing-loop gate (the default). Connect: the T126 gate, which runs the real
    # daemon against the same endpoint and drives it over its control pipe.
    [ValidateSet('Loop', 'Connect')] [string] $Gate = 'Loop',
    # Which transport the Loop gate measures: A (AmneziaWG, the default) or Hy2 (Hysteria 2). Hy2
    # makes the VM serve Hysteria 2 as well. The Connect gate always serves and tests all three.
    [ValidateSet('A', 'Hy2')] [string] $Transport = 'A',
    # The SID of the person who started the lab; Launch passes it so the SYSTEM task can hand the
    # results folder back to them. Validated before it reaches icacls.
    [string] $GrantSid,
    [switch] $NoWait
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Here        = $PSScriptRoot
$Repo        = (Resolve-Path (Join-Path $Here '..\..')).Path
$StateFile   = Join-Path $Here 'wsl-lab-state.json'
$LogFile     = Join-Path $Here 'wsl-lab.log'
$EndpointLog = Join-Path $Here 'wsl-lab-endpoint.log'
$LabParams   = Join-Path $Here 'wsl-lab-awg-client.json'
# The Connect gate also serves Hysteria 2 and REALITY; their client files are exported beside the
# AmneziaWG one, under the names `xtask import-harness-endpoint` reads.
$ClientDir   = Join-Path $Here 'wsl-lab-client'
# The VM serves Hysteria 2 and REALITY too when either gate needs them.
$ServeAll    = ($Gate -eq 'Connect') -or ($Transport -eq 'Hy2')
$Results     = Join-Path $Here 'results'
$Runner      = Join-Path $Repo 'target\release\examples\spike_r4.exe'
$Dnetd       = Join-Path $Repo 'target\release\dnetd.exe'
$Xtask       = Join-Path $Repo 'target\release\xtask.exe'
$Dnetctl     = Join-Path $Repo 'target\release\dnetctl.exe'
# Rendezvous between the SYSTEM side (Invoke-ConnectGate.ps1) and the client side (Invoke-ConnectDriver.ps1).
$ReadyFile   = Join-Path $Here 'wsl-lab-connect.ready'
$StopFile    = Join-Path $Here 'wsl-lab-connect.stop'
$DriverOut   = Join-Path $Here 'wsl-lab-connect-result.json'
$SwitchPat   = 'vEthernet (WSL*'
$RunTask     = 'dnet-t055-run'
$DogTask     = 'dnet-t055-watchdog'
$Finished    = 'LAB-FINISHED'
$Utf8NoBom   = New-Object System.Text.UTF8Encoding($false)

function Log([string]$m) {
    $line = "$(Get-Date -Format o) $m"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Test-Role([Security.Principal.WindowsBuiltInRole]$Role) {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole($Role)
}
function Test-System { [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem }

function Get-Switch { Get-NetAdapter | Where-Object { $_.Name -like $SwitchPat } | Select-Object -First 1 }

# wsl.exe prints UTF-16 with NULs when redirected.
function Invoke-Wsl([string[]]$WslArgs) {
    # Windows PowerShell 5.1 turns a native command's stderr into a terminating error under 'Stop'.
    $ErrorActionPreference = 'Continue'
    (((& wsl.exe @WslArgs 2>&1) | ForEach-Object { "$_" }) -join "`n") -replace "`0", ''
}

# ------------------------------------------------------------------ preflight
# Everything that can be known before the host's routing is touched. Collected, not thrown one
# at a time, so a user fixes all of it in one go. Nothing here changes the host.
function Get-Problems([bool]$NeedElevation) {
    $p = New-Object System.Collections.Generic.List[string]
    if ($NeedElevation -and -not (Test-Role Administrator)) { $p.Add('Launch needs an elevated PowerShell (Run as administrator).') }
    if (Test-Path $StateFile) { $p.Add("A previous run left $StateFile. Run -Phase Restore first.") }

    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($EndpointIp, [ref]$addr) -or $addr.AddressFamily -ne 'InterNetwork') {
        $p.Add("-EndpointIp '$EndpointIp' is not an IPv4 address.")
    } elseif ([System.Net.IPAddress]::IsLoopback($addr) -or $EndpointIp -eq '203.0.113.80') {
        $p.Add("-EndpointIp $EndpointIp is loopback or the tunnel-only origin address.")
    } else {
        # The endpoint must not be on-link today, or the gate would call the topology VACUOUS.
        try {
            $r = Find-NetRoute -RemoteIPAddress $EndpointIp -ErrorAction Stop |
                Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
            if ($r -and $r.DestinationPrefix -ne '0.0.0.0/0') {
                $p.Add("$EndpointIp is already routed by $($r.DestinationPrefix); it must only match the default route.")
            }
        } catch { }
    }

    $running = Get-ScheduledTask -TaskName 'dnet-t055-*' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    if ($running) { $p.Add("Scheduled task '$($running[0].TaskName)' is still running.") }
    if (Get-NetAdapter -Name 'dnet-tun0', 'dnet-awg0' -ErrorAction SilentlyContinue) {
        $p.Add('Adapters dnet-tun0/dnet-awg0 already exist (earlier run?). Reboot or remove them first.')
    }
    if (Get-NetRoute -DestinationPrefix "$EndpointIp/32" -ErrorAction SilentlyContinue) {
        $p.Add("A /32 route to $EndpointIp already exists; it would mask a loop.")
    }

    # A run that died before it restored leaves the real adapter on the fixed metric the lab sets.
    # The next run would then save that as the "original" and put it back, for ever: found when a
    # Wi-Fi adapter stayed at 9000 after a stuck run.
    $stuck = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.ConnectionState -eq 'Connected' -and $_.AutomaticMetric -eq 'Disabled' -and
            $_.InterfaceMetric -ge 9000 -and $_.InterfaceAlias -notlike $SwitchPat }
    foreach ($i in $stuck) {
        $p.Add("Interface '$($i.InterfaceAlias)' has a fixed metric of $($i.InterfaceMetric), which the lab sets and an earlier run did not undo. " +
               "Put it back first (elevated): Set-NetIPInterface -InterfaceIndex $($i.ifIndex) -AddressFamily IPv4 -AutomaticMetric Enabled")
    }

    # The endpoint Launch starts is a wsl.exe process holding this file open. One left over from an
    # interrupted run makes the next Launch fail with a sharing violation; Restore stops it.
    $emptyIn = Join-Path ([IO.Path]::GetTempPath()) 'wsl-lab-empty.in'
    try { [IO.File]::Open($emptyIn, 'OpenOrCreate', 'ReadWrite', 'None').Dispose() }
    catch [System.IO.IOException] { $p.Add("An endpoint from an earlier run is still running (it holds $emptyIn). Run -Phase Restore, which stops it.") }
    catch { }

    $distros = (Invoke-Wsl @('-l', '-q')) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($distros -notcontains $Distro) { $p.Add("WSL distro '$Distro' is not installed (wsl -l -q shows: $($distros -join ', ')).") }

    if ($Gate -eq 'Connect') {
        foreach ($f in $Dnetd, $Xtask, $Dnetctl) {
            if (-not (Test-Path $f)) { $p.Add("Missing $f. Build it: cargo build --release -p dnetd -p xtask -p dnetctl") }
        }
    } elseif (-not (Test-Path $Runner)) {
        $p.Add("Missing $Runner. Build it: cargo build --release -p dnet-netstate --example spike_r4")
    }
    foreach ($f in 'wintun\wintun.dll', 'primary-core\primary-core.exe', 'amneziawg-go\amneziawg-go.exe') {
        if (-not (Test-Path (Join-Path $Repo "vendor\$f"))) { $p.Add("Missing vendor\$f. Run: cargo run -p xtask -- fetch-vendor") }
    }
    if (-not (Test-Path (Join-Path $Here 'wsl-endpoint.sh'))) { $p.Add('Missing wsl-endpoint.sh.') }
    return $p
}

# ------------------------------------------------------------------ endpoint in the VM
# Copies wsl-endpoint.sh into the distro, starts it as a hidden long-lived process (it holds the
# VM alive), waits for READY, and exports the client parameters the gate needs. Returns the VM's
# eth0 address and the process, which the caller must stop if it abandons the run.
function Start-Endpoint([int]$HoldSeconds) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("wsl-endpoint-" + [guid]::NewGuid().ToString('N') + '.sh')
    try {
        # The distro needs LF line endings whatever the checkout's autocrlf did.
        $text = (Get-Content (Join-Path $Here 'wsl-endpoint.sh') -Raw) -replace "`r`n", "`n"
        [IO.File]::WriteAllText($tmp, $text, $Utf8NoBom)
        $copy = Start-Process wsl.exe -PassThru -Wait -WindowStyle Hidden -RedirectStandardInput $tmp `
            -RedirectStandardOutput "$EndpointLog.copy" -RedirectStandardError "$EndpointLog.copyerr" `
            -ArgumentList @('-d', $Distro, '-u', 'root', '--exec', 'sh', '-c', '"cat > /opt/wsl-endpoint.sh && chmod 755 /opt/wsl-endpoint.sh"')
        if ($copy.ExitCode -ne 0) { throw "copying wsl-endpoint.sh into $Distro failed (exit $($copy.ExitCode))" }
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Remove-Item "$EndpointLog.copy", "$EndpointLog.copyerr" -Force -ErrorAction SilentlyContinue
    }

    Remove-Item $EndpointLog, "$EndpointLog.err" -Force -ErrorAction SilentlyContinue
    $nul = Join-Path ([IO.Path]::GetTempPath()) 'wsl-lab-empty.in'
    [IO.File]::WriteAllText($nul, '', $Utf8NoBom)
    $proc = Start-Process wsl.exe -PassThru -WindowStyle Hidden -RedirectStandardInput $nul `
        -RedirectStandardOutput $EndpointLog -RedirectStandardError "$EndpointLog.err" `
        -ArgumentList (@('-d', $Distro, '-u', 'root', '--exec', '/opt/wsl-endpoint.sh', $EndpointIp, "$HoldSeconds") + $(if ($ServeAll) { 'all' } else { @() }))

    $deadline = (Get-Date).AddSeconds(120)
    $ethIp = $null
    while ((Get-Date) -lt $deadline) {
        $out = if (Test-Path $EndpointLog) { (Get-Content $EndpointLog -Raw -ErrorAction SilentlyContinue) } else { $null }
        if ($out -and $out -match '(?m)^FAILED (.+)$') { $proc.Kill(); throw "endpoint setup failed: $($Matches[1])" }
        if ($out -and $out -match '(?m)^READY (\d+\.\d+\.\d+\.\d+)\s*$') { $ethIp = $Matches[1]; break }
        if ($proc.HasExited) { throw "endpoint process exited early (code $($proc.ExitCode)); see $EndpointLog and $EndpointLog.err" }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ethIp) { $proc.Kill(); throw "endpoint did not report READY within 120 s; see $EndpointLog" }

    # Export the client parameters the gate reads. UTF-8 without a BOM: serde_json rejects one.
    $json = Invoke-Wsl @('-d', $Distro, '-u', 'root', '--exec', 'cat', '/opt/state/awg-client.json')
    try { $parsed = $json | ConvertFrom-Json } catch { $proc.Kill(); throw "client parameters are not valid JSON: $_" }
    foreach ($k in 'client_private_key_hex', 'server_public_key_hex', 'client_address', 'listen_port', 'obfuscation') {
        if (-not $parsed.PSObject.Properties[$k]) { $proc.Kill(); throw "client parameters lack '$k'" }
    }
    [IO.File]::WriteAllText($LabParams, $json, $Utf8NoBom)

    if ($ServeAll) {
        New-Item -ItemType Directory -Force $ClientDir | Out-Null
        Get-ChildItem $ClientDir -File -ErrorAction SilentlyContinue | Remove-Item -Force
        [IO.File]::WriteAllText((Join-Path $ClientDir 'awg-client.json'), $json, $Utf8NoBom)
        foreach ($name in 'hy2', 'reality') {
            $other = Invoke-Wsl @('-d', $Distro, '-u', 'root', '--exec', 'cat', "/opt/state/$name-client.json")
            try { $null = $other | ConvertFrom-Json } catch { $proc.Kill(); throw "$name client parameters are not valid JSON" }
            [IO.File]::WriteAllText((Join-Path $ClientDir "$name-client.json"), $other, $Utf8NoBom)
        }
    }

    # READY is only printed after the script verified, inside the VM, that the endpoint address is
    # the VM's own, the server process runs and a UDP listener holds the port.
    return @{ WslIp = $ethIp; Process = $proc }
}

# ------------------------------------------------------------------ restoration
# Kills what the gate staged under results\ (cores run from private per-run copies, so the path
# match cannot hit anything else) and the runner. Cores die before routes are undone: removing
# the endpoint route while a core still sends would loop its packets.
function Stop-Leftovers {
    $victims = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ExecutablePath -and ($_.ExecutablePath.StartsWith($Results, 'OrdinalIgnoreCase') -or
                                $_.ExecutablePath -ieq $Runner)
    }
    foreach ($v in $victims) {
        Log "restore: stopping leftover $($v.Name) (pid $($v.ProcessId))"
        Stop-Process -Id $v.ProcessId -Force -ErrorAction SilentlyContinue
    }
    if ($victims) { Start-Sleep -Seconds 2 }
}

function Invoke-Restore {
    if (-not (Test-Path $StateFile)) { Log 'restore: no saved state; nothing to do'; return }
    $s = Get-Content $StateFile -Raw | ConvertFrom-Json
    Stop-Leftovers
    # Only rows that point at this lab's VM: the default route and the endpoint host route.
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $s.WslIp -and ($_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq "$($s.EndpointIp)/32") } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($i in $s.Interfaces) {
        if ($i.Automatic -eq 'Enabled') {
            Set-NetIPInterface -InterfaceIndex $i.Index -AddressFamily IPv4 -AutomaticMetric Enabled
        } else {
            Set-NetIPInterface -InterfaceIndex $i.Index -AddressFamily IPv4 -InterfaceMetric $i.Metric
        }
    }
    Remove-Item $StateFile -Force
    $left = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { "if$($_.ifIndex) via $($_.NextHop)" })
    Log "restore: default route and interface metrics put back; default routes now: $($left -join '; ')"
}

# The gate runs as SYSTEM, and the files and folders it creates belong to SYSTEM. Give them back to
# the person who started the lab, so the results can be read, committed-around and deleted without
# an elevated shell. Works from an elevated user (takes ownership first) and from SYSTEM.

# The first link (junction or symbolic link) at or under $Root, or $null. Never descends into one.
# The results folder is writable by the person who starts the lab, and Repair-Results changes
# ownership and permissions recursively as an administrator or SYSTEM: a link planted inside it
# would send that change to wherever it points.
function Find-ReparsePoint {
    param([string]$Root)
    $link = [IO.FileAttributes]::ReparsePoint
    if ((Get-Item -LiteralPath $Root -Force).Attributes -band $link) { return $Root }
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($Root)
    while ($pending.Count) {
        $dir = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue) {
            if ($item.Attributes -band $link) { return $item.FullName }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
    return $null
}

function Repair-Results {
    param([string]$Sid)
    if (-not (Test-Path $Results)) { return }
    if ($Sid -notmatch '^S-1-\d+(-\d+)+$') { Log "restore: not repairing results permissions (no valid SID given)"; return }
    $link = Find-ReparsePoint $Results
    if ($link) { Log "restore: NOT repairing results permissions: '$link' is a link, and the repair would follow it. Remove it and run -Phase Restore."; return }
    if (-not (Test-System)) { & takeown.exe /f $Results /r /d y *> $null }
    & icacls.exe $Results /grant "*${Sid}:(OI)(CI)F" /t /c /q *> $null
    Log "restore: results folder handed back to $Sid"
}

# What the VM saw during the run: the packets on the endpoint port in both directions, the server's
# own debug log and the NAT counters. Only the person who started the lab can ask the VM (WSL
# distros are per user), so Launch calls this after the SYSTEM task has finished.
function Save-VmDiagnostics {
    $text = Invoke-Wsl @('-d', $Distro, '-u', 'root', '--exec', '/opt/wsl-endpoint.sh', 'diag')
    [IO.File]::WriteAllText((Join-Path $Here 'wsl-lab-vm-diag.txt'), $text, $Utf8NoBom)
    $latest = Get-ChildItem $Results -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($latest) {
        # A folder left by a SYSTEM run may still be unwritable until Launch repairs it.
        try { [IO.File]::WriteAllText((Join-Path $latest.FullName 'vm-diag.txt'), $text, $Utf8NoBom) }
        catch { Log "diagnostics: could not copy into $($latest.Name): $($_.Exception.Message)" }
    }
    Log "diagnostics: the VM's view saved to wsl-lab-vm-diag.txt ($($text.Length) characters)"
    return $text
}

function Remove-LabTasks {
    foreach ($t in $RunTask, $DogTask) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
}

switch ($Phase) {

    'Check' {
        $problems = @(Get-Problems $false)
        if ($problems.Count) { $problems | ForEach-Object { Write-Host "PROBLEM: $_" -ForegroundColor Red }; exit 2 }
        Log 'check: preflight clean; starting the endpoint for a 90 s self-test'
        $ep = Start-Endpoint 90
        try {
            $sw = Get-Switch
            Log "check: endpoint READY in the VM ($($ep.WslIp)); client parameters exported to $LabParams"
            if ($sw) { Log "check: host adapter '$($sw.Name)' present (ifIndex $($sw.ifIndex))" }
            else { Log 'check: WARNING no "vEthernet (WSL" adapter on the host; Launch will refuse until it exists' }
            if ($sw) {
                $net = Get-NetIPAddress -InterfaceIndex $sw.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($net) { Log "check: host side of the VM switch is $($net.IPAddress)/$($net.PrefixLength); VM is $($ep.WslIp)" }
            }
            $diag = Save-VmDiagnostics
            foreach ($needle in '== PREROUTING nat rules', "server's view of the peer", 'errno=0') {
                if ($diag -notmatch [regex]::Escape($needle)) { throw "check: the VM diagnostics lack '$needle'" }
            }
            Log 'check: OK. Nothing on the host was changed.'
        } finally {
            if (-not $ep.Process.HasExited) { $ep.Process.Kill() }
        }
    }

    'Launch' {
        $problems = @(Get-Problems $true)
        if ($problems.Count) { $problems | ForEach-Object { Write-Host "PROBLEM: $_" -ForegroundColor Red }; exit 2 }
        Remove-LabTasks
        # Kept, not deleted: a run that fails is the one whose log is wanted.
        if (Test-Path $LogFile) { Move-Item $LogFile "$LogFile.prev" -Force -ErrorAction SilentlyContinue }
        $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Repair-Results $mySid

        $hold = ($WatchdogMinutes + 3) * 60
        $ep = Start-Endpoint $hold
        $sw = Get-Switch
        if (-not $sw) { $ep.Process.Kill(); throw 'No "vEthernet (WSL" adapter on the host; is the WSL VM running?' }
        $WslIp = $ep.WslIp

        $self = Join-Path $Here 'Invoke-WslLab.ps1'
        $sys  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        # A laptop on battery must still run the watchdog, and neither task may outlive its purpose.
        $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes ($WatchdogMinutes + 2))
        $mk = {
            param($phase, $at, $name)
            $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$self`" -Phase $phase -EndpointIp $EndpointIp -WslIp $WslIp -WatchdogMinutes $WatchdogMinutes -Gate $Gate -Transport $Transport -GrantSid $mySid"
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
            $trg = New-ScheduledTaskTrigger -Once -At $at
            Register-ScheduledTask -TaskName $name -Action $act -Trigger $trg -Principal $sys -Settings $set -Force | Out-Null
        }
        $dogAt = (Get-Date).AddMinutes($WatchdogMinutes)
        # The watchdog is registered first, so networking is always restored.
        & $mk 'Watchdog' $dogAt $DogTask
        & $mk 'Run' (Get-Date).AddYears(1) $RunTask
        Log "launch: endpoint up at $WslIp; watchdog restores networking at $($dogAt.ToString('HH:mm:ss')); starting the gate as SYSTEM. The host goes offline now."
        Remove-Item $ReadyFile, $StopFile, $DriverOut -Force -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $RunTask

        # The Connect gate's client half runs here, as the person at the console: the daemon only
        # accepts a Connect from them, and the SYSTEM task cannot be that person.
        $driverExit = $null
        if ($Gate -eq 'Connect' -and -not $NoWait) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Here 'Invoke-ConnectDriver.ps1') `
                -ReadyFile $ReadyFile -StopFile $StopFile -ResultFile $DriverOut -Dnetctl $Dnetctl *>&1 |
                Tee-Object -FilePath (Join-Path $Here 'wsl-lab-connect-driver.log') | ForEach-Object { Log "driver: $_" }
            $driverExit = $LASTEXITCODE
            Log "driver exit code $driverExit"
            # The gate never came up: waiting out the watchdog (10 minutes) tells the person nothing
            # and leaves the host offline. Stop now, put networking back, and say what to read.
            if ($driverExit -ne 0 -and -not (Test-Path $ReadyFile)) {
                Log 'launch: the gate never signalled ready; stopping the lab now instead of waiting for the watchdog'
                Stop-ScheduledTask -TaskName $RunTask -ErrorAction SilentlyContinue
                try { Invoke-Restore } catch { Log "ERROR while restoring: $_" }
                try { [void](Save-VmDiagnostics) } catch { }
                $ep.Process.Kill()
                Invoke-Wsl @('--terminate', $Distro) | Out-Null
                Remove-LabTasks
                Repair-Results $mySid
                Write-Host "The gate never became ready, so the lab was stopped and networking put back. Read $LogFile for the step that stalled." -ForegroundColor Red
                exit 5
            }
        }

        if ($NoWait) { Write-Host "Not waiting. Follow $LogFile; the line '$Finished' marks the end."; break }
        $until = (Get-Date).AddMinutes($WatchdogMinutes + 2)
        while ((Get-Date) -lt $until) {
            Start-Sleep -Seconds 3
            if ((Test-Path $LogFile) -and (Select-String -Path $LogFile -Pattern $Finished -Quiet)) { break }
        }
        try { [void](Save-VmDiagnostics) } catch { Log "launch: could not collect the VM's view: $_" }
        $ep.Process.Kill()
        Remove-LabTasks
        if (-not ((Test-Path $LogFile) -and (Select-String -Path $LogFile -Pattern $Finished -Quiet))) {
            Write-Host "The lab did not report completion. Run: .\Invoke-WslLab.ps1 -Phase Restore" -ForegroundColor Red
            exit 5
        }
        Get-Content $LogFile | Select-Object -Last 25 | ForEach-Object { Write-Host $_ }
        $latest = Get-ChildItem $Results -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        if ($latest -and (Test-Path (Join-Path $latest.FullName 'summary.md'))) { Write-Host "`nSummary: $(Join-Path $latest.FullName 'summary.md')" }
        $codeLine = Select-String -Path $LogFile -Pattern 'gate exit code (\d+)' | Select-Object -Last 1
        $gateExit = if ($codeLine) { [int]$codeLine.Matches[0].Groups[1].Value } else { 5 }
        if ($Gate -eq 'Connect') {
            # Both halves must be clean: the driver saw it work, and the gate saw nothing left behind.
            Log "connect gate: driver $driverExit, daemon side $gateExit; result in $DriverOut"
            if ($driverExit -ne 0) { exit 1 }
            exit $gateExit
        }
        exit $gateExit
    }

    'Run' {
        try {
            # Every step is timestamped by `Log`, so a stall shows where it was.
            Log 'run: started as SYSTEM'
            if (-not (Test-System)) { throw 'Run must execute as LocalSystem (BUG-007); it is started by Launch.' }
            $wsl = Get-Switch
            if (-not $wsl) { throw 'No "vEthernet (WSL" adapter; is the WSL VM running?' }
            if (-not $WslIp) { throw 'Run needs -WslIp (Launch passes it).' }
            if (-not (Test-Path $LabParams)) { throw "Missing $LabParams (Launch writes it)." }
            if ($ServeAll -and -not (Test-Path (Join-Path $ClientDir 'reality-client.json'))) { throw "Missing the client files in $ClientDir (Launch writes them)." }
            Log "WSL VM $WslIp on $($wsl.Name) (ifIndex $($wsl.ifIndex)); endpoint $EndpointIp"

            $targets = @($wsl.ifIndex) + @((Get-NetRoute -DestinationPrefix '0.0.0.0/0').ifIndex) | Select-Object -Unique
            $state = @{
                WslIp = $WslIp
                EndpointIp = $EndpointIp
                Interfaces = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $targets -contains $_.ifIndex } | ForEach-Object {
                    @{ Index = $_.ifIndex; Automatic = "$($_.AutomaticMetric)"; Metric = $_.InterfaceMetric } })
            }
            # The record is durable BEFORE the first change, so any later failure can be undone.
            [IO.File]::WriteAllText($StateFile, ($state | ConvertTo-Json -Depth 4), $Utf8NoBom)

            Log 'run: network state recorded; changing the default route'
            # Every other default route loses to the VM by metric; none is deleted.
            foreach ($i in $state.Interfaces) {
                if ($i.Index -ne $wsl.ifIndex) { Set-NetIPInterface -InterfaceIndex $i.Index -AddressFamily IPv4 -InterfaceMetric 9000 }
            }
            Set-NetIPInterface -InterfaceIndex $wsl.ifIndex -AddressFamily IPv4 -InterfaceMetric 1
            New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $wsl.ifIndex -NextHop $WslIp -RouteMetric 0 | Out-Null

            $via = Find-NetRoute -RemoteIPAddress $EndpointIp | Where-Object { $_.PSObject.Properties['NextHop'] -and $_.NextHop } | Select-Object -First 1
            Log "route to $EndpointIp : $($via.DestinationPrefix) via $($via.NextHop) on ifIndex $($via.InterfaceIndex)"

            Log "run: checking that $EndpointIp answers"
            $ok = Test-Connection -ComputerName $EndpointIp -Count 2 -Quiet
            if (-not $ok) { throw "$EndpointIp does not answer through the VM; not running the gate." }
            Log 'endpoint answers through the VM; running the gate as SYSTEM'

            if ($Gate -eq 'Connect') {
                $script = Join-Path $Here 'Invoke-ConnectGate.ps1'
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -EndpointIp $EndpointIp `
                    -ParamsDir $ClientDir -ReadyFile $ReadyFile -StopFile $StopFile -WaitMinutes ($WatchdogMinutes - 2) *>&1 |
                    Tee-Object -FilePath (Join-Path $Here 'wsl-lab-gate.log') | ForEach-Object { Log "gate: $_" }
            } else {
                $script = Join-Path $Here 'Invoke-SpikeR4.ps1'
                $params = if ($Transport -eq 'Hy2') { Join-Path $ClientDir 'hy2-client.json' } else { $LabParams }
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -EndpointIp $EndpointIp `
                    -Transport $Transport -ParamsFile $params -SkipBuild *>&1 |
                    Tee-Object -FilePath (Join-Path $Here 'wsl-lab-gate.log') | ForEach-Object { Log "gate: $_" }
            }
            Log "gate exit code $LASTEXITCODE"
        }
        catch { Log "ERROR: $_" }
        finally {
            try { Invoke-Restore } catch { Log "ERROR while restoring: $_" }
            try { Repair-Results $GrantSid } catch { Log "ERROR while handing back the results: $_" }
            Log $Finished
        }
    }

    'Watchdog' {
        try {
            Log 'watchdog: fired'
            Stop-ScheduledTask -TaskName $RunTask -ErrorAction SilentlyContinue
            Invoke-Restore
        }
        catch { Log "ERROR in watchdog: $_" }
        finally {
            try { Repair-Results $GrantSid } catch { Log "ERROR while handing back the results: $_" }
            Remove-LabTasks; Log $Finished
        }
    }

    'Restore' {
        if (-not (Test-Role Administrator)) { throw 'Restore needs an elevated PowerShell.' }
        Stop-ScheduledTask -TaskName $RunTask -ErrorAction SilentlyContinue
        Invoke-Restore
        # The endpoint Launch started is a wsl.exe process; an interrupted Launch cannot stop it, and it
        # would hold the lab's input file and block the next run. The distro is the lab's alone.
        Invoke-Wsl @('--terminate', $Distro) | Out-Null
        Log "restore: stopped the lab endpoint ($Distro)"
        Repair-Results ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        Remove-LabTasks
    }
}
