<#
.SYNOPSIS
  Controls the DNet Engine lab VM: a throwaway Windows 11 under QEMU (Windows Hypervisor Platform), for the tests
  that must not run on a person's own computer (routes, the firewall guard, install and uninstall, sleep).

.DESCRIPTION
  No elevation, no driver, no system-wide install: QEMU is unpacked into a folder, the guest is reached over SSH on
  127.0.0.1:2222 with a key made for it, and the guest reaches this computer's localhost (including the Docker
  harness) at 10.0.2.2. Everything lives under $env:DNET_VM_DIR (default D:\vm); nothing here is in the repository
  except these scripts.

  A guest that restarts itself ends its QEMU process (`-no-reboot`) and a small supervisor starts a fresh one. This
  is deliberate: this accelerator cannot reset a running virtual CPU cleanly (a restart ended in `WHPX: Unexpected VP
  exit code 4`, a processor exception, at the start of the second boot), but a new process is a clean cold boot every
  time. A restart of the guest is therefore a few seconds longer than on real hardware, and otherwise the same.

  Commands:
    start [-Install]   start the guest (-Install boots the Windows ISO and the unattended answer ISO)
    stop               ask Windows to shut down, then end QEMU if it has not
    kill               end QEMU at once
    status             is it running, and does SSH answer
    shot [file]        a screenshot of the guest's screen (PNG)
    keys <names...>    send keys to the guest (QEMU names: ret, spc, esc, f8 ...)
    type <text>        type text into the guest (for when SSH is not up yet); ends with Enter
    ssh <command>      run a command in the guest, elevated, and print what it says
    put <local> <remote-dir>   copy a file or folder into the guest
    get <remote> <local-dir>   copy a file or folder out of the guest
    snapshot <name>    save the disk state (guest must be stopped)
    restore <name>     go back to a saved disk state (guest must be stopped)

.EXAMPLE
  .\lab.ps1 start
  .\lab.ps1 ssh "whoami /groups | findstr /i Mandatory"
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('start', '_supervise', 'stop', 'kill', 'status', 'shot', 'keys', 'type', 'ssh', 'put', 'get', 'snapshot', 'restore')]
    [string]$Command,
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest,
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$Dir = if ($env:DNET_VM_DIR) { $env:DNET_VM_DIR } else { 'D:\vm' }
$Lab = Join-Path $Dir 'win11-lab'
$Qemu = Join-Path $Dir 'qemu'
$SshPort = 2222
$MonitorPort = 4444
$Key = Join-Path $Lab 'keys\lab_ed25519'
$StopFlag = Join-Path $Lab 'stop.flag'
$SshOpts = @('-i', $Key, '-p', "$SshPort", '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
    '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=8', '-o', 'BatchMode=yes')
$OpenSsh = Join-Path $env:SystemRoot 'System32\OpenSSH'

function Get-LabProcess {
    Get-CimInstance Win32_Process -Filter "Name = 'qemu-system-x86_64.exe'" |
        Where-Object { $_.CommandLine -match 'dnet-lab' } | Select-Object -First 1
}

function Get-Supervisor {
    Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
        Where-Object { $_.CommandLine -match '_supervise' } | Select-Object -First 1
}

function Send-Monitor([string]$Text) {
    $client = New-Object Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $MonitorPort)
    $stream = $client.GetStream()
    $writer = New-Object IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    Start-Sleep -Milliseconds 150
    $writer.WriteLine($Text)
    Start-Sleep -Milliseconds 400
    $buffer = New-Object byte[] 65536
    $reply = ''
    while ($stream.DataAvailable) { $reply += [Text.Encoding]::ASCII.GetString($buffer, 0, $stream.Read($buffer, 0, $buffer.Length)) }
    $client.Close()
    $reply
}

function Test-Ssh {
    # Native stderr must not become a terminating error here: "not answering yet" is an ordinary answer.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & "$OpenSsh\ssh.exe" @SshOpts lab@127.0.0.1 'echo ok' 2>$null } catch { $out = '' }
    finally { $ErrorActionPreference = $previous }
    return ($out -join '') -match 'ok'
}

# One QEMU process, to run until the guest stops or restarts itself.
function Start-Qemu([bool]$WithInstall) {
    $disk = Join-Path $Lab 'disk.qcow2'
    if (-not (Test-Path $disk)) { & "$Qemu\qemu-img.exe" create -q -f qcow2 $disk 60G }
    $vars = Join-Path $Lab 'OVMF_VARS.fd'
    if (-not (Test-Path $vars)) { Copy-Item "$Qemu\share\edk2-i386-vars.fd" $vars }
    $qargs = @(
        '-name', 'dnet-lab',
        '-no-reboot',
        '-machine', 'q35,accel=whpx,kernel-irqchip=on',
        '-cpu', 'Haswell-noTSX,-hypervisor,-xsave,-xsaveopt,-avx,-avx2,-fma,-f16c', '-smp', '2', '-m', '4096',
        '-drive', "if=pflash,format=raw,unit=0,readonly=on,file=$Qemu\share\edk2-x86_64-code.fd",
        '-drive', "if=pflash,format=raw,unit=1,file=$vars",
        '-drive', "if=none,id=disk0,file=$disk,format=qcow2",
        '-device', 'nvme,serial=dnetlab0,drive=disk0,bootindex=2',
        '-netdev', "user,id=n0,hostfwd=tcp:127.0.0.1:$SshPort-:22",
        '-device', 'e1000e,netdev=n0',
        '-device', 'qemu-xhci', '-device', 'usb-tablet',
        '-device', 'VGA',
        '-rtc', 'base=utc',
        '-debugcon', "file:$Lab\ovmf-debug.log", '-global', 'isa-debugcon.iobase=0x402',
        '-display', 'none', '-vnc', '127.0.0.1:1',
        '-monitor', "tcp:127.0.0.1:$MonitorPort,server,nowait"
    )
    if ($WithInstall) {
        $iso = Get-ChildItem (Join-Path $Dir 'iso') -Filter 'win11*.iso' | Select-Object -First 1
        if (-not $iso) { throw "no Windows ISO in $Dir\iso" }
        # The machine's own AHCI ports (ide.0, ide.1): an extra controller left the firmware stuck at its logo.
        $qargs += @(
            '-drive', "if=none,id=cd0,media=cdrom,readonly=on,file=$($iso.FullName)",
            '-device', 'ide-cd,drive=cd0,bus=ide.0,bootindex=1',
            '-drive', "if=none,id=cd1,media=cdrom,readonly=on,file=$Lab\answer.iso",
            '-device', 'ide-cd,drive=cd1,bus=ide.1'
        )
    }
    $p = Start-Process "$Qemu\qemu-system-x86_64.exe" -ArgumentList $qargs -PassThru -WindowStyle Hidden `
        -RedirectStandardError (Join-Path $Lab 'qemu.err') -RedirectStandardOutput (Join-Path $Lab 'qemu.out')
    Start-Sleep -Seconds 3
    if ($p.HasExited) { throw "QEMU ended at once: $(Get-Content (Join-Path $Lab 'qemu.err') -Raw)" }
    return $p
}

switch ($Command) {
    'start' {
        if ((Get-LabProcess) -or (Get-Supervisor)) { 'already running'; return }
        Remove-Item $StopFlag -ErrorAction SilentlyContinue
        $scriptArgs = @('-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '_supervise')
        if ($Install) { $scriptArgs += '-Install' }
        $s = Start-Process powershell -ArgumentList $scriptArgs -PassThru -WindowStyle Hidden
        for ($i = 0; $i -lt 30 -and -not (Get-LabProcess); $i++) { Start-Sleep -Seconds 1 }
        if (-not (Get-LabProcess)) { throw "QEMU did not start: $(Get-Content (Join-Path $Lab 'qemu.err') -Raw -ErrorAction SilentlyContinue)" }
        "started (supervisor pid $($s.Id))"
    }
    '_supervise' {
        $first = $true
        while ($true) {
            $p = Start-Qemu ([bool]$Install)
            if ($first -and $Install) {
                # "Press any key to boot from CD": the first seconds of the firmware, so ask for a key repeatedly. Only the
                # first boot: later ones must fall through to the disk Setup has written.
                1..40 | ForEach-Object { try { Send-Monitor 'sendkey ret' | Out-Null } catch { }; Start-Sleep -Milliseconds 700 }
            }
            $first = $false
            $p.WaitForExit()
            if (Test-Path $StopFlag) { break }
            Start-Sleep -Seconds 2
        }
    }
    'stop' {
        if (-not (Get-LabProcess)) { 'not running'; return }
        New-Item -ItemType File -Force $StopFlag | Out-Null
        if (Test-Ssh) { & "$OpenSsh\ssh.exe" @SshOpts lab@127.0.0.1 'shutdown /s /t 0' 2>$null | Out-Null }
        else { Send-Monitor 'system_powerdown' | Out-Null }
        for ($i = 0; $i -lt 60 -and (Get-LabProcess); $i++) { Start-Sleep -Seconds 2 }
        if (Get-LabProcess) { 'did not shut down in 2 minutes; ending it'; (Get-LabProcess) | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } } else { 'stopped' }
    }
    'kill' {
        New-Item -ItemType File -Force $StopFlag | Out-Null
        Get-CimInstance Win32_Process -Filter "Name = 'qemu-system-x86_64.exe'" | Where-Object { $_.CommandLine -match 'dnet-lab' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
        $s = Get-Supervisor
        if ($s) { Stop-Process -Id $s.ProcessId -Force }
        'killed'
    }
    'status' {
        $p = Get-LabProcess
        if (-not $p) { if (Get-Supervisor) { 'restarting' } else { 'not running' }; return }
        "running (pid $($p.ProcessId)); ssh " + $(if (Test-Ssh) { 'answers' } else { 'does not answer yet' })
    }
    'shot' {
        $file = if ($Rest) { $Rest[0] } else { Join-Path $Lab 'screen.png' }
        Send-Monitor "screendump $file -f png" | Out-Null
        Start-Sleep -Milliseconds 500
        $file
    }
    'keys' { foreach ($k in $Rest) { Send-Monitor "sendkey $k" | Out-Null; Start-Sleep -Milliseconds 200 } }
    'type' {
        $plain = @{ ' ' = 'spc'; '.' = 'dot'; ',' = 'comma'; '-' = 'minus'; '=' = 'equal'; ';' = 'semicolon'; "'" = 'apostrophe';
            '/' = 'slash'; '`' = 'grave_accent'; '[' = 'bracket_left'; ']' = 'bracket_right' }
        $shifted = @{ ':' = 'semicolon'; '"' = 'apostrophe'; '|' = 'backslash'; '_' = 'minus'; '+' = 'equal'; '<' = 'comma';
            '>' = 'dot'; '?' = 'slash'; '{' = 'bracket_left'; '}' = 'bracket_right'; '~' = 'grave_accent'; '!' = '1'; '@' = '2';
            '#' = '3'; '$' = '4'; '%' = '5'; '^' = '6'; '&' = '7'; '*' = '8'; '(' = '9'; ')' = '0' }
        foreach ($ch in ($Rest -join ' ').ToCharArray()) {
            $t = [string]$ch
            if ($t -ceq [string][char]92) { $k = 'backslash' }
            elseif ($plain.ContainsKey($t)) { $k = $plain[$t] }
            elseif ($shifted.ContainsKey($t)) { $k = 'shift-' + $shifted[$t] }
            elseif ($t -cmatch '[A-Z]') { $k = 'shift-' + $t.ToLower() }
            elseif ($t -match '[a-z0-9]') { $k = $t }
            else { continue }
            Send-Monitor "sendkey $k" | Out-Null
            Start-Sleep -Milliseconds 60
        }
        Send-Monitor 'sendkey ret' | Out-Null
    }
    'ssh' { & "$OpenSsh\ssh.exe" @SshOpts lab@127.0.0.1 ($Rest -join ' ') }
    'put' {
        & "$OpenSsh\scp.exe" -r -i $Key -P $SshPort -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR $Rest[0] "lab@127.0.0.1:$($Rest[1])"
    }
    'get' {
        & "$OpenSsh\scp.exe" -r -i $Key -P $SshPort -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR "lab@127.0.0.1:$($Rest[0])" $Rest[1]
    }
    'snapshot' {
        if (Get-LabProcess) { throw 'stop the guest first' }
        & "$Qemu\qemu-img.exe" snapshot -c $Rest[0] (Join-Path $Lab 'disk.qcow2')
        Copy-Item (Join-Path $Lab 'OVMF_VARS.fd') (Join-Path $Lab "OVMF_VARS.$($Rest[0]).fd") -Force
        "saved $($Rest[0])"
    }
    'restore' {
        if (Get-LabProcess) { throw 'stop the guest first' }
        & "$Qemu\qemu-img.exe" snapshot -a $Rest[0] (Join-Path $Lab 'disk.qcow2')
        Copy-Item (Join-Path $Lab "OVMF_VARS.$($Rest[0]).fd") (Join-Path $Lab 'OVMF_VARS.fd') -Force
        "restored $($Rest[0])"
    }
}
