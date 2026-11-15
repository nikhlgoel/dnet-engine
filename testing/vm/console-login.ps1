<#
.SYNOPSIS
  Gives the lab VM a signed-in console session, so the tests that need a person at the keyboard can run.

.DESCRIPTION
  The service accepts "connect" (and other changes that redirect traffic) only from the user signed in at the machine's
  console (`dnet-ipc/src/authz.rs`): a program over SSH is not that person, and is refused with "no interactive console
  session is active". That is the right behaviour, and it means a lab guest that nobody is signed in to cannot be asked
  to connect.

  This makes the throwaway `lab` account passwordless and signs it in automatically when the guest starts. That is
  acceptable here and nowhere else: the guest is a disposable test machine on QEMU's private network with no bridge to
  any real one, SSH to it accepts only the key in `D:\vm\win11-lab\keys`, and a passwordless account cannot be used over
  the network at all (Windows refuses a network sign-in with a blank password). Nothing is typed at a logon screen.

  Run from the repository root with the guest up:  powershell -File testing\vm\console-login.ps1
  It restarts the guest and waits until it answers again and the `lab` session exists.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Lab = Join-Path $PSScriptRoot 'lab.ps1'
$Scratch = if ($env:TEMP) { $env:TEMP } else { '.' }

function Guest([string]$Body) {
    $file = Join-Path $Scratch 'dnet-console-login-guest.ps1'
    Set-Content -Path $file -Value $Body
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $Lab put $file 'C:\lab\' 2>&1 | Out-Null
    $out = & $Lab ssh 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\lab\dnet-console-login-guest.ps1' 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = $previous
    ($out -join "`n").Trim()
}

# A line of `quser` for the lab account in the Active state. (Matching the word "lab" alone would also match the
# folder C:\lab in an error message.)
$Active = '(?m)^\s*>?lab\s+(\S+\s+)?\d+\s+Active'
$before = Guest 'quser 2>&1 | Out-String'
if ($before -match $Active) {
    Write-Host 'The lab account already has a console session; nothing to do.'
    exit 0
}

Write-Host 'Making the lab account passwordless and signing it in at start-up ...'
Guest @'
net user lab "" | Out-Null
$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $key AutoAdminLogon '1'
Set-ItemProperty $key DefaultUserName 'lab'
Set-ItemProperty $key DefaultPassword ''
Set-ItemProperty $key DefaultDomainName $env:COMPUTERNAME
'configured'
'@ | Out-Null

Write-Host 'Restarting the guest ...'
Guest 'Restart-Computer -Force' | Out-Null
Start-Sleep -Seconds 20
$deadline = (Get-Date).AddMinutes(6)
do {
    Start-Sleep -Seconds 8
    $state = (& $Lab status 2>&1 | Out-String)
    $session = if ($state -match 'ssh answers') { Guest 'quser 2>&1 | Out-String' } else { '' }
} until (($session -match $Active) -or ((Get-Date) -gt $deadline))

if ($session -match $Active) {
    Write-Host 'The lab account has a console session.'
    Write-Host $session
} else {
    Write-Host 'No console session appeared in six minutes:'
    Write-Host $session
    exit 1
}
