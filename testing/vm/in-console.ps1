<#
.SYNOPSIS
  Runs on the lab guest: runs a script inside the signed-in console session and prints what it wrote.

.DESCRIPTION
  The service accepts requests that change things only from the user signed in at the console (`dnet-ipc/src/authz.rs`),
  and a program started over SSH is a different logon session and is refused. A scheduled task that runs "only when the
  user is logged on" starts the program in the console session, which is the same position as a person typing in a
  window. See `console-login.ps1` for how the guest gets that session.

  Copy this and the script to run into the guest, then:  powershell -File C:\lab\in-console.ps1 C:\lab\your-script.ps1
#>
param([Parameter(Mandatory = $true)][string]$Script, [int]$WaitSeconds = 240)

$out = 'C:\lab\console.out'
$wrapper = 'C:\lab\console-wrap.cmd'
Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
Set-Content -Path $wrapper -Value @(
    '@echo off',
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$Script`" > `"$out`" 2>&1",
    "echo DONE >> `"$out`""
)
schtasks /Delete /F /TN dnetconsole 2>&1 | Out-Null
schtasks /Create /F /TN dnetconsole /SC ONCE /ST 00:00 /RU lab /IT /RL HIGHEST /TR $wrapper 2>&1 | Out-Null
schtasks /Run /TN dnetconsole 2>&1 | Out-Null
$deadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    Start-Sleep -Seconds 2
    $text = if (Test-Path $out) { Get-Content $out -Raw } else { '' }
} until (($text -match 'DONE') -or ((Get-Date) -gt $deadline))
$text -replace 'DONE\s*$', ''
