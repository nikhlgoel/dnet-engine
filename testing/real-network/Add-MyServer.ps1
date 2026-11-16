<#
.SYNOPSIS
  Adds a server (yours) to the DNet Engine installed on this computer, and approves it. Run it in an ordinary PowerShell.

.DESCRIPTION
  A server holds keys, and adding one sends your traffic somewhere new, so the service holds the change until a person
  approves it in a way a program running as you cannot do alone: Windows asks you (the blue-and-yellow shield prompt),
  and then a small window asks you to type yes. This script asks for the change, finds it, and starts that approval.
  Nothing happens until you approve it. The credentials file holds your keys: keep it, and never send it to anyone.

  .\Add-MyServer.ps1 -Name "Fast server" -Address 130.210.108.141 -Credentials "$HOME\Documents\DNet server (keep private)\fast-credentials.json"
#>
param(
    [string]$Name = 'My fast server',
    [string]$Address = '130.210.108.141',
    [string]$Credentials = (Join-Path $PSScriptRoot 'fast-credentials.json')
)
$ctl = 'C:\Program Files\DNet Engine\dnetctl.exe'
if (-not (Test-Path $ctl)) { throw 'DNet Engine is not installed here.' }
if (-not (Test-Path $Credentials)) { throw "No credentials file at $Credentials" }
$state = & $ctl status 2>&1 | Out-String
if ($state -match 'service is not running|control pipe') {
    Write-Host 'The DNet Engine service is not running. In an administrator PowerShell run:  Start-Service DNetEngine   and try again.' -ForegroundColor Yellow
    return
}
$job = Start-Job { param($c, $n, $a, $f) & $c add-endpoint $n --host $a --credentials-file $f 2>&1 | Out-String } -ArgumentList $ctl, $Name, $Address, $Credentials
$id = $null
for ($i = 0; $i -lt 15 -and -not $id; $i++) {
    Start-Sleep -Seconds 1
    $id = ((& $ctl pending 2>&1) -split "`n" | Select-String '^\s*\S{8}\s' | ForEach-Object { ($_.Line.Trim() -split '\s+')[0] } | Select-Object -First 1)
}
if (-not $id) { Write-Host (Receive-Job $job -Wait | Out-String); Write-Host 'No change is waiting for approval; see the message above.' -ForegroundColor Yellow; return }
Write-Host "Asking you to approve adding '$Name' (change $id). Windows will ask; then answer yes in the small window."
& $ctl approve $id
Receive-Job $job -Wait | Out-Null
& $ctl endpoints
Write-Host "`nNow turn the connection on in the DNet Engine window (Status), or run:  dnetctl connect"
