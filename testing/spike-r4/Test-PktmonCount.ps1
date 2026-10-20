<#
.SYNOPSIS
    Offline test of PktmonCount.ps1 against pktmon output captured from the first live run of the
    gate (2026-10-20, see README.md section 6). Needs no elevation, no network and no pktmon.

    Exit 0: every assertion held. Exit 1: at least one failed.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PktmonCount.ps1')
$fx = Join-Path $PSScriptRoot 'fixtures'

$failures = New-Object System.Collections.Generic.List[string]
function Assert-That([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "  ok   $Message" } else { Write-Host "  FAIL $Message" -ForegroundColor Red; $failures.Add($Message) }
}
function Read-Fixture([string]$Name) {
    (Get-Content (Join-Path $fx $Name) -Raw -Encoding UTF8)
}

# What the gate asks for in the live run: the physical adapter is the host vNIC of the WSL switch,
# the tunnel adapters are the two the cores create, named as pktmon describes them.
$physNeedles   = @('vEthernet (WSL (Hyper-V firewall))', 'Hyper-V Virtual Ethernet Adapter')
$tunnelNeedles = @('dnet-tun0', 'dnet-awg0', 'sing-tun Tunnel', 'WireGuard Tunnel')

Write-Host 'component ids'
$list = Read-Fixture 'components-pass.txt'
$physIds = Get-PktmonComponentIds $list $physNeedles
Assert-That ($physIds.Count -eq 1 -and $physIds[0] -eq 157) 'the vEthernet adapter resolves to component 157'
$tunIds = Get-PktmonComponentIds $list $tunnelNeedles
Assert-That ((($tunIds | Sort-Object) -join ',') -eq '1,2') 'the two tunnel adapters resolve to components 1 and 2'
Assert-That ((Get-PktmonComponentIds $list @('Ethernet')).Count -eq 0) 'a name is compared whole: "Ethernet" matches nothing'
Assert-That ((Get-PktmonComponentIds $list @('Realtek PCIe GbE Family Controller'))[0] -eq 155) 'an adapter with a MAC resolves'

Write-Host 'PASS run (no loop expected)'
$pass = Read-Fixture 'counters-pass.json' | ConvertFrom-Json
$phys = Measure-Adapter $pass $physNeedles $physIds
$tun  = Measure-Adapter $pass $tunnelNeedles $tunIds
Assert-That ($phys.Hit) 'the physical adapter is found'
Assert-That ($phys.Sum -eq 35) "35 endpoint packets are counted on the physical adapter (got $($phys.Sum))"
Assert-That ($tun.Hit) 'the tunnel adapters are found'
Assert-That ($tun.Sum -eq 0) "no endpoint packet reaches a tunnel adapter (got $($tun.Sum))"

Write-Host 'CONTROL run (loop expected)'
$control = Read-Fixture 'counters-control.json' | ConvertFrom-Json
$controlTun = Measure-Adapter $control $tunnelNeedles (Get-PktmonComponentIds (Read-Fixture 'components-control.txt') $tunnelNeedles)
Assert-That ($controlTun.Hit -and $controlTun.Sum -eq 35) "the loop shows as 35 packets on a tunnel adapter (got $($controlTun.Sum))"

Write-Host 'regression: the defect the live run exposed'
$nameOnly = Measure-Adapter $pass $physNeedles
Assert-That ($nameOnly.Hit -and $nameOnly.Sum -eq 0) 'matching by name alone finds the adapter but counts 0 (this is why Ids are needed)'

Write-Host 'blind instrument'
$absent = Measure-Adapter $pass @('no such adapter') @()
Assert-That (-not $absent.Hit) 'an adapter that is not there is not "found with zero packets"'

if ($failures.Count) { Write-Host "`n$($failures.Count) assertion(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll assertions held."
exit 0
