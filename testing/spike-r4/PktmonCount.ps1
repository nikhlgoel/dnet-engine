<#
.SYNOPSIS
    Reading pktmon's per-adapter counters (SPIKE-R4 / T055). Functions only; dot-source it.

.DESCRIPTION
    Extracted from Invoke-SpikeR4.ps1 so it can be tested against real pktmon output
    (Test-PktmonCount.ps1, fixtures/). The first live run (2026-10-20) showed why that matters:

    pktmon does not always file an adapter's traffic under a component with the adapter's name.
    A Hyper-V host vNIC is listed as "vEthernet (WSL ...)" (Id 157) holding only drop counters,
    while the packets are counted under a sibling component named "Host vNic" with the SAME Id.
    Matching by name alone found the adapter, summed its (zero) drop counters and reported no
    traffic. Matching by component Id as well finds both.

    A zero is only believed if the adapter was found (Hit). A blind instrument must make the gate
    INCONCLUSIVE, never PASS.
#>

# Ids of the pktmon components whose Name appears in $Needles, read from `pktmon list` output.
# A line is "<id> [<mac>] <name>"; virtual adapters have no MAC. Names are compared whole,
# so "Ethernet" does not match "Ethernet 2".
function Get-PktmonComponentIds {
    param([string]$ListText, [string[]]$Needles)
    $ids = New-Object System.Collections.Generic.List[int]
    foreach ($line in ($ListText -split "`r?`n")) {
        if ($line -match '^\s*(\d+)\s+(?:[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\s+)?(.+?)\s*$') {
            if ($Needles -contains $Matches[2]) { $ids.Add([int]$Matches[1]) }
        }
    }
    return , $ids.ToArray()
}

# Packets counted for the adapter named by $Needles (a name or description, compared whole) or
# carrying one of $Ids (a pktmon component Id). Every object below a match contributes its numeric
# *Packet* properties. The walk is generic because pktmon's JSON nests components, counters and
# directions differently per adapter kind.
function Measure-Adapter {
    param($Node, [string[]]$Needles, [int[]]$Ids = @(), [bool]$InMatch = $false)
    $out = @{ Sum = [long]0; Hit = $false }
    if ($null -eq $Node -or $Node -is [string]) { return $out }
    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($item in $Node) {
            $r = Measure-Adapter $item $Needles $Ids $InMatch
            $out.Sum += $r.Sum; $out.Hit = $out.Hit -or $r.Hit
        }
        return $out
    }
    if ($Node -isnot [pscustomobject]) { return $out }
    $self = $InMatch
    foreach ($p in $Node.PSObject.Properties) {
        if ($p.Value -is [string] -and ($Needles -contains $p.Value)) { $self = $true }
        if ($p.Name -eq 'Id' -and ($p.Value -is [int] -or $p.Value -is [long]) -and ($Ids -contains [int]$p.Value)) { $self = $true }
    }
    $out.Hit = $self
    foreach ($p in $Node.PSObject.Properties) {
        $isNumber = $p.Value -is [int] -or $p.Value -is [long] -or $p.Value -is [double] -or $p.Value -is [decimal]
        if ($self -and $isNumber -and $p.Name -match 'Packet') {
            $out.Sum += [long]$p.Value
        } elseif ($p.Value -isnot [string] -and -not $isNumber) {
            $r = Measure-Adapter $p.Value $Needles $Ids $self
            $out.Sum += $r.Sum; $out.Hit = $out.Hit -or $r.Hit
        }
    }
    return $out
}
