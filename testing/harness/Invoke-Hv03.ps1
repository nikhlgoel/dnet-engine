<#
.SYNOPSIS
  HV-03 - proves the harness can distinguish obfuscated from unobfuscated traffic.

.DESCRIPTION
  This is the Phase 0 exit gate (T020, contracts/harness.md §5).

  A harness that passes everything proves nothing. Before any obfuscation claim
  can be trusted, the harness must be shown to actually DETECT the thing it
  claims to detect. So this test has two halves and BOTH must hold:

    1. NEGATIVE CONTROL - a deliberately unobfuscated WireGuard handshake is
       sent through the simulated UTM with H3 active. It MUST be dropped.
       If it survives, the H3 signature rule is not working and every later
       "obfuscation succeeded" result is meaningless.

    2. POSITIVE CASE - a packet with randomised header bytes and non-standard
       length (what AmneziaWG's H1..H4 and Jc/Jmin/Jmax produce) MUST pass.
       If it is also dropped, H3 is over-broad and would fail obfuscated
       traffic too.

  This runs before the real transport exists: it sends synthetic packets, so it
  tests the HARNESS, not the product. Phase 4 re-runs HV-03 against the real
  AmneziaWG profile.
#>
[CmdletBinding()]
param([switch]$KeepConditions)

# Relaxed deliberately: docker writes routine output to stderr, which under
# 'Stop' PowerShell 5.1 converts into terminating NativeCommandErrors.
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

$UTM = 'dnet-utm'
$ENDPOINT = '172.32.0.20'
$PORT = 51820

function Send-Probe {
    <#
      Sends a UDP payload from inside the utm container towards the endpoint and
      reports whether the H3 rules counted a drop. Sending from inside the
      container keeps the test independent of host firewall behaviour.
    #>
    param([string]$HexPayload, [string]$Label)

    $py = @"
import socket, binascii
payload = binascii.unhexlify('$HexPayload')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
try:
    s.sendto(payload, ('$ENDPOINT', $PORT))
    print('sent', len(payload))
except Exception as e:
    print('error', e)
"@
    $countCmd = "iptables -L DNET_COND -v -n -x | awk '/H3-/ {s+=`$1} END {print s+0}'"
    $before = & docker @('exec', $UTM, 'bash', '-c', $countCmd)
    & docker @('exec', $UTM, 'python3', '-c', $py) | Out-Null
    Start-Sleep -Milliseconds 300
    $after = & docker @('exec', $UTM, 'bash', '-c', $countCmd)

    $dropped = ([int]$after - [int]$before) -gt 0
    return [pscustomobject]@{ Label = $Label; Dropped = $dropped; Before = [int]$before; After = [int]$after }
}

Write-Host 'HV-03: harness discrimination test' -ForegroundColor Cyan
Write-Host '===================================' -ForegroundColor Cyan

& "$PSScriptRoot\harness.ps1" clear | Out-Null
& "$PSScriptRoot\harness.ps1" apply H3 | Out-Null
Write-Host 'H3 applied (unobfuscated WireGuard signatures dropped)' -ForegroundColor Gray

# --- Negative control: a genuine WireGuard handshake initiation. -------------
# Type 1, three reserved zero bytes, then 144 bytes of body = 148 total, which
# is the exact fixed size real WireGuard emits.
$wgInit = '01000000' + ('00' * 144)
$control = Send-Probe -HexPayload $wgInit -Label 'unobfuscated WireGuard handshake'

# --- Positive case: what AmneziaWG actually produces. ------------------------
# Randomised first 4 bytes (H1..H4 substitution) and a non-standard length
# (junk-packet padding), so neither the signature nor the length rule matches.
$rand = -join ((1..4) | ForEach-Object { '{0:x2}' -f (Get-Random -Min 1 -Max 255) })
$obfuscated = $rand + ('ab' * 191)
$treated = Send-Probe -HexPayload $obfuscated -Label 'obfuscated (randomised header + padding)'

Write-Host ''
Write-Host 'Results:' -ForegroundColor Cyan
foreach ($r in @($control, $treated)) {
    $state = if ($r.Dropped) { 'DROPPED' } else { 'PASSED ' }
    Write-Host ("  {0}  {1}  (H3 counter {2} -> {3})" -f $state, $r.Label, $r.Before, $r.After)
}

Write-Host ''
$ok = $true

if ($control.Dropped) {
    Write-Host '  PASS  negative control was dropped - H3 detects real WireGuard' -ForegroundColor Green
}
else {
    Write-Host '  FAIL  negative control SURVIVED - H3 does not detect WireGuard.' -ForegroundColor Red
    Write-Host '        Every later obfuscation result would be meaningless.' -ForegroundColor Red
    $ok = $false
}

if (-not $treated.Dropped) {
    Write-Host '  PASS  obfuscated probe passed - H3 is not over-broad' -ForegroundColor Green
}
else {
    Write-Host '  FAIL  obfuscated probe was ALSO dropped - H3 is over-broad and' -ForegroundColor Red
    Write-Host '        would reject legitimately obfuscated traffic.' -ForegroundColor Red
    $ok = $false
}

if (-not $KeepConditions) { & "$PSScriptRoot\harness.ps1" clear | Out-Null }

Write-Host ''
if ($ok) {
    Write-Host 'HV-03 PASSED - the harness can tell the difference.' -ForegroundColor Green
    exit 0
}
else {
    Write-Host 'HV-03 FAILED - Phase 0 exit gate not met.' -ForegroundColor Red
    exit 1
}
