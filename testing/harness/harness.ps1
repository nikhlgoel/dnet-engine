<#
.SYNOPSIS
  T017 - control surface for the DNet Engine simulation harness.

.DESCRIPTION
  Conditions are applied at runtime, mid-session, without restarting the client
  under test (HN-01). That is what makes SC-004 measurable: the product must
  recover when a profile is blocked *while connected*.

  Constitution Principle III: every network-path test runs here. Testing against
  a live managed network is prohibited.

.EXAMPLE
  .\harness.ps1 up
  .\harness.ps1 apply H1
  .\harness.ps1 apply H4 -Arg B
  .\harness.ps1 report
  .\harness.ps1 clear
  .\harness.ps1 down
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('up', 'down', 'status', 'apply', 'clear', 'report', 'verify', 'logs')]
    [string]$Command = 'status',

    [Parameter(Position = 1)]
    [string]$Condition,

    [string]$Arg
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$UTM = 'dnet-utm'
$ENDPOINT = 'dnet-endpoint'
$COMPOSE = @('compose', '-f', 'docker-compose.yml')

# Condition ID -> (script, argument). Mirrors contracts/harness.md §1.
$CONDITIONS = @{
    'H1'      = @('degrade.sh', 'H1')
    'H2'      = @('block.sh', 'H2')
    'H3'      = @('dpi.sh', 'H3')
    'H4'      = @('block.sh', 'H4')
    'H5'      = @('dns-hijack.sh', 'H5')
    'H6'      = @('portal.sh', 'H6')
    'H7-down' = @('path.sh', 'H7-down')
    'H7-up'   = @('path.sh', 'H7-up')
    'H8'      = @('path.sh', 'H8')
    'H9'      = @('degrade.sh', 'H9')
    'H1+H9'   = @('degrade.sh', 'H1+H9')
    'login'   = @('portal.sh', 'login')
}

# Native executables are invoked with ErrorActionPreference temporarily relaxed.
# Under 'Stop', PowerShell 5.1 turns anything a native command writes to stderr
# into a NativeCommandError and leaves $LASTEXITCODE unreliable - docker writes
# routine progress to stderr, so the strict setting reports false failures.
function Invoke-Container {
    param([string]$Container, [string[]]$Cmd)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Build one argument array and splat it once. Mixing literal arguments
        # with splatting in a single call collapses the array into one string
        # in PowerShell 5.1, which surfaces as a confusing exec-not-found.
        $dockerArgs = @('exec', $Container) + $Cmd
        $output = & docker @dockerArgs 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        $output | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw "$Container command failed (exit $code): $($Cmd -join ' ')"
    }
    return $output
}

function Invoke-Utm {
    param([string[]]$Cmd)
    Invoke-Container -Container $UTM -Cmd $Cmd
}

function Invoke-Endpoint {
    param([string[]]$Cmd)
    Invoke-Container -Container $ENDPOINT -Cmd $Cmd
}

# Traffic shaping must be applied in BOTH containers. netem's `root` qdisc is
# egress-only, so the utm shapes the upload path and the endpoint shapes the
# download path. Shaping only the utm leaves bulk downloads undegraded - this
# was measured, not assumed. See HARNESS-NOTES.md.
$BIDIRECTIONAL = @('degrade.sh')

function Test-Up {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $id = & docker ps -q -f "name=$UTM" } finally { $ErrorActionPreference = $prev }
    return [bool]$id
}

switch ($Command) {
    'up' {
        Write-Host 'Starting harness...' -ForegroundColor Cyan
        & docker @COMPOSE up -d --build --wait
        if ($LASTEXITCODE -ne 0) { throw 'harness failed to start' }
        Write-Host 'Harness ready.' -ForegroundColor Green
        Write-Host '  Profile A (AmneziaWG)      udp/51820'
        Write-Host '  Profile B (Hysteria 2)     udp/44443'
        Write-Host '  Profile C (VLESS+REALITY)  tcp/8443'
        Write-Host '  HTTP origin                tcp/8080'
        Write-Host '  Ground truth               tcp/9090'
    }

    'down' {
        & docker @COMPOSE down -v
        Write-Host 'Harness stopped.' -ForegroundColor Green
    }

    'status' {
        if (-not (Test-Up)) {
            Write-Host 'Harness is DOWN. Run: .\harness.ps1 up' -ForegroundColor Yellow
            return
        }
        Write-Host 'Harness is UP.' -ForegroundColor Green
        & docker @COMPOSE ps
        Write-Host "`nActive conditions:" -ForegroundColor Cyan
        Invoke-Utm @('bash', '-c', 'iptables -L DNET_COND -n --line-numbers | tail -n +3')
        Write-Host "`nTraffic shaping:" -ForegroundColor Cyan
        Invoke-Utm @('bash', '-c', 'tc qdisc show dev eth1')
    }

    'apply' {
        if (-not $Condition) { throw "specify a condition, e.g. 'apply H1'. Known: $($CONDITIONS.Keys -join ', ')" }
        if (-not $CONDITIONS.ContainsKey($Condition)) {
            throw "unknown condition '$Condition'. Known: $($CONDITIONS.Keys -join ', ')"
        }
        if (-not (Test-Up)) { throw 'harness is not running; run `.\harness.ps1 up` first' }

        $spec = $CONDITIONS[$Condition]
        # The concatenation MUST be parenthesised. Without it PowerShell parses
        # `'x/' + $spec[0], $spec[1]` as `'x/' + ($spec[0], $spec[1])`, joining
        # the array into a single space-separated string - which then reaches
        # docker as one argument and fails as "no such file or directory".
        $cmd = @(('/opt/conditions/' + $spec[0]), $spec[1])
        if ($Arg) { $cmd += $Arg }
        Invoke-Utm ($cmd)
        if ($BIDIRECTIONAL -contains $spec[0]) {
            Invoke-Endpoint ($cmd)
            Write-Host "Applied $Condition (both directions)." -ForegroundColor Green
        }
        else {
            Write-Host "Applied $Condition." -ForegroundColor Green
        }
    }

    'clear' {
        if (-not (Test-Up)) { throw 'harness is not running' }
        foreach ($s in @('degrade.sh', 'block.sh', 'dns-hijack.sh', 'portal.sh', 'path.sh')) {
            Invoke-Utm @(('/opt/conditions/' + $s), 'clear')
        }
        Invoke-Endpoint @('/opt/conditions/degrade.sh', 'clear')
        Write-Host 'All conditions cleared.' -ForegroundColor Green
    }

    'report' {
        # Ground truth (HN-03): which rules fired, and how many packets each
        # dropped. A test uses this to tell "obfuscation worked" apart from
        # "the rule never fired".
        if (-not (Test-Up)) { throw 'harness is not running' }
        Invoke-Utm @('/opt/conditions/report.sh')
    }

    'verify' {
        # Phase 0 exit gate (T020). Confirms each condition can be applied and
        # cleared, and that baseline reachability works when nothing is applied.
        if (-not (Test-Up)) { throw 'harness is not running; run `.\harness.ps1 up` first' }
        $failures = @()

        Write-Host 'Baseline reachability (no conditions)...' -ForegroundColor Cyan
        & "$PSScriptRoot\harness.ps1" clear | Out-Null
        try {
            $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/' -TimeoutSec 5 -UseBasicParsing
            if ($r.Content -notmatch 'dnet-harness-origin') { $failures += 'baseline: unexpected origin response' }
            else { Write-Host '  OK  origin reachable' -ForegroundColor Green }
        }
        catch { $failures += "baseline: origin unreachable ($_)" }

        foreach ($id in @('H1', 'H2', 'H3', 'H5', 'H9')) {
            try {
                & "$PSScriptRoot\harness.ps1" apply $id | Out-Null
                Write-Host "  OK  $id applies" -ForegroundColor Green
                & "$PSScriptRoot\harness.ps1" clear | Out-Null
            }
            catch { $failures += "$id failed to apply: $_" }
        }

        # H4 needs a profile argument.
        try {
            & "$PSScriptRoot\harness.ps1" apply H4 -Arg B | Out-Null
            Write-Host '  OK  H4 applies' -ForegroundColor Green
            & "$PSScriptRoot\harness.ps1" clear | Out-Null
        }
        catch { $failures += "H4 failed to apply: $_" }

        # H7 down/up must round-trip.
        try {
            & "$PSScriptRoot\harness.ps1" apply H7-down | Out-Null
            & "$PSScriptRoot\harness.ps1" apply H7-up | Out-Null
            Write-Host '  OK  H7 down/up round-trips' -ForegroundColor Green
        }
        catch { $failures += "H7 failed: $_" }

        & "$PSScriptRoot\harness.ps1" clear | Out-Null

        Write-Host ''
        if ($failures.Count -eq 0) {
            Write-Host 'Harness verification PASSED.' -ForegroundColor Green
            Write-Host 'Note: this checks conditions apply and clear. The Phase 0 exit'
            Write-Host 'gate additionally requires HV-03 with an unobfuscated control'
            Write-Host 'that FAILS - see Invoke-Hv03.ps1.'
        }
        else {
            Write-Host "Harness verification FAILED ($($failures.Count)):" -ForegroundColor Red
            $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            exit 1
        }
    }

    'logs' {
        & docker @COMPOSE logs --tail 80
    }
}
