<#
.SYNOPSIS
  Everything that needs an elevated Windows prompt and no server, in one run. Every output is saved under
  .local-logs\owner-elevated\<time>\ so it can be read afterwards.

.DESCRIPTION
  Run it from the repository root:   powershell -ExecutionPolicy Bypass -File testing\Invoke-OwnerElevatedChecks.ps1
  It asks Windows for elevation once (one UAC prompt) and then needs nothing from you.

  What it does, in order:
    1. Saves a "before" picture of the network (routes, DNS, adapters) and of the installed service.
    2. Removes the leftover development server named "harness" from the installed service, so a first run is judged fairly.
    3. Stops the installed service, runs the tests that change the real routing table and file permissions and
       put everything back (supervisor, network, config, service, trace crates), and starts the service again, whatever happens.
    4. Runs the trace-session check.
    5. Reads the link facts of this computer and the service's own view (read only).
    6. Saves an "after" picture and compares it with "before": routes and DNS must be as they were.

  It never connects to anything, never touches an institutional network, and never uninstalls the program.
  -DryRun: no elevation and no change at all; runs only the read-only parts and says what it would do (for testing this script).
#>
param(
  [switch]$Relaunched,
  [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $DryRun) {
  # One UAC prompt, then the same script again with the rights it needs.
  Start-Process powershell.exe -Verb RunAs -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Relaunched')
  exit 0
}

Set-Location $repo
if ($repo -match '\s') { throw "The repository path must not contain spaces for this script: $repo" }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $repo ".local-logs\owner-elevated\$stamp"
New-Item -ItemType Directory -Force $out | Out-Null
$summary = Join-Path $out 'SUMMARY.txt'
$ctl = 'C:\Program Files\DNet Engine\dnetctl.exe'
$service = 'DNetEngine'
$results = @()

function Say([string]$text) { $text | Tee-Object -FilePath $summary -Append | Write-Host }

# Run a command line through cmd so its own stderr goes straight to the log (Windows PowerShell 5.1 would
# otherwise turn a native program's stderr into an error). Returns the exit code.
function Invoke-Logged([string]$commandLine, [string]$logName) {
  $log = Join-Path $out $logName
  cmd.exe /c "$commandLine > $log 2>&1"
  return $LASTEXITCODE
}

function Step([string]$name, [scriptblock]$body) {
  Say ("`n=== {0}  ({1})" -f $name, (Get-Date -Format 'HH:mm:ss'))
  $verdict = 'FAIL'
  try {
    $r = & $body
    $verdict = if ($r -is [string]) { $r } elseif ($r) { 'PASS' } else { 'FAIL' }
  } catch {
    Say "  ERROR: $($_.Exception.Message)"
  }
  $script:results += [pscustomobject]@{ Step = $name; Result = $verdict }
  Say "  -> $verdict"
}

function Save-Network([string]$tag) {
  route.exe print | Out-File (Join-Path $out "net-$tag-routes.txt") -Encoding utf8
  Get-DnsClientServerAddress | Sort-Object InterfaceAlias, AddressFamily |
    Format-Table InterfaceAlias, AddressFamily, ServerAddresses -AutoSize |
    Out-String -Width 250 | Out-File (Join-Path $out "net-$tag-dns.txt") -Encoding utf8
  Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, LinkSpeed -AutoSize |
    Out-String -Width 250 | Out-File (Join-Path $out "net-$tag-adapters.txt") -Encoding utf8
}

Say "DNet Engine elevated checks  $stamp"
Say "repository: $repo"
Say "mode: $(if ($DryRun) { 'DRY RUN (read only, no elevation)' } else { 'real run (elevated)' })"

Step '1. Before: network picture and the installed service' {
  Save-Network 'before'
  sc.exe query $service | Out-File (Join-Path $out 'service-before.txt') -Encoding utf8
  git rev-parse HEAD | Out-File (Join-Path $out 'git-head.txt') -Encoding utf8
  (Test-Path $ctl) -and ([bool](Get-Command cargo -ErrorAction SilentlyContinue))
}

Step '2. Remove the leftover development server "harness" from the installed service' {
  $json = & $ctl --json endpoints | Out-String
  $json | Out-File (Join-Path $out 'endpoints-before.json') -Encoding utf8
  $stale = @(($json | ConvertFrom-Json).endpoints | Where-Object { $_.label -eq 'harness' })
  foreach ($e in $stale) {
    if ($DryRun) { Say "  would remove endpoint $($e.id) ($($e.address))"; continue }
    & $ctl remove-endpoint $e.id | Out-File (Join-Path $out "remove-$($e.id).txt") -Encoding utf8
  }
  & $ctl --json endpoints | Out-File (Join-Path $out 'endpoints-after.json') -Encoding utf8
  & $ctl --json status | Out-File (Join-Path $out 'status-after-removal.json') -Encoding utf8
  if ($DryRun) { return 'SKIPPED (dry run)' }
  $after = Get-Content (Join-Path $out 'status-after-removal.json') -Raw
  $after -notmatch 'harness'
}

Step '3. Elevated tests: real routes, permissions and undo (service stopped meanwhile, started again after)' {
  if ($DryRun) { Say '  would stop the service, run cargo test -- --ignored, start the service'; return 'SKIPPED (dry run)' }
  $wasRunning = (Get-Service $service -ErrorAction SilentlyContinue).Status -eq 'Running'
  try {
    if ($wasRunning) { Stop-Service $service -Force; (Get-Service $service).WaitForStatus('Stopped', '00:00:30') }
    $code = Invoke-Logged 'cargo test -p dnet-supervisor -p dnet-netstate -p dnet-config -p dnetd -p dnet-etw --no-fail-fast -- --ignored --nocapture' 'elevated-tests.log'
    Say "  cargo exit code: $code"
    $code -eq 0
  } finally {
    if ($wasRunning) { Start-Service $service; Say "  service started again: $((Get-Service $service).Status)" }
  }
}

Step '4. The trace session left behind by a crash is taken back' {
  if ($DryRun) { Say '  would create a trace session and run the trace test'; return 'SKIPPED (dry run)' }
  logman.exe create trace DNetEngineAttribution -rt -ets | Out-File (Join-Path $out 'etw-create.txt') -Encoding utf8
  try {
    $code = Invoke-Logged 'cargo test -p dnet-etw -- --ignored --nocapture' 'etw-test.log'
    logman.exe query DNetEngineAttribution -ets | Out-File (Join-Path $out 'etw-query-after.txt') -Encoding utf8
    $code -eq 0
  } finally {
    logman.exe stop DNetEngineAttribution -ets 2>$null | Out-Null
  }
}

Step '5. Facts about this computer and the service (read only)' {
  netsh.exe wlan show interfaces | Out-File (Join-Path $out 'facts-wlan.txt') -Encoding utf8
  Get-NetAdapter | Format-List Name, InterfaceDescription, Status, LinkSpeed, MediaType, PhysicalMediaType |
    Out-String -Width 250 | Out-File (Join-Path $out 'facts-adapters.txt') -Encoding utf8
  ipconfig.exe /all | Out-File (Join-Path $out 'facts-ipconfig.txt') -Encoding utf8
  Get-NetIPInterface | Format-Table InterfaceAlias, AddressFamily, NlMtu, InterfaceMetric, ConnectionState -AutoSize |
    Out-String -Width 250 | Out-File (Join-Path $out 'facts-interfaces.txt') -Encoding utf8
  foreach ($c in 'status', 'paths', 'stats', 'events') {
    & $ctl --json $c | Out-File (Join-Path $out "service-$c.json") -Encoding utf8
  }
  $true
}

Step '6. After: the network is as it was' {
  Save-Network 'after'
  sc.exe query $service | Out-File (Join-Path $out 'service-after.txt') -Encoding utf8
  $same = $true
  foreach ($part in 'routes', 'dns') {
    $a = Get-Content (Join-Path $out "net-before-$part.txt")
    $b = Get-Content (Join-Path $out "net-after-$part.txt")
    $diff = Compare-Object $a $b | Where-Object { $_.InputObject -notmatch 'Active Routes|Persistent Routes|Interface List|^\s*$' }
    if ($diff) {
      $same = $false
      $diff | Out-File (Join-Path $out "net-diff-$part.txt") -Encoding utf8
      Say "  $part differ: see net-diff-$part.txt"
    }
  }
  $same
}

Say "`n===== SUMMARY ====="
$results | Format-Table -AutoSize | Out-String -Width 200 | Tee-Object -FilePath $summary -Append | Write-Host
Copy-Item $summary (Join-Path $repo '.local-logs\owner-elevated\LATEST.txt') -Force
Say "Logs: $out"
Say "Tell Claude: done. Claude reads the logs itself."
if (-not $DryRun -and $Relaunched) { Read-Host 'Press Enter to close this window' | Out-Null }
