# Runs one command from LOCAL-COMMANDS.md and saves everything it prints to .local-logs\<id>.log
# (UTF-8, with the commit, the time and the exit code), so an assistant can read the result itself.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File testing\log.ps1 <id> "<command line>"
#
# The command line is one quoted string, run from the repository root. (Passed as separate words,
# Windows PowerShell would swallow cargo's `--` and some of its options.)

$ErrorActionPreference = 'Continue'
if ($args.Count -ne 2) {
    Write-Host 'usage: testing\log.ps1 <id> "<command line>"'
    exit 2
}
$Id = [string]$args[0]
$CommandLine = [string]$args[1]

$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root '.local-logs'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$log = Join-Path $dir "$Id.log"
$utf8 = New-Object System.Text.UTF8Encoding($false)

$commit = (git -C $root rev-parse --short HEAD 2>$null)
$branch = (git -C $root rev-parse --abbrev-ref HEAD 2>$null)
$dirty = if (git -C $root status --porcelain 2>$null) { ' (with uncommitted changes)' } else { '' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$header = @(
    "# $Id"
    "# command:  $CommandLine"
    "# started:  $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))"
    "# commit:   $branch $commit$dirty"
    "# user:     $($identity.Name) (elevated: $elevated)"
    "# windows:  $([Environment]::OSVersion.VersionString)"
    ''
) -join "`n"
[IO.File]::WriteAllText($log, $header + "`n", $utf8)

$global:LASTEXITCODE = $null
Push-Location $root
try {
    Invoke-Expression $CommandLine 2>&1 | ForEach-Object {
        $line = "$_"
        Write-Host $line
        [IO.File]::AppendAllText($log, $line + "`n", $utf8)
    }
    $ok = $?
    $code = $global:LASTEXITCODE
    if ($null -eq $code) { $code = if ($ok) { 0 } else { 1 } }
} catch {
    $line = "log.ps1: the command failed to run: $_"
    Write-Host $line
    [IO.File]::AppendAllText($log, $line + "`n", $utf8)
    $code = 1
} finally {
    Pop-Location
}

[IO.File]::AppendAllText($log, "`n# finished: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))`n# exit:     $code`n", $utf8)
Write-Host "`n[$Id] exit $code -> .local-logs\$Id.log"
exit $code
