<#
.SYNOPSIS
  Installs the built installer on THIS machine, checks what it promises, uninstalls, and compares the network
  before and after. Needs an administrator shell. It never connects to anything.

.DESCRIPTION
  What it touches: it runs the installer silently (the service DNetEngine, C:\Program Files\DNet Engine,
  C:\ProgramData\DNet Engine, a Run key for the tray) and then the uninstaller. The installer's own rule is that
  an uninstall restores the network or refuses to remove the service; the last step checks that from outside.

  Before it starts it refuses if: the shell is not elevated, the installer is not built, DNet Engine is already
  installed or its service exists, or a development dnetd.exe is running (it holds the control pipe).

  Steps: 1 before-state, 2 the installer's signature, 3 install, 4 the service, 5 folders and their permissions,
  6 signatures of the installed files, 7 the installed command-line tool talks to the service, 8 uninstall,
  9 the network after. Each prints PASS, FAIL or NOTE. Exit code 0 only when nothing FAILed.

  -KeepInstalled stops after step 7 so you can look at the window; run again with -UninstallOnly to finish.

  Logs and the before and after snapshots: .local-logs\install-test\
#>
[CmdletBinding()]
param(
    [switch]$KeepInstalled,
    [switch]$UninstallOnly,
    [string]$Installer
)

$ErrorActionPreference = 'Continue'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logDir = Join-Path $repo '.local-logs\install-test'
$installDir = 'C:\Program Files\DNet Engine'
$dataDir = 'C:\ProgramData\DNet Engine'
$script:failed = 0

function Pass($what) { Write-Host "PASS  $what" -ForegroundColor Green }
function Fail($what) { Write-Host "FAIL  $what" -ForegroundColor Red; $script:failed++ }
function Note($what) { Write-Host "NOTE  $what" -ForegroundColor Yellow }
function Check($ok, $what) { if ($ok) { Pass $what } else { Fail $what } }
function Step($n, $title) { Write-Host ''; Write-Host "== $n. $title" -ForegroundColor Cyan }

function Snapshot($path) {
    $routes = Get-NetRoute -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}|{2}' -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias } | Sort-Object -Unique
    $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}|{2}' -f $_.InterfaceAlias, $_.AddressFamily, (($_.ServerAddresses | Sort-Object) -join ',') } | Sort-Object -Unique
    $adapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}' -f $_.Name, $_.InterfaceDescription } | Sort-Object -Unique
    $services = Get-Service -Name 'DNetEngine' -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}' -f $_.Name, $_.Status }
    @('[routes]') + $routes + @('[dns]') + $dns + @('[adapters]') + $adapters + @('[service]') + $services | Set-Content -Encoding utf8 $path
}

function Compare-Snapshots($before, $after) {
    $b = Get-Content $before; $a = Get-Content $after
    Compare-Object $b $a | ForEach-Object { '{0} {1}' -f $_.SideIndicator, $_.InputObject }
}

# ---------------------------------------------------------------- preconditions
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an ADMINISTRATOR PowerShell: it installs a Windows service.' -ForegroundColor Red; exit 2 }
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

if (-not $Installer) {
    $Installer = (Get-ChildItem (Join-Path $repo 'apps\dnet-tray\src-tauri\target\release\bundle\nsis\*-setup.exe') -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
}
$uninstaller = Join-Path $installDir 'uninstall.exe'
$cli = Join-Path $installDir 'dnetctl.exe'

if ($UninstallOnly) {
    if (-not (Test-Path $uninstaller)) { Write-Host 'Nothing to uninstall: uninstall.exe is not there.' -ForegroundColor Red; exit 2 }
}
else {
    if (-not $Installer -or -not (Test-Path $Installer)) { Write-Host 'No installer found. Build it first: LOCAL-COMMANDS 7.1 and 7.2.' -ForegroundColor Red; exit 2 }
    if (Test-Path $installDir) { Write-Host "$installDir already exists. This test needs a machine without DNet Engine; uninstall it first." -ForegroundColor Red; exit 2 }
    if (Get-Service -Name 'DNetEngine' -ErrorAction SilentlyContinue) { Write-Host 'A DNetEngine service already exists. Remove it first.' -ForegroundColor Red; exit 2 }
    if (Get-Process -Name dnetd -ErrorAction SilentlyContinue) { Write-Host 'A dnetd.exe is running (a development service holds the control pipe). Stop it first: taskkill /im dnetd.exe /f' -ForegroundColor Red; exit 2 }
    if (Get-Process -Name dnet-tray -ErrorAction SilentlyContinue) { Write-Host 'The tray program is running. Quit it from its tray icon first.' -ForegroundColor Red; exit 2 }
}

$beforeFile = Join-Path $logDir 'before.txt'

if (-not $UninstallOnly) {
    # ------------------------------------------------------------ 1. before
    Step 1 'The network before'
    Snapshot $beforeFile
    Pass "saved to $beforeFile"

    # ------------------------------------------------------------ 2. installer signature
    Step 2 "The installer's signature"
    $sig = Get-AuthenticodeSignature -LiteralPath $Installer
    $fingerprint = $null
    if ($sig.SignerCertificate) {
        $fingerprint = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($sig.SignerCertificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    Note ('{0}  ({1:N1} MB)' -f (Split-Path $Installer -Leaf), ((Get-Item $Installer).Length / 1MB))
    Note ('SHA-256 of the file: ' + (Get-FileHash $Installer).Hash)
    if ($sig.Status -eq 'NotSigned') { Note 'the installer is not signed (a build without a key)' }
    elseif ($sig.Status -eq 'HashMismatch') { Fail 'the installer was changed after it was signed' }
    else { Pass "signed; signer SHA-256 $fingerprint (Windows says: $($sig.Status), expected for the project's own key)" }
    Set-Content -Encoding ascii (Join-Path $logDir 'signer-fingerprint.txt') ([string]$fingerprint)

    # ------------------------------------------------------------ 3. install
    Step 3 'Install (silent)'
    $t = Get-Date
    $p = Start-Process -FilePath $Installer -ArgumentList '/S' -Wait -PassThru
    Note ('took {0:N0} s' -f ((Get-Date) - $t).TotalSeconds)
    Check ($p.ExitCode -eq 0) "the installer exited with $($p.ExitCode)"
    if ($p.ExitCode -ne 0) { Write-Host 'Stopping: the install failed. Run the uninstaller if anything was left behind.'; exit 1 }

    # ------------------------------------------------------------ 4. service
    Step 4 'The service'
    Start-Sleep -Seconds 3
    $svc = Get-CimInstance Win32_Service -Filter "Name='DNetEngine'"
    Check ($null -ne $svc) 'the service DNetEngine exists'
    if ($svc) {
        Check ($svc.StartName -eq 'LocalSystem') "runs as $($svc.StartName) (LocalSystem expected)"
        Check ($svc.StartMode -eq 'Auto') "start mode is $($svc.StartMode) (Auto expected)"
        Check ($svc.State -eq 'Running') "state is $($svc.State) (Running expected)"
        $q = & sc.exe qfailure DNetEngine 2>&1 | Out-String
        Check ($q -match 'RESTART') 'crash recovery is set: the Service Control Manager restarts it'
        Note (($q -split "`n" | Where-Object { $_ -match 'RESET_PERIOD|RESTART|REBOOT' } | ForEach-Object { $_.Trim() }) -join ' / ')
    }

    # ------------------------------------------------------------ 5. folders
    Step 5 'Folders and who may change them'
    foreach ($f in @('dnetd.exe', 'dnetctl.exe', 'primary-core.exe', 'amneziawg-go.exe', 'wintun.dll', 'server-pins.json', 'uninstall.exe')) {
        Check (Test-Path (Join-Path $installDir $f)) "installed: $f"
    }
    $tray = Get-ChildItem $installDir -Filter '*.exe' | Where-Object { $_.Name -notin @('dnetd.exe', 'dnetctl.exe', 'primary-core.exe', 'amneziawg-go.exe', 'uninstall.exe') } | Select-Object -First 1
    Check ($null -ne $tray) ('the tray program is installed' + $(if ($tray) { ": $($tray.Name)" }))
    Check (Test-Path (Join-Path $installDir 'licences')) 'the licence texts are installed'
    foreach ($dir in @($installDir, $dataDir)) {
        if (-not (Test-Path $dir)) { Note "$dir does not exist yet"; continue }
        $loose = (Get-Acl $dir).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles|AppendData'
        }
        Check (-not $loose) "$dir cannot be changed by ordinary users"
        if ($loose) { $loose | ForEach-Object { Note ('  {0} may {1}' -f $_.IdentityReference, $_.FileSystemRights) } }
    }
    $run = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    Check ([bool]($run.PSObject.Properties | Where-Object { $_.Value -match 'DNet' })) 'the tray starts when someone signs in (Run key)'

    # ------------------------------------------------------------ 6. signatures of what was installed
    Step 6 'Signatures of the installed files'
    if ($fingerprint) {
        $files = @((Join-Path $installDir 'dnetd.exe'), $cli)
        if ($tray) { $files += $tray.FullName }
        & (Join-Path $repo 'installer\Test-Signature.ps1') -CertSha256 $fingerprint @files
        Check ($LASTEXITCODE -eq 0) "dnetd.exe, dnetctl.exe and the tray program are signed by the installer's signer"
    }
    else { Note 'the installer is unsigned, so there is nothing to compare the files with' }
    $wintun = Get-AuthenticodeSignature -LiteralPath (Join-Path $installDir 'wintun.dll')
    Check ($wintun.Status -eq 'Valid') "wintun.dll keeps its vendor's signature ($($wintun.Status))"

    # ------------------------------------------------------------ 7. the service answers
    Step 7 'The installed command-line tool talks to the installed service'
    $out = & $cli status 2>&1 | Out-String
    Check ($out -match 'Status:') 'dnetctl status got an answer'
    Note ($out.Trim() -replace "`r?`n", ' | ')
    $outP = & $cli profiles 2>&1 | Out-String
    Check ($outP -match 'PROFILE') 'dnetctl profiles lists the connection profiles'

    if ($KeepInstalled) {
        Write-Host ''
        Write-Host 'Left installed. Open the window from the Start menu or the tray, then finish with:' -ForegroundColor Cyan
        Write-Host '  testing\Invoke-InstallTest.ps1 -UninstallOnly' -ForegroundColor Cyan
        if ($script:failed -gt 0) { exit 1 } else { exit 0 }
    }
}

# ------------------------------------------------------------------ 8. uninstall
Step 8 'Uninstall (silent)'
$t = Get-Date
$u = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru
Start-Sleep -Seconds 5
Note ('took {0:N0} s' -f ((Get-Date) - $t).TotalSeconds)
Check ($u.ExitCode -eq 0) "the uninstaller exited with $($u.ExitCode)"
Check (-not (Get-Service -Name 'DNetEngine' -ErrorAction SilentlyContinue)) 'the service is gone'
Check (-not (Test-Path (Join-Path $installDir 'dnetd.exe'))) 'dnetd.exe is gone'
$run = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Check (-not [bool]($run.PSObject.Properties | Where-Object { $_.Value -match 'DNet' })) 'the Run key is gone'
if (Test-Path $dataDir) { Note "$dataDir was kept (the uninstaller keeps settings unless asked to remove them)" }

# ------------------------------------------------------------------ 9. network after
Step 9 'The network after, against before'
$afterFile = Join-Path $logDir 'after.txt'
Snapshot $afterFile
if (Test-Path $beforeFile) {
    $diff = @(Compare-Snapshots $beforeFile $afterFile)
    if ($diff.Count -eq 0) { Pass 'routes, name servers and adapters are exactly as before' }
    else {
        Note 'differences (<= only before, => only after). Some, such as a Wi-Fi lease renewing, are not DNet Engine:'
        $diff | ForEach-Object { Write-Host "      $_" }
        Check (-not ($diff | Where-Object { $_ -match 'wintun|dnet|10\.66\.|10\.9\.' })) 'nothing of DNet Engine (adapter, tunnel route or name server) is left behind'
    }
}
else { Note 'no before-snapshot (this was an -UninstallOnly run); nothing to compare' }

Write-Host ''
if ($script:failed -gt 0) { Write-Host "$($script:failed) check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host 'No check failed.' -ForegroundColor Green
exit 0
