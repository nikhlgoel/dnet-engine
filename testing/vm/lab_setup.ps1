# DNet Engine lab VM: first-logon setup. Makes the guest controllable over SSH from the host (key only) and leaves a
# READY marker. Nothing here touches anything outside this throwaway VM.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\lab\setup-transcript.txt -Force | Out-Null
"start: $(Get-Date -Format o)"

# A private network profile, so the firewall's private-profile rules apply as on a home network.
Get-NetConnectionProfile | ForEach-Object { Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private -ErrorAction SilentlyContinue }

# Programs the tests build and run live here; keep Defender from quarantining unsigned test executables.
New-Item -ItemType Directory -Force C:\lab\bin | Out-Null
Add-MpPreference -ExclusionPath C:\lab -ErrorAction SilentlyContinue

# OpenSSH server: from Windows' own optional features, falling back to the project's release zip.
$installed = $false
for ($i = 1; $i -le 6 -and -not $installed; $i++) {
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
        if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
        $installed = (Get-Service sshd -ErrorAction SilentlyContinue) -ne $null
    } catch { "attempt $i failed: $_" }
    if (-not $installed) { Start-Sleep -Seconds 20 }
}
if (-not $installed) {
    "capability install failed; trying the release zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $zip = 'C:\lab\OpenSSH-Win64.zip'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip' -OutFile $zip
        Expand-Archive $zip -DestinationPath 'C:\Program Files' -Force
        & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1'
        $installed = (Get-Service sshd -ErrorAction SilentlyContinue) -ne $null
    } catch { "zip install failed: $_" }
}

if ($installed) {
    # The key from the host is the only way in: administrators' keys file, readable by SYSTEM and Administrators only.
    $keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    New-Item -ItemType Directory -Force C:\ProgramData\ssh | Out-Null
    Copy-Item C:\lab\lab_key.pub $keys -Force
    icacls $keys /inheritance:r /grant 'SYSTEM:(F)' /grant 'BUILTIN\Administrators:(F)' | Out-Null
    New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
    $cfg = 'C:\ProgramData\ssh\sshd_config'
    if (Test-Path $cfg) {
        (Get-Content $cfg) -replace '^#?PasswordAuthentication .*', 'PasswordAuthentication no' | Set-Content $cfg
    }
    Set-Service sshd -StartupType Automatic
    Restart-Service sshd
    if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (lab)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }
}

"sshd installed: $installed"
(Get-ComputerInfo -Property OsName,OsBuildNumber,OsVersion | Format-List | Out-String)
"ready: $(Get-Date -Format o)" | Set-Content C:\lab\READY
Stop-Transcript | Out-Null
