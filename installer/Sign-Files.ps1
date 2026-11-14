<#
.SYNOPSIS
  Signs files with the project's own code-signing key. Used by the release workflow, by Tauri's bundler
  (bundle.windows.signCommand, one file per call) and by hand.

.DESCRIPTION
  The key is the project's own, made by installer\New-SigningCertificate.ps1: it is not a purchased
  certificate, so Windows does not trust it by default and SmartScreen still warns. What the signature gives
  is that a file that was changed after signing, or was signed by another key, fails Test-Signature.ps1
  against the published fingerprint (docs\release-signing.md).

  Which key, from the environment (never from an argument, so it is not written to a log):
    DNET_SIGN_PFX + DNET_SIGN_PFX_PASSWORD   a key file, as the release workflow has it
    DNET_SIGN_THUMBPRINT                     a certificate in this user's store, as a local build has it
    DNET_SIGN_TIMESTAMP_URL                  an RFC 3161 server; 'none' for no timestamp (tests); default DigiCert's

  With no key configured this signs nothing and succeeds, so an ordinary build is unaffected. With a key
  configured, anything that goes wrong fails: a half-signed release is worse than an unsigned one.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = 'Stop'

$pfx = $env:DNET_SIGN_PFX
$thumbprint = $env:DNET_SIGN_THUMBPRINT
if (-not $pfx -and -not $thumbprint) {
    Write-Host 'Sign-Files: no signing key configured (DNET_SIGN_PFX or DNET_SIGN_THUMBPRINT); not signing'
    exit 0
}

foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Sign-Files: no such file: $file" }
}

$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'Sign-Files: signtool.exe was not found (the Windows SDK provides it)' }

$timestamp = if ($null -ne $env:DNET_SIGN_TIMESTAMP_URL) { $env:DNET_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

$common = @('sign', '/fd', 'SHA256', '/d', 'DNet Engine')
if ($pfx) {
    if (-not (Test-Path -LiteralPath $pfx -PathType Leaf)) { throw 'Sign-Files: DNET_SIGN_PFX names a file that is not there' }
    $common += @('/f', $pfx)
    if ($env:DNET_SIGN_PFX_PASSWORD) { $common += @('/p', $env:DNET_SIGN_PFX_PASSWORD) }
}
else {
    $common += @('/sha1', $thumbprint)
}
if ($timestamp -and $timestamp -ne 'none') { $common += @('/tr', $timestamp, '/td', 'SHA256') }

foreach ($file in $Files) {
    $done = $false
    for ($attempt = 1; $attempt -le 3 -and -not $done; $attempt++) {
        # signtool's own output can name the key file; keep it out of the log unless the signing failed. Under
        # 'Stop', Windows PowerShell 5.1 turns the first line a native command writes to stderr into a
        # terminating error, which would skip the retry and the message below, so this one call is not 'Stop'.
        $ErrorActionPreference = 'Continue'
        $out = & $signtool.FullName @common $file 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -eq 0) { $done = $true; break }
        if ($attempt -lt 3) { Start-Sleep -Seconds (2 * $attempt) }
    }
    if (-not $done) { throw "Sign-Files: could not sign $file`n$($out -join "`n")" }
    Write-Host "Sign-Files: signed $file"
}
