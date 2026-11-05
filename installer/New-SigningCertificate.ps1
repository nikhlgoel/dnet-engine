<#
.SYNOPSIS
  One-time: makes the project's own code-signing key, like the keystore an Android app is signed with.

.DESCRIPTION
  Writes, to a folder OUTSIDE the repository (default: your home folder, 'dnet-signing'):
    dnet-engine-signing.pfx   the private key, protected by the password you type. Never commit it, never send it.
    dnet-engine-signing.cer   the public certificate, which is safe to publish.
  and prints the certificate's SHA-256 fingerprint, which is what people compare a download against, and the
  commands that give the release workflow the key.

  The certificate is removed from your Windows certificate store once the files are written, because an
  exportable copy in the store would let any program running as you copy the key without the password. A local
  build signs with DNET_SIGN_PFX and DNET_SIGN_PFX_PASSWORD (the key file); pass -KeepInStore to keep it in the
  store instead and sign with DNET_SIGN_THUMBPRINT, knowing the risk.

  This is the project's own key, not a purchased one. Windows does not trust it by default and SmartScreen will
  still warn; see docs\release-signing.md for what the signature does and does not give.

  BACK UP the .pfx and its password somewhere offline (a second drive, a password manager). If the key is lost,
  the project has a new identity: old and new releases can no longer be tied together.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $HOME 'dnet-signing'),
    [string]$Subject = 'CN=DNet Engine (nikhlgoel), O=DNet Engine project',
    [securestring]$Password,
    [int]$Years = 10,
    [switch]$KeepInStore
)

$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$out = [System.IO.Path]::GetFullPath($OutDir)
if ($out.StartsWith($repo, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to write a private key inside the repository ($repo). Choose a folder outside it."
}
if (-not $Password) { $Password = Read-Host -AsSecureString 'Password for the key file (you will need it again; keep it with the backup)' }
# A stolen key file can be attacked offline, so the password must be strong: 16 or more characters, with at least
# three of lower case, upper case, digits and symbols.
$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
$classes = @('[a-z]', '[A-Z]', '[0-9]', '[^a-zA-Z0-9]') | Where-Object { $plain -cmatch $_ }
$strong = ($plain.Length -ge 16) -and (@($classes).Count -ge 3)
$plain = $null
if (-not $strong) { throw 'Use a password of at least 16 characters with at least three of: lower case, upper case, digits, symbols.' }

New-Item -ItemType Directory -Force -Path $out | Out-Null
$pfxPath = Join-Path $out 'dnet-engine-signing.pfx'
$cerPath = Join-Path $out 'dnet-engine-signing.cer'
if ((Test-Path $pfxPath) -or (Test-Path $cerPath)) {
    throw "A key already exists in $out. Not overwriting it: a new key is a new identity. Move it away first if that is what you mean."
}

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears($Years) `
    -CertStoreLocation Cert:\CurrentUser\My
# AES-256 for the key file (the default is an old 3DES scheme that is cheap to attack).
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $Password -CryptoAlgorithmOption AES256_SHA256 | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null

$sha256 = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('x2') }) -join ''

Write-Host ''
Write-Host "Key file      : $pfxPath   (private: back it up offline, never commit it)"
Write-Host "Certificate   : $cerPath   (public)"
Write-Host "Valid until   : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "SHA-256       : $sha256"
Write-Host ''
Write-Host 'Next, from the repository:'
Write-Host "  1. Publish the fingerprint:  Set-Content installer\signing-cert.sha256 '$sha256'   and  Copy-Item '$cerPath' installer\dnet-engine-signing.cer"
Write-Host '  2. Give the release workflow the key (it never leaves GitHub secrets):'
Write-Host "       [Convert]::ToBase64String([IO.File]::ReadAllBytes('$pfxPath')) | gh secret set SIGN_PFX_BASE64 --repo nikhlgoel/dnet-engine"
Write-Host '       gh secret set SIGN_PFX_PASSWORD --repo nikhlgoel/dnet-engine      (paste the password when asked)'
Write-Host '  3. Sign a local build:  $env:DNET_SIGN_PFX = ''<the .pfx path>''; $env:DNET_SIGN_PFX_PASSWORD = ''<the password>''  then build the installer'
Write-Host '  4. Check any file:      installer\Test-Signature.ps1 -CertSha256 (Get-Content installer\signing-cert.sha256 -Raw).Trim() <file>'

if ($KeepInStore) {
    Write-Host ''
    Write-Host ('Kept in your certificate store (-KeepInStore): sign locally with $env:DNET_SIGN_THUMBPRINT = ''{0}''. Any program running as you can export it.' -f $cert.Thumbprint)
}
else {
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)"
    Write-Host ''
    Write-Host 'Removed from your certificate store: the key now exists only in the .pfx file.'
}
