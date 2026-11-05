<#
.SYNOPSIS
  Checks that each file is signed, unchanged since, and signed by the project's key.

.DESCRIPTION
  -CertSha256 is the SHA-256 fingerprint of the project's public signing certificate, as published in
  docs\release-signing.md and installer\signing-cert.sha256. Windows does not trust that certificate (it is the
  project's own), so a signature that is otherwise sound reports "not trusted"; that is expected and accepted
  here. What is not accepted: no signature, a file that no longer matches its signature, or any other key.

  Exit code 0 when every file passes, 1 otherwise. Each failure says FAIL and why.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CertSha256,
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files
)

$ErrorActionPreference = 'Stop'
$want = ($CertSha256 -replace '[:\s]', '').ToLowerInvariant()
$failed = 0

foreach ($file in $Files) {
    $reason = $null
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        $reason = 'no such file'
    }
    else {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        if ($sig.Status -eq 'NotSigned' -or -not $sig.SignerCertificate) { $reason = 'not signed' }
        elseif ($sig.Status -eq 'HashMismatch') { $reason = 'the file was changed after it was signed' }
        elseif ($sig.Status -notin @('Valid', 'UnknownError', 'NotTrusted')) { $reason = "the signature is not usable ($($sig.Status))" }
        else {
            $got = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($sig.SignerCertificate.RawData) |
                    ForEach-Object { $_.ToString('x2') }) -join ''
            if ($got -ne $want) { $reason = "signed by a different key ($got)" }
        }
    }
    if ($reason) {
        Write-Host "FAIL: $file : $reason"
        $failed++
    }
    else {
        Write-Host "OK: $file is signed by the project's key"
    }
}
exit $(if ($failed -gt 0) { 1 } else { 0 })
