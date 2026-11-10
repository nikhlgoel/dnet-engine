<#
.SYNOPSIS
  T189 - runs the fairness helper against a real Linux kernel in Docker and checks that a small download keeps
  its share while another device sends as fast as it can.

.DESCRIPTION
  Needs Docker. Builds nothing and changes nothing outside a throwaway container. The helper under test is the
  one the scripts install on a server, printed by `cargo run -p dnet-provision --example fairness_helper`.
  Exit 0 only when the check passes; the log is in the output.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dnet-fairness-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  # The helper, exactly as installed (LF line ends: it runs on Linux).
  $helper = & cargo run -q -p dnet-provision --example fairness_helper
  if ($LASTEXITCODE -ne 0) { throw 'could not print the helper' }
  [System.IO.File]::WriteAllText((Join-Path $work 'helper.sh'), (($helper -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
  $check = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'check.sh')) -replace "`r`n", "`n"
  [System.IO.File]::WriteAllText((Join-Path $work 'check.sh'), $check, (New-Object System.Text.UTF8Encoding($false)))

  $env:MSYS_NO_PATHCONV = '1'
  & docker run --rm --privileged -v "${work}:/work:ro" ubuntu:24.04 sh /work/check.sh /work/helper.sh
  exit $LASTEXITCODE
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
