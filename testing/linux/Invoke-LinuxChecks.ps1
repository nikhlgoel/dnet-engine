<#
.SYNOPSIS
  Build, lint and test the workspace on Ubuntu inside Docker.
.DESCRIPTION
  Builds testing/linux/Dockerfile once, streams the source (without target/, .git or the UI spikes) into
  a container, and runs testing/linux/checks.sh: clippy with warnings denied, the tests, the MSRV check
  and the branding lint. Cargo's registry and the build output live in named volumes, so a second run is
  much faster. Exit code 0 only if every check passed.
.EXAMPLE
  powershell -File testing/linux/Invoke-LinuxChecks.ps1
#>
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/../..").Path
$image = 'dnet-linux-checks:ubuntu-24.04'

docker build -t $image "$PSScriptRoot"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$tar = Join-Path $env:TEMP 'dnet-source.tar'
Push-Location $root
try {
    tar --exclude=./target --exclude=./.git --exclude=./testing/spike-ui --exclude=./testing/spike-r4/results --exclude=./apps/dnet-tray/node_modules --exclude=./apps/dnet-tray/dist --exclude=./apps/dnet-tray/src-tauri/target -cf $tar .
} finally { Pop-Location }

# The source goes in on stdin. A binary stream is only reliable through cmd's redirection, which both
# Windows PowerShell 5.1 and PowerShell 7 can run.
$checks = Join-Path $PSScriptRoot 'checks.sh'
cmd /c "docker run --rm -i -v dnet-linux-cargo:/opt/cargo/registry -v dnet-linux-work:/work -v `"${checks}:/tmp/checks.sh:ro`" $image bash /tmp/checks.sh < `"$tar`""
exit $LASTEXITCODE
