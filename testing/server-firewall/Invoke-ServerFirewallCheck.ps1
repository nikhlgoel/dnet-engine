<#
.SYNOPSIS
  Runs the firewall script we put on a person's server against real iptables, in a throwaway container.

.DESCRIPTION
  Renders `dnet-net-up` from the bootstrap template (an ignored test in dnet-provision writes it), then runs
  testing/server-firewall/check.sh inside a privileged Ubuntu container: it builds a tunnel peer, a "public" host and a
  "private cloud network" out of network namespaces, shows what an open firewall lets through (the control), then applies
  the script behind an image-like firewall and shows what it lets through and refuses.

  It changes only the container's own firewall. Needs Docker. Exit code 0 only if every check passed.

.PARAMETER Image
  An Ubuntu image to run in (the check installs iptables itself). Default: the one testing/linux builds.
#>
param(
    [string]$Image = 'dnet-linux-checks:ubuntu-24.04',
    # 'legacy' runs the same checks on the older, non-nftables iptables that many cloud images still have.
    [ValidateSet('nft', 'legacy')][string]$Mode = 'nft'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is needed for this check and was not found.' }

$work = Join-Path ([IO.Path]::GetTempPath()) ('dnet-server-firewall-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # 1. the rendered script, from the template the product really uses
    $env:DNET_DUMP_NET_UP = Join-Path $work 'dnet-net-up'
    & cargo test -q -p dnet-provision --lib dump_the_firewall_script_for_the_container_check -- --ignored
    if ($LASTEXITCODE -ne 0) { throw 'could not render the firewall script' }
    Remove-Item Env:\DNET_DUMP_NET_UP

    # 2. both files with Unix line endings: a carriage return would break `sh` in the container
    $lf = New-Object Text.UTF8Encoding($false)
    foreach ($name in 'dnet-net-up') {
        $path = Join-Path $work $name
        [IO.File]::WriteAllText($path, ([IO.File]::ReadAllText($path) -replace "`r`n", "`n"), $lf)
    }
    $check = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'check.sh')) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $work 'check.sh'), $check, $lf)

    # 3. the check, in a container that is thrown away
    Write-Host "Running the check in a throwaway container ($Image)..." -ForegroundColor Cyan
    # Windows PowerShell 5.1 turns a native command's stderr into a terminating error under 'Stop'; here stderr is
    # just output, and the exit code is what counts.
    $ErrorActionPreference = 'Continue'
    & docker run --rm --privileged -e "IPTABLES_MODE=$Mode" -v "${work}:/work:ro" $Image sh /work/check.sh /work/dnet-net-up
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
exit $code
