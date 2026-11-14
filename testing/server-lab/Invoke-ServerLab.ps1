<#
.SYNOPSIS
  A server for the lab, set up by the product's own setup script (T200): an Ubuntu container with systemd.

.DESCRIPTION
  The setup script is the part of "make your own server" that, until now, was only checked as text (T098). This runs
  it for real, in a container that behaves like a small cloud machine (systemd, iptables, tunnel devices), then reads
  the report it prints with the product's own parser and writes the credentials a client adds with
  `dnetctl add-endpoint --credentials-file`. The server speaks a session over the carriers, which the older harness
  endpoint does not: it is what the kill switch, the carrier switch and the "no control port" refusal need.

    Invoke-ServerLab.ps1 up      build, start, serve the cores, run the script, write .state\credentials.json
    Invoke-ServerLab.ps1 status  the services on the server and what the script reported
    Invoke-ServerLab.ps1 down    remove the container

  What it touches: one container (dnet-serverlab) and files under testing\server-lab\.state (test keys of a
  throwaway server; gitignored). It publishes the ports 52820/udp, 45443/udp and 9443/tcp. Docker must be running.
  The cores are the project's own builds in target\server-cores (`cargo xtask build-server-cores`, or a release's).
#>
[CmdletBinding()]
param([Parameter(Position = 0)][ValidateSet('up', 'status', 'down')][string]$Action = 'status')

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Here '..\..')).Path
$State = Join-Path $Here '.state'
$Compose = Join-Path $Here 'docker-compose.yml'
$Container = 'dnet-serverlab'
$Ports = @{ awg = 52820; hy2 = 45443; reality = 9443 }

function Step($text) { Write-Host "== $text" -ForegroundColor Cyan }
# Not named `Docker`: PowerShell would resolve `docker` to this function and call itself forever.
# Docker prints progress on stderr; that is not a failure, so the stop-on-error mode is lifted for the call.
function Dk {
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & docker.exe @args 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = $previous
}
# Bash needs line feeds; a script written on Windows can arrive with carriage returns, which it reads as part of the words.
function InServer([string]$Command) { Dk exec $Container bash -c ($Command -replace "`r", '') }

function Wait-Systemd {
    for ($i = 0; $i -lt 60; $i++) {
        $s = (InServer 'systemctl is-system-running 2>&1') -join ''
        if ($s -match 'running|degraded') { return }
        Start-Sleep -Seconds 2
    }
    throw 'systemd in the container did not come up in two minutes'
}

switch ($Action) {
    'down' {
        Dk compose -f $Compose down | Out-Null
        Write-Host 'removed'
    }
    'status' {
        InServer 'systemctl is-active dnet-net dnet-primary dnet-awg dnet-origin dnet-origin-session 2>&1; iptables -S INPUT 2>&1 | head -5' | Write-Host
        if (Test-Path (Join-Path $State 'setup.out')) { Get-Content (Join-Path $State 'setup.out') -Tail 3 | ForEach-Object { if ($_.Length -gt 200) { $_.Substring(0, 200) + '...' } else { $_ } } }
    }
    'up' {
        New-Item -ItemType Directory -Force $State | Out-Null
        foreach ($f in 'primary-core-linux-amd64', 'amneziawg-go-linux-amd64', 'server-pins.json') {
            if (-not (Test-Path (Join-Path $Repo "target\server-cores\$f"))) { throw "target\server-cores\$f is missing (cargo xtask build-server-cores)" }
        }

        Step 'Building and starting the server container'
        # The image is built once (it downloads packages, which is slow on a poor connection) and kept; `down` removes
        # the container, not the image. Delete the image (`docker rmi dnet-serverlab-server`) to build it again.
        $haveImage = [bool](Dk image ls -q dnet-serverlab-server)
        if ($haveImage) { Dk compose -f $Compose up -d | Out-Null } else { Dk compose -f $Compose up -d --build | Out-Null }
        Wait-Systemd

        # The image carries python3 when it was built after this was added; an older one gets it here (one small
        # download). The server's own origin service needs the whole of it too, not only this script.
        InServer 'test -f /usr/lib/python3.12/http/server.py || (apt-get update -qq && apt-get install -y --no-install-recommends python3 >/dev/null 2>&1); test -f /usr/lib/python3.12/http/server.py && echo python-ready' | Write-Host

        Step 'Serving the cores over HTTPS from inside the server (cores.lab)'
        InServer 'mkdir -p /srv/cores' | Out-Null
        foreach ($f in 'primary-core-linux-amd64', 'amneziawg-go-linux-amd64') {
            Dk cp (Join-Path $Repo "target\server-cores\$f") "${Container}:/srv/cores/$f" | Out-Null
        }
        Dk cp (Join-Path $Here 'serve-cores.py') "${Container}:/srv/serve-cores.py" | Out-Null
        # Its own call: the whole of a longer script is in its shell's command line, and `pkill -f` would find itself.
        InServer "pkill -f '[s]erve-cores.py'; true" | Out-Null
        InServer @'
set -e
grep -q cores.lab /etc/hosts || echo '127.0.0.1 cores.lab' >> /etc/hosts
if [ ! -f /srv/cores.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=cores.lab -addext subjectAltName=DNS:cores.lab \
    -keyout /srv/cores.key -out /srv/cores.pem >/dev/null 2>&1
  cp /srv/cores.pem /usr/local/share/ca-certificates/cores-lab.crt
  update-ca-certificates >/dev/null 2>&1
fi
nohup python3 /srv/serve-cores.py /srv/cores /srv/cores.pem /srv/cores.key >/srv/serve.log 2>&1 &
sleep 1
curl -fsS --proto =https --tlsv1.2 -o /dev/null https://cores.lab/primary-core-linux-amd64 && echo served
'@ | Write-Host

        Step 'Making the plan and the setup script with the product''s own code'
        $pins = Get-Content (Join-Path $Repo 'target\server-cores\server-pins.json') -Raw | ConvertFrom-Json
        $pins.base_url = 'https://cores.lab/'
        $pinsFile = Join-Path $State 'pins.json'
        # No byte-order mark: the product's reader is strict about JSON.
        [System.IO.File]::WriteAllText($pinsFile, ($pins | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        Push-Location $Repo
        try {
            cargo run -q -p dnet-provision --example local_server -- plan $pinsFile $State amd64 $Ports.awg $Ports.hy2 $Ports.reality
            if ($LASTEXITCODE -ne 0) { throw 'the plan could not be made' }
        } finally { Pop-Location }

        # A real machine uses a resolver on the network; Docker's embedded one (127.0.0.11) has its port rewritten before
        # the script's outbound rules see it, so they would refuse the carriers' name lookups. Use an ordinary one.
        InServer "printf 'nameserver 1.1.1.1
' > /etc/resolv.conf" | Out-Null

        Step 'Running the setup script on the server (as root, once)'
        Dk cp (Join-Path $State 'setup.sh') "${Container}:/srv/setup.sh" | Out-Null
        $out = InServer 'bash /srv/setup.sh 2>&1; echo "script-exit=$?"'
        # No byte-order mark: the report parser expects its line to start with the prefix.
        [System.IO.File]::WriteAllLines((Join-Path $State 'setup.out'), [string[]]$out, (New-Object System.Text.UTF8Encoding($false)))
        $out | Select-Object -Last 14 | ForEach-Object { if ($_.Length -gt 180) { $_.Substring(0, 180) + '...' } else { $_ } } | Write-Host
        if (-not ($out -match 'script-exit=0')) { throw 'the setup script failed (see .state\setup.out)' }

        Step 'Reading the report and writing the client credentials'
        Push-Location $Repo
        try {
            cargo run -q -p dnet-provision --example local_server -- credentials $State (Join-Path $State 'setup.out') (Join-Path $State 'credentials.json')
            if ($LASTEXITCODE -ne 0) { throw 'the report could not be read' }
        } finally { Pop-Location }

        Step 'Services on the server'
        InServer 'systemctl is-active dnet-net dnet-primary dnet-awg dnet-origin dnet-origin-session 2>&1' | Write-Host
    }
}
