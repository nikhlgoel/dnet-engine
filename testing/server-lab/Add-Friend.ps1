<#
.SYNOPSIS
  Adds a friend's device to your own server, takes one off again, or lists the devices (T188, the owner's half).

.DESCRIPTION
  A friend uses the window: Servers, then "Join a friend's server", and sends you the request it makes (a line that
  starts with DNET-DEVICE-REQUEST; it holds only a name and a PUBLIC key, so any chat will do). You run this:

    .\Add-Friend.ps1 -Add    -Request .\asha.txt           # a file holding the request, or -RequestText '<the text>'
    .\Add-Friend.ps1 -Remove -Request .\asha.txt           # takes that device off the server again
    .\Add-Friend.ps1 -List                                  # who is on the server

  `-Add` asks the server (over SSH, with your own key) to accept the friend's public key, reads what the server says
  with the product's own parser, checks it against your own credentials for that server, and writes the INVITE to
  "$HOME\Documents\DNet invites\<name>.txt". Send that file to that friend and nobody else: it holds your server's
  access details (not your keys, and not theirs). The invite is never printed here.

  Everyone on the server shares its speed. The server holds at most 8 devices (yours is one).

  Needs: your SSH key for the server, and `testing/server-lab/.state/fast/credentials.json` (made when the server was
  set up; for the older free machine pass -Server 130.210.116.219 and -Credentials .state\oracle\credentials.json; it holds your keys, keep it private). Builds the helper with cargo the first time.
#>
[CmdletBinding()]
param(
    [switch]$Add, [switch]$Remove, [switch]$List,
    [string]$Request, [string]$RequestText,
    [string]$Label = 'DNet server',
    [string]$Server = '130.210.108.141',
    [string]$User = 'ubuntu',
    [string]$Key = (Join-Path $HOME '.ssh\dnet-oracle'),
    [string]$Credentials
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (-not $Credentials) { $Credentials = Join-Path $PSScriptRoot '.state\fast\credentials.json' }
if (@($Add, $Remove, $List | Where-Object { $_ }).Count -ne 1) { throw 'Say exactly one of -Add, -Remove, -List.' }
if (-not (Test-Path $Key)) { throw "Your SSH key is not at $Key." }

$work = Join-Path ([IO.Path]::GetTempPath()) ('dnet-friend-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
try {
    Push-Location $root
    cargo build -q -p dnet-provision --example local_server
    Pop-Location
    $tool = Join-Path $root 'target\debug\examples\local_server.exe'
    $ssh = @('-i', $Key, '-o', 'ConnectTimeout=20', '-o', 'StrictHostKeyChecking=accept-new')
    $utf8 = New-Object Text.UTF8Encoding($false)

    function Run-OnServer([string]$ScriptPath) {
        scp @ssh $ScriptPath "${User}@${Server}:/tmp/dnet-friend.sh" | Out-Null
        $out = ssh @ssh "${User}@${Server}" 'sudo sh /tmp/dnet-friend.sh; rm -f /tmp/dnet-friend.sh' 2>&1 | Out-String
        return $out
    }

    $req = Join-Path $work 'request.txt'
    if (-not $List) {
        $text = if ($RequestText) { $RequestText } elseif ($Request) { Get-Content -Raw $Request } else { throw 'Give -Request <file> or -RequestText <text>.' }
        [IO.File]::WriteAllText($req, $text, $utf8)
    }

    if ($List) {
        & $tool list-devices (Join-Path $work 'list.sh') | Out-Null
        $out = Run-OnServer (Join-Path $work 'list.sh')
        ($out -split "`n" | Where-Object { $_ -like 'DNET-DEVICE-REPORT*' }) -replace '^DNET-DEVICE-REPORT ', ''
    }
    elseif ($Remove) {
        & $tool remove-device $req (Join-Path $work 'remove.sh')
        $out = Run-OnServer (Join-Path $work 'remove.sh')
        ($out -split "`n" | Where-Object { $_ -like 'DNET-DEVICE-REPORT*' }) -replace '^DNET-DEVICE-REPORT ', ''
    }
    else {
        & $tool add-device $req (Join-Path $work 'add.sh')
        $out = Run-OnServer (Join-Path $work 'add.sh')
        $report = Join-Path $work 'report.txt'
        [IO.File]::WriteAllText($report, $out, $utf8)
        $dir = Join-Path $HOME 'Documents\DNet invites'
        New-Item -ItemType Directory -Force $dir | Out-Null
        $file = Join-Path $dir ("invite-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
        & $tool invite $Credentials $req $report $Label $Server $file
        Write-Host "Send $file to that friend, and nobody else."
    }
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
