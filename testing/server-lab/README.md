# The lab server (T200)

A server for tests that need one, made by the product's own setup script rather than by hand.

The "make your own server" guide ends in one script that runs once, as root, on a new Ubuntu or Debian machine: it
downloads two pinned programs and checks their checksums, makes the server's keys, writes the configuration, installs
systemd services, and opens three ports. Until now that script was only checked as text. This runs it for real, in a
container that behaves like a small cloud machine (systemd, iptables, tunnel devices), reads the one line it prints back
with the product's own parser, and writes the credentials a client adds with
`dnetctl add-endpoint --credentials-file`.

It matters because this server speaks a **session** over the carriers. The older harness endpoint
(`testing/harness`) does not, and several things need one: the kill switch (it refuses a connection with no control
port), switching carriers without ending the connection, and the setup script itself.

```powershell
powershell -File testing\server-lab\Invoke-ServerLab.ps1 up       # build, start, run the script, write .state\credentials.json
powershell -File testing\server-lab\Invoke-ServerLab.ps1 status   # the services, and the end of what the script printed
powershell -File testing\server-lab\Invoke-ServerLab.ps1 down     # remove the container
```

What it touches: one container, `dnet-serverlab`, and files under `testing\server-lab\.state` (the test keys of a
throwaway server; gitignored). It publishes `52820/udp`, `45443/udp` and `9443/tcp`, which are not the harness's ports,
so both can run at once. Docker must be running. The cores are the project's own builds in `target\server-cores`
(`cargo xtask build-server-cores`).

## How it works, and what is and is not the product's

| Step | Whose |
|---|---|
| the plan, the keys, the script text | the product (`dnet-provision::bootstrap`, through `examples/local_server.rs`) |
| running the script as root on a fresh machine | the product's script, unchanged, in the container |
| reading the report, checking it against the plan, making the credentials | the product (`BootstrapReport`) |
| the machine, and the HTTPS file server for the two programs | the lab |

The script downloads from `https` only and does not skip certificate checks, so the lab serves the two programs from the
server itself (`serve-cores.py`, on the name `cores.lab`, loopback only) with a certificate it makes and trusts inside
that one container. The pins file is the project's own, with only its download address changed.

## What it cannot show

It is one container on this computer's Docker. It says nothing about a cloud provider's network, its firewall in front
of the machine, a real address that a network might block, or a second Ubuntu or Debian release. Those stay with the
real server (`docs/owner-gates.md`).
