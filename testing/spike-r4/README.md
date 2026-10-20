# SPIKE-R4 / HV-13 — running the live routing-loop gate (T055)

> **Status 2026-09-11 — live run deferred to Phase 8.** No suitable endpoint is available yet.
> The project owner deferred the live run until the provisioned cloud endpoint exists (Phase 8).
> Until then, R4 rests on the logic-level tests only; see `tasks.md` T055 for what that does and
> does not cover. This runbook is what Phase 8 will execute.

> **Known blocker — BUG-007 (2026-10-16).** The AmneziaWG core creates its control pipe with SYSTEM as
> owner, so it fails to start from an Administrator shell, and the spike stops before it measures any
> routing. An elevated shell is necessary but **not sufficient**: run the spike as LocalSystem
> (section 2). The earlier 2026-09-11 run failed this way; see
> [`docs/bugs/bug-007-spike-r4-uapi-pipe-owner.md`](../../docs/bugs/bug-007-spike-r4-uapi-pipe-owner.md).

> **Added 2026-10-20 — a WSL2 lab (section 6) can stand in for the cloud endpoint.** Its third
> elevated run returned **PASS** with a looping control (details and limits in section 6). Whether
> that PASS may close T055, or only reduces the risk until T098a runs against a provisioned
> endpoint, is the owner's decision.

**What it proves.** With both cores running, Profile A (AmneziaWG) carries real traffic,
and the tunnel's own encrypted packets to the endpoint leave **only** through the physical
adapter — none re-enter the TUN. Failure presents as a successful handshake with zero
throughput, so the gate counts packets per adapter instead of trusting "it connected".

**Why it needs a remote endpoint.** A loop can only form when the endpoint is reached
through the **default gateway**. The Phase 0 harness publishes ports on `127.0.0.1`, and
loopback traffic never enters a TUN — HV-13 would pass vacuously there. The script refuses
to run against a loopback or on-link endpoint (exit code 3).

**Not supported: a VM on the client's own LAN.** A LAN endpoint is on-link, so the script rejects
it as `VACUOUS`. Making it look off-subnet was tried on 2026-09-11 and failed. The attempt gave a
bridged Ubuntu VM a TEST-NET address on loopback and temporarily made the VM the client's default
gateway. Two problems stopped it:

- **Wi-Fi bridge isolation.** The hypervisor bridge sat on an Intel Wi-Fi adapter, and forwarded
  traffic through it was dropped. 802.11 client mode allows only the station's own MAC address
  on the air, so bridging over Wi-Fi relies on MAC rewriting that drivers and access points handle
  inconsistently. If the VM runs on the client machine itself, host-to-guest packets can also be
  switched inside the bridge filter driver, below the layer pktmon counts. The physical-adapter
  count would then read zero even though the packets arrived.
- **pktmon instability.** Packet Monitor stopped during the run (`Packet Monitor is not running`).
  The verdict depends entirely on pktmon's per-adapter counters, so a run without them is
  worthless.

Do not work around this with a `/32` route to the VM on the client. That is exactly the host route
the loop guard installs, so the negative control could no longer loop. A static route on the home
router is also unreliable: the router's ICMP redirects can teach the client a direct on-link path,
which suppresses re-entry and makes the control `INVALID`. Use an endpoint that is genuinely
reached through the default gateway, on a different network from the client.

**How it guards against a false PASS.**
- A **negative control** run withholds the host route. It *must* show re-entry; if it does
  not, the verdict is `INVALID` — the measurement cannot see loops.
- A PASS requires a non-zero count on the physical adapter and the tunnel adapters to be
  *found* with zero counts. If pktmon's output does not expose them, the verdict is
  `INCONCLUSIVE`, never PASS.

---

## 1. Endpoint host (off-subnet, e.g. an Oracle Cloud Always Free VM)

Any Linux host with a public IP that is **not on the Windows client's LAN** works.

```bash
# Docker Engine + compose plugin (Ubuntu)
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker "$USER" && newgrp docker

git clone https://github.com/nikhlgoel/dnet-engine.git && cd dnet-engine
git checkout <the commit you are testing>
cd testing/harness
docker compose up -d --build          # builds the pinned AmneziaWG server (a few minutes)
docker compose ps                     # both services "healthy"
docker compose logs endpoint | grep '\[awg\]'   # expect: "[awg] server up; ..."
```

**Cloud firewall — open only the port of the profile under test.** In the VCN security list (or
your provider's equivalent), add an ingress rule for **UDP 51820 (Profile A) or UDP 44443
(Hysteria 2, section 5) from your Windows client's public IP only**. Do not open 8080, 8443, or
9090: the harness control port executes a report script and must never be internet-reachable. (Docker-published ports bypass the
VM's own iptables, so the cloud-level rule is the control that matters.)

**Hand over the client parameters.** They are test keys generated by the container — never
real credentials:

```bash
# on your Windows machine, from the repo root
scp <user>@<VM-IP>:dnet-engine/testing/harness/.state/awg-client.json testing/harness/.state/
```

## 2. Windows client

Vendor binaries (already present in this working copy; needed on a fresh clone). Requires
Git, Go 1.25+, and `curl.exe`:

```powershell
cargo run -p xtask -- fetch-vendor    # builds both cores from pinned source (primary core with the
                                      # DLL-loader patch), fetches the signed driver DLL
cargo run -p xtask -- verify-vendor   # expect: verify-vendor: OK
```

Optional elevated self-checks of the OS seams (install a real test route, full ACL flow):

```powershell
cargo test -p dnet-netstate -- --ignored
cargo test -p dnet-config -- --ignored
```

Run the spike as **LocalSystem**, not merely elevated (BUG-007). Disconnect any other VPN first —
it would own the default route. The SYSTEM account is unlikely to have your user's cargo and rustup
environment, so build the runner once as yourself in an elevated shell, and have the SYSTEM run skip
the build:

```powershell
# 1. As yourself, elevated: build the runner once.
cargo build --release -p dnet-netstate --example spike_r4

# 2. As LocalSystem, using Sysinternals PsExec (a separate download):
psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "<repo>\testing\spike-r4\Invoke-SpikeR4.ps1" -EndpointIp <VM-public-IP> -SkipBuild
```

This form has not been run in this repository yet. The SYSTEM window closes when the script exits,
so read `testing\spike-r4\results\<timestamp>\summary.md` afterwards. A scheduled task running as
SYSTEM works the same way if you prefer not to use PsExec.

Optional — exercise the host-route rewrite across a **real** interface change by adding a
second physical path (e.g. a USB-tethered phone) and passing its gateway:

```powershell
# Launch as SYSTEM exactly as above, giving the script these arguments:
.\testing\spike-r4\Invoke-SpikeR4.ps1 -EndpointIp <VM-public-IP> -AltGateway <second-path-gateway> -SkipBuild
```

Without `-AltGateway` the path-change part is reported as `SKIPPED`, not passed.

## 3. Reading the result

`testing/spike-r4/results/<timestamp>/summary.md`, plus per-run `runner.log`,
`runner-report.json`, `counters.txt`, `counters.json`, `components.txt`, `capture.pcapng`.

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | PASS | Transfer succeeded; endpoint packets only on the physical adapter; control looped; nothing left behind |
| 1 | FAIL | Re-entry, failed transfer, missing host route, or restoration residue — reasons listed |
| 2 | setup | Not elevated, missing binaries/params, or residue from an earlier run |
| 3 | VACUOUS | Endpoint is loopback or not behind the default gateway — the test cannot mean anything |
| 4 | INVALID | Control withheld the host route yet showed no re-entry — the instrument is blind |
| 5 | INCONCLUSIVE | A run errored, or pktmon output did not expose the adapters |

A core that never becomes ready should surface as INCONCLUSIVE (exit 5), because the adapters never
exist for pktmon to count. The 2026-09-11 run left no `summary.md` at all, so this has not been seen
end to end. Either way the reason is in `runner.log`, on a line containing `uapi socket`. If it says
the security ID may not be assigned as the owner, the script was not running as LocalSystem (BUG-007).

Send back `summary.md` and, for anything but PASS, the whole results folder (it contains
only encrypted test traffic; no keys are captured).

## 4. Clean up

```bash
# endpoint host
cd dnet-engine/testing/harness && docker compose down && sudo rm -rf .state
```
```powershell
# Windows client
Remove-Item testing\harness\.state\awg-client.json
```
Remove the cloud firewall rule when finished.

---

## 5. The Hysteria 2 variant (`-Transport Hy2`)

The same gate for the second profile. It matters because a loop is only ever formed by a core's
**own** outbound traffic, and the two profiles guard against it differently:

| | Profile A (AmneziaWG) | Hysteria 2 |
|---|---|---|
| Cores | AmneziaWG + primary | primary only |
| Adapters | `dnet-awg0` and `dnet-tun0` | `dnet-tun0` |
| Loop guard | endpoint host route via the physical gateway | the core's `auto_detect_interface` |
| Control withholds | the host route | `auto_detect_interface` |

PASS, INVALID and VACUOUS follow the same rules. A control that does not loop is `INVALID`: for
Hysteria 2 that would mean the core protects its sockets some other way, and this instrument
could not tell.

**Endpoint host.** As in section 1. `docker compose up -d --build` now also builds the primary
core (a few minutes more) and starts a Hysteria 2 server. Expect `[hy2] server up` in
`docker compose logs endpoint`. Open **UDP 44443** from your client's public IP only, then:

```bash
scp <user>@<VM-IP>:dnet-engine/testing/harness/.state/hy2-client.json testing/harness/.state/
```

**Windows client.** As in section 2, building first as yourself and then launching as SYSTEM:

```powershell
psexec -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "<repo>\testing\spike-r4\Invoke-SpikeR4.ps1" -EndpointIp <VM-public-IP> -Transport Hy2 -SkipBuild
```

**What has and has not been run (2026-10-16).**
- Run: the server configuration passes the pinned core's `check`; the pinned core as server and as
  client carries 200,000 bytes through the pair on localhost with Chrome mimicry on and an ECDSA
  certificate; a wrong obfuscation password and a wrong certificate pin each carry nothing. The
  runner's pure parts have unit tests, and the production configuration is asserted to carry
  `auto_detect_interface`.
- Run, later the same day: the endpoint image builds with the Hysteria 2 stage (the first attempt
  failed during Go module downloads and succeeded on retry), both servers start in the container, and
  the client core on Windows pulled 5,000,000 bytes through the published port and the simulated UTM
  into the containerised server (about 25 MB/s, loopback). A wrong obfuscation password carried nothing.
- **Not run:** the TUN path, the wrapper's `-Transport Hy2` flow past argument binding, and any
  measurement against an off-LAN endpoint. Until those run, the Hysteria 2 profile is as unproven
  against the loop as Profile A is.

---

## 6. The WSL2 lab (`Invoke-WslLab.ps1`): an off-subnet endpoint without a cloud host

For when no cloud VM exists. A WSL2 VM sits behind its own Hyper-V switch, so the script makes the VM
the host's temporary **default gateway** and gives the endpoint an address (`203.0.113.10`, TEST-NET-3)
that the VM answers for by DNAT to its own address, not one on the switch's subnet. The host then reaches
the endpoint through its default route, which is the only way a loop can form. (DNAT, because conntrack
rewrites every reply's source back to the endpoint address by itself; an address on the loopback with an
SNAT rule, the first version, left replies coming from the VM's own address.)

**How this differs from the unsupported LAN-VM attempt (top of this file).** There the endpoint was a
bridged VM on a Wi-Fi adapter, where forwarded traffic was dropped and the counting could be bypassed
inside the bridge driver. Here no physical NIC is involved: the "physical" adapter the gate counts is
the host's own `vEthernet (WSL …)` adapter, so the packets are counted where they enter the switch.
That is a virtual NIC, so the lab cannot say anything about a real NIC's offloads, MTU or NAT; it can
only say whether the cores' own encrypted packets re-enter the TUN. That is the failure T055 exists to catch.

**The gate's own guards still decide.** The control run must loop, and pktmon must expose both
adapters. If the control does not loop the verdict is `INVALID`; if pktmon does not show the vEthernet
adapter it is `INCONCLUSIVE`. Neither is a pass, and neither says anything about the design.

**Prerequisites.**
- WSL distro `dnet-endpoint`: an export of the harness endpoint image (it holds `/opt/awg-server.sh`
  and the pinned `amneziawg-go`). `wsl-endpoint.sh` is copied in on every run.
- `cargo build --release -p dnet-netstate --example spike_r4`, and the vendor binaries
  (`cargo run -p xtask -- fetch-vendor`).
- Disconnect any VPN. **The host has no internet while the gate runs.** If the machine's only
  connection is a tethered phone, expect that to drop too.

**1. Dry run (no elevation, changes nothing on the host).**

```powershell
.\testing\spike-r4\Invoke-WslLab.ps1 -Phase Check
```

It runs every preflight, starts the endpoint in the VM for 90 s and has the VM check itself before it
says READY: a NAT self-test (a connected UDP socket must get a reply whose source was rewritten back
to the endpoint address), the DNAT rule, the server process, a UDP listener on 51820 and the packet
recorder. It exports the client parameters to `wsl-lab-awg-client.json` (test keys; gitignored). Exit 0
means the endpoint half works; exit 2 lists every problem it found.

**2. The run (elevated PowerShell).**

```powershell
.\testing\spike-r4\Invoke-WslLab.ps1 -Phase Launch
```

Launch repeats the preflight, starts the endpoint, then registers two SYSTEM scheduled tasks: the gate
(`Run`) and a watchdog (`Watchdog`, default 10 minutes). `Run` saves the interface metrics to
`wsl-lab-state.json` **before** it changes anything, makes the VM the default gateway, confirms the
endpoint answers, runs `Invoke-SpikeR4.ps1` as SYSTEM (which satisfies BUG-007) and restores. If the
gate hangs, the watchdog stops it, kills what it staged, restores networking and removes both tasks.
Launch waits, prints the tail of `wsl-lab.log`, and exits with the gate's exit code (section 3's table).

**3. If networking is left broken** (power loss mid-run, a killed shell). From an elevated shell:

```powershell
.\testing\spike-r4\Invoke-WslLab.ps1 -Phase Restore
```

It is idempotent and removes only routes whose next hop is the lab VM. Rebooting also works: the
default route it adds is not persistent.

**First elevated run, 2026-10-20 16:44: FAIL.** Not a verdict on the design. What it did establish:

- **The lab works.** Preflight, the endpoint in the VM, the route flip (`203.0.113.10` via the VM on
  `vEthernet (WSL …)`), the gate under SYSTEM, and restoration (default routes and metrics back, no
  residue) all behaved. The AmneziaWG core started under SYSTEM and configured its peer, so the
  BUG-007 workaround holds.
- **The control looped.** With the host route withheld, 35 endpoint packets appeared on the
  `sing-tun` adapter. The instrument can see a loop.
- **In the PASS run no endpoint packet reached a tunnel adapter**, and `counters.txt` shows 35 leaving
  through the host vNIC. But the transfer failed (the endpoint never answered), so this does not show
  that a working tunnel stays off the TUN.
- **Gate defect, found by this run.** The gate reported 0 packets on the physical adapter. pktmon
  files the traffic under a sibling component named `Host vNic` that shares the adapter's component
  Id (157) but not its name, and the gate matched by name only. The defect fails toward FAIL, never
  toward PASS.
- **The endpoint did not answer.** Both runs sent 35 packets that reached the VM's vNIC; nothing came
  back (host vNIC Rx 0) and the handshake never completed. The server's log held only its startup
  banner. Cause not yet established.

**Third elevated run, 2026-10-20 17:23: PASS (exit 0), Profile A.**

| | PASS run (host route in force) | CONTROL run (host route withheld) |
|---|---|---|
| 20 MB transfer through the tunnel | ok, 144.8 Mbit/s | ok, 216.9 Mbit/s |
| endpoint packets on the physical adapter | 185,297 | 193,623 |
| endpoint packets on a tunnel adapter | **0** | **21,895** |

The server's own counters agree (two handshakes, 42 MB sent back, which is the two downloads), and
restoration left no residue. **What it shows:** with the production loop guard, none of 185,297
endpoint packets re-entered the TUN, and real traffic flowed; without it, 21,895 did re-enter, so the
instrument can tell the two cases apart (the gate's own validity condition).

**What it does not show — keep these in view before calling T055 closed:**
- **The control did not collapse.** With the host route withheld the transfer still succeeded (faster,
  in fact), so the "successful handshake, zero throughput" failure that §R4 predicts was not
  reproduced; the re-entering packets were evidently handled and sent on. I infer, but have not tested,
  that the primary core's `auto_detect_interface` rescued them. The result supports "the host route
  prevents re-entry", not "re-entry is fatal".
- **Path change was SKIPPED.** T055 also requires the host-route rewrite across a simulated interface
  change. This lab has one physical path (the VM); it cannot exercise that.
- **The physical path is a virtual NIC** (Hyper-V), on one machine, in one run. It says nothing about a
  real NIC's offloads, MTU or NAT, and one run is not a distribution.
- **Profile A only.** The Hysteria 2 variant (`-Transport Hy2`) has not been run through the lab.
- It is not the provisioned endpoint of T098a.

**Second elevated run, 2026-10-20 17:00: FAIL, with the tunnel working.** After the fixes below:
- The PASS run counted **190 endpoint packets on the physical adapter and 0 on the tunnel adapters**;
  the control looped (167 on the tunnel adapter). The counting is sound.
- The handshake completed (`Received handshake response` on the client; initiation, response and
  keepalives on the server). The DNAT worked: replies left as `203.0.113.10`.
- The transfer still failed: the core dialled the in-tunnel origin `203.0.113.80:8080` and was refused.
  The lab endpoint never started the HTTP origin (the Docker image's entrypoint does; this lab replaces
  that entrypoint). It now starts it and fetches it from inside the VM before reporting READY.
  Nothing about the routing design is implicated.

**Changes made after the first run** (all exercised by the third run):
- The gate matches pktmon components by Id as well as by name. `Test-PktmonCount.ps1` replays the
  first run's real counters (`fixtures/`, hardware addresses removed): 35 physical and 0 tunnel packets
  for the PASS run, 35 tunnel packets for the control, and 0 for name-only matching, which pins the defect.
- The VM answers for the endpoint address by DNAT (see above), with a NAT self-test before READY.
- The VM records the packets on the endpoint port in both directions and runs the server at debug
  level. After the run, `Launch` saves that, with the NAT counters and the server's view of the peer,
  to `wsl-lab-vm-diag.txt` and into the results folder as `vm-diag.txt`, so a failed handshake can be
  told apart from a dropped reply.
- The gate deletes each run's generated core `config` and `state` folders (key material; readable only
  by SYSTEM and Administrators by design), and the lab hands the results folder back to the person who
  started it. `verify-vendor` skips that folder.
- The HTTP origin is started and self-checked (above).
