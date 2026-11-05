# What only you can do, in order

Written 2026-11-05. Everything here needs your hands, an elevated Windows prompt, or a real server. Everything that
does not is tested by me and listed in `.agent/HANDOFF.md`. Commands come from `LOCAL-COMMANDS.md` (section numbers
in brackets) and `docs/owner-gates.md`; read those for the longer reasons.

Never test against a school, work or other institutional network. Your home connection, your phone's hotspot and your
own server are the only networks involved.

To save each command's output where I can read it, once per terminal:

```powershell
function run { powershell -NoProfile -ExecutionPolicy Bypass -File testing\log.ps1 @args }
```

After each step, tell me the number (or "done"). I read `.local-logs\<number>.log` myself.

---

## Part 1. Elevated Windows work

"Elevated" means PowerShell opened with Run as administrator. Your signed build is installed on this PC, so its
service (`DNetEngine`) is running and holds the control pipe. Stop it for the steps that say so and start it again after.

### 1A. Today, no server needed

**Rows 1 to 4 are done by one script** (one UAC prompt, then nothing to type; it saves every output and Claude reads them):
`powershell -ExecutionPolicy Bypass -File testing\Invoke-OwnerElevatedChecks.ps1`. Only row 5 (typing `yes` at Windows' prompt) is by hand.

| # | What | Why it matters | Pass looks like |
|---|---|---|---|
| 1 | Remove the leftover development server. `dnetctl --json endpoints` lists it; then `dnetctl remove-endpoint <uuid>` for the one named `harness`. Normal PowerShell. | The installed service says "Failed: endpoint 'harness' has no measurement origin" because of it. You cannot judge a first run until it is gone. | `dnetctl status` stops saying Failed. |
| 2 | Elevated tests that touch the real routing table, real file permissions and the undo path: `Stop-Service DNetEngine`, then `run 10.2 "cargo test -p dnet-supervisor -p dnet-netstate -p dnet-config -p dnetd -p dnet-etw -- --ignored --nocapture"`, then `Start-Service DNetEngine`. [1.5, 10.2] | This is the code I cannot run: it changes real routes and DNS and must put them back. Coverage of these modules is thin for exactly this reason. | `test result: ok` on every line, 0 failed. Tell me if any fail: do not rerun until I have read the log. |
| 3 | The trace that records which program opened a connection: `run 2.1 "logman create trace DNetEngineAttribution -rt -ets; cargo test -p dnet-etw -- --ignored; logman query DNetEngineAttribution -ets"`. [2.1] | A trace left behind by a crash must be taken back, not leak. | Test passes. |
| 4 | What your machine and link look like, read-only. Run once per network you use: `run 10.5 "..."` [10.5] and `run 10.6 "..."` [10.6]. | Real adapter names, MTU and link speed are what the speed and MTU decisions are built on. | Logs exist. Nothing changes. |
| 5 | The Windows approval prompt, end to end. [10.8 to 10.12] You need a connection file of any server; the dev `harness` one works. | A held change must show Windows' own prompt and apply only after you type `yes`. | See `LOCAL-COMMANDS.md` 10.8 to 10.12. The refused ones must give no Windows prompt. |

### 1B. After the real server exists (Part 2 first)

| # | What | Why it matters |
|---|---|---|
| 6 | `run 10.4 ...` [10.4]. Connect, then kill `dnetd`. | The transport programs must die with the service. If one survives it keeps the adapter and the routes. |
| 7 | The routing-loop gate, four runs as SYSTEM through PsExec (you need PsExec from Sysinternals): `run 3.1`, `3.2`, `3.3` (needs your phone tethered), `3.4`, `3.5`, then `run 3.6`. [3, `owner-gates.md` T098a] | The tunnel's own packets must never go back into the tunnel. This is the gate we waived at risk; everything on the transport path is provisional until it passes. A `SKIPPED`, `VACUOUS`, `INVALID` or `INCONCLUSIVE` run does not count. |
| 8 | Interface-change survival: unplug or disable Wi-Fi while a 500 MB download runs, three times for each of Profile A and B. Procedure in `owner-gates.md` T085. | It decides whether a profile may be called Tier 1. Today every profile is Tier 2 because nothing has been measured. Record failed runs too. |
| 9 | Stays on across restart, crash and sleep: [7.5, 7.6, 7.7, 7.10]. | The program must reconnect by itself. |

### 1C. Only in a virtual machine, never on this PC

| # | What | Why |
|---|---|---|
| 10 | Installer steps 7.3 to 7.10 on a Windows 11 VM with a snapshot, including the uninstall that must restore the network, and a data folder someone else owns (7.9 needs a second ordinary user). | Uninstall on your PC is untested and I will not run it there without you saying so. |
| 11 | The kill switch's lab checks (ADR-0006 section 5a). | The Windows applier is not built yet. Nothing about the kill switch is live. |

### 1D. Not elevated, but only you can do them

- Copy the signing password from `%LOCALAPPDATA%\DNetEngineSigning\password.txt` into a password manager. The key
  copy on D: is on the same disk as C:, so put one copy on a USB stick too.
- Key ceremony for the profile feed (`owner-gates.md` T066d). Needs an offline machine. The feed stays inert until then.
- Screen reader pass with Narrator and NVDA (`owner-gates.md` T111).

---

## Part 2. Setting up the real Oracle server

The window has this same guide (Servers, Set up a server for me, Use my own server, Oracle Cloud, free). Follow it as a
stranger would, and write down every moment you hesitate. The wording of Oracle's console may differ from the guide.

### 2.1 Before you start

- About 20 minutes, an email address, a phone that can receive a text, and a credit or debit card in your own name.
  The card is an identity check and is not charged for the free server unless you upgrade the account.
- Choose the **home region** carefully: free servers can only be created in it. Pick a region in a different country
  from the network that blocks you; nearer is faster.
- Choose the shape. The Arm shape (Ampere A1, 1 core and 6 GB is plenty) is faster, but Oracle sometimes has none free.
  The AMD shape (`VM.Standard.E2.1.Micro`) is always there but Oracle lists it at up to 50 Mbps. The Arm server
  programs have been built but never run, so a first Arm run also tests those.

### 2.2 Create the server

1. Create the account at oracle.com/cloud/free and sign in to the Console.
2. Menu at the top left, then Compute, then Instances, then Create instance.
3. Image: Ubuntu, newest long-term version. Shape: as chosen above.
4. Networking: keep the defaults, and make sure a **public IPv4 address** is assigned. Do not turn IPv6 on.
5. SSH keys: generate a key pair and **download the private key**. Keep that file safe; it is the only way in.
6. Create. Wait for Running and write down the public IP.

### 2.3 Open exactly three ports

In the instance's subnet security list (and in a network security group if you use one), add three ingress rules,
source `0.0.0.0/0`:

| Protocol | Port | What listens |
|---|---|---|
| UDP | 51820 | AmneziaWG (the last-resort path) |
| UDP | 44443 | Hysteria 2 |
| TCP | 8443 | VLESS + REALITY |

Leave the ssh rule (TCP 22) Oracle made. Open nothing else. Oracle's Ubuntu image also has its own firewall rules on
the server; the setup script handles that side, so do not edit it by hand. Why these are safe to expose and what the
script filters on the server: `docs/security/server-firewall.md`.

### 2.4 Run the setup

1. In the window's Servers page, choose the same shape you created, and follow its Run step. It shows the exact ssh
   command and a block to paste. Copy the block with the Copy button, not by selecting text.
2. If ssh says `UNPROTECTED PRIVATE KEY FILE`, run the `icacls` line the window shows, then try again.
3. Paste the block at the server prompt. It takes one to three minutes and ends with one long line starting with
   `DNET-BOOTSTRAP-REPORT`.
4. Paste that line back into the window, name the server, and type its public IP. It appears in Servers.
5. Turn the connection on from Status.

What to expect: the window says "waits for your approval" and Windows shows one prompt, because adding a server is a
protected change.

### 2.5 Checks I need from you on the real server

Run these and tell me the numbers; I read the logs.

- `run 10.7 "ssh -i <key> <user>@<server> '...'"` [10.7]: services active, files owned by `dnet`, config accepted.
- `run 9.2 ...` [9.2]: the measurement origin listens on the tunnel address only.
- From **outside** the server (your home PC or phone, not the server): that the three doors answer as expected and
  nothing else does. This is the firewall's first real test from outside, which I cannot do for you.
  `Test-NetConnection <server-ip> -Port 8443` should succeed; a scan of other ports should show closed or filtered.
- On the server: `journalctl -u dnet-net` (the firewall service log), `systemctl list-timers` shows
  `dnet-keepalive.timer` and `dnet-housekeeping.timer`, `journalctl --disk-usage` under 100 MB.
- **A crashed transport program comes back (T182).** With the connection on, in an elevated PowerShell run `Stop-Process -Name primary-core -Force`. Within a few seconds the window should show it starting again and then connected, and Activity should say the transport program stopped on its own and was started again (restart 1 of 2). Do it a third time within five minutes: it should stop restarting, treat the profile as blocked and try the others. Tell me what you saw.
- Measure throughput through the tunnel with a large download from the server's origin; write it next to the shape used.
- After a week idle, check the server is still running. If Oracle reclaimed it, tell me when.

### 2.6 Negative checks (they should fail)

Run the Arm script on an AMD server: it must stop at once and install nothing. Paste a result from an older script
after starting a new setup: it must be refused. Paste text with no result: refused, nothing echoed. Close and reopen
the window mid-guide: the same script comes back.

### 2.7 If anything goes wrong

Do not retry in a loop. Copy the last 50 lines of the terminal and `journalctl -u dnet-net -n 100` and give them to me.
Oracle bans abusive traffic, and a loop of failed logins can look like that.
