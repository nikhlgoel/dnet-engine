# Harness Notes

What this harness covers, what it does **not**, and the non-obvious things that were
measured rather than assumed. Read this before trusting a harness result.

Contract: [`specs/001-network-resilience-client/contracts/harness.md`](../../specs/001-network-resilience-client/contracts/harness.md)

---

## Topology, and why it is shaped this way

```
[ Windows host: dnetd under test ]
        |  published ports on 127.0.0.1
        v
   [ utm ] --- transit --- [ endpoint ]
   netem + iptables         cores + HTTP origin
```

The client under test is `dnetd` **on the Windows host**, not in a container, because
`dnetd` is a Windows service. The `utm` publishes the profile ports to `127.0.0.1`, so
`dnetd` connects to localhost and its traffic traverses the shaped path.

**Consequence:** conditions shape the *client-to-endpoint path*. They do not degrade the
host's own NIC. This matters for exactly one scenario — see H7 below.

---

## Things that were measured, not assumed

These are recorded because each one silently produced a *passing* test that proved nothing.

### 1. `tc qdisc ... root` is egress-only

Shaping only the `utm` left bulk downloads **completely undegraded**, because download data
flows endpoint → utm → host, which is *ingress* on the utm's transit interface. Only the
small ACKs were delayed.

Measured: 2 MB download at 3.73 Mbit/s baseline vs **5.16 Mbit/s "under H1"** — faster with
the condition applied.

**Fix:** shaping is applied in **both** containers. The utm shapes the upload path; the
endpoint shapes the download path. `harness.ps1` does this automatically for `degrade.sh`
conditions (`$BIDIRECTIONAL`).

After the fix: 64 KB at **4.94 kbit/s under H1** vs **3,134 kbit/s baseline** — a 635×
degradation. H1 is severe by design; 20% loss at 150 ms RTT collapses bare TCP throughput,
which is precisely the condition the product exists to survive.

### 2. Interface names are not stable

Docker does not guarantee that the second network lands on `eth1`. Observed as `eth1` on one
run and `eth0` on the next. Each container resolves its own transit interface by subnet at
startup and writes it to **`/run/dnet-iface`** — deliberately *not* the shared `/opt/state`
volume, because both containers mount that and would read each other's marker.

### 3. `-m length` matches the total IP packet length

The WireGuard handshake initiation is a 148-byte UDP payload, so the rule needs
`--length 176` (20 IP + 8 UDP + 148), not 156. At 156 the rule matched nothing and H3
appeared to work while detecting nothing.

### 4. The `utm` needs `python3`

`report.sh`, the DNS forger, the captive portal, and the HV-03 probe all use it. Without it
`docker exec ... python3` failed silently, the probe never sent a packet, and HV-03 reported
a rule miss that was really a missing interpreter.

### 5. PowerShell traps that produced false failures

- **Operator precedence**: `@('/x/' + $a[0], $a[1])` parses as `'/x/' + ($a[0], $a[1])`,
  joining the array into one space-separated string. Parenthesise the concatenation.
- **Native stderr under `$ErrorActionPreference='Stop'`**: PowerShell 5.1 turns anything a
  native command writes to stderr into a terminating `NativeCommandError` and leaves
  `$LASTEXITCODE` unreliable. Docker writes routine progress to stderr. Native calls run with
  the preference temporarily relaxed and the exit code captured explicitly.

---

## Coverage

| Condition | Covered | Notes |
|---|---|---|
| H1 latency + loss | Yes, bidirectional | 150 ms ±50 ms, 20% loss |
| H2 total UDP block | Yes | forces the TCP-carrier profile |
| H3 WireGuard signature drop | Yes, **verified by HV-03** | both u32 header match and fixed-length match |
| H4 selective profile block | Yes | per profile A/B/C |
| H5 DNS hijack | Yes | forged A records on port 53 |
| H6 captive portal | Yes | intercept until `login` |
| H7 path loss | **Partial — see below** | |
| H8 endpoint blocklist | Yes | drops traffic to one endpoint address |
| H9 bandwidth ceiling | Yes, bidirectional | catches "connected but unusable" |

### H7 limitation (affects SPIKE-R9)

`H7-down` drops the **utm's transit link**, simulating the *path* failing. It does **not**
detach a Windows NIC, so the host still sees its adapter as up.

That is sufficient for SC-005 (traffic resumes over another path) but **not** sufficient on
its own for HV-07 / SPIKE-R9, which must prove an open transfer survives a real interface
change on both Tier 1 profiles. Genuine host-side interface failover requires disabling a
Windows adapter (`Disable-NetAdapter`) or a second physical path. **Phase 6 must add that
host-side step, or SPIKE-R9 will be measured against a weaker event than the one it claims
to test.** Tracked as a Phase 6 prerequisite.

---

## Usage

```powershell
.\harness.ps1 up            # build and start
.\harness.ps1 apply H1      # apply a condition (mid-session; no client restart)
.\harness.ps1 apply H4 -Arg B
.\harness.ps1 report        # ground truth: which rules fired, packet counts
.\harness.ps1 verify        # all conditions apply and clear
.\Invoke-Hv03.ps1           # the Phase 0 exit gate
.\harness.ps1 clear
.\harness.ps1 down
```

**Always read `report` before trusting a negative result.** A profile that "survived" a
condition whose rule shows 0 packets was never actually tested (HN-03).
