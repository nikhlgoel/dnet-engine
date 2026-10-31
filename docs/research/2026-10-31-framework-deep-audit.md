# Deep audit of the framework: weaknesses found in our own code, published failure classes, and upgrades (2026-10-31)

**Why this file exists.** The owner asked for research "on a much deeper scale" into what else is weak in the framework and
what else can be added. [`2026-10-31-framework-research.md`](2026-10-31-framework-research.md) found eleven design weaknesses
(W1 to W11) and [ADR-0008](../adr/0008-session-carrier-framework.md) proposed the session–carrier framework. This file goes
below that: it reads the code for concrete security and robustness weaknesses (Part E), collects published failure classes the
project has not considered (Part F), and lists upgrades beyond ADR-0008 (Part G).

**How to read it.** Same labels as before. *Verified* = I read the code, the vendor's own source or the primary document.
*Hypothesis* = a plausible failure that needs a lab test; nothing is built on it. A finding that only says "the code has no X"
was checked by searching the whole source tree (the search is named). **Nothing here is a measurement on a real network.** No
code was changed to produce this file.

**Follow-up.** The chosen fix for each finding, with the evidence that it works (most of it run on the pinned core), is in
[`2026-10-31-solutions.md`](2026-10-31-solutions.md). Two statements below were corrected there (E7, E10) and are marked.

**Scope line.** Everything below is about (a) the security of the client and of the servers it makes, (b) staying usable on
networks that interfere, and (c) telling the person the truth about their network. It does not contain, and the project will
not build, features whose purpose is to hide the use of the product from a network's operator or to anonymise the person
(FR-033, Principle VI, ADR-0006 §3). Part H says what was left out and why.

---

## Part E — Weaknesses in our own code and templates

Severity is about what an attacker gains in this project's setting (a person's own laptop, often on a hostile network, and a
person's own free cloud server). "Fix" is a proposal, not a change.

### E1. The server's exit is an unrestricted relay (Medium, verified)

`crates/dnet-provision/src/bootstrap.rs` writes the server core's configuration with **one outbound, a bare `direct`, and no
route rules** (line 432). The AmneziaWG path turns on IP forwarding and masquerades the tunnel's subnet (lines 492 to 501) with
no forwarding filter. So anyone holding a client credential can ask the server to connect to **its own loopback services, its
private subnet, and the cloud provider's metadata address (169.254.169.254)**. The credential sits on every device the person
has ever set up.

*Impact today is bounded:* the server is the person's own and holds no cloud credentials unless they add some. It is still the
classic "proxy as a pivot" weakness, and the fix is cheap.
*Fix:* a route rule that rejects private, loopback and link-local destinations (`ip_is_private` is documented in the sing-box
route rules since 1.8.0, so it exists in the pinned 1.14.0), with an explicit exemption for the measurement origin that
deliberately lives on the tunnel's private address (`bootstrap.rs:73`); equivalent forwarding drops for the AmneziaWG path.
Needs the mandatory security review (it changes what a privileged server script does) and a run on a real server.

### E2. One shared credential per protocol for every device (Medium, verified)

The server configuration has a single user named `dnet` for Hysteria 2 (line 406) and for VLESS (line 419), and one client key
for AmneziaWG (line 481). A lost or sold laptop means rotating the server's secrets for everyone, and there is no way to say
which device a connection came from. The pinned core accepts a list of users, so per-device credentials are a script and
data-model change, not a core change.
*Fix:* a user per device, created at setup time, with a "remove this device" action that edits the server over ssh the way
setup does.

### E3. The control pipe authorises *who*, not *intent* (Medium, verified; a design limit, not a bug)

`authz.rs` lets any process running as the signed-in console user make every `Mutating` request (`protocol.rs:285` to `301`):
add an endpoint, change rules, import a feed, finish a server. The pipe's descriptor is explicit and sound (`server.rs:35`),
but a program the person was tricked into running can do `AddEndpoint` and then `Connect`, which sends the whole machine's
traffic to a server it chose. That is a normal limit of a per-user-controlled system service; it cannot be closed completely
against malware that already runs as the same user.
*Fix (raises the cost, does not remove the limit):* (1) a mutation that changes *where traffic goes* (new or changed endpoint,
a rule that bypasses the tunnel) never takes effect without a confirmation the window shows, with the server's identity;
(2) the service records every such mutation with a time and the client's program path, and the window shows the last few;
(3) the service checks the connecting program's path and publisher for the sensitive requests. Say plainly in the threat model
that same-user malware is out of reach.

### E4. Read-only means "any signed-in user, in any session" (Low to Medium, verified)

`authz.rs:49` answers every `ReadOnly` and `Stream` request for any authenticated caller, and the pipe grants read and write to
Authenticated Users (`server.rs:35`). The state the window reads includes the **names of the networks the person is on**
(`crates/dnet-view/tests/fixtures/snapshot-connected.json:23`). On a shared machine (a lab PC, a family computer, a second
user left signed in) another user can read that. Remote clients are not a problem: the pipe is created with tokio's default,
which rejects remote clients (`reject_remote_clients: true` in the pinned tokio source), and the first instance flag is set
(`server.rs:399`), which stops a pre-created pipe from taking the name.
*Fix:* answer read-only requests in full only to the console user and administrators; anyone else gets the version and a
coarse state.

### E5. The server is never patched, and the script says more than it does (Medium, verified)

The bootstrap script installs packages and cleans caches (lines 303 to 306, 519, 520) but sets up **no automatic security
updates and no SSH hardening**, on a free VM that is meant to run unattended for months. Its comment says the firewall step
opens "exactly the three ports" (line 488), but the code only *adds* accept rules (lines 494 to 497); it sets no default deny,
so whatever the image already allows stays allowed. (Oracle's images ship with their own rules; I did not check them.)
*Fix:* enable the distribution's unattended security updates; leave key-only SSH as the image has it and say so; either set a
real default deny for inbound (with SSH kept) or correct the comment and the guide.

### E6. The client's own core logs at `info` (Low, verified)

`primary.rs:320` sets the client core's log level to `info`, at which the core writes the destination of connections. Today
nothing persists it: the supervisor forwards core output to `tracing` at debug level (`process.rs:3`), and the service's own
filter defaults to `info` (`main.rs:86`), with no file sink anywhere in `dnetd`. So this is **not a leak now**; it is one
careless change away from one, and the server already uses `warn` (line 398).
*Fix:* `warn` for the client core as well, and a test that fails if a log sink is ever added without a redaction check.

### E7. No MTU strategy (Medium, hypothesis)

The generated client configuration has no `mtu` and no `stack` for the tunnel (`primary.rs:334` to `342`); the only size limit
in the code is the cap on Hysteria 2's packet size (`transport_params.rs:62`). Tunnels over QUIC carry datagrams that cannot be
split, and a path that drops oversized packets without the ICMP reply produces the familiar "some sites half-load" failure
(RFC 8899 exists for this reason). Whether the defaults of the pinned core hit this on a typical Wi-Fi is not known.
*Update after reading the pinned source:* this mostly dissolves. Hysteria 2 fragments oversized UDP messages itself, and TCP
streams end in the core's own stack, so packet size never reaches the carrier; the new design carries user traffic as
streams ([solutions](2026-10-31-solutions.md) §0, §7). What remains is the AmneziaWG adapter's MTU.
*Test (S7), narrowed:* only for the AmneziaWG profile, in the Docker lab.

### E8. The IPv6 path is unspecified (Medium, hypothesis)

The FakeIP configuration has an IPv6 pool (`fakeip.rs:32`) but the tunnel interface has one IPv4 address
(`primary.rs:97`, `172.19.0.1/30`). What happens to an IPv6 connection (blocked, leaked, or routed) depends on the core's
`strict_route` behaviour, which its documentation describes only for DNS and "unsupported networks" ("makes unsupported
networks unreachable"). It might be exactly right; it has not been tested.
*Test (S4):* IPv6-only and dual-stack lab networks, with the guard off and on.

### E9. Nothing handles sleep, resume or shutdown ordering (Medium, verified absence; effect hypothesis)

I searched every crate for service power events, session-change events and pre-shutdown handling and found none. (The
console user *is* read afresh on each request, `console.rs:27`, so a fast user switch does not break authorisation.) After
resume the network usually changes under the service; it is picked up by the interface-change watcher, and a dead carrier by
its health probe, so the likely result is a delay, not a failure. Similar clients have had worse: another VPN's tracker reports
routes lost after resume while the connection still looked active ([OpenVPN #71](https://community.openvpn.net/openvpn/ticket/71),
secondary), and a sing-box issue shows a default-route metric loop on Windows
([sing-box #3858](https://github.com/SagerNet/sing-box/issues/3858), secondary). Neither is shown to apply to our pins.
*Test (S8):* suspend and resume a lab VM while connected, with the guard on and off; measure the time to a working tunnel.

### E10. The first local control endpoint is about to be added by ADR-0008 (High for the design, verified current state)

Today the generated configuration contains **no local listener except the tunnel** (the probe configuration has a loopback
SOCKS proxy, and it requires a username and password: `probe.rs:36` to `40`, a good pattern). ADR-0008 proposes switching the
selector through the core's Clash API, which is a local control endpoint. A local web API without authentication and a Host
check is a known target for pages that make a browser talk to `127.0.0.1` (DNS rebinding and cross-site request forgery;
[Unit 42](https://unit42.paloaltonetworks.com/dns-rebinding/), general class, primary for the technique; I found no advisory
specific to this core's API).
*Requirement for ADR-0008 (corrected after measuring the pinned build; see
[the solutions file](2026-10-31-solutions.md) §3.1):* if the Clash API is used, it listens on loopback only with a random per-run
secret that the service alone holds; the service refuses an empty secret (that disables authentication); the cross-origin allow
list names one origin that cannot occur (an *empty* list means allow-all in the source); a test that a request without the secret
fails and that a foreign-origin preflight gets no allow-origin header. The core has **no Host check and only a TCP listener**
(a foreign `Host` with the right secret returns 200), so the secret is the only protection, and the guard adds a rule that lets
only `dnetd` reach the port.

### Checked and sound (so nobody re-checks them)

| What | Evidence |
|---|---|
| Remote clients cannot open the control pipe | tokio default `reject_remote_clients: true` (`tokio-1.54.0/src/net/windows/named_pipe.rs:1779`) |
| A pre-created pipe cannot take the name | `first_pipe_instance(first)` (`server.rs:399`) |
| The pipe's descriptor is an explicit DACL, never null | `server.rs:29` to `36` |
| The undo journal is replayed by SYSTEM, so it is refused unless owned by SYSTEM or Administrators with no other access, written by temp file and rename | `undo_file.rs` header and the test `a_journal_anyone_can_write_is_refused` |
| Sealed credentials use a different DPAPI entropy per blob; machine scope is a stated choice, so a local administrator can read them | `secret_store.rs:8` to `19`, `362` (accepted; belongs in the threat model as out of scope) |
| The probe's loopback proxy needs credentials | `probe.rs:36` to `40` |
| The window has a strict content policy and no global Tauri object | `tauri.conf.json:9` and `:11` |
| Mutations are refused while a previous run's network changes are unrestored | `service_impl.rs:609` |

---

## Part F — Published failure classes new to this project

| ID | Finding | Source (confidence) | What it changes |
|---|---|---|---|
| **F1** | WFP object lifetimes: *dynamic* objects vanish when the session or the process ends; *static* ones live until the filtering service stops or the machine shuts down; *persistent* ones live until deleted; *boot-time* filters exist from the TCP/IP driver's start until the filtering service finishes starting; a persistent object owned by a provider that names a Windows service is applied at start **only if that service is set to auto-start** | [Microsoft Learn, object management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) (primary) | A guard made of dynamic filters fails open when `dnetd` dies, which is the W6 gap again. A guard of persistent filters survives a crash and a reboot, and the provider-with-service rule gives lockout safety: tie the provider to the `DNetEngine` service, and a disabled or removed service means the block is not applied at the next start. This is a stronger version of the R4 mitigation in ADR-0008 |
| **F2** | The reference rule set in WireGuard for Windows: permit the tunnel interface, permit its own service (matched by program path **and** user), loopback, DHCPv4/v6, the five neighbour-discovery message types, **Hyper-V VM-to-VM traffic**; then block everything; a separate DNS block with exceptions. The filters in that file are not marked persistent | [`tunnel/firewall/rules.go`](https://github.com/WireGuard/wireguard-windows/blob/master/tunnel/firewall/rules.go) (primary) | The guard's allow list is at least this; it must include the Hyper-V permit, because the owner's own lab is Docker and WSL |
| **F3** | Mullvad's guard is reported to keep a highest-weight persistent blocking sublayer when the daemon exits while a block should stay (lockdown mode, or an exit the user did not ask for), active before the filtering service starts at boot; its help pages describe a failure where a WFP transaction times out waiting for the lock, and trouble with third-party security software | [Mullvad app docs](https://github.com/mullvad/mullvadvpn-app/blob/master/docs/security.md) (the page itself was not read; the details come from mirrors, **secondary**) | Design the guard for three failure modes from the start: transaction timeout, filtering service restart, and a third-party firewall |
| **F4** | The sing-box documentation for `strict_route` on Windows says only that it prevents DNS leaks from Windows' multihomed name resolution and makes unsupported networks unreachable; it does not describe a general block | [sing-box tun inbound](https://sing-box.sagernet.org/configuration/inbound/tun/) (primary) | Confirms that `strict_route` is **not** a kill switch. The README and the About text must not call it one |
| **F5** | A SANS paper on Windows 10 multihomed name resolution reports that turning the feature off did not always stop the leak and that name-resolution policy rules worked across editions | [SANS reading room](https://www.sans.org/reading-room/whitepapers/dns/preventing-windows-10-smhnr-dns-leakage-40165) (search excerpt only; **secondary, not read in full**) | The DNS-leak lab test (S4) checks LLMNR and NetBIOS name queries as well as DNS |
| **F6** | A review site's kill-switch test (23 services) reports leaks on reboot and client crash; the page is behind a membership wall, so I could read only its title and the number of services tested | [RTINGS](https://www.rtings.com/vpn/learn/research/killswitch-leak) (**not usable as evidence**; listed so nobody cites its claims) | None. F1 and F3 cover the same ground from primary and vendor material |
| **F7** | QUIC datagrams are atomic and an oversized one is an error, not a fragmentation; RFC 8899 defines probing for the largest packet that works | [RFC 8899](https://datatracker.ietf.org/doc/rfc8899/) (primary); the Quinn behaviour is from a project note (secondary) | E7 |

---

## Part G — Upgrades beyond ADR-0008

Each one says what it is, why (the evidence above), cost and risk, and the gate it needs. The numbering G1 to G12 is only for
reference.

**G1. Guard v2 (replaces §3.5's outline).** Persistent, provider-scoped filters, with the provider named after the `DNetEngine`
service so a disabled or uninstalled service lifts the block (F1); the allow list of F2 as a floor; matching the carrier by
program path **and** user (F2) so no other program reaches the endpoint; an explicit design for transaction timeouts, filtering
service restarts and third-party firewalls (F3); a recovery path that needs no network (`dnetctl guard-release`, the uninstaller,
and a documented safe-mode command). Because a block filter wins over a route, it also closes the DHCP-route class
(TunnelVision) without parsing DHCP. *Cost:* the project's most dangerous new code, a user-mode WFP layer. *Gate:* S4, security
review, an owner lab run, ADR-0006 P3 approval.

**G2. Server profile v2.** E1 (reject private destinations), E2 (a credential per device with a remove action), E5 (automatic
security updates, a truthful firewall step), plus a small health beacon reachable only through the tunnel so the client can tell
"the server is down" from "this network blocks the carriers". *Cost:* a script and data-model change in code that already has a
test harness (`bootstrap/tests.rs`, 1979-test suite). *Gate:* security review, real-server run (`LOCAL-COMMANDS.md` §8).
**This is the best first code change:** no design uncertainty, it removes real weaknesses, and it does not wait for any spike.

**G3. Network Truth: tell the person what the network is doing to them.** Measured facts only (the project's own rule for
tiers), each shown in plain words and recorded as component evidence: whether UDP on port 443 gets through; whether the
certificate chain presented for a known test site differs when fetched through the tunnel and directly (a sign the network is
inspecting TLS); whether a resolver's answer differs between the network's resolver and the tunnel's (tampering); captive-portal
state; large clock skew (a wrong clock breaks TLS); whether the DHCP lease contained classless static routes (needs a lab check
that Windows exposes it to a service). This is the honest counterpart of "hiding": it makes the tool the one that *knows*,
which suits FR-033, and it feeds the live map and the per-network class in Memory. *Cost:* probes the service mostly has
already (the portal probe, the race, the measurement origin). *Risk:* a false "your network is inspecting traffic" would
frighten people, so each check has a stated false-positive bound and a negative control. *Gate:* design review; lab.

**G4. Hostile-network posture (opt-in, per network class).** When the person marks a network as untrusted, apply and remember
(in the undo journal, undo registered first) a stricter local posture: the Public firewall profile for that network; no
inbound file sharing; name-resolution broadcast protocols (LLMNR, NetBIOS) not sent on that interface. This protects the
*device* on a LAN with other people on it, which the owner asked for, without claiming anything about the tunnel. *Risk:* it
changes system settings, so it needs its own ADR and security review, a strict undo test, and a default of **off**. *Gate:* ADR.

**G5. Control-plane hardening.** E3 and E4 together: sensitive mutations need a confirmation the window shows; read-only
detail is limited to the console user and administrators; a short, visible log of what changed the routing-relevant state and
which program asked; and the Clash API requirements of E10. *Cost:* small, in `dnet-ipc` and `dnetd`. *Gate:* security review;
the T039-style attack test extended.

**G6. Power and session awareness.** Handle the service's power, session-change and pre-shutdown notifications (E9): on suspend
mark every carrier's health stale and keep the guard armed; on resume re-validate before reporting "connected", and
re-run the interface-change logic; on pre-shutdown finish the undo bookkeeping. *Cost:* modest, Windows-only, testable behind
the existing fake-effects pattern for the ordering. *Gate:* S8.

**G7. A verification programme that matches the risk.** The tests prove what was built; the live gates prove the claims, and
the lowest-covered code is the riskiest (coverage 40% and 0% on the Windows routing and bring-up code). Proposed, in order of
value per effort: (1) a recorded **network weather** library (loss, delay, throttling, blocking patterns captured from the
owner's own networks and from the lab) that every release replays in the Docker harness, deterministically; (2) fault injection
in the lab (killing a core mid-transfer, flapping an interface, resuming from sleep); (3) fuzz targets with `cargo-fuzz` for
the parsers fed by outsiders (control-pipe frames, the bootstrap report, the feed envelope, the rule patterns) alongside the
property tests that already exist (the dnetctl fuzz module is a start); (4) model checking of the Conductor's state machine
(the pure `dnet-core` makes this practical) with one of the existing Rust model checkers or TLA+, chosen by a one-day spike;
(5) a Windows runner in CI for the `--ignored` tests, which today only the owner's elevated shell runs. *Gate:* the owner's
choice on (5), which needs a self-hosted or paid runner.

**G8. Supply chain for the two Go cores and the server cores.** They are the largest unaudited code in the product and are
built from pinned source by `fetch-vendor`. Add: a reproducibility check (build twice, compare hashes), `go mod verify` and a
vulnerability scan of the cores' dependency graph in CI, a software bill of materials in each release, signed provenance for
release assets, and a documented way to update the **server** cores (E5 and W10 meet here: a patched server core today needs
the person to re-run setup). *Gate:* none; mostly CI and release-workflow work. (General practice; not verified against a
specific source here.)

**G9. Flight recorder.** A bounded, redacted, local ring of component events and measurements (the Registry's history),
stored in the same trusted directory as the other state, exportable only by the person's own action. It makes the live map
explain *what happened* rather than only *what is*, makes a support conversation possible without any telemetry, and gives G7
real traces to replay. *Gate:* the redaction test of the diagnostics module extended to it.

**G10. Cause attribution.** The hardest question in this domain is "is it my network, the server, or my machine?". Witness
checks (a neutral reference, the server's second port, the beacon of G2) let the Registry attach evidence to a cause without
adding to the seven `FailureCause` variants. *Gate:* design only; depends on P1.

**G11. Independent second server in onboarding.** W5 again, with evidence from the plan: the only lasting free tier can reclaim
an idle VM (`docs/plans/2026-10-30-guided-onboarding.md` §3). The guide should lead to a second server at a different provider
or region, and the client should say "your server may have been reclaimed" when the beacon and every port are silent but the
network is otherwise fine (G10).

**G12. Performance by measurement.** The tunnel's packet stack and MTU are not chosen (E7); the congestion-control option
(Brutal) is already owner-opt-in with a warning. Run the same transfer through each stack setting and an MTU ladder on the
owner's laptop and record CPU, throughput and latency under load before choosing defaults. *Gate:* S9, which needs a Windows
machine.

---

## Part H — Considered and left out

Left out on purpose, so the next session does not rediscover it as a gap:

- Anything whose purpose is to make the tunnel *undetectable by a network's operator*, to *anonymise* the person, or to defeat
  a named institution's monitoring or policy. The published detection research (Part C.2 of the first file) shows such claims
  fail, which is a safety problem for the person, and the project decided against them (FR-033, ADR-0006 §3, Principle VI).
  What the carriers do — look like ordinary encrypted web traffic so that they are not blocked by accident — is a robustness
  property of the protocols, stated as that.
- A relay or rendezvous service run by the project (the project operates no infrastructure).
- Multipath aggregation and download acceleration (separate specifications by the constitution).
- A custom session or transport layer in our own code (Principle I; ADR-0008 alternative B).

---

## Part I — Priority, gates and what is unproven

| Order | Work | Gate | Why this order |
|---|---|---|---|
| 1 | **G2** server profile v2 (E1, E2, E5) and **E6** log level | Security review; real-server run | Real weaknesses, no design risk, independent of every spike |
| 2 | **G5** read-only split and mutation confirmation (E3, E4) | Security review | Small, closes the cheapest local attacks before the Registry adds more read data |
| 3 | ADR-0008 **P1** Registry and the live map, with **G9** | None | Fixes W9, feeds the map the owner wants, and is the data G3 and G10 need |
| 4 | Spikes **S1, S2, S3, S6** (ADR-0008) plus new **S7** MTU, **S8** sleep/resume, **S9** stack and throughput, with **S4** extended by E8 | Harness / lab VM | Answer the open questions before any engine change |
| 5 | **G1** Guard v2 | S4, ADR-0006 P3 approval, security review, owner lab run | The most valuable and the most dangerous change |
| 6 | **G3** Network Truth, **G6** power and session awareness | Lab | Builds on the Registry |
| 7 | **G4** hostile-network posture | Its own ADR | Changes system settings; opt-in |
| 8 | ADR-0008 P4 to P6 | Spike results | The framework change itself |
| any time | **G7** weather library and fuzz targets, **G8** supply chain, **G11** second server | — | Raise confidence in everything above |

**Unproven, and where it would be settled:** whether the pinned core can carry a WireGuard endpoint over another outbound and
move a live session on a carrier switch (S1, S2); whether MTU, IPv6, sleep and the DHCP-route class behave on Windows as the
code assumes (S4, S7, S8); the real cost of any of this on the owner's machine (S9, S6). Several sources here are secondary and
say so in the table.
