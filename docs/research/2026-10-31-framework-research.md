# Framework research and status audit (2026-10-31)

**Purpose.** The owner asked for two things before more features are built: (1) where the project stands after
the work done on another account, and (2) a deep look at how this kind of software is built elsewhere, where the
current framework is weak, and what a better foundation would be. This file is the evidence. The proposal that
follows from it is [`docs/adr/0008-session-carrier-framework.md`](../adr/0008-session-carrier-framework.md).

**How to read it.** Every outside claim names its source and a confidence. *Primary* = the standard, the paper
or the project's own documentation. *Secondary* = a vendor or community write-up. *Unverified* = a preprint or a
page I could not check against its primary source; it is listed so it is not lost, and nothing is built on it.
Nothing here is a measurement made on a real network: the project has run none yet.
A second, deeper pass (weaknesses found by reading our own code, more published failure classes, and the upgrades they lead
to) is in [`2026-10-31-framework-deep-audit.md`](2026-10-31-framework-deep-audit.md).

---

## Part A — Where the project stands

### A.1 What happened since the last session I saw (2026-10-24)

Three commits on branch `wip` (the other account, a cloud Linux session plus a local Windows session):

| Commit | Date | What it added |
|---|---|---|
| `28c13ae` | 10-26 | The window (Svelte in a Tauri shell), `dnet-view`, provisioning engine (mock provider only), process attribution, signed profile feed |
| `4a9dd50` | 10-30 | Guided server setup (`PrepareServer`/`FinishServer`), always-on service (T147/T148), self-installing service, NSIS installer and release workflow, Brutal mode and personal rules end to end |
| `e8431b4` | 10-30 | A guided server now carries a measurement origin (found by the plan re-read, not by a user); idle network cost cut from about 92 MB/h to about 1 MB/h; leak settings pinned by a test |

Uncommitted now: a test fix in `dnet-provision` (a `sh -n` check that WSL's launcher misread), a fix to the local
log wrapper `testing/log.ps1` (stderr was not reaching the logs), and a test for it (`crates/xtask/tests/`).

### A.2 What has actually been run

| Evidence | Result |
|---|---|
| Whole Rust workspace on the current tree (this session, not elevated) | **1979 passed, 0 failed, 14 ignored** |
| Same, on the Windows machine, elevated (`.local-logs/1.4.log`, 2026-10-30) | 1979 passed, 0 failed, 14 ignored |
| Window (`pnpm check`, `pnpm test`) on the current tree | 0 type errors, **259 tests passed** |
| Elevated `--ignored` tests: real routes, file permissions, undo recovery (`1.5.log`) | Pass: a real host route is installed, preferred and removed; a route left by a crashed run is removed by replay; a real interface change is signalled |
| ETW attribution test, elevated (`2.1.log`) | The test passes; the log's exit code is non-zero only because the closing `logman query` found no leftover session |
| `dnetd` as SYSTEM, Brutal on and off through `dnetctl` (`4.2`, `4.3`) | Works; the warning is shown first and nothing changes without `--accept-warning` |
| Window launched elevated (`4.5`) | It started and ran six minutes; **what the person saw and did is not recorded** |
| `cargo audit` (`1.8`) | One allowed warning (a `tokio` unsoundness notice) |
| Coverage of the four crates not in CI (`1.6`) | 83.2% of lines overall. **Windows-specific code is the least covered**: `win_route.rs` 40%, `win_bringup.rs` 0%, `dnet-supervisor/windows_runtime.rs` 0%, `dnet-etw/session.rs` 0% |

### A.3 What has *not* been run (the foundation is unproven)

None of the live gates has passed. Sections 5 to 9 of `LOCAL-COMMANDS.md` (rules, installer on a VM, guided setup on a
real Oracle server, the network-cost measurement) have no logs. The open gate tasks are T055 and T098a (the routing-loop
gate), T068, T079, T085 (does an open transfer survive an interface change: HV-07), T098, T111 (a stranger and a screen
reader), T114 to T118 (installer, size, memory, crash recovery), and T066d (the root key ceremony, which keeps the signed
update channel switched off). By count: **140 tasks done, 18 open**, and the open ones are the ones that prove the claims.

### A.4 The files in use

About 80,000 lines of Rust in 12 crates and 7,700 lines of window code, plus the documents that govern them.

| Where | What it is | Size |
|---|---|---|
| `crates/dnetd` | The privileged service: orchestrator, effects, configuration changes, server setup, intent, keep-trying, installer hooks | 18.2k lines |
| `crates/dnet-core` | Pure decisions: engine (state machine), selection, failover, rules, feed, telemetry, degraded reporting. No I/O | 17.4k |
| `crates/dnet-config` | Writes each core's configuration; credentials; secret store; install trust | 9.2k |
| `crates/dnet-ipc` | The control pipe: framing, protocol, authorisation, client | 8.4k |
| `crates/dnet-provision` | Server setup engine and script generator (mock provider; no real cloud provider) | 7.6k |
| `crates/dnetctl` | Command-line client | 4.9k |
| `crates/dnet-netstate` | Interfaces, routes, undo journal, network-change events, Wi-Fi names | 4.5k |
| `crates/xtask` | Build tooling: vendor cores, installer staging, feed tools | 4.0k |
| `crates/dnet-view` | The only door between the window and the service | 2.7k |
| `crates/dnet-probe` | Measures each method on the current network | 2.2k |
| `crates/dnet-etw`, `crates/dnet-supervisor` | Process attribution; child-process lifecycle | 1.6k, 1.4k |
| `apps/dnet-tray` | The window and its Tauri shell (detached from the workspace) | 7.7k |
| `vendor/` | Two pinned cores built from source: sing-box **v1.14.0** (tags `with_quic,with_utls,with_clash_api,with_gvisor,with_external_windivert`, patched) and amneziawg-go **v3.1.20260828**; the signed Wintun DLL | — |
| `installer/`, `.github/workflows` | NSIS installer, winget manifests, CI and a draft-release workflow | — |
| `testing/harness`, `testing/spike-r4`, `testing/linux` | Docker hostile-network lab, the routing-loop gate runner, Ubuntu-in-Docker checks | — |
| `docs/`, `specs/001-…` | Constitution, research critique, ADR-0001 to 0007, spec, plan, `tasks.md` (the delivery record), owner gates, network budget | — |

---

## Part B — Where the current framework is weak

Each weakness points at the code or document that shows it. These are findings about the *design*, not about test
failures: the tests pass because they test what was built.

**W1. One tunnel at a time; every switch is break-before-make.** The engine's actions are `StartRace`, `StartTunnel`,
`StopTunnel` (`dnet-core/src/engine.rs`); after `StopTunnel` the posture is fail-closed until another tunnel is up. A
switch of method or endpoint is therefore an outage, targeted at 30 seconds, and nothing is pre-warmed.

**W2. The session is welded to the carrier.** Each profile is its own VPN session (a WireGuard session, a QUIC
connection, a TCP+TLS stream). Changing carrier or network means a new session, so every inner connection resets. This is
why the architecture document says the REALITY profile "breaks established connections on interface change", and why
**today every profile is labelled Tier 2**: no profile has a recorded survival result (HV-07 is unrun). Today "Stabilize"
means "reconnect quickly", not "stay up".

**W3. Selection is episodic and forgetful.** The race runs at each connect (up to 576 KiB, `docs/network-budget.md`) and
the engine reacts to blocks afterwards. Nothing remembers that on *this* network method X worked yesterday. There is no
per-network memory anywhere in `dnet-core` or `dnetd` (searched). Comparable systems do remember (Part C).

**W4. The menu of carriers is closed.** Three fixed profiles; the signed feed can tune parameters, not add a carrier. A new
way through needs a new release and a new pinned core. Outline's design shows the alternative: composable strategies.

**W5. One server is a single point of failure for everything.** The guided path makes one free Oracle VM. If that address is
blocked, or the provider reclaims the VM, the result is `NoEndpointReachable` and the person is offline. Multi-endpoint
rotation exists in the model, but onboarding does not lead to a second endpoint.

**W6. Fail-closed is a decision, not an enforcement.** `RoutingPosture` has no direct variant, but nothing in the operating
system enforces it (README and ADR-0006 say so); the project makes no use of the Windows Filtering Platform of its own. The
only protection is the core's `strict_route`, whose firewall rules **have not been verified on Windows** (`docs/network-budget.md`
says so). A crash of `dnetd` restores direct routing by design. Two published leak classes are not mentioned anywhere in the
repository (searched for DHCP option 121, TunnelVision, TunnelCrack, LocalNet):
- *TunnelVision* (CVE-2024-3661): a rogue DHCP server pushes static routes (option 121) that send traffic around the tunnel.
- *TunnelCrack* (USENIX Security 2023): the *LocalNet* and *ServerIP* attacks. **LocalNet is not a problem here by
  construction**: the built-in local bypass is a fixed list (RFC 1918, link-local, multicast) and is not derived from the
  interface's address (`dnet-core/src/builtin_rules.rs`). **ServerIP is partly open**: the endpoint's host route sends
  *any* program's traffic to the endpoint's address outside the tunnel, not only the core's.

**W7. Carriers are chosen without regard to the policy of the network.** Managed networks commonly block QUIC (UDP 443)
on purpose so that inspection works (Part C). Two of the three profiles are UDP. The third is TCP with the TLS-in-TLS
fingerprint risk the literature describes. The race finds what works *now*, but there is no ladder, no learned order and no
notion of "this network class blocks UDP".

**W8. The riskiest and least-tested code is the Windows platform layer.** The second core (AmneziaWG) needs its own adapter,
so the project carries the routing-loop hazard (host route before tunnel, rewrite before rebind, and the rest of
`CLAUDE.md`'s ordering rules). That layer has the lowest coverage (A.2) and its gate (T055/T098a) has never passed.

**W9. No component model, so no honest "which part failed".** The service reports one overall state and a reason. It cannot
say that the adapter is up, the primary core has restarted three times, one network is lossy and one endpoint is not
answering, all at once. This blocks both good diagnostics and the live map the owner wants.

**W10. The update channel is inert.** Signed definitions are built but no root keys exist (T066d). The promise in
`Research-Critique.md` D6, that a blocked profile can be replaced without a release, is not true yet; and the two cores are
pinned, so a patched core also needs a release.

**W11. Complexity concentrated in one privileged service** (18k lines) and two supervised Go programs.

---

## Part C — What comparable systems do

| System | Idea | What it teaches here | Source (confidence) |
|---|---|---|---|
| **Turbo Tunnel** (Fifield, FOCI 2020; in obfs4, meek, Snowflake) | A reliable *session layer inside* the carrier, so the session survives when the carrier dies or changes. In Snowflake the session moves across temporary WebRTC proxies, retransmitting lost packets through another proxy instead of waiting for a 30 s timeout | The answer to W2: make the carrier replaceable, put persistence in the layer above it. Caveat from the same work: layering a naive session over a request-response carrier can be several times slower (a 10 MB transfer took 10.6 s over TCP-encapsulated QUIC, 23.3 s over plain meek, 34.9 s over meek with encapsulated QUIC) | [USENIX FOCI 2020](https://www.usenix.org/conference/foci20/presentation/fifield) (primary); numbers via a [summary](https://corpus.lantern.io/papers/2020-fifield-turbo/) (secondary, check the paper before quoting) |
| **Outline SDK Smart Dialer** | Takes a list of strategies (DNS resolvers × TLS tricks × fallbacks), *tests them* against test domains and returns a dialer using what works; fallbacks are tried only after the proxyless strategies fail | The answer to W3/W4: a strategy list that is data, tested per network | [Google/Outline docs](https://developers.google.com/outline/docs/reference/smart-dialer-config) (primary) |
| **Psiphon** | Server-supplied *tactics* that override client parameters; successful dial parameters are **saved and replayed**, keyed by network, server and protocol | W3: replay what worked on this network before racing again. (Whether it dials in parallel is not confirmed by what I found.) | [pkg.go.dev tactics](https://pkg.go.dev/gitee.com/lqinggang/psiphon-tunnel-core/psiphon/common/tactics), [DeepWiki](https://deepwiki.com/Psiphon-Labs/psiphon-tunnel-core/2.3-server-discovery-and-selection) (secondary: mirrors and a wiki) |
| **Lantern** | An adversarial bandit (EXP3.S) with a weight vector **per ISP**; a protocol whose success falls under 15% for an ISP has its weight cut but is still explored; polling adapts to confidence. Their own write-up reports a failure mode: early luck let one route dominate | W3: learning per network is the established approach; the failure mode is a warning to bound it | [Lantern blog](https://lantern.io/en/blog/how-lantern-uses-adaptive-machine-learning-to-outsmart-censors-133) (vendor, not peer reviewed). Related peer-reviewed theory: [Nasr et al., NDSS 2019](https://ndss-symposium.org/ndss-paper/enemy-at-the-gateways-censorship-resilient-proxy-distribution-using-game-theory) and the [FOCI 2026 revisit](https://petsymposium.org/foci/2026/foci-2026-0003.php) |
| **Tailscale** | Every connection starts through a relay and is **upgraded** to a direct path in the background; relays are picked by measured latency; paths are re-checked periodically | W1: start on whatever works, improve without interrupting; "path upgrade" is a normal operation, not an event | [Tailscale docs](https://tailscale.com/docs/reference/connection-types) (primary) |
| **Multipath QUIC** | IESG-approved March 2026 and in the RFC Editor queue; no RFC number found | Aggregation stays deferred (constitution), but the standard is real and arriving; a design should not close the door | [datatracker](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath) (primary) |
| **Forward error correction over tunnels** | Redundant packets trade bandwidth for loss: reported 10% loss reduced to about 0.09% for about 50% extra bandwidth; practitioners note it helps TCP by avoiding retransmits but is limited when whole frames are lost | A possible later feature for lossy Wi-Fi; not v1 | [Hopbox](https://hopbox.net/?p=360), [tinyFecVPN](https://gitee.com/mirrors/tinyFecVPN) (secondary) |

### C.2 Where tunnel designs fail (published)

| Finding | Why it matters here | Source (confidence) |
|---|---|---|
| **TunnelVision, CVE-2024-3661.** A rogue DHCP server's classless static routes (option 121) can steer traffic around a VPN. Windows, Linux, macOS and iOS are listed as potentially affected; mitigations are DHCP snooping on the network, ignoring option 121 on the client, and keeping local resources out of full-tunnel mode | W6: a hostile network is exactly this project's setting | [Red Hat CVE](https://access.redhat.com/security/cve/CVE-2024-3661), [Zscaler](https://www.zscaler.com/jp/blogs/security-research/cve-2024-3661-k-tunnelvision-exposes-vpn-bypass-vulnerability), [AhnLab](https://asec.ahnlab.com/en/79470/) (primary for the CVE; secondary for the platform list) |
| **TunnelCrack** (Xue, Malla, Xia, Pöpper, Vanhoef; USENIX Security 2023). 248 experiments on 67 providers; every one vulnerable in at least one case; LocalNet and ServerIP attacks, CVE-2023-36672 and CVE-2023-36673 | W6, as above | [paper](https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf), [project site](https://tunnelcrack.mathyvanhoef.com/) (primary) |
| **Enterprise firewalls block QUIC on purpose.** Palo Alto, Fortinet and Zscaler guidance recommends blocking UDP 443 so browsers fall back to TLS over TCP where inspection works; one vendor's community notes newer versions can detect HTTP/3 instead (community claim) | W7: on a managed network UDP carriers may be blocked by *policy*, not by accident | [Palo Alto](https://live.paloaltonetworks.com/t5/Management-Articles/How-to-Block-QUIC-Protocol/ta-p/120207), [Fortinet](https://docs.fortinet.com/document/fortisase/latest/administration-guide/219936/blocking-quic), [Zscaler](https://help.zscaler.com/zia/managing-quic-protocol) (vendor documentation; secondary) |
| **QUIC Initial packets are readable by any observer** (keys derive from a public connection ID), and the Great Firewall has blocked QUIC by SNI since April 2024 | Plain QUIC leaks its server name; the project's Hysteria 2 profile uses Salamander obfuscation, which is the reason it exists | [USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) (primary, abstract read) |
| **Encapsulated TLS handshakes are detectable** even with padding and several layers; tested on 23 proxy configurations including VLESS, in a deployment at an ISP with over a million users. The authors say multiplexing shows promise but padding and multiplexing alone do not remove the burst and round-trip features | The inner protocol of a TLS-based carrier should *not itself be TLS*. This favours an inner session that is not TLS (such as WireGuard) | [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue) (primary, abstract read) |
| A tool published June 2025 (*Aparecium*) distinguished REALITY servers from real web servers by TLS message sequence; a fix followed | A server-side core needs a way to be updated quickly (W10) | [Lantern corpus summary](https://corpus.lantern.io/defenses/reality/) (**secondary; not checked against the original**) |
| AmneziaWG 2.0: signature packets, padding on every packet, header ranges; reported to need the app's newer version and a self-hosted server | The AmneziaWG project is moving; our pin is v3.1.20260828 and its server counterpart must move with it | [Tom's Guide](https://www.tomsguide.com/computing/vpns/amneziavpn-launches-amneziawg-2-0-and-its-a-fundamental-shift-from-its-predecessor), [GL.iNet docs](https://docs.gl-inet.com/router/en/4/faq/amneziawg_obfuscation_parameters/) (secondary) |
| Encrypted Client Hello is standardised (one source says RFC 9849, March 2026, **unverified**) and on by default in major browsers when encrypted DNS is on; sources agree network-side SNI filtering is weakening | Long-term, domain rules that depend on seeing the SNI weaken; this project routes by the *requested name via FakeIP*, which does not depend on it | [IETF draft on deployment](https://datatracker.ietf.org/doc/draft-campling-ech-deployment-considerations/), [IEPG briefing](https://www.potaroo.net/iepg/2024-11-03-ietf121/slides-121-iepg-sessa-encrypted-client-hello-and-network-operators-00.pdf) (mixed) |
| *Unverified:* a 2026 preprint (AEGIS) reports a flow classifier whose detection of VLESS+REALITY falls to about 1% when mixed with real browsing | Nothing built on it | [summary page](https://corpus.lantern.io/findings/2026-ferrel-aegis-adversarial-entropy-guided__vless-reality-human-entropy-detection-limit/) (**unverified**) |

### C.3 What the pinned core supports (checked in its documentation)

From the sing-box documentation: the **WireGuard endpoint exists since 1.11.0** (we pin 1.14.0) and includes the shared dial fields
by reference; the dial fields include **`detour`** (send the connection through another outbound by tag) and `bind_interface`;
the **selector** outbound switches at runtime through the Clash API (we build with `with_clash_api`) and keeps existing
connections unless `interrupt_exist_connections` is true. `network_strategy` (try Wi-Fi and cellular together) is documented as
**Android and Apple graphical clients only**, so it is not available to us on Windows.
**Not confirmed by what I read:** that a WireGuard endpoint can use another outbound as its `detour`, whether the pinned
build's tags include what the WireGuard endpoint needs, and how re-handshake behaves when the carrier underneath changes.
These are the first spike (ADR-0008, S1). Sources: [WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/),
[dial fields](https://sing-box.sagernet.org/configuration/shared/dial/), [selector](https://sing-box.sagernet.org/configuration/outbound/selector/) (primary).

---

## Part D — What this research does not establish

- No measurement on a wire. The network-cost numbers in `docs/network-budget.md` are worst cases from constants, not captures.
- Whether Hysteria 2 or REALITY, as *this project configures them*, are blocked on any particular managed network. That is
  what the simulated harness and, later, the owner's own networks can say. The vendor guidance above says only that blocking
  UDP 443 is common.
- The exact current behaviour of Windows with DHCP option 121 and of the core's `strict_route`: both need a lab test (ADR-0008, S4).
- Whether the Lantern-corpus summaries match their papers; they are used only for pointers.
- Nothing here argues that the product can hide that a tunnel exists. The published detection work cuts the other way, and
  FR-033 stands: the documentation must keep saying that volume and destination remain visible to the network.
