# Assembly, deeper access, and adapting to the network: what helps and what does not (2026-10-31)

**The owner's question.** Would writing the core in assembly or "binary" give deeper access and a better product? And
should the software understand the kind of network it is on (Wi-Fi generation, 2G to 5G, a college hotspot, a mobile
hotspot, another country's carrier) and adapt by itself?

**Answer in one line.** Assembly would give no extra access and no useful speed, and it would add risk. The second half of the idea
is right and is buildable in the existing language: read what the operating system already knows about the link, measure the rest, and let
that choose how the connection is made.

Labels as before: *Source* (read in the pinned crate, library or a primary document), *Secondary*, *Designed*, *Unverified*.

---

## 1. Language and access

| Claim | What is true | Evidence |
|---|---|---|
| "Binary or assembly is the origin language, so it has more access" | Every compiled language (Rust, C, Go) ends as machine code, the same thing assembly produces. Access is set by the **privilege the process runs with** and by the **operating system's interfaces**, not by the language. A program in assembly started as a normal program has the same permissions as one in Rust. | general fact |
| "Deeper access" | The only deeper level on Windows is **kernel mode**: a driver. That is a different kind of program (any language), not a different language. Windows loads new kernel drivers only if they are signed through Microsoft's hardware programme; vendor sources agree on the programme and an extended-validation certificate, and disagree on whether a plain certificate is enough (Secondary; check Microsoft's driver-signing pages before relying on it). | vendor pages, conflicting |
| Is the access we lack something a driver would give? | No. We already use the vendor-signed Wintun driver for the tunnel adapter. The block-and-permit power the guard needs (stopping traffic that bypasses the tunnel) is a **user-mode** interface, the Windows Filtering Platform, all of whose calls are already in the workspace's Windows crate (solutions §4). The constitution forbids kernel drivers without an ADR. | Source |
| Speed | Assembly pays only in small hot loops, and the cores **already contain it where it counts**: the hand-written amd64 assembly for ChaCha20-Poly1305 and BLAKE2 in `golang.org/x/crypto`, which the cores build in. Over large code a compiler beats hand-written assembly and the result runs on one CPU family only (Windows laptops now come on ARM too). | Source (files in the module cache) |
| Safety | Assembly has no memory safety. The audit's biggest structural finding is that the privileged service and the cores already run as SYSTEM and parse hostile input; adding unsafe code there makes that worse, not better. The constitution's Principle I also forbids writing our own transport or crypto. | Source (audit E11) |
| Maintainability | The owner does not program in Rust; assembly would be unreviewable for them and for most contributors. | session rules |

If one specific CPU instruction is ever needed, Rust has inline assembly for that one spot; nothing needs rewriting.

**Where the measured slowness is.** On loopback, 300 MB took 8.0 s as a plain Hysteria 2 stream, 15.6 s as a session over Hysteria 2 datagrams, and
5.3 s as a session over REALITY (`testing/spike-carrier`; one CPU, relative only). The expensive part is the QUIC datagram path in user space.
The pinned QUIC library has UDP segmentation and receive-coalescing code for **Linux and macOS only**; for Windows it has a single file
about the don't-fragment bit. Windows itself offers UDP Segmentation Offload (Windows 10 version 2004 and later) and UDP Receive Segment
Coalescing (Windows 11 24H2 and later), which an application opts into through socket options (Microsoft Learn, driver documentation).
That is the "deeper" lever that exists, it needs no assembly and no driver, and whether it helps this library on Windows is **Unverified**: one spike (T168).

---

## 2. What "the internet has versions" means here

Two different layers, which is why the idea needs separating:

- **The radio link** between the device and the router or tower: Wi-Fi 5 / 6 / 6E / 7 and their channel widths, 2G to 5G. It decides the speed ceiling,
  delay, loss, power use and, on mobile data, **cost**. Our software cannot change it.
- **The internet protocols above it**: IPv4 and IPv6, TCP and UDP, HTTP/1.1, 2 and 3 (QUIC), TLS 1.2 and 1.3. These are the "versions" the tunnel meets, and they are
  where networks differ in ways that matter to us: UDP blocked, IPv6 only, shared addresses.

### What the operating system already tells us (no assembly needed)

| Fact | Interface | State |
|---|---|---|
| Wi-Fi generation (`ax` is Wi-Fi 6 and 6E, `be` is Wi-Fi 7), link rate, signal quality | the WLAN API; the PHY types `dot11_phy_type_he` and `dot11_phy_type_eht` and the association attributes are in the workspace's Windows crate (the `WiFi` feature is already enabled) | Source |
| Metered or limited: unrestricted, fixed, variable, over the data limit, roaming | the Network List Manager cost constants, in the same crate | Source |
| Wired, Wi-Fi or cellular | `IF_TYPE_*`, already read by `paths.rs` | built |
| Cellular generation (4G or 5G) | the mobile-broadband / Windows.Networking interfaces; the plain Win32 constants for it were not found in the crate | Unverified |

### What the project reads today

Only the **kind** of link, with the default preference wired over Wi-Fi over cellular "because it costs data" (`paths.rs`). It does not read the Wi-Fi
generation, rate, signal, the metered flag, or whether the network is IPv6 only. And it has a hard rule that matters for your example:

> *A physical network adapter that is up and has an IPv4 default route (endpoints are IPv4 literals, so an adapter with only an IPv6 route cannot carry one)* (`paths.rs`)

---

## 3. India and Jio, and any other carrier

Jio's own presentation says it moved toward an IPv6-only core, keeping dual-stack for tethering because IPv6-only was poor for hotspot users
([APNIC](https://conference.apnic.net/50/assets/files/APCS790/Harnessing-the-power-of-IPv6.pdf)); a LinkedIn engineering post says nearly all of Jio's Android
devices are IPv6-only ([LinkedIn](https://engineering.linkedin.com/blog/2019/02/the-growth-of-ipv6-in-the-asia-pacific-region)); and a tester found 464XLAT unreliable for
applications that hard-code IPv4 addresses ([Anurag Bhatia](https://anuragbhatia.com/post/2023/02/jio-5g-ipv6-only/)); a 5G home router was described as giving IPv6 plus
shared (CGNAT) IPv4 ([TechEnclave](https://techenclave.com/t/running-full-keyhelp-web-server-behind-jio-5g-cpe-ipv6-only-limited-cpe-need-ipv4-router-setup/398381)). All
Secondary. No source on Jio's UDP timeouts was found.

What follows for this project:
1. **A PC that gets only IPv6 finds no path today**, and could not reach an IPv4-literal server anyway. Two fixes, one to choose by lab test: give the server an IPv6
   address as well (whether the free tier allows it is Unverified), or learn the network's NAT64 prefix (RFC 7050: ask for the AAAA record of `ipv4only.arpa`)
   and dial the server's IPv4 address through it (Designed).
2. Shared-address (CGNAT) networks forget idle UDP mappings sooner than a home router. The session's keepalive (25 s) and the carrier's own idle settings should
   come from a **measured** value per network, not a country table.
3. **Nothing should be country-specific.** Everything is found on the spot and remembered per network (ADR-0008 Memory), so the same code works in the US, India or anywhere.

---

## 4. The adaptive path profile (the part of the idea worth building)

**Inputs** (cheap, no traffic): link kind; Wi-Fi generation, band, rate and signal; metered flag and roaming; IPv4 and IPv6 availability; captive-portal state.
**Measured** (the race and probes the service already runs): is UDP reachable, delay, loss, throughput samples, how long a mapping survives.
**Outputs** (a small policy table; every row is a hypothesis until measured):

| Situation | What changes |
|---|---|
| UDP blocked | the TCP carrier first in the ladder |
| Metered or roaming | no hot standby; no full race (use Memory); no Brutal; update and feed fetches wait |
| Shared-address mobile | shorter keepalive, from a measured value |
| IPv6 only | NAT64 or IPv6 server (above) |
| Weak Wi-Fi signal or low link rate | say so in plain words, prefer a stronger path if one exists |
| Wired or strong Wi-Fi | defaults |

Shown to the person as plain facts, not as claims about the tunnel (FR-033). It is also what the live map needs as component evidence (ADR-0008 Registry).

**Honest limits.** The software cannot make the carrier's network or the Wi-Fi faster, and using two networks at once is aggregation, a separate specification by the constitution.
It can choose the best path and carrier, fail over, and avoid waste.

---

## 5. Proposed tasks (recorded in `tasks.md`, none started)

- **T165** Read and show the link's facts (Wi-Fi generation, rate, signal, metered flag) as component evidence. After the Registry.
- **T166** IPv6-only networks: a path rule that accepts them, and NAT64 or an IPv6 server address. Lab first.
- **T167** Metered-aware policy from §4's table, each row behind a measurement.
- **T168** Spike: do the Windows UDP offloads help the QUIC path (needs a patch to the QUIC library, as the project already patches one).

Decision for the owner: whether to adopt §4 as the plan for "works on every kind of network". It changes no existing behaviour until built.
