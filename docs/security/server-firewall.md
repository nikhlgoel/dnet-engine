# The firewall and the ports: what is open, why, and what protects it

Written 2026-11-05 (T176). It says what the server and your computer expose, what stops a stranger or a stolen device
from misusing it, and, just as important, **what was tested and what was not** (section 7). Where something is how the
software is designed to behave but was not measured, it says so.

## 1. The short answer

- Your server has **three doors open to the whole internet**, and only these three. Each one only works for someone who
  holds a secret key that is made on your server and kept on your devices. Everything else about the server is as your
  provider and your operating system left it.
- **Nothing on the server can be used by a stranger as a free proxy.** The doors lead into the tunnel software and
  nowhere else; a device that is let in is limited to the public internet, not to your cloud's inside and not to the
  server itself.
- **A lost device or a leaked key cannot turn the server into a way into your cloud, a mail sender or a flood.** The
  server refuses private and reserved destinations, its own addresses, mail sent straight to other servers and anything
  but ordinary TCP, UDP and ping, and it caps how fast new connections can start. This is what keeps a free server's
  address from being banned.
- **Your computer opens no door to the network.** The program listens only on this computer itself, behind secrets,
  and it does not change Windows Firewall today.
- The part that makes a dropped tunnel *impossible* to leak around (the kill switch, enforced by Windows itself) is
  **designed and modelled but not built**. Until it is, the program decides to block your traffic; Windows does not
  enforce it.

## 2. The three doors

The wizard asks you to open exactly these on your provider's firewall, from "everywhere" (you cannot know in advance
which network you will connect from). The server script opens the same three on the server itself.

| Door | Port | What answers | What a stranger who knocks gets (by design) | What a person with your key gets |
|---|---|---|---|---|
| AmneziaWG | UDP 51820 | A WireGuard-style tunnel, made hard to recognise | Nothing: a packet not signed with your key is dropped without an answer. | A tunnel to the server (the last-resort path) |
| Hysteria 2 | UDP 44443 | A QUIC-style carrier, scrambled with its own secret | Nothing useful: without the scrambling secret the bytes are not a valid first packet, and without the password nothing is let through. | The carrier to the session, below |
| VLESS + REALITY | TCP 8443 | A carrier that looks like a visit to a real website | The real website: a visitor without your key is passed on to the genuine site you chose as cover. | The carrier to the session, below |

Behind the two carriers sits the **session**: a tunnel inside the server, with one key pair per device. A carrier can
reach **only** that session and nothing else (every other destination is refused in the server's own configuration), so
knowing a carrier password is not enough to use the server; you also need a device key.

The secrets are made on your server (16 random bytes for each Hysteria 2 secret, key pairs for the rest), kept in files
only the server's own accounts can read, and the script never regenerates one that exists.

### Doors that are never open to the internet

- The session's own UDP port. The core gives it no address to listen on, so a firewall rule is what keeps it for this
  machine: from outside it is dropped, IPv4 and IPv6.
- The measurement origin (the small page the client fetches to judge the tunnel): on the tunnel address and on
  loopback, never on the public address, and run by an account with no rights.
- Your ssh: the provider made that rule. **Keep it, and keep it key-only** (section 8).

## 3. What the server refuses to do for a device that is let in

A device that has the key can reach the public internet through the server. It cannot reach:

| Refused | Why |
|---|---|
| Private and reserved addresses (`10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, multicast and reserved ranges, Azure's control address; for IPv6 the NAT64 prefix, `fc00::/7`, `fe80::/10`, `ff00::/8`) | Your cloud's inside network and the **instance metadata service** (`169.254.169.254`), which can hold secrets. Without this a leaked key is a way into your cloud account. |
| The server itself: its own addresses (its public one too) and every service on them | Otherwise a device could reach, through the server, services your provider's firewall keeps closed. From the tunnel, only the measurement origin and a ping are answered; not ssh, not the other services, not the three public doors. |
| Port 25 (mail sent directly to other servers) | The way spam starts. Providers ban an address for it quickly. |
| Anything but TCP, UDP and ping (IP-in-IP, GRE and the like) | A known way to have a server's address reported for reflected attacks. |
| More than 30 new connections a second to one address, or 60 a second overall after a burst of 300 | A flood from a stolen device is the other way an address gets banned. Ordinary browsing never gets near it. **This slows a scan to a crawl; it does not make one impossible**, because that would break normal use. |

Two paths carry traffic out of the server, and both are covered: the AmneziaWG tunnel (the kernel forwards it, so the
rules are on the forwarding path) and the session (the carrier account makes the connections, so the rules are on that
account's outgoing traffic). That account may still reach: the replies to what came in (a client may sit on a private
address, a neighbour in your cloud's network for example), the session's port and the origin on this machine and
nothing else on it, and the name servers the machine itself uses. Port 53 is **not** open to anywhere, because that
would have skipped the caps and the refusals.

Every stranger's visit to the REALITY door that does not hold the key makes the server call the cover site once, as the
same account whose exits are capped. So one address can start only a few connections a second to that door (5 a second
after a burst of 20; a device keeps one connection there), and the calls to any one address are limited too, before the
overall cap. **A flood from many addresses at once can still use up the shared cap.** That is a limit of this design, and
it is not claimed to be prevented.

All of it is added **after** the three doors and the forwarding, one rule at a time:

- A rule the kernel does not support is skipped with a note instead of stopping the server, except a refusal: where the
  kernel has no REJECT it becomes a DROP, because a skipped refusal would be a hole.
- But the three jumps that carry the protection (for what the tunnel forwards, for what it asks of the server, and for
  the carriers' account) are checked afterwards, and **the server does not start without them**: a server that looks
  protected and is not is worse than one that does not start. The IPv6 one is required only if the machine can reach
  anything over IPv6, so a server with no IPv6 is not refused because its kernel has no IPv6 filtering.
- The firewall tool is installed if it is missing (without it nothing here would exist), and the script waits for the
  firewall's lock, for every rule including the three doors, when another tool holds it.
- A packet that claims one of the tunnel's addresses but did not arrive through the tunnel (a neighbour on the
  provider's network, writing a source it made up) is dropped.
- Running the script again changes nothing. A changed firewall script or changed service files are applied to a server
  that is already running (the firewall unit is restarted, which restarts the tunnel programs that need it), and the
  setup waits for every service to be running before it prints its report, naming the first that is not.

## 4. Why your server's address should not get banned

What gets a free server's address banned, and what stands in the way:

| Cause | What stands in the way |
|---|---|
| Spam sent from it | Port 25 refused on both exit paths. |
| Scans and floods from it | The caps above; only your own devices have keys. A slow scan is slowed, not stopped. |
| A stranger using it as a proxy | Not possible without a device key (section 2). |
| Reaching into the provider's network | Private, metadata and the server's own addresses refused (section 3). |
| Reflected attacks | Only TCP, UDP and ping leave; and a device's source address is pinned to its own, so it cannot pretend to be someone else. |
| The server being taken over | Security updates install themselves; the carriers and the origin run as an account with no rights; the script **warns** if ssh takes passwords. |
| Copyright complaints from file sharing | **Nothing technical stops this.** It is your traffic. Do not share a device key with anyone, and do not use the server for it. |

If a provider still bans an address, that is the provider's rule and not something a firewall can promise.

## 5. Who can reach what (summary)

```
internet ──▶ UDP 51820 ──▶ AmneziaWG ──(your key)──▶ tunnel ──▶ public internet only
internet ──▶ UDP 44443 ──▶ Hysteria 2 ─┐
internet ──▶ TCP 8443  ──▶ REALITY ────┴─(password + device key)──▶ session ──▶ public internet only
everything else ─────────────────────────────────▶ as your provider and image left it (ssh, key-only)
```

## 6. Your own computer

- **No listening door.** Every socket the program opens for itself is on `127.0.0.1`: the short-lived test proxy used to
  measure a connection method (a random user name and password every time) and the control channel of the tunnel
  software (a 256-bit random secret, and only one named website origin, which cannot exist, is accepted).
- **The service's control channel is a Windows named pipe, not a network port.** Network access to it is refused (the
  library's default, checked in the version we use), only signed-in users can open it, and what a user may ask for is
  decided by who they are: changes that send traffic somewhere new wait for an administrator's approval.
- **The program does not change Windows Defender Firewall.** Nothing it runs needs a firewall prompt.
- **The kill switch** (Windows blocking everything except the tunnel, the carrier and the few things a network needs)
  is modelled and tested as data (`dnet_core::guard`) and approved with conditions (ADR-0006 section 5a). The part that
  applies it to Windows is **not built**, and it will be tried only in a virtual machine first, never on your computer.
  The model already refuses the mistakes that would make it leak: a program permit without its account, a range that is
  not local, a path on a network share, and a list that differs from what was planned.

## 7. What was tested, and what was not

Tested (2026-11-05), with real `iptables` in a throwaway Linux container (`testing/server-firewall`, entry 8.7 in
`LOCAL-COMMANDS.md`): 64 checks on the nftables-backed iptables, and 56 on the older kind (`-Mode legacy`; the kernel
used has no IPv6 filtering for that kind, so its IPv6 checks are skipped and said to be). First the control: with no
script, a tunnel device reaches private hosts, mail, the server's ssh by the tunnel and by its public address, the
carriers' account reaches the private network (on any port, port 53 included), mail and the server's own addresses, a
GRE tunnel gets through, and floods all get through (1,500 connections, and 300 at the REALITY door), so each check can
fail. Then the script behind a firewall that rejects forwarding and everything but ssh, as a cloud image does:

- the three doors stay reachable and another port does not; the session's own port is dropped from outside;
- a device reaches the public internet (and can ping), but not the private network, a mail port, the server's ssh (by
  the tunnel or by its public address) or the public doors from inside; GRE is dropped; it can reach the measurement
  origin and ping the tunnel address;
- the carriers' account reaches public hosts (IPv4 and IPv6), the origin on its own machine and the one resolver the
  machine uses, but not the private networks (port 53 included), a mail port, the server's own public addresses or any
  other loopback port; other accounts on the server are not affected;
- a burst of 1,500 new connections lets 300 through when spread over many addresses and 60 when aimed at one, on both
  exit paths and for IPv6; 300 at the REALITY door from one address let 20 through; a normal connection (and an ordinary
  visitor at the door) works right after;
- running the script a second time changes nothing;
- on a kernel that cannot do everything (simulated by a copy of iptables that fails for one module): without the owner
  match the script **refuses to start** and says why; without REJECT every refusal is a drop and the private network is
  still refused; without the limit modules the caps are missing but ordinary traffic still works and the private network
  is still refused.

**Found and fixed while checking:**

- An independent review of the first version found that the tunnel's exit could reach the server itself, that port 53
  bypassed the caps, that IPv6 had no cap, that one stranger could drain the shared cap, that IP-in-IP and GRE were
  forwarded, that a refusal the kernel could not install failed open, that rule changes never reached a running server,
  and that the session's port was not actually closed to the network as this page first claimed. A second review of the
  fixes found more: with no iptables installed none of it existed and nothing said so, a changed service file waited for
  the next reboot, the lock wait did not cover the three doors, a neighbour on the provider's network could write a
  tunnel address as its source, one stranger could still starve the exit through the REALITY door, and the stub resolver
  of a systemd machine was refused if the resolver file changed after the start. All are fixed above.
- **A bug unrelated to the firewall.** The script ran under `umask 077`, so `/opt/dnet` and `/opt/dnet/bin` were
  root-only and the core, which runs as an unprivileged account, could not start its own program: on a fresh server
  the setup would have stopped before printing its report. Fixed (the program directories are made readable and
  walkable; nothing secret lives there). It had never been seen because no real server run has happened yet.

**Not tested, so not claimed:**

- A real Oracle (or any real cloud) server, and the systemd units (the container has no systemd): the sandbox
  settings of the origin and the tunnel program, the restart of the firewall unit and the wait for every service are
  checked as text only.
- IPv6 on the older kind of iptables (the kernel used has no support for it), and the DROP fallback, the lock wait and
  a real reboot on a real image.
- A flood at the REALITY door from many addresses at once (only one address was tried).
- How a scanner sees the three doors. "Nothing answers" is how the software is designed to behave; it was not measured.
- Whether the core's own `ip_is_private` refusal covers every range in the list (the kernel rules do, and were tested).
- Whether the REALITY cover site you choose keeps behaving like a normal website.
- The AmneziaWG program still runs as root, because it makes a network device; it has only the lighter sandbox settings.
  Narrowing it further (capabilities, a read-only system) needs a real systemd to try.
- Running the firewall script **by hand** while tunnels are up: the rules are rebuilt chain by chain, and for a moment
  one chain is empty (closed on an image that rejects forwarding, unfiltered on an open one). Through the setup script
  the tunnels are stopped while that happens.
- The two permits that are not narrowed by address on the client's future kill switch (the IPv4 address request and
  IPv6 neighbour discovery), which the lab checks are meant to measure.
- A provider changing its own firewall or abuse rules.

## 8. What you can do yourself to be safer

1. **Keep ssh key-only.** The script warns if the server allows password logins; turn them off
   (`PasswordAuthentication no` in `/etc/ssh/sshd_config`, then restart ssh) and keep the key file private.
2. **Do not open any other port** on the provider's firewall, and do not turn on IPv6 for the server (the program's
   servers are IPv4).
3. **Share a device key with nobody.** To drop a device, set the server up again without its key.
4. **If you can, limit ssh to your own address** in the provider's firewall (not possible if your address changes).
5. **Do not use the server for file sharing or for anything the provider forbids.** No firewall can prevent that.
