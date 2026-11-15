# Changelog

What changed, for someone who uses the program. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The day-by-day record of how each part was built and tested is
[`specs/001-network-resilience-client/tasks.md`](specs/001-network-resilience-client/tasks.md). This file is
the short version.

## [Unreleased]

**No release has been published.** Everything below is in the repository and tested there, in a simulated
hostile network, a Windows lab and, where it says so, a clean Windows machine. None of it has run on a real
network yet; the checks that need one are listed in [`docs/owner-gates.md`](docs/owner-gates.md), and a first
release waits for them.

### Added

- **The service (`dnetd`).** Connects through three connection methods, chooses between them by measuring,
  watches the server's health, recovers when a method is blocked, and puts the machine's routes and name
  servers back when it stops or after a crash. It has no "send it direct" fallback.
- **Following the network.** Moves the connection to another network when the one in use changes, and says
  why. Working for one of the three methods; not yet proven on two real networks.
- **The command line (`dnetctl`).** Status, connect and disconnect, events, networks, counts, every part of
  the connection with its state and reason, your own servers, rules, and signed updates from a file.
- **The tray icon and window.** Status, servers, rules, activity, settings, a first-run notice and an About
  page, with accessibility checks.
- **A guide that makes your own server** on Oracle Cloud's free tier or any Ubuntu or Debian server. It
  never asks for a cloud password or key.
- **Sharing a server.** A friend's device joins your server with a key of its own; no key is ever sent.
- **Destination rules**, and blocking programs' own encrypted name lookups so those rules apply to them.
- **Noticing a sign-in page** (a captive portal) in the way, and saying so instead of blaming the server.
- **An optional kill switch**, off by default: firewall rules that keep traffic inside the tunnel, survive a
  crash or a restart of the service, and can be taken out from the window, from `dnetctl guard-release`, or
  with `dnetd release-guard` when the service is not answering. Checked in a lab virtual machine only. One
  connection method (AmneziaWG) cannot be covered yet and is refused while the switch is on.
- **Changes that redirect traffic wait for your approval** in an elevated window: a new server, a rule that
  goes around the tunnel, an imported update.
- **Signed updates to the connection methods.** Built and tested; switched off until the publisher's keys
  exist.
- **A Windows installer**, signed with the project's own key (Windows shows "unknown publisher"), with a
  build attestation. About 15 MB.

- **A log file for the service**, in `%ProgramData%\DNet Engine\logs` (readable only by administrators and the system,
  about 4 MB at most). It records what the service did and why, and each request it refused. It holds no password or
  key, and never where you go on the network (the service does not know that).

### Changed

- **A new icon: the tunnel.** Arches receding to a doorway, polished from the concept you chose. It is the program's icon,
  the website's, the logo in the window, and the tray icon. The doorway shows the state by shape as well as colour: empty
  (not connected), filling and draining (finding a way through), lit (connected), half lit (slow), lit with a gap through
  it (failed), crossed (the service did not answer).
- **The window and the tray feel alive, and only when something is happening.** An opening that draws the tunnel in and
  opens it outward (skippable, and not made at all if you ask your computer for less motion); the logo and the tray icon
  breathe while the connection is being found, and are still otherwise; a ring leaves the core when the state changes;
  new words and new pages rise into place.

### Fixed

- **The service and `dnetctl` start on a Windows that has never had the Visual C++ runtime installed.** Built the
  default way they needed a library Windows does not include, so on such a computer the service would not have started.
  They now carry it, and the release build refuses a program that does not.
- **A server made by the setup guide now starts, and the program can connect to it over Hysteria 2 and REALITY.**
  Found by running the real setup script in a lab: the server's main service was not allowed to read the machine's
  routes and stopped at start, and the program waited for a log line that a quiet connection never prints, so only
  the AmneziaWG method could connect. Both are fixed.
- **Websites by name now load through a server made by the setup guide.** Found on the first real server: the
  connection carried only requests to numeric addresses, because the program had no way to turn a name into an address
  through the tunnel. It does now, and the server's firewall no longer blocks the machine's own name server.
- **The kill switch no longer opens for a moment when the connection's program restarts.** Found on the first real
  server by watching what leaves the network card: every time the connection's program stopped (a crash and its
  restart, say), the program took the kill switch out of the firewall with the tunnel, and for a second or so new
  connections went straight out of your network card until the restart put it back. The kill switch now stays in
  through restarts and failures, as it always claimed, and comes out only when you disconnect or turn it off.
- **Connections that were open before you connected no longer keep going out of your network card.** Found on the first
  real server: a connection already open (a kept-alive web page, say) kept reporting your own address through the
  connect, after the tunnel's program was stopped, and after the disconnect, and the kill switch could not stop it.
  The program now ends such IPv4 TCP connections when the tunnel comes up (sending nothing to the other end) and the
  program that held one reconnects through the tunnel. IPv6 TCP and connections that are not TCP are still not covered.
- `dnetctl endpoints` shows each server's id, which the commands that remove, enable and disable a server need.
- A new connection is no longer announced as "the network connection changed ... will not survive the move" when nothing
  had moved.

### Known limits

- The kill switch is not a guarantee: see above, and the [README](README.md#read-this-before-relying-on-it).
- Rules by program are best-effort and not connected to the service yet.
- Every method is treated as one that drops open transfers when the network changes, until a recorded
  measurement says otherwise.
- While connected, Windows still sends name lookups to the physical network's resolver as well as the tunnel's, so that
  network can see the names you look up; the kill switch does not stop this. See the README.
- IPv6 TCP connections and connections that are not TCP (QUIC, calls, games) that were open before you connected keep
  going out of your network card until they stop of their own accord.
- Networks that give only IPv6 are not supported.
- Windows 10 version 1809 or later, 64-bit (x64) only.

### Security

- Dependencies are checked for known vulnerabilities and for licences the project may combine with; the
  bundled network programs are built from pinned source and checked.
- To report a security problem, see [`SECURITY.md`](SECURITY.md).
