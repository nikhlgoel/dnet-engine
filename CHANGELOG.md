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

### Fixed

- **The service and `dnetctl` start on a Windows that has never had the Visual C++ runtime installed.** Built the
  default way they needed a library Windows does not include, so on such a computer the service would not have started.
  They now carry it, and the release build refuses a program that does not.
- A new connection is no longer announced as "the network connection changed ... will not survive the move" when nothing
  had moved.

### Known limits

- The kill switch is not a guarantee: see above, and the [README](README.md#read-this-before-relying-on-it).
- Rules by program are best-effort and not connected to the service yet.
- Every method is treated as one that drops open transfers when the network changes, until a recorded
  measurement says otherwise.
- Networks that give only IPv6 are not supported.
- Windows 10 version 1809 or later, 64-bit (x64) only.

### Security

- Dependencies are checked for known vulnerabilities and for licences the project may combine with; the
  bundled network programs are built from pinned source and checked.
- To report a security problem, see [`SECURITY.md`](SECURITY.md).
