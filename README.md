# DNet Engine

A self-hosted network resilience and tunnel client for Windows. **GPL-3.0-or-later.**

DNet Engine keeps a computer connected on networks that are unreliable, restrictive or both: a
campus network, a hostel, a café. It sends your traffic through a server **you** run, over whichever
of several connection methods works on the network you are on, and it keeps the connection going when
the network under it changes.

> **A free, open-source project** for anyone on a network that gets in the way. "DNet Engine" names
> the technology. The finished program may get a different name; that would change only what people
> see, not the engine's own names (the service, the pipe, the data folder), which stay
> ([ADR-0009](docs/adr/0009-product-identity-and-identifiers.md)).
> A one-page summary of what it does and does not do is at
> [nikhlgoel.github.io/dnet-engine](https://nikhlgoel.github.io/dnet-engine/) (source in [`site/`](site/)).

## What it is, and what it is not

It is a **tunnel client and a resilience layer**. It does not provide a server, a pool of servers, or
any account. There is no shared infrastructure and nothing in it is operated by this project: you
bring an endpoint (or, in a later version, let the program set one up in your own cloud account), and
the connection goes there.

It is **not** a firewall bypass, and it is not positioned as one. See [Using it responsibly](#using-it-responsibly).

## Read this before relying on it

These are the limits, stated plainly, because a tool that overstates what it does is worse than one
that does less.

- **It does not hide that you are using a tunnel.** The obfuscation it applies conceals the
  *content* of your traffic and the *protocol* it is carried in, so that it does not look like a known
  tunnel. It does **not** conceal traffic **volume** or **destination**: whoever operates the network
  you are on can still see how much you send and receive, and where the tunnel's packets go.
- **It does not make you anonymous.** Your traffic is encrypted between your computer and your own
  endpoint, and then it leaves that endpoint. The operator of the endpoint (you) and the operator of
  the network the endpoint sits on can see what any ordinary server operator sees.
- **The kill switch is a decision, not yet a guarantee.** The service decides that traffic must not
  leave unprotected (it has no "send it direct" fallback), but nothing at the operating-system level
  enforces that yet. Until it does, a crash or a stopped service is not a promise that nothing leaves
  the machine unprotected.
- **Per-application rules are best-effort.** Rules by destination name or address are reliable.
  Rules by application depend on identifying the program at the moment it connects, which can miss
  short-lived connections. They are labelled best-effort wherever they appear.
- **Failover has tiers, and the tier is measured, not assumed.** A *Tier 1* connection method should
  keep an open transfer alive when you switch networks; a *Tier 2* one will drop open connections
  (the next ones work). A method becomes Tier 1 only after a recorded measurement says it survives.
  Today every method is shown as Tier 2.

## Using it responsibly

Using a tunnel on a managed network (a school's, an employer's, a library's) may violate that
network's acceptable-use policy, and the consequences are yours. DNet Engine is for staying connected
and for protecting your traffic on networks you do not control; it is not a tool for evading
restrictions you have agreed to. Read the policy of the network you are on. The first-run flow of the
application repeats this and requires it to be acknowledged.

## Status

Early. The engine, a window, a guided server setup and a Windows installer exist and are tested; they have not yet run
together across a real network, and no release has been published. "Tested" below means tests, a simulated hostile
network and, where it says so, a clean Windows machine; it never means a live network.

| Part | State |
|---|---|
| Privileged service (`dnetd`): connects through three connection methods, supervises two transport processes, restores the machine's network settings on stop or after a crash | Working, exercised in a simulated hostile network and a Windows-host lab |
| Method selection by measurement, endpoint health, rotation, and recovery when a method is blocked | Working |
| Following the network as it changes, moving the connection to the best available network, and saying so honestly when it cannot | Working for one of the three methods; not yet proven on two real networks |
| Command-line client (`dnetctl`): connect, status, events, networks, counts; add, remove, enable and disable your own servers; choose how encrypted name lookups are handled; hand it a signed update from a file | Working |
| Destination rules, and blocking programs' own encrypted name lookups so those rules apply | Built and tested; not yet met a real network |
| Noticing a sign-in page in the way (a captive portal) and saying so rather than blaming the server | Built and tested against stand-ins; not yet met a real one |
| Signed updates to the connection methods | Built and tested; switched off until the publisher's keys exist; fetching is built but has not met the real hosts |
| Tray icon and window, drawn with its own title bar (status, servers, rules, activity, settings, first-run notice, about) | Built and tested (300+ tests, accessibility checks), and run against a real running service on one machine; not yet used on a real network or under a screen reader, and the icons are placeholders |
| Step-by-step server setup in the window: make a server on Oracle Cloud's free tier, or on any Ubuntu or Debian server, by following the steps; it never asks for a cloud password or key | Built and tested against the program's own stand-in; the wording of each provider's console is not verified against the live pages, and it has not been run against a real server |
| Setting up a server through a cloud provider's own programming interface | Built and tested against a stand-in provider only; no real provider is connected and nothing calls it |
| Rules by program | Designed and partly built; not connected to the service |
| Windows installer | Builds (about 15 MB), and was installed, checked and uninstalled on a clean Windows machine in the release build: the service runs as the system account, starts by itself and is restarted after a crash, ordinary users cannot change its folders, and the network is exactly as before after the uninstall. It has also been installed and run on a real Windows 11 computer. |
| Release signing | Releases are signed with the project's own key and attested; Windows does not trust that key, so it will say "unknown publisher". See [`docs/release-signing.md`](docs/release-signing.md) for what that does and does not give |
| Keeping traffic in the tunnel at the operating-system level (the kill switch) | Decided, not built; today it is the service's own decision and nothing in Windows enforces it |

[`specs/001-network-resilience-client/tasks.md`](specs/001-network-resilience-client/tasks.md) is the
authoritative, dated delivery status.

## How it works

```text
  tray and window            ─┐
  dnetctl                    ─┼──▶  control pipe  ──▶  dnetd  (privileged Windows service)
  anything else you build    ─┘     authenticated        ├─▶ connection method A (own process)
                                    versioned             ├─▶ connection method B (own process)
                                                          └─▶ adapter, routes, DNS (restored on exit)
```

- **One privileged component.** `dnetd` is the only part that may change routes, DNS or adapters. The
  user interface is unprivileged and talks to it over a named pipe that checks who is asking.
- **Separate processes, never linked.** The transport software runs as child processes that `dnetd`
  starts, watches, restarts and stops. `dnetd` implements no transport of its own.
- **A pure decision layer.** What to connect with, when to move, what to tell the user: all decided in
  `dnet-core`, which does no input or output and can be tested anywhere.
- **Every automatic change says why.** Each change of state carries a plain-language reason, shown to
  the user, so "why did it do that?" never needs a log.

## Building and testing

You need Rust (the minimum version is in `Cargo.toml`) and, to run the service, Windows.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p xtask -- lint-branding      # keeps vendor names to the attribution files
cargo run -p xtask -- verify-vendor      # checks the bundled third-party binaries
cargo run -p dnetctl -- status           # talk to a running service
```

The window needs Node 22 or later and pnpm; the shell around it is built with Cargo, after the page:

```bash
cd apps/dnet-tray
pnpm install --frozen-lockfile   # dependencies are held back 14 days and run no install scripts
pnpm check && pnpm test         # types, then the tests (including contrast, accessibility, and the contract with dnet-view)
pnpm build                      # builds the page and holds it to the size budget
cargo build --manifest-path src-tauri/Cargo.toml
```

Tests that touch the real routing table or pipes are marked `#[ignore]` and need an elevated shell
(`cargo test -- --ignored`). Tests of behaviour on a hostile network run only against the simulated
network in `testing/harness`, never against a live one. The cores are built from pinned source by
`cargo run -p xtask -- fetch-vendor` (needs Go); they are not committed.

The crates are small and each has one job:

| Crate | Job |
|---|---|
| `dnetd` | The service: lifecycle, orchestration, recovery |
| `dnet-core` | Pure decisions: selection, health, failover, rules |
| `dnet-ipc` | The control pipe: framing, protocol, authorization |
| `dnet-supervisor` | Child processes: start, watch, restart, stop |
| `dnet-config` | Writes the configuration each transport process needs |
| `dnet-netstate` | Interfaces, routes, change notification, undo records |
| `dnet-probe` | Measures how well each method works on the current network |
| `dnetctl` | The command-line client |
| `dnet-view` | What the window is told: replies turned into small checked view-models, and the commands it may give |
| `apps/dnet-tray` | The tray icon and the window: a native tray, and a Svelte page in a Tauri shell (not part of the Cargo workspace) |
| `xtask` | Build tooling |

## Documentation

- [`.specify/memory/constitution.md`](.specify/memory/constitution.md): the binding principles.
- [`docs/Research-Critique.md`](docs/Research-Critique.md): the decisions and their reasons.
- [`specs/001-network-resilience-client/`](specs/001-network-resilience-client/): the specification,
  plan, contracts and tasks.
- [`docs/adr/`](docs/adr/): decisions that amend the above.
- [`docs/design/`](docs/design/): the interface design system and a live preview.

## Security

The service is the privilege boundary and is treated as one: a caller is authenticated before anything
it asks is considered, programs it runs as SYSTEM must live in places ordinary users cannot change,
and everything read from the other end of the pipe is treated as untrusted input. If you find a
security problem, please report it privately to the maintainer rather than in a public issue.

## Licence

GPL-3.0-or-later. Third-party components, their licences and the obligations they carry are listed in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md); they run as separate programs beside this one.

## Contributing

Work is spec-driven and test-first: a change starts from a task in `tasks.md`, begins with a failing
test, and ends with the whole output of the test run read. Commit messages follow the conventional
format and say precisely what that commit changed.
