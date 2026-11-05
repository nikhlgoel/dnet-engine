# Contributing to DNet Engine

Thank you for looking. This is a small, free, GPL-3.0-or-later project. Bug reports, test reports from
networks you are allowed to test on, documentation fixes and code are all welcome.

Please read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first, and
[`SECURITY.md`](SECURITY.md) if what you found is a security problem (do not open a public issue for it).

## What the project is, and is not

DNet Engine keeps a connection to **a server the user runs** going when the network changes. It is not a
bypass tool, ships no server, and does not promise to get past any block. Changes that turn it into one
(for example built-in servers, shared keys, or wording that sells evasion) will not be accepted. The
binding principles are in [`.specify/memory/constitution.md`](.specify/memory/constitution.md).

## Where to start

Read these in order; when they disagree, the earlier one wins:

1. [`.specify/memory/constitution.md`](.specify/memory/constitution.md): principles and licence duties.
2. [`docs/Research-Critique.md`](docs/Research-Critique.md): decisions D1 to D10 and open items.
3. [`specs/001-network-resilience-client/tasks.md`](specs/001-network-resilience-client/tasks.md): the
   dated list of work, with notes on what is done and what is open.
4. [`docs/adr/`](docs/adr/): decisions that amend the above.

Work starts from a task in `tasks.md`. If you want to change something that is not there, open an issue
first so we can agree on it before you spend time on it.

## Setting up

You need Rust 1.88 or newer (the minimum supported version, checked in CI). The service is
Windows-only at run time, but most crates build and test on Linux and macOS too, and a change must not
break that.

The window (`apps/dnet-tray`) also needs Node 22 or newer and pnpm.

## Before you open a pull request

Run what CI runs, from the repository root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p xtask -- verify-vendor
cargo run -p xtask -- lint-branding
```

If you touched the window:

```bash
cd apps/dnet-tray
pnpm install --frozen-lockfile && pnpm check && pnpm test && pnpm build
```

Tests marked `#[ignore]` touch the real routing table or named pipes and need an elevated shell. They
are not run in CI; say in your pull request if you ran them.

## Rules that are easy to break

- **Test first, and read the whole output.** A change starts with a test that fails for the right reason.
  Say what you ran and what it showed; "should work" is not a result.
- **Never test against a network you do not own or are not allowed to test on.** The simulated harness
  under `testing/harness` is the target for network-path tests.
- **Fail closed.** There is no direct-fallback routing state, and none may be added.
- **Tier comes from measurement.** A profile is only called dependable after a recorded measurement says so.
- **Do not name the primary transport core, WireGuard or Wintun in any user-visible text** (UI strings,
  installer manifests, the website). In code the core is `primary_core`. `lint-branding` enforces this.
- **Wintun is the vendor-signed prebuilt DLL only,** as a separate file. No Wintun source, no copy inside
  another executable, and no kernel driver without an ADR.
- **No hardcoded endpoints, keys or institution-specific tuning,** and no project-run shared servers.
- **`dnet-core` does no I/O.** Put operating-system effects behind a trait in the crate that owns them and
  test the order of operations against a fake.
- **Secrets** use `dnet_config::secret::Secret`, which is redacted from `Debug`, `Display` and errors.
- **The window never talks to the control pipe.** `dnet-view` is its only door; colours, sizes and
  durations come from `docs/design/tokens.css`, with no `{@html}` and no inline styles.
- **A security review is required** for any change to the IPC boundary, privileged operations, key or
  credential handling, routing or DNS changes, the undo path, the profile feed or core configuration
  generation. Say in the pull request what you checked.
- A change that departs from a mandated technology, a deferral boundary or a non-negotiable principle
  needs an ADR in `docs/adr/`.

## Commits and pull requests

- Use conventional-commit subjects (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`) that say precisely
  what the commit changes, and name the task from `tasks.md` when there is one, for example
  `fix(ipc): refuse an oversized frame (T123)`.
- Prefer one commit per finished piece of work, with its code, tests and task note together.
- Keep a pull request to one subject. Pull requests are squash-merged.
- Update the task's note in `tasks.md` and any contract or ADR your change affects, in the same pull request.

## Licence

By contributing you agree that your work is released under GPL-3.0-or-later, the licence of the project.
Do not add code or files you do not have the right to publish under it; third-party components and
their obligations are listed in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
