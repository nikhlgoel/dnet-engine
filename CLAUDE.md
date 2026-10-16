# DNet Engine

Network resilience client, GPLv3. v1 is Windows today; ADR-0005 proposes Linux as a second v1
platform and is **not approved yet** (decisions L1–L6), so the constitution still says Windows-only.
Keep new code portable where it costs nothing: it must build and lint cleanly on Linux hosts.
`dnetd` is a privileged Rust service that supervises two third-party transport processes; it
implements no transport of its own. The tray UI (`dnet-tray`) does not exist yet. The release name for
the finished product is not decided here.

## Read these first, in this order

1. `.specify/memory/constitution.md` — binding principles and licence obligations (v1.3.0)
2. `docs/Research-Critique.md` — decisions D1–D10, findings, open items. Supersedes the research blueprints
3. `specs/001-network-resilience-client/tasks.md` — **current delivery status**; each task carries its own dated notes
4. `docs/adr/` — decisions that amend the above

When documents disagree, that order wins (`docs/README.md`). `docs/DNet-Engine-Research.md` is unverified
context, not truth. `.claudeignore` keeps `docs/`, `target/` and `Cargo.lock` out of automatic loading;
they are all readable on demand.

## Commands (what CI runs)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p xtask -- verify-vendor    # no Wintun source, no embedded executables, signed DLL
cargo run -p xtask -- lint-branding    # confines the primary core's vendor name to attribution files
cargo run -p xtask -- fetch-vendor     # builds the pinned cores from source; needs Go
```

`cargo xtask <task>` works too: `.cargo/config.toml` aliases it to the form above.

To see profile selection under hostile conditions (needs the Docker harness up, no elevation):

```bash
powershell -File testing/harness/Invoke-Race.ps1      # six scenarios; exit 0 only if all match
cargo run -p dnet-probe --example race                # one race, with each profile's measurement
```

- Tests marked `#[ignore]` touch the real routing table or pipes and need an **elevated** shell:
  `cargo test -- --ignored`. They are not run in CI.
- Network-path tests run only in the Docker harness (`testing/harness/harness.ps1`: `status`, `apply <ID>`,
  `clear`, `report`, `verify`). A harness result that cannot fail proves nothing: keep the negative controls.
- `dnetd` refuses to run off Windows. `dnet-core` does no I/O and is testable anywhere; several other
  crates contain Windows-only modules. The owner also develops on Fedora, so a change must not break
  the Linux build (`cargo clippy --workspace --all-targets -- -D warnings` on Linux).

## Rules that are easy to break

- **Test first, then read the whole output.** Say what ran and what it showed. Do not report "should work".
- **Never commit without explicit permission.** Conventional-commit messages, precise to that commit, with no
  `Co-Authored-By` trailer and no sign of AI involvement.
- **Never test against a live institutional network.** The simulated harness is the only target.
- **Do not name the primary core, WireGuard or Wintun in any UI string, installer manifest or marketing
  text.** In code it is `primary_core` / `PrimaryCore`. `lint-branding` enforces this.
- **Wintun is the vendor-signed prebuilt DLL only,** shipped as a separate file. No Wintun source, no
  copy embedded in another executable, and no kernel driver without an ADR.
- **Tier comes from measurement, never from the profile kind.** Only a recorded HV-07 result makes a
  profile Tier 1 (`dnet_core::tier::recorded_survival`). Today every profile is Tier 2.
- **Fail closed.** `RoutingPosture` has no direct-fallback variant. Do not add one.
- **Application rules are best-effort and typed that way.** `FailureCause` has seven variants and no `Unknown`.
- **Order is safety-critical in the loop-prevention path:** host route before tunnel, rewrite before rebind,
  reap before adapter, kill before undo. Every routing mutation registers its undo before it is applied.
- **Security review is mandatory** before any commit touching the IPC boundary, privileged operations,
  key or credential material, routing or DNS mutation, the undo path, the profile feed, or core config
  generation.
- **No hardcoded endpoints, keys or institution-specific tuning.** No project-operated shared infrastructure.
- A deviation from a mandated technology, a deferral boundary or a NON-NEGOTIABLE principle needs an ADR.
  Aggregation, download acceleration and extra platforms are separate specifications, not stretch goals.

## Code conventions

- `dnet-core` does no I/O and calls no Windows API. Put OS effects behind a trait in the crate that owns
  them (`dnet-netstate`, `dnet-supervisor`, `dnet-config`) and test the ordering against a fake.
- Doc comments name the task they implement (`//! T026 — ...`) and the contract or ADR section they follow.
- `thiserror` in libraries, `anyhow` in binaries. Warnings are denied in CI, not in source.
- MSRV is Rust 1.83: `ed25519-dalek` stays on 2.x for that reason. Check before bumping a dependency.
- Secrets use `dnet_config::secret::Secret`: redacted from `Debug`, `Display` and errors.

## Known gaps

- T055 (live routing-loop gate) was waived at risk and moved to T098a. Anything built on the AmneziaWG
  transport path is provisional until it passes (`docs/Research-Critique.md` §6.6).
- `dnet-etw` and `dnet-provision` are empty crates, and `Connect` returns "not available in this build".
  The decision logic (probe, selection, re-probe, migration, failure classification) exists in
  `dnet-core` and is exercised against the harness by `dnet-probe`, but `dnetd` does not call it yet.
- CI's coverage step covers `dnet-core`, `dnet-ipc`, `dnet-config` and `dnet-probe`. Its `harness` job
  is disabled, and no CI run has been inspected: `verify-vendor` needs vendored binaries that are
  not committed, so the licence job may need a `fetch-vendor` step.
- AmneziaWG cannot be probed through a proxy (it needs its own adapter), so profile racing covers
  Hysteria 2 and VLESS+REALITY only.
