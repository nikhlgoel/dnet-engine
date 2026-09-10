# Quickstart: Validating DNet Engine v1

**Plan**: [plan.md](./plan.md) | **Contracts**: [contracts/](./contracts/)

How to build, run, and prove the feature works. Validation only — implementation detail belongs in
`tasks.md` and the implementation phase.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10 1809+ or Windows 11, x64/ARM64 | The only supported v1 platform |
| Rust 1.83+ with `x86_64-pc-windows-msvc` | `rustup default stable-msvc` |
| Node 20+ and pnpm | Tray application only |
| Docker Desktop with Linux containers | **Required** — the harness gates every network test |
| Administrator rights | `dnetd` installs as a Windows Service |
| A cloud account | Only for Phase 1 provisioning validation; everything else uses the mock endpoint |

`vendor/` binaries are fetched and signature-verified by `cargo xtask fetch-vendor`. Wintun is
obtained as the **vendor-signed prebuilt DLL only** — the build fails if any Wintun source is present
([research.md](./research.md) §R6).

---

## Build

```powershell
cargo xtask fetch-vendor      # fetch + verify pinned cores and signed Wintun DLL
cargo xtask verify-vendor     # assert signatures; reject vendored Wintun source
cargo xtask lint-branding     # assert the primary core's vendor name appears only in attribution files
cargo build --workspace --release
pnpm --dir apps/dnet-tray install && pnpm --dir apps/dnet-tray build
```

`verify-vendor` and `lint-branding` enforce the two binding licence obligations and run in CI. A
build that skips them is not shippable.

---

## Run the test suites

```powershell
cargo test --workspace                    # unit + contract tests (no network, no Docker)
cargo nextest run --profile integration   # requires the harness to be up
pnpm --dir apps/dnet-tray test            # tray unit tests
cargo llvm-cov --workspace --fail-under-lines 80
```

Coverage floor is 80% outside the UI and the supervised processes (Constitution Principle IV).

---

## Bring up the harness

```powershell
cd testing/harness
docker compose up -d
./harness.ps1 status                       # confirm all conditions available
./harness.ps1 apply H1                     # 150ms +/-50ms, 20% loss
./harness.ps1 apply H2                     # block all outbound UDP
./harness.ps1 clear
```

Conditions are toggleable at runtime, mid-session — required by HN-01, and what makes SC-004
measurable. See [contracts/harness.md](./contracts/harness.md).

---

## Validation scenarios

Each corresponds to an integration test and a success criterion. Run in this order; each phase's gate
must pass before the next is meaningful.

### Phase 0 — the harness can tell the difference

```powershell
./harness.ps1 apply H3                     # drop standard WireGuard signatures
cargo nextest run -E 'test(hv_03)'
```

**Expect**: the obfuscated profile connects **and** the deliberately unobfuscated control **fails**.
Both halves are required. A harness where everything passes proves nothing.

### Phase 2 — the privilege boundary holds

```powershell
cargo nextest run -E 'test(ipc_01)'
```

**Expect**: an unprivileged, non-console client issuing `Connect` receives `Unauthorized` and routing
state is unchanged. This is SC-019 verified by explicit attempt, not by inspection.

### Phase 3 — traffic flows, and does not loop

```powershell
./harness.ps1 apply H1
cargo nextest run -E 'test(hv_13)'         # SPIKE-R4 gate
```

**Expect**: traffic flows end-to-end on Profile A, and packet counts on the tunnel adapter versus the
physical interface show no re-entry. **Phase 3 does not pass without this** — the failure mode is a
silent routing loop presenting as a successful handshake with zero throughput
([research.md](./research.md) §R4).

### Phase 4 — recovery when the active profile is blocked

```powershell
cargo nextest run -E 'test(hv_04)'
```

**Expect**: with a profile blocked mid-session, traffic flows again within 30 seconds with no user
action (SC-004).

### Phase 5 — browser traffic routes correctly

```powershell
./harness.ps1 apply H5                     # DNS hijack
cargo nextest run -E 'test(hv_10)'
```

**Expect**: correct resolution and routing despite forged answers, **including for a browser using
encrypted DNS** — the case that silently defeats naive implementations (FR-025).

### Phase 6 — failover, honestly labelled

```powershell
cargo nextest run -E 'test(hv_07) + test(hv_08)'   # SPIKE-R9 gate
```

**Expect**: HV-07 — an open transfer survives an interface change on both Tier 1 profiles. HV-08 —
on the Tier 2 profile the connection breaks **and the UI said so beforehand**. A Tier 1 profile that
fails HV-07 is demoted to Tier 2 in configuration and UI; the label follows the measurement.

### Phase 7 — a stranger can use it

Manual, and the only scenario that is not automatable. Give a clean machine and a cloud account to
someone who has never provisioned a server. Time them, offer no help, and record where they stall.

**Expect**: a verified working endpoint in under 20 minutes, unaided (SC-009), and a working
connection without consulting documentation beyond the wizard (SC-010).

---

## Restoration check — run after any crash-path change

```powershell
cargo nextest run -E 'test(hv_14) + test(sup_t2)'
```

**Expect**: after killing `dnetd` mid-session, no core process survives, no route or DNS change
remains, and networking is identical to pre-installation (SC-016, FR-029). Recovery runs at service
**start** as well as shutdown — a crash leaves no one to run the shutdown path.

---

## Before opening a PR

- [ ] `cargo xtask verify-vendor` and `lint-branding` pass
- [ ] `cargo test --workspace` passes and the output was read, not skimmed (Principle IV)
- [ ] Integration tests for the touched phase pass inside the harness
- [ ] Coverage at or above 80% outside UI and supervised processes
- [ ] No test targets a live managed network (Principle III)
- [ ] Any new user-facing claim is measured, not asserted (Principle VI)
