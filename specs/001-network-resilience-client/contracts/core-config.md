# Contract: Supervised Core Configuration

**Owner crate**: `dnet-config` (generation), `dnet-supervisor` (lifecycle)

`dnetd` generates configuration for two supervised processes and never patches, forks, or links
either. This contract fixes what is generated and what must be true of it.

**Naming obligation (binding).** The primary transport core is referred to in all code, configuration
keys, types, log messages, UI strings, and file paths as `primary_core` / `PrimaryCore` — never by its
vendor name. The vendor name appears only in `THIRD-PARTY-NOTICES.md` and the About screen.
`xtask lint-branding` enforces this in CI (see [plan.md](../plan.md) Constitution Check).

---

## 1. Primary core configuration

Generated as JSON to `%PROGRAMDATA%\DNet Engine\run\primary-core.json`, regenerated on every profile
or endpoint change, applied by restarting or by the core's runtime control API where available.

### 1.1 Required invariants

| # | Invariant | Why |
|---|---|---|
| CC-01 | TUN inbound is present for **every** profile, including AmneziaWG | Uniform FakeIP, rules, and attribution across profiles (R4) |
| CC-02 | `inet4_range = 198.18.0.0/15`, `inet6_range = fc00::/18` | R3; documented defaults |
| CC-03 | Hysteria 2 outbounds omit the `bandwidth` section unless Brutal is explicitly enabled | Yields BBR by default (R2, FR-006) |
| CC-04 | Enabling Brutal requires a recorded user acknowledgement and emits both `up` and `down` | Partial bandwidth config silently half-enables Brutal |
| CC-05 | A `Bypass`/direct rule for the **active endpoint address** is always present | Mirrors the R4 host route; divergence causes the routing loop |
| CC-06 | Built-in bypass rules for RFC1918, link-local, multicast, and captive-portal probe hosts are always present and non-removable | FR-024, FR-026, SC-018 |
| CC-07 | When Profile A is active, the active outbound is `direct` with `bind_interface` set to the AmneziaWG adapter | R4 |
| CC-08 | Generated config contains no credential material in cleartext beyond what the core requires at runtime, and the file's ACL restricts it to SYSTEM and Administrators | FR-035 |
| CC-09 | Generation is deterministic — identical domain state yields byte-identical output | Makes config a testable pure function |

### 1.2 Contract tests

| ID | Assertion |
|---|---|
| CFG-01 | Hysteria 2 profile with `brutal: None` produces config with **no** `bandwidth` key anywhere. |
| CFG-02 | Hysteria 2 profile with `brutal: Some(..)` produces both `up` and `down`, and fails generation if either is absent. |
| CFG-03 | Every generated config contains the endpoint bypass rule, for all three profiles. |
| CFG-04 | Profile A config sets `bind_interface` to the AmneziaWG adapter name and to nothing else. |
| CFG-05 | Built-in bypass rules are present and survive an attempt to remove them. |
| CFG-06 | Generation is deterministic across 100 runs of identical input. |
| CFG-07 | No generated artifact, log line, or error message contains the vendor name of the primary core. |

---

## 2. AmneziaWG core configuration

Configured at runtime over UAPI at
`\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\<adapter>` as text `key=value` lines (R5).

> **Corrected 2026-09-11.** Earlier text gave the leaf directory as `WireGuard\awg0`. The pinned
> core (`amneziawg-go` `b5928efb`, `ipc/uapi_windows.go`) listens under `AmneziaWG\`, with the
> adapter name as the leaf; `dnetd` uses the adapter `dnet-awg0`. A client built from the old
> path could never connect. Verified against source, and asserted by
> `dnet-config::uapi_pipe::tests::pipe_path_matches_the_pinned_core`.
>
> **Peer endpoints are IP literals.** On Windows the core resolves a hostname `endpoint` through
> the OS resolver; with the TUN up that returns a FakeIP address and the tunnel dials itself.
> `dnetd` resolves the endpoint before bring-up; the builder rejects hostnames.

### 2.1 Required invariants

| # | Invariant | Why |
|---|---|---|
| AW-01 | The adapter is created before the primary core's outbound is bound to it | Binding to a non-existent interface fails opaquely |
| AW-02 | The **endpoint host route via the physical gateway is installed before the tunnel starts** and removed after it stops | The R4 routing loop; this is the single most dangerous ordering in the system |
| AW-03 | On a carrying-path change, the host route is rewritten to the new gateway **before** the tunnel is told to rebind | A stale gateway route silently loops |
| AW-04 | Obfuscation parameters are set in the same UAPI transaction as the peer | A peer configured without obfuscation is a plain WireGuard handshake — exactly the signature we exist to avoid |
| AW-05 | Private key material is written to the pipe and never to disk or logs | FR-035 |

### 2.2 Contract tests

| ID | Assertion |
|---|---|
| AWG-01 | Starting Profile A with no gateway available fails cleanly with `NoUsablePath` and starts no tunnel. **Prevents the loop.** |
| AWG-02 | Host route exists before the tunnel process is spawned; asserted by ordering, not by timing. |
| AWG-03 | Host route is removed after tunnel stop, including after an abnormal stop. |
| AWG-04 | Simulated carrying-path change rewrites the host route before rebinding; asserted by call ordering. |
| AWG-05 | A peer is never configured without its obfuscation parameters in the same transaction. |
| AWG-06 | No private key appears in any log, diagnostic bundle, or on-disk file. |

---

## 3. Supervision contract

Applies to **both** cores (FR-030).

| # | Requirement |
|---|---|
| SUP-01 | Each core is spawned as a child with stdio captured; output is parsed for health, never echoed raw to the user |
| SUP-02 | Restart on unexpected exit with exponential backoff, jittered |
| SUP-03 | **Backoff has a ceiling and an attempt limit.** On exceeding it, supervision stops and reports `CoreFailedPersistently { core }` — it does not loop forever |
| SUP-04 | Both cores are terminated, and all routing/DNS mutations undone, when `dnetd` stops for any reason |
| SUP-05 | Orphaned cores from a previous crashed run are detected and killed at service start, before any new adapter is created |
| SUP-06 | A core that fails to become ready within a timeout is treated as failed, not awaited indefinitely |

### 3.1 Contract tests

| ID | Assertion |
|---|---|
| SUP-T1 | A core exiting repeatedly reaches `CoreFailedPersistently` within the attempt limit and stops being restarted. |
| SUP-T2 | Killing `dnetd` abruptly leaves no running core and no residual route or DNS change after service restart. **Verifies SC-016.** |
| SUP-T3 | Orphaned cores from a simulated prior crash are reaped at start. |
| SUP-T4 | A core that never signals ready is failed at the timeout, not awaited. |
