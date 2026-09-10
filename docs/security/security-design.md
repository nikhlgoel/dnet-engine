# Security Design

**Governed by**: Constitution Principle V (least privilege by construction) and VI (honest claims)

DNet Engine is privileged software that rewrites system routing and DNS on the user's machine. That
makes its own attack surface a first-class concern, independent of the network threats it exists to
address.

---

## 1. Privilege model

Exactly one component may mutate system state.

| Component | Privilege | May alter routing/DNS/adapters |
|---|---|---|
| `dnetd` | LocalSystem (Windows Service) | **Yes — solely** |
| `dnet-tray` | User, unprivileged | No |
| Native-messaging stub (v2) | User, unprivileged, browser child | No |
| Supervised cores | Inherit `dnetd` | Only as `dnetd` configures them |

`dnetd` requires LocalSystem for two reasons: the AmneziaWG UAPI pipe is ACL-restricted to
Administrators, and route-table and DNS mutation require it. This is a deliberate, recorded
constraint, not an accident.

**Rule**: an unprivileged process able to rewrite system routing through any interface DNet Engine
exposes is a **CRITICAL** defect, treated as a vulnerability rather than a bug.

---

## 2. The IPC trust boundary

`\\.\pipe\DNetEngine\control` — 4-byte length prefix, UTF-8 JSON.

Four controls, layered:

1. **Explicit SDDL.** `GENERIC_READ | GENERIC_WRITE` for Authenticated Users; full control for SYSTEM
   and Administrators. Never a NULL DACL. A test asserts the SDDL matches exactly (IPC-02).
2. **Per-connection identity.** On accept, `dnetd` impersonates the client, captures the token,
   reverts immediately, and records the client SID and session ID.
3. **Console-session requirement for mutation.** Every mutating request is rejected unless the caller
   is the interactive console user. Read-only requests need only an authenticated caller.
4. **All input is hostile.** Paths, patterns, addresses, and identifiers are validated server-side.
   The tray is never trusted; nor is any future browser stub.

Rejection is always explicit (`Unauthorized { reason }`). **Silent no-ops are a defect** — they hide
authorization failures from both user and operator.

Verified by IPC-01, which attempts the escalation directly and asserts routing state is unchanged.
That is SC-019 proven by attack, not by inspection.

---

## 3. Secret handling

Recorded in full in [`credential-handling.md`](./credential-handling.md). The design rules:

- **Secrets are references in the domain, material only at the boundary.** `CredentialRef` exposes no
  accessor returning plaintext. Only `dnet-provision` and `dnet-config` resolve one.
- **Cloud credentials**: scoped, least-privilege, user-created, single-step revocable. Root or
  tenancy-wide credentials are **rejected at validation**, not merely discouraged.
- **At rest**: DPAPI user scope for cloud credentials; machine scope only for service-held material.
- **Never**: in logs, diagnostics, IPC messages, error text, telemetry, or the tree.
- **Server-side keys are generated server-side**; only public material returns to the client.
- **Deleted by default** once provisioning succeeds.

Verified by scanning every output for a sentinel value (PRV-02) and by asserting the diagnostic
bundle contains no credential material and no browsing destinations (IPC-07).

---

## 4. Supply chain

Third-party binaries execute with `dnetd`'s privilege. Their integrity is therefore a security
property, not a build convenience.

| Control | Mechanism |
|---|---|
| Pinning | Sources pinned by **commit SHA, not tag** — a tag can be moved |
| Verification | Fetched tree re-checked against the pin **before** building; mismatch fails loudly |
| Prebuilt integrity | Wintun DLL SHA-256 verified, Authenticode signature asserted |
| Provenance | `BUILD-PROVENANCE.md` records repo, version, commit, package, build tags |
| Attack-surface reduction | Minimal build tags exclude ~16 unused protocols from the primary core |
| No extraction | Wintun taken only from the official distribution, never from another product |

**Open item O5**: the transport-profile update feed can push routing changes, so it is a
supply-chain surface in its own right and **must be signed**. Blocks FR-007/FR-008.

---

## 5. What the product does not protect against

Stated because overstating protection is a defect under Principle VI, and because users make
decisions based on these claims.

| Not protected | Reality |
|---|---|
| **The existence of a tunnel** | Sustained high-entropy traffic to one unfamiliar address is visible to flow analytics even when unclassifiable. Obfuscation hides content and protocol, not volume or destination |
| **Traffic volume and timing** | Fully observable to the network operator |
| **Endpoint ownership** | The endpoint is yours; traffic exits from an address attributable to your cloud account |
| **A compromised local machine** | Anything with Administrator can read the configuration and subvert the service |
| **Acceptable-use consequences** | Technical evasion is not policy immunity. Disclosed at first run (FR-032) |
| **Application-rule accuracy** | Best-effort by construction; hard guarantees require domain or IP rules |

---

## 6. Secure-by-default posture

| Default | Rationale |
|---|---|
| BBR congestion control | Brutal degrades every other user on a shared access point |
| Encrypted DNS blocked | Destination rules must work; disclosed with one-click opt-out |
| Local networks bypassed | Printers and intranet stay reachable without user configuration |
| Diagnostics exclude destinations | Browsing history is not collected by default |
| Credential deleted after provisioning | Defaults to yes |
| Tier 1 profile preferred | Stronger failover chosen unless the user consents otherwise |
| No hardcoded endpoints or keys | Nothing shipped is a shared secret |

---

## 7. Review triggers

Security review is **mandatory** before any commit touching: the IPC boundary or its authorization,
privileged operations in `dnetd`, key or credential material, routing and DNS mutation, the undo and
restoration path, the profile update feed, or supervised-core configuration generation.
