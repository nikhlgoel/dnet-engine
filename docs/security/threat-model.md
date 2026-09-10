# Threat Model

Method: STRIDE against the trust boundaries in
[`system-architecture.md`](../architecture/system-architecture.md).

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Cloud API credential | Can create billable resources in the user's account |
| Endpoint private keys | Compromise means tunnel decryption or impersonation |
| System routing and DNS state | Mutation redirects **all** machine traffic |
| The IPC channel | The privilege boundary; the escalation path if broken |
| Supervised core binaries | Execute at LocalSystem |
| The profile update feed | Can push routing changes to every installation |
| Browsing destinations | Privacy-sensitive; excluded from diagnostics by default |

## 2. Trust boundaries

| # | Boundary | Crossing |
|---|---|---|
| **TB1** | Unprivileged UI ⇄ LocalSystem service | Named pipe |
| **TB2** | `dnetd` ⇄ supervised cores | Process spawn, config file, UAPI pipe |
| **TB3** | Client ⇄ endpoint | Obfuscated transport over a hostile network |
| **TB4** | Client ⇄ cloud provider API | HTTPS with a scoped credential |
| **TB5** | Build ⇄ upstream sources | Pinned fetch and verified build |
| **TB6** | Client ⇄ profile update feed | **Unresolved — open item O5** |

---

## 3. Threats

### TB1 — the privilege boundary

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T1.1 | Elevation | Unprivileged process rewrites routing via IPC | SDDL + per-connection identity + console-session requirement for mutation; IPC-01 attempts it directly | Low |
| T1.2 | Spoofing | Malware impersonates the tray | Token capture and SID check per connection | Low |
| T1.3 | Tampering | Malformed frames crash or corrupt the service | Length-prefix validation; oversized and truncated input rejected without panicking (IPC-08) | Low |
| T1.4 | DoS | Connection flooding starves the service | Bounded concurrent connections; no orphaned tasks (IPC-09) | Medium |
| T1.5 | Elevation | A future browser stub is hijacked by another extension | Extension ID pinned; stub is unprivileged and crosses TB1 like any client | Low |

### TB2 — supervised cores

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T2.1 | Tampering | Config file rewritten between generation and read | ACL restricted to SYSTEM and Administrators; regenerated on every change | Low |
| T2.2 | Elevation | A core vulnerability yields LocalSystem | Minimal build tags remove ~16 unused protocols; pinned versions | **Medium — accepted** |
| T2.3 | Info disclosure | Core stdout leaks keys into logs | Output parsed for health, never echoed raw | Low |
| T2.4 | DoS | Core crash-loops indefinitely | Backoff ceiling and attempt limit terminating in `CoreFailedPersistently` | Low |
| T2.5 | Tampering | **Peer configured without obfuscation parameters** | Both set in a single UAPI transaction (AW-04) | Low |

**T2.2 is the largest accepted residual risk.** The cores run at LocalSystem, so a remote-code
vulnerability in either is a full compromise. Mitigated by minimising the compiled surface and
pinning versions; not eliminated. This is the price of Principle I, and it is the right trade — the
alternative is our own unaudited crypto implementation with a far worse expected defect rate.

### TB3 — the hostile network

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T3.1 | Info disclosure | DPI classifies the tunnel and blocks it | Three independently-fingerprinted profiles, active probing, updatable profiles | Medium |
| T3.2 | Info disclosure | **Flow analytics infers a tunnel exists** | **None — explicitly out of scope** and disclosed (FR-033) | **Accepted** |
| T3.3 | Spoofing | Forged DNS answers | FakeIP; resolution happens at the endpoint | Low |
| T3.4 | Tampering | Endpoint address blocklisted | Multi-endpoint health rotation (v1 scope) | Low |
| T3.5 | Info disclosure | Browser encrypted DNS bypasses FakeIP | Known endpoints blocked by default, disclosed with opt-out | Low |
| T3.6 | Repudiation | Operator attributes traffic to the user | Inherent — the endpoint is the user's | **Accepted, disclosed** |

### TB4 — cloud provider

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T4.1 | Info disclosure | Credential stolen from disk | DPAPI user scope; deleted after provisioning by default | Low |
| T4.2 | Elevation | Over-privileged credential enables account takeover | Root credentials rejected at validation; over-privileged ones warned | Low |
| T4.3 | Info disclosure | Credential leaks into logs or diagnostics | Excluded by construction; sentinel scan asserts it (PRV-02) | Low |
| T4.4 | DoS | Provisioning leaks billable resources | Ledger written **before** each create call; idempotent cleanup | Low |

### TB5 — supply chain

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T5.1 | Tampering | Upstream tag moved to malicious code | Pinned by **commit SHA**; tree re-verified after fetch | Low |
| T5.2 | Tampering | Wintun DLL substituted | SHA-256 pin plus Authenticode assertion | Low |
| T5.3 | Tampering | Compromised build machine | Out of scope for v1; no reproducible-build guarantee yet | **Accepted** |
| T5.4 | Spoofing | Unsigned installer flagged, users trained to bypass warnings | Documented honestly; code signing deferred post-v1 | **Medium — accepted** |

### TB6 — profile update feed

| ID | STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|---|
| T6.1 | Tampering | Malicious feed pushes routing that exfiltrates traffic | **UNRESOLVED — open item O5.** Must be signed before FR-007/FR-008 ship | **BLOCKING** |

**T6.1 is the most dangerous unresolved threat in the system.** A feed able to change routing rules
is equivalent to remote code execution for traffic. The feature does not ship until O5 is closed.

---

## 4. Out of scope

Compromised local machine · malicious Administrator · physical access · cloud provider compromise ·
targeted cryptanalysis of the underlying transports · consequences of acceptable-use violations.

---

## 5. Review cadence

Re-examine on: any change to TB1 or TB2, closing O5, adding a transport profile, adding a cloud
provider, and before v1 release.
