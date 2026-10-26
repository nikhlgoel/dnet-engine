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
| **TB6** | Client ⇄ profile update feed | Signed feed; design accepted (ADR-0002, O5 closed 2026-09-12); **ingestion not yet wired — T066a–d** |

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
| T1.6 | Elevation | Code running as the console user itself (malware in the user's session, a compromised browser) calls a mutating request: connects, or adds its own endpoint and connects, and so sends the machine's traffic to a server it chose | **Accepted.** The console user is the product's owner and its authority: mutation is allowed to the interactive console user and no one else (T1.1), and adding an endpoint is the feature (FR-010). A request that needs the user's own token cannot be told apart from the user, and the unprivileged tray (no elevation prompt per action) is a design decision. Other users, services and other sessions are kept out by T1.1; this is about code that already is the user | Accepted (see §4) |
| T1.7 | Elevation | Text from outside (a Wi-Fi name, a service reply) becomes markup or script in the window's web view and then calls the window's commands, which include connect and add-endpoint | Every string is drawn as text (a test forbids `{@html}`, `innerHTML`, `eval` and inline `style=`); it is cleaned of control, bidirectional and zero-width characters on **both** sides of the door (`dnet-view::text`, `sanitize.ts`); the page's CSP is `default-src 'self'` with no remote content, and was seen applied in the running window; the capability list is the 12 commands in `build.rs` plus event listen/unlisten, and the framework was seen refusing a window command and an unknown one; the web view never touches the pipe (ADR-0007 R4). WebView2 will take a remote-debugging port from an environment variable, but only code that already runs as the user can set it (T1.6) | Low |
| T1.8 | Info disclosure | Endpoint credentials, typed or loaded from a file in the window, are kept or leaked | The file's text lives in the form only until it is submitted or the form is closed; it goes once over Tauri's in-process IPC to `dnet-view`, which checks it with the service's own rules and sends it in one request; no output of `dnet-view` ever contains it (a test with a known secret asserts this); the window stores only two keys in the web view's storage (`dnet.prefs.v1`: theme and motion; `dnet.acceptable-use.v1`: the time and the text shown) | Low |
| T1.9 | Spoofing | Another program creates a pipe with the service's name so the tray talks to it, shows it a person's credentials or shows the person what it says | `PipeLink::service()` uses `Trust::ServiceOwnedOnly`: the pipe's owner must be SYSTEM or Administrators, or the client refuses and says whose pipe it is; `--allow-unprivileged-service` lifts this for a development run and says so | Low (the flag, if used, removes it) |

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
| T6.1 | Tampering | Malicious feed pushes parameters that weaken obfuscation, or routing that exfiltrates traffic | Signed feed per ADR-0002: Ed25519 in DSSE envelopes, 2-of-3 offline root keys delegating short-lived signing keys, and rollback, freeze and equivocation defences. The closed schema carries parameters only, so a compromised signing key can weaken obfuscation but cannot add routing, DNS, endpoint or credential changes. Parameters the endpoint must also know are staged for re-provisioning, never applied alone | Low once T066a–d and the root key ceremony land. **BLOCKING until then: the feed must not ship** |

**T6.1 was the most dangerous threat in the system, and its design is now closed.** A feed able to
change routing rules would be equivalent to remote code execution for traffic, so ADR-0002 gives the
feed no way to carry them. The feature still does not ship until fetching, persistence and the root
key ceremony (T066a–d) exist.

---

## 4. Out of scope

Compromised local machine · malicious Administrator · physical access · cloud provider compromise ·
targeted cryptanalysis of the underlying transports · consequences of acceptable-use violations ·
**code already running as the interactive console user** (T1.6): it holds the same authority as the person
at the keyboard, so the product does not try to tell it from them. If this is ever to change, the change is
a per-action elevation prompt for `AddEndpoint`, `ImportFeed` and `SetEncryptedDnsHandling`, which is a
decision about the tray's design, not a patch.

---

## 5. Review cadence

Re-examine on: any change to TB1 or TB2, closing O5, adding a transport profile, adding a cloud
provider, and before v1 release.
