# Credential and API Key Handling

Every secret the product touches, and the rule for each.

Contract: [`provisioning.md`](../../specs/001-network-resilience-client/contracts/provisioning.md)

---

## 1. Inventory

| Secret | Origin | Storage | Lifetime |
|---|---|---|---|
| Cloud API signing key | User creates it, guided by the wizard | DPAPI **user** scope | Deleted after provisioning by default |
| Endpoint private key (server) | Generated **on the server** | Server only, never transmitted | Life of the endpoint |
| Endpoint client key | Generated locally | DPAPI **machine** scope (service-held) | Life of the endpoint |
| AmneziaWG obfuscation params | Generated locally | With the profile, DPAPI machine scope | Life of the profile |
| REALITY key pair | Generated during bootstrap | Public to client, private on server | Life of the endpoint |

---

## 2. The core rule

> **Secrets are references in the domain, and material only at the boundary.**

`CredentialRef` is an opaque handle. It exposes **no accessor returning plaintext**. Only
`dnet-provision` and `dnet-config` resolve one, and neither returns plaintext to a caller. Every
other crate — including all of `dnet-core`, the IPC layer, and the UI — handles references alone.

This is enforced by type design, not by discipline. There is no method to call that would leak.

---

## 3. Cloud credential lifecycle

```
1. DISCLOSE      Wizard states which permissions it needs and how to revoke,
                 BEFORE requesting anything.
                 (Asking first and explaining later trains bad habits.)
2. GUIDE         Step-by-step creation of a dedicated, least-privilege IAM user.
3. VALIDATE      Root/tenancy-wide credentials are REJECTED, not merely discouraged.
                 Over-privileged scope produces a warning the user must acknowledge.
4. STORE         DPAPI user scope. Never machine scope: this is the user's credential,
                 not the service's.
5. USE           Provisioning only. Never at connect time.
6. DELETE        Offered on success, defaulting to YES.
7. REVOKE        One documented step, stated up front in step 1.
```

### Rejected outright

| Rejected | Why |
|---|---|
| Tenancy or account root credentials | Blast radius is the whole account |
| Credentials with write access beyond compute and networking | Exceeds what provisioning needs |
| Storing the credential in `dnetd`'s configuration | It is the user's credential, not the service's |
| Machine-scope DPAPI for cloud credentials | Would make it readable by any Administrator process |
| Any credential shipped with the product | Nothing shipped is a shared secret (FR-034) |

---

## 4. Exclusion surfaces

A secret must never appear in any of these. Each is verified, not assumed.

| Surface | Verification |
|---|---|
| Log output | Sentinel scan across all logs (PRV-02) |
| Diagnostic bundle | Asserted free of credential material **and** browsing destinations (IPC-07) |
| IPC messages | Protocol types carry references only |
| Error text | `ProvisioningError` never embeds credential material |
| Generated core configuration | ACL-restricted; only what the core requires at runtime |
| The repository | `.gitignore` covers `.env`, `*.pem`, `*.key`, `*.pfx`, `oci_api_key*` |
| Crash dumps | Secrets held in DPAPI-protected buffers, not long-lived plaintext |

**The sentinel test is the important one.** A known value is placed in a credential, provisioning is
exercised, and every output is scanned for it. Reviewing code for leaks catches what you thought of;
the sentinel catches what you did not.

---

## 5. AmneziaWG UAPI

Peer keys are written to `\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\dnet-awg0` as text
(path verified against the pinned core; earlier drafts said `WireGuard\awg0`), and
**never to disk or logs** (AW-05).

The pipe's ACL restricts it to Administrators, which `dnetd` satisfies as LocalSystem and the tray
does not — the OS reinforces the privilege split for free.

**Peer and obfuscation parameters are written in a single transaction** (AW-04). A peer configured
without obfuscation is a plain WireGuard handshake — precisely the signature the profile exists to
avoid — so a partial write is a security failure, not merely a configuration bug.

---

## 6. Key rotation and compromise

| Event | Response |
|---|---|
| Cloud credential suspected compromised | Revoke in the provider console (one step, documented at first use). No product action needed |
| Endpoint key compromised | Re-run bootstrap; keys regenerate server-side |
| Endpoint address blocklisted | Not a compromise — health rotation moves to another endpoint |
| A profile's obfuscation is fingerprinted | Not a key compromise — update the profile via the feed (blocked on O5) |

---

## 7. Verification checklist

Before any commit touching credential handling:

- [ ] No new path where plaintext leaves `dnet-provision` or `dnet-config`
- [ ] Sentinel test passes across logs, diagnostics, IPC, and error text
- [ ] DPAPI scope is correct: **user** for cloud credentials, machine for service-held material
- [ ] Root and over-privileged credentials still rejected or warned at validation
- [ ] Revocation instructions still shown **before** the credential is requested
- [ ] Deletion still defaults to yes on success
- [ ] `.gitignore` still covers any new secret file pattern
