# Contract: Endpoint Provisioning

**Owner crate**: `dnet-provision` | **Spec**: FR-009, FR-009a, FR-010 – FR-015 | **Research**: R10

The wizard creates an exit endpoint in the **user's own** cloud account. The project operates no
shared infrastructure (FR-015).

---

## 1. Credential contract

| # | Requirement |
|---|---|
| PR-01 | The wizard accepts **only** a scoped, least-privilege API signing key belonging to a dedicated IAM user it walks the user through creating. Tenancy or account root credentials are rejected by validation, not merely discouraged |
| PR-02 | The wizard states, **before** requesting the credential, exactly which permissions it needs and how to revoke the credential in one step |
| PR-03 | The credential is stored under DPAPI **user** scope, never machine scope, and never in the service's configuration |
| PR-04 | The credential never appears in logs, diagnostics, IPC messages, error text, or telemetry |
| PR-05 | On successful provisioning the wizard offers to delete the stored credential, defaulting to delete |
| PR-06 | Validation confirms the credential is scoped before use; an over-privileged credential produces a warning the user must acknowledge |

---

## 2. Stage machine

```
CredentialValidation ─▶ CapacityCheck ─▶ InstanceCreate ─▶ NetworkConfigure
     ─▶ ServerBootstrap ─▶ KeepaliveInstall ─▶ ReachabilityVerify ─▶ Done
```

Each transition emits a progress event on the IPC `Subscribe` stream.

| Stage | Must handle |
|---|---|
| `CredentialValidation` | Invalid, expired, revoked, or over-privileged credential — each distinguishable |
| `CapacityCheck` | **Free-tier compute capacity exhausted in the chosen region.** Returns `CapacityUnavailable` with alternative regions and their added RTT. This is a normal outcome, not an error dialog (US2-2) |
| `InstanceCreate` | Free-tier allowance already consumed by pre-existing resources |
| `NetworkConfigure` | Security list / firewall rules for the profile ports |
| `ServerBootstrap` | Install and configure both server-side transport cores; generate keys server-side where possible |
| `KeepaliveInstall` | **Install an idle-activity keepalive** so the provider does not reclaim the instance for inactivity (R10) |
| `ReachabilityVerify` | End-to-end reachability on at least one profile before an `Endpoint` is created |

---

## 3. Cleanup contract

| # | Requirement |
|---|---|
| PR-07 | Every created cloud resource is appended to `created_resources` **before** the create call is issued, never after |
| PR-08 | Cancellation at any stage attempts full cleanup of recorded resources |
| PR-09 | Resources that cannot be removed automatically are reported to the user with enough identifying detail to remove them manually (SC-011) |
| PR-10 | A job that fails after `KeepaliveInstall` but before `ReachabilityVerify` creates **no** `Endpoint` record |
| PR-11 | Cleanup is idempotent and safe to re-run |

---

## 4. Server bootstrap contract

| # | Requirement |
|---|---|
| PR-12 | The bootstrap installs both server-side cores, pinned to versions matching the client's bundled cores |
| PR-13 | Server-side private keys are generated **on the server**; only public material returns to the client where the protocol allows |
| PR-14 | The bootstrap is idempotent — re-running against an existing endpoint repairs rather than duplicates |
| PR-15 | The bootstrap records the endpoint's licence attribution obligations alongside the installed cores |
| PR-16 | Bootstrap failure leaves the instance in a state the cleanup path can remove |

---

## 5. Contract tests

Run against a **mocked provider API**; no test creates real cloud resources.

| ID | Assertion |
|---|---|
| PRV-01 | A tenancy-root credential is rejected at validation and never used for any call. |
| PRV-02 | Credential material appears in no log line, no diagnostic bundle, and no IPC message. Asserted by scanning all outputs for a known sentinel value. |
| PRV-03 | `CapacityUnavailable` is returned with at least one alternative region and its added RTT, and the job remains retryable. |
| PRV-04 | Simulated crash after each individual create call leaves a `created_resources` entry for that resource. Parameterised over every stage. |
| PRV-05 | Cancellation removes every recorded resource; anything unremovable is reported with identifying detail. |
| PRV-06 | Failure at `ReachabilityVerify` creates no `Endpoint`. |
| PRV-07 | Re-running bootstrap against a provisioned endpoint changes nothing and reports success. |
| PRV-08 | Cleanup run twice produces the same result and no error. |
| PRV-09 | A provisioned endpoint has a keepalive installed; absence fails the job. |
