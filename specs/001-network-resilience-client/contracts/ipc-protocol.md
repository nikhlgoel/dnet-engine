# Contract: dnet-tray ⇄ dnetd IPC

**Transport**: Windows named pipe `\\.\pipe\DNetEngine\control`
**Framing**: 4-byte little-endian length prefix, then UTF-8 JSON
**Owner crate**: `dnet-ipc` (shared by both sides)

This contract is written before implementation and becomes the first failing test suite
(Constitution Principle IV).

---

## Authorization

The privilege boundary lives here. `dnet-tray` is unprivileged; `dnetd` is LocalSystem.

1. **Pipe ACL.** Created with an explicit SDDL granting `GENERIC_READ | GENERIC_WRITE` to
   `Authenticated Users` and full control to `SYSTEM` and `Administrators`. It is never created with
   a `NULL` DACL.
2. **Per-connection identity check.** On accept, `dnetd` calls `ImpersonateNamedPipeClient`, captures
   the client token, and reverts immediately. It records the client SID and session ID.
3. **Mutating operations require the interactive console user.** Any request in the *Mutating* class
   below is rejected unless the client's session ID equals the active console session and the client
   SID matches the logged-on user. Read-only requests need only an authenticated caller.
4. **No request is trusted for content.** All paths, patterns, addresses, and identifiers are
   validated server-side. The tray is treated as hostile input (Principle V).

**Rejection is explicit**: `Err(Unauthorized { reason })`. Silent no-ops are a defect.

---

## Request classes

| Class | Requests | Authorization |
|---|---|---|
| **Read-only** | `GetState`, `GetSession`, `ListEndpoints`, `ListProfiles`, `ListRules`, `GetDiagnostics` | Authenticated caller |
| **Mutating** | `Connect`, `Disconnect`, `AddEndpoint`, `RemoveEndpoint`, `SetEndpointEnabled`, `AddRule`, `RemoveRule`, `SetProfileParams`, `EnableBrutal`, `SetEncryptedDnsHandling`, `StartProvisioning`, `CancelProvisioning` | Interactive console user |
| **Stream** | `Subscribe` | Authenticated caller |

---

## Core messages

### `GetState → StateSnapshot`

```jsonc
{
  "status": "Disconnected | Probing | Connected | Failed",
  "active_profile":  { "id": "...", "kind": "AmneziaWg", "tier": "Tier1" } | null,
  "active_endpoint": { "id": "...", "label": "oracle-mumbai" } | null,
  "carrying_path":   { "kind": "Wifi", "quality": { "loss": 0.02, "rtt_ms": 43 } } | null,
  "standby_paths":   [ { "kind": "Cellular", "role": "Standby" } ],
  "failure":         { "cause": "AllProfilesBlocked", "detail": "..." } | null,
  "warnings":        [ "Tier2ProfileActive", "BrutalEnabled", "EncryptedDnsOverridden" ]
}
```

**Contract requirements**
- `tier` is **always** present on an active profile. The UI must be able to show it without a second
  request (FR-016b).
- `failure.cause` is one of the seven distinguishable `FailureCause` variants. `"Unknown"` is not a
  permitted value (FR-039, SC-020).
- `warnings` surfaces every state the user consented to but should not forget.

### `Connect { endpoint: Option<EndpointId>, profile: Option<ProfileId> } → Accepted`

Both fields `null` means "choose for me" — the single-control path (FR-036).

- If the selection resolves to a `Tier2` profile while a `Tier1` profile is viable, the server
  responds `Err(TierDowngradeRequiresConsent { profile, tier })`. The tray must re-issue with
  `acknowledge_tier2: true`. Consent is not inferable from the first request (FR-016b).
- Progress is delivered on the `Subscribe` stream, not as a blocking response.

### `Subscribe → stream<ConnectionEvent>`

Every event carries `because`. Event variants mirror `ConnectionEvent` in
[data-model.md](../data-model.md) §5.1.

```jsonc
{ "event": "ProfileSelected", "profile": "hy2-default",
  "because": "AmneziaWG probe timed out after 6s; Hysteria 2 carried 1.2 Mbit/s" }
```

**Contract requirement**: `because` is never empty and never restates the event name.

### `StartProvisioning { provider, region } → JobId`

Progress streams as `ProvisioningStage` transitions. See
[provisioning.md](./provisioning.md).

- `Err(CapacityUnavailable { region, alternatives: [{ region, added_rtt_ms }] })` is a **normal,
  retryable** outcome, not a failure (US2-2).

### `GetDiagnostics → DiagnosticBundle`

**Contract requirement**: the bundle MUST NOT contain credential material, and MUST NOT contain
browsing destinations unless the user has explicitly enabled destination logging for this session
(FR-035). A test asserts that a bundle produced after a session containing a known domain does not
contain that domain.

---

## Error model

```jsonc
{ "error": "Unauthorized" | "InvalidRequest" | "TierDowngradeRequiresConsent"
          | "CapacityUnavailable" | "NotConnected" | "ServiceBusy" | "InternalError",
  "detail": "human-readable, actionable",
  "retryable": true }
```

`InternalError` must still carry an actionable `detail`. A bare internal error reaching the UI is a
defect.

---

## Contract tests (written first)

| ID | Assertion |
|---|---|
| IPC-01 | Unprivileged non-console client issuing `Connect` receives `Unauthorized`; routing state is unchanged. **Directly verifies SC-019.** |
| IPC-02 | Pipe is never created with a NULL DACL; SDDL matches the specification exactly. |
| IPC-03 | Every `FailureCause` variant round-trips and is distinguishable; `"Unknown"` fails to deserialize. |
| IPC-04 | `Connect` resolving to Tier 2 while Tier 1 is viable returns `TierDowngradeRequiresConsent`. |
| IPC-05 | `StateSnapshot` with an active profile always includes a non-null `tier`. |
| IPC-06 | Every emitted `ConnectionEvent` has a non-empty `because` that differs from the event name. |
| IPC-07 | `DiagnosticBundle` contains no credential material and no browsing destinations by default. |
| IPC-08 | Malformed frames, oversized lengths, and truncated payloads are rejected without panicking or leaking the connection. |
| IPC-09 | A client disconnecting mid-request leaves no orphaned server task. |
