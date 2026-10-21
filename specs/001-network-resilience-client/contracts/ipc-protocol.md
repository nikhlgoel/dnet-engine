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
| **Read-only** | `GetVersion`, `GetState`, `GetSession`, `ListEndpoints`, `ListProfiles`, `ListRules`, `GetDiagnostics` | Authenticated caller |
| **Mutating** | `Connect`, `Disconnect`, `AddEndpoint`, `RemoveEndpoint`, `SetEndpointEnabled`, `AddRule`, `RemoveRule`, `SetProfileParams`, `EnableBrutal`, `SetEncryptedDnsHandling`, `StartProvisioning`, `CancelProvisioning` | Interactive console user |
| **Stream** | `Subscribe` | Authenticated caller |

---

## Core messages

### `GetVersion → ProtocolVersion` (T132)

The first thing a client asks. The service answers it itself, to any authenticated caller, without
consulting any state:

```jsonc
{ "protocol_version": 1, "min_protocol_version": 1, "service_version": "0.1.0" }
```

- `protocol_version` is the newest version the service speaks; `min_protocol_version` the oldest
  client it still serves. A client speaking `c` can talk to it when `min_protocol_version <= c <=
  protocol_version`; outside that range the client stops and tells the user which end to update.
- `protocol_version` goes up when a change would break an existing client (a request or field removed
  or changed in meaning, a rule an old client would trip over). Adding a request, or an optional field
  a client may ignore, does not change it. `service_version` is for people, never for deciding.
- Both numbers are integers from 1; `service_version` is at most 64 characters of letters, digits and
  `. - + _`. A client treats the reply as untrusted input and refuses anything else.
- A service that answers `GetVersion` with `InvalidRequest` predates this request; a client treats
  it as incompatible rather than assuming it is fine.
- This is the same idea as Docker's engine API version negotiation: the engine and the programs that
  drive it are updated separately, and must be able to tell whether they still understand each other.

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

> **Implemented shape (T125, 2026-10-20).** `carrying_path` and `standby_paths` are **absent** until
> Phase 7 can produce them; an empty list would claim there is no standby path. `routing_posture`
> is added: `{"posture":"Tunnelled","tier":"Tier1"}` or `{"posture":"FailClosed"}`. It is the posture
> the engine **decided**, not proof that the OS enforces it. `failure` also carries `title`, `detail`
> and `action`. `active_profile` and `active_endpoint` are set only while `Connected`.
> A snapshot that contradicts itself (connected with nothing active, failed with no cause, tunnelled
> while not connected, a posture tier that differs from the profile's) is refused by the encoder and
> by the decoder.

**Contract requirements**
- `tier` is **always** present on an active profile. The UI must be able to show it without a second
  request (FR-016b).
- `failure.cause` is one of the seven distinguishable `FailureCause` variants. `"Unknown"` is not a
  permitted value (FR-039, SC-020).
- `warnings` surfaces every state the user consented to but should not forget.

### `Connect { endpoint: Option<EndpointId>, profile: Option<ProfileId> } → Accepted`

Both fields `null` means "choose for me" — the single-control path (FR-036).

- `profile` is 1 to 64 of `a-z`, `0-9`, `-`, not starting or ending with `-`. `endpoint` is a UUID
  in hyphenated form. `acknowledge_tier2` must be a boolean if present. Anything else is
  `InvalidRequest`; a malformed selector is never ignored. A named `profile` is tried alone and no
  other is substituted. A named `endpoint` is validated but the engine cannot yet honour one, so the
  daemon answers `InvalidRequest` saying so rather than connecting elsewhere.
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

**Stream behaviour (T125).**
- The reply to `Subscribe` is `{"subscribed":true,"backlog":N}`, then the `N` events of the current
  session that are still held (at most 256, oldest dropped), then live events with no gap and no repeat.
- Each event carries `seq`, a number that never repeats within one run of the daemon. A gap in `seq`
  is how a client sees that events were missed.
- A client that reads too slowly receives `{"event":"EventsLost","missed":N,"because":"..."}` in place
  of what it missed, and the stream continues.
- The connection is **one-way** after `Subscribe`. Any further byte from the client is answered with
  `InvalidRequest` and the connection is closed. Open a second connection to send requests.
- At most 16 subscriptions exist at once; the 17th gets `ServiceBusy` (retryable). A subscriber that
  does not accept a write within 10 s is dropped. Closing the connection frees the slot (IPC-09).
- 64-bit interface ids (`PathChanged.from`/`to`) are decimal strings.

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
| IPC-10 | `Connect` selectors are validated server-side and every request round-trips. |
| IPC-11 | A `StateSnapshot` round-trips; an inconsistent one cannot be encoded or decoded. |
| IPC-12 | Every `ConnectionEvent` encodes with a `because` that explains it; a producer that supplies none is an error, not a blank. |
| IPC-13 | The event bus replays the session, bounds its memory, numbers events and caps subscribers. |
| IPC-14 | A subscription is one-way, bounded and ends when the client goes; verified over a real pipe in `pipe_stream.rs`. |
| IPC-15 | `GetVersion` is answered by the dispatch itself for any authenticated caller, never reaches the service, and tells an unauthenticated caller nothing; the reply has exactly the contracted keys; a client refuses a reply that is malformed, out of range, or from a service that predates the request. |
