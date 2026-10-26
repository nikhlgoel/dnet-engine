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
| **Read-only** | `GetVersion`, `GetState`, `GetSession`, `GetPaths`, `GetStats`, `ListEndpoints`, `ListProfiles`, `ListRules`, `GetDiagnostics` | Authenticated caller |
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

### `GetPaths → PathsReply` and `GetStats → StatsReply` (T144)

Added so the interface can show the networks and the session without inventing anything. Both are
read-only. **Additive:** the protocol version is not raised (an addition never raises it, see
`GetVersion`); a service that predates them answers `InvalidRequest` ("unknown request"), which a
client shows as "this service cannot say", never as an empty list.

```jsonc
// GetPaths
{ "as_of_unix_ms": 1730000000000,      // when this was true, by the service's clock
  "watching": true,                    // false: nothing is connected, so nothing is being looked at
  "paths": [ { "id": "7", "kind": "Wifi | Cellular | Ethernet | Other",
               "name": "Hostel-5G" | null,           // cleaned, at most 64 characters
               "role": "Carrying | Standby | Unusable",
               "measured": true,                     // false: nothing below may be read as fine
               "quality": "Good | Poor | Unusable" | null,
               "rtt_ms": 43.3 | null, "jitter_ms": 4.0 | null, "loss": 0.023 | null,
               "trace_ms": [40.1, null, 45.5],       // at most 64; null is a lost probe
               "typical_ms": [38.0, 52.0] | null } ],   // 10th-90th percentile, once there are enough
  "degraded": { "path": "7", "quality": "Poor", "staying": "OnlyPath" } | null }

// GetStats
{ "connected": true, "connected_for_s": 11520, "network_changes": 2,
  "changes_that_drop_connections": 1,  // changes under a Tier 2 profile
  "method_switches": 1, "endpoint_switches": 0,
  "degraded_periods": 1, "longest_degraded_s": 6 }  |  { "connected": false }
```

- **Nothing is claimed that was not measured.** A network with no recent measurement has
  `measured: false` and `null` for `quality`, `rtt_ms`, `jitter_ms` and `loss`; a reply that says
  otherwise is refused by the decoder. A client must not read `null` as "fine".
- **Never stale as current.** `as_of_unix_ms` lets a client say "last known"; the service stamps every
  reply. A network whose probes have gone quiet reads as unmeasured, not as its last value.
- **A network name is untrusted text** (chosen by whoever runs the access point): control and
  direction-changing characters are removed and the length capped on both ends. It can reveal where a
  person is: it is shown only locally and kept out of the diagnostics bundle by default (T112).
  Recent Windows may refuse to give it until the user allows location access; the name is then
  `null` and the network is shown by its kind.
- **Counters, not comparisons.** `GetStats` counts what happened (events the engine recorded). There
  is no drop counter or interruption length because nothing measures when traffic stopped; and no
  "improvement" figure, because that needs a comparison nobody has made. `longest_degraded_s` is how
  long the carrying network was poor with no way out (`Degraded` to `Recovered`).
- Interface ids are decimal strings; every bound above is enforced by the decoder (a client refuses
  more than 32 networks, a trace over 64 readings, a latency over a day, loss outside 0 to 1, more
  than one carrying network, or stats that contradict themselves).

### `ListEndpoints → { endpoints }` and `ListRules → { rules, encrypted_dns }` (T146, T100)

Read-only. The window draws exactly these fields, and `dnet-view` copies only these out of the reply.

```jsonc
// ListEndpoints: at most 64. `address` is host:port as the service will dial it; credentials are never returned.
{ "endpoints": [ { "id": "<uuid>", "label": "oracle-mumbai", "address": "203.0.113.9:44443",
                   "enabled": true, "health": "Unknown | Healthy | Degraded | Unreachable" } ] }

// ListRules: the rule list, and the encrypted-name choice that rides along with it (no request of its own
// was warranted for two booleans).
{ "rules": [ { "precedence": 1, "action": "Bypass", "reliability": "Deterministic | BestEffort", "builtin": true } ],
  "encrypted_dns": { "block": true,            // false: the person opted out (SetEncryptedDnsHandling)
                     "needs_disclosure": false // true until the first-run disclosure has been shown and answered
                   } }
```

- `reliability` is `BestEffort` for application rules and `Deterministic` for address and domain rules (Principle
  VI); a window shows the difference in the row itself, never in a tooltip.
- A client treats a list that is not in this form as an error with a reason, never as an empty list: "no
  endpoints" and "could not read the endpoints" are different things to tell a person.

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

### Configuration requests (Phase 9a, IPC-17 to IPC-21)

```jsonc
{ "request": "AddEndpoint", "label": "home", "host": "203.0.113.9",
  "credentials": { "version": 1, "hysteria2": { ... }, "reality": { ... } } }   // -> { "endpoint": "<uuid>" }
{ "request": "RemoveEndpoint",     "endpoint": "<uuid>" }                       // -> { "applied": true }
{ "request": "SetEndpointEnabled", "endpoint": "<uuid>", "enabled": false }     // -> { "applied": true }
{ "request": "SetEncryptedDnsHandling", "block": false }
   // -> { "block": true }   |   { "block": false, "consequence": "<what allowing costs>" }
```

- **Strict.** Each request names exactly its fields: an unknown field, a missing one, `null` and a
  value of the wrong type are `InvalidRequest`, never ignored or defaulted. There is no `port`: each
  connection method in `credentials` carries its own server port, and a second answer would only
  disagree with the first.
- **Checked by the rules the saved configuration applies.** `label` is 1 to 64 printable ASCII
  characters. `host` is an IP address or a host name (no scheme, port, path or userinfo; not an
  unspecified or multicast address). `credentials` is the stored form of a credential set, with at
  least one connection method. A request that passes can always be saved.
- **Errors never repeat what the client sent**: not a label, a host, a credential, nor the name of an
  unknown field. They name the field at fault, or list the fields the request takes.
- **Idle only.** These are accepted only while nothing is connected or being connected; otherwise
  `InvalidRequest` says to disconnect first. The engine and what it drives were built from the
  endpoints and rules of the moment, and replacing them under a live tunnel would leave it running
  on a configuration nobody can see. When accepted, the change is saved first, then applied, and the
  next connect uses it.
- **All or nothing.** The sealed credentials, the saved configuration and the in-memory store change
  together or not at all. A failure to save is `InternalError`, and the service is as it was.
  Removing an endpoint writes the file first and forgets its credentials second, so a failure leaves
  a stray sealed blob at worst, never an endpoint without credentials.
- **Removing an endpoint that holds cloud resources is refused**: it would leave them running and
  billed, and the request has no way to say they should be cleaned up. That goes through provisioning.
- **`SetEncryptedDnsHandling { block: false }` is the one-action opt-out (FR-025a).** Its reply
  carries the consequence, which the interface must show; a client treats a reply without it as
  malformed. `block: true` needs no consent. The choice is saved, and a restart keeps it.
- At most 64 endpoints; a label already in use is refused. The credentials arrive over the control
  pipe, which only the interactive console user can use (Mutating class), and are sealed on arrival;
  they are never returned by any request.

### `ImportFeed { keys?, feed? } → { imported, changes }` (T066a, IPC-23)

Hands the service signed profile-feed documents it did not fetch (ADR-0002 §7, offline import).

```jsonc
{ "request": "ImportFeed", "keys": "<DSSE envelope, text>", "feed": "<DSSE envelope, text>" }
// -> { "imported": true, "changes": ["Updated"] }     // [] when the service already had these
```

- **At least one of `keys` and `feed`;** each at most 262,144 bytes (the cap every source is held to);
  anything else, or an unknown field, is `InvalidRequest` (never repeated back). The request is
  `Mutating` (interactive console user), but it grants no privilege: an import can install only what the
  signing keys already authorised.
- **Keys are taken first,** so a feed signed under new keys can travel with them. If the keys are taken
  and the feed is refused, the error says so ("the keys document was taken, but the feed was refused: …");
  the keys stay.
- **Every check a fetched document gets,** plus feed step 8: a trial configuration for every bundled
  profile with the proposed values, through the generators a real connection uses. One profile that
  would not generate refuses the whole feed. A refusal is `InvalidRequest` naming the profile and the
  rule; a failure to save is `InternalError` and nothing has changed.
- **Applied from the next connection.** The client section goes into the definitions the next
  configuration is generated from; a tunnel already up is never regenerated. The endpoint section is
  **never applied**: it is staged for the person to approve for their own server.
- A build with no trust anchor (the key ceremony, T066d, has not happened) answers `InternalError`
  "not available in this build yet".
- `changes` names, in order: `Updated`, `Evicted` (a new keys document dropped the key the applied feed
  depended on, rule R), `OutOfDate`, `Discarded` (a stored document no longer verified at start-up).

### `FetchFeed → { started, route }` (T066b, IPC-23)

Check for updated definitions now, because the person asked. Takes no field: what to fetch and from where
are compiled in, and a request that names a place is refused.

```jsonc
{ "request": "FetchFeed" }  // -> { "started": true, "route": "tunnel" | "physical" }
```

- **Which network (D2).** Through the tunnel while one carries traffic; **directly over the physical
  network when disconnected**, which is the one flow that bypasses the fail-closed posture and exists only
  because this request was made. The reply says which, so the interface can say it too.
- **The result arrives as an event** (`DefinitionsChanged`: `Updated`, or `CheckFailed` with a coarse
  `reason` of `Unreachable` or `Refused`). A check that is already under way is `ServiceBusy` (retryable).
- **A scheduled check never goes out on its own over the physical network:** the service checks at start-up
  plus every six hours with jitter, but only while a tunnel carries traffic. A scheduled check that finds
  nothing is logged, not announced.
- **What is fetched is not trusted.** HTTPS to the two compiled-in hosts only, each URL (and each of at most
  two redirects) checked before it is requested, no proxy, no cookie, a fixed `User-Agent`, 30 seconds, and
  no more than 256 KiB; then the same verification and trial generation as an import.
- A build with no trust anchor answers `InternalError` "not available in this build yet".

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
- 64-bit interface ids (`PathChanged.from`/`to`, `Degraded.path`, `Recovered.path`) are decimal strings.

**Definitions (T066a, ADR-0002 §6).** One more event, additive, sent when it happens (not tied to a
connection, so a client that connects later learns the state from its status, not by replay):

```jsonc
{ "event": "DefinitionsChanged", "change": "Updated", "sequence": "17", "endpoint_updates": 2,
  "because": "connection method definitions updated (sequence 17); 2 of them also propose a change to your server, which waits for your approval" }
{ "event": "DefinitionsChanged", "change": "Evicted" | "OutOfDate" | "Discarded", "because": "..." }
{ "event": "DefinitionsChanged", "change": "CheckFailed", "reason": "Unreachable" | "Refused", "because": "..." }
```

`sequence` is a decimal string (64 bits). `OutOfDate` is sent once per expired feed, when a client next asks
for the state; the definitions stay in use, because reverting would only substitute older ones.

**Degradation (T084, FR-019).** Two events, additive (a client that does not know them shows them like
any other event: name, number, `because`):

```jsonc
{ "event": "Degraded", "path": "7", "quality": "Poor", "staying": "OnlyPath",
  "because": "the network carrying your connection is slow or dropping packets, and it is the only network available, so there is nothing to switch to" }
{ "event": "Recovered", "path": "7",
  "because": "the network carrying your connection is working normally again" }
```

- `quality` is `Poor` or `Unusable`, never `Good` (the encoder refuses it). `staying` is why the
  connection is not moving: `OnlyPath`, `NoBetterPath`, `Proving`, `Dwell` or `Budget`.
- `Degraded` is sent only after the carrying path has stayed poor for as long as the failover machine
  waits before leaving a path, so it means "it would have moved if it could"; it is sent again only
  when it says something new (another reason, or `Poor` to `Unusable`). `Recovered` is sent only after
  a `Degraded`, once the path has stayed good for 10 s. A path that is not being measured is neither.
- Neither event is a move or a failure, and neither says that the connection was moved.
- Only profiles the service steers are measured, so only for those can these be sent. A profile that
  is only observed has no quality to report (limit, not a promise of silence meaning "fine").

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
| IPC-16 | `GetPaths` and `GetStats` replies round-trip; an unmeasured network claims nothing and a reply that says otherwise is refused; names are cleaned on both ends; every bound is enforced; contradictory stats are refused; the decoders never panic on arbitrary input (property tests, with a check that the generator reaches acceptance). |
| IPC-12b | `Degraded` and `Recovered` encode with a `because` that differs by reason and by band, name the path as a decimal string, never claim a move, and a `Degraded` of a good network is an error. |
| IPC-17 | Each configuration request round-trips and carries exactly the fields it names. |
| IPC-18 | An unknown, missing or mistyped field is `InvalidRequest`, never ignored or defaulted. |
| IPC-19 | An endpoint's label, address and credentials are checked by the rules the saved configuration applies; there is no port of its own. |
| IPC-20 | No error repeats a value from the request (including an unknown field's name), and nothing that prints a request shows a secret. |
| IPC-21 | The decoder never panics on damaged or hostile text. |
| IPC-22 | (daemon) A change is saved, applied and followed by a rebuilt orchestrator; a failure at any step leaves the store, the file and the sealed credentials as they were; nothing is changed while a connection is up or being made; an endpoint holding cloud resources is not removed. |
| IPC-23 | `ImportFeed` carries the keys document, the feed, or both, each within the size cap, and nothing else; an unknown field is refused without being repeated. |
| IPC-15 | `GetVersion` is answered by the dispatch itself for any authenticated caller, never reaches the service, and tells an unauthenticated caller nothing; the reply has exactly the contracted keys; a client refuses a reply that is malformed, out of range, or from a service that predates the request. |
