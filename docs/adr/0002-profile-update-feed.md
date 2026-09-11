# ADR-0002: Signed profile update feed

**Status**: Proposed. §3–§6 are normative for T066. Decisions D1–D4 (§10) need owner approval
before T066 starts.
**Date**: 2026-09-12
**Task**: T065 (open item O5)
**Decides**: FR-007, FR-008
**Blocks**: T066 (`crates/dnet-core/src/feed.rs`)

---

## Context

- **FR-007**: connection-method definitions can be updated without installing a new version.
- **FR-008**: externally supplied definitions are verified for integrity and authenticity before
  they are applied.

A feed changes what `dnetd`, running as LocalSystem, generates for the supervised cores. That makes
it a supply-chain surface. Whoever can sign the feed can change how every installed client looks on
the network. If the schema allowed it, they could also change where traffic goes.

Three facts shape the design.

**1. The parameters worth updating are mostly tied to the endpoint.** A parameter that the server
must also know cannot be changed on the client alone. Changing it there breaks the handshake with
the user's endpoint. Checked against the pinned cores (ADR-0004):

| Kind | Parameter | Client only? | Evidence |
|---|---|---|---|
| AmneziaWG | `jc`, `jmin`, `jmax` (junk packets) | **Yes** | Core README at `b5928ef`: junk packets "do not carry any actual data, so there is no need to specify it on both sides" |
| AmneziaWG | `s1`, `s2` (padding), `h1`–`h4` (headers) | No | The receiver must strip the padding and recognise the message type, so it must know both values. The README does not say this; it follows from the mechanism. |
| Hysteria 2 | `bbr_profile`, Chrome QUIC parroting | **Yes** | Pinned `option/hysteria2.go`. Congestion control and ClientHello shaping are local to the sender. |
| Hysteria 2 | `obfs.type` (`salamander`, `gecko`), Gecko packet sizes | No | Obfuscation is symmetric. Gecko sizes are treated as coupled because they are not verified as one-sided. |
| VLESS+REALITY | `utls.fingerprint` | **Yes** | Pinned `option/tls.go`. The server does not constrain the ClientHello fingerprint. |
| VLESS+REALITY | Borrowed TLS target (`server_name`), `flow` | No | The server's REALITY handshake target and user flow must agree with the client. |

**2. The feed matters most when the tunnel is down.** A method becomes recognised, every profile
fails, and the fix has to arrive over the hostile network itself.

**3. The project operates no infrastructure that carries user traffic (FR-015).** A static,
signed file is metadata, not traffic. It must still not require a server we run.

## Threat model

**The attacker can:**
- control the network path (DPI, TLS interception, captive portals);
- control or compromise the host that serves the feed, or a mirror;
- steal one feed-signing key;
- steal root keys up to one below the threshold.

**Out of scope:**
- A local administrator or SYSTEM on the client, who can replace `dnetd` anyway.
- Compromise of the build pipeline, which is covered by ADR-0004.

Each attack in the TUF specification v1.0.36 threat model is mapped to its mitigation below.

| TUF attack | Mitigation here |
|---|---|
| Arbitrary installation / wrong software | Ed25519 signatures with a root-anchored key hierarchy (§2, §4). The payload type binds each signature to a role (§3). |
| Endless data | Hard size cap, enforced while reading (§3) |
| Rollback | Monotonic `(keys_version, sequence)` ordering, plus floors compiled into the binary (§4) |
| Indefinite freeze | `expires_at` on every document, a lifetime cap, and a "stale" status once expired (§4, §8) |
| Fast-forward | A new keys document evicts any applied feed that no longer verifies under it (§4, rule R) |
| Mix-and-match | A feed names the `keys_version` it was signed under, and that version must be the one accepted (§4) |
| Malicious mirrors | Integrity does not depend on the transport, so any source can be tried, including offline import (§7) |
| Key compromise | Root threshold 2 of 3. Signing keys are short-lived and revocable. The scope limit bounds what a compromised key can do (§1, §8). |

---

## Decision

### 1. Scope: what the feed may change

The feed **proposes parameter values for profiles already defined in the application**. Nothing
else. Its schema is closed (§5), so every exclusion below is **structural**: the parser has nowhere
to put the value. There is no blocklist.

**The feed never carries:**

| Excluded | Why |
|---|---|
| Routing rules of any kind: bypass, tunnel, application, CIDR, domain | A signed `Bypass` rule silently routes traffic around the tunnel. This is the surface O5 names. |
| DNS servers or DNS rules | A feed-chosen resolver sees every query |
| Endpoint addresses, ports, port ranges | Endpoints belong to the user (FR-015) |
| Credentials: passwords, UUIDs, keys, REALITY `short_id` and public key | Secrets never leave the credential store (FR-035) |
| Brutal bandwidth | Requires a recorded user acknowledgement (FR-006). A feed cannot give one. |
| New profile ids or kinds | New ids need generator code, which ships in an application release |
| Raw core JSON, free-form maps, URLs, executables, core versions | Would bypass the typed validators, and could reach driver-backed features (ADR-0004 Finding 4) |
| Human-readable text shown to the user | A signed "notice" is a phishing channel ("enter your cloud credentials at…") |

**What this bounds.** A fully compromised signing key can move client parameters only within the
§5 bounds. The worst outcome is weaker obfuscation, which makes the client easier to detect.
Traffic redirection, credential theft, DNS or traffic leaks, and turning on Brutal all stay out of
reach. This bound is why the scope is this narrow.

### 2. Keys and roles

The only algorithm is **Ed25519, pure mode, per RFC 8032**. Ed25519ph and Ed25519ctx are not
accepted. Two roles:

| Role | Where the public key lives | Signs only | Threshold | Lifetime |
|---|---|---|---|---|
| **Root** | Compiled into `dnetd` (`ROOT_KEYS`, `ROOT_THRESHOLD`) | Keys documents | **2 of 3** (D3) | Until an application release removes it |
| **Signing** | The accepted keys document | Feed documents | `signing_threshold` in the keys document (v1 publishes 1) | At most 180 days, enforced by the client |

- **Key identity** is the lowercase hex SHA-256 of the 32-byte public key, computed by the client.
  An envelope's `keyid` is an unauthenticated hint. DSSE: it "MUST NOT be used for security
  decisions".
- **Thresholds count distinct public keys.** Two valid signatures from the same key count once.
- **Roles are disjoint.** A keys document that lists a root key as a signing key is refused.
- **Verification is strict.** Refuse:
  - signatures whose `s` is not reduced;
  - signatures whose `R` has a small-order component;
  - weak (low-order) public keys.

  In `ed25519-dalek` this is `VerifyingKey::verify_strict` plus `is_weak`. T066 records the crate
  and version it pins.

### 3. Envelope: DSSE v1

Every document travels in a **Dead Simple Signing Envelope** (secure-systems-lab/dsse):

```json
{
  "payload": "<Base64(SERIALIZED_BODY)>",
  "payloadType": "<PAYLOAD_TYPE>",
  "signatures": [{ "keyid": "<hint>", "sig": "<Base64(SIGNATURE)>" }]
}
```

- **What is signed:**
  `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`.
  `LEN` is the ASCII decimal byte length with no leading zeros; `SP` is 0x20.
  DSSE signs the exact payload bytes, so there is no JSON canonicalisation to get wrong. The payload
  type is inside the signed bytes, so a signature on one document type never validates as another.
- **Payload types**, compared by exact byte equality:
  - `application/vnd.dnet-engine.feed-keys.v1+json`, signed by root keys;
  - `application/vnd.dnet-engine.profile-feed.v1+json`, signed by signing keys.
- **Envelope rules:**
  - exactly the three fields above (`keyid` optional; unknown fields refused);
  - base64 uses the standard alphabet with padding, and must be canonical (re-encoding reproduces the
    input);
  - 1 to 8 signatures, each decoding to exactly 64 bytes.
- **No format downgrade.** Once a client has accepted a document of payload-type version *n*, it
  refuses any lower version of the same role. A future v2 feed cannot be rolled back by serving v1.
- **Size cap: 262,144 bytes** per envelope, from any source. The reader stops at the cap plus one
  byte and refuses. The envelope is never read whole first.
- **Parse after verify.** The payload is not parsed as JSON until the signature threshold is met.
  The bytes that were verified are the bytes that are parsed. DSSE: implementations "MUST NOT
  re-parse the envelope after verification to pull out the payload."

### 4. Verification (normative)

`SKEW` is 24 hours. Campus networks often block NTP, so clocks drift. Every rejection is a typed
error naming the step and field, never the payload contents.

**Two kinds of check, with different trust.**
- **Ordering checks** (`keys_version`, `sequence`, digests) do not depend on the clock. They are the
  rollback defence.
- **Time checks** (`issued_at`, `expires_at`, key validity windows) trust the system clock.
  Windows time sync is not authenticated on a machine outside a domain, so a network attacker who can
  shift the clock can stretch a freeze window. Time checks are therefore defence in depth. No
  guarantee in §1 depends on them.

#### Keys document

1. **Read and decode.** Read within the cap. Parse the envelope only. Require the keys payload type.
   Decode the payload bytes `P`.
2. **Count root signatures.** Count distinct root keys whose strict verification over
   `PAE(type, P)` succeeds. Require at least `ROOT_THRESHOLD`.
3. **Parse.** Parse `P` against the keys schema (§5.2).
4. **Check order.** Require `keys_version ≥ max(stored, MIN_KEYS_VERSION)`. `MIN_KEYS_VERSION` is
   compiled in, bumped at each release to the version current at build time. If `keys_version`
   equals the stored version, `SHA-256(P)` must equal the stored digest. Two different documents
   with the same version is equivocation, and it is refused and reported.
5. **Check time and keys:**
   - `issued_at ≤ now + SKEW`;
   - `expires_at > now − SKEW`;
   - `expires_at − issued_at ≤ 366 days`;
   - 1 to 8 signing keys, pairwise distinct, none weak, none a root key;
   - each key's `not_after − not_before ≤ 180 days`;
   - `1 ≤ signing_threshold ≤` the number of keys.
6. **Accept.** Persist the envelope bytes and the digest with the durable write and SYSTEM/
   Administrators DACL used by the undo journal. Then apply rule R.

#### Feed document

1. **Read and decode.** Read within the cap. Parse the envelope only. Require the feed payload type.
   Decode `P`.
2. **Require a current keys document.** The accepted keys document must not be expired
   (`expires_at > now − SKEW`). Otherwise no new feed is accepted.
3. **Count signing signatures.** Count distinct signing keys from the accepted keys document that
   verify strictly over `PAE(type, P)` and satisfy `not_before − SKEW ≤ now ≤ not_after + SKEW`.
   Require at least `signing_threshold`. Key validity is checked against `now`, not the feed's own
   `issued_at`, because a key holder controls `issued_at`.
4. **Parse.** Parse `P` against the feed schema (§5.3).
5. **Check the keys version.** `keys_version` must equal the accepted keys document's version.
6. **Check order** of `(keys_version, sequence)` against the applied feed:
   - greater: continue;
   - equal with the same digest: no-op;
   - anything else: refuse as a rollback.
7. **Check time:**
   - `issued_at ≤ now + SKEW`;
   - `expires_at > now − SKEW`;
   - `expires_at − issued_at ≤ 30 days`.
8. **Validate every value.** Each value passes the same validators as the bundled defaults (§5.4).
   For every profile, a trial configuration is generated with the proposed values and must satisfy
   CC-01…CC-09 and AW-04.
9. **Refuse whole or accept whole.** A feed with one invalid entry is refused entirely. Nothing is
   partially applied.
10. **Accept.** Persist the envelope, then apply per §6.

#### Rule R: eviction on key rotation

When a new keys document is accepted, the stored applied feed is re-checked. Only the signature and
threshold part of feed step 3 runs, without validity windows: its signatures are verified against
the **new** signing keys, ignoring step 5.

- **It still meets the threshold:** keep it.
- **It does not:** drop it, revert to the bundled defaults, and raise a `ConnectionEvent`.

This evicts anything a revoked key signed, including a feed pushed to `sequence = u64::MAX`.

#### Startup

- Stored envelopes are **re-verified from their bytes** at every `dnetd` start, never trusted as
  parsed state:
  - the keys document runs keys steps 1–3;
  - the applied feed runs feed steps 1, 3 and 4 against the stored keys document, **without** the
    validity-window checks.

  The time checks gate *accepting* a document, not *keeping* one. Without that distinction an
  applied feed would silently disappear when its signing key's window closed during a freeze,
  contradicting §6.
- A stored document that fails verification is treated as absent: bundled defaults are used, and
  the failure is logged and reported.
- Unlike an unrestored undo journal (T038), a bad feed state does not lock the service. The bundled
  defaults are always a safe floor.

### 5. Payload schemas (v1)

#### 5.1 Encoding rules for both documents

- UTF-8 JSON with no byte-order mark.
- Every object refuses unknown fields and duplicate keys.
- Numbers are integers only: no fractions, no exponents. Each must fit its field's type.
- Times are integer seconds since the Unix epoch, UTC.
- Strings are at most 253 bytes.

#### 5.2 Keys document

```json
{
  "keys_version": 4,
  "issued_at": 1757635200,
  "expires_at": 1789171200,
  "signing_threshold": 1,
  "signing_keys": [
    { "public_key": "<base64, 32 bytes>", "not_before": 1757635200, "not_after": 1773187200 },
    { "public_key": "<base64, 32 bytes>", "not_before": 1765411200, "not_after": 1780963200 }
  ]
}
```

| Field | Type | Rule |
|---|---|---|
| `keys_version` | u64 | Monotonic, at least 1 (§4) |
| `issued_at`, `expires_at` | u64 | Lifetime at most 366 days |
| `signing_threshold` | u8 | 1 to the number of `signing_keys` |
| `signing_keys` | array, 1–8 entries | Distinct, not weak, not a root key |
| `signing_keys[].public_key` | base64, 32 bytes | Standard alphabet, padded, canonical |
| `signing_keys[].not_before`, `not_after` | u64 | `not_before < not_after`; at most 180 days apart |

#### 5.3 Feed document

```json
{
  "keys_version": 4,
  "sequence": 17,
  "issued_at": 1757635200,
  "expires_at": 1760227200,
  "profiles": [
    {
      "profile_id": "awg-default",
      "kind": "amnezia_wg",
      "client":   { "jc": 6, "jmin": 40, "jmax": 90 },
      "endpoint": { "s1": 72, "s2": 41, "h1": 1873209, "h2": 5520871, "h3": 90121, "h4": 334210 }
    },
    {
      "profile_id": "hy2-default",
      "kind": "hysteria2",
      "client":   { "bbr_profile": "standard", "chrome_parrot": true },
      "endpoint": { "obfs": { "type": "gecko", "min_packet_size": 512, "max_packet_size": 1200 } }
    },
    {
      "profile_id": "reality-default",
      "kind": "vless_reality",
      "client":   { "utls_fingerprint": "chrome" },
      "endpoint": { "target_domain_candidates": ["www.example.com"] }
    }
  ]
}
```

| Field | Type | Rule |
|---|---|---|
| `keys_version` | u64 | Equals the accepted keys document's version |
| `sequence` | u64 | Monotonic within a `keys_version` |
| `issued_at`, `expires_at` | u64 | Lifetime at most 30 days |
| `profiles` | array, 1–16 entries | At most one entry per `profile_id` |
| `profiles[].profile_id` | string | Must be an id in the bundled profile catalogue |
| `profiles[].kind` | enum | `amnezia_wg`, `hysteria2`, or `vless_reality`; must match the catalogue's kind for that id |
| `profiles[].client` | object, optional | Kind-specific, §5.4 |
| `profiles[].endpoint` | object, optional | Kind-specific, §5.4 |

An entry with neither `client` nor `endpoint` is refused. Within a section every field is
optional; an omitted field keeps its current value.

#### 5.4 Per-kind fields and bounds

The bounds are set by this ADR and are **narrower than the cores accept**. The feed gets the
tightest range that is still useful. AmneziaWG bounds follow the Amnezia documentation constraints
for a 1280-byte MTU.

| Kind | Section | Field | Bound |
|---|---|---|---|
| `amnezia_wg` | client | `jc` | 1–16 |
| | client | `jmin`, `jmax` | `0 ≤ jmin < jmax ≤ 1280` |
| | endpoint | `s1` | 0–1132 (1280 − 148) |
| | endpoint | `s2` | 0–1188 (1280 − 92), and `s1 + 56 ≠ s2`, so the padded initiation and response differ in size |
| | endpoint | `h1`–`h4` | 5 to 2³¹−1, pairwise distinct. Values 1–4 are the plain message types, which is the unobfuscated signature. |
| `hysteria2` | client | `bbr_profile` | `standard`, `conservative`, or `aggressive` |
| | client | `chrome_parrot` | bool |
| | endpoint | `obfs.type` | `salamander` or `gecko` |
| | endpoint | `obfs.min_packet_size`, `obfs.max_packet_size` | Gecko only; `256 ≤ min ≤ max ≤ 1400` |
| `vless_reality` | client | `utls_fingerprint` | `chrome`, `firefox`, `edge`, `safari`, `ios`, or `android` |
| | endpoint | `target_domain_candidates` | 1–8 DNS hostnames. No IP literals; no suffix covered by a built-in bypass (T031); no single-label names. Letters, digits, hyphens and dots only; internationalised names must already be in A-label (`xn--`) form. |

When both sides of a cross-field rule are present (for example `jmin < jmax`), the rule is checked
on the resulting value. That value is the proposed field merged over the value in effect.

### 6. Applying parameters

- **Client section.**
  - Takes effect at the next profile generation, never mid-session.
  - Precedence: a value the user set, then the feed, then the bundled default.
  - A `ConnectionEvent` reports "connection method definitions updated (sequence *N*)".
- **Endpoint section.**
  - **Never applied by the client alone**, because the endpoint would still be running the old
    values.
  - Staged as "endpoint update available". `dnet-provision` applies it by reconfiguring the user's
    endpoint, with the user's consent (the Phase 8 contract). Only then does the client switch.
  - The consent prompt names every changed value. For REALITY that includes the target domain: it
    will appear in the SNI of every connection, and the endpoint will forward unauthenticated probes
    to it.
  - The values in effect always come from the endpoint record, whether provisioned or entered for a
    user-added endpoint (FR-010). The feed proposes; it never overrides.
- **Once an applied feed expires,** its parameters stay in use and the status shows "definitions
  out of date".
  - Reverting would only substitute the bundled defaults, which are older still.
  - Stale parameters weaken obfuscation. They leak nothing.

### 7. Distribution and fetching

- **Two static files:**
  - `feed-keys.dsse.json`;
  - `profile-feed.v1.dsse.json`.

  They are always published together (§8).
- **Integrity comes only from the signatures.** Every host, mirror, and offline copy is equally
  untrusted. TLS is used for confidentiality, not for authenticity.
- **Only `dnetd` fetches and verifies.** The tray never interprets a feed.
  - **Offline import:** the tray passes the envelope bytes over IPC as a `Mutating` request, and
    `dnetd` runs the same §4 steps.
  - **Who may import.** Any user the IPC boundary admits may import. This grants no privilege: an
    import can only install what the signing keys already authorised, which is exactly what a
    fetch would install. The IPC frame limit enforces the §3 size cap.
- **Fetch limits:**
  - HTTPS with rustls, to compiled-in URLs;
  - redirects only within a compiled-in host allowlist;
  - a 30-second timeout and the §3 size cap;
  - no cookies, no user or machine identifiers, a fixed `User-Agent`.
- **When to fetch** (D2):
  - automatically at start and every 6 hours, with jitter, **while tunnelled**;
  - directly over the physical network **only when the user asks** while disconnected.

  A direct fetch is the one flow that bypasses the fail-closed posture, so it is never automatic.

### 8. Key rotation and compromise

| Event | Publisher action | Client effect |
|---|---|---|
| **Routine signing-key rotation** (at least every 90 days; lifetime cap 180) | Root ceremony issues keys document V+1 listing old and new keys, with overlapping validity. Publish it with a feed re-signed under V+1. A later V+2 drops the old key. | Accepts V+1, then the paired feed. The applied feed stays under rule R while the old key is still listed. |
| **Keys document renewal** (at least every 12 months; cap 366 days) | Root ceremony re-issues it with `keys_version` incremented | Once it expires unrenewed, no new feed is accepted. The applied feed stays in use and is shown as stale. |
| **Feed heartbeat** (at least every 14 days; cap 30) | Re-sign with `sequence + 1`, even with no parameter change | Lets a client tell a freeze from a quiet period |
| **Signing key compromised** | Within 24 hours: keys document V+1 without the key, and a fresh feed | Rule R evicts everything the key signed, including a fast-forwarded sequence. Exposure lasts until the client fetches V+1, and is bounded by §1. |
| **Fresh install after a compromise** | Release with `MIN_KEYS_VERSION` raised past the revocation | Until then, an install with no stored state can be served an older, unexpired keys document that still lists the revoked key. The exposure ends when that key's window closes (≤ 180 days) or the client fetches the newer document, and it is bounded by §1. |
| **One root key compromised or lost** | Below the 2-of-3 threshold. Replace it in the next application release. | Nothing immediate |
| **Two root keys compromised** | Emergency application release with a new root set and a raised `MIN_KEYS_VERSION` | Clients stay exposed to attacker keys documents until they update. They are still bounded by §1. This is stated plainly, not hidden. |
| **Root set change** | Only in an application release. The release that removes a root must already trust its replacement. | — |

**Custody** (D3):
- Root keys are held offline on three separate encrypted media and never touch a networked machine.
- Signing keys are held offline and used by `cargo xtask feed-sign`. That command runs the payload
  through the same `dnet-core` parser and validators before signing, and refuses anything the client
  would refuse.
- Private keys never appear in the repository, CI, logs, or diagnostics (constitution, secrets).

### 9. Alternatives considered

| Option | Why not |
|---|---|
| HTTPS with certificate pinning only | Compromising the host compromises the feed. No mirrors, no offline import, no key rotation independent of hosting. |
| Full TUF, e.g. `tough` | Its snapshot, timestamp, and targets roles solve many-file repositories; we have one file. We adopt TUF's threat model and its mitigations for the attacks that apply, with far less surface. Revisit if the feed grows to several targets. |
| minisign or signify | A single key: no roles, no threshold, no rotation story |
| Sigstore keyless | Verification needs an online trust root and transparency log, which is fragile on the hostile networks this feed exists for |
| JWS over canonical JSON | Canonicalisation is a known source of verification bypasses. DSSE signs bytes. |
| OpenPGP | Large parser attack surface for a signature over one file |

### 10. Decisions required

| # | Decision | Recommendation |
|---|---|---|
| D1 | Where the files are hosted | **GitHub Release assets on the project repository.** Static, with no server we operate. FR-015 concerns user traffic, not a signed metadata file. Offline import always remains available. |
| D2 | Fetching over the physical network while disconnected | **Only when the user asks** (§7). Automatic direct fetches would add a standing exception to fail-closed. Never fetching would make the feed useless exactly when it is needed. |
| D3 | Root threshold and custody | **2 of 3, offline, separate media.** Survives the loss of one medium and the compromise of one. Costs a second medium per keys ceremony, which is a rare operation. |
| D4 | Scope | **Parameters only; no routing content in v1** (§1). This narrows FR-007 to parameters. Signed routing content, for example an encrypted-DNS endpoint list for FR-025, would need its own ADR. |

### 11. Consequences

- **T066** implements §3–§6.
  - `dnet-core` holds a pure decision function: envelope bytes, `now`, and stored state in; accept
    or refuse out.
  - `dnetd` owns fetching and persistence.
  - This is the first cryptography in `dnet-core`. It is pure computation, which keeps the crate's
    no-I/O rule.
- **Generators (T056–T058)** take typed, validated parameter structs split into client and endpoint
  groups. Feed values then pass through the same validators as bundled and user values, and no
  second validation path exists to drift.
- **Contract tests to add with T066:**

  | ID | Assertion |
  |---|---|
  | FEED-01 | A valid feed applies. One flipped payload byte is refused. |
  | FEED-02 | A root-key signature on a feed is refused, and a signing-key signature on a keys document is refused (role binding) |
  | FEED-03 | Two signatures from one key count once toward the threshold |
  | FEED-04 | A lower `sequence` is refused. An equal `sequence` with a different digest is refused. |
  | FEED-05 | A feed whose `keys_version` is not the accepted version is refused |
  | FEED-06 | Keys document V+1 without key K evicts an applied feed signed by K, including one at `u64::MAX` |
  | FEED-07 | An expired feed is not accepted. An applied feed past expiry is kept and reported stale. |
  | FEED-08 | An envelope over the cap is refused without reading past cap + 1 |
  | FEED-09 | An unknown field, duplicate key, or non-integer number anywhere refuses the whole document |
  | FEED-10 | Any out-of-bounds value refuses the whole feed (`h1 = 1`, `jmin ≥ jmax`, `s1 + 56 = s2`, an unlisted fingerprint, an IP-literal target) |
  | FEED-11 | A payload with a bad signature reports a signature error, never a parse error (parse after verify) |
  | FEED-12 | A weak signing key in a keys document is refused. A non-canonical signature is refused. |
  | FEED-13 | Tampered stored state at start is treated as absent, and bundled defaults are used |
  | FEED-14 | Routing, DNS, endpoint address, credential, and Brutal fields are refused by the schema |
  | FEED-15 | Known-answer vectors: fixed test-only keys and golden envelope bytes, so the signing tool and the client cannot drift |

- **Profile catalogue.** `data-model.md` gains a feed-state entity and the bundled profile catalogue
  (ids and kinds) in T066.

## References

- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
- DSSE protocol and envelope: `github.com/secure-systems-lab/dsse`, `protocol.md` and `envelope.md`.
- The Update Framework specification v1.0.36, §Goals / threat model.
- `ed25519-dalek` `VerifyingKey::verify_strict` and `is_weak` (docs.rs).
- Amnezia documentation, AmneziaWG parameter constraints: `docs.amnezia.org/documentation/amnezia-wg/`.
- Pinned cores (ADR-0004):
  - primary core `0b89958`: `option/hysteria2.go`, `option/tls.go`, `common/tls/reality_client.go`;
  - `amneziawg-go` `b5928ef`: `README.md`.
