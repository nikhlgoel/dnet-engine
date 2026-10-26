# Publishing the profile feed

A runbook for the person who holds the keys. The design and the reasons are in
[ADR-0002](adr/0002-profile-update-feed.md); this is only what to type and what to check. Task: T066d (the
key ceremony) is the owner's, and this is its script.

**What is signed.** Two documents, both as DSSE envelopes:

| Document | Signed by | Holds |
|---|---|---|
| **Keys document** | 2 of the 3 **root** keys | which short-lived **signing** keys may sign feeds, and until when |
| **Feed** | the delegated **signing** key (1 of 1 in v1) | proposed parameter changes for the bundled profiles |

Root keys sign keys documents and nothing else. A root cannot sign a feed, and the client enforces it.

**Never in the repository.** Private keys are never written inside the repository, to CI, to a log, or to
a diagnostics bundle. The tools below refuse to write one inside the repository or to read one from it.
A key file, once made, exists once: the tools never overwrite a file.

## 1. The ceremony (once)

On an offline machine, with three separate encrypted media (one per root):

```bash
cargo run -p xtask -- feed-keygen --out /media/root-a/root.key
cargo run -p xtask -- feed-keygen --out /media/root-b/root.key
cargo run -p xtask -- feed-keygen --out /media/root-c/root.key
```

Each prints its **public** key. Write the three down. They are the only thing that leaves the offline
machine at this step: they are compiled into `dnetd` (`ROOT_KEYS` and `MIN_KEYS_VERSION` in
`crates/dnetd/src/feed_trust.rs`, where `ROOT_KEYS` is `None` until you fill it in; with it empty the
service has no feed machinery at all, which is the safe state). `cargo test -p dnetd` then checks the three
make a usable anchor (distinct, not weak, valid points).
Make the signing key the same way (it may live on a different medium, and is replaced every 90 days):

```bash
cargo run -p xtask -- feed-keygen --out /media/signing/signing.key
```

## 2. The keys document

Write the payload (`keys.json`) using the current time for the dates; the limits are the client's: the
document may last at most 366 days, a signing key's window at most 180 days (aim for 90).

```json
{
  "keys_version": 1,
  "issued_at": 1790000000,
  "expires_at": 1815000000,
  "signing_threshold": 1,
  "signing_keys": [
    { "public_key": "<signing public key>", "not_before": 1790000000, "not_after": 1797000000 }
  ]
}
```

Sign it with two roots (the three `--root-public` values are the build's root keys, in any order):

```bash
cargo run -p xtask -- feed-sign --document keys --payload keys.json \
  --key /media/root-a/root.key --key /media/root-b/root.key \
  --root-public <root A public> --root-public <root B public> --root-public <root C public> \
  --out keys.envelope
```

The tool parses the payload with the client's own parser, signs, then offers the finished envelope to the
client's own acceptance code as a fresh install would. If the client would refuse it, nothing is written
and the error says why (one root only, a root delegated as a signing key, an expired document...).

## 3. A feed

`feed.json` follows ADR-0002 §5. `keys_version` must equal the keys document's, and `sequence` must rise
with every feed (a feed re-signed with `sequence + 1` at least every 14 days is the heartbeat).

```bash
cargo run -p xtask -- feed-sign --document feed --payload feed.json \
  --key /media/signing/signing.key --keys-envelope keys.envelope \
  --root-public <root A public> --root-public <root B public> --root-public <root C public> \
  --out feed.envelope
```

Here the check is: would a client that has accepted `keys.envelope` apply this feed? It refuses a
stranger's key, a root's key, a feed under another keys version, and an expired feed.

## 4. Publishing

Attach `keys.envelope` and `feed.envelope` to the `profile-feed` release (D1). Integrity does not depend
on where they are served from, so any mirror or an offline copy is equally good.

### Trying a feed on one machine without publishing it

A machine whose `dnetd` was built with your root keys can be handed the two files directly (the
`profile-feed` release is not involved):

```bash
cargo run -p dnetctl -- import-feed --keys-file keys.envelope --feed-file feed.envelope
```

The service runs every check a fetched document gets, then generates a trial configuration for each
profile with the proposed values and refuses the whole feed if any one fails. Nothing else is needed to
test what a feed does, and a refusal says why. It takes effect on the **next** connection, never a live one.

## 5. When things change (ADR-0002 §8)

| Event | Do |
|---|---|
| Every ≤ 14 days | Re-sign the feed with `sequence + 1`, even if nothing changed |
| Every ≤ 90 days | New signing key; a keys document `keys_version + 1` listing old and new, overlapping |
| Every ≤ 12 months | Re-issue the keys document with `keys_version + 1` |
| A signing key leaks | Within 24 hours: a keys document without it, and a fresh feed |
| A root is lost or leaked | Below the threshold; replace it in the next application release |

## What these tools do not do

They do not hold or back up keys, they do not publish anything, and they cannot tell whether a payload
says what you meant. The client checks that a document is **well-formed, current and signed by the right
keys**; reading `feed.json` and deciding the parameters are sensible is still a person's job.
