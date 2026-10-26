//! T066c — `cargo xtask feed-keygen` and `cargo xtask feed-sign` (ADR-0002 §8, "Custody").
//!
//! The publisher's two chores: making a key, and signing a document with it.
//!
//! - **`feed-keygen --out <file>`** makes an Ed25519 key from the operating system's randomness, writes
//!   the secret to `<file>` (one line, base64, never overwriting a file, mode 0600 where that exists) and
//!   prints the **public** key, which is the only thing that is ever shared or compiled into a build. The
//!   secret is never printed. The file must not be inside the repository: a private key in a working tree
//!   is one `git add .` from being published (ADR-0002 §8: private keys never appear in the repository,
//!   CI, logs or diagnostics).
//! - **`feed-sign --document keys|feed ...`** signs a document and writes the envelope. It does not trust
//!   itself: it runs the payload through the client's own parser and validators first, then **offers the
//!   finished envelope to the client's own acceptance code** as a fresh install would (`rehearse_keys`,
//!   `rehearse_feed`), and writes nothing unless the client would accept it. A signature on a document the
//!   client refuses cannot be taken back and fails on every user's machine instead of on the publisher's.
//!
//! The signing function is `dnet_core::feed::sign::seal`, pinned to an independently produced
//! known-answer signature (FEED-15); this tool adds no cryptography of its own, only I/O and refusal.
//!
//! Root keys are meant to be held offline on separate media (D3), so this runs on an offline machine; the
//! only thing that has to travel to it is the payload, and the only thing that leaves it is the envelope.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use dnet_core::feed::sign::{
    check_feed_payload, check_keys_payload, payload_type, rehearse_feed, rehearse_keys, seal,
};
use dnet_core::feed::{Document, FeedError, FeedTrust, ENVELOPE_MAX_BYTES, ROOT_KEY_COUNT};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

// ------------------------------------------------------------------ keys

/// A fresh 32-byte seed from the operating system.
fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)
        .map_err(|e| anyhow!("the operating system gave no randomness: {e}"))?;
    Ok(seed)
}

/// The text of a secret key file: the seed, base64, one line.
fn secret_text(seed: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("{}\n", STANDARD.encode(seed)))
}

/// Read a secret key file's text. The error never repeats the text: it is a secret.
pub fn parse_secret(text: &str) -> Result<SigningKey> {
    let bad = || anyhow!("not a feed key file: expected one line holding 32 bytes, base64-encoded");
    let bytes = Zeroizing::new(STANDARD.decode(text.trim()).map_err(|_| bad())?);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(bytes.as_slice().try_into().map_err(|_| bad())?);
    Ok(SigningKey::from_bytes(&seed))
}

/// A public key as text, for the keys document and for the trust anchor compiled into a build.
pub fn public_text(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().as_bytes())
}

/// Read a public key given on the command line.
pub fn parse_public(text: &str) -> Result<[u8; 32]> {
    let bad = || anyhow!("a public key must be 32 bytes, base64-encoded");
    let bytes = STANDARD.decode(text.trim()).map_err(|_| bad())?;
    bytes.as_slice().try_into().map_err(|_| bad())
}

// ------------------------------------------------------------------ files

/// Whether `path` is, or would be, inside the repository at `root`. The directory it is in must exist.
fn inside_repository(root: &Path, path: &Path) -> Result<bool> {
    let root = std::fs::canonicalize(root).context("could not resolve the repository root")?;
    let resolved = if path.exists() {
        std::fs::canonicalize(path)?
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = std::fs::canonicalize(parent)
            .with_context(|| format!("the directory for {} does not exist", path.display()))?;
        parent.join(
            path.file_name()
                .ok_or_else(|| anyhow!("{} names no file", path.display()))?,
        )
    };
    Ok(resolved.starts_with(root))
}

/// Create `path`, failing if it exists. `private` asks for owner-only access where the platform has it.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path).with_context(|| {
        format!(
            "could not create {} (it may already exist; this never overwrites)",
            path.display()
        )
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Read a private key file, refusing one that lives in the repository.
fn read_key_file(root: &Path, path: &Path) -> Result<SigningKey> {
    if inside_repository(root, path)? {
        bail!(
            "refusing to use {}: it is inside the repository, and private keys never belong there",
            path.display()
        );
    }
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("could not read the key file {}", path.display()))?,
    );
    parse_secret(&text).with_context(|| format!("in {}", path.display()))
}

// ------------------------------------------------------------------ arguments

/// `--flag value` pairs; every option takes exactly one value, and an unknown option is an error.
fn parse_flags(args: &[String], allowed: &[&str]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        if !allowed.contains(&flag.as_str()) {
            bail!("unknown option {flag}");
        }
        let value = rest.next().ok_or_else(|| anyhow!("{flag} needs a value"))?;
        out.push((flag.clone(), value.clone()));
    }
    Ok(out)
}

fn values<'a>(flags: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    flags
        .iter()
        .filter(|(flag, _)| flag == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

fn single<'a>(flags: &'a [(String, String)], name: &str) -> Result<Option<&'a str>> {
    match values(flags, name).as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => bail!("{name} was given more than once"),
    }
}

fn required<'a>(flags: &'a [(String, String)], name: &str) -> Result<&'a str> {
    single(flags, name)?.ok_or_else(|| anyhow!("{name} is required"))
}

// ------------------------------------------------------------------ feed-keygen

/// `feed-keygen --out <file>`
pub fn run_keygen(root: &Path, args: &[String]) -> Result<()> {
    let flags = parse_flags(args, &["--out"])?;
    let out = Path::new(required(&flags, "--out")?);
    if inside_repository(root, out)? {
        bail!(
            "refusing to write a private key inside the repository ({}). Put it on offline media.",
            out.display()
        );
    }
    let seed = random_seed()?;
    write_new(out, secret_text(&seed).as_bytes(), true)?;
    let key = SigningKey::from_bytes(&seed);
    println!(
        "secret key written to {} (never printed, never shared)",
        out.display()
    );
    println!("public key: {}", public_text(&key));
    println!();
    println!("Keep the secret file on offline, encrypted media. A root key must never touch a");
    println!("networked machine (ADR-0002 §8). Anyone with the file can sign as this key.");
    Ok(())
}

// ------------------------------------------------------------------ feed-sign

/// Everything a signature needs and a check consults.
pub struct SignJob {
    pub document: Document,
    pub payload: Vec<u8>,
    pub signers: Vec<SigningKey>,
    /// The three root public keys compiled into the build the document is for.
    pub roots: [[u8; 32]; ROOT_KEY_COUNT],
    pub min_keys_version: u64,
    /// The published, root-signed keys document: required to sign a feed.
    pub keys_envelope: Option<Vec<u8>>,
}

/// What was signed.
#[derive(Debug)]
pub struct Signed {
    pub envelope: Vec<u8>,
    pub signatures: usize,
    pub summary: String,
}

/// Sign `job.payload` and prove the client would accept the result at `now`.
pub fn sign(job: &SignJob, now: u64) -> Result<Signed> {
    if job.signers.is_empty() {
        bail!("no signing key was given");
    }
    let mut seen = Vec::new();
    for signer in &job.signers {
        let public = signer.verifying_key();
        if seen.contains(&public) {
            bail!("the same key was given twice; a key counts once");
        }
        seen.push(public);
    }
    let trust = FeedTrust::new(job.roots, job.min_keys_version)
        .map_err(|e| anyhow!("the root keys given are not usable: {e}"))?;
    let refused = |e: FeedError| anyhow!("the client would refuse this {}: {e}", job.document);
    let signers: Vec<&SigningKey> = job.signers.iter().collect();

    let (envelope, summary) = match job.document {
        Document::Keys => {
            let document = check_keys_payload(&job.payload, &trust).map_err(refused)?;
            let envelope = seal(payload_type(Document::Keys), &job.payload, &signers);
            rehearse_keys(&trust, &envelope, now).map_err(refused)?;
            (
                envelope,
                format!(
                    "keys document version {}, delegating {} signing key(s)",
                    document.keys_version,
                    document.signing_keys.len()
                ),
            )
        }
        Document::Feed => {
            let keys = job.keys_envelope.as_deref().ok_or_else(|| {
                anyhow!(
                    "a feed is signed against the published keys document: give --keys-envelope"
                )
            })?;
            let document = check_feed_payload(&job.payload).map_err(refused)?;
            let envelope = seal(payload_type(Document::Feed), &job.payload, &signers);
            rehearse_feed(&trust, keys, &envelope, now).map_err(refused)?;
            (
                envelope,
                format!(
                    "profile feed sequence {} under keys version {}, {} profile(s)",
                    document.sequence,
                    document.keys_version,
                    document.profiles.len()
                ),
            )
        }
    };
    // (An envelope over the client's size cap is refused by the rehearsal above, which is the client's
    // own check, so there is no second one here to drift from it.)
    Ok(Signed {
        envelope,
        signatures: job.signers.len(),
        summary,
    })
}

fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() > ENVELOPE_MAX_BYTES {
        bail!(
            "{} is larger than any envelope a client accepts",
            path.display()
        );
    }
    Ok(bytes)
}

/// `feed-sign --document keys|feed --payload <file> --key <file>... --root-public <b64> x3
///  [--min-keys-version N] [--keys-envelope <file>] --out <file>`
pub fn run_sign(root: &Path, args: &[String]) -> Result<()> {
    let flags = parse_flags(
        args,
        &[
            "--document",
            "--payload",
            "--key",
            "--root-public",
            "--min-keys-version",
            "--keys-envelope",
            "--out",
        ],
    )?;
    let document = match required(&flags, "--document")? {
        "keys" => Document::Keys,
        "feed" => Document::Feed,
        other => bail!("--document must be 'keys' or 'feed', not '{other}'"),
    };
    let payload = read_capped(Path::new(required(&flags, "--payload")?))?;
    let out = Path::new(required(&flags, "--out")?);

    let signers = values(&flags, "--key")
        .into_iter()
        .map(|path| read_key_file(root, Path::new(path)))
        .collect::<Result<Vec<_>>>()?;

    let roots: Vec<[u8; 32]> = values(&flags, "--root-public")
        .into_iter()
        .map(parse_public)
        .collect::<Result<_>>()?;
    let roots: [[u8; 32]; ROOT_KEY_COUNT] = roots.try_into().map_err(|_| {
        anyhow!(
            "--root-public must be given exactly {ROOT_KEY_COUNT} times (the build's root keys)"
        )
    })?;
    let min_keys_version = match single(&flags, "--min-keys-version")? {
        None => 1,
        Some(text) => text
            .parse()
            .map_err(|_| anyhow!("--min-keys-version must be a whole number"))?,
    };
    let keys_envelope = single(&flags, "--keys-envelope")?
        .map(|path| read_capped(Path::new(path)))
        .transpose()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow!("the system clock is before 1970"))?
        .as_secs();
    let signed = sign(
        &SignJob {
            document,
            payload,
            signers,
            roots,
            min_keys_version,
            keys_envelope,
        },
        now,
    )?;
    write_new(out, &signed.envelope, false)?;
    println!(
        "signed {} with {} key(s); wrote {} ({} bytes)",
        signed.summary,
        signed.signatures,
        out.display(),
        signed.envelope.len()
    );
    println!("checked as a fresh client would at the current time: it accepts this envelope");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const NOW: u64 = 1_757_635_200;
    const DAY: u64 = 86_400;
    /// FEED-15: the public key of the independent known-answer vector's first root (seed `[1; 32]`).
    const KAT_ROOT_1_PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn roots() -> [[u8; 32]; ROOT_KEY_COUNT] {
        [1u8, 2, 3].map(|n| key(n).verifying_key().to_bytes())
    }

    fn keys_payload_at(now: u64, delegate: &SigningKey) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys_version": 1, "issued_at": now - DAY, "expires_at": now + 300 * DAY,
            "signing_threshold": 1,
            "signing_keys": [{
                "public_key": public_text(delegate),
                "not_before": now - DAY, "not_after": now + 90 * DAY,
            }],
        }))
        .unwrap()
    }

    fn keys_payload(delegate: &SigningKey) -> Vec<u8> {
        keys_payload_at(NOW, delegate)
    }

    fn feed_payload(keys_version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys_version": keys_version, "sequence": 7,
            "issued_at": NOW - 3600, "expires_at": NOW + 14 * DAY,
            "profiles": [{
                "profile_id": "awg-default", "kind": "amnezia_wg",
                "client": { "jc": 6, "jmin": 40, "jmax": 90 },
                "endpoint": { "s1": 72, "s2": 41, "h1": 1873209, "h2": 5520871, "h3": 90121, "h4": 334210 },
            }],
        }))
        .unwrap()
    }

    fn keys_job(signers: Vec<SigningKey>, payload: Vec<u8>) -> SignJob {
        SignJob {
            document: Document::Keys,
            payload,
            signers,
            roots: roots(),
            min_keys_version: 1,
            keys_envelope: None,
        }
    }

    fn signed_keys_envelope() -> Vec<u8> {
        sign(
            &keys_job(vec![key(1), key(2)], keys_payload(&key(100))),
            NOW,
        )
        .unwrap()
        .envelope
    }

    fn feed_job(signers: Vec<SigningKey>, keys_version: u64) -> SignJob {
        SignJob {
            document: Document::Feed,
            payload: feed_payload(keys_version),
            signers,
            roots: roots(),
            min_keys_version: 1,
            keys_envelope: Some(signed_keys_envelope()),
        }
    }

    // ---------------------------------------------------------------- keys

    #[test]
    fn a_key_file_round_trips_and_derives_the_public_key_the_known_answer_names() {
        let seed = [1u8; 32];
        let text = secret_text(&seed);
        assert!(text.ends_with('\n'));
        let key = parse_secret(&text).unwrap();
        assert_eq!(public_text(&key), KAT_ROOT_1_PUBLIC_KEY);
        assert_eq!(key.to_bytes(), seed);
    }

    #[test]
    fn a_damaged_key_file_is_refused_without_repeating_it() {
        let sentinel = "SENTINEL-do-not-echo";
        for bad in [
            String::new(),
            sentinel.to_owned(),
            format!("{}\n{sentinel}", STANDARD.encode([1u8; 32])),
            STANDARD.encode([1u8; 31]),
            STANDARD.encode([1u8; 33]),
            "!!!!".to_owned(),
            // A valid key broken across two lines, or with a space inside: one line, strictly.
            {
                let line = STANDARD.encode([1u8; 32]);
                format!("{}\n{}", &line[..20], &line[20..])
            },
            {
                let line = STANDARD.encode([1u8; 32]);
                format!("{} {}", &line[..20], &line[20..])
            },
        ] {
            let error = parse_secret(&bad).unwrap_err().to_string();
            assert!(!error.contains(sentinel), "{error}");
            assert!(error.contains("32 bytes"), "{error}");
        }
    }

    #[test]
    fn generated_seeds_differ() {
        let (a, b) = (random_seed().unwrap(), random_seed().unwrap());
        assert_ne!(*a, *b);
        assert_ne!(*a, [0u8; 32]);
    }

    #[test]
    fn public_keys_are_read_strictly() {
        assert_eq!(
            parse_public(KAT_ROOT_1_PUBLIC_KEY).unwrap(),
            key(1).verifying_key().to_bytes()
        );
        for bad in ["", "not base64!", &STANDARD.encode([1u8; 31])] {
            assert!(parse_public(bad).is_err(), "{bad:?}");
        }
    }

    // ---------------------------------------------------------------- files

    #[test]
    fn nothing_is_written_inside_the_repository() {
        let repo = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(inside_repository(repo.path(), &repo.path().join("root-1.key")).unwrap());
        let nested = repo.path().join("keys");
        std::fs::create_dir(&nested).unwrap();
        assert!(inside_repository(repo.path(), &nested.join("root-1.key")).unwrap());
        assert!(!inside_repository(repo.path(), &elsewhere.path().join("root-1.key")).unwrap());
        // A directory that does not exist is an error, not a pass.
        assert!(inside_repository(repo.path(), &elsewhere.path().join("no/such/dir/k")).is_err());
    }

    #[test]
    fn keygen_writes_a_usable_key_outside_the_repository_and_never_overwrites() {
        let repo = tempfile::tempdir().unwrap();
        let media = tempfile::tempdir().unwrap();
        let out = media.path().join("root-1.key");
        let args = vec!["--out".to_owned(), out.display().to_string()];
        run_keygen(repo.path(), &args).unwrap();
        let key = read_key_file(repo.path(), &out).unwrap();
        assert_eq!(key.to_bytes().len(), 32);
        // A second run must not replace the first key.
        let before = std::fs::read(&out).unwrap();
        assert!(run_keygen(repo.path(), &args).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), before);
    }

    #[test]
    fn keygen_refuses_a_path_inside_the_repository_and_writes_nothing() {
        let repo = tempfile::tempdir().unwrap();
        let out = repo.path().join("root-1.key");
        let error = run_keygen(
            repo.path(),
            &["--out".to_owned(), out.display().to_string()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("inside the repository"));
        assert!(!out.exists());
    }

    #[test]
    fn a_key_stored_inside_the_repository_is_not_used_to_sign() {
        let repo = tempfile::tempdir().unwrap();
        let stored = repo.path().join("oops.key");
        std::fs::write(&stored, secret_text(&[1u8; 32]).as_bytes()).unwrap();
        let error = read_key_file(repo.path(), &stored).unwrap_err();
        assert!(error.to_string().contains("inside the repository"));
    }

    #[test]
    fn options_are_parsed_strictly() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(parse_flags(&args(&["--nope", "x"]), &["--out"]).is_err());
        assert!(parse_flags(&args(&["--out"]), &["--out"]).is_err());
        let flags = parse_flags(&args(&["--out", "a", "--out", "b"]), &["--out"]).unwrap();
        assert_eq!(values(&flags, "--out"), ["a", "b"]);
        assert!(single(&flags, "--out").is_err());
        assert!(required(&flags, "--missing").is_err());
    }

    // ---------------------------------------------------------------- signing

    #[test]
    fn two_roots_sign_a_keys_document_the_client_accepts_and_the_bytes_are_stable() {
        let job = || keys_job(vec![key(1), key(2)], keys_payload(&key(100)));
        let (a, b) = (sign(&job(), NOW).unwrap(), sign(&job(), NOW).unwrap());
        assert_eq!(a.envelope, b.envelope);
        assert_eq!(a.signatures, 2);
        assert!(a.summary.contains("version 1"), "{}", a.summary);
        let value: Value = serde_json::from_slice(&a.envelope).unwrap();
        assert_eq!(value["signatures"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn one_root_is_refused_because_the_client_would_refuse_it() {
        let error = sign(&keys_job(vec![key(1)], keys_payload(&key(100))), NOW).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("would refuse"), "{text}");
        assert!(text.contains("threshold"), "{text}");
    }

    #[test]
    fn a_key_that_is_not_a_root_cannot_make_a_keys_document() {
        let error = sign(
            &keys_job(vec![key(1), key(50)], keys_payload(&key(100))),
            NOW,
        )
        .unwrap_err();
        assert!(error.to_string().contains("threshold"), "{error}");
    }

    #[test]
    fn the_same_key_twice_is_refused_before_anything_is_signed() {
        let error = sign(
            &keys_job(vec![key(1), key(1)], keys_payload(&key(100))),
            NOW,
        )
        .unwrap_err();
        assert!(error.to_string().contains("twice"), "{error}");
        assert!(sign(&keys_job(vec![], keys_payload(&key(100))), NOW).is_err());
    }

    #[test]
    fn a_payload_the_client_refuses_is_never_signed() {
        // A root key delegated as a signing key, a document that is not one, and an incomplete one.
        for payload in [
            keys_payload(&key(1)),
            b"not json".to_vec(),
            br#"{"keys_version":1}"#.to_vec(),
        ] {
            let error = sign(&keys_job(vec![key(1), key(2)], payload), NOW).unwrap_err();
            assert!(error.to_string().contains("would refuse"), "{error}");
        }
    }

    #[test]
    fn a_document_that_has_expired_is_not_signed() {
        let error = sign(
            &keys_job(vec![key(1), key(2)], keys_payload(&key(100))),
            NOW + 400 * DAY,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not valid at this time"),
            "{error}"
        );
    }

    #[test]
    fn a_root_set_that_is_unusable_is_refused() {
        let mut job = keys_job(vec![key(1), key(2)], keys_payload(&key(100)));
        job.roots = [roots()[0], roots()[0], roots()[1]];
        assert!(sign(&job, NOW)
            .unwrap_err()
            .to_string()
            .contains("not usable"));
    }

    #[test]
    fn the_delegated_key_signs_a_feed_the_client_applies() {
        let signed = sign(&feed_job(vec![key(100)], 1), NOW).unwrap();
        assert!(signed.summary.contains("sequence 7"), "{}", signed.summary);
        assert!(
            signed.summary.contains("keys version 1"),
            "{}",
            signed.summary
        );
    }

    #[test]
    fn a_feed_signed_by_anyone_the_keys_document_does_not_list_is_refused() {
        // A stranger, and a root: roots sign keys documents only.
        for signer in [key(101), key(1)] {
            let error = sign(&feed_job(vec![signer], 1), NOW).unwrap_err();
            let text = error.to_string();
            assert!(
                text.contains("would refuse") && text.contains("threshold"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_feed_cannot_be_signed_without_the_published_keys_document() {
        let mut job = feed_job(vec![key(100)], 1);
        job.keys_envelope = None;
        assert!(sign(&job, NOW)
            .unwrap_err()
            .to_string()
            .contains("--keys-envelope"));
    }

    #[test]
    fn a_feed_under_another_keys_version_is_refused() {
        let error = sign(&feed_job(vec![key(100)], 2), NOW).unwrap_err();
        assert!(
            error.to_string().contains("other than the accepted one"),
            "{error}"
        );
    }

    #[test]
    fn the_whole_command_signs_from_files_and_never_overwrites_its_output() {
        let repo = tempfile::tempdir().unwrap();
        let media = tempfile::tempdir().unwrap();
        let path = |name: &str| media.path().join(name);
        for (name, seed) in [("root-1.key", 1u8), ("root-2.key", 2)] {
            std::fs::write(path(name), secret_text(&[seed; 32]).as_bytes()).unwrap();
        }
        // The command signs against the real clock, so the document's dates must be current.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(path("keys.json"), keys_payload_at(now, &key(100))).unwrap();

        let arg = |s: &str| s.to_owned();
        let mut args = vec![
            arg("--document"),
            arg("keys"),
            arg("--payload"),
            path("keys.json").display().to_string(),
            arg("--out"),
            path("keys.envelope").display().to_string(),
        ];
        for name in ["root-1.key", "root-2.key"] {
            args.extend([arg("--key"), path(name).display().to_string()]);
        }
        for n in [1u8, 2, 3] {
            args.extend([arg("--root-public"), public_text(&key(n))]);
        }

        run_sign(repo.path(), &args).unwrap();
        let first = std::fs::read(path("keys.envelope")).unwrap();
        assert!(!first.is_empty());
        // Running it again must not replace what was written.
        assert!(run_sign(repo.path(), &args).is_err());
        assert_eq!(std::fs::read(path("keys.envelope")).unwrap(), first);
    }

    #[test]
    fn a_file_larger_than_any_envelope_is_not_read_in() {
        let media = tempfile::tempdir().unwrap();
        let big = media.path().join("big.json");
        std::fs::write(&big, vec![b' '; ENVELOPE_MAX_BYTES + 1]).unwrap();
        assert!(read_capped(&big).is_err());
        let fits = media.path().join("fits.json");
        std::fs::write(&fits, vec![b' '; ENVELOPE_MAX_BYTES]).unwrap();
        assert_eq!(read_capped(&fits).unwrap().len(), ENVELOPE_MAX_BYTES);
    }

    #[test]
    fn an_oversized_document_is_refused_by_the_clients_own_check() {
        // Valid JSON padded past the cap: the rehearsal (the client's parser) says no.
        let mut payload = keys_payload(&key(100));
        payload.extend(vec![b' '; ENVELOPE_MAX_BYTES]);
        let error = sign(&keys_job(vec![key(1), key(2)], payload), NOW).unwrap_err();
        assert!(error.to_string().contains("would refuse"), "{error}");
    }

    #[test]
    fn the_command_needs_exactly_three_root_keys() {
        let repo = tempfile::tempdir().unwrap();
        let media = tempfile::tempdir().unwrap();
        let payload = media.path().join("p.json");
        std::fs::write(&payload, b"{}").unwrap();
        let args: Vec<String> = [
            "--document",
            "keys",
            "--payload",
            &payload.display().to_string(),
            "--out",
            &media.path().join("o").display().to_string(),
            "--root-public",
            &public_text(&key(1)),
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert!(run_sign(repo.path(), &args)
            .unwrap_err()
            .to_string()
            .contains("exactly"));
    }
}
