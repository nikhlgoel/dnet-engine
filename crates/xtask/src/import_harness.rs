//! `cargo xtask import-harness-endpoint` — put the simulated harness endpoint into the saved
//! configuration and the secret store, so the Connect orchestrator (T126) has something to connect to.
//!
//! **Developer tooling for the simulated harness, not a product feature.** The product creates
//! endpoints through provisioning (T093) or a user import (T097), over the IPC boundary. This reads
//! the client parameter files the harness endpoint writes (`awg-client.json`, `hy2-client.json`,
//! `reality-client.json`, test keys only) and does what the product will do with their contents:
//! seal them in the machine secret store and record an endpoint that points at them.
//!
//! ```text
//! cargo xtask import-harness-endpoint --host <ip-or-name> [--label harness] [--replace]
//!                                     [--state-dir <dir>] [--dry-run]
//!                                     [--config <file>] [--secrets-dir <dir>]
//! ```
//!
//! - `--host` is required and has no default: a silent loopback default would make the routing-loop
//!   gate meaningless. A loopback host is accepted, with a warning, for the prober's tests.
//! - A real import writes under `%PROGRAMDATA%\DNet Engine\state` and so needs an **elevated** shell.
//!   It refuses before touching anything otherwise: an unelevated attempt would leave behind a
//!   directory owned by the user, which the service (rightly) refuses to trust.
//! - `--dry-run` reads and validates everything and prints what would change; it writes nothing and
//!   needs no elevation.
//! - It never prints a secret, and its errors name a file and a field, never a value.
//! - The secret is written first and the configuration second, so the configuration never names
//!   credentials that are not there. If the second write fails, a newly written secret is removed.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dnet_config::amneziawg::{ObfuscationParams, PrivateKey};
use dnet_config::credentials::{
    parse_spki_sha256_hex, AmneziaWgCredentials, EndpointCredentials, Hysteria2Bundle,
    RealityBundle,
};
use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use dnet_config::persist::{ConfigStore, LoadedConfig, MemoryStateFile};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::secret_store::{MemorySecretStore, SecretKey, SecretStore};
use dnet_config::tls::ServerTrust;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::ids::EndpointId;
use dnet_core::origin::Origin;
use serde::de::DeserializeOwned;
use serde::Deserialize;

const DEFAULT_LABEL: &str = "harness";

// ------------------------------------------------------------------ the harness files

// `Debug` is deliberately not derived: these hold secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwgFile {
    client_private_key_hex: String,
    server_public_key_hex: String,
    client_address: Ipv4Addr,
    prefix_len: u8,
    listen_port: u16,
    origin_url: String,
    obfuscation: ObfuscationFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfuscationFile {
    jc: u32,
    jmin: u32,
    jmax: u32,
    s1: u32,
    s2: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2File {
    server_port: u16,
    server_name: String,
    spki_sha256_hex: String,
    auth_password: String,
    obfs_password: String,
    origin_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityFile {
    server_port: u16,
    target_domain: String,
    public_key: String,
    short_id: String,
    uuid: String,
    flow: String,
    origin_url: String,
}

/// Read one harness file, if it is there. An error names the file and where it is wrong, never a
/// value: serde can quote the offending text, and these files are full of secrets.
fn read_file<T: DeserializeOwned>(dir: &Path, name: &str) -> Result<Option<T>> {
    let path = dir.join(name);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("cannot read {}: {}", path.display(), e.kind())),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        use serde_json::error::Category;
        let kind = match e.classify() {
            Category::Io => "unreadable",
            Category::Syntax => "not valid JSON",
            Category::Data => "a field is missing, unknown or of the wrong type",
            Category::Eof => "ends unexpectedly",
        };
        anyhow!("{name}: {kind} (line {}, column {})", e.line(), e.column())
    })
}

/// The credentials in the harness files that exist in `dir`, and the names of the profiles found.
/// A harness that serves only some of the transports imports only those.
pub fn read_credentials(dir: &Path) -> Result<(EndpointCredentials, Vec<&'static str>)> {
    let awg: Option<AwgFile> = read_file(dir, "awg-client.json")?;
    let hy2: Option<Hy2File> = read_file(dir, "hy2-client.json")?;
    let reality: Option<RealityFile> = read_file(dir, "reality-client.json")?;

    let mut found = Vec::new();
    let mut bundle = EndpointCredentials::default();
    // Each file names the origin the harness serves; they describe one harness, so they must agree.
    let mut origins: Vec<(&'static str, String)> = Vec::new();

    if let Some(a) = awg {
        found.push("AmneziaWG");
        origins.push(("awg-client.json", a.origin_url.clone()));
        bundle.amneziawg = Some(AmneziaWgCredentials {
            client_private_key: PrivateKey::new(a.client_private_key_hex),
            server_public_key: a.server_public_key_hex,
            client_address: a.client_address,
            prefix_len: a.prefix_len,
            obfuscation: ObfuscationParams {
                jc: a.obfuscation.jc,
                jmin: a.obfuscation.jmin,
                jmax: a.obfuscation.jmax,
                s1: a.obfuscation.s1,
                s2: a.obfuscation.s2,
                h1: a.obfuscation.h1,
                h2: a.obfuscation.h2,
                h3: a.obfuscation.h3,
                h4: a.obfuscation.h4,
            },
            server_port: a.listen_port,
        });
    }
    if let Some(h) = hy2 {
        found.push("Hysteria 2");
        origins.push(("hy2-client.json", h.origin_url.clone()));
        let pin = parse_spki_sha256_hex(&h.spki_sha256_hex).ok_or_else(|| {
            anyhow!("hy2-client.json: spki_sha256_hex is not 64 lowercase hex digits")
        })?;
        bundle.hysteria2 = Some(Hysteria2Bundle {
            server_port: h.server_port,
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(h.auth_password),
                obfs_password: Secret::new(h.obfs_password),
            },
            endpoint: Hysteria2EndpointParams {
                // The harness server is configured with Salamander (hy2-server.sh).
                obfs: Hysteria2Obfs::Salamander,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: h.server_name,
                    spki_sha256: pin,
                },
            },
        });
    }
    if let Some(r) = reality {
        found.push("VLESS+REALITY");
        origins.push(("reality-client.json", r.origin_url.clone()));
        let flow = match r.flow.as_str() {
            "xtls-rprx-vision" => VlessFlow::Vision,
            "none" | "" => VlessFlow::None,
            _ => bail!("reality-client.json: flow is not 'xtls-rprx-vision' or 'none'"),
        };
        bundle.reality = Some(RealityBundle {
            server_port: r.server_port,
            credentials: RealityCredentials {
                uuid: Secret::new(r.uuid),
                short_id: Secret::new(r.short_id),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse(&r.target_domain)
                    .map_err(|_| anyhow!("reality-client.json: target_domain was refused"))?,
                public_key: RealityPublicKey::parse(&r.public_key)
                    .map_err(|_| anyhow!("reality-client.json: public_key was refused"))?,
                flow,
            },
        });
    }

    bundle.measure_origin = agreed_origin(&origins)?;

    if found.is_empty() {
        bail!(
            "no harness client files in {} (looked for awg-client.json, hy2-client.json and \
             reality-client.json). Start the harness endpoint first: `cd testing/harness && \
             docker compose up -d`, or the WSL lab",
            dir.display()
        );
    }
    Ok((bundle, found))
}

/// The one origin the files agree on. Disagreement is an error that names the files, not a pick:
/// the files come from one harness, so a mismatch means one of them is from another run.
fn agreed_origin(origins: &[(&'static str, String)]) -> Result<Option<Origin>> {
    let mut agreed: Option<(&'static str, Origin)> = None;
    for (file, url) in origins {
        let origin =
            Origin::parse(url).map_err(|e| anyhow!("{file}: origin_url was refused: {e}"))?;
        match &agreed {
            Some((first, existing)) if existing != &origin => {
                bail!("{first} and {file} name different origins; they must come from one harness")
            }
            Some(_) => {}
            None => agreed = Some((file, origin)),
        }
    }
    Ok(agreed.map(|(_, origin)| origin))
}

// ------------------------------------------------------------------ applying it

/// What an import did (or, for a dry run, would do). Carries no secret.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub id: EndpointId,
    pub label: String,
    pub host: String,
    pub replaced: bool,
    pub credential_key: String,
}

/// Record the endpoint and its credentials.
///
/// Reads the saved configuration first and **refuses to touch anything** if it was itself refused
/// (it may be the only copy of the user's endpoints). The secret is written before the
/// configuration; if the configuration cannot be written, a secret that was new is removed again.
pub fn apply(
    host: &str,
    label: &str,
    credentials: &EndpointCredentials,
    replace: bool,
    config: &ConfigStore,
    secrets: &dyn SecretStore,
) -> Result<Outcome> {
    let mut saved = match config.load() {
        Ok(Some(saved)) => saved,
        Ok(None) => LoadedConfig::default(),
        Err(e) => bail!("{e}. Nothing was changed; correct or remove that file first"),
    };

    let existing = saved.endpoints.iter().position(|e| e.label() == label);
    if existing.is_some() && !replace {
        bail!("an endpoint named '{label}' already exists; pass --replace to update it");
    }
    // Replacing keeps the endpoint's identity, so its credentials are overwritten in place.
    let (id, replaced) = match existing {
        Some(i) => (saved.endpoints[i].id(), true),
        None => (EndpointId::new(), false),
    };
    let key = SecretKey::for_endpoint(id);

    // The port on the endpoint is not used to connect (each profile has its own, in the
    // credentials); it is the first profile's, so the listing shows something real.
    let display_port = credentials
        .amneziawg
        .as_ref()
        .map(|a| a.server_port)
        .or_else(|| credentials.hysteria2.as_ref().map(|h| h.server_port))
        .or_else(|| credentials.reality.as_ref().map(|r| r.server_port))
        .ok_or_else(|| anyhow!("there are no credentials to import"))?;
    let endpoint = Endpoint::new(
        id,
        label,
        EndpointAddress::new(host, display_port).map_err(|e| anyhow!("--host: {e}"))?,
        EndpointOrigin::Manual,
        key.credential_ref(),
    )
    .map_err(|e| anyhow!("--label: {e}"))?;

    match existing {
        Some(i) => saved.endpoints[i] = endpoint,
        None => saved.endpoints.push(endpoint),
    }

    // Everything is checked before anything is written.
    dnet_config::persist::encode_config(&saved).map_err(|e| anyhow!("{e}"))?;
    credentials
        .to_plaintext_json()
        .map(drop)
        .map_err(|e| anyhow!("{e}"))?;

    secrets
        .put(&key, credentials)
        .map_err(|e| anyhow!("could not store the credentials: {e}"))?;
    if let Err(e) = config.save_config(&saved) {
        if !replaced {
            // Best effort: the secret has no endpoint, so it is only clutter.
            let _ = secrets.delete(&key);
        }
        bail!("could not save the configuration: {e}");
    }

    Ok(Outcome {
        id,
        label: label.to_owned(),
        host: host.to_owned(),
        replaced,
        credential_key: key.as_str().to_owned(),
    })
}

// ------------------------------------------------------------------ the command

struct Args {
    host: String,
    label: String,
    state_dir: Option<PathBuf>,
    replace: bool,
    dry_run: bool,
    // Read only where the stores live under %PROGRAMDATA% (Windows); parsed everywhere so the
    // command line is the same on every platform.
    #[cfg_attr(not(windows), allow(dead_code))]
    config: Option<PathBuf>,
    #[cfg_attr(not(windows), allow(dead_code))]
    secrets_dir: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut host = None;
    let mut label = DEFAULT_LABEL.to_owned();
    let mut state_dir = None;
    let mut replace = false;
    let mut dry_run = false;
    let mut config = None;
    let mut secrets_dir = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = |what: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| anyhow!("{what} needs a value"))
        };
        match flag.as_str() {
            "--host" => host = Some(value("--host")?),
            "--label" => label = value("--label")?,
            "--state-dir" => state_dir = Some(PathBuf::from(value("--state-dir")?)),
            "--config" => config = Some(PathBuf::from(value("--config")?)),
            "--secrets-dir" => secrets_dir = Some(PathBuf::from(value("--secrets-dir")?)),
            "--replace" => replace = true,
            "--dry-run" => dry_run = true,
            other => bail!("unknown option '{other}'"),
        }
    }
    Ok(Args {
        host: host.ok_or_else(|| {
            anyhow!(
                "--host is required: the address the harness endpoint is reached at \
                 (203.0.113.10 for the WSL lab; 127.0.0.1 for the local Docker harness, which \
                 cannot exercise the routing-loop gate)"
            )
        })?,
        label,
        state_dir,
        replace,
        dry_run,
        config,
        secrets_dir,
    })
}

pub fn run(root: &Path, args: &[String]) -> Result<()> {
    let args = parse_args(args)?;
    let state_dir = args
        .state_dir
        .clone()
        .unwrap_or_else(|| root.join("testing").join("harness").join(".state"));

    let (credentials, found) = read_credentials(&state_dir)
        .with_context(|| format!("reading the harness endpoint in {}", state_dir.display()))?;
    if let Ok(ip) = args.host.parse::<IpAddr>() {
        if ip.is_loopback() {
            eprintln!(
                "warning: {ip} is loopback. Loopback traffic never enters a tunnel, so this endpoint \
                 cannot exercise the routing-loop gate; it is only good for the prober's tests."
            );
        }
    }

    if args.dry_run {
        return dry_run(&args, &credentials, &found);
    }
    real_run(&args, &credentials, &found)
}

fn dry_run(args: &Args, credentials: &EndpointCredentials, found: &[&'static str]) -> Result<()> {
    // The real configuration if it can be read (it needs elevation), else none: say which.
    let (existing, note) = match existing_config_bytes(args) {
        Ok(bytes) => (bytes, "the saved configuration was read"),
        Err(why) => (None, why),
    };
    let config = ConfigStore::new(Box::new(MemoryStateFile::with_bytes(existing)));
    let secrets = MemorySecretStore::new();
    let outcome = apply(
        &args.host,
        &args.label,
        credentials,
        args.replace,
        &config,
        &secrets,
    )?;
    println!("dry run: nothing was written ({note}).");
    print_outcome(&outcome, found, true);
    Ok(())
}

#[cfg(windows)]
fn existing_config_bytes(args: &Args) -> std::result::Result<Option<Vec<u8>>, &'static str> {
    use dnet_config::persist::{default_config_path, StateFile, TrustedStateFile};
    let path = args.config.clone().unwrap_or_else(default_config_path);
    TrustedStateFile::new(path).read().map_err(|_| {
        "the saved configuration could not be read here, so it was assumed empty; read it elevated"
    })
}

#[cfg(not(windows))]
fn existing_config_bytes(_: &Args) -> std::result::Result<Option<Vec<u8>>, &'static str> {
    Ok(None)
}

#[cfg(windows)]
fn real_run(args: &Args, credentials: &EndpointCredentials, found: &[&'static str]) -> Result<()> {
    use dnet_config::persist::{default_config_path, default_secrets_dir, TrustedStateFile};
    use dnet_config::secret_store::machine_secret_store;

    if !is_elevated() {
        bail!(
            "this writes to %PROGRAMDATA%\\DNet Engine\\state and must run from an elevated \
             PowerShell (Run as administrator). Nothing was changed. Use --dry-run to check the \
             import without elevation"
        );
    }
    let config = ConfigStore::new(Box::new(TrustedStateFile::new(
        args.config.clone().unwrap_or_else(default_config_path),
    )));
    let secrets =
        machine_secret_store(args.secrets_dir.clone().unwrap_or_else(default_secrets_dir));
    let outcome = apply(
        &args.host,
        &args.label,
        credentials,
        args.replace,
        &config,
        &secrets,
    )?;
    print_outcome(&outcome, found, false);
    Ok(())
}

#[cfg(not(windows))]
fn real_run(_: &Args, _: &EndpointCredentials, _: &[&'static str]) -> Result<()> {
    bail!("importing is Windows-only for now (the Linux secret store is T-L10); use --dry-run")
}

fn print_outcome(outcome: &Outcome, found: &[&'static str], dry: bool) {
    let verb = match (dry, outcome.replaced) {
        (true, false) => "would add",
        (true, true) => "would replace",
        (false, false) => "added",
        (false, true) => "replaced",
    };
    println!("{verb} endpoint '{}' at {}", outcome.label, outcome.host);
    println!("  id          {}", outcome.id);
    println!("  profiles    {}", found.join(", "));
    println!(
        "  credentials stored under the key {}",
        outcome.credential_key
    );
}

/// Whether this process runs with an elevated token.
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: plain queries on this process's own token; the handle is closed before returning.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dnet_config::persist::StateFile;

    use super::*;

    const SENTINEL: &str = "SENTINEL-import-3f9a";

    fn awg_json() -> String {
        format!(
            r#"{{"client_private_key_hex":"{}","server_public_key_hex":"{}","client_address":"10.66.0.2",
            "prefix_len":24,"listen_port":51820,"origin_url":"http://203.0.113.80:8080",
            "obfuscation":{{"jc":4,"jmin":40,"jmax":70,"s1":15,"s2":20,"h1":1053421987,
            "h2":2083245612,"h3":3175921403,"h4":4012837465}}}}"#,
            "0".repeat(62) + "ab",
            "0".repeat(62) + "cd",
        )
    }

    fn hy2_json() -> String {
        format!(
            r#"{{"server_port":44443,"server_name":"hy2.harness.test","spki_sha256_hex":"{}",
            "auth_password":"auth-{SENTINEL}","obfs_password":"obfs-{SENTINEL}",
            "origin_url":"http://203.0.113.80:8080"}}"#,
            "9".repeat(64)
        )
    }

    fn reality_json() -> String {
        r#"{"server_port":8443,"target_domain":"harness-target.example.net",
        "public_key":"c2VjcmV0LXB1YmxpYy1rZXktMzItYnl0ZXMhISEhISE","short_id":"0123abcd",
        "uuid":"123e4567-e89b-42d3-a456-426614174000","flow":"xtls-rprx-vision",
        "origin_url":"http://203.0.113.80:8080"}"#
            .to_owned()
    }

    fn state_dir(files: &[(&str, String)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        dir
    }

    fn all_files() -> tempfile::TempDir {
        state_dir(&[
            ("awg-client.json", awg_json()),
            ("hy2-client.json", hy2_json()),
            ("reality-client.json", reality_json()),
        ])
    }

    fn stores() -> (Arc<MemoryStateFile>, MemorySecretStore) {
        (
            Arc::new(MemoryStateFile::default()),
            MemorySecretStore::new(),
        )
    }

    fn config_over(file: &Arc<MemoryStateFile>) -> ConfigStore {
        ConfigStore::new(Box::new(Arc::clone(file)))
    }

    fn credentials() -> EndpointCredentials {
        read_credentials(all_files().path()).unwrap().0
    }

    // ---------------------------------------------------------------- reading the harness

    #[test]
    fn all_three_files_become_one_valid_bundle_with_each_profiles_own_port() {
        let dir = all_files();
        let (bundle, found) = read_credentials(dir.path()).unwrap();

        assert_eq!(found, ["AmneziaWG", "Hysteria 2", "VLESS+REALITY"]);
        assert_eq!(bundle.amneziawg.as_ref().unwrap().server_port, 51820);
        assert_eq!(bundle.hysteria2.as_ref().unwrap().server_port, 44443);
        assert_eq!(bundle.reality.as_ref().unwrap().server_port, 8443);
        // What a store would accept: the same validation the secret store applies.
        bundle.to_plaintext_json().expect("a valid bundle");
    }

    #[test]
    fn the_origin_the_harness_serves_becomes_the_endpoints_measurement_origin() {
        let (bundle, _) = read_credentials(all_files().path()).unwrap();
        let origin = bundle.measure_origin.expect("the origin is imported");
        assert_eq!((origin.host(), origin.port()), ("203.0.113.80", 8080));
    }

    #[test]
    fn files_that_name_different_origins_are_refused_by_name() {
        let other = reality_json().replace("203.0.113.80", "203.0.113.99");
        let dir = state_dir(&[
            ("hy2-client.json", hy2_json()),
            ("reality-client.json", other),
        ]);
        let err = read_credentials(dir.path()).unwrap_err().to_string();
        assert!(err.contains("hy2-client.json"), "{err}");
        assert!(err.contains("reality-client.json"), "{err}");
        assert!(err.contains("different origins"), "{err}");
    }

    #[test]
    fn an_origin_that_cannot_be_used_is_refused_naming_the_file() {
        let bad = hy2_json().replace("http://203.0.113.80:8080", "https://203.0.113.80");
        let dir = state_dir(&[("hy2-client.json", bad)]);
        let err = read_credentials(dir.path()).unwrap_err().to_string();
        assert!(
            err.contains("hy2-client.json") && err.contains("origin_url"),
            "{err}"
        );
    }

    #[test]
    fn a_harness_serving_only_some_transports_imports_only_those() {
        let dir = state_dir(&[("reality-client.json", reality_json())]);
        let (bundle, found) = read_credentials(dir.path()).unwrap();
        assert_eq!(found, ["VLESS+REALITY"]);
        assert!(bundle.amneziawg.is_none() && bundle.hysteria2.is_none());
    }

    #[test]
    fn no_files_is_an_error_that_says_how_to_start_the_harness() {
        let dir = state_dir(&[]);
        let err = read_credentials(dir.path()).unwrap_err().to_string();
        assert!(err.contains("docker compose up"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_refused_and_the_error_quotes_no_value() {
        let tampered = hy2_json().replacen(
            "\"server_port\"",
            &format!("\"{SENTINEL}\":1,\"server_port\""),
            1,
        );
        let dir = state_dir(&[("hy2-client.json", tampered)]);
        let err = read_credentials(dir.path()).unwrap_err().to_string();
        assert!(err.contains("hy2-client.json"), "{err}");
        assert!(!err.contains(SENTINEL), "{err}");
    }

    #[test]
    fn a_wrong_type_does_not_echo_the_secret_beside_it() {
        // `server_port` as text: serde would quote it, and the passwords are in the same file.
        let tampered = hy2_json().replacen("44443", &format!("\"{SENTINEL}\""), 1);
        let dir = state_dir(&[("hy2-client.json", tampered)]);
        let err = read_credentials(dir.path()).unwrap_err().to_string();
        assert!(!err.contains(SENTINEL), "{err}");
    }

    #[test]
    fn bad_values_name_the_file_and_the_field() {
        let cases: [(&str, String, &str); 4] = [
            (
                "hy2-client.json",
                hy2_json().replace(&"9".repeat(64), "abc"),
                "spki_sha256_hex",
            ),
            (
                "reality-client.json",
                reality_json().replace("xtls-rprx-vision", "warp"),
                "flow",
            ),
            (
                "reality-client.json",
                reality_json().replace("harness-target.example.net", "203.0.113.9"),
                "target_domain",
            ),
            (
                "awg-client.json",
                awg_json().replace(&("0".repeat(62) + "cd"), "zz"),
                "server key",
            ),
        ];
        for (name, text, mention) in cases {
            let dir = state_dir(&[(name, text)]);
            let outcome = read_credentials(dir.path())
                .and_then(|(b, _)| b.to_plaintext_json().map(drop).map_err(|e| anyhow!("{e}")));
            let err = outcome.expect_err(name).to_string();
            assert!(err.contains(mention), "{name}: {err}");
        }
    }

    // ---------------------------------------------------------------- applying

    #[test]
    fn an_import_stores_the_credentials_and_records_an_endpoint_that_names_them() {
        let (file, secrets) = stores();
        let outcome = apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config_over(&file),
            &secrets,
        )
        .unwrap();

        assert!(!outcome.replaced);
        let key = SecretKey::for_endpoint(outcome.id);
        assert_eq!(secrets.get(&key).unwrap(), Some(credentials()));

        let saved = config_over(&file).load().unwrap().unwrap();
        assert_eq!(saved.endpoints.len(), 1);
        let endpoint = &saved.endpoints[0];
        assert_eq!(endpoint.id(), outcome.id);
        assert_eq!(endpoint.label(), "harness");
        assert_eq!(endpoint.address().host(), "203.0.113.10");
        assert_eq!(endpoint.credentials().store_key(), key.as_str());
    }

    #[test]
    fn the_saved_configuration_holds_no_secret() {
        let (file, secrets) = stores();
        apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config_over(&file),
            &secrets,
        )
        .unwrap();
        let text = String::from_utf8(file.bytes().unwrap()).unwrap();
        assert!(!text.contains(SENTINEL) && !text.contains("auth-") && !text.contains("0123abcd"));
    }

    #[test]
    fn the_report_carries_no_secret() {
        let (file, secrets) = stores();
        let outcome = apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config_over(&file),
            &secrets,
        )
        .unwrap();
        assert!(!format!("{outcome:?}").contains(SENTINEL));
    }

    #[test]
    fn importing_twice_without_replace_refuses_and_changes_nothing() {
        let (file, secrets) = stores();
        let config = config_over(&file);
        apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();
        let (bytes_before, secrets_before) = (file.bytes(), secrets.len());

        let err = apply(
            "203.0.113.99",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("--replace"), "{err}");
        assert_eq!(file.bytes(), bytes_before);
        assert_eq!(secrets.len(), secrets_before);
    }

    #[test]
    fn replace_keeps_the_identity_and_updates_the_host_and_credentials() {
        let (file, secrets) = stores();
        let config = config_over(&file);
        let first = apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();

        let mut changed = credentials();
        changed.reality = None;
        let second = apply("198.51.100.7", "harness", &changed, true, &config, &secrets).unwrap();

        assert!(second.replaced);
        assert_eq!(second.id, first.id, "the endpoint keeps its identity");
        let saved = config.load().unwrap().unwrap();
        assert_eq!(saved.endpoints.len(), 1);
        assert_eq!(saved.endpoints[0].address().host(), "198.51.100.7");
        assert_eq!(
            secrets.len(),
            1,
            "the credentials were overwritten in place"
        );
        assert_eq!(
            secrets.get(&SecretKey::for_endpoint(first.id)).unwrap(),
            Some(changed)
        );
    }

    #[test]
    fn a_second_label_is_added_beside_the_first() {
        let (file, secrets) = stores();
        let config = config_over(&file);
        apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();
        apply(
            "198.51.100.7",
            "other",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();
        assert_eq!(config.load().unwrap().unwrap().endpoints.len(), 2);
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn a_refused_saved_configuration_is_not_touched() {
        // It may be the only copy of the user's endpoints.
        let garbage = b"{ this is not a configuration".to_vec();
        let file = Arc::new(MemoryStateFile::with_bytes(Some(garbage.clone())));
        let secrets = MemorySecretStore::new();

        let err = apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config_over(&file),
            &secrets,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("Nothing was changed"), "{err}");
        assert_eq!(file.bytes(), Some(garbage));
        assert!(secrets.is_empty());
    }

    #[test]
    fn unrelated_saved_endpoints_and_profile_settings_survive() {
        let (file, secrets) = stores();
        let config = config_over(&file);
        apply(
            "203.0.113.10",
            "keep-me",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();
        // Give a profile a setting, as a user would.
        let mut saved = config.load().unwrap().unwrap();
        let mut params = dnet_core::profile::ProfileParams::new();
        params.set("dns", "9.9.9.9");
        saved.profiles.push(dnet_config::persist::ProfileSettings {
            id: dnet_core::ids::ProfileId::new("awg-default"),
            params,
            brutal: None,
        });
        config.save_config(&saved).unwrap();

        apply(
            "198.51.100.7",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap();

        let after = config.load().unwrap().unwrap();
        assert_eq!(after.endpoints.len(), 2);
        assert_eq!(after.profiles.len(), 1);
        assert_eq!(after.profiles[0].params.get("dns"), Some("9.9.9.9"));
    }

    #[test]
    fn a_bad_host_or_label_is_refused_before_anything_is_written() {
        let long_label = "x".repeat(65);
        for (host, label) in [
            ("http://x", "harness"),
            ("not a host", "harness"),
            ("localhost", "harness"),
            ("203.0.113.10", ""),
            ("203.0.113.10", long_label.as_str()),
        ] {
            let (file, secrets) = stores();
            let result = apply(
                host,
                label,
                &credentials(),
                false,
                &config_over(&file),
                &secrets,
            );
            assert!(result.is_err(), "{host:?}/{label:?}");
            assert!(
                file.bytes().is_none() && secrets.is_empty(),
                "nothing may be written for {host:?}/{label:?}"
            );
        }
    }

    #[test]
    fn if_the_configuration_cannot_be_written_a_new_secret_is_removed_again() {
        struct FailingWrites;
        impl StateFile for FailingWrites {
            fn read(&self) -> Result<Option<Vec<u8>>, String> {
                Ok(None)
            }
            fn write(&self, _: &[u8]) -> Result<(), String> {
                Err("disk full".into())
            }
        }
        let config = ConfigStore::new(Box::new(FailingWrites));
        let secrets = MemorySecretStore::new();

        let err = apply(
            "203.0.113.10",
            "harness",
            &credentials(),
            false,
            &config,
            &secrets,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("disk full"), "{err}");
        // No endpoint was recorded, so no credentials may be left lying around.
        assert!(secrets.is_empty(), "the secret must be rolled back");
    }

    // ---------------------------------------------------------------- arguments

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_host_is_required_and_has_no_default() {
        let err = parse_args(&args(&["--dry-run"])).err().unwrap().to_string();
        assert!(err.contains("--host is required"), "{err}");
    }

    #[test]
    fn options_parse_and_unknown_ones_are_refused() {
        let a = parse_args(&args(&[
            "--host",
            "203.0.113.10",
            "--label",
            "lab",
            "--replace",
            "--dry-run",
        ]))
        .unwrap();
        assert_eq!(
            (a.host.as_str(), a.label.as_str(), a.replace, a.dry_run),
            ("203.0.113.10", "lab", true, true)
        );
        let defaults = parse_args(&args(&["--host", "203.0.113.10"])).unwrap();
        assert_eq!(
            (defaults.label.as_str(), defaults.replace, defaults.dry_run),
            (DEFAULT_LABEL, false, false)
        );
        assert!(parse_args(&args(&["--host", "x", "--nope"])).is_err());
        assert!(
            parse_args(&args(&["--host"])).is_err(),
            "a flag without its value"
        );
    }
}
