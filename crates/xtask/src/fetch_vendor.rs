//! T005 — `cargo xtask fetch-vendor`
//!
//! Produces the three bundled third-party artifacts under `vendor/`:
//!
//! | Artifact       | How it is obtained                                            |
//! |----------------|---------------------------------------------------------------|
//! | Wintun DLL     | Downloaded as the vendor's **signed prebuilt binary**, SHA-256 verified |
//! | Primary core   | **Built from pinned source** with minimal build tags           |
//! | `amneziawg-go` | **Built from pinned source** (upstream publishes no binaries)  |
//!
//! Wintun is never built from source and never extracted from another product: its
//! source is GPLv2 (incompatible with this project's GPLv3) and its prebuilt licence
//! §3(a) forbids extraction. See `docs/adr/0004-vendored-binary-pins.md`.
//!
//! Sources are pinned by **commit SHA**, not tag, because a tag can be moved. Every
//! downloaded byte is verified before use; an unpinned artifact is rejected rather
//! than accepted, because an unpinned download is a supply-chain hole.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// A third-party Go program built from pinned source.
struct GoSource {
    /// Directory name under `vendor/`.
    dest: &'static str,
    repo: &'static str,
    /// Human-readable version, recorded in the build provenance file.
    version: &'static str,
    /// Immutable commit SHA. A tag can be moved; a commit cannot.
    commit: &'static str,
    /// Package path to build, relative to the repository root.
    package: &'static str,
    /// Output executable name.
    binary: &'static str,
    /// Go build tags. Empty means the upstream default.
    ///
    /// For the primary core we select only what the three v1 profiles need, which
    /// takes the binary from 78 MB to a fraction of it (ADR-0004, Finding 3).
    /// Notably `with_wireguard` is **absent**: AmneziaWG is served by a separate
    /// supervised process, so the primary core needs no WireGuard support at all.
    tags: &'static str,
}

const GO_SOURCES: &[GoSource] = &[
    GoSource {
        dest: "primary-core",
        repo: "https://github.com/SagerNet/sing-box",
        version: "v1.14.0",
        commit: "0b8995879f29a9b98ee027bc17b75e101445b238",
        package: "./cmd/sing-box",
        binary: "primary-core.exe",
        // with_quic       -> Hysteria 2 (Profile B)
        // with_utls       -> REALITY fingerprinting (Profile C)
        // with_clash_api  -> the runtime control API dnetd drives the core through
        // with_gvisor     -> TUN network stack
        tags: "with_quic,with_utls,with_clash_api,with_gvisor",
    },
    GoSource {
        dest: "amneziawg-go",
        repo: "https://github.com/amnezia-vpn/amneziawg-go",
        version: "v3.1.20260828",
        commit: "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        package: ".",
        binary: "amneziawg-go.exe",
        tags: "",
    },
];

/// The Wintun signed prebuilt distribution.
struct PrebuiltZip {
    dest: &'static str,
    url: &'static str,
    sha256: &'static str,
    /// (path inside the archive, destination file name)
    extract: &'static [(&'static str, &'static str)],
}

const WINTUN: PrebuiltZip = PrebuiltZip {
    dest: "wintun",
    url: "https://www.wintun.net/builds/wintun-0.14.1.zip",
    sha256: "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
    extract: &[
        ("wintun/bin/amd64/wintun.dll", "wintun.dll"),
        ("wintun/LICENSE.txt", "LICENSE.txt"),
    ],
};

pub fn run(repo_root: &Path) -> Result<()> {
    require_tool("go", &["version"])
        .context("Go toolchain is required to build the vendored transport cores")?;
    require_tool("git", &["--version"]).context("git is required to fetch pinned sources")?;

    fetch_wintun(repo_root)?;
    for src in GO_SOURCES {
        build_go_source(repo_root, src)?;
    }

    println!();
    println!("fetch-vendor: OK");
    println!("  Run `cargo xtask verify-vendor` to confirm licence compliance.");
    Ok(())
}

// ---------------------------------------------------------------- Wintun

fn fetch_wintun(repo_root: &Path) -> Result<()> {
    let dest = repo_root.join("vendor").join(WINTUN.dest);
    let dll = dest.join("wintun.dll");
    if dll.exists() {
        println!("wintun: already present, skipping");
        return Ok(());
    }

    println!("wintun: downloading signed prebuilt binary");
    let tmp = dest.join(".download");
    std::fs::create_dir_all(&tmp)?;
    let zip = tmp.join("wintun.zip");

    download(WINTUN.url, &zip)?;
    let bytes = std::fs::read(&zip)?;
    verify_digest(&bytes, WINTUN.sha256).context("Wintun archive failed digest verification")?;
    println!("  digest OK ({} bytes)", bytes.len());

    extract_zip(&zip, &tmp)?;
    for (inside, out) in WINTUN.extract {
        let from = tmp.join(inside.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !from.exists() {
            bail!("expected {inside} inside the Wintun archive, but it was not there");
        }
        std::fs::copy(&from, dest.join(out))
            .with_context(|| format!("failed to place {out} into {}", dest.display()))?;
        println!("  extracted {out}");
    }

    std::fs::remove_dir_all(&tmp).ok();
    Ok(())
}

// ---------------------------------------------------------------- Go builds

fn build_go_source(repo_root: &Path, src: &GoSource) -> Result<()> {
    let dest = repo_root.join("vendor").join(src.dest);
    let out = dest.join(src.binary);
    if out.exists() {
        println!("{}: already built, skipping", src.dest);
        return Ok(());
    }
    std::fs::create_dir_all(&dest)?;

    let work = dest.join(".src");
    if work.exists() {
        std::fs::remove_dir_all(&work).ok();
    }

    println!("{}: fetching source at {}", src.dest, &src.commit[..12]);
    // A shallow fetch of one commit: reproducible, and far cheaper than a full clone.
    run_cmd("git", &["init", "--quiet", work.to_str().unwrap()], None)?;
    run_cmd("git", &["remote", "add", "origin", src.repo], Some(&work))?;
    run_cmd(
        "git",
        &["fetch", "--quiet", "--depth", "1", "origin", src.commit],
        Some(&work),
    )?;
    run_cmd("git", &["checkout", "--quiet", "FETCH_HEAD"], Some(&work))?;

    // Confirm we are on exactly the pinned commit. A moved tag or a redirected
    // remote must fail loudly rather than silently build something else.
    let head = capture("git", &["rev-parse", "HEAD"], Some(&work))?;
    let head = head.trim();
    if head != src.commit {
        bail!(
            "{}: expected commit {}, but the fetched tree is at {head}",
            src.dest,
            src.commit
        );
    }
    println!("  commit verified");

    println!(
        "  building (tags: {})",
        if src.tags.is_empty() {
            "<default>"
        } else {
            src.tags
        }
    );
    let mut args = vec!["build", "-trimpath", "-ldflags", "-s -w", "-o"];
    let out_str = out.to_string_lossy().to_string();
    args.push(&out_str);
    if !src.tags.is_empty() {
        args.push("-tags");
        args.push(src.tags);
    }
    args.push(src.package);
    run_cmd("go", &args, Some(&work))?;

    let size = std::fs::metadata(&out)?.len();
    println!(
        "  built {} ({:.2} MB)",
        src.binary,
        size as f64 / 1_048_576.0
    );

    write_provenance(&dest, src, size)?;
    std::fs::remove_dir_all(&work).ok();
    Ok(())
}

/// Records exactly what was built, so a shipped binary can be traced to its source.
/// GPLv3 §6 obliges us to be able to offer the corresponding source for the primary
/// core; this file is how we know which source that is.
fn write_provenance(dest: &Path, src: &GoSource, size: u64) -> Result<()> {
    let content = format!(
        "# Build provenance\n\n\
         repository:  {}\n\
         version:     {}\n\
         commit:      {}\n\
         package:     {}\n\
         build tags:  {}\n\
         binary:      {} ({} bytes)\n\
         built by:    cargo xtask fetch-vendor\n\n\
         This binary was built from the exact commit above. See\n\
         `docs/adr/0004-vendored-binary-pins.md` and `THIRD-PARTY-NOTICES.md`.\n",
        src.repo,
        src.version,
        src.commit,
        src.package,
        if src.tags.is_empty() {
            "<upstream default>"
        } else {
            src.tags
        },
        src.binary,
        size,
    );
    std::fs::write(dest.join("BUILD-PROVENANCE.md"), content)?;
    Ok(())
}

// ---------------------------------------------------------------- helpers

/// Verify a downloaded artifact against its pinned digest.
pub fn verify_digest(bytes: &[u8], expected_hex: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    if expected_hex.trim().is_empty() {
        bail!("artifact has no pinned SHA-256; refusing to accept it");
    }
    let actual = hex(&Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        bail!("digest mismatch: expected {expected_hex}, got {actual}");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `curl.exe` ships with Windows 10 1803+ and is present on the CI images, so this
/// avoids pulling an HTTP stack into build tooling.
fn download(url: &str, to: &Path) -> Result<()> {
    run_cmd(
        "curl",
        &["-fsSL", "--retry", "3", "-o", to.to_str().unwrap(), url],
        None,
    )
    .with_context(|| format!("failed to download {url}"))
}

fn extract_zip(zip: &Path, into: &Path) -> Result<()> {
    if cfg!(windows) {
        run_cmd(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
                    zip.display(),
                    into.display()
                ),
            ],
            None,
        )
    } else {
        run_cmd(
            "unzip",
            &[
                "-o",
                "-q",
                zip.to_str().unwrap(),
                "-d",
                into.to_str().unwrap(),
            ],
            None,
        )
    }
}

fn require_tool(bin: &str, args: &[&str]) -> Result<()> {
    Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("`{bin}` was not found on PATH"))?;
    Ok(())
}

fn run_cmd(bin: &str, args: &[&str], cwd: Option<&Path>) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run `{bin}`"))?;
    if !status.success() {
        bail!("`{bin} {}` failed with {status}", args.join(" "));
    }
    Ok(())
}

fn capture(bin: &str, args: &[&str], cwd: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd
        .output()
        .with_context(|| format!("failed to run `{bin}`"))?;
    if !out.status.success() {
        bail!("`{bin} {}` failed", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pin_is_rejected() {
        assert!(verify_digest(b"anything", "").is_err());
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        assert!(verify_digest(b"hello", &"0".repeat(64)).is_err());
    }

    #[test]
    fn correct_digest_is_accepted() {
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_digest(b"hello", expected).is_ok());
    }

    #[test]
    fn every_go_source_is_pinned_to_a_full_commit_sha() {
        for s in GO_SOURCES {
            assert_eq!(s.commit.len(), 40, "{} is not pinned to a full SHA", s.dest);
            assert!(s.commit.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// The primary core must not carry WireGuard support: AmneziaWG is served by a
    /// separate supervised process, and including it would inflate the binary against
    /// the installer budget for no benefit.
    #[test]
    fn primary_core_excludes_wireguard() {
        let core = GO_SOURCES
            .iter()
            .find(|s| s.dest == "primary-core")
            .unwrap();
        assert!(!core.tags.contains("with_wireguard"));
        assert!(core.tags.contains("with_quic"));
        assert!(core.tags.contains("with_utls"));
        assert!(core.tags.contains("with_clash_api"));
    }

    /// The harness endpoint builds its AmneziaWG server from source. Both ends must run
    /// the identical protocol revision, so the endpoint's pin must equal the client's.
    #[test]
    fn harness_endpoint_pins_the_same_amneziawg_commit_as_the_client() {
        let client = GO_SOURCES
            .iter()
            .find(|s| s.dest == "amneziawg-go")
            .unwrap();
        let dockerfile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testing/harness/endpoint/Dockerfile");
        let text = std::fs::read_to_string(&dockerfile).expect("harness endpoint Dockerfile");
        let pinned = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("ARG AMNEZIAWG_GO_COMMIT="))
            .expect("endpoint Dockerfile declares ARG AMNEZIAWG_GO_COMMIT");
        assert_eq!(
            pinned.trim(),
            client.commit,
            "harness endpoint and client AmneziaWG pins have drifted"
        );
    }

    #[test]
    fn wintun_is_pinned_and_not_built_from_source() {
        assert_eq!(WINTUN.sha256.len(), 64);
        assert!(WINTUN.url.ends_with(".zip"));
    }
}
