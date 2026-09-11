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
//! Nor may a core carry its own embedded copy. The primary core's TUN dependency compiles
//! the DLL into the executable upstream. `fetch-vendor` patches that loader (a Go module
//! `replace`) so the core loads the official vendored DLL from disk, digest-verified.
//! `verify-vendor` then scans the built binary to prove no copy remains (ADR-0004,
//! Finding 4).
//!
//! Sources are pinned by **commit SHA**, not tag, because a tag can be moved. Every
//! downloaded byte is verified before use; an unpinned artifact is rejected rather
//! than accepted, because an unpinned download is a supply-chain hole.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::pins::{sha256_hex, wintun_dll};

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
    /// Source patches applied to a dependency before building.
    patch: Option<&'static ModulePatch>,
}

/// A patch to one Go module dependency, applied through a `go mod edit -replace` onto a
/// patched copy. The copy starts from the module cache, verified against the pinned
/// source's `go.sum`.
struct ModulePatch {
    module: &'static str,
    /// The exact version the pinned source requires. A core bump that changes it fails
    /// loudly, so the patch is re-reviewed rather than silently applied to new code.
    version: &'static str,
    /// Directory under `crates/xtask/` whose files overwrite or add to the module copy.
    overlay: &'static str,
    /// Paths deleted from the module copy. Each must exist, or the patch no longer
    /// matches upstream.
    remove: &'static [&'static str],
    /// Directory in the patched copy that must end up with no `go:embed` directive.
    no_embed_dir: &'static str,
    /// Package whose tests exercise the patch, run with `DNET_WINTUN_DLL` set.
    test_package: &'static str,
}

const TUN_DLL_LOADER_PATCH: ModulePatch = ModulePatch {
    module: "github.com/sagernet/sing-tun",
    version: "v0.9.0-beta.4",
    overlay: "patches/sing-tun",
    remove: &[
        "internal/wintun/dll_windows_386.go",
        "internal/wintun/dll_windows_amd64.go",
        "internal/wintun/dll_windows_arm.go",
        "internal/wintun/dll_windows_arm64.go",
        "internal/wintun/x86",
        "internal/wintun/amd64",
        "internal/wintun/arm",
        "internal/wintun/arm64",
    ],
    no_embed_dir: "internal/wintun",
    test_package: "github.com/sagernet/sing-tun/internal/wintun",
};

const GO_SOURCES: &[GoSource] = &[
    GoSource {
        dest: "primary-core",
        repo: "https://github.com/SagerNet/sing-box",
        version: "v1.14.0",
        commit: "0b8995879f29a9b98ee027bc17b75e101445b238",
        package: "./cmd/sing-box",
        binary: "primary-core.exe",
        // with_quic               -> Hysteria 2 (Profile B)
        // with_utls               -> REALITY fingerprinting (Profile C)
        // with_clash_api          -> the runtime control API dnetd drives the core through
        // with_gvisor             -> TUN network stack
        // with_external_windivert -> do NOT embed the packet-diversion kernel driver. No
        //                            profile uses it, and we never ship the driver file,
        //                            so the features needing it fail closed (Finding 4).
        tags: "with_quic,with_utls,with_clash_api,with_gvisor,with_external_windivert",
        patch: Some(&TUN_DLL_LOADER_PATCH),
    },
    GoSource {
        dest: "amneziawg-go",
        repo: "https://github.com/amnezia-vpn/amneziawg-go",
        version: "v3.1.20260828",
        commit: "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        package: ".",
        binary: "amneziawg-go.exe",
        tags: "",
        patch: None,
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

    // The zip digest already covers the DLL; the per-file pin is what the core's loader
    // patch checks at runtime, so confirm the two agree here rather than at first start.
    let pin = wintun_dll("amd64");
    verify_digest(&std::fs::read(&dll)?, pin.sha256)
        .context("extracted DLL does not match the digest the core's loader pins")?;

    std::fs::remove_dir_all(&tmp).ok();
    Ok(())
}

// ---------------------------------------------------------------- Go builds

fn build_go_source(repo_root: &Path, src: &GoSource) -> Result<()> {
    let dest = repo_root.join("vendor").join(src.dest);
    let out = dest.join(src.binary);
    let fingerprint = build_fingerprint(src)?;
    if out.exists() && provenance_fingerprint(&dest).as_deref() == Some(fingerprint.as_str()) {
        println!(
            "{}: already built with this pin, tags, and patch; skipping",
            src.dest
        );
        return Ok(());
    }
    if out.exists() {
        println!(
            "{}: pin, tags, or patch changed since the last build; rebuilding",
            src.dest
        );
        std::fs::remove_file(&out)?;
    }
    std::fs::create_dir_all(&dest)?;

    let work = dest.join(".src");
    let patched = dest.join(".patched");
    for dir in [&work, &patched] {
        if dir.exists() {
            remove_tree(dir)?;
        }
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

    if let Some(patch) = src.patch {
        apply_module_patch(patch, &work, &patched)?;
    }

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

    if let Some(patch) = src.patch {
        test_module_patch(repo_root, patch, &work)?;
    }

    write_provenance(&dest, src, size, &fingerprint)?;
    remove_tree(&work)?;
    remove_tree(&patched)?;
    Ok(())
}

// ---------------------------------------------------------------- module patches

/// Copies the pinned dependency out of the module cache, applies the patch, proves the
/// patched package embeds nothing, and points the build at the copy.
fn apply_module_patch(patch: &ModulePatch, work: &Path, patched: &Path) -> Result<()> {
    println!("  patching {}", patch.module);
    let required = capture(
        "go",
        &["list", "-m", "-f", "{{.Version}}", patch.module],
        Some(work),
    )?;
    if required.trim() != patch.version {
        bail!(
            "the pinned source now requires {} {}, but the patch was reviewed against {}. \
             Re-review crates/xtask/{} before building.",
            patch.module,
            required.trim(),
            patch.version,
            patch.overlay
        );
    }
    // Download verifies the module against the pinned source's go.sum.
    run_cmd("go", &["mod", "download", patch.module], Some(work))?;
    let cached = capture(
        "go",
        &["list", "-m", "-f", "{{.Dir}}", patch.module],
        Some(work),
    )?;
    let cached = PathBuf::from(cached.trim());
    if !cached.is_dir() {
        bail!("module cache has no directory for {}", patch.module);
    }

    copy_tree(&cached, patched)?;
    for rel in patch.remove {
        let path = patched.join(rel);
        if path.is_dir() {
            remove_tree(&path)?;
        } else if path.is_file() {
            std::fs::remove_file(&path)?;
        } else {
            bail!("patch expects {rel} in {}, but it is absent", patch.module);
        }
    }
    for (rel, contents) in overlay_files(patch)? {
        let to = patched.join(&rel);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&to, contents)?;
    }

    assert_embeds_nothing(&patched.join(patch.no_embed_dir))?;
    println!("  verified: no go:embed directive and no DLL or driver file remains");

    // Relative, because Go records the replacement path in the binary's build info: an
    // absolute path would publish the build machine's directory layout in a shipped file.
    let (Some(work_parent), Some(patched_name)) = (work.parent(), patched.file_name()) else {
        bail!("patch directories must have a parent and a name");
    };
    if patched.parent() != Some(work_parent) {
        bail!("patched copy must sit beside the source tree for a relative replace");
    }
    let replace = format!(
        "-replace={}=../{}",
        patch.module,
        patched_name.to_string_lossy()
    );
    run_cmd("go", &["mod", "edit", &replace], Some(work))
}

/// The patch's Go tests load the official vendored DLL through the patched loader, and
/// prove a tampered or missing DLL is refused.
fn test_module_patch(repo_root: &Path, patch: &ModulePatch, work: &Path) -> Result<()> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        println!("  warning: patch tests need a Windows x64 host; NOT RUN on this host");
        return Ok(());
    }
    println!("  testing the patched loader against vendor/wintun/wintun.dll");
    let dll = repo_root.join("vendor/wintun/wintun.dll");
    let status = Command::new("go")
        .args(["test", "-count=1", patch.test_package])
        .current_dir(work)
        .env("DNET_WINTUN_DLL", &dll)
        .status()
        .context("failed to run `go test`")?;
    if !status.success() {
        bail!("patched loader tests failed ({status}); the core was not accepted");
    }
    Ok(())
}

/// Overlay files, relative path to contents, with line endings normalised to LF so the
/// patch digest does not depend on how git checked the files out.
fn overlay_files(patch: &ModulePatch) -> Result<Vec<(String, Vec<u8>)>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(patch.overlay);
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed to read patch directory {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(&root)?
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read(&path)?;
            let lf: Vec<u8> = String::from_utf8(text)
                .with_context(|| format!("patch file {rel} is not UTF-8"))?
                .replace("\r\n", "\n")
                .into_bytes();
            files.push((rel, lf));
        }
    }
    if files.is_empty() {
        bail!("patch directory {} is empty", root.display());
    }
    files.sort();
    Ok(files)
}

/// Digest over every overlay file's path and contents, and the removal list.
fn patch_digest(patch: &ModulePatch) -> Result<String> {
    let mut material = Vec::new();
    for (rel, contents) in overlay_files(patch)? {
        material.extend_from_slice(rel.as_bytes());
        material.push(0);
        material.extend_from_slice(&contents);
        material.push(0);
    }
    for rel in patch.remove {
        material.extend_from_slice(b"remove:");
        material.extend_from_slice(rel.as_bytes());
        material.push(0);
    }
    Ok(sha256_hex(&material))
}

fn assert_embeds_nothing(dir: &Path) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if ext == "dll" || ext == "sys" {
                bail!("patched module still contains {}", path.display());
            }
            if ext == "go" && std::fs::read_to_string(&path)?.contains("go:embed") {
                bail!("patched module still embeds a file in {}", path.display());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- provenance

/// What determines the built bytes: the commit, the tags, and the patch. A change to any
/// of them rebuilds, so a stale binary from before a patch cannot survive a fetch.
fn build_fingerprint(src: &GoSource) -> Result<String> {
    let patch = match src.patch {
        Some(p) => format!("{}@{}+{}", p.module, p.version, patch_digest(p)?),
        None => "none".into(),
    };
    Ok(format!("{} tags={} patch={}", src.commit, src.tags, patch))
}

fn provenance_fingerprint(dest: &Path) -> Option<String> {
    std::fs::read_to_string(dest.join("BUILD-PROVENANCE.md"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint: ").map(str::to_owned))
}

/// Records exactly what was built, so a shipped binary can be traced to its source.
/// GPLv3 §6 obliges us to be able to offer the corresponding source for the primary
/// core; this file, with the patch files it names, is how we know which source that is.
fn write_provenance(dest: &Path, src: &GoSource, size: u64, fingerprint: &str) -> Result<()> {
    let patch = match src.patch {
        Some(p) => format!(
            "{} {} patched from crates/xtask/{} (sha256 {})",
            p.module,
            p.version,
            p.overlay,
            patch_digest(p)?
        ),
        None => "none".into(),
    };
    let content = format!(
        "# Build provenance\n\n\
         repository:  {}\n\
         version:     {}\n\
         commit:      {}\n\
         package:     {}\n\
         build tags:  {}\n\
         patches:     {}\n\
         binary:      {} ({} bytes)\n\
         built by:    cargo xtask fetch-vendor\n\n\
         fingerprint: {}\n\n\
         This binary was built from the exact commit above, with the patches listed. See\n\
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
        patch,
        src.binary,
        size,
        fingerprint,
    );
    std::fs::write(dest.join("BUILD-PROVENANCE.md"), content)?;
    Ok(())
}

// ---------------------------------------------------------------- helpers

/// Verify a downloaded artifact against its pinned digest.
pub fn verify_digest(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.trim().is_empty() {
        bail!("artifact has no pinned SHA-256; refusing to accept it");
    }
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        bail!("digest mismatch: expected {expected_hex}, got {actual}");
    }
    Ok(())
}

/// Recursive copy that clears the read-only attribute: the Go module cache marks its
/// files read-only, and the copy must be patchable and removable.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dst)?;
        } else {
            std::fs::copy(entry.path(), &dst)?;
            make_writable(&dst)?;
        }
    }
    Ok(())
}

/// `remove_dir_all` fails on read-only files on Windows, so clear the flag first.
fn remove_tree(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                make_writable(&path)?;
            }
        }
    }
    std::fs::remove_dir_all(dir).with_context(|| format!("failed to remove {}", dir.display()))
}

// Only ever applied to our own scratch copies under vendor/, never to a shipped file.
#[allow(clippy::permissions_set_readonly_false)]
fn make_writable(path: &Path) -> Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
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

    fn primary_core() -> &'static GoSource {
        GO_SOURCES
            .iter()
            .find(|s| s.dest == "primary-core")
            .unwrap()
    }

    /// Finding 4: the packet-diversion kernel driver must not be compiled into the core.
    #[test]
    fn primary_core_does_not_embed_the_packet_diversion_driver() {
        assert!(primary_core()
            .tags
            .split(',')
            .any(|t| t == "with_external_windivert"));
    }

    /// Finding 4: the core's TUN dependency must be built with the disk-loading patch,
    /// which removes every file that embedded the adapter DLL.
    #[test]
    fn primary_core_is_built_with_the_dll_loader_patch() {
        let patch = primary_core()
            .patch
            .expect("primary core carries the loader patch");
        for goarch in ["386", "amd64", "arm", "arm64"] {
            let embed_file = format!("internal/wintun/dll_windows_{goarch}.go");
            assert!(patch.remove.contains(&embed_file.as_str()), "{embed_file}");
        }
        for dll_dir in ["x86", "amd64", "arm", "arm64"] {
            let dir = format!("internal/wintun/{dll_dir}");
            assert!(patch.remove.contains(&dir.as_str()), "{dir}");
        }
    }

    #[test]
    fn loader_patch_embeds_nothing_and_loads_by_verified_absolute_path() {
        let files = overlay_files(&TUN_DLL_LOADER_PATCH).unwrap();
        let loader = files
            .iter()
            .find(|(rel, _)| rel == "internal/wintun/dll_windows.go")
            .map(|(_, c)| String::from_utf8_lossy(c).into_owned())
            .expect("patch replaces the loader");
        assert!(loader.contains("LoadLibraryEx"));
        assert!(loader.contains("loadVerified(path, dllSHA256)"));
        assert!(!loader.contains("memmod"));
        for (rel, contents) in &files {
            assert!(
                !String::from_utf8_lossy(contents).contains("go:embed"),
                "{rel} embeds a file"
            );
        }
    }

    /// A binary built before a tag or patch change must be rebuilt, not skipped.
    #[test]
    fn fingerprint_changes_with_tags_and_patch() {
        let core = primary_core();
        let base = build_fingerprint(core).unwrap();
        let untagged = GoSource {
            tags: "with_quic",
            ..*core
        };
        let unpatched = GoSource {
            patch: None,
            ..*core
        };
        assert_ne!(base, build_fingerprint(&untagged).unwrap());
        assert_ne!(base, build_fingerprint(&unpatched).unwrap());
        assert_eq!(base, build_fingerprint(core).unwrap());
    }
}
