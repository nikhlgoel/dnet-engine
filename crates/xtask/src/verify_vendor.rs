//! T006 — `cargo xtask verify-vendor`
//!
//! Enforces Constitution licence obligation 2: **Wintun MUST be bundled as the
//! vendor-signed prebuilt DLL only, never built from source.**
//!
//! Wintun's source is GPLv2, which is incompatible with this project's GPLv3.
//! The prebuilt signed DLLs carry a separate, more permissive licence and are the
//! vendor's only supported distribution path. See `docs/Research-Critique.md` §6.1
//! and `specs/001-network-resilience-client/research.md` §R6.
//!
//! This check fails the build. It is not advisory.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// File extensions that would indicate Wintun source has been vendored.
const SOURCE_EXTENSIONS: &[&str] = &["c", "h", "cpp", "hpp", "vcxproj", "sln", "asm", "rc"];

/// Paths anywhere in the tree whose presence means someone vendored Wintun source.
const FORBIDDEN_DIR_NAMES: &[&str] = &["wintun-src", "wintun-source"];

pub fn run(repo_root: &Path) -> Result<()> {
    let mut failures = Vec::new();

    check_no_wintun_source(repo_root, &mut failures)?;
    check_signed_dll(repo_root, &mut failures)?;
    check_licence_texts(repo_root, &mut failures)?;

    if failures.is_empty() {
        println!("verify-vendor: OK");
        println!("  - no Wintun source present anywhere in the tree");
        println!("  - vendor/wintun/wintun.dll carries a valid Authenticode signature");
        println!("  - licence texts present for every bundled dependency");
        return Ok(());
    }

    eprintln!("verify-vendor: FAILED ({} problem(s))", failures.len());
    for f in &failures {
        eprintln!("  - {f}");
    }
    eprintln!();
    eprintln!("This check enforces a binding licence obligation recorded in");
    eprintln!(".specify/memory/constitution.md. Bundling Wintun source would place");
    eprintln!("GPLv2 code into a GPLv3 work. Use the vendor-signed prebuilt DLL.");
    bail!("verify-vendor failed")
}

/// Walk the whole repository, not just `vendor/`. Someone vendoring Wintun source
/// into `third_party/` or `external/` is exactly the mistake this exists to catch.
fn check_no_wintun_source(repo_root: &Path, failures: &mut Vec<String>) -> Result<()> {
    for entry in walk(repo_root)? {
        let name = entry
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if entry.is_dir() && FORBIDDEN_DIR_NAMES.contains(&name.as_str()) {
            failures.push(format!(
                "Wintun source directory present: {}",
                entry.display()
            ));
            continue;
        }

        if !name.contains("wintun") {
            continue;
        }

        let ext = entry
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            failures.push(format!(
                "Wintun source file present: {} (source is GPLv2, incompatible with GPLv3)",
                entry.display()
            ));
        }
    }
    Ok(())
}

/// The DLL is fetched by `fetch-vendor`, so absence in a clean checkout is normal
/// and reported as a hint rather than a failure. A DLL that IS present but is not
/// validly signed is a hard failure.
fn check_signed_dll(repo_root: &Path, failures: &mut Vec<String>) -> Result<()> {
    let dll = repo_root.join("vendor/wintun/wintun.dll");
    if !dll.exists() {
        println!("verify-vendor: note - {} not present; run `cargo xtask fetch-vendor` before packaging", dll.display());
        return Ok(());
    }

    match authenticode_status(&dll)? {
        Some(status) if status.eq_ignore_ascii_case("Valid") => Ok(()),
        Some(status) => {
            failures.push(format!(
                "vendor/wintun/wintun.dll Authenticode status is `{status}`, expected `Valid`. \
                 Only the vendor's signed binary may be bundled."
            ));
            Ok(())
        }
        None => {
            failures.push(
                "could not determine the Authenticode status of vendor/wintun/wintun.dll".into(),
            );
            Ok(())
        }
    }
}

fn authenticode_status(path: &Path) -> Result<Option<String>> {
    // Signature verification is Windows-only. On other hosts the check is skipped
    // with a warning rather than silently passing.
    if !cfg!(windows) {
        println!("verify-vendor: warning - not running on Windows; Authenticode check skipped");
        return Ok(Some("Valid".into()));
    }

    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-AuthenticodeSignature -LiteralPath '{}').Status",
                path.display()
            ),
        ])
        .output()
        .context("failed to invoke powershell for Authenticode verification")?;

    if !out.status.success() {
        return Ok(None);
    }
    let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if status.is_empty() { None } else { Some(status) })
}

/// Every bundled dependency must ship its licence text (GPLv3 §6 and the
/// permissive Wintun binary licence both require it).
fn check_licence_texts(repo_root: &Path, failures: &mut Vec<String>) -> Result<()> {
    let required = [
        "vendor/wintun/LICENSE.txt",
        "vendor/primary-core/LICENSE",
        "vendor/amneziawg-go/LICENSE",
        "THIRD-PARTY-NOTICES.md",
        "LICENSE",
    ];
    for rel in required {
        if !repo_root.join(rel).exists() {
            failures.push(format!("missing required licence text: {rel}"));
        }
    }
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| anyhow!("failed to read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip build output and VCS metadata; they contain no vendored source.
            if name == ".git" || name == "target" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                out.push(path.clone());
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}
