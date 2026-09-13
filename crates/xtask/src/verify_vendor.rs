//! T006 — `cargo xtask verify-vendor`
//!
//! Enforces Constitution licence obligation 2: **Wintun MUST be bundled as the
//! vendor-signed prebuilt DLL only, never built from source, and never as a copy
//! embedded inside another executable.**
//!
//! Wintun's source is GPLv2, which is incompatible with this project's GPLv3.
//! The prebuilt signed DLLs carry a separate **proprietary** licence (not a permissive
//! one) whose §3(d) permits redistribution only alongside software using the documented
//! API, and whose §3(a) forbids extraction from other products. Compatibility rests on
//! aggregation under GPLv3 §5: DNet Engine's own code neither links nor loads the DLL, and
//! no GPL-covered executable we build carries the DLL inside it.
//! See `docs/adr/0004-vendored-binary-pins.md` (Finding 4) and `research.md` §R6.
//!
//! This check fails the build. It is not advisory.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::embedded::find_embedded_images;
use crate::pins::{forbidden_embedded_images, sha256_hex, wintun_dll};

/// Vendored executables that must not carry any embedded executable image.
const CORE_EXECUTABLES: &[&str] = &[
    "vendor/primary-core/primary-core.exe",
    "vendor/amneziawg-go/amneziawg-go.exe",
];

/// File extensions that would indicate Wintun source has been vendored.
const SOURCE_EXTENSIONS: &[&str] = &["c", "h", "cpp", "hpp", "vcxproj", "sln", "asm", "rc"];

/// Paths anywhere in the tree whose presence means someone vendored Wintun source.
const FORBIDDEN_DIR_NAMES: &[&str] = &["wintun-src", "wintun-source"];

pub fn run(repo_root: &Path) -> Result<()> {
    let mut failures = Vec::new();

    check_no_wintun_source(repo_root, &mut failures)?;
    let dll = check_signed_dll(repo_root, &mut failures)?;
    let scanned = check_no_embedded_images(repo_root, &mut failures)?;
    check_licence_texts(repo_root, &mut failures)?;

    if failures.is_empty() {
        println!("verify-vendor: OK");
        println!("  - no Wintun source present anywhere in the tree");
        println!("  - {}", dll.summary());
        println!("  - {}", embedded_summary(scanned));
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
    eprintln!("GPLv2 code into a GPLv3 work, and an embedded copy would place proprietary");
    eprintln!("code inside a GPL executable. Ship only the vendor-signed prebuilt DLL, as a");
    eprintln!("separate file; rebuild the cores with `cargo xtask fetch-vendor`.");
    bail!("verify-vendor failed")
}

/// Obligation 2's no-embedded-copies rule. A byte-identical copy of the official DLL, or
/// the packet-diversion driver, inside a core executable is named. Any other embedded PE
/// image is reported too: a different build of the same DLL would match no digest.
///
/// Returns how many core executables were present and scanned.
fn check_no_embedded_images(repo_root: &Path, failures: &mut Vec<String>) -> Result<usize> {
    let forbidden = forbidden_embedded_images();
    let mut scanned = 0;
    for rel in CORE_EXECUTABLES {
        let exe = repo_root.join(rel);
        if !exe.exists() {
            continue;
        }
        scanned += 1;
        let bytes = std::fs::read(&exe).with_context(|| format!("failed to read {rel}"))?;
        for image in find_embedded_images(&bytes, &forbidden) {
            failures.push(match image.identified {
                Some(label) => format!(
                    "{rel} embeds a byte-identical copy of the {label} at offset {}",
                    image.offset
                ),
                None => format!(
                    "{rel} embeds an unidentified executable image at offset {}",
                    image.offset
                ),
            });
        }
    }
    Ok(scanned)
}

fn embedded_summary(scanned: usize) -> String {
    match scanned {
        0 => "no vendored core executable present: embedded-image scan NOT run".into(),
        n => format!(
            "{n} of {} vendored core executable(s) scanned; none embeds a DLL, driver, or other PE image",
            CORE_EXECUTABLES.len()
        ),
    }
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

/// What the Wintun DLL check was able to establish. The OK summary reports exactly this,
/// never more: a check that did not run is not described as passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DllCheck {
    /// No DLL in the tree, which is normal before `fetch-vendor`.
    Absent,
    /// Digest matches the pin; the Authenticode status was not checked on this host.
    DigestOnly,
    /// Digest matches the pin and Authenticode reports `Valid`.
    DigestAndSignature,
}

impl DllCheck {
    fn summary(self) -> &'static str {
        match self {
            DllCheck::Absent => {
                "vendor/wintun/wintun.dll not present: digest and signature NOT checked"
            }
            DllCheck::DigestOnly => {
                "vendor/wintun/wintun.dll matches the pinned digest \
                 (Authenticode not checkable on this host)"
            }
            DllCheck::DigestAndSignature => {
                "vendor/wintun/wintun.dll matches the pinned digest and is validly signed"
            }
        }
    }
}

/// The DLL is fetched by `fetch-vendor`, so absence in a clean checkout is normal
/// and reported as a hint rather than a failure. A DLL that IS present but is not
/// validly signed is a hard failure.
fn check_signed_dll(repo_root: &Path, failures: &mut Vec<String>) -> Result<DllCheck> {
    let dll = repo_root.join("vendor/wintun/wintun.dll");
    if !dll.exists() {
        println!(
            "verify-vendor: note - {} not present; run `cargo xtask fetch-vendor` before packaging",
            dll.display()
        );
        return Ok(DllCheck::Absent);
    }

    let pin = wintun_dll("amd64");
    let digest = sha256_hex(&std::fs::read(&dll).context("failed to read wintun.dll")?);
    if digest != pin.sha256 {
        failures.push(format!(
            "vendor/wintun/wintun.dll SHA-256 is {digest}, expected the pinned {} ({})",
            pin.sha256, pin.label
        ));
    }

    match authenticode_status(&dll)? {
        Signature::NotCheckable => Ok(DllCheck::DigestOnly),
        Signature::Status(status) if status.eq_ignore_ascii_case("Valid") => {
            Ok(DllCheck::DigestAndSignature)
        }
        Signature::Status(status) => {
            failures.push(format!(
                "vendor/wintun/wintun.dll Authenticode status is `{status}`, expected `Valid`. \
                 Only the vendor's signed binary may be bundled."
            ));
            Ok(DllCheck::DigestOnly)
        }
        Signature::Unknown => {
            failures.push(
                "could not determine the Authenticode status of vendor/wintun/wintun.dll".into(),
            );
            Ok(DllCheck::DigestOnly)
        }
    }
}

/// Outcome of asking the host for a file's Authenticode status.
enum Signature {
    /// This host has no Authenticode verifier. The pinned digest still binds the file to
    /// the vendor's signed release, but the signature itself was not examined.
    NotCheckable,
    /// The verifier ran but produced no status.
    Unknown,
    /// The status string the verifier reported (`Valid`, `NotSigned`, `HashMismatch`, ...).
    Status(String),
}

fn authenticode_status(path: &Path) -> Result<Signature> {
    // Signature verification uses PowerShell's Get-AuthenticodeSignature, so it runs on
    // Windows only. Elsewhere it is reported as not checked, never as valid.
    if !cfg!(windows) {
        println!("verify-vendor: warning - not running on Windows; Authenticode check skipped");
        return Ok(Signature::NotCheckable);
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
        return Ok(Signature::Unknown);
    }
    let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if status.is_empty() {
        Signature::Unknown
    } else {
        Signature::Status(status)
    })
}

/// Every bundled dependency must ship its licence text: GPLv3 §6 requires it for the
/// GPL components, and the Wintun prebuilt licence requires its notices be retained.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The summary never claims a check that did not run.
    #[test]
    fn summary_claims_only_what_was_checked() {
        assert!(DllCheck::Absent.summary().contains("NOT checked"));
        assert!(!DllCheck::Absent.summary().contains("validly signed"));
        assert!(!DllCheck::DigestOnly.summary().contains("validly signed"));
        assert!(DllCheck::DigestAndSignature
            .summary()
            .contains("validly signed"));
    }

    #[test]
    fn embedded_summary_says_when_nothing_was_scanned() {
        assert!(embedded_summary(0).contains("NOT run"));
        assert!(embedded_summary(2).starts_with("2 of 2"));
    }

    #[test]
    fn absent_dll_is_reported_as_unchecked_not_failed() {
        let root = std::env::temp_dir().join(format!("verify-vendor-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut failures = Vec::new();
        let outcome = check_signed_dll(&root, &mut failures).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(outcome, DllCheck::Absent);
        assert!(failures.is_empty());
    }
}
