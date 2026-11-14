// SPDX-License-Identifier: GPL-3.0-or-later
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
        Signature::Unknown(why) => {
            failures.push(format!(
                "could not determine the Authenticode status of vendor/wintun/wintun.dll: {why}"
            ));
            Ok(DllCheck::DigestOnly)
        }
    }
}

/// Outcome of asking the host for a file's Authenticode status.
enum Signature {
    /// This host has no Authenticode verifier. The pinned digest still binds the file to
    /// the vendor's signed release, but the signature itself was not examined.
    NotCheckable,
    /// The verifier ran but produced no status; why, as it said it.
    Unknown(String),
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

    let out = windows_powershell()
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

    let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || status.is_empty() {
        let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let why = if said.is_empty() {
            format!("the verifier printed nothing ({})", out.status)
        } else {
            said
        };
        return Ok(Signature::Unknown(why));
    }
    Ok(Signature::Status(status))
}

/// Windows PowerShell for the tools that ask it something. It is started without the module path of whatever started
/// this program: from PowerShell 7 (as a release build on GitHub's runner is) it would inherit PowerShell 7's module
/// path, and its own security cmdlets and certificate drive then fail to load.
pub(crate) fn windows_powershell() -> Command {
    let mut command = Command::new("powershell");
    command.env_remove("PSModulePath");
    command
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

/// Where `testing/spike-r4/Invoke-SpikeR4.ps1` writes its run artifacts, relative to the repo root.
fn spike_results_dir() -> PathBuf {
    Path::new("testing").join("spike-r4").join("results")
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
            // The SPIKE-R4 gate's own output. It is gitignored, so nothing in it can reach the
            // repository, and a run as SYSTEM leaves directories (the generated core
            // configuration, T049) that only SYSTEM and Administrators may read.
            if path
                .strip_prefix(root)
                .is_ok_and(|rel| rel == spike_results_dir())
            {
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

    /// The release build runs this from PowerShell 7 on GitHub's runner, and Windows PowerShell started from it
    /// inherits PowerShell 7's module path, which broke its security cmdlets: the signature could not be read and the
    /// release stopped. A child Windows PowerShell must not inherit it.
    #[cfg(windows)]
    #[test]
    fn windows_powershell_does_not_inherit_the_parents_module_path() {
        let command = windows_powershell();
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "PSModulePath" && value.is_none()),
            "PSModulePath is passed on to the child"
        );
    }

    /// A signature that cannot be read is reported with the reason, not as a bare "could not determine".
    #[cfg(windows)]
    #[test]
    fn an_unreadable_signature_says_why() {
        match authenticode_status(Path::new(
            r"C:
o\sucholderile.exe",
        ))
        .unwrap()
        {
            Signature::Unknown(why) => assert!(!why.trim().is_empty(), "no reason given"),
            Signature::Status(status) => panic!("a missing file read as {status}"),
            Signature::NotCheckable => panic!("this host can check signatures"),
        }
    }

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

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("verify-vendor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// The gate's output directory is not part of what is checked; everything else still is.
    #[test]
    fn walk_skips_only_the_spike_results_directory() {
        let root = scratch("walk");
        let results = root.join(spike_results_dir()).join("20260101-000000");
        std::fs::create_dir_all(&results).unwrap();
        std::fs::write(results.join("staged.txt"), "x").unwrap();
        let other = root.join("testing").join("harness");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("kept.txt"), "x").unwrap();
        // A directory that merely has the same last name elsewhere is still walked.
        let lookalike = root.join("vendor").join("results");
        std::fs::create_dir_all(&lookalike).unwrap();
        std::fs::write(lookalike.join("also-kept.txt"), "x").unwrap();

        let found: Vec<String> = walk(&root)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        std::fs::remove_dir_all(&root).unwrap();

        assert!(!found.contains(&"staged.txt".to_string()), "{found:?}");
        assert!(found.contains(&"kept.txt".to_string()), "{found:?}");
        assert!(found.contains(&"also-kept.txt".to_string()), "{found:?}");
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

/// The gate run against trees built for the purpose. Each failure the gate exists to catch is made once on its own
/// and must be found, and a clean tree must pass, so a gate that stopped looking would be noticed.
#[cfg(test)]
mod gate_tests {
    use super::*;

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    const LICENCES: [&str; 5] = [
        "vendor/wintun/LICENSE.txt",
        "vendor/primary-core/LICENSE",
        "vendor/amneziawg-go/LICENSE",
        "THIRD-PARTY-NOTICES.md",
        "LICENSE",
    ];

    /// Every licence text the gate requires, and nothing else.
    fn tree_with_licences() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for rel in LICENCES {
            write(dir.path(), rel, b"licence");
        }
        dir
    }

    fn pe_image(len: usize) -> Vec<u8> {
        let mut image = vec![0u8; len];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image
    }

    fn found_in_source(root: &Path) -> Vec<String> {
        let mut failures = Vec::new();
        check_no_wintun_source(root, &mut failures).unwrap();
        failures
    }

    #[test]
    fn a_tree_with_no_wintun_source_has_nothing_to_report() {
        let dir = tree_with_licences();
        write(dir.path(), "src/main.c", b"int main(){}");
        write(dir.path(), "vendor/wintun/wintun.dll", b"not source");
        write(dir.path(), "docs/wintun.md", b"notes");
        assert!(found_in_source(dir.path()).is_empty());
    }

    #[test]
    fn wintun_source_is_found_wherever_in_the_tree_it_was_put() {
        for rel in [
            "wintun.c",
            "third_party/wintun/wintun.h",
            "external/deep/er/Wintun.CPP",
            "vendor/WINTUN.vcxproj",
            "x/wintun.sln",
            "x/wintun.asm",
            "x/wintun.rc",
            "x/wintun.hpp",
        ] {
            let dir = tempfile::tempdir().unwrap();
            write(dir.path(), rel, b"source");
            let failures = found_in_source(dir.path());
            assert_eq!(failures.len(), 1, "{rel}: {failures:?}");
            assert!(
                failures[0].contains("Wintun source file present"),
                "{rel}: {failures:?}"
            );
        }
    }

    #[test]
    fn a_directory_named_for_wintun_source_is_found_even_when_empty() {
        for name in ["wintun-src", "Wintun-Source", "a/b/wintun-source"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join(name)).unwrap();
            let failures = found_in_source(dir.path());
            assert_eq!(failures.len(), 1, "{name}: {failures:?}");
            assert!(
                failures[0].contains("Wintun source directory present"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_source_file_that_is_not_about_wintun_is_none_of_the_gates_business() {
        let dir = tempfile::tempdir().unwrap();
        for rel in ["a.c", "b.h", "deep/c.cpp", "d.asm"] {
            write(dir.path(), rel, b"x");
        }
        assert!(found_in_source(dir.path()).is_empty());
    }

    #[test]
    fn build_output_version_control_and_package_folders_are_not_searched() {
        let dir = tempfile::tempdir().unwrap();
        for rel in [
            "target/debug/wintun.c",
            ".git/objects/wintun.h",
            "node_modules/x/wintun.cpp",
        ] {
            write(dir.path(), rel, b"x");
        }
        assert!(found_in_source(dir.path()).is_empty());
    }

    #[test]
    fn the_spike_results_folder_is_skipped_only_at_its_own_place() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "testing/spike-r4/results/wintun.c", b"x");
        assert!(
            found_in_source(dir.path()).is_empty(),
            "its own output is skipped"
        );
        write(
            dir.path(),
            "elsewhere/testing/spike-r4/results/wintun.c",
            b"x",
        );
        assert_eq!(
            found_in_source(dir.path()).len(),
            1,
            "the same names elsewhere are not"
        );
    }

    #[test]
    fn a_missing_licence_text_is_named() {
        let dir = tree_with_licences();
        let mut failures = Vec::new();
        check_licence_texts(dir.path(), &mut failures).unwrap();
        assert!(failures.is_empty(), "{failures:?}");

        for rel in LICENCES {
            let dir = tree_with_licences();
            std::fs::remove_file(dir.path().join(rel)).unwrap();
            let mut failures = Vec::new();
            check_licence_texts(dir.path(), &mut failures).unwrap();
            assert_eq!(failures, [format!("missing required licence text: {rel}")]);
        }
    }

    #[test]
    fn a_core_that_embeds_an_executable_image_is_named_and_a_clean_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut clean = pe_image(0x200);
        clean.extend(vec![0xAAu8; 0x400]);
        write(dir.path(), "vendor/primary-core/primary-core.exe", &clean);
        let mut failures = Vec::new();
        assert_eq!(
            check_no_embedded_images(dir.path(), &mut failures).unwrap(),
            1
        );
        assert!(failures.is_empty(), "{failures:?}");

        // The same host with a second image inside it, as a go:embed of a DLL would leave.
        let mut dirty = clean.clone();
        let inside = dirty.len();
        dirty.extend(pe_image(0x300));
        write(dir.path(), "vendor/amneziawg-go/amneziawg-go.exe", &dirty);
        let mut failures = Vec::new();
        assert_eq!(
            check_no_embedded_images(dir.path(), &mut failures).unwrap(),
            2
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("amneziawg-go.exe"), "{failures:?}");
        assert!(failures[0].contains("unidentified"), "{failures:?}");
        assert!(failures[0].contains(&inside.to_string()), "{failures:?}");
    }

    #[test]
    fn with_no_core_present_nothing_is_scanned_and_the_summary_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut failures = Vec::new();
        assert_eq!(
            check_no_embedded_images(dir.path(), &mut failures).unwrap(),
            0
        );
        assert!(embedded_summary(0).contains("NOT run"));
        assert!(embedded_summary(2).contains("2 of 2"));
        assert!(embedded_summary(1).contains("1 of 2"));
    }

    #[test]
    fn a_wintun_dll_that_is_not_the_pinned_one_is_a_failure_and_an_absent_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut failures = Vec::new();
        assert_eq!(
            check_signed_dll(dir.path(), &mut failures).unwrap(),
            DllCheck::Absent
        );
        assert!(failures.is_empty());

        write(
            dir.path(),
            "vendor/wintun/wintun.dll",
            b"not the vendor file",
        );
        let mut failures = Vec::new();
        let _ = check_signed_dll(dir.path(), &mut failures);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("SHA-256") && f.contains("expected the pinned")),
            "{failures:?}"
        );
    }

    #[test]
    fn the_summaries_never_claim_more_than_was_checked() {
        assert!(DllCheck::Absent.summary().contains("NOT checked"));
        assert!(DllCheck::DigestOnly.summary().contains("not checkable"));
        let signed = DllCheck::DigestAndSignature.summary();
        assert!(signed.contains("validly signed"), "{signed}");
        assert_ne!(DllCheck::Absent.summary(), DllCheck::DigestOnly.summary());
    }

    #[test]
    fn the_whole_gate_passes_a_clean_tree_and_stops_each_kind_of_bad_one() {
        let clean = tree_with_licences();
        assert!(run(clean.path()).is_ok());

        let with_source = tree_with_licences();
        write(with_source.path(), "third_party/wintun/wintun.c", b"x");
        assert!(run(with_source.path()).is_err());

        let without_licence = tree_with_licences();
        std::fs::remove_file(without_licence.path().join("LICENSE")).unwrap();
        assert!(run(without_licence.path()).is_err());

        let embedding = tree_with_licences();
        let mut host = pe_image(0x200);
        host.extend(pe_image(0x200));
        write(
            embedding.path(),
            "vendor/primary-core/primary-core.exe",
            &host,
        );
        assert!(run(embedding.path()).is_err());
    }
}
