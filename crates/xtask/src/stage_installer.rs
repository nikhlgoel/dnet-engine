// SPDX-License-Identifier: GPL-3.0-or-later
//! T114 — `cargo xtask stage-installer`: put everything the installer ships, and nothing else, in
//! `target/payload`, from which `installer/hooks.nsh` takes it.
//!
//! 1. `verify-vendor` first: nothing is staged from a tree that fails the licence obligations.
//! 2. `dnetd` and `dnetctl` are built in release mode.
//! 3. The service, the CLI, both cores and the adapter DLL go to `app/`, which the installer copies to
//!    the install folder, so they all sit **beside each other** (beside `dnetd.exe`: start-up recovery
//!    reaps orphans by exactly those paths; beside each core: the patched core loads the DLL only from
//!    its own folder).
//! 4. The licence texts, the notices and the build provenance go to `licences/`.
//! 5. Every staged file is read back and compared with its source by SHA-256.
//!
//! Windows only: the payload is Windows executables.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::pins::sha256_hex;

/// Where the payload is staged, relative to the repository root. `installer/hooks.nsh` reads it.
pub const PAYLOAD_DIR: &str = "target/payload";

/// The executables, and the one library, that must sit together in the install folder. The core
/// names are the ones `dnetd` looks for beside itself (`recovery::windows_ops::CORE_EXECUTABLES`).
pub fn app_files() -> Vec<(PathBuf, &'static str)> {
    vec![
        (PathBuf::from("target/release/dnetd.exe"), "dnetd.exe"),
        (PathBuf::from("target/release/dnetctl.exe"), "dnetctl.exe"),
        (
            PathBuf::from("vendor/primary-core/primary-core.exe"),
            "primary-core.exe",
        ),
        (
            PathBuf::from("vendor/amneziawg-go/amneziawg-go.exe"),
            "amneziawg-go.exe",
        ),
        (PathBuf::from("vendor/wintun/wintun.dll"), "wintun.dll"),
        // What a person's own server downloads while it is set up, by processor (T149).
        (
            PathBuf::from("target/server-cores/server-pins.json"),
            "server-pins.json",
        ),
    ]
}

/// The licence texts and notices, by the folder they are shipped in under `licences/`.
pub fn licence_files() -> Vec<(PathBuf, String)> {
    let mut files = vec![
        (PathBuf::from("LICENSE"), "LICENSE".to_string()),
        (
            PathBuf::from("THIRD-PARTY-NOTICES.md"),
            "THIRD-PARTY-NOTICES.md".to_string(),
        ),
    ];
    for (component, names) in [
        (
            "primary-core",
            &["LICENSE", "README.md", "BUILD-PROVENANCE.md"][..],
        ),
        (
            "amneziawg-go",
            &["LICENSE", "README.md", "BUILD-PROVENANCE.md"],
        ),
        ("wintun", &["LICENSE.txt", "README.md"]),
    ] {
        for name in names {
            files.push((
                PathBuf::from("vendor").join(component).join(name),
                format!("{component}/{name}"),
            ));
        }
    }
    files
}

pub fn run(repo_root: &Path) -> Result<()> {
    if !cfg!(windows) {
        bail!("stage-installer builds a Windows payload; run it on Windows");
    }
    crate::verify_vendor::run(repo_root).context("the vendored files must verify first")?;

    let status = std::process::Command::new(std::env::var("CARGO").unwrap_or("cargo".into()))
        .current_dir(repo_root)
        .args(["build", "--release", "-p", "dnetd", "-p", "dnetctl"])
        .status()
        .context("cargo could not be run")?;
    if !status.success() {
        bail!("building dnetd and dnetctl failed");
    }

    let payload = repo_root.join(PAYLOAD_DIR);
    if payload.exists() {
        std::fs::remove_dir_all(&payload)
            .with_context(|| format!("{} could not be cleared", payload.display()))?;
    }
    let mut staged = Vec::new();
    for (from, name) in app_files() {
        staged.push(stage(repo_root, &from, &payload.join("app").join(name))?);
    }
    for (from, to) in licence_files() {
        staged.push(stage(repo_root, &from, &payload.join("licences").join(to))?);
    }

    let total: u64 = staged.iter().sum();
    println!(
        "stage-installer: OK - {} files, {:.1} MB uncompressed, in {PAYLOAD_DIR}",
        staged.len(),
        total as f64 / 1_000_000.0
    );
    println!("  next: cd apps/dnet-tray; pnpm installer");
    Ok(())
}

/// Copy one file and check the copy byte for byte. Returns its size.
fn stage(repo_root: &Path, from: &Path, to: &Path) -> Result<u64> {
    let source = repo_root.join(from);
    let bytes = std::fs::read(&source).with_context(|| {
        format!(
            "{} is missing (run `cargo xtask fetch-vendor` for the cores)",
            source.display()
        )
    })?;
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(to, &bytes).with_context(|| format!("{} could not be written", to.display()))?;
    let copy = std::fs::read(to)?;
    if sha256_hex(&copy) != sha256_hex(&bytes) {
        bail!("{} does not match its source after copying", to.display());
    }
    Ok(bytes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service, both cores and the adapter DLL land in one folder: the T114 layout rule.
    #[test]
    fn the_service_the_cores_and_the_library_are_staged_together() {
        let names: Vec<&str> = app_files().iter().map(|(_, name)| *name).collect();
        for required in [
            "dnetd.exe",
            "primary-core.exe",
            "amneziawg-go.exe",
            "wintun.dll",
            "server-pins.json",
        ] {
            assert!(names.contains(&required), "{required} is not staged");
        }
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "a name is staged twice");
    }

    /// Every source named is one the repository has (the binaries are fetched or built; their licence
    /// texts are tracked), so a renamed file fails here rather than in a release build.
    #[test]
    fn every_licence_text_named_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (from, _) in licence_files() {
            assert!(root.join(&from).is_file(), "{} is missing", from.display());
        }
    }
}
