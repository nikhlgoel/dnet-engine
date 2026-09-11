//! DNet Engine build tooling.
//!
//! `verify-vendor` and `lint-branding` enforce the two binding licence obligations
//! recorded in `.specify/memory/constitution.md`. They run in CI and fail the build.

use anyhow::{bail, Result};
use std::path::PathBuf;

mod embedded;
mod fetch_vendor;
mod lint_branding;
mod pins;
mod verify_vendor;

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    let root = repo_root()?;

    match task.as_deref() {
        Some("fetch-vendor") => fetch_vendor::run(&root),
        Some("verify-vendor") => verify_vendor::run(&root),
        Some("lint-branding") => lint_branding::run(&root),
        Some(other) => {
            eprintln!("unknown task: {other}");
            print_help();
            bail!("unknown task")
        }
        None => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    eprintln!("usage: cargo xtask <task>");
    eprintln!();
    eprintln!("  fetch-vendor    download and hash-verify pinned third-party binaries");
    eprintln!("  verify-vendor   assert signed Wintun DLL; reject its source and embedded copies");
    eprintln!("  lint-branding   assert the primary core vendor name stays in attribution files");
}

/// The workspace root, resolved from this crate's manifest directory.
fn repo_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("could not resolve repository root"))
}
