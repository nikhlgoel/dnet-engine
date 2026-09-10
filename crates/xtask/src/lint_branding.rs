//! T007 — `cargo xtask lint-branding`
//!
//! Enforces Constitution licence obligation 1: the primary transport core is
//! licensed GPL-3.0-or-later **plus an additional term permitted under GPLv3 §7(e)** —
//! *"no derivative work may use the name or imply association with this application
//! without prior consent."*
//!
//! DNet Engine therefore must not use that vendor's name in its product name,
//! branding, UI, installer, or marketing. Attribution in documentation and an About
//! screen is required and explicitly allowed.
//!
//! This check fails the build. See `docs/Research-Critique.md` §6.1.

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};

/// Names DNet Engine must not use in branding, UI, installer, or marketing.
///
/// Two independent obligations, both recorded in `.specify/memory/constitution.md`:
///
/// - **Obligation 1** — the primary transport core's licence carries a GPLv3 §7(e)
///   term declining to grant trademark rights.
/// - **Obligation 3** — the Wintun prebuilt licence §3(e) forbids using the
///   WireGuard LLC, WireGuard project, or Wintun names to endorse or promote
///   products derived from the Software (ADR-0004, Finding 1).
///
/// Assembled at runtime so this source file does not itself trip the lint.
fn forbidden_terms() -> Vec<String> {
    let core = ["sing", "box"].join("-");
    let wg = ["wire", "guard"].join("");
    let wt = ["win", "tun"].join("");
    vec![
        core.clone(),
        core.replace('-', ""),
        core.replace('-', "_"),
        wg,
        wt,
    ]
}

/// Surfaces the obligation actually covers: anything user-facing or promotional.
const LINTED_ROOTS: &[&str] = &["apps", "installer", "crates", "vendor"];
const LINTED_ROOT_FILES: &[&str] = &["README.md"];

/// Attribution is required, so these surfaces are allowed to name the vendors.
/// Engineering documents under `docs/` and `specs/`, and the `xtask` build tooling,
/// are internal records rather than branding or marketing, and are likewise exempt.
///
/// What this check protects is what a *user* sees: shipped binaries' strings, the UI,
/// the installer, and the README.
const ALLOWED: &[&str] = &[
    "THIRD-PARTY-NOTICES.md",
    "docs/",
    "specs/",
    "vendor/primary-core/LICENSE",
    "vendor/primary-core/NOTICE.md",
    "vendor/primary-core/BUILD-PROVENANCE.md",
    "vendor/amneziawg-go/LICENSE",
    "vendor/amneziawg-go/BUILD-PROVENANCE.md",
    "vendor/amneziawg-go/README.md",
    "vendor/wintun/LICENSE.txt",
    "vendor/wintun/README.md",
    // Build tooling. `xtask` never ships to a user, so it is not a branding or
    // marketing surface; and its whole job is naming what it fetches, builds, and
    // checks for. Linting it would make the check unsatisfiable.
    "crates/xtask/",
    // The About screen is the one UI surface permitted to carry attribution.
    "apps/dnet-tray/src/lib/About.svelte",
];

const LINTED_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "svelte", "html", "css", "json", "toml", "yml", "yaml", "md", "wxs",
    "nsi", "rc", "manifest",
];

pub fn run(repo_root: &Path) -> Result<()> {
    let terms = forbidden_terms();
    let mut violations: Vec<(PathBuf, usize, String)> = Vec::new();

    let mut targets: Vec<PathBuf> = Vec::new();
    for root in LINTED_ROOTS {
        let p = repo_root.join(root);
        if p.exists() {
            targets.extend(walk(&p)?);
        }
    }
    for f in LINTED_ROOT_FILES {
        let p = repo_root.join(f);
        if p.exists() {
            targets.push(p);
        }
    }

    for path in targets {
        if path.is_dir() || !is_linted(&path) || is_allowed(repo_root, &path) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // binary or unreadable; not a branding surface
        };
        for (i, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if terms.iter().any(|t| lower.contains(t.as_str())) {
                violations.push((path.clone(), i + 1, line.trim().to_string()));
            }
        }
    }

    if violations.is_empty() {
        println!("lint-branding: OK - primary core vendor name confined to attribution surfaces");
        return Ok(());
    }

    eprintln!("lint-branding: FAILED ({} occurrence(s))", violations.len());
    for (path, line, text) in &violations {
        let rel = path.strip_prefix(repo_root).unwrap_or(path);
        let shown: String = text.chars().take(120).collect();
        eprintln!("  {}:{}: {}", rel.display(), line, shown);
    }
    eprintln!();
    eprintln!("Two licence obligations restrict these names in branding, UI, installer,");
    eprintln!("and marketing surfaces:");
    eprintln!();
    eprintln!("  1. The primary transport core's licence carries a GPLv3 §7(e) term");
    eprintln!("     declining to grant trademark rights. Refer to it in code and");
    eprintln!("     configuration as `primary_core` / `PrimaryCore`.");
    eprintln!("  3. The Wintun prebuilt licence §3(e) forbids using the WireGuard LLC,");
    eprintln!("     WireGuard project, or Wintun names to endorse or promote this product.");
    eprintln!();
    eprintln!("Attribution belongs in THIRD-PARTY-NOTICES.md and the About screen only.");
    bail!("lint-branding failed")
}

fn is_linted(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| LINTED_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn is_allowed(repo_root: &Path, path: &Path) -> bool {
    let rel = path
        .strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    ALLOWED.iter().any(|a| {
        if a.ends_with('/') {
            rel.starts_with(a)
        } else {
            rel == *a
        }
    })
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
            if name == ".git" || name == "target" || name == "node_modules" || name == "dist" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}
