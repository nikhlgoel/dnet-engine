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

/// The vendor name, in the spellings that would plausibly appear.
/// Assembled at runtime so this source file does not itself trip the lint.
fn forbidden_terms() -> Vec<String> {
    let base = ["sing", "box"].join("-");
    vec![base.clone(), base.replace('-', ""), base.replace('-', "_")]
}

/// Surfaces the obligation actually covers: anything user-facing or promotional.
const LINTED_ROOTS: &[&str] = &["apps", "installer", "crates", "vendor"];
const LINTED_ROOT_FILES: &[&str] = &["README.md"];

/// Attribution is required, so these surfaces are allowed to name the vendor.
/// Engineering documents under `docs/` and `specs/` are internal records, not
/// branding or marketing, and are likewise exempt.
const ALLOWED: &[&str] = &[
    "THIRD-PARTY-NOTICES.md",
    "docs/",
    "specs/",
    "vendor/primary-core/LICENSE",
    "vendor/primary-core/NOTICE.md",
    // The About screen is the one UI surface permitted to carry attribution.
    "apps/dnet-tray/src/lib/About.svelte",
    // This linter and its tests necessarily mention what they search for.
    "crates/xtask/src/lint_branding.rs",
    "crates/xtask/tests/",
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
    eprintln!("The primary transport core's licence carries a GPLv3 §7(e) term declining");
    eprintln!("to grant trademark rights. DNet Engine must not use that name in its product");
    eprintln!("name, branding, UI, installer, or marketing.");
    eprintln!();
    eprintln!("Refer to it in code and configuration as `primary_core` / `PrimaryCore`.");
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
        let entries =
            std::fs::read_dir(&dir).map_err(|e| anyhow!("failed to read {}: {e}", dir.display()))?;
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
