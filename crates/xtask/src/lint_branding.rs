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
const LINTED_ROOTS: &[&str] = &["apps", "installer", "crates", "vendor", "site"];
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
    "nsi", "nsh", "rc", "manifest",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The names, built the way the lint builds them, so this file stays clean of them too.
    fn names() -> [String; 5] {
        [
            ["sing", "box"].join("-"),
            ["sing", "box"].join(""),
            ["sing", "box"].join("_"),
            ["wire", "guard"].join(""),
            ["win", "tun"].join(""),
        ]
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn lint(root: &Path) -> bool {
        run(root).is_ok()
    }

    // ---------------------------------------------------------------- the list of names

    #[test]
    fn every_spelling_of_every_name_is_forbidden() {
        let terms = forbidden_terms();
        assert_eq!(terms.len(), 5);
        for name in names() {
            assert!(terms.contains(&name), "{name} is not forbidden");
        }
    }

    // ---------------------------------------------------------------- which files are looked at

    #[test]
    fn only_text_that_can_reach_a_person_is_linted() {
        for yes in [
            "a.rs",
            "a.ts",
            "a.tsx",
            "a.js",
            "a.svelte",
            "a.html",
            "a.css",
            "a.json",
            "a.toml",
            "a.yml",
            "a.yaml",
            "a.md",
            "a.wxs",
            "a.nsi",
            "a.nsh",
            "a.rc",
            "a.manifest",
        ] {
            assert!(is_linted(Path::new(yes)), "{yes}");
        }
        for no in [
            "a.png",
            "a.exe",
            "a.dll",
            "a.ico",
            "a.txt",
            "a.lock",
            "a",
            "rs",
            ".gitignore",
            "a.rs.bak",
        ] {
            assert!(!is_linted(Path::new(no)), "{no}");
        }
    }

    #[test]
    fn an_upper_case_extension_is_still_linted() {
        assert!(is_linted(Path::new("A.RS")));
        assert!(is_linted(Path::new("README.MD")));
    }

    #[test]
    fn the_attribution_surfaces_are_allowed_and_nothing_near_them_is() {
        let root = Path::new("repo");
        for allowed in [
            "THIRD-PARTY-NOTICES.md",
            "docs/adr/0001.md",
            "specs/001/tasks.md",
            "vendor/primary-core/LICENSE",
            "vendor/primary-core/NOTICE.md",
            "vendor/primary-core/BUILD-PROVENANCE.md",
            "vendor/amneziawg-go/LICENSE",
            "vendor/amneziawg-go/README.md",
            "vendor/wintun/LICENSE.txt",
            "vendor/wintun/README.md",
            "crates/xtask/src/main.rs",
            "apps/dnet-tray/src/lib/About.svelte",
        ] {
            assert!(is_allowed(root, &root.join(allowed)), "{allowed}");
        }
        for not_allowed in [
            "README.md",
            "docs-extra/a.md",
            "doc/a.md",
            "specs2/a.md",
            "vendor/primary-core/LICENSE2",
            "vendor/primary-core/README.md",
            "vendor/wintun/other.md",
            "crates/xtask2/src/a.rs",
            "crates/dnetd/src/main.rs",
            "apps/dnet-tray/src/lib/About.svelte.bak",
            "apps/dnet-tray/src/views/Settings.svelte",
            "installer/a.wxs",
            "site/index.html",
            "THIRD-PARTY-NOTICES.md.old",
        ] {
            assert!(!is_allowed(root, &root.join(not_allowed)), "{not_allowed}");
        }
    }

    // ---------------------------------------------------------------- the walk

    #[test]
    fn the_walk_finds_nested_files_and_skips_the_four_folders_it_must() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a.rs", "");
        write(root, "deep/er/b.rs", "");
        for skipped in [".git", "target", "node_modules", "dist"] {
            write(root, &format!("{skipped}/x.rs"), "");
            write(root, &format!("sub/{skipped}/y.rs"), "");
        }
        let mut found: Vec<String> = walk(root)
            .unwrap()
            .into_iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect();
        found.sort();
        assert_eq!(found, ["a.rs", "deep/er/b.rs"]);
    }

    #[test]
    fn a_folder_that_cannot_be_read_is_an_error_naming_it() {
        let missing = Path::new("this/folder/does/not/exist");
        let error = walk(missing).unwrap_err().to_string();
        assert!(error.contains("exist"), "{error}");
    }

    // ---------------------------------------------------------------- the whole check

    #[test]
    fn a_clean_repository_passes() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "apps/ui/main.ts", "export const x = 1;");
        write(dir.path(), "README.md", "A network resilience client.");
        assert!(lint(dir.path()));
    }

    #[test]
    fn an_empty_repository_passes() {
        let dir = tempfile::tempdir().unwrap();
        assert!(lint(dir.path()));
    }

    #[test]
    fn each_name_in_a_user_facing_file_fails_the_check() {
        for name in names() {
            let dir = tempfile::tempdir().unwrap();
            write(
                dir.path(),
                "apps/ui/App.svelte",
                &format!("<h1>Powered by {name}</h1>"),
            );
            assert!(!lint(dir.path()), "{name} was let through");
        }
    }

    #[test]
    fn the_match_ignores_case() {
        for name in names() {
            let dir = tempfile::tempdir().unwrap();
            write(
                dir.path(),
                "installer/product.wxs",
                &name.to_ascii_uppercase(),
            );
            assert!(!lint(dir.path()), "{name} in capitals was let through");
        }
    }

    #[test]
    fn a_name_inside_a_longer_word_is_still_caught() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "crates/dnetd/src/lib.rs",
            &format!("let x = \"my{}2\";", names()[3]),
        );
        assert!(!lint(dir.path()));
    }

    #[test]
    fn a_name_on_the_last_line_without_a_newline_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "site/index.html",
            &format!("<p>ok</p>\n<p>{}", names()[4]),
        );
        assert!(!lint(dir.path()));
    }

    #[test]
    fn the_readme_at_the_root_is_a_surface() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "README.md",
            &format!("Built on {}.", names()[0]),
        );
        assert!(!lint(dir.path()));
    }

    #[test]
    fn attribution_where_it_is_allowed_passes() {
        let dir = tempfile::tempdir().unwrap();
        let name = &names()[0];
        write(dir.path(), "THIRD-PARTY-NOTICES.md", name);
        write(dir.path(), "docs/adr/x.md", name);
        write(dir.path(), "vendor/primary-core/LICENSE", name);
        write(dir.path(), "crates/xtask/src/a.rs", name);
        write(dir.path(), "apps/dnet-tray/src/lib/About.svelte", name);
        assert!(lint(dir.path()));
    }

    #[test]
    fn a_neighbour_of_an_allowed_file_is_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "vendor/primary-core/README.md", &names()[0]);
        assert!(!lint(dir.path()));
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "apps/dnet-tray/src/views/Settings.svelte",
            &names()[0],
        );
        assert!(!lint(dir.path()));
    }

    #[test]
    fn a_name_in_a_file_type_that_is_not_linted_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "apps/ui/notes.txt", &names()[0]);
        write(dir.path(), "apps/ui/data.bin", &names()[1]);
        assert!(lint(dir.path()));
    }

    #[test]
    fn a_name_in_a_skipped_folder_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "apps/ui/node_modules/pkg/index.js", &names()[0]);
        write(dir.path(), "crates/dnetd/target/gen.rs", &names()[0]);
        write(dir.path(), "apps/ui/dist/app.js", &names()[0]);
        assert!(lint(dir.path()));
    }

    #[test]
    fn a_name_outside_the_linted_roots_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "notes/todo.md", &names()[0]);
        write(dir.path(), "OTHER.md", &names()[0]);
        assert!(lint(dir.path()));
    }

    #[test]
    fn a_file_that_is_not_text_is_skipped_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("apps/ui/blob.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert!(lint(dir.path()));
    }

    #[test]
    fn one_violation_among_many_clean_files_still_fails() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..30 {
            write(dir.path(), &format!("apps/ui/f{n}.ts"), "clean");
        }
        write(dir.path(), "apps/ui/f17.ts", &format!("// {}", names()[2]));
        assert!(!lint(dir.path()));
    }
}
