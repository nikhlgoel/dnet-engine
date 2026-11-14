// SPDX-License-Identifier: GPL-3.0-or-later
//! T191 — every Rust source file says what it is licensed under, on its first line.
//!
//! The project is GPL-3.0-or-later (`Cargo.toml`, `LICENSE`). A file that is copied out of the repository
//! should still say so, and a file that arrives from somewhere else under another licence should be noticed:
//! this test fails on any Rust file whose first line is not the project's identifier.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    const LINE: &str = "// SPDX-License-Identifier: GPL-3.0-or-later";

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // Build output, dependencies and generated code are not the project's sources.
                if matches!(name.as_ref(), "target" | "node_modules" | "gen" | "dist")
                    || name.starts_with('.')
                {
                    continue;
                }
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn every_rust_file_starts_with_the_projects_licence_identifier() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for dir in ["crates", "apps/dnet-tray/src-tauri", "testing"] {
            rust_files(&root.join(dir), &mut files);
        }
        assert!(files.len() > 200, "found only {} Rust files", files.len());
        let missing: Vec<String> = files
            .iter()
            .filter(|f| {
                std::fs::read_to_string(f)
                    .ok()
                    .and_then(|text| text.lines().next().map(|l| l.trim_end() != LINE))
                    .unwrap_or(true)
            })
            .map(|f| f.display().to_string())
            .collect();
        assert!(
            missing.is_empty(),
            "no licence identifier on the first line of: {missing:#?}"
        );
    }
}
