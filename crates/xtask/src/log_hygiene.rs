// SPDX-License-Identifier: GPL-3.0-or-later
//! T198 — what the log may carry, enforced.
//!
//! The service keeps a log file (`dnetd/src/logfile.rs`). A log is read by people the person sends it to, and it
//! outlives the run that wrote it, so a line that names a credential, a key or a token would be a leak that nobody
//! notices until a report is posted in public. This test reads every `tracing` call in the product's code and refuses
//! one whose arguments (not its message text) name such a thing.
//!
//! It reads the call's fields and values: `tracing::warn!(key = ?secret, "...")` is refused, and
//! `tracing::warn!("a sealed credential set was left behind")` is not, because words in a sentence leak nothing. It is
//! a guard against the careless line, not a proof about every possible format string: a value interpolated inside the
//! message (`"{e}"`) is as safe as the error it prints, and those errors are the secret store's, which never carry a
//! byte of the credentials (`dnet-config/src/secret_store.rs`).

use std::path::Path;

/// Names that must not appear as a field or a value in a log call.
const FORBIDDEN: [&str; 14] = [
    "password",
    "passwd",
    "secret",
    "private_key",
    "privatekey",
    "credential",
    "token",
    "expose",
    "psk",
    "obfs",
    "short_id",
    "auth_",
    "uuid",
    "signing_key",
];

/// One refused call: where it is and what it names.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub name: &'static str,
}

/// Where the product's code ends in `source`: at a `#[cfg(test)]` that opens a module. (A `#[cfg(test)]` on one
/// function or `use` is not the end of the product's code, and cutting there hid the log calls after it.)
fn product_part(source: &str) -> &str {
    let mut from = 0;
    while let Some(found) = source[from..].find("#[cfg(test)]") {
        let at = from + found;
        let after = source[at + "#[cfg(test)]".len()..].trim_start();
        let after = after.strip_prefix("pub ").unwrap_or(after).trim_start();
        if after.starts_with("mod ") {
            return &source[..at];
        }
        from = at + 1;
    }
    source
}

/// The arguments of every log call in `source` (the product's part of it), with the text of string literals
/// removed, and the line each starts on. A call is `info!(`, `warn!(`, `error!(`, `debug!(` or `trace!(`, with or
/// without a `tracing::` in front: `use tracing::info; info!(..)` is the same call.
fn call_arguments(source: &str) -> Vec<(usize, String)> {
    let code = product_part(source);
    let bytes = code.as_bytes();
    let mut calls = Vec::new();
    let mut from = 0;
    while from < code.len() {
        // The next macro name that opens a call.
        let next = ["info!(", "warn!(", "error!(", "debug!(", "trace!("]
            .iter()
            .filter_map(|name| code[from..].find(name).map(|at| (from + at, name.len())))
            .min();
        let Some((start, name_len)) = next else { break };
        from = start + name_len;
        // Not part of a longer name (`my_info!(`).
        let before = code[..start].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let open = start + name_len - 1; // the "("
        let mut depth = 0usize;
        let mut index = open;
        let mut args = String::new();
        let mut in_string = false;
        let mut escaped = false;
        while index < bytes.len() {
            let c = bytes[index] as char;
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                    args.push('"');
                }
            } else {
                match c {
                    '"' => {
                        in_string = true;
                        args.push('"');
                    }
                    '(' => {
                        depth += 1;
                        args.push(c);
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        args.push(c);
                    }
                    _ => args.push(c),
                }
            }
            index += 1;
        }
        let line = code[..start].matches('\n').count() + 1;
        calls.push((line, args));
        from = index.min(code.len());
    }
    calls
}

/// The calls in `source` whose arguments name something that must not be logged.
pub fn findings(source: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line, args) in call_arguments(source) {
        let lower = args.to_ascii_lowercase();
        if let Some(name) = FORBIDDEN.iter().find(|name| lower.contains(*name)) {
            out.push(Finding { line, name });
        }
    }
    out
}

/// Every Rust source file of the product's crates (not their tests, examples or this tool).
pub fn product_sources(repo_root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![
        repo_root.join("crates"),
        repo_root
            .join("apps")
            .join("dnet-tray")
            .join("src-tauri")
            .join("src"),
    ];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !matches!(name.as_str(), "tests" | "examples" | "xtask" | "target") {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" {
                found.push(path);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_that_names_a_credential_is_refused() {
        let source = r#"
fn f() {
    tracing::info!(password = %p, "connecting");
    tracing::warn!(?credentials, "the plan");
    tracing::error!(error = %e, key = %secret.expose(), "x");
}
"#;
        let found = findings(source);
        assert_eq!(found.len(), 3, "{found:?}");
        assert_eq!(found[0].name, "password");
        assert_eq!(found[0].line, 3);
        assert_eq!(found[1].name, "credential");
    }

    /// Words in a sentence leak nothing; only fields and values are read.
    #[test]
    fn words_in_the_message_are_not_a_finding() {
        let source = r#"
fn f() {
    tracing::warn!("a sealed credential set was left behind after a failed save: {cleanup}");
    tracing::error!(%error, "the credentials for the race could not be read");
    tracing::warn!("not sending it the secret");
}
"#;
        assert_eq!(findings(source), []);
    }

    #[test]
    fn a_call_that_spans_lines_and_nests_is_read_whole() {
        let source = r#"
fn f() {
    tracing::debug!(
        addr = %format!("{}", ip),
        why = ?inner(token),
        "message (with parentheses)"
    );
}
"#;
        let found = findings(source);
        assert_eq!(
            found,
            [Finding {
                line: 3,
                name: "token"
            }]
        );
    }

    #[test]
    fn code_after_the_test_marker_is_not_read() {
        let source = "fn f() { tracing::info!(\"fine\"); }\n#[cfg(test)]\nmod t { fn g() { tracing::info!(password = 1); } }\n";
        assert_eq!(findings(source), []);
    }

    /// A test-only function in the middle of a file does not end the product's code.
    #[test]
    fn a_cfg_test_on_one_function_does_not_hide_the_calls_after_it() {
        let source = "#[cfg(test)]\nfn helper() {}\nfn f() { tracing::warn!(password = 1); }\n";
        assert_eq!(
            findings(source),
            [Finding {
                line: 3,
                name: "password"
            }]
        );
        // But a test module is the end of it.
        let module =
            "fn f() {}\n#[cfg(test)]\nmod tests { fn g() { tracing::warn!(password = 1); } }\n";
        assert_eq!(findings(module), []);
    }

    /// `use tracing::info;` and a bare `info!(..)` are the same call.
    #[test]
    fn a_call_without_the_crate_name_in_front_is_read_too() {
        let source = "use tracing::info;\nfn f() { info!(key = ?secret_value, \"x\"); }\n";
        assert_eq!(
            findings(source),
            [Finding {
                line: 2,
                name: "secret"
            }]
        );
        // A longer macro name that merely ends in one of these is not a log call.
        assert_eq!(findings("fn f() { my_info!(password = 1); }"), []);
    }

    #[test]
    fn a_string_with_an_escaped_quote_does_not_end_early() {
        let source = r#"fn f() { tracing::info!("say \"secret\" then", port = 1); }"#;
        assert_eq!(findings(source), []);
    }

    /// The real check: nothing the product logs names a credential.
    #[test]
    fn no_log_call_in_the_product_names_a_credential() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let files = product_sources(&root);
        assert!(
            files.len() > 50,
            "only {} files found: the walk is broken",
            files.len()
        );
        let mut calls = 0;
        let mut problems = Vec::new();
        for file in files {
            let source = std::fs::read_to_string(&file).unwrap_or_default();
            calls += call_arguments(&source).len();
            for finding in findings(&source) {
                problems.push(format!(
                    "{}:{} names `{}`",
                    file.strip_prefix(&root).unwrap_or(&file).display(),
                    finding.line,
                    finding.name
                ));
            }
        }
        assert!(
            calls > 40,
            "only {calls} log calls found: the reader is broken"
        );
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}
