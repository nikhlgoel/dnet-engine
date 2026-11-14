// SPDX-License-Identifier: GPL-3.0-or-later
//! `testing/log.ps1` — the wrapper `LOCAL-COMMANDS.md` runs every local command through. The log is
//! what an assistant reads instead of the screen, so whatever a command prints must reach it: cargo
//! writes compile errors, clippy warnings and test panics to stderr, not stdout.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn the_log_holds_what_the_command_wrote_to_stderr_and_its_exit_code() {
    let root = repo_root();
    let id = format!("xtask-test-{}", std::process::id());
    let output = match Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(root.join("testing").join("log.ps1"))
        .arg(&id)
        .arg("cmd /c 'echo to-stdout & (echo.)1>&2 & echo to-stderr 1>&2 & exit 3'")
        .current_dir(&root)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("SKIPPED: no Windows PowerShell on this machine: {e}");
            return;
        }
    };
    let log_path = root.join(".local-logs").join(format!("{id}.log"));
    let log = std::fs::read_to_string(&log_path);
    let _ = std::fs::remove_file(&log_path);
    let log = log.expect("log.ps1 wrote no log");

    // Whole lines: the `# command:` header holds both words too, and must not satisfy the check.
    let printed = |word: &str| log.lines().any(|line| line.trim() == word);
    assert_eq!(output.status.code(), Some(3), "{log}");
    assert!(printed("to-stdout"), "{log}");
    assert!(
        printed("to-stderr"),
        "stderr is missing from the log:\n{log}"
    );
    for wrapper in ["NativeCommandError", "RemoteException"] {
        assert!(
            !log.contains(wrapper),
            "stderr reached the log wrapped as a PowerShell error, not as the command's own words:\n{log}"
        );
    }
    assert!(log.contains("# exit:     3"), "{log}");
}
