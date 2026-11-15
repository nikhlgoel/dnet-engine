// SPDX-License-Identifier: GPL-3.0-or-later
//! T197 — `cargo xtask check-static-runtime <file>...`: refuse a program that needs the Visual C++ runtime installed.
//!
//! A Rust program for Windows built the default way loads `VCRUNTIME140.dll` when it starts. Windows 10 and 11 do not
//! come with that library; it arrives with other programs' installers. On a computer that has never had one, the
//! program does not start at all: Windows shows a dialog about a missing DLL (exit code `0xC0000135`), and a person who
//! just installed DNet Engine has a service that never runs. It was found in the lab VM, a clean Windows 11, where
//! every program built the default way failed and the same programs linked statically ran.
//!
//! The fix is to link the runtime into the program (`-C target-feature=+crt-static`, in `.cargo/config.toml` and in the
//! release job). This check is what makes the fix stay: it reads the imports of what is about to ship, so a build that
//! lost the flag fails before an installer is made, not on a stranger's computer.
//!
//! A program's imports are stored in it as plain text names of libraries, so the check looks for the names of the
//! runtime libraries in the file's bytes. That can read a program that merely mentions a name as a failure. A library
//! the loader must find when the program starts is spelled out in the file, so it is seen; a library a program loads
//! later under a name it builds while running is not. This is a guard for the build, not a proof about the program.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// The libraries a default Windows Rust build asks the person's computer for, by the start of their file names. The
/// universal C runtime (`api-ms-win-crt-*`, `ucrtbase`) is not here on purpose: Windows 10 and 11 ship it.
const NOT_IN_WINDOWS: [&str; 6] = [
    "vcruntime140",
    "msvcp140",
    "concrt140",
    "vcomp140",
    "vccorlib140",
    "mfc140",
];

/// The names from [`NOT_IN_WINDOWS`] that these bytes spell out as a library to load.
pub fn runtime_libraries_needed(bytes: &[u8]) -> Vec<&'static str> {
    let lower = bytes.to_ascii_lowercase();
    NOT_IN_WINDOWS
        .iter()
        .copied()
        .filter(|name| {
            lower
                .windows(name.len())
                .any(|window| window == name.as_bytes())
        })
        .collect()
}

/// Check each file. Errors name the file and the libraries, so a failed release says what to fix.
pub fn run(files: &[String]) -> Result<()> {
    if files.is_empty() {
        bail!("usage: cargo xtask check-static-runtime <file>...");
    }
    let mut problems = Vec::new();
    for file in files {
        let bytes = std::fs::read(file).with_context(|| format!("{file} could not be read"))?;
        let needed = runtime_libraries_needed(&bytes);
        if needed.is_empty() {
            println!("check-static-runtime: OK  {file}");
        } else {
            println!(
                "check-static-runtime: FAIL {file} needs {}",
                needed.join(", ")
            );
            problems.push(file.as_str());
        }
    }
    if !problems.is_empty() {
        bail!(
            "{} program(s) need a runtime library Windows does not ship; build with \
             RUSTFLAGS including `-C target-feature=+crt-static` (T197)",
            problems.len()
        );
    }
    Ok(())
}

/// The same check for the programs `stage-installer` has just built.
pub fn check_staged(repo_root: &Path, relative: &[&str]) -> Result<()> {
    let files: Vec<String> = relative
        .iter()
        .map(|r| repo_root.join(r).to_string_lossy().into_owned())
        .collect();
    run(&files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a default build has in its import table: a library name, in text, with a terminating zero.
    fn program_importing(libraries: &[&str]) -> Vec<u8> {
        let mut bytes = b"MZ\x90\x00 some code KERNEL32.dll\0".to_vec();
        for library in libraries {
            bytes.extend_from_slice(library.as_bytes());
            bytes.push(0);
        }
        bytes.extend_from_slice(b"api-ms-win-crt-runtime-l1-1-0.dll\0");
        bytes
    }

    #[test]
    fn a_program_that_loads_the_c_plus_plus_runtime_is_refused() {
        for library in ["VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll"] {
            let bytes = program_importing(&[library]);
            assert!(
                !runtime_libraries_needed(&bytes).is_empty(),
                "{library} was not noticed"
            );
        }
    }

    #[test]
    fn the_spelling_does_not_matter_but_the_library_does() {
        assert_eq!(
            runtime_libraries_needed(&program_importing(&["vcruntime140.DLL"])),
            ["vcruntime140"]
        );
        assert_eq!(
            runtime_libraries_needed(&program_importing(&["VCRUNTIME140.dll", "MSVCP140.dll"])),
            ["vcruntime140", "msvcp140"]
        );
    }

    /// Windows ships its own C runtime; a program that uses only that runs on a clean computer.
    #[test]
    fn a_program_that_needs_only_what_windows_ships_passes() {
        let bytes = program_importing(&["KERNEL32.dll", "ntdll.dll", "ucrtbase.dll"]);
        assert!(runtime_libraries_needed(&bytes).is_empty());
        assert!(runtime_libraries_needed(&[]).is_empty());
    }

    #[test]
    fn a_file_is_checked_by_name_and_a_missing_or_empty_list_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.exe");
        let good = dir.path().join("good.exe");
        std::fs::write(&bad, program_importing(&["VCRUNTIME140.dll"])).unwrap();
        std::fs::write(&good, program_importing(&["KERNEL32.dll"])).unwrap();
        let path = |p: &Path| p.to_string_lossy().into_owned();

        assert!(run(&[path(&good)]).is_ok());
        let error = run(&[path(&good), path(&bad)]).unwrap_err().to_string();
        assert!(error.contains("1 program(s)"), "{error}");
        assert!(run(&[]).is_err(), "no file named is not a pass");
        assert!(run(&[path(&dir.path().join("missing.exe"))]).is_err());
    }
}
