//! `installer/Sign-Files.ps1` and `installer/Test-Signature.ps1`: signing a release with the project's own
//! key (not a purchased certificate; `docs/release-signing.md`), and checking that what was signed is still
//! what was signed and was signed by that key.
//!
//! Each test makes a throwaway certificate in the current user's store, signs a copy of an unsigned
//! executable, and removes the certificate again, so nothing is left behind and no trust is granted: a
//! self-made certificate is deliberately not trusted by Windows, and the check does not need it to be.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn script(name: &str) -> PathBuf {
    repo_root().join("installer").join(name)
}

fn powershell() -> Option<Command> {
    let mut probe = Command::new("powershell");
    probe.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "exit 0",
    ]);
    // Is there a Windows PowerShell at all? Say so and skip, as the other script tests do.
    match probe.output() {
        Ok(_) => {
            let mut real = Command::new("powershell");
            real.args(["-NoProfile", "-ExecutionPolicy", "Bypass"]);
            Some(real)
        }
        Err(e) => {
            eprintln!("SKIPPED: no Windows PowerShell on this machine: {e}");
            None
        }
    }
}

fn run_script(file: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = powershell().expect("PowerShell");
    command.arg("-File").arg(file).args(args);
    // No key of the owner's leaks into a test through the environment.
    for k in [
        "DNET_SIGN_PFX",
        "DNET_SIGN_PFX_PASSWORD",
        "DNET_SIGN_THUMBPRINT",
        "DNET_SIGN_TIMESTAMP_URL",
    ] {
        command.env_remove(k);
    }
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().expect("run the script")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A certificate that exists only for one test and is removed when the guard drops.
struct Throwaway {
    thumbprint: String,
    sha256: String,
}

impl Throwaway {
    fn new(tag: &str) -> Throwaway {
        let subject = format!("CN=dnet-sign-test-{}-{tag}", std::process::id());
        let out = powershell()
            .expect("PowerShell")
            .arg("-Command")
            .arg(format!(
                "$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject '{subject}' \
                 -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(2); \
                 $c.Thumbprint; \
                 ([System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | ForEach-Object {{ $_.ToString('x2') }}) -join ''"
            ))
            .output()
            .expect("make a certificate");
        let printed = String::from_utf8_lossy(&out.stdout).to_string();
        let mut lines = printed.lines().map(str::trim).filter(|l| !l.is_empty());
        let thumbprint = lines
            .next()
            .unwrap_or_else(|| panic!("no certificate: {}", text(&out)))
            .to_string();
        let sha256 = lines.next().expect("no fingerprint").to_string();
        Throwaway { thumbprint, sha256 }
    }
}

impl Drop for Throwaway {
    fn drop(&mut self) {
        if let Some(mut c) = powershell() {
            let _ = c
                .arg("-Command")
                .arg(format!(
                    "Remove-Item -LiteralPath 'Cert:\\CurrentUser\\My\\{}' -ErrorAction SilentlyContinue",
                    self.thumbprint
                ))
                .output();
        }
    }
}

/// An unsigned executable to sign: a copy of this test's own program, in a folder of its own.
fn unsigned_copy(tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("dnet-sign-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sample.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &file).unwrap();
    (dir, file)
}

fn sign(file: &Path, key: &Throwaway) -> Output {
    // No timestamp server: a test must not need the network.
    run_script(
        &script("Sign-Files.ps1"),
        &[file.to_str().unwrap()],
        &[
            ("DNET_SIGN_THUMBPRINT", key.thumbprint.as_str()),
            ("DNET_SIGN_TIMESTAMP_URL", "none"),
        ],
    )
}

fn check(file: &Path, fingerprint: &str) -> Output {
    run_script(
        &script("Test-Signature.ps1"),
        &["-CertSha256", fingerprint, file.to_str().unwrap()],
        &[],
    )
}

#[test]
fn with_no_key_configured_nothing_is_signed_and_the_build_goes_on() {
    if powershell().is_none() {
        return;
    }
    let (dir, file) = unsigned_copy("nokey");
    let before = std::fs::read(&file).unwrap();
    let out = run_script(&script("Sign-Files.ps1"), &[file.to_str().unwrap()], &[]);
    let said = text(&out);
    let after = std::fs::read(&file).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("not signing"), "{said}");
    assert_eq!(before, after, "a file was changed with no key configured");
}

#[test]
fn a_file_signed_with_the_key_passes_the_check_for_that_key_and_only_that_key() {
    if powershell().is_none() {
        return;
    }
    let key = Throwaway::new("good");
    let (dir, file) = unsigned_copy("good");

    let signed = sign(&file, &key);
    assert_eq!(signed.status.code(), Some(0), "{}", text(&signed));

    let right = check(&file, &key.sha256);
    assert_eq!(right.status.code(), Some(0), "{}", text(&right));

    let wrong = check(&file, &"0".repeat(64));
    let said = text(&wrong);
    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(
        wrong.status.code(),
        Some(0),
        "a different key was accepted: {said}"
    );
    assert!(said.contains("FAIL"), "{said}");
}

#[test]
fn an_unsigned_file_fails_the_check() {
    if powershell().is_none() {
        return;
    }
    let (dir, file) = unsigned_copy("unsigned");
    let out = check(&file, &"0".repeat(64));
    let said = text(&out);
    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(out.status.code(), Some(0), "{said}");
    assert!(
        said.contains("FAIL") && said.contains("not signed"),
        "{said}"
    );
}

#[test]
fn a_file_changed_after_it_was_signed_fails_the_check() {
    if powershell().is_none() {
        return;
    }
    let key = Throwaway::new("tamper");
    let (dir, file) = unsigned_copy("tamper");
    let signed = sign(&file, &key);
    assert_eq!(signed.status.code(), Some(0), "{}", text(&signed));

    // One byte, well inside the part of the file the signature covers.
    let mut bytes = std::fs::read(&file).unwrap();
    let at = bytes.len() / 4;
    bytes[at] ^= 0xFF;
    std::fs::write(&file, bytes).unwrap();

    let out = check(&file, &key.sha256);
    let said = text(&out);
    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(out.status.code(), Some(0), "a changed file passed: {said}");
    assert!(said.contains("FAIL"), "{said}");
    assert!(
        said.contains("changed after it was signed"),
        "said something else: {said}"
    );
}

#[test]
fn a_key_that_is_configured_but_cannot_sign_stops_the_build_instead_of_leaving_a_file_unsigned() {
    if powershell().is_none() {
        return;
    }
    let (dir, file) = unsigned_copy("badkey");
    let out = run_script(
        &script("Sign-Files.ps1"),
        &[file.to_str().unwrap()],
        &[
            ("DNET_SIGN_THUMBPRINT", &"A".repeat(40)),
            ("DNET_SIGN_TIMESTAMP_URL", "none"),
        ],
    );
    let said = text(&out);
    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failed signing was reported as success: {said}"
    );
    // By the script's own message, not by a crash on the way: the file and the reason are named.
    assert!(said.contains("could not sign"), "{said}");
}

#[test]
fn a_file_that_does_not_exist_is_an_error_not_a_skip() {
    if powershell().is_none() {
        return;
    }
    let key = Throwaway::new("missing");
    let out = run_script(
        &script("Sign-Files.ps1"),
        &["C:\\does\\not\\exist.exe"],
        &[
            ("DNET_SIGN_THUMBPRINT", key.thumbprint.as_str()),
            ("DNET_SIGN_TIMESTAMP_URL", "none"),
        ],
    );
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
}
