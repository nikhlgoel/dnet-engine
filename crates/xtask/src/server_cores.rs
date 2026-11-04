//! T149 — `cargo xtask build-server-cores --base-url <https://…/>`: the Linux builds of the two server-side
//! cores, from the same pinned commits as the client's (T093 gap: until now nothing made them).
//!
//! For each core and each processor (amd64, arm64) the pinned commit is fetched, confirmed to be exactly
//! that commit, and built with the Go toolchain (`CGO_ENABLED=0 GOOS=linux`, `-trimpath`). The files and a
//! `server-pins.json` (names and SHA-256 of each) are written to `target/server-cores`. The release
//! workflow uploads them as release assets, and the installer ships `server-pins.json` beside the service,
//! which is how the setup script learns what to download and what checksum to demand.
//!
//! The pinned source needs no patch here: the client's patch concerns only the Windows adapter loader.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use dnet_provision::server_pins::{BuiltFile, PinnedCore, ServerPins, PINS_VERSION};

use crate::fetch_vendor::{capture, remove_tree, run_cmd, GoSource, GO_SOURCES};
use crate::pins::sha256_hex;

pub const OUT_DIR: &str = "target/server-cores";
const ARCHES: [&str; 2] = ["amd64", "arm64"];

/// What a core is built with on a server: the Hysteria 2 and REALITY inbounds, and the session endpoint they
/// forward to (ADR-0008). The endpoint runs in user space, which is the gVisor tag; nothing else of the
/// client's tunnel (no control API, no packet-diversion driver).
fn server_tags(dest: &str) -> &'static str {
    match dest {
        "primary-core" => "with_quic,with_utls,with_wireguard,with_gvisor",
        _ => "",
    }
}

/// The name a built file has in the release.
pub fn asset_name(core: &str, arch: &str) -> String {
    format!("{core}-linux-{arch}")
}

/// The licence identifier recorded for a core (PR-15).
fn licence_of(dest: &str) -> &'static str {
    match dest {
        "primary-core" => "GPL-3.0-or-later",
        _ => "MIT",
    }
}

pub fn run(repo_root: &Path, args: &[String]) -> Result<()> {
    let base_url = match args {
        [flag, url] if flag == "--base-url" => url.as_str(),
        _ => bail!("usage: cargo xtask build-server-cores --base-url <https://…/releases/download/vX.Y.Z/>"),
    };
    crate::fetch_vendor::require_tool("go", &["version"])
        .context("the Go toolchain is required")?;
    let out = repo_root.join(OUT_DIR);
    if out.exists() {
        remove_tree(&out)?;
    }
    std::fs::create_dir_all(&out)?;

    let mut cores = Vec::new();
    for src in GO_SOURCES {
        cores.push(build_core(src, &out)?);
    }
    let mut cores = cores.into_iter();
    let (primary_core, amneziawg) = (cores.next().unwrap(), cores.next().unwrap());
    let pins = pins_from(base_url, primary_core, amneziawg)?;
    std::fs::write(out.join("server-pins.json"), pins.render())?;

    let mut sums = String::new();
    for core in [&pins.primary_core, &pins.amneziawg] {
        for built in [&core.amd64, &core.arm64] {
            sums.push_str(&format!("{}  {}\n", built.sha256, built.file));
        }
    }
    std::fs::write(out.join("SHA256SUMS.txt"), sums)?;
    println!(
        "build-server-cores: OK - {} files and server-pins.json in {OUT_DIR}",
        ARCHES.len() * 2
    );
    Ok(())
}

/// Assemble and check the list. Pure, so it is tested without a Go toolchain.
pub fn pins_from(
    base_url: &str,
    primary_core: PinnedCore,
    amneziawg: PinnedCore,
) -> Result<ServerPins> {
    let pins = ServerPins {
        version: PINS_VERSION,
        base_url: base_url.to_owned(),
        primary_core,
        amneziawg,
    };
    // The same strict read a client makes of it, so a list that would be refused is never published.
    ServerPins::parse(&pins.render())
        .map_err(|e| anyhow::anyhow!("the list would be refused: {e}"))?;
    Ok(pins)
}

fn build_core(src: &GoSource, out: &Path) -> Result<PinnedCore> {
    let work = out.join(format!(".src-{}", src.dest));
    println!("{}: fetching source at {}", src.dest, &src.commit[..12]);
    std::fs::create_dir_all(&work)?;
    run_cmd("git", &["init", "--quiet", work.to_str().unwrap()], None)?;
    run_cmd("git", &["remote", "add", "origin", src.repo], Some(&work))?;
    run_cmd(
        "git",
        &["fetch", "--quiet", "--depth", "1", "origin", src.commit],
        Some(&work),
    )?;
    run_cmd("git", &["checkout", "--quiet", "FETCH_HEAD"], Some(&work))?;
    let head = capture("git", &["rev-parse", "HEAD"], Some(&work))?;
    if head.trim() != src.commit {
        bail!(
            "{}: expected commit {}, the tree is at {}",
            src.dest,
            src.commit,
            head.trim()
        );
    }

    crate::fetch_vendor::warm_go_cache(&work);
    let mut built = Vec::new();
    for arch in ARCHES {
        let file = asset_name(src.dest, arch);
        let path = out.join(&file);
        println!("  building {file}");
        let tags = server_tags(src.dest);
        let mut command = Command::new("go");
        command
            .current_dir(&work)
            .env("CGO_ENABLED", "0")
            .env("GOOS", "linux")
            .env("GOARCH", arch)
            .args(["build", "-trimpath", "-ldflags", "-s -w", "-o"])
            .arg(&path);
        if !tags.is_empty() {
            command.args(["-tags", tags]);
        }
        command.arg(src.package);
        let status = command.status().context("go could not be run")?;
        if !status.success() {
            bail!("building {file} failed");
        }
        let bytes = std::fs::read(&path)?;
        // A Linux program starts with the ELF magic; anything else was not built for Linux.
        if bytes.get(..4) != Some(&[0x7f, b'E', b'L', b'F']) {
            bail!("{file} is not a Linux program");
        }
        built.push(BuiltFile {
            file,
            sha256: sha256_hex(&bytes),
        });
    }
    remove_tree(&work)?;
    let mut built = built.into_iter();
    Ok(PinnedCore {
        name: src.dest.to_owned(),
        version: src.version.to_owned(),
        licence: licence_of(src.dest).to_owned(),
        source: src.repo.to_owned(),
        amd64: built.next().unwrap(),
        arm64: built.next().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(name: &str, tag: char) -> PinnedCore {
        PinnedCore {
            name: name.to_owned(),
            version: "v1.0.0".to_owned(),
            licence: "MIT".to_owned(),
            source: "https://example.test/src".to_owned(),
            amd64: BuiltFile {
                file: asset_name(name, "amd64"),
                sha256: tag.to_string().repeat(64),
            },
            arm64: BuiltFile {
                file: asset_name(name, "arm64"),
                sha256: tag
                    .to_ascii_uppercase()
                    .to_string()
                    .to_ascii_lowercase()
                    .repeat(64),
            },
        }
    }

    #[test]
    fn files_are_named_by_core_and_processor() {
        assert_eq!(
            asset_name("primary-core", "amd64"),
            "primary-core-linux-amd64"
        );
        assert_eq!(
            asset_name("amneziawg-go", "arm64"),
            "amneziawg-go-linux-arm64"
        );
    }

    #[test]
    fn a_complete_build_makes_a_list_a_client_accepts() {
        let pins = pins_from(
            "https://example.test/d/",
            core("primary-core", 'a'),
            core("amneziawg-go", 'b'),
        )
        .unwrap();
        assert_eq!(ServerPins::parse(&pins.render()).unwrap(), pins);
    }

    #[test]
    fn a_list_a_client_would_refuse_is_never_made() {
        for url in [
            "http://example.test/d/",
            "https://example.test/d",
            "https://example.test/$(x)/",
        ] {
            assert!(
                pins_from(url, core("primary-core", 'a'), core("amneziawg-go", 'b')).is_err(),
                "{url}"
            );
        }
        let mut bad = core("primary-core", 'a');
        bad.amd64.sha256 = "xyz".to_owned();
        assert!(pins_from("https://example.test/d/", bad, core("amneziawg-go", 'b')).is_err());
    }

    #[test]
    fn the_primary_core_gets_the_server_inbounds_and_the_session_endpoint_and_nothing_of_the_clients(
    ) {
        let tags: Vec<&str> = server_tags("primary-core").split(',').collect();
        // The carriers (Hysteria 2, REALITY) and the session endpoint with its user-space network stack
        // (`system: false` is behind the gVisor tag), ADR-0008 §11.
        for needed in ["with_quic", "with_utls", "with_wireguard", "with_gvisor"] {
            assert!(tags.contains(&needed), "{needed}");
        }
        for client_only in ["with_clash_api", "with_external_windivert"] {
            assert!(!tags.contains(&client_only), "{client_only}");
        }
        assert_eq!(server_tags("amneziawg-go"), "");
    }

    #[test]
    fn the_licences_are_the_ones_the_notices_state() {
        assert_eq!(licence_of("primary-core"), "GPL-3.0-or-later");
        assert_eq!(licence_of("amneziawg-go"), "MIT");
    }
}
