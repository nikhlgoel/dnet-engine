//! Pinned digests of third-party binary images, shared by `fetch-vendor` and
//! `verify-vendor`.
//!
//! These serve two jobs. Downloads are checked against them, and `verify-vendor` uses
//! them to name any copy of these images it finds *embedded inside* a vendored
//! executable. Constitution licence obligation 2 forbids embedded copies (ADR-0004,
//! Finding 4).

/// One exact binary image, identified by length and SHA-256.
pub struct PinnedImage {
    pub label: &'static str,
    /// Architecture directory name as used by the image's own distribution.
    pub arch: &'static str,
    pub size: usize,
    pub sha256: &'static str,
}

/// The adapter DLLs in the official 0.14.1 distribution zip, one per `bin/<arch>`.
/// The Go loader patch pins the same digests (checked by a test below).
pub const WINTUN_DLLS: &[PinnedImage] = &[
    PinnedImage {
        label: "adapter DLL 0.14.1 (amd64)",
        arch: "amd64",
        size: 427_552,
        sha256: "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    },
    PinnedImage {
        label: "adapter DLL 0.14.1 (arm64)",
        arch: "arm64",
        size: 222_488,
        sha256: "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
    },
    PinnedImage {
        label: "adapter DLL 0.14.1 (x86)",
        arch: "x86",
        size: 550_928,
        sha256: "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
    },
    PinnedImage {
        label: "adapter DLL 0.14.1 (arm)",
        arch: "arm",
        size: 364_552,
        sha256: "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
    },
];

/// The packet-diversion kernel drivers the pinned primary core embeds unless built with
/// `with_external_windivert` (source commit `0b89958`, `common/windivert/assets`).
pub const PACKET_DIVERSION_DRIVERS: &[PinnedImage] = &[
    PinnedImage {
        label: "WinDivert64.sys kernel driver",
        arch: "amd64",
        size: 94_144,
        sha256: "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    },
    PinnedImage {
        label: "WinDivert32.sys kernel driver",
        arch: "x86",
        size: 79_792,
        sha256: "2f43f4251be4d72dd56c91bf6cce475d379eb9ba6c4dda2be3022ea633d5e807",
    },
];

/// Every image that must never appear embedded in a vendored executable.
pub fn forbidden_embedded_images() -> Vec<&'static PinnedImage> {
    WINTUN_DLLS.iter().chain(PACKET_DIVERSION_DRIVERS).collect()
}

pub fn wintun_dll(arch: &str) -> &'static PinnedImage {
    WINTUN_DLLS
        .iter()
        .find(|p| p.arch == arch)
        .expect("every shipped architecture has a pinned adapter DLL")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pin_is_a_full_lowercase_sha256_with_a_size() {
        for p in forbidden_embedded_images() {
            assert_eq!(p.sha256.len(), 64, "{}", p.label);
            assert!(p
                .sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
            assert!(p.size > 0, "{}", p.label);
        }
    }

    /// The Go loader patch carries its own copy of each DLL digest, because it runs inside
    /// the core. The two copies must never drift.
    #[test]
    fn loader_patch_pins_the_same_dll_digests() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("patches/sing-tun/internal/wintun");
        for dll in WINTUN_DLLS {
            let goarch = if dll.arch == "x86" { "386" } else { dll.arch };
            let file = dir.join(format!("dll_digest_windows_{goarch}.go"));
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            let pinned = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("const dllSHA256 = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("{} declares no dllSHA256", file.display()));
            assert_eq!(pinned, dll.sha256, "{} drifted", file.display());
        }
    }

    #[test]
    fn digest_helper_matches_a_known_vector() {
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
