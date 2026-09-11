//! Finds executable images embedded inside another executable's bytes.
//!
//! A Go program that compiles a DLL or driver into itself (`//go:embed`) carries the file
//! byte-for-byte, so the copy begins with a complete PE header. We look for PE headers
//! anywhere past offset 0, then name each one against the pinned forbidden images.
//!
//! An unidentified embedded image is still reported. A future upstream version
//! could embed a *different* build of the same DLL, which no digest would match.

use crate::pins::{sha256_hex, PinnedImage};

/// Offset of `e_lfanew` (the PE header's file offset) inside the DOS header.
const E_LFANEW_FIELD: usize = 0x3C;
/// Plausible `e_lfanew` bounds. Linkers emit values from 0x40 to a few hundred bytes;
/// the bound keeps random "MZ" pairs from matching by chance.
const E_LFANEW_RANGE: std::ops::RangeInclusive<usize> = 0x40..=0x1000;

#[derive(Debug, PartialEq, Eq)]
pub struct EmbeddedImage {
    pub offset: usize,
    /// Label of the pinned image this is a byte-identical copy of, if any.
    pub identified: Option<&'static str>,
}

/// Every PE image embedded in `bytes` after offset 0 (offset 0 is the host executable).
///
/// Images lying inside an identified copy are its own contents (the adapter DLL carries
/// its drivers as resources) and are folded into that finding rather than reported again.
pub fn find_embedded_images(bytes: &[u8], known: &[&'static PinnedImage]) -> Vec<EmbeddedImage> {
    let candidates: Vec<(usize, Option<&'static PinnedImage>)> = (1..bytes.len())
        .filter(|&offset| is_pe_image_at(bytes, offset))
        .map(|offset| {
            let pin = known.iter().copied().find(|pin| {
                bytes
                    .get(offset..offset + pin.size)
                    .is_some_and(|window| sha256_hex(window) == pin.sha256)
            });
            (offset, pin)
        })
        .collect();

    let identified_spans: Vec<std::ops::Range<usize>> = candidates
        .iter()
        .filter_map(|(offset, pin)| pin.map(|p| *offset..offset + p.size))
        .collect();

    candidates
        .into_iter()
        .filter(|(offset, pin)| {
            pin.is_some() || !identified_spans.iter().any(|span| span.contains(offset))
        })
        .map(|(offset, pin)| EmbeddedImage {
            offset,
            identified: pin.map(|p| p.label),
        })
        .collect()
}

fn is_pe_image_at(bytes: &[u8], offset: usize) -> bool {
    if bytes.get(offset..offset + 2) != Some(b"MZ".as_slice()) {
        return false;
    }
    let Some(field) = bytes.get(offset + E_LFANEW_FIELD..offset + E_LFANEW_FIELD + 4) else {
        return false;
    };
    let e_lfanew = u32::from_le_bytes(field.try_into().expect("4-byte slice")) as usize;
    E_LFANEW_RANGE.contains(&e_lfanew)
        && bytes.get(offset + e_lfanew..offset + e_lfanew + 4) == Some(b"PE\0\0".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE-shaped image: DOS magic, `e_lfanew`, PE signature, then filler.
    fn fake_image(len: usize, fill: u8) -> Vec<u8> {
        let mut img = vec![fill; len];
        img[0..2].copy_from_slice(b"MZ");
        img[E_LFANEW_FIELD..E_LFANEW_FIELD + 4].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        img
    }

    fn host_with(payload: &[u8], at: usize) -> Vec<u8> {
        let mut host = fake_image(at, 0);
        host.extend_from_slice(payload);
        host.extend_from_slice(&[0u8; 64]);
        host
    }

    fn pin_for(img: &[u8]) -> &'static PinnedImage {
        Box::leak(Box::new(PinnedImage {
            label: "test image",
            arch: "amd64",
            size: img.len(),
            sha256: Box::leak(sha256_hex(img).into_boxed_str()),
        }))
    }

    #[test]
    fn host_executable_alone_has_no_embedded_images() {
        assert!(find_embedded_images(&fake_image(4096, 7), &[]).is_empty());
    }

    #[test]
    fn a_pinned_image_embedded_mid_file_is_found_and_named() {
        let payload = fake_image(2048, 0xAB);
        let host = host_with(&payload, 5000);
        let found = find_embedded_images(&host, &[pin_for(&payload)]);
        assert_eq!(
            found,
            vec![EmbeddedImage {
                offset: 5000,
                identified: Some("test image")
            }]
        );
    }

    #[test]
    fn an_unpinned_image_is_still_reported() {
        let host = host_with(&fake_image(2048, 0xCD), 3000);
        let found = find_embedded_images(&host, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].identified, None);
    }

    #[test]
    fn images_nested_inside_an_identified_copy_are_folded_into_it() {
        let mut payload = fake_image(4096, 0xAB);
        let inner = fake_image(512, 0x11);
        payload[2000..2512].copy_from_slice(&inner);
        let pin = pin_for(&payload);
        let mut host = host_with(&payload, 3000);
        // A separate, unidentified image after the identified one is still reported.
        host.extend_from_slice(&fake_image(512, 0x22));

        let found = find_embedded_images(&host, &[pin]);
        assert_eq!(
            found,
            vec![
                EmbeddedImage {
                    offset: 3000,
                    identified: Some("test image")
                },
                EmbeddedImage {
                    offset: 3000 + 4096 + 64,
                    identified: None
                },
            ]
        );
    }

    #[test]
    fn a_modified_copy_is_reported_but_not_misidentified() {
        let payload = fake_image(2048, 0xAB);
        let pin = pin_for(&payload);
        let mut altered = payload.clone();
        altered[1000] ^= 1;
        let found = find_embedded_images(&host_with(&altered, 3000), &[pin]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].identified, None);
    }

    #[test]
    fn stray_mz_bytes_without_a_pe_signature_are_ignored() {
        let mut host = fake_image(8192, 0);
        host[4000..4002].copy_from_slice(b"MZ");
        host[4000 + E_LFANEW_FIELD..4000 + E_LFANEW_FIELD + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());
        assert!(find_embedded_images(&host, &[]).is_empty());
    }

    #[test]
    fn headers_truncated_by_end_of_file_do_not_panic() {
        let mut host = fake_image(512, 0);
        host.extend_from_slice(b"MZ");
        assert!(find_embedded_images(&host, &[]).is_empty());
        let mut host = fake_image(512, 0);
        host.extend_from_slice(&fake_image(0x84, 1)[..0x50]);
        assert!(find_embedded_images(&host, &[]).is_empty());
    }

    #[test]
    fn a_pin_longer_than_the_remaining_bytes_does_not_match() {
        let payload = fake_image(2048, 0xAB);
        let pin = pin_for(&payload);
        let truncated = host_with(&payload[..1024], 3000);
        let found = find_embedded_images(&truncated[..3000 + 1024], &[pin]);
        assert_eq!(found[0].identified, None);
    }
}
