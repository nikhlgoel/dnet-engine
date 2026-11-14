// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading credentials: bounded, tolerant of what a Windows editor writes, and silent about content.

use std::io::Write;

use dnet_config::credentials::{EndpointCredentials, RealityBundle, MAX_STORED_LEN};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;

use super::*;

/// In the secrets below. If it shows up in an error, a secret leaked.
pub(crate) const SENTINEL: &str = "SENTINEL-input-5b19";

/// A bundle serving one profile, in the form the service stores.
pub(crate) fn credentials_json() -> Vec<u8> {
    EndpointCredentials {
        amneziawg: None,
        hysteria2: None,
        reality: Some(RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("0123456789abcdef"),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        }),
        measure_origin: None,
        session: None,
    }
    .to_plaintext_json()
    .unwrap()
}

fn file_with(bytes: &[u8]) -> (tempfile::TempDir, CredentialsSource) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.json");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    let source = CredentialsSource::File(path.to_string_lossy().into_owned());
    (dir, source)
}

#[test]
fn a_credentials_file_is_read_and_understood() {
    let (_dir, source) = file_with(&credentials_json());
    let bytes = read_bytes(&source).unwrap();
    assert!(parse(&bytes).unwrap().reality.is_some());
}

#[test]
fn a_byte_order_mark_from_a_windows_editor_is_tolerated() {
    let mut text = BOM.to_vec();
    text.extend(credentials_json());
    assert!(parse(&text).unwrap().reality.is_some());
}

#[test]
fn a_file_that_does_not_exist_is_reported_without_a_path_or_content() {
    // A folder of our own, not a drive letter: a letter can be a network share that takes a minute to give up.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir
        .path()
        .join("no")
        .join("such")
        .join("SENTINEL-path.json");
    let error = read_bytes(&CredentialsSource::File(
        missing.to_string_lossy().into_owned(),
    ))
    .unwrap_err();
    assert!(error.contains("could not be opened"), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}

#[test]
fn a_file_larger_than_any_credentials_is_refused_not_read_whole() {
    let (_dir, source) = file_with(&vec![b' '; MAX_STORED_LEN + 1]);
    let error = read_bytes(&source).unwrap_err();
    assert!(error.contains("not a credentials file"), "{error}");
}

#[test]
fn a_file_exactly_at_the_limit_is_read() {
    let (_dir, source) = file_with(&vec![b' '; MAX_STORED_LEN]);
    assert_eq!(read_bytes(&source).unwrap().len(), MAX_STORED_LEN);
}

#[test]
fn reading_stops_at_the_limit_whatever_the_source_holds() {
    struct Endless;
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(b'x');
            Ok(buf.len())
        }
    }
    assert!(read_limited(Endless).is_err());
}

#[test]
fn text_that_is_not_credentials_is_refused_without_repeating_it() {
    for text in [
        format!("{SENTINEL} is not json"),
        format!(r#"{{"version":1,"reality":{{"server_port":"{SENTINEL}"}}}}"#),
        format!(r#"{{"version":"{SENTINEL}"}}"#),
        String::new(),
    ] {
        let error = parse(text.as_bytes()).unwrap_err();
        assert!(error.contains("not usable"), "{error}");
        assert!(!error.contains("SENTINEL"), "{error}");
    }
}

#[test]
fn a_bundle_with_no_connection_method_is_refused() {
    assert!(parse(br#"{"version":1}"#).is_err());
}

// ------------------------------------------------------------------ signed documents

#[test]
fn a_signed_document_is_read_as_text_without_a_byte_order_mark() {
    let mut bytes = BOM.to_vec();
    bytes.extend(br#"{"payloadType":"x"}"#);
    let (_dir, source) = file_with(&bytes);
    let CredentialsSource::File(path) = source else {
        unreachable!()
    };
    assert_eq!(read_document(&path).unwrap(), r#"{"payloadType":"x"}"#);
}

#[test]
fn a_document_at_the_size_cap_is_read_and_one_byte_over_is_not() {
    let cap = dnet_core::feed::ENVELOPE_MAX_BYTES;
    let (_a, at) = file_with(&vec![b' '; cap]);
    let (_b, over) = file_with(&vec![b' '; cap + 1]);
    let (CredentialsSource::File(at), CredentialsSource::File(over)) = (at, over) else {
        unreachable!()
    };
    assert_eq!(read_document(&at).unwrap().len(), cap);
    assert!(read_document(&over)
        .unwrap_err()
        .contains("no signed document is"));
}

#[test]
fn a_document_that_is_not_text_or_not_there_is_refused_without_its_content_or_path() {
    let (_dir, source) = file_with(&[0xff, 0xfe, 0x00]);
    let CredentialsSource::File(path) = source else {
        unreachable!()
    };
    assert!(read_document(&path).unwrap_err().contains("not text"));
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no").join("SENTINEL-path.json");
    let error = read_document(&missing.to_string_lossy()).unwrap_err();
    assert!(error.contains("could not be opened"), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}
