// SPDX-License-Identifier: GPL-3.0-or-later
//! T093 — what the server prints is input from a machine this client does not control.
//!
//! The bootstrap report is read from the output of a script run on a remote machine; anything on
//! that machine, or between it and the client, can change it. Whatever it holds, reading it ends in
//! a report or a refusal, never a panic, and neither the refusal nor a report's `Debug` repeats the
//! secrets it carries.

use dnet_provision::bootstrap::{BootstrapReport, REPORT_PREFIX};
use proptest::prelude::*;

const SENTINEL: &str = "SENTINEL";

fn good_report() -> String {
    format!(
        r#"{{"version":2,"amneziawg":{{"server_public_key_hex":"{d}","listen_port":51820,"client_address":"10.66.0.2","prefix_len":24,"client_public_key_hex":"{c}"}},"hysteria2":{{"server_port":44443,"server_name":"edge.example.net","spki_sha256_hex":"{e}","auth_password":"{SENTINEL}-auth-0123456789","obfs_password":"{SENTINEL}-obfs-0123456789","cert_key_algorithm":"ecdsa-p256"}},"reality":{{"server_port":8443,"target_domain":"www.example.com","public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef","uuid":"bf000d23-0752-40b4-affe-68f7707a9661","flow":"xtls-rprx-vision"}},"session":{{"server_public_key":"{k3}","port":25182,"server_address":"10.9.0.1","devices":[{{"address":"10.9.0.2","public_key":"{k1}"}}]}},"cores":{{"primary_core":{{"version":"v1.14.0","sha256":"{a}"}},"amneziawg":{{"version":"v1.14.0","sha256":"{b}"}}}}}}"#,
        k1 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        k3 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
        c = "c".repeat(64),
        d = "d".repeat(64),
        e = "e".repeat(64),
        a = "a".repeat(64),
        b = "b".repeat(64),
    )
}

fn assert_quiet(result: &Result<BootstrapReport, impl std::fmt::Display + std::fmt::Debug>) {
    let shown = match result {
        Ok(report) => format!("{report:?}"),
        Err(error) => format!("{error} {error:?}"),
    };
    assert!(!shown.contains(SENTINEL), "a secret was repeated: {shown}");
}

#[test]
fn the_sample_is_a_good_report() {
    let parsed = BootstrapReport::parse(&format!("{REPORT_PREFIX}{}\n", good_report()));
    assert!(parsed.is_ok(), "{parsed:?}");
    assert_quiet(&parsed);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn any_output_is_read_without_panicking(text in "\\PC{0,400}") {
        let _ = BootstrapReport::parse(&text);
    }

    #[test]
    fn any_report_line_is_read_without_panicking(text in "\\PC{0,400}") {
        let _ = BootstrapReport::parse(&format!("progress\n{REPORT_PREFIX}{text}\ndone\n"));
    }

    /// One character of a good report changed, anywhere, to anything: a report or a refusal, and the
    /// secrets are never repeated, whichever it is.
    #[test]
    fn a_report_changed_in_one_place_never_panics_or_repeats_a_secret(
        at in any::<prop::sample::Index>(),
        with in any::<char>(),
    ) {
        let mut chars: Vec<char> = good_report().chars().collect();
        let i = at.index(chars.len());
        chars[i] = with;
        let line: String = chars.into_iter().collect();
        let parsed = BootstrapReport::parse(&format!("{REPORT_PREFIX}{line}\n"));
        assert_quiet(&parsed);
    }

    /// A good report cut short anywhere is refused, never half-read.
    #[test]
    fn a_report_cut_short_is_refused(at in any::<prop::sample::Index>()) {
        let report = good_report();
        let cut = at.index(report.len());
        prop_assume!(report.is_char_boundary(cut));
        let parsed = BootstrapReport::parse(&format!("{REPORT_PREFIX}{}\n", &report[..cut]));
        prop_assert!(parsed.is_err());
        assert_quiet(&parsed);
    }
}
