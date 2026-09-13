//! DNS hostname validation for names that reach a TLS handshake (`server_name`), shared by
//! the configuration generators and the profile feed so the two can never disagree.
//!
//! Deliberately strict: ASCII letters, digits and hyphens (an internationalised name must
//! already be in `xn--` form), at least two labels, and never something that parses as an
//! IP address. A name in a ClientHello is visible to every observer, so a malformed one is a
//! fingerprint as well as a failure.

use crate::builtin_rules::CAPTIVE_PORTAL_PROBE_SUFFIXES;

/// Maximum length of a DNS name in text form, without a trailing dot (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 253;
/// Maximum length of one label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Whether `name` is a multi-label DNS hostname that is not an IP literal.
pub fn is_dns_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|l| is_label(l)) {
        return false;
    }
    // An all-numeric final label is an IPv4 literal (or an ambiguous name), never a hostname.
    let tld = labels[labels.len() - 1];
    !tld.bytes().all(|b| b.is_ascii_digit())
}

fn is_label(label: &str) -> bool {
    (1..=MAX_LABEL_LEN).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Validate a REALITY target domain and return it lower-cased (ADR-0002 §5.4, T058).
///
/// Refuses anything that is not a multi-label hostname, and any name under a built-in bypass
/// suffix (T031). The error is a fixed reason, never the name.
pub fn validate_target_domain(name: &str) -> Result<String, &'static str> {
    let name = name.to_ascii_lowercase();
    if !is_dns_hostname(&name) {
        return Err("not a DNS hostname");
    }
    let bypassed = CAPTIVE_PORTAL_PROBE_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")));
    if bypassed {
        return Err("covered by a built-in bypass rule");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_hostnames() {
        for name in [
            "www.example.com",
            "a.b",
            "xn--bcher-kva.example",
            "edge-1.example.net",
        ] {
            assert!(is_dns_hostname(name), "{name}");
        }
    }

    #[test]
    fn refuses_everything_else() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}.com", ["a"; 127].join("."));
        for name in [
            "",
            "localhost",
            "203.0.113.9",
            "2001:db8::1",
            "example.com.",
            ".example.com",
            "exa mple.com",
            "-bad.example.com",
            "bad-.example.com",
            "b\u{fc}cher.example",
            "under_score.example.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(!is_dns_hostname(name), "{name:?}");
        }
    }

    #[test]
    fn a_target_domain_is_lower_cased() {
        assert_eq!(
            validate_target_domain("WWW.Example.COM"),
            Ok("www.example.com".to_string())
        );
    }

    #[test]
    fn a_target_domain_may_not_be_a_bypassed_probe_host() {
        for name in [
            "msftconnecttest.com",
            "www.msftconnecttest.com",
            "dns.msftncsi.com",
        ] {
            assert_eq!(
                validate_target_domain(name),
                Err("covered by a built-in bypass rule"),
                "{name}"
            );
        }
        // A suffix match is by label, not by substring.
        assert!(validate_target_domain("notmsftncsi.com").is_ok());
    }
}
