//! DNS hostname validation for names that reach a TLS handshake (`server_name`).
//!
//! Deliberately strict: ASCII letters, digits and hyphens (an internationalised name must
//! already be in `xn--` form), at least two labels, and never something that parses as an
//! IP address. A name in a ClientHello is visible to every observer, so a malformed one is a
//! fingerprint as well as a failure.

/// Maximum length of a DNS name in text form, without a trailing dot (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 253;
/// Maximum length of one label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Whether `name` is a multi-label DNS hostname that is not an IP literal.
pub(crate) fn is_dns_hostname(name: &str) -> bool {
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
}
