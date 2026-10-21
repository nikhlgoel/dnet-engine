//! Names and addresses that come from outside must not be able to crash the decision layer.
//!
//! An origin URL and a REALITY target domain are text a person types or an imported bundle carries.
//! The answer is a value or a refusal; and what is accepted is within the limits the rest of the
//! code relies on.

use dnet_core::hostname::{is_dns_hostname, validate_target_domain, MAX_NAME_LEN};
use dnet_core::origin::Origin;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn an_origin_of_any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,200}") {
        let _ = Origin::parse(&text);
    }

    #[test]
    fn an_origin_shaped_text_is_refused_or_accepted_without_panicking(
        scheme in prop::sample::select(vec!["http", "https", "ftp", "file", "", "HTTP"]),
        host in "[a-zA-Z0-9.:\\[\\]@%/-]{0,60}",
        port in prop::option::of(any::<u32>()),
        path in "[ -~]{0,40}",
    ) {
        let url = match port {
            Some(p) => format!("{scheme}://{host}:{p}/{path}"),
            None => format!("{scheme}://{host}/{path}"),
        };
        let _ = Origin::parse(&url);
    }

    #[test]
    fn a_hostname_of_any_text_is_judged_without_panicking(text in "\\PC{0,300}") {
        let _ = is_dns_hostname(&text);
        let _ = validate_target_domain(&text);
    }

    /// What is accepted as a hostname is within the lengths the rest of the code relies on, and
    /// plain ASCII: a name that can be shown, compared and written into a configuration safely.
    #[test]
    fn an_accepted_hostname_is_ascii_and_within_the_length_limits(text in "[a-zA-Z0-9.-]{0,300}") {
        if is_dns_hostname(&text) {
            prop_assert!(text.is_ascii() && text.len() <= MAX_NAME_LEN);
            prop_assert!(text.split('.').all(|label| (1..=63).contains(&label.len())));
            prop_assert!(text.contains('.'));
        }
    }

    #[test]
    fn an_accepted_target_domain_is_lower_case_and_a_hostname(text in "[a-zA-Z0-9.-]{0,120}") {
        if let Ok(domain) = validate_target_domain(&text) {
            prop_assert!(is_dns_hostname(&domain));
            prop_assert_eq!(domain.clone(), domain.to_ascii_lowercase());
        }
    }
}
