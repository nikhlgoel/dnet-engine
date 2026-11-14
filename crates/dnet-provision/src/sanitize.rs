// SPDX-License-Identifier: GPL-3.0-or-later
//! Everything a provider says on its own account passes through here before a person or a log sees it
//! (PR-04: the credential never appears in logs, diagnostics, IPC messages, error text or telemetry).
//!
//! A provider's error text is its own words, produced by code this crate does not control and often by a
//! remote service that echoes the request it was sent. The credential is in the request. So the text is
//! cleaned of the credential's value (and of parts of it long enough to identify it), of control
//! characters that could forge a log line, of characters that reorder or hide text, and cut to a
//! length that fits a dialog.
//!
//! This is the second line of defence. The first is that a [`crate::secret::Secret`] never prints.

use crate::secret::Secret;

/// Longest provider text shown, in characters.
pub const MAX_TEXT_CHARS: usize = 240;

/// Shortest fragment of a secret that is treated as identifying it.
const MIN_FRAGMENT: usize = 8;

/// Removes known secrets from text.
#[derive(Default)]
pub struct Sanitizer {
    secrets: Vec<Secret>,
}

impl Sanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Also remove this secret from anything cleaned from now on.
    pub fn with_secret(mut self, secret: Secret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// `text` with every known secret (and every run of `MIN_FRAGMENT` or more of its characters, so a
    /// truncated echo is caught) replaced by `<redacted>`, control characters removed, and the length cut.
    pub fn clean(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in &self.secrets {
            let value = secret.expose_secret();
            if value.is_empty() {
                continue;
            }
            out = out.replace(value, "<redacted>");
            // A service that truncates what it echoes leaves a prefix, a suffix or a middle of the value.
            out = redact_fragments(&out, value);
        }
        let printable: String = out
            .chars()
            .map(|c| if hides_or_forges(c) { ' ' } else { c })
            .collect();
        let collapsed = printable.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.chars().count() > MAX_TEXT_CHARS {
            let cut: String = collapsed.chars().take(MAX_TEXT_CHARS).collect();
            format!("{cut}…")
        } else {
            collapsed
        }
    }
}

/// Replace every stretch of `text` that shares `MIN_FRAGMENT` or more consecutive characters with
/// `secret` by one `<redacted>`. Linear in the two lengths: every `MIN_FRAGMENT`-character window of the
/// secret goes into a set, and each window of the text is looked up in it.
/// Control characters (which can forge a log line), and characters that reorder or hide text (which
/// can make a dialog read as something it does not say). The same set `dnetctl` keeps off a terminal.
fn hides_or_forges(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
        )
}

fn redact_fragments(text: &str, secret: &str) -> String {
    let text: Vec<char> = text.chars().collect();
    let secret: Vec<char> = secret.chars().collect();
    if secret.len() < MIN_FRAGMENT || text.len() < MIN_FRAGMENT {
        return text.into_iter().collect();
    }
    let known: std::collections::HashSet<&[char]> = secret.windows(MIN_FRAGMENT).collect();
    let mut covered = vec![false; text.len()];
    for (start, window) in text.windows(MIN_FRAGMENT).enumerate() {
        if known.contains(window) {
            covered[start..start + MIN_FRAGMENT].fill(true);
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut in_run = false;
    for (c, hidden) in text.iter().zip(covered) {
        match (hidden, in_run) {
            (true, false) => {
                out.push_str("<redacted>");
                in_run = true;
            }
            (true, true) => {}
            (false, _) => {
                out.push(*c);
                in_run = false;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "SENTINEL-oci-key-0123456789abcdef";

    fn sanitizer() -> Sanitizer {
        Sanitizer::new().with_secret(Secret::new(KEY))
    }

    #[test]
    fn the_whole_credential_is_removed_wherever_it_appears() {
        let cleaned = sanitizer().clean(&format!("bad request for {KEY}: signature {KEY} invalid"));
        assert!(!cleaned.contains("SENTINEL"), "{cleaned}");
        assert_eq!(cleaned.matches("<redacted>").count(), 2);
    }

    #[test]
    fn a_truncated_echo_of_the_credential_is_removed_too() {
        for echo in [&KEY[..12], &KEY[5..20], &KEY[KEY.len() - 10..]] {
            let cleaned = sanitizer().clean(&format!("header was {echo}..."));
            assert!(!cleaned.contains(echo), "{echo} survived: {cleaned}");
        }
    }

    #[test]
    fn a_short_coincidence_is_left_alone() {
        // Fewer than eight characters in common is not an identification, and removing them would mangle
        // ordinary words.
        let cleaned = sanitizer().clean("the SENTIN word is fine");
        assert_eq!(cleaned, "the SENTIN word is fine");
    }

    #[test]
    fn control_characters_cannot_forge_a_log_line() {
        let cleaned = Sanitizer::new().clean("denied\r\n[INFO] approved\u{1b}[2J\u{7}");
        assert!(!cleaned.chars().any(char::is_control), "{cleaned:?}");
        assert!(cleaned.starts_with("denied "), "{cleaned}");
    }

    /// A provider's text is shown in a dialog. Characters that reorder or hide text could make it
    /// read as something it does not say.
    #[test]
    fn bidirectional_and_invisible_characters_cannot_disguise_the_text() {
        let cleaned = Sanitizer::new()
            .clean("quota\u{202E}deveirter\u{2066}x\u{2069}\u{200B}y\u{FEFF}\u{200F}");
        for c in [
            '\u{202E}', '\u{2066}', '\u{2069}', '\u{200B}', '\u{FEFF}', '\u{200F}',
        ] {
            assert!(!cleaned.contains(c), "{c:?} survived: {cleaned:?}");
        }
        assert_eq!(cleaned, "quota deveirter x y");
    }

    #[test]
    fn long_text_is_cut() {
        let cleaned = Sanitizer::new().clean(&"word ".repeat(500));
        assert!(cleaned.chars().count() <= MAX_TEXT_CHARS + 1);
        assert!(cleaned.ends_with('…'));
    }

    #[test]
    fn text_with_nothing_to_remove_is_unchanged_apart_from_spacing() {
        assert_eq!(
            Sanitizer::new().clean("  quota   exceeded "),
            "quota exceeded"
        );
        assert_eq!(sanitizer().clean("quota exceeded"), "quota exceeded");
    }

    #[test]
    fn a_long_credential_is_cleaned_quickly() {
        // A signing key is a PEM block of well over a thousand characters; the scan must stay linear.
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            "MIIEvQIBADANBgkq".repeat(120)
        );
        let cleaner = Sanitizer::new().with_secret(Secret::new(pem.clone()));
        let started = std::time::Instant::now();
        let cleaned = cleaner.clean(&format!("rejected: {pem} (and again {pem})"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(!cleaned.contains("MIIEvQIB"), "{cleaned}");
        assert!(!cleaned.contains("PRIVATE KEY"), "{cleaned}");
    }

    #[test]
    fn several_secrets_are_all_removed() {
        let both = Sanitizer::new()
            .with_secret(Secret::new("first-secret-value-aaaa"))
            .with_secret(Secret::new("second-secret-value-bbbb"));
        let cleaned = both.clean("a first-secret-value-aaaa and a second-secret-value-bbbb");
        assert!(!cleaned.contains("secret-value"), "{cleaned}");
    }
}

/// What the mutation run showed the sanitizer's own tests did not pin: where the cut falls, and the exact
/// size at which a stretch of a secret is long enough to count.
#[cfg(test)]
mod edge_tests {
    use super::*;

    #[test]
    fn text_of_exactly_the_longest_length_is_kept_whole_and_one_more_is_cut() {
        let exactly = "a".repeat(MAX_TEXT_CHARS);
        assert_eq!(Sanitizer::new().clean(&exactly), exactly);
        let one_more = "a".repeat(MAX_TEXT_CHARS + 1);
        let cut = Sanitizer::new().clean(&one_more);
        assert_eq!(cut.chars().count(), MAX_TEXT_CHARS + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(cut.chars().filter(|c| *c == 'a').count(), MAX_TEXT_CHARS);
    }

    #[test]
    fn a_stretch_of_exactly_the_minimum_length_is_a_match_and_one_short_is_not() {
        let secret = "ABCDEFGHIJKL";
        let eight = &secret[3..3 + MIN_FRAGMENT];
        assert_eq!(
            redact_fragments(&format!("see {eight}!"), secret),
            "see <redacted>!"
        );
        let seven = &secret[3..3 + MIN_FRAGMENT - 1];
        assert_eq!(
            redact_fragments(&format!("see {seven}!"), secret),
            format!("see {seven}!")
        );
    }

    #[test]
    fn a_secret_that_is_exactly_the_minimum_length_is_still_looked_for() {
        let secret = "ABCDEFGH";
        assert_eq!(secret.len(), MIN_FRAGMENT);
        assert_eq!(redact_fragments("x ABCDEFGH y", secret), "x <redacted> y");
        assert_eq!(redact_fragments("ABCDEFGH", secret), "<redacted>");
    }

    #[test]
    fn text_that_is_exactly_the_minimum_length_is_still_searched() {
        let secret = "0123456789abcdef";
        let window = &secret[4..4 + MIN_FRAGMENT];
        assert_eq!(window.len(), MIN_FRAGMENT);
        assert_eq!(redact_fragments(window, secret), "<redacted>");
    }

    #[test]
    fn a_secret_or_text_shorter_than_the_minimum_changes_nothing() {
        assert_eq!(
            redact_fragments("ABCDEFG and more words", "ABCDEFG"),
            "ABCDEFG and more words"
        );
        assert_eq!(redact_fragments("ABCDEFG", "ABCDEFGHIJKL"), "ABCDEFG");
        assert_eq!(redact_fragments("", "ABCDEFGHIJKL"), "");
        assert_eq!(redact_fragments("anything", ""), "anything");
    }

    #[test]
    fn two_separate_stretches_are_each_replaced_once() {
        let secret = "ABCDEFGHIJKLMNOP";
        let got = redact_fragments("a ABCDEFGH b IJKLMNOP c", secret);
        assert_eq!(got.matches("<redacted>").count(), 2, "{got}");
        assert!(got.starts_with("a ") && got.ends_with(" c"), "{got}");
    }
}
