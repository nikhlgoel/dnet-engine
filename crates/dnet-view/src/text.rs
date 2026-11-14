// SPDX-License-Identifier: GPL-3.0-or-later
//! T100 — text from the service, made safe to hand to a web view (design-system §14, §17 rule 2).
//!
//! The window cleans every string again on its side (`sanitize.ts`); this is the same rule applied here, so a
//! string is clean at both ends of the door and the two cannot be played against each other. Control
//! characters would drive a terminal if the text were ever printed; bidirectional controls would reorder or
//! hide the text around them; zero-width characters would hide text altogether. All become `?`, which is also
//! what `dnetctl` does (`render::plain`).

/// `text` with every character that could drive a display or disguise other text replaced by `?`, cut to
/// `max` characters (with an ellipsis when it was cut).
#[must_use]
pub fn plain(text: &str, max: usize) -> String {
    let mut shown = String::new();
    for (count, ch) in text.chars().enumerate() {
        if count == max {
            shown.push('…');
            break;
        }
        shown.push(if unsafe_char(ch) { '?' } else { ch });
    }
    shown
}

fn unsafe_char(ch: char) -> bool {
    let c = u32::from(ch);
    c < 0x20
        || (0x7f..=0x9f).contains(&c)
        // line and paragraph separators, which some renderers break on
        || c == 0x2028
        || c == 0x2029
        // zero-width space, non-joiner, joiner, word joiner and the byte-order mark
        || (0x200b..=0x200d).contains(&c)
        || c == 0x2060
        || c == 0xfeff
        // bidirectional marks, embeddings, overrides and isolates
        || c == 0x061c
        || c == 0x200e
        || c == 0x200f
        || (0x202a..=0x202e).contains(&c)
        || (0x2066..=0x2069).contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutation testing showed that six of these single code points could be dropped from the filter without a
    /// test noticing. Every one is pinned here, together with the characters just outside each range, which
    /// must survive (a filter that eats ordinary text is a bug too).
    #[test]
    fn exactly_the_documented_characters_are_replaced() {
        let unsafe_points: Vec<u32> = (0x00..0x20)
            .chain(0x7f..=0x9f)
            .chain([0x2028, 0x2029, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff])
            .chain([0x061c, 0x200e, 0x200f])
            .chain(0x202a..=0x202e)
            .chain(0x2066..=0x2069)
            .collect();
        for &p in &unsafe_points {
            let ch = char::from_u32(p).unwrap();
            assert_eq!(plain(&ch.to_string(), 8), "?", "U+{p:04X} must be replaced");
        }
        for p in [
            0x20, 0x7e, 0xa0, 0x061b, 0x061d, 0x200a, 0x2010, 0x2027, 0x202f, 0x205f, 0x2061,
            0x2065, 0x206a, 0xfefe, 0xff00, 0x1f600,
        ] {
            let ch = char::from_u32(p).unwrap();
            assert_eq!(
                plain(&ch.to_string(), 8),
                ch.to_string(),
                "U+{p:04X} must be kept"
            );
        }
        // The rule is exactly this list: nothing else in the whole range of characters is touched.
        for p in 0..=0x10_ffff_u32 {
            if let Some(ch) = char::from_u32(p) {
                let replaced = plain(&ch.to_string(), 8) == "?";
                assert_eq!(
                    replaced,
                    unsafe_points.contains(&p) || ch == '?',
                    "U+{p:04X}"
                );
            }
        }
    }

    #[test]
    fn a_long_text_is_cut_with_an_ellipsis_and_a_short_one_is_not() {
        assert_eq!(plain("abcd", 4), "abcd");
        assert_eq!(plain("abcde", 4), "abcd…");
        assert_eq!(plain("", 0), "");
    }
}
