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
