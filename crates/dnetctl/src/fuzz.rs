//! What `dnetctl` reads is untrusted: the command line is the user's, but every reply is whatever
//! owns the pipe chose to send. Printing it must not crash, and must not let it reach the terminal
//! as anything but text.

use proptest::prelude::*;
use serde_json::{Map, Value};

use crate::cli;
use crate::render;

fn json() -> impl Strategy<Value = Value> {
    let key = prop::sample::select(vec![
        "profiles",
        "endpoints",
        "id",
        "kind",
        "tier",
        "carrier",
        "brutal",
        "label",
        "address",
        "enabled",
        "health",
        "status",
        "rtt_ms",
    ])
    .prop_map(str::to_owned);
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        "\\PC{0,24}".prop_map(Value::String),
        Just(Value::String("\u{1b}[31mred\u{7}\u{202e}".to_owned())),
    ];
    leaf.prop_recursive(3, 30, 5, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec((key.clone(), inner), 0..6)
                .prop_map(|pairs| Value::Object(pairs.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// Control characters and the characters that reorder or hide text (bidirectional controls).
fn dangerous(c: char) -> bool {
    c.is_control() && c != '\n'
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn a_profile_list_of_any_json_is_printed_or_refused_without_panicking(value in json()) {
        let _ = render::profiles(&value);
    }

    #[test]
    fn an_endpoint_list_of_any_json_is_printed_or_refused_without_panicking(value in json()) {
        let _ = render::endpoints(&value);
    }

    /// Whatever the service says, nothing it says reaches the terminal as a control sequence.
    #[test]
    fn printed_text_never_carries_control_or_bidirectional_characters(text in "\\PC{0,200}|[\u{0}-\u{1f}\u{202a}-\u{202e}\u{2066}-\u{2069}a-z ]{0,60}") {
        let shown = render::plain(&text);
        prop_assert!(!shown.chars().any(dangerous), "{shown:?}");
    }

    #[test]
    fn the_command_line_of_any_words_is_accepted_or_refused_without_panicking(
        args in prop::collection::vec("\\PC{0,20}", 0..8)
    ) {
        let _ = cli::parse(&args);
    }

    #[test]
    fn the_command_line_made_of_real_words_is_accepted_or_refused_without_panicking(
        args in prop::collection::vec(
            prop::sample::select(vec![
                "status", "connect", "disconnect", "events", "profiles", "endpoints", "version",
                "help", "--json", "--timeout", "--profile", "--accept-tier2", "--no-wait", "-f",
                "--follow", "--allow-unprivileged-service", "0", "99999999999999999999", "-1",
                "hy2-default", "",
            ]),
            0..8
        )
    ) {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        let _ = cli::parse(&args);
    }
}
