//! T091 — "no free capacity here" is a normal answer, not an error (PR-02 stage, US2-2).
//!
//! Free-tier compute is rationed per region, and the popular regions run out. When the chosen one has
//! nothing, the person should be offered the regions that do, with what each one costs them in latency,
//! and be able to pick one and carry on. So the answer is a value ([`Capacity::Unavailable`]) that the
//! stage machine turns into a retryable outcome; nothing has been created at that point, so there is
//! nothing to clean up and nothing to apologise for.
//!
//! Pure logic: no I/O.

/// Another region that has capacity, and how much further away it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    pub region: String,
    /// Round-trip time added over the chosen region, in milliseconds. What the person is trading for.
    pub added_rtt_ms: u32,
}

/// What the provider has to give in a region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capacity {
    Available,
    Unavailable { alternatives: Vec<Alternative> },
}

/// Most alternatives worth showing. More is a menu, not a recommendation.
pub const MAX_ALTERNATIVES: usize = 5;

/// The alternatives to offer, nearest first: the chosen region itself is never an alternative to itself,
/// each region appears once (at its smallest added latency), and only the nearest few are kept.
pub fn rank(alternatives: &[Alternative], chosen_region: &str) -> Vec<Alternative> {
    let mut best: Vec<Alternative> = Vec::new();
    for alternative in alternatives {
        if alternative.region == chosen_region {
            continue;
        }
        match best.iter_mut().find(|b| b.region == alternative.region) {
            Some(existing) => {
                existing.added_rtt_ms = existing.added_rtt_ms.min(alternative.added_rtt_ms)
            }
            None => best.push(alternative.clone()),
        }
    }
    best.sort_by(|a, b| {
        a.added_rtt_ms
            .cmp(&b.added_rtt_ms)
            .then_with(|| a.region.cmp(&b.region))
    });
    best.truncate(MAX_ALTERNATIVES);
    best
}

/// How an alternative is put to the person: the region and what it costs.
pub fn describe(alternative: &Alternative) -> String {
    format!(
        "{} (about {} ms further away)",
        alternative.region, alternative.added_rtt_ms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alt(region: &str, rtt: u32) -> Alternative {
        Alternative {
            region: region.to_owned(),
            added_rtt_ms: rtt,
        }
    }

    #[test]
    fn the_nearest_come_first_and_ties_are_stable() {
        let ranked = rank(&[alt("c", 90), alt("a", 30), alt("b", 30)], "home");
        let names: Vec<_> = ranked.iter().map(|a| a.region.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[test]
    fn the_chosen_region_is_not_an_alternative_to_itself() {
        let ranked = rank(&[alt("home", 0), alt("other", 40)], "home");
        assert_eq!(ranked, [alt("other", 40)]);
    }

    #[test]
    fn a_region_listed_twice_keeps_its_smallest_latency() {
        let ranked = rank(&[alt("x", 80), alt("x", 20), alt("x", 50)], "home");
        assert_eq!(ranked, [alt("x", 20)]);
    }

    #[test]
    fn only_the_nearest_few_are_kept() {
        let many: Vec<_> = (0..20).map(|i| alt(&format!("r{i:02}"), 100 - i)).collect();
        let ranked = rank(&many, "home");
        assert_eq!(ranked.len(), MAX_ALTERNATIVES);
        assert!(ranked
            .windows(2)
            .all(|w| w[0].added_rtt_ms <= w[1].added_rtt_ms));
        // The nearest of all twenty is in there.
        assert_eq!(ranked[0].added_rtt_ms, 100 - 19);
    }

    #[test]
    fn nothing_to_offer_is_an_empty_list_not_an_error() {
        assert!(rank(&[], "home").is_empty());
        assert!(rank(&[alt("home", 0)], "home").is_empty());
    }

    #[test]
    fn an_alternative_is_described_with_its_cost() {
        let text = describe(&alt("Frankfurt", 120));
        assert!(
            text.contains("Frankfurt") && text.contains("120 ms"),
            "{text}"
        );
    }
}
