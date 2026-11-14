// SPDX-License-Identifier: GPL-3.0-or-later
//! T175 — HV-07 results as data, not as an edit to code (shrinks the "switching networks drops open
//! connections" limit without a lab, an admin right or the owner).
//!
//! Before this, recording that a method survives an interface change meant editing `recorded_survival` by hand,
//! with the evidence somewhere else and nothing tying the claim to the core it was measured on. Now the result is
//! a record in `evidence/survival.json` (compiled in, so this crate still does no I/O): the kind, the exact
//! source commit of the core that was measured, and each run. The tier follows from it by rules that fail
//! closed:
//!
//! - **Survived** needs at least three runs at the *pinned* commit, every one of them a transfer that finished
//!   in the same connection, with every byte, and with the tunnel moving without a disconnect.
//! - **One failing run at the pinned commit is Broke.** A method is not called better on a lucky run.
//! - **A record for any other commit is ignored**: bumping a core pin turns every claim back to NotMeasured
//!   until the lab is run again, with nothing for anyone to remember to do.
//! - **Anything unreadable, unknown, duplicated or malformed is NotMeasured**, and a test refuses the shipped
//!   file if it is.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::profile::ProfileKind;
use crate::tier::SurvivalMeasurement;

/// The commit of the primary core the client is built from (`xtask` pins the same; a test there compares).
pub const PINNED_PRIMARY_COMMIT: &str = "c005f35300ce76427dc285481ec5695f5b179cd2";
/// The commit of the AmneziaWG core the client is built from.
pub const PINNED_AMNEZIAWG_COMMIT: &str = "b5928efb6ca19f0153958460c3d141f04abc5c2e";
/// The fewest runs that can show survival.
pub const MIN_RUNS: usize = 3;
/// The most records and runs read; far above any real file.
const MAX_RECORDS: usize = 16;
const MAX_RUNS: usize = 32;

/// The commit the core serving `kind` is pinned to.
pub fn pinned_commit(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::AmneziaWg => PINNED_AMNEZIAWG_COMMIT,
        ProfileKind::Hysteria2 | ProfileKind::VlessReality => PINNED_PRIMARY_COMMIT,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("the evidence is not in the expected form ({0})")]
    Malformed(&'static str),
    #[error("the evidence is for format version {0}, which this build cannot read")]
    Version(u32),
    #[error("a record is not valid ({0})")]
    Invalid(&'static str),
    #[error("there is more than one record for the same method at the same core commit")]
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// When it was run, as the person wrote it down (`YYYY-MM-DD`).
    pub on: String,
    /// The transfer finished in the same connection, without being restarted or resumed.
    pub same_connection: bool,
    pub bytes_expected: u64,
    pub bytes_received: u64,
    /// The events showed the tunnel moving to the other network with no disconnect.
    pub moved_without_disconnect: bool,
}

impl Run {
    fn survived(&self) -> bool {
        self.same_connection
            && self.moved_without_disconnect
            && self.bytes_expected > 0
            && self.bytes_received == self.bytes_expected
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// `amneziawg`, `hysteria2` or `vless_reality`.
    pub method: String,
    /// The 40-digit source commit of the core that was measured.
    pub core_commit: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    records: Vec<Record>,
}

fn kind_of(method: &str) -> Option<ProfileKind> {
    match method {
        "amneziawg" => Some(ProfileKind::AmneziaWg),
        "hysteria2" => Some(ProfileKind::Hysteria2),
        "vless_reality" => Some(ProfileKind::VlessReality),
        _ => None,
    }
}

/// Read the evidence. Strict: an unknown field, method, version or shape is an error, never a guess.
pub fn parse(text: &str) -> Result<Vec<Record>, EvidenceError> {
    let file: File = serde_json::from_str(text).map_err(|e| {
        use serde_json::error::Category;
        EvidenceError::Malformed(match e.classify() {
            Category::Io => "unreadable",
            Category::Syntax => "not valid JSON",
            Category::Data => "a field is missing, unknown or of the wrong type",
            Category::Eof => "ends unexpectedly",
        })
    })?;
    if file.version != 1 {
        return Err(EvidenceError::Version(file.version));
    }
    if file.records.len() > MAX_RECORDS {
        return Err(EvidenceError::Invalid("too many records"));
    }
    for (i, record) in file.records.iter().enumerate() {
        if kind_of(&record.method).is_none() {
            return Err(EvidenceError::Invalid("unknown method"));
        }
        let commit = &record.core_commit;
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(EvidenceError::Invalid("core commit"));
        }
        if record.runs.is_empty() || record.runs.len() > MAX_RUNS {
            return Err(EvidenceError::Invalid("number of runs"));
        }
        if record.runs.iter().any(|r| {
            r.on.len() != 10
                || !r.on.bytes().enumerate().all(|(n, b)| {
                    if n == 4 || n == 7 {
                        b == b'-'
                    } else {
                        b.is_ascii_digit()
                    }
                })
        }) {
            return Err(EvidenceError::Invalid("date"));
        }
        if file.records[..i]
            .iter()
            .any(|other| other.method == record.method && other.core_commit == record.core_commit)
        {
            return Err(EvidenceError::Duplicate);
        }
    }
    Ok(file.records)
}

/// What the evidence says about `kind` for a core built from `pinned`.
pub fn decide(kind: ProfileKind, records: &[Record], pinned: &str) -> SurvivalMeasurement {
    let Some(record) = records
        .iter()
        .find(|r| kind_of(&r.method) == Some(kind) && r.core_commit == pinned)
    else {
        return SurvivalMeasurement::NotMeasured;
    };
    if record.runs.iter().any(|run| !run.survived()) {
        return SurvivalMeasurement::Broke;
    }
    if record.runs.len() >= MIN_RUNS {
        SurvivalMeasurement::Survived
    } else {
        SurvivalMeasurement::NotMeasured
    }
}

/// The evidence shipped with this build.
const SHIPPED: &str = include_str!("../evidence/survival.json");

fn shipped() -> &'static [Record] {
    static RECORDS: OnceLock<Vec<Record>> = OnceLock::new();
    RECORDS.get_or_init(|| parse(SHIPPED).unwrap_or_default())
}

/// The recorded result for `kind` at the pinned core: from the shipped evidence, and `NotMeasured` if there is
/// none or it cannot be read.
pub fn recorded(kind: ProfileKind) -> SurvivalMeasurement {
    decide(kind, shipped(), pinned_commit(kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const OLD: &str = "1111111111111111111111111111111111111111";

    fn run(ok: bool) -> Value {
        json!({ "on": "2026-11-05", "same_connection": ok, "bytes_expected": 524288000u64,
                "bytes_received": 524288000u64, "moved_without_disconnect": true })
    }

    fn file(records: Vec<Value>) -> String {
        json!({ "version": 1, "records": records }).to_string()
    }

    fn record(method: &str, commit: &str, runs: Vec<Value>) -> Value {
        json!({ "method": method, "core_commit": commit, "runs": runs })
    }

    fn decide_from(text: &str, kind: ProfileKind) -> SurvivalMeasurement {
        decide(kind, &parse(text).unwrap(), pinned_commit(kind))
    }

    #[test]
    fn nothing_recorded_claims_nothing() {
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            assert_eq!(
                decide_from(&file(vec![]), kind),
                SurvivalMeasurement::NotMeasured
            );
        }
    }

    #[test]
    fn three_clean_runs_at_the_pinned_commit_are_survival() {
        let text = file(vec![record(
            "hysteria2",
            PINNED_PRIMARY_COMMIT,
            vec![run(true), run(true), run(true)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::Hysteria2),
            SurvivalMeasurement::Survived
        );
    }

    /// The chain the label rests on: evidence, then the measurement, then the tier. Only survival is Tier 1.
    #[test]
    fn only_clean_evidence_ends_as_tier_one() {
        use crate::tier::FailoverTier;
        let tier = |runs: Vec<Value>| {
            let text = file(vec![record("hysteria2", PINNED_PRIMARY_COMMIT, runs)]);
            FailoverTier::from_measurement(decide_from(&text, ProfileKind::Hysteria2))
        };
        assert_eq!(
            tier(vec![run(true), run(true), run(true)]),
            FailoverTier::Tier1
        );
        assert_eq!(tier(vec![run(true), run(true)]), FailoverTier::Tier2);
        assert_eq!(
            tier(vec![run(true), run(true), run(false)]),
            FailoverTier::Tier2
        );
        assert_eq!(tier(vec![run(true)]), FailoverTier::Tier2);
    }

    #[test]
    fn fewer_than_three_runs_prove_nothing() {
        for n in [1usize, 2] {
            let text = file(vec![record(
                "hysteria2",
                PINNED_PRIMARY_COMMIT,
                (0..n).map(|_| run(true)).collect(),
            )]);
            assert_eq!(
                decide_from(&text, ProfileKind::Hysteria2),
                SurvivalMeasurement::NotMeasured,
                "{n}"
            );
        }
    }

    #[test]
    fn one_failing_run_at_the_pinned_commit_is_broke_even_among_good_ones() {
        let text = file(vec![record(
            "hysteria2",
            PINNED_PRIMARY_COMMIT,
            vec![run(true), run(false), run(true), run(true)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::Hysteria2),
            SurvivalMeasurement::Broke
        );
        // A failure with fewer than three runs is still a failure.
        let text = file(vec![record(
            "vless_reality",
            PINNED_PRIMARY_COMMIT,
            vec![run(false)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::VlessReality),
            SurvivalMeasurement::Broke
        );
    }

    /// A run only counts if every part of the promise held, not only the flag that says so.
    #[test]
    fn a_run_that_lost_bytes_restarted_or_disconnected_does_not_count() {
        let mut bad = Vec::new();
        let mut short = run(true);
        short["bytes_received"] = json!(1000);
        bad.push(short);
        let mut zero = run(true);
        zero["bytes_expected"] = json!(0);
        zero["bytes_received"] = json!(0);
        bad.push(zero);
        let mut more = run(true);
        more["bytes_received"] = json!(524288001u64);
        bad.push(more);
        let mut dropped = run(true);
        dropped["moved_without_disconnect"] = json!(false);
        bad.push(dropped);
        bad.push(run(false));
        for b in bad {
            let text = file(vec![record(
                "hysteria2",
                PINNED_PRIMARY_COMMIT,
                vec![run(true), run(true), b.clone()],
            )]);
            assert_eq!(
                decide_from(&text, ProfileKind::Hysteria2),
                SurvivalMeasurement::Broke,
                "{b}"
            );
        }
    }

    /// Bumping a pin retires the claim by itself.
    #[test]
    fn a_result_for_another_commit_is_ignored() {
        let text = file(vec![record(
            "hysteria2",
            OLD,
            vec![run(true), run(true), run(true)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::Hysteria2),
            SurvivalMeasurement::NotMeasured
        );
        // And a stale failure does not blacken the new core either.
        let text = file(vec![record("hysteria2", OLD, vec![run(false)])]);
        assert_eq!(
            decide_from(&text, ProfileKind::Hysteria2),
            SurvivalMeasurement::NotMeasured
        );
    }

    /// A result for one method says nothing about another, and each is read against its own core.
    #[test]
    fn a_result_belongs_to_its_method_and_its_core() {
        let text = file(vec![record(
            "amneziawg",
            PINNED_AMNEZIAWG_COMMIT,
            vec![run(true), run(true), run(true)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::AmneziaWg),
            SurvivalMeasurement::Survived
        );
        assert_eq!(
            decide_from(&text, ProfileKind::Hysteria2),
            SurvivalMeasurement::NotMeasured
        );
        assert_eq!(
            decide_from(&text, ProfileKind::VlessReality),
            SurvivalMeasurement::NotMeasured
        );
        // AmneziaWG measured at the *primary* core's commit is not a measurement of the AmneziaWG core.
        let text = file(vec![record(
            "amneziawg",
            PINNED_PRIMARY_COMMIT,
            vec![run(true), run(true), run(true)],
        )]);
        assert_eq!(
            decide_from(&text, ProfileKind::AmneziaWg),
            SurvivalMeasurement::NotMeasured
        );
        assert_ne!(PINNED_PRIMARY_COMMIT, PINNED_AMNEZIAWG_COMMIT);
    }

    #[test]
    fn what_cannot_be_trusted_is_refused_not_guessed() {
        let good = record(
            "hysteria2",
            PINNED_PRIMARY_COMMIT,
            vec![run(true), run(true), run(true)],
        );
        let mutations: Vec<(&str, String)> = vec![
            ("not json", "nope".into()),
            ("empty", "".into()),
            (
                "version",
                json!({ "version": 2, "records": [] }).to_string(),
            ),
            (
                "unknown top field",
                json!({ "version": 1, "records": [], "x": 1 }).to_string(),
            ),
            (
                "unknown method",
                file(vec![record(
                    "openvpn",
                    PINNED_PRIMARY_COMMIT,
                    vec![run(true)],
                )]),
            ),
            (
                "short commit",
                file(vec![record("hysteria2", "abc", vec![run(true)])]),
            ),
            (
                "upper commit",
                file(vec![record(
                    "hysteria2",
                    &PINNED_PRIMARY_COMMIT.to_uppercase(),
                    vec![run(true)],
                )]),
            ),
            (
                "no runs",
                file(vec![record("hysteria2", PINNED_PRIMARY_COMMIT, vec![])]),
            ),
            (
                "too many runs",
                file(vec![record(
                    "hysteria2",
                    PINNED_PRIMARY_COMMIT,
                    (0..33).map(|_| run(true)).collect(),
                )]),
            ),
            (
                "bad date",
                file(vec![record(
                    "hysteria2",
                    PINNED_PRIMARY_COMMIT,
                    vec![
                        json!({"on":"yesterday","same_connection":true,"bytes_expected":1,"bytes_received":1,"moved_without_disconnect":true}),
                    ],
                )]),
            ),
            (
                "unknown run field",
                file(vec![record(
                    "hysteria2",
                    PINNED_PRIMARY_COMMIT,
                    vec![
                        json!({"on":"2026-11-05","same_connection":true,"bytes_expected":1,"bytes_received":1,"moved_without_disconnect":true,"extra":1}),
                    ],
                )]),
            ),
            ("duplicate", file(vec![good.clone(), good.clone()])),
            (
                "too many records",
                file(
                    (0..17)
                        .map(|i| record("hysteria2", &format!("{i:040x}"), vec![run(true)]))
                        .collect(),
                ),
            ),
        ];
        for (what, text) in mutations {
            assert!(parse(&text).is_err(), "{what} was accepted");
        }
    }

    /// The limits are where they are said to be: the most is accepted and one more is not, and each way a
    /// date or a duplicate can be wrong is enough on its own.
    #[test]
    fn the_limits_and_each_single_fault_are_exact() {
        let many_records: Vec<Value> = (0..16)
            .map(|i| record("hysteria2", &format!("{i:040x}"), vec![run(true)]))
            .collect();
        assert!(parse(&file(many_records)).is_ok(), "sixteen records");
        assert!(
            parse(&file(vec![record(
                "hysteria2",
                PINNED_PRIMARY_COMMIT,
                (0..32).map(|_| run(true)).collect()
            )]))
            .is_ok(),
            "thirty-two runs"
        );

        let dated = |on: &str| {
            let mut r = run(true);
            r["on"] = json!(on);
            file(vec![record("hysteria2", PINNED_PRIMARY_COMMIT, vec![r])])
        };
        assert!(parse(&dated("2026-11-05")).is_ok());
        for bad in [
            "2026-1-05",
            "2026/11/05",
            "2026-11-5x",
            "20261105-1",
            "abcd-ef-gh",
            "2026-11-050",
        ] {
            assert!(parse(&dated(bad)).is_err(), "{bad}");
        }

        // The same method at two commits, and two methods at one commit, are not duplicates.
        let ok = file(vec![
            record("hysteria2", PINNED_PRIMARY_COMMIT, vec![run(true)]),
            record("hysteria2", OLD, vec![run(true)]),
            record("vless_reality", PINNED_PRIMARY_COMMIT, vec![run(true)]),
        ]);
        assert!(parse(&ok).is_ok());
        let dup = file(vec![
            record("hysteria2", PINNED_PRIMARY_COMMIT, vec![run(true)]),
            record("hysteria2", PINNED_PRIMARY_COMMIT, vec![run(false)]),
        ]);
        assert_eq!(parse(&dup), Err(EvidenceError::Duplicate));
    }

    #[test]
    fn nothing_the_file_said_is_repeated_in_an_error() {
        let text = file(vec![record(
            "SENTINEL-method",
            PINNED_PRIMARY_COMMIT,
            vec![run(true)],
        )]);
        let shown = parse(&text).unwrap_err().to_string();
        assert!(!shown.contains("SENTINEL"), "{shown}");
    }

    /// The file this build ships must be one it can read: a bad edit fails here, in CI, instead of
    /// silently turning every method back to NotMeasured.
    #[test]
    fn the_shipped_evidence_is_readable() {
        parse(SHIPPED).expect("evidence/survival.json must parse");
    }

    /// Today nothing has been measured, so nothing is Tier 1. When a record is added this test is where the
    /// tier of each kind is stated, and it is changed with the record.
    #[test]
    fn what_the_shipped_evidence_says_today() {
        let records = parse(SHIPPED).unwrap();
        for kind in [
            ProfileKind::AmneziaWg,
            ProfileKind::Hysteria2,
            ProfileKind::VlessReality,
        ] {
            let expected = if records
                .iter()
                .any(|r| kind_of(&r.method) == Some(kind) && r.core_commit == pinned_commit(kind))
            {
                recorded(kind)
            } else {
                SurvivalMeasurement::NotMeasured
            };
            assert_eq!(recorded(kind), expected);
        }
        assert_eq!(
            recorded(ProfileKind::Hysteria2),
            SurvivalMeasurement::NotMeasured
        );
    }
}
