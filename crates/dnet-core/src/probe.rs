//! T059 — judging a profile probe and racing profiles (FR-004, FR-016b, HV-12).
//!
//! A profile counts as working only if it **carries usable traffic**, not merely if a handshake
//! completes: a throttled network can let a handshake through and then crawl (HV-12), and the
//! user would be told they are connected when they are not. [`judge`] decides that from what
//! the prober measured. [`ProbeRace`] then picks a winner among profiles probed in parallel.
//!
//! Pure: callers pass in measurements and elapsed time since the race started. No I/O, no clock.
//!
//! **Winner rule.** The first usable profile wins, except that a usable Tier 2 profile waits up
//! to [`TIER_GRACE`] for a still-pending Tier 1 profile, because Tier 1 is preferred whenever
//! more than one profile is viable (FR-016b). Today no profile is Tier 1 (tier is measured, and
//! nothing has been measured yet), so in practice the first usable profile wins at once.

use std::time::Duration;

use crate::ids::ProfileId;
use crate::profile::ConnectionProfile;
use crate::tier::FailoverTier;

/// Least data a probe must move before its rate means anything.
pub const USABLE_MIN_BYTES: u64 = 64 * 1024;
/// Slowest rate that counts as usable: 256 kbit/s. Below it a page load or an update check
/// would not finish in a reasonable time.
pub const USABLE_MIN_BITS_PER_SEC: u64 = 256_000;
/// How long a usable Tier 2 profile waits for a pending Tier 1 profile.
pub const TIER_GRACE: Duration = Duration::from_secs(3);
/// A profile that has not reported usable traffic by now has failed (SC-003: 15 s when the
/// first profile tried works).
pub const PROBE_DEADLINE: Duration = Duration::from_secs(15);

/// What the prober observed for one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileProbe {
    /// No session could be established.
    HandshakeFailed,
    /// A session was established but the transfer stalled or errored.
    HandshakeOnly,
    /// A transfer completed: `bytes` moved in `elapsed`.
    Transferred { bytes: u64, elapsed: Duration },
}

/// Why a probe did not show a usable profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    HandshakeFailed,
    /// Handshake completed, no data came through.
    NoTraffic,
    /// Too little data moved to judge a rate.
    TooLittleData,
    /// Data moved, but below [`USABLE_MIN_BITS_PER_SEC`].
    TooSlow,
    /// The measurement is not valid (zero elapsed time).
    InvalidMeasurement,
}

/// The judgement on one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Usable { bits_per_sec: u64 },
    Unusable(Unusable),
}

/// Decide whether a probe shows a usable profile.
pub fn judge(probe: ProfileProbe) -> Verdict {
    match probe {
        ProfileProbe::HandshakeFailed => Verdict::Unusable(Unusable::HandshakeFailed),
        ProfileProbe::HandshakeOnly => Verdict::Unusable(Unusable::NoTraffic),
        ProfileProbe::Transferred { bytes, elapsed } => {
            if elapsed.is_zero() {
                return Verdict::Unusable(Unusable::InvalidMeasurement);
            }
            if bytes < USABLE_MIN_BYTES {
                return Verdict::Unusable(Unusable::TooLittleData);
            }
            // u128 so that bytes * 8 * 1e9 cannot overflow for any u64 byte count.
            let bits_per_sec = (u128::from(bytes) * 8 * 1_000_000_000 / elapsed.as_nanos())
                .min(u128::from(u64::MAX));
            let bits_per_sec = bits_per_sec as u64;
            if bits_per_sec < USABLE_MIN_BITS_PER_SEC {
                Verdict::Unusable(Unusable::TooSlow)
            } else {
                Verdict::Usable { bits_per_sec }
            }
        }
    }
}

/// The race's decision at a given moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceDecision {
    /// Keep waiting for more results.
    Pending,
    /// Use this profile.
    Selected {
        profile: ProfileId,
        tier: FailoverTier,
        bits_per_sec: u64,
    },
    /// Every profile failed or the deadline passed with none usable.
    NoneUsable,
}

enum State {
    Pending,
    Done { verdict: Verdict, at: Duration },
}

struct Entry {
    id: ProfileId,
    tier: FailoverTier,
    state: State,
}

/// Profiles probed in parallel, and what each reported.
pub struct ProbeRace {
    entries: Vec<Entry>,
}

impl ProbeRace {
    /// Start a race over `profiles`, in their given order.
    pub fn start(profiles: &[ConnectionProfile]) -> Self {
        Self {
            entries: profiles
                .iter()
                .map(|p| Entry {
                    id: p.id().clone(),
                    tier: p.tier(),
                    state: State::Pending,
                })
                .collect(),
        }
    }

    /// Record a profile's probe, observed `at` after the race started. Returns `false` for an
    /// unknown profile or one that already reported; the first report stands.
    pub fn record(&mut self, id: &ProfileId, probe: ProfileProbe, at: Duration) -> bool {
        match self
            .entries
            .iter_mut()
            .find(|e| &e.id == id && matches!(e.state, State::Pending))
        {
            Some(entry) => {
                entry.state = State::Done {
                    verdict: judge(probe),
                    at,
                };
                true
            }
            None => false,
        }
    }

    /// No more results will ever arrive: every probe that has not reported has died. Mark each
    /// as a failed handshake, `at` after the race started, so the race ends now rather than
    /// waiting out the deadline for answers that cannot come.
    pub fn fail_pending(&mut self, at: Duration) {
        for entry in &mut self.entries {
            if matches!(entry.state, State::Pending) {
                entry.state = State::Done {
                    verdict: Verdict::Unusable(Unusable::HandshakeFailed),
                    at,
                };
            }
        }
    }

    /// What to do `now` (time since the race started).
    pub fn decide(&self, now: Duration) -> RaceDecision {
        // The best usable profile: lowest tier number (Tier 1 first), then earliest report.
        let best = self
            .entries
            .iter()
            .filter_map(|e| match e.state {
                State::Done {
                    verdict: Verdict::Usable { bits_per_sec },
                    at,
                } => Some((e, bits_per_sec, at)),
                _ => None,
            })
            .min_by_key(|(e, _, at)| (e.tier, *at));

        let any_pending = self
            .entries
            .iter()
            .any(|e| matches!(e.state, State::Pending));
        let timed_out = now >= PROBE_DEADLINE;

        let Some((entry, bits_per_sec, at)) = best else {
            return if any_pending && !timed_out {
                RaceDecision::Pending
            } else {
                RaceDecision::NoneUsable
            };
        };

        // A Tier 2 winner waits for a Tier 1 profile that has not reported yet, but only for
        // the grace period and never past the deadline.
        let tier1_pending = self
            .entries
            .iter()
            .any(|e| e.tier == FailoverTier::Tier1 && matches!(e.state, State::Pending));
        if entry.tier == FailoverTier::Tier2
            && tier1_pending
            && !timed_out
            && now < at.saturating_add(TIER_GRACE)
        {
            return RaceDecision::Pending;
        }

        RaceDecision::Selected {
            profile: entry.id.clone(),
            tier: entry.tier,
            bits_per_sec,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{ProfileKind, ProfileParams};
    use crate::tier::SurvivalMeasurement;

    const SEC: Duration = Duration::from_secs(1);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn t2(id: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::new(ProfileId::new(id), kind, ProfileParams::new())
    }

    fn t1(id: &str, kind: ProfileKind) -> ConnectionProfile {
        ConnectionProfile::measured(
            ProfileId::new(id),
            kind,
            ProfileParams::new(),
            SurvivalMeasurement::Survived,
        )
    }

    fn good() -> ProfileProbe {
        ProfileProbe::Transferred {
            bytes: 1_000_000,
            elapsed: SEC,
        }
    }

    fn id(s: &str) -> ProfileId {
        ProfileId::new(s)
    }

    // ------------------------------------------------------------------ judge

    #[test]
    fn a_failed_handshake_is_unusable() {
        assert_eq!(
            judge(ProfileProbe::HandshakeFailed),
            Verdict::Unusable(Unusable::HandshakeFailed)
        );
    }

    /// FR-004: a completed handshake alone is not success.
    #[test]
    fn a_handshake_with_no_traffic_is_unusable() {
        assert_eq!(
            judge(ProfileProbe::HandshakeOnly),
            Verdict::Unusable(Unusable::NoTraffic)
        );
    }

    #[test]
    fn too_little_data_cannot_show_a_rate() {
        let probe = ProfileProbe::Transferred {
            bytes: USABLE_MIN_BYTES - 1,
            elapsed: Duration::from_millis(1),
        };
        assert_eq!(judge(probe), Verdict::Unusable(Unusable::TooLittleData));
    }

    /// HV-12: connected but throttled to a crawl is unusable.
    #[test]
    fn a_throttled_transfer_is_unusable() {
        // 1 MiB in 60 s is about 140 kbit/s.
        let probe = ProfileProbe::Transferred {
            bytes: 1024 * 1024,
            elapsed: secs(60),
        };
        assert_eq!(judge(probe), Verdict::Unusable(Unusable::TooSlow));
    }

    #[test]
    fn a_fast_transfer_is_usable_and_reports_its_rate() {
        assert_eq!(
            judge(good()),
            Verdict::Usable {
                bits_per_sec: 8_000_000
            }
        );
    }

    #[test]
    fn the_thresholds_are_inclusive() {
        // Exactly 64 KiB at exactly 256 kbit/s: 65_536 bytes * 8 / 2.048 s = 256_000 bit/s.
        let probe = ProfileProbe::Transferred {
            bytes: USABLE_MIN_BYTES,
            elapsed: Duration::from_millis(2048),
        };
        assert_eq!(
            judge(probe),
            Verdict::Usable {
                bits_per_sec: USABLE_MIN_BITS_PER_SEC
            }
        );
    }

    #[test]
    fn zero_elapsed_time_is_an_invalid_measurement_not_a_division_by_zero() {
        let probe = ProfileProbe::Transferred {
            bytes: 10_000_000,
            elapsed: Duration::ZERO,
        };
        assert_eq!(
            judge(probe),
            Verdict::Unusable(Unusable::InvalidMeasurement)
        );
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let probe = ProfileProbe::Transferred {
            bytes: u64::MAX,
            elapsed: Duration::from_nanos(1),
        };
        assert!(matches!(judge(probe), Verdict::Usable { .. }));
    }

    // ------------------------------------------------------------------- race

    #[test]
    fn with_no_tier1_profile_the_first_usable_profile_wins_at_once() {
        let profiles = [
            t2("awg", ProfileKind::AmneziaWg),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        assert_eq!(race.decide(Duration::ZERO), RaceDecision::Pending);
        race.record(&id("reality"), good(), secs(2));
        assert_eq!(
            race.decide(secs(2)),
            RaceDecision::Selected {
                profile: id("reality"),
                tier: FailoverTier::Tier2,
                bits_per_sec: 8_000_000
            }
        );
    }

    /// FR-016b: a usable Tier 2 profile waits briefly for a pending Tier 1.
    #[test]
    fn a_usable_tier2_waits_for_a_pending_tier1_until_the_grace_ends() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("reality"), good(), secs(1));
        assert_eq!(race.decide(secs(2)), RaceDecision::Pending);
        let at_grace_end = secs(1) + TIER_GRACE;
        assert!(matches!(
            race.decide(at_grace_end),
            RaceDecision::Selected { ref profile, tier: FailoverTier::Tier2, .. } if *profile == id("reality")
        ));
    }

    #[test]
    fn a_tier1_that_arrives_within_the_grace_beats_an_earlier_tier2() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("reality"), good(), secs(1));
        race.record(&id("hy2"), good(), secs(3));
        assert!(matches!(
            race.decide(secs(3)),
            RaceDecision::Selected { ref profile, tier: FailoverTier::Tier1, .. } if *profile == id("hy2")
        ));
    }

    /// A failed Tier 1 does not make the Tier 2 wait out the grace.
    #[test]
    fn a_tier2_is_not_held_for_a_tier1_that_already_failed() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("hy2"), ProfileProbe::HandshakeFailed, secs(1));
        race.record(&id("reality"), good(), secs(1));
        assert!(matches!(
            race.decide(secs(1)),
            RaceDecision::Selected {
                tier: FailoverTier::Tier2,
                ..
            }
        ));
    }

    /// HV-12: a throttled profile never wins; another usable one does.
    #[test]
    fn a_throttled_profile_does_not_win_and_another_does() {
        let profiles = [
            t2("awg", ProfileKind::AmneziaWg),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(
            &id("awg"),
            ProfileProbe::Transferred {
                bytes: 1024 * 1024,
                elapsed: secs(60),
            },
            secs(1),
        );
        assert_eq!(race.decide(secs(1)), RaceDecision::Pending);
        race.record(&id("reality"), good(), secs(4));
        assert!(matches!(
            race.decide(secs(4)),
            RaceDecision::Selected { ref profile, .. } if *profile == id("reality")
        ));
    }

    #[test]
    fn when_every_profile_has_failed_none_is_usable_without_waiting_for_the_deadline() {
        let profiles = [
            t2("a", ProfileKind::AmneziaWg),
            t2("b", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("a"), ProfileProbe::HandshakeFailed, secs(1));
        assert_eq!(race.decide(secs(1)), RaceDecision::Pending);
        race.record(&id("b"), ProfileProbe::HandshakeOnly, secs(2));
        assert_eq!(race.decide(secs(2)), RaceDecision::NoneUsable);
    }

    #[test]
    fn at_the_deadline_silent_profiles_count_as_failed() {
        let profiles = [t2("a", ProfileKind::AmneziaWg)];
        let race = ProbeRace::start(&profiles);
        assert_eq!(
            race.decide(PROBE_DEADLINE - Duration::from_millis(1)),
            RaceDecision::Pending
        );
        assert_eq!(race.decide(PROBE_DEADLINE), RaceDecision::NoneUsable);
    }

    #[test]
    fn an_empty_race_has_nothing_usable() {
        assert_eq!(
            ProbeRace::start(&[]).decide(Duration::ZERO),
            RaceDecision::NoneUsable
        );
    }

    /// A probe that panics or dies never reports. Once the runner knows nothing more can arrive,
    /// the race must end, not idle until the deadline.
    #[test]
    fn failing_the_pending_probes_ends_a_race_with_no_survivor_at_once() {
        let profiles = [
            t2("a", ProfileKind::AmneziaWg),
            t2("b", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        assert_eq!(race.decide(secs(1)), RaceDecision::Pending);
        race.fail_pending(secs(1));
        assert_eq!(race.decide(secs(1)), RaceDecision::NoneUsable);
    }

    #[test]
    fn failing_a_pending_tier1_releases_a_usable_tier2_from_the_grace_wait() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("reality"), good(), secs(1));
        assert_eq!(
            race.decide(secs(1)),
            RaceDecision::Pending,
            "waiting on Tier 1"
        );
        race.fail_pending(secs(1));
        assert!(matches!(
            race.decide(secs(1)),
            RaceDecision::Selected { ref profile, .. } if *profile == id("reality")
        ));
    }

    #[test]
    fn failing_the_pending_probes_leaves_the_ones_that_reported_alone() {
        let profiles = [
            t2("a", ProfileKind::AmneziaWg),
            t2("b", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("a"), good(), secs(1));
        race.fail_pending(secs(5));
        assert!(matches!(
            race.decide(secs(5)),
            RaceDecision::Selected { ref profile, .. } if *profile == id("a")
        ));
    }

    /// `record` is public, so an absurd timestamp must not be able to panic the grace arithmetic.
    #[test]
    fn an_enormous_timestamp_cannot_overflow_the_grace_arithmetic() {
        let profiles = [
            t1("hy2", ProfileKind::Hysteria2),
            t2("reality", ProfileKind::VlessReality),
        ];
        let mut race = ProbeRace::start(&profiles);
        race.record(&id("reality"), good(), Duration::MAX);
        // `now` is small, so the grace comparison is evaluated rather than short-circuited.
        assert_eq!(race.decide(secs(1)), RaceDecision::Pending);
    }

    #[test]
    fn an_unknown_profile_or_a_second_report_is_ignored() {
        let profiles = [t2("a", ProfileKind::AmneziaWg)];
        let mut race = ProbeRace::start(&profiles);
        assert!(!race.record(&id("nope"), good(), secs(1)));
        assert!(race.record(&id("a"), ProfileProbe::HandshakeFailed, secs(1)));
        assert!(
            !race.record(&id("a"), good(), secs(2)),
            "the first report stands"
        );
        assert_eq!(race.decide(secs(2)), RaceDecision::NoneUsable);
    }
}
