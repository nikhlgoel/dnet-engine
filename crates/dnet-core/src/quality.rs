//! T081 — path quality: smoothing raw samples, and naming what the smoothed value means (FR-018).
//!
//! A path's quality arrives as a stream of samples, each a probe that either came back after some
//! round-trip time or was lost. A single sample is noise: one lost packet says nothing about a
//! Wi-Fi link, and switching on it would make the connection flap (SC-007). So samples never
//! reach a decision directly. They are folded into [`PathQuality`] (`path.rs`), and decisions read
//! a [`QualityBand`] derived from the smoothed values.
//!
//! - **Loss** is an exponentially weighted fraction in `[0, 1]`.
//! - **Round-trip time** and **jitter** follow RFC 6298 (`SRTT` and `RTTVAR`), the same
//!   recurrences `health.rs` uses for endpoints, so the two agree on what "smoothed" means. A lost
//!   sample measured no round trip and leaves both untouched.
//! - **Bands** are three: `Good`, `Poor`, `Unusable`. Three, because a decision needs "fine",
//!   "worth leaving if something better exists" and "not worth staying on at all", and nothing
//!   finer than that is stable enough to act on.
//!
//! Pure logic: no clock, no I/O.

use std::time::Duration;

use crate::health::{RTTVAR_EWMA_BETA, RTT_EWMA_ALPHA};
use crate::path::PathQuality;

/// EWMA weight for the loss fraction, the same `1/8` as the round-trip estimate. One stray loss
/// from a clean start reads `0.125`, below the `Poor` line, and decays away; two in a row read
/// `0.23` (`Poor`); it takes six in a row (`1 − 0.875⁶ ≈ 0.55`) to read `Unusable`.
pub const LOSS_EWMA_ALPHA: f64 = 0.125;

/// One observation of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSample {
    /// The probe was answered after `rtt`.
    Answered { rtt: Duration },
    /// The probe got no answer.
    Lost,
}

/// How good a path is, as far as a decision is concerned. Ordered: `Unusable < Poor < Good`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QualityBand {
    /// Not worth staying on: most probes are lost.
    Unusable,
    /// Working, but lossy or slow.
    Poor,
    /// Fine.
    Good,
}

/// Where the bands begin. Defaults are tuned for the links the product exists for: shared campus
/// Wi-Fi, where a few percent loss and a few hundred milliseconds are ordinary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityThresholds {
    /// Smoothed loss at or above this is `Poor`.
    pub poor_loss: f64,
    /// Smoothed loss at or above this is `Unusable`.
    pub unusable_loss: f64,
    /// Smoothed round-trip time at or above this is `Poor`.
    pub poor_rtt: Duration,
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            poor_loss: 0.15,
            unusable_loss: 0.50,
            poor_rtt: Duration::from_millis(300),
        }
    }
}

impl PathQuality {
    /// Fold one sample into the smoothed quality, returning the result.
    ///
    /// The first answered sample seeds the round-trip estimate as RFC 6298 specifies
    /// (`SRTT = R`, `RTTVAR = R/2`); later ones use the EWMA recurrences. Loss always updates; a
    /// lost sample never touches the round-trip estimate, because it measured no round trip.
    #[must_use]
    pub fn observe(&self, sample: PathSample) -> PathQuality {
        let lost = matches!(sample, PathSample::Lost);
        let loss =
            LOSS_EWMA_ALPHA * f64::from(u8::from(lost)) + (1.0 - LOSS_EWMA_ALPHA) * self.loss_ewma;
        let mut next = PathQuality {
            loss_ewma: loss.clamp(0.0, 1.0),
            rtt_ewma: self.rtt_ewma,
            jitter_ewma: self.jitter_ewma,
        };
        if let PathSample::Answered { rtt } = sample {
            match self.rtt_ewma {
                None => {
                    next.rtt_ewma = Some(rtt);
                    next.jitter_ewma = Some(rtt / 2);
                }
                Some(srtt) => {
                    let r = rtt.as_secs_f64();
                    let s = srtt.as_secs_f64();
                    let var = self.jitter_ewma.map_or(0.0, |v| v.as_secs_f64());
                    let new_var = (1.0 - RTTVAR_EWMA_BETA) * var + RTTVAR_EWMA_BETA * (s - r).abs();
                    let new_srtt = (1.0 - RTT_EWMA_ALPHA) * s + RTT_EWMA_ALPHA * r;
                    next.rtt_ewma = Some(Duration::from_secs_f64(new_srtt.max(0.0)));
                    next.jitter_ewma = Some(Duration::from_secs_f64(new_var.max(0.0)));
                }
            }
        }
        next
    }

    /// The band this quality falls in. Loss decides `Unusable`; loss or round-trip time decides
    /// `Poor`. A path with no estimates yet is `Good`: nothing says otherwise, and treating an
    /// unmeasured path as bad would stop a freshly detected link from ever being chosen.
    pub fn band(&self, thresholds: &QualityThresholds) -> QualityBand {
        if self.loss_ewma >= thresholds.unusable_loss {
            QualityBand::Unusable
        } else if self.loss_ewma >= thresholds.poor_loss
            || self.rtt_ewma.is_some_and(|rtt| rtt >= thresholds.poor_rtt)
        {
            QualityBand::Poor
        } else {
            QualityBand::Good
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(ms: u64) -> PathSample {
        PathSample::Answered {
            rtt: Duration::from_millis(ms),
        }
    }

    fn fold(start: PathQuality, samples: &[PathSample]) -> PathQuality {
        samples.iter().fold(start, |q, s| q.observe(*s))
    }

    #[test]
    fn the_first_answer_seeds_the_estimate_as_rfc_6298_says() {
        let q = PathQuality::unmeasured().observe(answered(80));
        assert_eq!(q.rtt_ewma, Some(Duration::from_millis(80)));
        assert_eq!(q.jitter_ewma, Some(Duration::from_millis(40)));
        assert_eq!(q.loss_ewma, 0.0);
    }

    #[test]
    fn later_answers_move_the_estimate_by_one_eighth_of_the_difference() {
        let q = fold(PathQuality::unmeasured(), &[answered(80), answered(160)]);
        // 7/8 * 80 + 1/8 * 160 = 90
        let srtt = q.rtt_ewma.unwrap().as_secs_f64() * 1000.0;
        assert!((srtt - 90.0).abs() < 1e-6, "{srtt}");
        // 3/4 * 40 + 1/4 * |80 - 160| = 50
        let var = q.jitter_ewma.unwrap().as_secs_f64() * 1000.0;
        assert!((var - 50.0).abs() < 1e-6, "{var}");
    }

    #[test]
    fn a_lost_sample_raises_loss_and_measures_no_round_trip() {
        let before = PathQuality::unmeasured().observe(answered(80));
        let after = before.observe(PathSample::Lost);
        assert!((after.loss_ewma - LOSS_EWMA_ALPHA).abs() < 1e-12);
        assert_eq!(after.rtt_ewma, before.rtt_ewma);
        assert_eq!(after.jitter_ewma, before.jitter_ewma);
    }

    #[test]
    fn a_lost_sample_on_an_unmeasured_path_leaves_it_without_a_round_trip_estimate() {
        let q = PathQuality::unmeasured().observe(PathSample::Lost);
        assert_eq!(q.rtt_ewma, None);
        assert_eq!(q.jitter_ewma, None);
    }

    #[test]
    fn loss_decays_when_answers_resume() {
        let lossy = fold(PathQuality::unmeasured(), &[PathSample::Lost; 3]);
        let recovered = fold(lossy.clone(), &[answered(50); 10]);
        // Each answered sample keeps seven eighths of what was there.
        let expected = lossy.loss_ewma * (1.0 - LOSS_EWMA_ALPHA).powi(10);
        assert!(
            (recovered.loss_ewma - expected).abs() < 1e-12,
            "{}",
            recovered.loss_ewma
        );
        assert!(recovered.loss_ewma < lossy.loss_ewma / 3.0);
    }

    #[test]
    fn loss_stays_within_zero_and_one_however_long_it_runs() {
        let all_lost = fold(PathQuality::unmeasured(), &[PathSample::Lost; 500]);
        assert!(all_lost.loss_ewma <= 1.0 && all_lost.loss_ewma > 0.99);
        let all_ok = fold(all_lost, &[answered(10); 500]);
        assert!((0.0..=1e-9).contains(&all_ok.loss_ewma));
    }

    // ------------------------------------------------------------------ bands

    #[test]
    fn a_path_nothing_is_known_about_is_good() {
        let t = QualityThresholds::default();
        assert_eq!(PathQuality::unmeasured().band(&t), QualityBand::Good);
    }

    #[test]
    fn one_lost_probe_does_not_make_a_path_poor() {
        let t = QualityThresholds::default();
        let q = fold(PathQuality::unmeasured(), &[answered(40), answered(40)])
            .observe(PathSample::Lost);
        assert_eq!(q.band(&t), QualityBand::Good, "loss {}", q.loss_ewma);
    }

    #[test]
    fn two_lost_probes_in_a_row_make_a_path_poor() {
        let t = QualityThresholds::default();
        let q = fold(PathQuality::unmeasured(), &[PathSample::Lost; 2]);
        assert_eq!(q.band(&t), QualityBand::Poor, "loss {}", q.loss_ewma);
    }

    #[test]
    fn it_takes_six_lost_probes_in_a_row_to_make_a_path_unusable() {
        let t = QualityThresholds::default();
        let five = fold(PathQuality::unmeasured(), &[PathSample::Lost; 5]);
        assert_eq!(five.band(&t), QualityBand::Poor, "loss {}", five.loss_ewma);
        let six = five.observe(PathSample::Lost);
        assert_eq!(
            six.band(&t),
            QualityBand::Unusable,
            "loss {}",
            six.loss_ewma
        );
    }

    #[test]
    fn a_slow_but_lossless_path_is_poor_not_unusable() {
        let t = QualityThresholds::default();
        let q = fold(PathQuality::unmeasured(), &[answered(450); 5]);
        assert_eq!(q.band(&t), QualityBand::Poor);
    }

    #[test]
    fn the_boundaries_belong_to_the_worse_band() {
        let t = QualityThresholds::default();
        let at = |loss: f64, rtt_ms: u64| PathQuality {
            loss_ewma: loss,
            rtt_ewma: Some(Duration::from_millis(rtt_ms)),
            jitter_ewma: None,
        };
        assert_eq!(at(0.15, 10).band(&t), QualityBand::Poor);
        assert_eq!(at(0.1499, 10).band(&t), QualityBand::Good);
        assert_eq!(at(0.50, 10).band(&t), QualityBand::Unusable);
        assert_eq!(at(0.4999, 10).band(&t), QualityBand::Poor);
        assert_eq!(at(0.0, 300).band(&t), QualityBand::Poor);
        assert_eq!(at(0.0, 299).band(&t), QualityBand::Good);
    }

    #[test]
    fn bands_order_from_worst_to_best() {
        assert!(QualityBand::Unusable < QualityBand::Poor);
        assert!(QualityBand::Poor < QualityBand::Good);
    }

    /// FR-018: every fourth probe lost is a raw signal that flips constantly, but the smoothed band
    /// settles and stays put once the filter has warmed up.
    #[test]
    fn steady_intermittent_loss_gives_a_steady_band() {
        let t = QualityThresholds::default();
        let mut q = PathQuality::unmeasured();
        let mut bands = Vec::new();
        for i in 0..400 {
            q = q.observe(if i % 4 == 3 {
                PathSample::Lost
            } else {
                answered(40)
            });
            if i >= 100 {
                bands.push(q.band(&t));
            }
        }
        assert!(
            bands.iter().all(|b| *b == QualityBand::Poor),
            "25% loss is Poor throughout"
        );
    }

    /// The honest limit of a memoryless band: a signal sitting exactly on a threshold can cross it
    /// on noise. That is why decisions use time (`failover.rs`), never a single reading.
    #[test]
    fn a_signal_on_a_threshold_can_cross_it_which_is_why_decisions_wait() {
        let t = QualityThresholds::default();
        let mut q = PathQuality::unmeasured();
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            q = q.observe(if i % 2 == 0 {
                PathSample::Lost
            } else {
                answered(40)
            });
            if i >= 100 {
                seen.insert(q.band(&t));
            }
        }
        assert!(seen.contains(&QualityBand::Unusable) && seen.contains(&QualityBand::Poor));
    }
}
