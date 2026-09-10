//! `FailoverTier`: whether established connections survive a change of network interface.
//!
//! Tier is set from **measurement**, never inferred from the profile kind. A profile
//! whose Tier 1 claim fails SPIKE-R9 is demoted to `Tier2` in configuration and in the
//! UI (data-model §2.1, research.md R9, Constitution Principle VI).

/// Failover behaviour of a connection profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailoverTier {
    /// Established connections survive an interface change. Preferred when several
    /// profiles are viable (FR-016b).
    Tier1,
    /// Access only: established connections break and re-establish. The user is
    /// warned before selection (FR-016b).
    Tier2,
}
