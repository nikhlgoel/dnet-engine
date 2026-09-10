//! Connection profiles (data-model §2).
//!
//! So far this module holds only `CoreBinding`, because
//! `FailureCause::CoreFailedPersistently` needs to name the supervised process that
//! failed. The rest of the profile model lands in T026.

/// Which supervised process serves a profile (research.md R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreBinding {
    /// The primary transport core: Hysteria 2 and VLESS+REALITY.
    PrimaryCore,
    /// The separate AmneziaWG process.
    AmneziaWgCore,
}
