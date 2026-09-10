//! Connection sessions and how they end (data-model §5).
//!
//! So far this module holds only `FailureCause`. `ConnectionSession` and
//! `ConnectionEvent` land in T030.

use crate::profile::CoreBinding;

/// Why a connection failed.
///
/// Each variant is distinguishable, and there is deliberately **no `Unknown`**: a
/// generic error reaching the user is a defect (FR-039, SC-020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureCause {
    /// No configured endpoint answered.
    NoEndpointReachable,
    /// The network is blocking every connection profile.
    AllProfilesBlocked,
    /// A captive portal is intercepting traffic until the user logs in.
    CaptivePortalUnsatisfied,
    /// The service lacks the privilege it needs.
    InsufficientPrivilege,
    /// A supervised core kept failing and restarts have stopped.
    CoreFailedPersistently {
        /// The process that failed.
        core: CoreBinding,
    },
    /// No network interface can carry traffic.
    NoUsablePath,
    /// The configuration cannot be used as written.
    ConfigurationInvalid {
        /// What is wrong, stated so the user can act on it.
        detail: String,
    },
}
