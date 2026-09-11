//! Network-state errors.

/// A failure while mutating routes, DNS, or adapters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetstateError {
    /// A routing/adapter operation failed.
    #[error("network-state operation failed: {0}")]
    Operation(String),
}
