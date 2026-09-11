//! Domain validation errors.
//!
//! Every constructor that can reject its input returns one of these, so invalid
//! states are refused at the boundary rather than represented (Principle: parse,
//! don't validate).

/// A domain-level validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// An endpoint label was outside the 1–64 character range.
    #[error("endpoint label must be 1-64 characters, got {0}")]
    InvalidLabel(usize),

    /// An endpoint address had an empty host.
    #[error("endpoint host must not be empty")]
    EmptyHost,

    /// An endpoint address had a zero port.
    #[error("endpoint port must not be zero")]
    ZeroPort,

    /// A CIDR string could not be parsed.
    #[error("invalid CIDR {0:?}")]
    InvalidCidr(String),

    /// A domain or application matcher pattern was empty.
    #[error("routing rule match pattern must not be empty")]
    EmptyPattern,

    /// Brutal congestion control was requested on a non-Hysteria 2 profile.
    #[error("Brutal congestion control is only available on a Hysteria 2 profile")]
    BrutalRequiresHysteria2,

    /// Brutal congestion control was requested without the required acknowledgement.
    #[error("Brutal congestion control requires explicit acknowledgement of its shared-AP impact")]
    BrutalNotAcknowledged,

    /// A profile set contained no TCP-carrier profile, so it is dead on UDP-blocking
    /// networks (FR-002).
    #[error("a profile set must contain at least one TCP-carrier profile")]
    NoTcpFallback,

    /// Two routing rules shared a precedence value (FR-022).
    #[error("routing rules share precedence {0}; precedence must be unique")]
    PrecedenceCollision(u32),

    /// More than one network path was marked as carrying traffic.
    #[error("at most one path may be carrying; found {0}")]
    MultipleCarryingPaths(usize),
}
