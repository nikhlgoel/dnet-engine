//! Configuration-generation errors.

/// A failure while generating supervised-core configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Brutal congestion control was requested with only one of `up`/`down` set. A
    /// partial bandwidth configuration silently half-enables Brutal (CC-04), so it is
    /// refused at generation time.
    #[error("Brutal congestion control requires both up and down bandwidth")]
    PartialBrutalBandwidth,

    /// Profile A (AmneziaWG) generation was asked for without the AmneziaWG adapter
    /// name, so the outbound could not be bound to it (CC-07).
    #[error("Profile A requires the AmneziaWG adapter name to bind its outbound")]
    MissingAmneziaWgAdapter,

    /// A peer was configured with an empty public key or endpoint, which cannot form a
    /// valid AmneziaWG peer.
    #[error("AmneziaWG peer requires a non-empty public key and endpoint")]
    IncompletePeer,
}
