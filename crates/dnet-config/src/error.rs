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

    /// The peer endpoint was not an `IP:port` literal. On Windows the core resolves a
    /// hostname through the OS resolver; once the TUN is up that lookup returns a FakeIP
    /// address and the tunnel would dial into itself. The host resolves the endpoint
    /// before bring-up and passes the literal.
    #[error("AmneziaWG peer endpoint must be an IP:port literal, resolved before bring-up")]
    InvalidPeerEndpoint,

    /// Two of the `h1`..`h4` header values were equal. The pinned core rejects
    /// overlapping headers, so this is caught before the UAPI transaction.
    #[error("AmneziaWG h1..h4 header values must not overlap")]
    OverlappingHeaders,
}
