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

    /// Brutal was enabled under an acknowledgement of a warning revision that is no longer
    /// in force (FR-006). The user must accept the current warning again.
    #[error(
        "Brutal congestion control requires acknowledgement of the current shared-capacity warning"
    )]
    BrutalNotAcknowledged,

    /// A primary-core profile was generated without its transport settings and credentials,
    /// or with those of another kind. Names the profile kind.
    #[error("the {0} profile requires its transport settings and credentials")]
    MissingTransport(&'static str),

    /// A Gecko packet size was outside the accepted bounds, or the minimum exceeded the maximum.
    #[error("Gecko packet sizes must satisfy 256 <= min <= max <= 1400")]
    InvalidGeckoPacketSize,

    /// The TLS server name was not a DNS hostname.
    #[error("TLS server name must be a DNS hostname")]
    InvalidServerName,

    /// The REALITY target domain was refused, for the reason given.
    #[error("REALITY target domain refused: {0}")]
    InvalidTargetDomain(&'static str),

    /// The REALITY public key was not 32 bytes of unpadded URL-safe base64.
    #[error("REALITY public key must be 32 bytes of unpadded URL-safe base64")]
    InvalidRealityPublicKey,

    /// A credential was missing or malformed. Names the credential, **never its value**.
    #[error("credential is missing or malformed: {0}")]
    InvalidCredential(&'static str),
}
