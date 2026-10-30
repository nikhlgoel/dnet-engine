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

    /// Brutal congestion control was requested without an acknowledgement of the current
    /// shared-capacity warning revision.
    #[error("Brutal congestion control requires explicit acknowledgement of its shared-AP impact")]
    BrutalNotAcknowledged,

    /// A profile set contained no TCP-carrier profile, so it is dead on UDP-blocking
    /// networks (FR-002).
    #[error("a profile set must contain at least one TCP-carrier profile")]
    NoTcpFallback,

    /// A domain pattern that could not be a DNS name: empty, with a space or control character, an
    /// empty or over-long label, or outside ASCII (an internationalised name is given as `xn--`).
    #[error("{0:?} is not a domain name a rule can match")]
    InvalidDomainPattern(String),

    /// Two routing rules shared a precedence value (FR-022).
    #[error("routing rules share precedence {0}; precedence must be unique")]
    PrecedenceCollision(u32),

    /// More than one network path was marked as carrying traffic.
    #[error("at most one path may be carrying; found {0}")]
    MultipleCarryingPaths(usize),

    /// A rule set lacked the built-in DNS-capture rule, so plaintext port-53 queries
    /// could leak to the physical network (DNS-leak prevention, FakeIP).
    #[error("rule set must contain the built-in DNS-capture rule; without it DNS can leak")]
    MissingDnsCapture,

    /// A `DnsPort` matcher was paired with an action other than `Capture`. Port-53
    /// traffic must always be captured into the tunnel, never tunnelled-with-fallback
    /// or bypassed.
    #[error("a DnsPort matcher must use the Capture action")]
    DnsPortRequiresCapture,

    /// Port 853 (encrypted DNS) is only ever refused, never tunnelled or bypassed (T070).
    #[error("an EncryptedDnsPort matcher must use the Reject action")]
    EncryptedDnsPortRequiresReject,

    /// Only the product's own rules may refuse traffic; a person's rule routes it (T070).
    #[error("only built-in rules may use the Reject action")]
    RejectIsBuiltinOnly,

    /// The person opted out of the encrypted-DNS block but some of it is still in the rule set (T070).
    #[error("encrypted DNS is allowed but the rule set still blocks it")]
    EncryptedDnsBlockLeftBehind,

    /// A range of the person's lies inside the pool of placeholder addresses handed out for names
    /// (T069). Nothing real lives there.
    #[error("{0} is inside the range used for placeholder addresses; a rule there cannot match a real destination")]
    RangeInsideFakeIpPool(String),

    /// A person's rule would outrank the encrypted-DNS block and quietly undo it (T070).
    #[error("rule precedence {0} outranks the built-in encrypted-DNS block; use {1} or higher")]
    OutranksEncryptedDnsBlock(u32, u32),

    /// A person's rule would come before a built-in rule (T108). Built-ins keep DNS captured, the
    /// endpoint off the tunnel and local resources reachable, so they always win.
    #[error("rule precedence {0} would outrank the built-in rules; a rule you add starts at {1}")]
    UserRuleOutranksBuiltins(u32, u32),

    /// A rule of a kind only the built-in set has: a port matcher, or capture or reject.
    #[error("a rule you add matches a domain, a domain and its subdomains, an address range or a program, and tunnels or bypasses")]
    NotAPersonalRule,

    /// A rule set lost a built-in rule. Built-ins keep local resources, portal login, the
    /// endpoint route, and DNS capture working, so they cannot be deleted (data-model §4).
    #[error("built-in rule {0} cannot be removed")]
    BuiltinRuleMissing(String),
}
