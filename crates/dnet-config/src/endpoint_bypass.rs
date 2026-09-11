//! T048 — the always-present active-endpoint bypass (CC-05, data-model §Cross-cutting 2).
//!
//! The endpoint's own address must reach the physical network directly, or the tunnel's
//! packets to the endpoint would themselves be routed back into the tunnel — the R4
//! loop. That fact lives in two places: the primary core's `direct` route rule (here)
//! and the host route installed via the physical gateway (`dnet-netstate`, T052). They
//! **must not diverge**, so both are derived from this single `ActiveEndpointBypass`.

use dnet_core::endpoint::EndpointAddress;

/// The single source of truth for "the active endpoint bypasses the tunnel".
///
/// Both the generated `direct` route rule and the physical-gateway host route are built
/// from one of these, so rule evaluation and the route table cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveEndpointBypass {
    host: String,
    port: u16,
}

impl ActiveEndpointBypass {
    /// Derive the bypass from the active endpoint's address.
    pub fn new(addr: &EndpointAddress) -> Self {
        Self {
            host: addr.host().to_string(),
            port: addr.port(),
        }
    }

    /// The endpoint host — the match target for the `direct` route rule and the
    /// destination of the host route. One value, one source.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}
