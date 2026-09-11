//! T053 — Profile A outbound binding (CC-07, research.md §R4).
//!
//! When AmneziaWG (Profile A) is active, the primary core must send that traffic out a
//! `direct` outbound **bound to the AmneziaWG adapter** — and to nothing else. The
//! AmneziaWG process owns the real tunnel; the primary core only hands packets to its
//! adapter. Binding to the wrong interface (or leaving it unbound) is one half of the
//! R4 routing loop, so the binding is explicit and single-valued.

use serde::Serialize;

/// A `direct` outbound bound to exactly one interface — the AmneziaWG adapter.
///
/// `bind_interface` is a single interface name, never a list, so Profile A traffic
/// cannot fan out to the physical interface (CC-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectBoundOutbound {
    /// The outbound's tag, referenced by the route's final rule.
    pub tag: String,
    /// Always `"direct"`; the primary core does not tunnel Profile A itself.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The AmneziaWG adapter name. The one interface this outbound may use.
    pub bind_interface: String,
}

impl DirectBoundOutbound {
    /// Bind a Profile A outbound to `adapter` (the AmneziaWG adapter name).
    pub fn to_amneziawg_adapter(tag: impl Into<String>, adapter: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            kind: "direct",
            bind_interface: adapter.into(),
        }
    }
}
