//! Typed identifiers for domain entities (newtype pattern, per Rust patterns).
//!
//! Distinct wrapper types prevent mixing an endpoint id with a rule id at a call
//! site — the compiler rejects it.

use uuid::Uuid;

/// Identifier of an [`crate::endpoint::Endpoint`]. Random v4, immutable once created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointId(Uuid);

impl EndpointId {
    /// Mint a fresh random id.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID (e.g. loaded from persisted configuration).
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for EndpointId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EndpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifier of a [`crate::profile::ConnectionProfile`].
///
/// A stable string, not a random UUID: profile ids are referenced by the update feed
/// (FR-007) and must survive a profile being re-issued, so they are assigned by the
/// feed / configuration rather than minted per instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a [`crate::rule::RoutingRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleId(Uuid);

impl RuleId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RuleId {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifier of a [`crate::session::ConnectionSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// A physical network interface, identified by its OS interface LUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceId(u64);

impl InterfaceId {
    pub fn new(luid: u64) -> Self {
        Self(luid)
    }

    pub fn luid(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_endpoint_ids_are_distinct() {
        assert_ne!(EndpointId::new(), EndpointId::new());
    }

    #[test]
    fn endpoint_id_round_trips_through_uuid() {
        let id = EndpointId::new();
        assert_eq!(EndpointId::from_uuid(*id.as_uuid()), id);
    }

    #[test]
    fn profile_id_is_stable_and_readable() {
        let id = ProfileId::new("hy2-default");
        assert_eq!(id.as_str(), "hy2-default");
        assert_eq!(id, ProfileId::new("hy2-default"));
        assert_ne!(id, ProfileId::new("awg-default"));
    }

    #[test]
    fn interface_id_preserves_its_luid() {
        assert_eq!(InterfaceId::new(42).luid(), 42);
    }
}
