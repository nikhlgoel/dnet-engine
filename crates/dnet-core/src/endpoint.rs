//! T024 — the `Endpoint` entity (data-model §1).
//!
//! A destination the user owns, through which their traffic exits.

use crate::credential::CredentialRef;
use crate::error::DomainError;
use crate::health::EndpointHealth;
use crate::ids::EndpointId;

/// Maximum length of a user-supplied endpoint label.
pub const MAX_LABEL_LEN: usize = 64;

/// Where an endpoint address points.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointAddress {
    host: String,
    port: u16,
}

impl EndpointAddress {
    /// Parse an address, rejecting an empty host or a zero port.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, DomainError> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(DomainError::EmptyHost);
        }
        if port == 0 {
            return Err(DomainError::ZeroPort);
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for EndpointAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// How an endpoint came to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointOrigin {
    /// Provisioned by the wizard into the user's cloud account. Records enough to
    /// clean the cloud resources up on deletion (SC-011).
    Provisioned {
        provider: String,
        region: String,
        resource_ids: Vec<String>,
    },
    /// Added by hand — a server the user already controls.
    Manual,
}

/// A destination the user owns, through which traffic exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    id: EndpointId,
    label: String,
    address: EndpointAddress,
    origin: EndpointOrigin,
    credentials: CredentialRef,
    health: EndpointHealth,
    enabled: bool,
}

impl Endpoint {
    /// Create an endpoint, validating the label length (1–64 chars).
    ///
    /// Label *uniqueness* among endpoints is a collection invariant enforced by the
    /// store that holds them, not something a single entity can guarantee.
    pub fn new(
        id: EndpointId,
        label: impl Into<String>,
        address: EndpointAddress,
        origin: EndpointOrigin,
        credentials: CredentialRef,
    ) -> Result<Self, DomainError> {
        let label = label.into();
        let len = label.chars().count();
        if len == 0 || len > MAX_LABEL_LEN {
            return Err(DomainError::InvalidLabel(len));
        }
        Ok(Self {
            id,
            label,
            address,
            origin,
            credentials,
            health: EndpointHealth::new(),
            enabled: true,
        })
    }

    pub fn id(&self) -> EndpointId {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn address(&self) -> &EndpointAddress {
        &self.address
    }

    pub fn origin(&self) -> &EndpointOrigin {
        &self.origin
    }

    /// The credential reference. There is no accessor for the secret material itself.
    pub fn credentials(&self) -> &CredentialRef {
        &self.credentials
    }

    pub fn health(&self) -> &EndpointHealth {
        &self.health
    }

    pub fn set_health(&mut self, health: EndpointHealth) {
        self.health = health;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether deleting this endpoint should prompt about cloud resources (SC-011):
    /// true for a provisioned endpoint that recorded resources.
    pub fn has_cloud_resources(&self) -> bool {
        matches!(&self.origin, EndpointOrigin::Provisioned { resource_ids, .. } if !resource_ids.is_empty())
    }
}

/// True if at least one endpoint in the set is enabled — required before a connection
/// attempt is permitted (data-model §1 invariant).
pub fn has_enabled_endpoint(endpoints: &[Endpoint]) -> bool {
    endpoints.iter().any(Endpoint::is_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> CredentialRef {
        CredentialRef::new("dpapi:test")
    }

    fn addr() -> EndpointAddress {
        EndpointAddress::new("vpn.example", 443).unwrap()
    }

    fn make(label: &str) -> Result<Endpoint, DomainError> {
        Endpoint::new(
            EndpointId::new(),
            label,
            addr(),
            EndpointOrigin::Manual,
            cred(),
        )
    }

    #[test]
    fn address_rejects_empty_host_and_zero_port() {
        assert_eq!(EndpointAddress::new("", 443), Err(DomainError::EmptyHost));
        assert_eq!(
            EndpointAddress::new("   ", 443),
            Err(DomainError::EmptyHost)
        );
        assert_eq!(EndpointAddress::new("h", 0), Err(DomainError::ZeroPort));
    }

    #[test]
    fn address_displays_as_host_port() {
        assert_eq!(addr().to_string(), "vpn.example:443");
    }

    #[test]
    fn label_must_be_one_to_sixty_four_chars() {
        assert_eq!(make(""), Err(DomainError::InvalidLabel(0)));
        assert!(make("a").is_ok());
        assert!(make(&"a".repeat(MAX_LABEL_LEN)).is_ok());
        assert_eq!(
            make(&"a".repeat(MAX_LABEL_LEN + 1)),
            Err(DomainError::InvalidLabel(MAX_LABEL_LEN + 1))
        );
    }

    #[test]
    fn label_length_counts_characters_not_bytes() {
        // A 2-char label of multi-byte chars must not be rejected for its byte length.
        assert!(make("é🌐").is_ok());
    }

    #[test]
    fn new_endpoint_is_enabled_and_unprobed() {
        let e = make("oracle-mumbai").unwrap();
        assert!(e.is_enabled());
        assert_eq!(e.health().state, crate::health::HealthState::Unknown);
    }

    #[test]
    fn provisioned_with_resources_prompts_on_delete() {
        let provisioned = Endpoint::new(
            EndpointId::new(),
            "oracle-mumbai",
            addr(),
            EndpointOrigin::Provisioned {
                provider: "oracle".into(),
                region: "ap-mumbai-1".into(),
                resource_ids: vec!["ocid1.instance.x".into()],
            },
            cred(),
        )
        .unwrap();
        assert!(provisioned.has_cloud_resources());
        assert!(!make("manual").unwrap().has_cloud_resources());
    }

    #[test]
    fn enabled_endpoint_presence_is_detected() {
        let mut e = make("a").unwrap();
        assert!(has_enabled_endpoint(std::slice::from_ref(&e)));
        e.set_enabled(false);
        assert!(!has_enabled_endpoint(std::slice::from_ref(&e)));
        assert!(!has_enabled_endpoint(&[]));
    }
}
