//! T097 — adding a server the person already runs, with no cloud account involved (FR-010, US2-5).
//!
//! Provisioning is for people who need a server made. Plenty of people already have one, or a friend who
//! does, and for them the whole wizard (credentials, regions, scripts) is in the way. A manual endpoint is
//! just a name and an address: no provider, no credential for any cloud, nothing created and so nothing to
//! clean up. It is an `Endpoint` whose origin is `Manual`, so deleting it never offers to remove cloud
//! resources.
//!
//! What is checked is what can be wrong with the *input*: the label, and that the address could be a
//! server at all. Whether anything answers there is found out by the first connection, not here.

use std::net::IpAddr;

use dnet_core::credential::CredentialRef;
use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
use dnet_core::error::DomainError;
use dnet_core::ids::EndpointId;

/// Why a manual endpoint was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManualError {
    #[error("the name must be 1 to {max} characters and contain no control characters", max = dnet_core::endpoint::MAX_LABEL_LEN)]
    Label,
    #[error("that is not an address a server could have")]
    Address,
    #[error("the port must be between 1 and 65535")]
    Port,
}

/// Whether `host` is an address or a name a server could have.
fn plausible_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return dnet_config::persist::address_could_be_a_server(ip);
    }
    dnet_core::rule_eval::normalize_domain(host).is_some_and(|name| name.contains('.'))
}

/// Make an endpoint from what the person typed. `credentials` names the sealed credentials that go with it;
/// it is a reference, never the material.
pub fn endpoint(
    label: &str,
    host: &str,
    port: u16,
    credentials: CredentialRef,
) -> Result<Endpoint, ManualError> {
    let label = label.trim();
    if label.is_empty() || label.chars().any(char::is_control) {
        return Err(ManualError::Label);
    }
    let host = host.trim();
    if !plausible_host(host) {
        return Err(ManualError::Address);
    }
    let address = EndpointAddress::new(host, port).map_err(|e| match e {
        DomainError::ZeroPort => ManualError::Port,
        _ => ManualError::Address,
    })?;
    Endpoint::new(
        EndpointId::new(),
        label,
        address,
        EndpointOrigin::Manual,
        credentials,
    )
    .map_err(|_| ManualError::Label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> CredentialRef {
        CredentialRef::new("dpapi:manual-test")
    }

    #[test]
    fn a_name_an_address_and_a_port_make_an_endpoint_with_no_cloud_attached() {
        let made = endpoint("  my server ", "203.0.113.7", 443, cred()).unwrap();
        assert_eq!(made.label(), "my server");
        assert_eq!(made.address().to_string(), "203.0.113.7:443");
        assert_eq!(made.origin(), &EndpointOrigin::Manual);
        assert!(
            !made.has_cloud_resources(),
            "deleting it never offers to remove cloud resources"
        );
        assert!(made.is_enabled());
    }

    #[test]
    fn a_host_name_is_accepted() {
        assert!(endpoint("s", "vpn.example.org", 8443, cred()).is_ok());
        assert!(endpoint("s", "VPN.Example.org.", 8443, cred()).is_ok());
        assert!(endpoint("s", "2001:db8::7", 443, cred()).is_ok());
    }

    #[test]
    fn addresses_a_server_cannot_have_are_refused() {
        for bad in [
            "",
            "   ",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "ff02::1",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
            "localhost",
            "no spaces.example",
            "a..b",
            "http://x.example",
            "x.example/path",
            "x.example:443",
            "-x.example",
        ] {
            assert_eq!(
                endpoint("s", bad, 443, cred()).unwrap_err(),
                ManualError::Address,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_zero_port_is_a_port_error() {
        assert_eq!(
            endpoint("s", "203.0.113.7", 0, cred()).unwrap_err(),
            ManualError::Port
        );
    }

    #[test]
    fn labels_are_checked_the_way_every_endpoint_label_is() {
        for bad in ["", "   ", "has\ncontrol", "tab\there"] {
            assert_eq!(
                endpoint(bad, "203.0.113.7", 443, cred()).unwrap_err(),
                ManualError::Label,
                "{bad:?}"
            );
        }
        let long = "x".repeat(65);
        assert_eq!(
            endpoint(&long, "203.0.113.7", 443, cred()).unwrap_err(),
            ManualError::Label
        );
        assert!(endpoint(&"x".repeat(64), "203.0.113.7", 443, cred()).is_ok());
    }

    #[test]
    fn the_credential_is_a_reference_and_the_endpoint_never_holds_the_material() {
        let made = endpoint("s", "203.0.113.7", 443, cred()).unwrap();
        assert_eq!(made.credentials().store_key(), "dpapi:manual-test");
    }
}
