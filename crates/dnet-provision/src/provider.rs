// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam between a provisioning job and a cloud provider.
//!
//! Everything the job asks of a provider is a method here, so the whole stage machine, the ledger and the
//! cleanup can be exercised against a mock that creates nothing real (the contract tests PRV-01…PRV-09 do
//! exactly that), and a concrete provider (Oracle Cloud's Always Free tier is the target, research R10) is
//! an implementation of one trait.
//!
//! **A provider is built with the credential and keeps it.** The job never holds the credential, so it
//! cannot leak it: it can only be asked to describe what the credential is
//! ([`Provider::inspect_credential`]) and to act with it. The text of a [`ProviderError`] is written by the
//! provider and must not contain the credential; the job passes every such string through
//! [`crate::sanitize::Sanitizer`] anyway, because a mistake there would put a cloud key in a log.
//!
//! Methods are synchronous and blocking: a job runs on its own worker, and cancellation is checked
//! between stages. A provider whose API is asynchronous blocks on it inside.

use std::net::Ipv4Addr;

use crate::capacity::Capacity;
use crate::credential::Inspection;

/// What a provider call can say. The strings are the provider's own words about the failure, and are
/// shown to the person after sanitising; they must not contain the credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The provider stopped accepting the credential partway through.
    #[error("the provider no longer accepts the credential")]
    Unauthorized,
    /// The free allowance is already used by resources that exist.
    #[error("the free allowance is used up: {0}")]
    QuotaExceeded(String),
    /// Not reachable, or busy. Worth trying again.
    #[error("the provider could not be reached or is busy: {0}")]
    Transient(String),
    /// The provider understood and said no.
    #[error("the provider refused the request: {0}")]
    Rejected(String),
}

/// A kind of cloud resource a job creates (and so must be able to remove).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// The virtual machine.
    Instance,
    /// The firewall / security rules that open the transport ports.
    NetworkRule,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::Instance => "instance",
            ResourceKind::NetworkRule => "network-rule",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "instance" => Some(ResourceKind::Instance),
            "network-rule" => Some(ResourceKind::NetworkRule),
            _ => None,
        }
    }
}

/// What to create. `token` is chosen by the job and is the same on every retry of the same job: creating
/// again with the same token must not make a second machine, and cleanup finds what a crash left behind by
/// looking for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSpec {
    pub token: String,
    pub region: String,
    pub shape: String,
}

/// A machine that exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceInfo {
    pub provider_id: String,
    pub public_ip: Ipv4Addr,
}

/// Firewall rules that exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub provider_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

/// One port to open to the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRule {
    pub protocol: Protocol,
    pub port: u16,
}

/// What removing a resource came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    /// It was not there to remove. Not an error: cleanup is meant to be run twice.
    AlreadyGone,
}

pub trait Provider: Send + Sync {
    /// A short name for the provider, recorded with the endpoint.
    fn name(&self) -> &str;

    /// The permissions a job needs, in the provider's words. Shown to the person before the credential is
    /// asked for (PR-02) and checked against it afterwards.
    fn required_permissions(&self) -> &[&'static str];

    /// Say what the credential is. The first call a job makes, and the last one it makes with a credential
    /// that turns out to be unusable.
    fn inspect_credential(&self) -> Result<Inspection, ProviderError>;

    fn check_capacity(&self, region: &str, shape: &str) -> Result<Capacity, ProviderError>;

    /// Create the machine. Idempotent in `spec.token`.
    fn create_instance(&self, spec: &InstanceSpec) -> Result<InstanceInfo, ProviderError>;

    /// Open `ports` on the machine. Idempotent in `token`.
    fn open_ports(
        &self,
        token: &str,
        region: &str,
        instance: &InstanceInfo,
        ports: &[PortRule],
    ) -> Result<NetworkInfo, ProviderError>;

    /// Run the bootstrap script on the machine and return what it printed. Idempotent: running it again
    /// against a set-up machine changes nothing and prints the same report.
    fn bootstrap(&self, instance: &InstanceInfo, script: &str) -> Result<String, ProviderError>;

    /// Run the keepalive installer on the machine.
    fn install_keepalive(&self, instance: &InstanceInfo, script: &str)
        -> Result<(), ProviderError>;

    /// Whether the keepalive is installed and running.
    fn keepalive_installed(&self, instance: &InstanceInfo) -> Result<bool, ProviderError>;

    /// The provider's id for the resource created under `token`, if one exists. How cleanup finds what a
    /// crash left behind before the id could be recorded.
    fn find(
        &self,
        kind: ResourceKind,
        token: &str,
        region: &str,
    ) -> Result<Option<String>, ProviderError>;

    /// Remove a resource. `AlreadyGone` if it was not there.
    fn delete(
        &self,
        kind: ResourceKind,
        provider_id: &str,
        region: &str,
    ) -> Result<DeleteOutcome, ProviderError>;
}
