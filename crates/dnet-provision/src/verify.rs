//! T095 — an endpoint exists only once it has been shown to work (PR-10, PRV-06).
//!
//! The last stage before an `Endpoint` is created is the one that matters most to the person: it is where
//! "the machine exists and the scripts ran" becomes "traffic really goes through it". It tries the
//! endpoint's profiles end to end, and the job needs **at least one** to succeed. If none does, the job
//! fails, the resources are cleaned up, and **no `Endpoint` record is created**: a person is never handed
//! an endpoint that has never carried a byte.
//!
//! The trying is done by the caller's [`Reachability`] (in the daemon, the same prober that races profiles
//! when connecting). This module only decides what the results mean.

use std::net::Ipv4Addr;

use dnet_config::credentials::EndpointCredentials;
use dnet_core::profile::ProfileKind;

/// Tries a profile of a new endpoint end to end.
pub trait Reachability: Send + Sync {
    /// For each profile `credentials` can serve, whether traffic went through `address` using it.
    fn verify(
        &self,
        address: Ipv4Addr,
        credentials: &EndpointCredentials,
    ) -> Vec<(ProfileKind, bool)>;
}

/// Why verification did not pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyFailure {
    /// Nothing was tried, so nothing can be said to work.
    #[error("no profile could be tried against the new endpoint")]
    NothingTried,
    /// Everything that was tried failed.
    #[error("none of the connection methods could reach the new endpoint")]
    NoneReachable { tried: Vec<ProfileKind> },
}

/// The profiles that worked, or why none did. At least one must have.
pub fn require_one(results: &[(ProfileKind, bool)]) -> Result<Vec<ProfileKind>, VerifyFailure> {
    if results.is_empty() {
        return Err(VerifyFailure::NothingTried);
    }
    let working: Vec<ProfileKind> = results
        .iter()
        .filter(|(_, ok)| *ok)
        .map(|(kind, _)| *kind)
        .collect();
    if working.is_empty() {
        return Err(VerifyFailure::NoneReachable {
            tried: results.iter().map(|(kind, _)| *kind).collect(),
        });
    }
    Ok(working)
}

/// A [`Reachability`] with a fixed answer. For tests.
pub struct FixedReachability(pub Vec<(ProfileKind, bool)>);

impl Reachability for FixedReachability {
    fn verify(
        &self,
        _address: Ipv4Addr,
        _credentials: &EndpointCredentials,
    ) -> Vec<(ProfileKind, bool)> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_working_profile_is_enough_and_the_others_do_not_matter() {
        let results = [
            (ProfileKind::AmneziaWg, false),
            (ProfileKind::Hysteria2, true),
            (ProfileKind::VlessReality, false),
        ];
        assert_eq!(require_one(&results), Ok(vec![ProfileKind::Hysteria2]));
    }

    #[test]
    fn all_working_are_all_reported() {
        let results = [
            (ProfileKind::AmneziaWg, true),
            (ProfileKind::Hysteria2, true),
        ];
        assert_eq!(
            require_one(&results),
            Ok(vec![ProfileKind::AmneziaWg, ProfileKind::Hysteria2])
        );
    }

    #[test]
    fn none_working_is_a_failure_that_names_what_was_tried() {
        let results = [
            (ProfileKind::AmneziaWg, false),
            (ProfileKind::VlessReality, false),
        ];
        assert_eq!(
            require_one(&results),
            Err(VerifyFailure::NoneReachable {
                tried: vec![ProfileKind::AmneziaWg, ProfileKind::VlessReality]
            })
        );
    }

    #[test]
    fn nothing_tried_is_not_a_pass() {
        assert_eq!(require_one(&[]), Err(VerifyFailure::NothingTried));
    }
}
