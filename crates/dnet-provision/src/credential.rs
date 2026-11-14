// SPDX-License-Identifier: GPL-3.0-or-later
//! T087 — is this credential one the wizard may use? (PR-01, PR-06)
//!
//! The wizard accepts only a scoped, least-privilege key belonging to a dedicated user it walked the
//! person through creating. A credential that belongs to the account's owner can do everything, including
//! things nobody asked this program to do, so it is **rejected by validation, not merely discouraged**: the
//! job stops before a single resource is created and the credential is never used for anything after the
//! inspection that revealed what it was.
//!
//! The provider tells us what a credential *is* ([`Inspection`]); this module decides what to do about it:
//!
//! 1. A credential that is not valid is refused, and *why* is distinguishable: invalid, expired, revoked.
//! 2. A root credential is refused, however valid.
//! 3. One that lacks a permission the job needs is refused, and the missing permissions are named.
//! 4. One that has permissions the job does **not** need is accepted with a warning the person must
//!    acknowledge: over-privilege is a risk they should choose, not one we should hide.
//!
//! Pure logic: no I/O.

/// Who a credential belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The account or tenancy owner: can do anything.
    Root,
    /// A dedicated user, with whatever permissions it was granted.
    DedicatedUser,
}

/// Whether the provider still honours the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    Valid,
    /// The provider does not recognise it at all.
    Invalid,
    Expired,
    Revoked,
}

/// What the provider says a credential is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub subject: Subject,
    pub standing: Standing,
    /// The permissions it holds, in the provider's own words.
    pub granted: Vec<String>,
}

/// Why a credential is refused. Each is a different thing for the person to do next.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialProblem {
    #[error("the provider does not recognise this credential")]
    Invalid,
    #[error("this credential has expired")]
    Expired,
    #[error("this credential has been revoked")]
    Revoked,
    #[error(
        "this is the account owner's credential; create a dedicated user with only the permissions listed and use that instead"
    )]
    RootCredential,
    #[error("this credential is missing permissions the setup needs: {}", .0.join(", "))]
    MissingPermissions(Vec<String>),
}

/// A credential that may be used. `over_privileged` lists permissions beyond what is needed; when it is
/// not empty the person must acknowledge them before anything is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    pub over_privileged: Vec<String>,
}

impl Validated {
    /// Whether the person has to acknowledge something before provisioning may go on.
    pub fn needs_acknowledgement(&self) -> bool {
        !self.over_privileged.is_empty()
    }
}

/// Decide what to do about `inspection`, given the permissions the job `required`.
pub fn validate(
    inspection: &Inspection,
    required: &[&str],
) -> Result<Validated, CredentialProblem> {
    match inspection.standing {
        Standing::Valid => {}
        Standing::Invalid => return Err(CredentialProblem::Invalid),
        Standing::Expired => return Err(CredentialProblem::Expired),
        Standing::Revoked => return Err(CredentialProblem::Revoked),
    }
    // Before looking at permissions: a root credential holds all of them and must still be refused.
    if inspection.subject == Subject::Root {
        return Err(CredentialProblem::RootCredential);
    }
    let missing: Vec<String> = required
        .iter()
        .filter(|needed| !inspection.granted.iter().any(|g| g == **needed))
        .map(|needed| (*needed).to_owned())
        .collect();
    if !missing.is_empty() {
        return Err(CredentialProblem::MissingPermissions(missing));
    }
    let mut extra: Vec<String> = inspection
        .granted
        .iter()
        .filter(|g| !required.contains(&g.as_str()))
        .cloned()
        .collect();
    extra.sort();
    extra.dedup();
    Ok(Validated {
        over_privileged: extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: &[&str] = &["manage instances", "manage network rules"];

    fn user(granted: &[&str]) -> Inspection {
        Inspection {
            subject: Subject::DedicatedUser,
            standing: Standing::Valid,
            granted: granted.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn exactly_the_needed_permissions_is_accepted_without_a_warning() {
        let ok = validate(&user(REQUIRED), REQUIRED).unwrap();
        assert!(!ok.needs_acknowledgement());
        assert!(ok.over_privileged.is_empty());
    }

    #[test]
    fn a_root_credential_is_refused_however_valid_and_however_much_it_holds() {
        let mut root = user(REQUIRED);
        root.subject = Subject::Root;
        assert_eq!(
            validate(&root, REQUIRED),
            Err(CredentialProblem::RootCredential)
        );
        // Even holding everything the job needs plus more.
        root.granted.push("manage everything".into());
        assert_eq!(
            validate(&root, REQUIRED),
            Err(CredentialProblem::RootCredential)
        );
    }

    #[test]
    fn an_invalid_expired_or_revoked_credential_is_each_told_apart() {
        for (standing, problem) in [
            (Standing::Invalid, CredentialProblem::Invalid),
            (Standing::Expired, CredentialProblem::Expired),
            (Standing::Revoked, CredentialProblem::Revoked),
        ] {
            let mut inspection = user(REQUIRED);
            inspection.standing = standing;
            assert_eq!(validate(&inspection, REQUIRED), Err(problem));
        }
        // A bad standing outranks a root subject: say what is wrong with the credential first.
        let mut both = user(REQUIRED);
        both.subject = Subject::Root;
        both.standing = Standing::Expired;
        assert_eq!(validate(&both, REQUIRED), Err(CredentialProblem::Expired));
    }

    #[test]
    fn missing_permissions_are_named() {
        let error = validate(&user(&["manage instances"]), REQUIRED).unwrap_err();
        assert_eq!(
            error,
            CredentialProblem::MissingPermissions(vec!["manage network rules".into()])
        );
        assert!(error.to_string().contains("manage network rules"));
        assert_eq!(
            validate(&user(&[]), REQUIRED),
            Err(CredentialProblem::MissingPermissions(
                REQUIRED.iter().map(|s| (*s).to_owned()).collect()
            ))
        );
    }

    #[test]
    fn extra_permissions_are_accepted_but_must_be_acknowledged_and_are_listed() {
        let granted = [
            "manage instances",
            "manage network rules",
            "read billing",
            "delete buckets",
            "read billing",
        ];
        let ok = validate(&user(&granted), REQUIRED).unwrap();
        assert!(ok.needs_acknowledgement());
        assert_eq!(ok.over_privileged, ["delete buckets", "read billing"]);
    }

    #[test]
    fn nothing_here_can_carry_a_credential() {
        // The inspection is the provider's description, not the credential: it has no secret field.
        let shown = format!("{:?}", user(REQUIRED));
        assert!(shown.contains("DedicatedUser"));
    }
}
