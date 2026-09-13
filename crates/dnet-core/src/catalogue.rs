//! The bundled profile catalogue: the profile ids and kinds this build defines.
//!
//! Profile ids are stable across updates (data-model §2). The profile feed may only propose
//! parameters for an id listed here, with the kind listed here (ADR-0002 §5.3). A new id needs
//! generator code, so it arrives in an application release, never in a feed.

use crate::profile::ProfileKind;

/// One bundled profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogueEntry {
    pub id: &'static str,
    pub kind: ProfileKind,
}

/// Every profile this build defines, in seeding order.
pub const BUNDLED_PROFILES: &[CatalogueEntry] = &[
    CatalogueEntry {
        id: "awg-default",
        kind: ProfileKind::AmneziaWg,
    },
    CatalogueEntry {
        id: "hy2-default",
        kind: ProfileKind::Hysteria2,
    },
    CatalogueEntry {
        id: "reality-default",
        kind: ProfileKind::VlessReality,
    },
];

/// The kind of a bundled profile id, or `None` if this build does not define it.
pub fn bundled_kind(id: &str) -> Option<ProfileKind> {
    BUNDLED_PROFILES
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Carrier;

    #[test]
    fn ids_are_unique() {
        for (i, a) in BUNDLED_PROFILES.iter().enumerate() {
            for b in &BUNDLED_PROFILES[i + 1..] {
                assert_ne!(a.id, b.id);
            }
        }
    }

    /// The catalogue must itself be a valid profile set: one TCP profile at least (FR-002).
    #[test]
    fn the_catalogue_includes_a_tcp_fallback() {
        assert!(BUNDLED_PROFILES
            .iter()
            .any(|entry| entry.kind.carrier() == Carrier::Tcp));
    }

    #[test]
    fn lookup_is_by_exact_id() {
        assert_eq!(bundled_kind("hy2-default"), Some(ProfileKind::Hysteria2));
        assert_eq!(bundled_kind("HY2-default"), None);
        assert_eq!(bundled_kind("hy2"), None);
    }
}
