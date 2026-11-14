// SPDX-License-Identifier: GPL-3.0-or-later
//! T165 — what a network connection costs its owner: is it metered, is it near a data limit, is it roaming.
//!
//! Some links are paid for by the byte (a mobile hotspot on a capped plan, a hotel's metered Wi-Fi, roaming abroad).
//! A program that keeps a second connection warm or races three methods every few minutes spends the owner's money
//! without being asked. Windows already knows; this reads what it says, so that the policy that decides how much
//! to spend (T167) has a fact to decide on instead of a guess.
//!
//! - **Read-only and local.** It queries the machine's own state through the system's connectivity hint. Nothing is
//!   sent anywhere and no privilege is needed.
//! - **"Unknown" is a value, and it is not "free".** The system often does not know (many Wi-Fi networks, a wired link
//!   with no policy). That is reported as [`LinkCost::Unknown`], never rounded to unrestricted, and never to metered:
//!   a policy must be able to tell "known to be free" from "nobody knows".
//! - **Any failure is "unknown".** No such interface, an older Windows without the call, a refusal: the answer is
//!   [`LinkFacts::unknown`]. A cost that could not be read must never stop a connection being watched.

/// What the system says a link costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkCost {
    /// The system does not know, or has no policy for this link.
    #[default]
    Unknown,
    /// No limit and no charge by the byte.
    Unrestricted,
    /// A fixed allowance of data, after which something changes (a speed drop, a charge).
    Fixed,
    /// Paid for by use.
    Variable,
}

impl LinkCost {
    /// The system's code for the cost, as `NL_NETWORK_CONNECTIVITY_COST_HINT` writes it. A code this does not know is
    /// `Unknown`: a newer Windows adding a value must not be read as a free link.
    pub fn from_code(code: i32) -> Self {
        match code {
            1 => Self::Unrestricted,
            2 => Self::Fixed,
            3 => Self::Variable,
            _ => Self::Unknown,
        }
    }
}

/// Everything known about what a link costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkFacts {
    pub cost: LinkCost,
    /// Near the allowance, as the system judges it.
    pub approaching_limit: bool,
    /// Past the allowance.
    pub over_limit: bool,
    /// Away from the home network, where data is dearer.
    pub roaming: bool,
}

impl LinkFacts {
    /// Nothing is known. What every failure reports.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Whether spending on this link should be careful: it is paid for by the byte or by an allowance, it is near or
    /// over that allowance, or it is roaming. **Unknown is not metered**: a link the system has no policy for is
    /// treated as an ordinary one, because treating every unknown link as metered would turn the product's
    /// protections off on most Wi-Fi networks. The facts are kept apart so a policy can choose otherwise.
    pub fn is_metered(&self) -> bool {
        matches!(self.cost, LinkCost::Fixed | LinkCost::Variable)
            || self.approaching_limit
            || self.over_limit
            || self.roaming
    }

    /// The facts as the system reports them: its code for the cost and its three flags.
    pub fn from_system(
        cost_code: i32,
        approaching_limit: bool,
        over_limit: bool,
        roaming: bool,
    ) -> Self {
        Self {
            cost: LinkCost::from_code(cost_code),
            approaching_limit,
            over_limit,
            roaming,
        }
    }
}

/// What the system says about the link with this interface index. Any failure is [`LinkFacts::unknown`].
#[cfg(windows)]
pub fn link_facts_for_index(interface_index: u32) -> LinkFacts {
    use windows::Win32::NetworkManagement::IpHelper::GetNetworkConnectivityHintForInterface;
    use windows::Win32::Networking::WinSock::NL_NETWORK_CONNECTIVITY_HINT;

    if interface_index == 0 {
        return LinkFacts::unknown();
    }
    let mut hint = NL_NETWORK_CONNECTIVITY_HINT::default();
    // SAFETY: a valid place for the system to write one hint; no other pointer is passed.
    let status = unsafe { GetNetworkConnectivityHintForInterface(interface_index, &mut hint) };
    if status.is_err() {
        return LinkFacts::unknown();
    }
    LinkFacts::from_system(
        hint.ConnectivityCost.0,
        hint.ApproachingDataLimit.as_bool(),
        hint.OverDataLimit.as_bool(),
        hint.Roaming.as_bool(),
    )
}

/// What the system says about the link with this LUID (the identity the rest of `dnet-netstate` uses).
#[cfg(windows)]
pub fn link_facts(luid: u64) -> LinkFacts {
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let luid = NET_LUID_LH { Value: luid };
    let mut index = 0u32;
    // SAFETY: both pointers are valid for the call.
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if status.is_err() {
        return LinkFacts::unknown();
    }
    link_facts_for_index(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_systems_codes_are_read_as_what_they_mean_and_a_new_one_is_unknown() {
        assert_eq!(LinkCost::from_code(0), LinkCost::Unknown);
        assert_eq!(LinkCost::from_code(1), LinkCost::Unrestricted);
        assert_eq!(LinkCost::from_code(2), LinkCost::Fixed);
        assert_eq!(LinkCost::from_code(3), LinkCost::Variable);
        // A value a newer Windows adds must never read as a free link, or as a metered one.
        for other in [-1, 4, 5, 99, i32::MAX, i32::MIN] {
            assert_eq!(LinkCost::from_code(other), LinkCost::Unknown, "{other}");
        }
    }

    /// The codes above are the system's. Compared with its own constants, so a mistake in either shows here.
    #[cfg(windows)]
    #[test]
    fn the_codes_match_the_systems_own_constants() {
        use windows::Win32::Networking::WinSock::{
            NetworkConnectivityCostHintFixed, NetworkConnectivityCostHintUnknown,
            NetworkConnectivityCostHintUnrestricted, NetworkConnectivityCostHintVariable,
        };
        assert_eq!(
            LinkCost::from_code(NetworkConnectivityCostHintUnknown.0),
            LinkCost::Unknown
        );
        assert_eq!(
            LinkCost::from_code(NetworkConnectivityCostHintUnrestricted.0),
            LinkCost::Unrestricted
        );
        assert_eq!(
            LinkCost::from_code(NetworkConnectivityCostHintFixed.0),
            LinkCost::Fixed
        );
        assert_eq!(
            LinkCost::from_code(NetworkConnectivityCostHintVariable.0),
            LinkCost::Variable
        );
    }

    #[test]
    fn metered_means_paid_by_use_or_allowance_near_or_over_it_or_roaming_and_never_unknown() {
        let facts = |cost, approaching, over, roaming| {
            LinkFacts::from_system(cost, approaching, over, roaming)
        };
        // Not metered: nothing known, or known to be free.
        assert!(!LinkFacts::unknown().is_metered());
        assert!(!facts(0, false, false, false).is_metered());
        assert!(!facts(1, false, false, false).is_metered());
        // Metered on cost alone.
        assert!(facts(2, false, false, false).is_metered());
        assert!(facts(3, false, false, false).is_metered());
        // Any one flag is enough, whatever the cost says.
        for cost in [0, 1] {
            assert!(
                facts(cost, true, false, false).is_metered(),
                "approaching, cost {cost}"
            );
            assert!(
                facts(cost, false, true, false).is_metered(),
                "over, cost {cost}"
            );
            assert!(
                facts(cost, false, false, true).is_metered(),
                "roaming, cost {cost}"
            );
        }
    }

    #[test]
    fn the_facts_are_kept_apart_so_unknown_can_be_told_from_free() {
        let unknown = LinkFacts::from_system(0, false, false, false);
        let free = LinkFacts::from_system(1, false, false, false);
        assert_ne!(unknown, free);
        assert_eq!(unknown, LinkFacts::unknown());
    }

    #[cfg(windows)]
    #[test]
    fn an_interface_that_does_not_exist_is_unknown_not_an_error() {
        assert_eq!(link_facts_for_index(0), LinkFacts::unknown());
        assert_eq!(link_facts_for_index(u32::MAX), LinkFacts::unknown());
        assert_eq!(link_facts(0), LinkFacts::unknown());
    }
}
