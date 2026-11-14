// SPDX-License-Identifier: GPL-3.0-or-later
//! T161 step 2 — the guard in the firewall engine's own terms (ADR-0006 §5a, conditions 2 to 4).
//!
//! `dnet_core::guard` says what the guard is: ordered rules, a few narrow permits above a block of everything. This
//! module says how the Windows Filtering Platform spells each of them, and nothing else. It is **pure** (no Windows
//! call), so the translation is tested on every machine and before anything is applied to one; applying it is the
//! Windows-only [`engine`] below, and it takes the output of [`to_wfp`], never anything of its own.
//!
//! Two things are held here and nowhere else:
//!
//! - **The translation is reversible.** [`from_wfp`] turns what is read back from the firewall into the model's own
//!   [`Filter`], so `dnet_core::guard::verify` can compare the installed rules with the plan in both directions. The
//!   round trip is tested for every filter the model builds.
//! - **The names the firewall holds are fixed.** One provider and one sublayer, with keys written down here, so that
//!   the removal paths (uninstall, `guard-release`, safe mode) and the undo record all point at the same objects, and
//!   cannot be made to point at anyone else's: [`is_ours`] is what a journal record is checked against.

use dnet_core::guard::{Action, Condition, Direction, Family, Filter};
use dnet_core::ids::InterfaceId;
use dnet_core::rule::IpCidr;

/// A GUID, in the layout the firewall engine uses, without borrowing the operating system's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lower case.
    pub fn to_text(self) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }

    /// Read the text form back. `None` for anything that is not exactly that form.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
            return None;
        }
        let hex: String = text.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let part = |from: usize, to: usize| u64::from_str_radix(&hex[from..to], 16).ok();
        let mut data4 = [0u8; 8];
        for (i, byte) in data4.iter_mut().enumerate() {
            *byte = u8::try_from(part(16 + 2 * i, 18 + 2 * i)?).ok()?;
        }
        Some(Self {
            data1: u32::try_from(part(0, 8)?).ok()?,
            data2: u16::try_from(part(8, 12)?).ok()?,
            data3: u16::try_from(part(12, 16)?).ok()?,
            data4,
        })
    }
}

/// The provider every guard object belongs to. Fixed, so a removal and an undo record name the same thing.
pub const PROVIDER_KEY: Guid = Guid {
    data1: 0x6d6e_6574,
    data2: 0x1f5a,
    data3: 0x4c1e,
    data4: [0x9a, 0x37, 0xd1, 0x7e, 0x2b, 0x40, 0xc0, 0x01],
};

/// The sublayer all guard filters sit in. Fixed, for the same reason.
pub const SUBLAYER_KEY: Guid = Guid {
    data1: 0x6d6e_6574,
    data2: 0x1f5a,
    data3: 0x4c1e,
    data4: [0x9a, 0x37, 0xd1, 0x7e, 0x2b, 0x40, 0xc0, 0x02],
};

/// The service the provider names: persistent filters of a provider that names a service are applied at start only if
/// that service is auto-start, so a disabled or uninstalled service lifts the block (the lockout safety).
pub const SERVICE_NAME: &str = "DNetEngine";

/// What the provider and the sublayer are called in the firewall's own listing.
pub const PROVIDER_NAME: &str = "DNet Engine guard";
pub const SUBLAYER_NAME: &str = "DNet Engine guard rules";

/// Whether `key` is the provider this module made. An undo record names a provider to delete, and the journal is
/// replayed by the system's own account, so a record that names any other is refused as tampering, never obeyed.
pub fn is_ours(key: &Guid) -> bool {
    *key == PROVIDER_KEY
}

/// Where in the firewall engine a rule sits: the decision about a new outbound connection, or about an inbound one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    AleAuthConnectV4,
    AleAuthConnectV6,
    AleAuthRecvAcceptV4,
    AleAuthRecvAcceptV6,
}

impl Layer {
    pub fn of(family: Family, direction: Direction) -> Self {
        match (family, direction) {
            (Family::V4, Direction::Outbound) => Layer::AleAuthConnectV4,
            (Family::V6, Direction::Outbound) => Layer::AleAuthConnectV6,
            (Family::V4, Direction::Inbound) => Layer::AleAuthRecvAcceptV4,
            (Family::V6, Direction::Inbound) => Layer::AleAuthRecvAcceptV6,
        }
    }

    pub fn family(self) -> Family {
        match self {
            Layer::AleAuthConnectV4 | Layer::AleAuthRecvAcceptV4 => Family::V4,
            Layer::AleAuthConnectV6 | Layer::AleAuthRecvAcceptV6 => Family::V6,
        }
    }

    pub fn direction(self) -> Direction {
        match self {
            Layer::AleAuthConnectV4 | Layer::AleAuthConnectV6 => Direction::Outbound,
            Layer::AleAuthRecvAcceptV4 | Layer::AleAuthRecvAcceptV6 => Direction::Inbound,
        }
    }
}

/// One match of a firewall condition, with its value, the way the engine takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// The adapter, by its LUID (`FWPM_CONDITION_IP_LOCAL_INTERFACE`).
    LocalInterface(u64),
    /// The program, by its full path (`FWPM_CONDITION_ALE_APP_ID`, which the engine takes as its own blob).
    AppId(String),
    /// The account, by its security identifier (`FWPM_CONDITION_ALE_USER_ID`, a security descriptor that names it).
    UserId(String),
    /// The loopback flag of the packet (`FWPM_CONDITION_FLAGS`).
    Loopback,
    /// The protocol number (`FWPM_CONDITION_IP_PROTOCOL`): 6 TCP, 17 UDP, 58 ICMPv6.
    Protocol(u8),
    LocalPort(u16),
    RemotePort(u16),
    /// A remote IPv4 range (`FWPM_CONDITION_IP_REMOTE_ADDRESS` with an address and a mask).
    RemoteV4 {
        addr: [u8; 4],
        prefix: u8,
    },
    /// A remote IPv6 range (the same condition with an address and a prefix length).
    RemoteV6 {
        addr: [u8; 16],
        prefix: u8,
    },
    /// The ICMP type (`FWPM_CONDITION_ICMP_TYPE`).
    IcmpType(u8),
}

/// One rule as the firewall engine will hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilter {
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    /// 0 to 15: the engine's own weight range, the same as the model's.
    pub weight: u8,
    pub matches: Vec<Match>,
}

/// Why a rule could not be translated, or read back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslateError {
    #[error("a weight above 15 is not one the firewall engine has: {0}")]
    WeightOutOfRange(u8),
    #[error("the rule is for the other family than its range: {0}")]
    FamilyMismatch(String),
    #[error("a firewall rule that does not read as one of the guard's own: {0}")]
    NotOurs(String),
}

/// The highest weight the engine's one-byte form allows.
pub const MAX_WEIGHT: u8 = 15;

/// The protocol number for ICMPv6.
const ICMPV6: u8 = 58;
const TCP: u8 = 6;
const UDP: u8 = 17;

/// Translate one rule of the model.
pub fn to_wfp(filter: &Filter) -> Result<WfpFilter, TranslateError> {
    if filter.weight > MAX_WEIGHT {
        return Err(TranslateError::WeightOutOfRange(filter.weight));
    }
    let mut matches = Vec::with_capacity(filter.conditions.len() + 1);
    for condition in &filter.conditions {
        match condition {
            Condition::Interface(id) => matches.push(Match::LocalInterface(id.luid())),
            Condition::Program(path) => matches.push(Match::AppId(path.clone())),
            Condition::User(sid) => matches.push(Match::UserId(sid.clone())),
            Condition::Loopback => matches.push(Match::Loopback),
            Condition::Udp => matches.push(Match::Protocol(UDP)),
            Condition::Tcp => matches.push(Match::Protocol(TCP)),
            Condition::LocalPort(port) => matches.push(Match::LocalPort(*port)),
            Condition::RemotePort(port) => matches.push(Match::RemotePort(*port)),
            Condition::Remote(range) => matches.push(remote(range, filter)?),
            // An ICMPv6 type means nothing without the protocol, so the engine is told both.
            Condition::IcmpV6(kind) => {
                matches.push(Match::Protocol(ICMPV6));
                matches.push(Match::IcmpType(*kind));
            }
        }
    }
    Ok(WfpFilter {
        name: filter.name.clone(),
        layer: Layer::of(filter.family, filter.direction),
        action: filter.action,
        weight: filter.weight,
        matches,
    })
}

fn remote(range: &IpCidr, filter: &Filter) -> Result<Match, TranslateError> {
    match (range.addr(), filter.family) {
        (std::net::IpAddr::V4(a), Family::V4) => Ok(Match::RemoteV4 {
            addr: a.octets(),
            prefix: range.prefix_len(),
        }),
        (std::net::IpAddr::V6(a), Family::V6) => Ok(Match::RemoteV6 {
            addr: a.octets(),
            prefix: range.prefix_len(),
        }),
        _ => Err(TranslateError::FamilyMismatch(filter.name.clone())),
    }
}

/// Read one rule back into the model's own terms: the inverse of [`to_wfp`].
pub fn from_wfp(filter: &WfpFilter) -> Result<Filter, TranslateError> {
    let not_ours = || TranslateError::NotOurs(filter.name.clone());
    if filter.weight > MAX_WEIGHT {
        return Err(TranslateError::WeightOutOfRange(filter.weight));
    }
    let mut conditions = Vec::with_capacity(filter.matches.len());
    let mut iter = filter.matches.iter().peekable();
    while let Some(m) = iter.next() {
        conditions.push(match m {
            Match::LocalInterface(luid) => Condition::Interface(InterfaceId::new(*luid)),
            Match::AppId(path) => Condition::Program(path.clone()),
            Match::UserId(sid) => Condition::User(sid.clone()),
            Match::Loopback => Condition::Loopback,
            Match::Protocol(UDP) => Condition::Udp,
            Match::Protocol(TCP) => Condition::Tcp,
            // ICMPv6 is a protocol and a type together, and only together.
            Match::Protocol(ICMPV6) => match iter.next() {
                Some(Match::IcmpType(kind)) => Condition::IcmpV6(*kind),
                _ => return Err(not_ours()),
            },
            Match::Protocol(_) | Match::IcmpType(_) => return Err(not_ours()),
            Match::LocalPort(port) => Condition::LocalPort(*port),
            Match::RemotePort(port) => Condition::RemotePort(*port),
            Match::RemoteV4 { addr, prefix } => {
                if filter.layer.family() != Family::V4 {
                    return Err(not_ours());
                }
                Condition::Remote(
                    IpCidr::parse(&format!("{}/{prefix}", std::net::Ipv4Addr::from(*addr)))
                        .map_err(|_| not_ours())?,
                )
            }
            Match::RemoteV6 { addr, prefix } => {
                if filter.layer.family() != Family::V6 {
                    return Err(not_ours());
                }
                Condition::Remote(
                    IpCidr::parse(&format!("{}/{prefix}", std::net::Ipv6Addr::from(*addr)))
                        .map_err(|_| not_ours())?,
                )
            }
        });
    }
    Ok(Filter {
        name: filter.name.clone(),
        family: filter.layer.family(),
        direction: filter.layer.direction(),
        action: filter.action,
        conditions,
        weight: filter.weight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::guard::{local_ranges, Guard, GuardPlan};

    fn plan() -> GuardPlan {
        GuardPlan {
            tunnel: InterfaceId::new(0x0006_0000_0000_0007),
            core_program: r"C:\Program Files\DNet Engine\primary-core.exe".into(),
            core_user: "S-1-5-18".into(),
            service_program: r"C:\Program Files\DNet Engine\dnetd.exe".into(),
            service_user: "S-1-5-18".into(),
            control_port: 34_567,
            local_ranges: local_ranges(),
        }
    }

    fn built() -> Vec<Filter> {
        Guard::build(&plan()).unwrap().filters().to_vec()
    }

    #[test]
    fn every_rule_the_model_builds_translates_and_reads_back_as_itself() {
        let filters = built();
        assert_eq!(filters.len(), 48, "the model's list is the one under test");
        for filter in &filters {
            let wfp = to_wfp(filter).unwrap_or_else(|e| panic!("{}: {e}", filter.name));
            assert_eq!(&from_wfp(&wfp).unwrap(), filter, "{}", filter.name);
        }
    }

    #[test]
    fn what_is_read_back_passes_the_models_own_check_against_the_plan() {
        let installed: Vec<Filter> = built()
            .iter()
            .map(|f| from_wfp(&to_wfp(f).unwrap()).unwrap())
            .collect();
        assert_eq!(
            dnet_core::guard::verify(&plan(), &installed),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_rule_missing_from_the_firewall_or_added_to_it_is_found_by_the_check() {
        let mut installed: Vec<Filter> = built()
            .iter()
            .map(|f| from_wfp(&to_wfp(f).unwrap()).unwrap())
            .collect();
        let removed = installed.pop().unwrap();
        assert!(
            !dnet_core::guard::verify(&plan(), &installed).is_empty(),
            "{}",
            removed.name
        );
        installed.push(removed.clone());
        let mut extra = removed;
        extra.name = "somebody else's permit".into();
        extra.conditions = vec![Condition::RemotePort(443)];
        extra.action = Action::Permit;
        extra.weight = 10;
        installed.push(extra);
        assert!(!dnet_core::guard::verify(&plan(), &installed).is_empty());
    }

    #[test]
    fn the_layer_is_the_family_and_the_direction_and_nothing_else() {
        for (family, direction, layer) in [
            (Family::V4, Direction::Outbound, Layer::AleAuthConnectV4),
            (Family::V6, Direction::Outbound, Layer::AleAuthConnectV6),
            (Family::V4, Direction::Inbound, Layer::AleAuthRecvAcceptV4),
            (Family::V6, Direction::Inbound, Layer::AleAuthRecvAcceptV6),
        ] {
            assert_eq!(Layer::of(family, direction), layer);
            assert_eq!((layer.family(), layer.direction()), (family, direction));
        }
    }

    #[test]
    fn an_icmpv6_type_is_sent_with_its_protocol_and_only_comes_back_with_it() {
        let filter = Filter {
            name: "ns".into(),
            family: Family::V6,
            direction: Direction::Outbound,
            action: Action::Permit,
            conditions: vec![Condition::IcmpV6(135)],
            weight: 10,
        };
        let wfp = to_wfp(&filter).unwrap();
        assert_eq!(wfp.matches, [Match::Protocol(58), Match::IcmpType(135)]);
        // A type with no protocol, or a protocol 58 with no type, is not one of ours.
        let mut lone_type = wfp.clone();
        lone_type.matches = vec![Match::IcmpType(135)];
        assert!(from_wfp(&lone_type).is_err());
        let mut lone_protocol = wfp;
        lone_protocol.matches = vec![Match::Protocol(58)];
        assert!(from_wfp(&lone_protocol).is_err());
    }

    #[test]
    fn a_protocol_the_guard_never_uses_is_not_one_of_its_own() {
        let mut wfp = to_wfp(&built()[4]).unwrap();
        wfp.matches = vec![Match::Protocol(1)];
        assert_eq!(
            from_wfp(&wfp),
            Err(TranslateError::NotOurs(wfp.name.clone()))
        );
    }

    #[test]
    fn a_range_of_the_wrong_family_for_its_layer_is_refused_both_ways() {
        let mut filter = built()
            .into_iter()
            .find(|f| {
                f.name.contains("10.0.0.0/8")
                    || f.conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Remote(_)))
            })
            .unwrap();
        filter.family = Family::V6;
        assert!(matches!(
            to_wfp(&filter),
            Err(TranslateError::FamilyMismatch(_))
        ));
        let wfp = WfpFilter {
            name: "v6 layer with a v4 range".into(),
            layer: Layer::AleAuthConnectV6,
            action: Action::Permit,
            weight: 10,
            matches: vec![Match::RemoteV4 {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }],
        };
        assert!(from_wfp(&wfp).is_err());
    }

    #[test]
    fn a_weight_the_engine_does_not_have_is_refused_both_ways() {
        let mut filter = built().remove(0);
        filter.weight = 16;
        assert_eq!(to_wfp(&filter), Err(TranslateError::WeightOutOfRange(16)));
        let mut wfp = to_wfp(&built()[0]).unwrap();
        wfp.weight = 200;
        assert_eq!(from_wfp(&wfp), Err(TranslateError::WeightOutOfRange(200)));
        for weight in [0u8, 1, 10, 14, 15] {
            let mut ok = built().remove(0);
            ok.weight = weight;
            assert_eq!(to_wfp(&ok).unwrap().weight, weight);
        }
    }

    #[test]
    fn the_model_is_blocked_by_a_block_at_the_lowest_weight_for_every_layer() {
        let wfp: Vec<WfpFilter> = built().iter().map(|f| to_wfp(f).unwrap()).collect();
        for layer in [
            Layer::AleAuthConnectV4,
            Layer::AleAuthConnectV6,
            Layer::AleAuthRecvAcceptV4,
            Layer::AleAuthRecvAcceptV6,
        ] {
            let block = wfp
                .iter()
                .find(|f| f.layer == layer && f.action == Action::Block && f.matches.is_empty())
                .unwrap_or_else(|| panic!("no block of everything at {layer:?}"));
            assert_eq!(block.weight, 0, "{layer:?}");
            // And nothing is lighter than it.
            assert!(wfp
                .iter()
                .filter(|f| f.layer == layer)
                .all(|f| f.weight >= block.weight));
        }
    }

    #[test]
    fn the_fixed_keys_are_distinct_and_read_back_from_their_text() {
        assert_ne!(PROVIDER_KEY, SUBLAYER_KEY);
        for key in [PROVIDER_KEY, SUBLAYER_KEY] {
            assert_eq!(Guid::parse(&key.to_text()), Some(key));
        }
        assert_eq!(
            PROVIDER_KEY.to_text(),
            "6d6e6574-1f5a-4c1e-9a37-d17e2b40c001"
        );
        assert!(is_ours(&PROVIDER_KEY));
        assert!(!is_ours(&SUBLAYER_KEY));
    }

    #[test]
    fn text_that_is_not_exactly_a_guid_is_not_one() {
        for bad in [
            "",
            "6d6e6574-1f5a-4c1e-9a37-d17e2b40c00",
            "6d6e6574-1f5a-4c1e-9a37-d17e2b40c0011",
            "6d6e6574_1f5a_4c1e_9a37_d17e2b40c001",
            "6d6e6574-1f5a-4c1e-9a37-d17e2b40c00g",
            "{6d6e6574-1f5a-4c1e-9a37-d17e2b40c001}",
            "6d6e6574-1f5a-4c1e-9a37-d17e2b40c001\n",
        ] {
            assert_eq!(Guid::parse(bad), None, "{bad:?}");
        }
        // Upper case is the same key.
        assert_eq!(
            Guid::parse("6D6E6574-1F5A-4C1E-9A37-D17E2B40C001"),
            Some(PROVIDER_KEY)
        );
    }
}
