//! T161 — what the guard lets through, as data (ADR-0006 P3 and section 5a; `docs/research/2026-10-31-solutions.md` section 4).
//!
//! The guard is the operating system's own half of the kill switch: a set of ordered rules in which a few narrow
//! **permits** sit above a **block of everything**. A leak is therefore a missing block or a permit that is too wide,
//! and both can be found by looking at the list. This module builds the list from a plan and checks it, with no
//! operating system involved, so the check is run on every machine and before anything is applied to a real one
//! (Principle IV). Applying it (the Windows firewall engine, persistent filters owned by the service's provider) is a
//! separate, Windows-only piece that takes a [`Guard`] as its input.
//!
//! **Weights.** Higher is looked at first. Permits take weights above [`BLOCK_WEIGHT`]; the one block per direction and
//! family takes it; the block of loopback traffic to the core's control port sits between the two, so that only the
//! service is let through to it (solutions section 3.1).
//!
//! **Two checks, and why there are two.** [`leaks`] looks for rules that are wrong in themselves: no block of
//! everything, a permit of everything, a bare protocol, a program without its account, a range that is not local. It
//! cannot know what was asked for, so a well-formed permit nobody asked for (any outbound port 443) passes it.
//! [`verify`] adds that: it compares a list with what the plan produces, in both directions, and is the check to run on
//! what is read back from the firewall. A [`Guard`] can be made only from a plan that passes both.
//!
//! **Residual, not hidden.** Two kinds of permit are narrow by protocol, port and message type but not by address: the
//! IPv4 address request (a lease may be renewed with a server whose address is public, on some networks) and IPv6
//! neighbour discovery (an advertisement may go to a global address on the link; the messages are only valid on the
//! local link). Scoping them would break addressing on some networks; the lab checks measure them.
//!
//! Pure logic: no I/O.

use std::fmt;
use std::sync::LazyLock;

use crate::builtin_rules::LOCAL_BYPASS_CIDRS;
use crate::ids::InterfaceId;
use crate::rule::IpCidr;

/// The weight of the block-everything rules, the lowest in the set.
pub const BLOCK_WEIGHT: u8 = 0;
/// The block of loopback traffic to the control port: above the loopback permit, below the service's own permit.
const CONTROL_BLOCK_WEIGHT: u8 = 14;
/// The service's permit to the control port: the highest of all.
const CONTROL_PERMIT_WEIGHT: u8 = 15;
/// The ordinary narrow permits.
const PERMIT_WEIGHT: u8 = 10;

/// Which way the traffic goes, as the firewall sees a connection (new outbound connections, new inbound ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// The address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

/// What a rule does with what it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

/// One thing a rule matches on. A rule matches when every one of its conditions does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Traffic on this network adapter (the tunnel's).
    Interface(InterfaceId),
    /// Traffic of this program, by its full path.
    Program(String),
    /// Traffic of this account, by its security identifier.
    User(String),
    /// Traffic to or from this computer itself.
    Loopback,
    Udp,
    Tcp,
    LocalPort(u16),
    RemotePort(u16),
    /// Traffic to or from this address range.
    Remote(IpCidr),
    /// An IPv6 control message of this type (neighbour discovery: 133 to 137).
    IcmpV6(u8),
}

impl Condition {
    /// Whether this condition narrows a permit by naming something. A bare protocol does not.
    fn names_something(&self) -> bool {
        !matches!(self, Condition::Udp | Condition::Tcp)
    }
}

/// One rule of the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// A stable name, shown in the dry-run list and in the firewall's own listing.
    pub name: String,
    pub family: Family,
    pub direction: Direction,
    pub action: Action,
    pub conditions: Vec<Condition>,
    pub weight: u8,
}

/// What the guard is built from. Everything here is something the service already knows.
#[derive(Debug, Clone)]
pub struct GuardPlan {
    /// The tunnel's adapter: everything on it is let through.
    pub tunnel: InterfaceId,
    /// The transport program that carries the encrypted traffic, by full path, and the account it runs as. Both, so
    /// that another program cannot borrow the permit by sharing a name or a folder.
    pub core_program: String,
    pub core_user: String,
    /// The service, by full path and account: the only program let through to the core's control port.
    pub service_program: String,
    pub service_user: String,
    /// The core's control port on this computer (solutions section 3.1).
    pub control_port: u16,
    /// The local ranges that stay reachable. Each must lie inside the built-in bypass list ([`local_ranges`]).
    pub local_ranges: Vec<IpCidr>,
}

/// Why a plan cannot be turned into a guard.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    #[error("the {0} is not a full path to a program on a local drive")]
    NotAFullPath(&'static str),
    #[error("the service and the transport program are the same program")]
    SameProgram,
    #[error("the account that runs the {0} is not named")]
    NoAccount(&'static str),
    #[error("the account for the {0} ({1:?}) is not one specific security identifier")]
    NotAnAccount(&'static str, String),
    #[error("the tunnel's adapter is not named")]
    NoTunnel,
    #[error("the control port is not a port")]
    NoPort,
    #[error("{0} is not a local range, so the guard will not let it through")]
    RangeNotLocal(String),
    #[error("the guard built from this plan would leak: {}", .0.join("; "))]
    WouldLeak(Vec<String>),
}

static LOCAL: LazyLock<Vec<IpCidr>> = LazyLock::new(|| {
    LOCAL_BYPASS_CIDRS
        .iter()
        .map(|c| IpCidr::parse(c).expect("built-in CIDR constants are valid"))
        .collect()
});

/// The built-in local ranges ([`LOCAL_BYPASS_CIDRS`]) as ranges. The bypass rules use the same list, so the guard and the
/// rules cannot disagree about what "local" means.
pub fn local_ranges() -> Vec<IpCidr> {
    LOCAL.clone()
}

/// Whether the whole of `range` lies inside one of the built-in local ranges. A range that is wider than a local one, or
/// elsewhere, is not: a default route would otherwise pass as "a range that names something".
fn is_local(range: &IpCidr) -> bool {
    LOCAL
        .iter()
        .any(|local| range.prefix_len() >= local.prefix_len() && local.overlaps(range))
}

/// The two destinations a request for an address goes to, and only on that request's own ports: the broadcast address
/// (DHCP for v4, client port 68 to server port 67) and the all-DHCP-agents group (v6, 546 to 547). They lie outside the
/// local ranges, so the lint above would call them a leak; nothing else is excused.
fn is_address_request_to(filter: &Filter, range: &IpCidr) -> bool {
    let ports = |client: u16, server: u16| {
        filter.conditions.contains(&Condition::Udp)
            && filter.conditions.contains(&Condition::LocalPort(client))
            && filter.conditions.contains(&Condition::RemotePort(server))
    };
    match range.to_string().as_str() {
        "255.255.255.255/32" => filter.family == Family::V4 && ports(68, 67),
        "ff02::1:2/128" => filter.family == Family::V6 && ports(546, 547),
        _ => false,
    }
}

/// A full path to a program on a local drive: `X:\dir\file`. Refused: a network share or a device path (the carrier's
/// permit must not follow a file somebody else controls), a wildcard, a forward slash, a stream (`:`), a control
/// character, an empty segment (a doubled or trailing backslash), and a segment ending in a dot or a space (`.`, `..`,
/// and what Windows quietly strips).
fn full_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return false;
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '*' | '?' | '<' | '>' | '|' | '"' | '/'))
    {
        return false;
    }
    // The first three bytes are ASCII, so this is a character boundary.
    let rest = &path[3..];
    !rest.contains(':')
        && rest
            .split('\\')
            .all(|segment| !segment.is_empty() && !segment.ends_with(['.', ' ']))
}

/// One account a program can really run as: the three service accounts (`S-1-5-18`, `-19`, `-20`), a per-service
/// identity (`S-1-5-80-...`), or an ordinary user of a domain or machine (`S-1-5-21-a-b-c-RID` with RID 1000 or
/// more). An allow-list on purpose: the firewall compares an account with the groups in a process's token, so any
/// group (Administrators, Interactive, an integrity level, Domain Users) would match almost everything. It also
/// refuses a name and anything that is not digits.
fn specific_account(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-5-") else {
        return false;
    };
    let digits = |p: &&str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    let parts: Vec<&str> = rest.split('-').collect();
    if !parts.iter().all(digits) {
        return false;
    }
    match parts.as_slice() {
        ["18" | "19" | "20"] => true,
        ["80", sub @ ..] => !sub.is_empty(),
        ["21", _, _, _, rid] => rid.parse::<u32>().is_ok_and(|r| r >= 1000),
        _ => false,
    }
}

const BOTH_DIRECTIONS: [Direction; 2] = [Direction::Outbound, Direction::Inbound];
const BOTH_FAMILIES: [Family; 2] = [Family::V4, Family::V6];

fn permit(
    name: impl Into<String>,
    family: Family,
    direction: Direction,
    conditions: Vec<Condition>,
) -> Filter {
    Filter {
        name: name.into(),
        family,
        direction,
        action: Action::Permit,
        conditions,
        weight: PERMIT_WEIGHT,
    }
}

fn family_of(cidr: &IpCidr) -> Family {
    if cidr.addr().is_ipv4() {
        Family::V4
    } else {
        Family::V6
    }
}

fn dir_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Outbound => "out",
        Direction::Inbound => "in",
    }
}

fn fam_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "v4",
        Family::V6 => "v6",
    }
}

/// What a plan must satisfy before anything is built from it.
fn check_plan(plan: &GuardPlan) -> Result<(), GuardError> {
    if !full_path(&plan.core_program) {
        return Err(GuardError::NotAFullPath("transport program"));
    }
    if !full_path(&plan.service_program) {
        return Err(GuardError::NotAFullPath("service"));
    }
    if plan
        .core_program
        .eq_ignore_ascii_case(&plan.service_program)
    {
        return Err(GuardError::SameProgram);
    }
    for (who, user) in [
        ("transport program", &plan.core_user),
        ("service", &plan.service_user),
    ] {
        if user.trim().is_empty() {
            return Err(GuardError::NoAccount(who));
        }
        if !specific_account(user) {
            return Err(GuardError::NotAnAccount(who, user.clone()));
        }
    }
    if plan.tunnel.luid() == 0 {
        return Err(GuardError::NoTunnel);
    }
    if plan.control_port == 0 {
        return Err(GuardError::NoPort);
    }
    if let Some(range) = plan.local_ranges.iter().find(|r| !is_local(r)) {
        return Err(GuardError::RangeNotLocal(range.to_string()));
    }
    Ok(())
}

/// The core's control port: only the service reaches it (the second layer behind its secret).
fn control_port_filters(plan: &GuardPlan, out: &mut Vec<Filter>) {
    for family in BOTH_FAMILIES {
        out.push(Filter {
            name: format!("service to the control port ({})", fam_name(family)),
            family,
            direction: Direction::Outbound,
            action: Action::Permit,
            conditions: vec![
                Condition::Program(plan.service_program.clone()),
                Condition::User(plan.service_user.clone()),
                Condition::Loopback,
                Condition::Tcp,
                Condition::RemotePort(plan.control_port),
            ],
            weight: CONTROL_PERMIT_WEIGHT,
        });
        out.push(Filter {
            name: format!("everyone else to the control port ({})", fam_name(family)),
            family,
            direction: Direction::Outbound,
            action: Action::Block,
            conditions: vec![
                Condition::Loopback,
                Condition::Tcp,
                Condition::RemotePort(plan.control_port),
            ],
            weight: CONTROL_BLOCK_WEIGHT,
        });
    }
}

/// What is let through in every direction and family: the tunnel, this computer, the carrier. (A permit for virtual
/// machines on a virtual switch was in the first version and is gone: the firewall engine refuses its condition at the
/// layers the guard works at, measured in the lab, and traffic between guests of a virtual switch is not traffic of this
/// computer's programs, which is all those layers see. WSL and Docker reach the host over the local ranges, which stay open.)
fn standing_filters(plan: &GuardPlan, out: &mut Vec<Filter>) {
    for family in BOTH_FAMILIES {
        for direction in BOTH_DIRECTIONS {
            let tag = format!("{} {}", dir_name(direction), fam_name(family));
            out.push(permit(
                format!("the tunnel adapter ({tag})"),
                family,
                direction,
                vec![Condition::Interface(plan.tunnel)],
            ));
            out.push(permit(
                format!("this computer itself ({tag})"),
                family,
                direction,
                vec![Condition::Loopback],
            ));
            out.push(permit(
                format!("the transport program ({tag})"),
                family,
                direction,
                vec![
                    Condition::Program(plan.core_program.clone()),
                    Condition::User(plan.core_user.clone()),
                ],
            ));
        }
    }
}

/// The local ranges that stay reachable, each once however often it was given.
fn range_filters(plan: &GuardPlan, out: &mut Vec<Filter>) {
    let mut given: Vec<&IpCidr> = Vec::new();
    for range in &plan.local_ranges {
        if given.contains(&range) {
            continue;
        }
        given.push(range);
        let family = family_of(range);
        for direction in BOTH_DIRECTIONS {
            out.push(permit(
                format!(
                    "the local range {} ({} {})",
                    range,
                    dir_name(direction),
                    fam_name(family)
                ),
                family,
                direction,
                vec![Condition::Remote(range.clone())],
            ));
        }
    }
}

/// Joining a network and finding neighbours on the local link.
fn link_filters(out: &mut Vec<Filter>) {
    // Addresses from the local network: the client asks on 68 and the server answers from 67 (v4), and on 546 and 547
    // for v6. Without them a network that must be asked for an address cannot be joined.
    for (family, client, server) in [(Family::V4, 68, 67), (Family::V6, 546, 547)] {
        // Only to where such a request goes (the broadcast address, or the all-DHCP-agents group), so a program
        // that binds the client port cannot use the permit to reach any other address.
        let asked = if family == Family::V4 {
            "255.255.255.255/32"
        } else {
            "ff02::1:2/128"
        };
        out.push(permit(
            format!("asking for an address ({})", fam_name(family)),
            family,
            Direction::Outbound,
            vec![
                Condition::Udp,
                Condition::LocalPort(client),
                Condition::RemotePort(server),
                Condition::Remote(IpCidr::parse(asked).expect("built-in address is valid")),
            ],
        ));
        out.push(permit(
            format!("the answer about an address ({})", fam_name(family)),
            family,
            Direction::Inbound,
            vec![
                Condition::Udp,
                Condition::LocalPort(client),
                Condition::RemotePort(server),
            ],
        ));
    }

    // Router and neighbour solicitation and advertisement, and redirect.
    for message in 133..=137u8 {
        for direction in BOTH_DIRECTIONS {
            out.push(permit(
                format!("neighbour discovery {message} ({})", dir_name(direction)),
                Family::V6,
                direction,
                vec![Condition::IcmpV6(message)],
            ));
        }
    }
}

/// The one block of everything else, per direction and family.
fn block_filters(out: &mut Vec<Filter>) {
    for family in BOTH_FAMILIES {
        for direction in BOTH_DIRECTIONS {
            out.push(Filter {
                name: format!(
                    "everything else ({} {})",
                    dir_name(direction),
                    fam_name(family)
                ),
                family,
                direction,
                action: Action::Block,
                conditions: Vec::new(),
                weight: BLOCK_WEIGHT,
            });
        }
    }
}

/// The guard for `plan`: narrow permits, then one block of everything per direction and family. Highest weight first,
/// and in a fixed order, so the same plan always gives the same list.
pub fn filters(plan: &GuardPlan) -> Result<Vec<Filter>, GuardError> {
    check_plan(plan)?;
    let mut out: Vec<Filter> = Vec::new();
    control_port_filters(plan, &mut out);
    standing_filters(plan, &mut out);
    range_filters(plan, &mut out);
    link_filters(&mut out);
    block_filters(&mut out);
    out.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// Whether two lists of conditions hold the same conditions, in any order.
fn same_conditions(a: &[Condition], b: &[Condition]) -> bool {
    a.len() == b.len() && a.iter().all(|c| b.contains(c)) && b.iter().all(|c| a.contains(c))
}

/// Whether two rules match the same traffic and act the same way, whatever they are called and however their
/// conditions are ordered.
fn same_match(a: &Filter, b: &Filter) -> bool {
    a.family == b.family
        && a.direction == b.direction
        && a.action == b.action
        && same_conditions(&a.conditions, &b.conditions)
}

/// Every way `filters` is wrong in itself, in words; empty when there is none. It cannot know what was asked for: a
/// well-formed permit nobody asked for passes it. [`verify`] is the check against a plan.
#[must_use]
pub fn leaks(filters: &[Filter]) -> Vec<String> {
    let mut found = Vec::new();

    for family in BOTH_FAMILIES {
        for direction in BOTH_DIRECTIONS {
            let blocked = filters.iter().any(|f| {
                f.action == Action::Block
                    && f.family == family
                    && f.direction == direction
                    && f.conditions.is_empty()
                    && f.weight == BLOCK_WEIGHT
            });
            if !blocked {
                found.push(format!(
                    "nothing blocks everything else ({} {})",
                    dir_name(direction),
                    fam_name(family)
                ));
            }
        }
    }

    for f in filters.iter().filter(|f| f.action == Action::Permit) {
        if f.conditions.is_empty() {
            found.push(format!("`{}` permits everything", f.name));
        } else if !f.conditions.iter().any(Condition::names_something) {
            found.push(format!(
                "`{}` is only a protocol: it names no interface, program, address or port",
                f.name
            ));
        }
        // Weights start at the block's, so "not above it" is "equal to it".
        if f.weight == BLOCK_WEIGHT {
            found.push(format!(
                "`{}` is not above the block of everything, so it never applies",
                f.name
            ));
        }
        for condition in &f.conditions {
            if let Condition::Remote(range) = condition {
                if !is_local(range) && !is_address_request_to(f, range) {
                    found.push(format!(
                        "`{}` lets {} through, which is not a local range",
                        f.name, range
                    ));
                }
            }
        }
        // A program is only ever named together with the account that runs it.
        let has_program = f
            .conditions
            .iter()
            .any(|c| matches!(c, Condition::Program(_)));
        if has_program && !f.conditions.iter().any(|c| matches!(c, Condition::User(_))) {
            found.push(format!(
                "`{}` names a program but not the account that runs it",
                f.name
            ));
        }
    }

    for family in BOTH_FAMILIES {
        let blocks_control = filters.iter().any(|f| {
            f.action == Action::Block
                && f.family == family
                && f.direction == Direction::Outbound
                && f.weight > BLOCK_WEIGHT
                && f.conditions.contains(&Condition::Loopback)
                && f.conditions.contains(&Condition::Tcp)
                && f.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::RemotePort(_)))
        });
        if !blocks_control {
            found.push(format!(
                "nothing keeps other programs off the control port ({})",
                fam_name(family)
            ));
        }
    }

    for (at, f) in filters.iter().enumerate() {
        if filters[..at].iter().any(|earlier| same_match(earlier, f)) {
            found.push(format!("`{}` is a duplicate of another rule", f.name));
        }
    }
    found
}

/// What is wrong with `installed` as the guard for `plan`: every way it leaks ([`leaks`]) and every difference from what
/// the plan produces ([`filters`]): a rule the plan did not ask for, and a rule it asked for that is missing or changed.
/// The order of rules and of conditions does not matter. Run it on what is read back from the firewall, not only on the
/// list that was applied.
#[must_use]
pub fn verify(plan: &GuardPlan, installed: &[Filter]) -> Vec<String> {
    let expected = match filters(plan) {
        Ok(expected) => expected,
        Err(error) => return vec![format!("the plan cannot be used: {error}")],
    };
    let mut found = leaks(installed);
    let same = |a: &Filter, b: &Filter| same_match(a, b) && a.weight == b.weight;
    for want in &expected {
        if !installed.iter().any(|have| same(want, have)) {
            found.push(format!(
                "`{}` is missing or changed ({})",
                want.name,
                describe(want)
            ));
        }
    }
    for have in installed {
        if !expected.iter().any(|want| same(want, have)) {
            found.push(format!(
                "`{}` is not part of the plan ({})",
                have.name,
                describe(have)
            ));
        }
    }
    found
}

/// A guard that passed its own check: the only thing an applier takes. It cannot be made from a plan that is refused,
/// and the list inside cannot be changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    filters: Vec<Filter>,
}

impl Guard {
    /// Build the guard for `plan`, refusing a plan that cannot be used and a list that would leak.
    pub fn build(plan: &GuardPlan) -> Result<Self, GuardError> {
        let filters = filters(plan)?;
        let found = leaks(&filters);
        if found.is_empty() {
            Ok(Self { filters })
        } else {
            Err(GuardError::WouldLeak(found))
        }
    }

    /// The rules, highest weight first.
    pub fn filters(&self) -> &[Filter] {
        &self.filters
    }
}

/// One line for a rule: what the dry run prints, and what a person reads to see what the guard would do.
pub fn describe(filter: &Filter) -> String {
    let what = match filter.action {
        Action::Permit => "permit",
        Action::Block => "block",
    };
    let mut parts: Vec<String> = Vec::new();
    for c in &filter.conditions {
        parts.push(match c {
            Condition::Interface(id) => format!("on adapter {}", id.luid()),
            Condition::Program(path) => format!("program {path}"),
            Condition::User(sid) => format!("as {sid}"),
            Condition::Loopback => "this computer itself".to_owned(),
            Condition::Udp => "UDP".to_owned(),
            Condition::Tcp => "TCP".to_owned(),
            Condition::LocalPort(p) => format!("local port {p}"),
            Condition::RemotePort(p) => format!("remote port {p}"),
            Condition::Remote(r) => format!("range {r}"),
            Condition::IcmpV6(t) => format!("ICMPv6 type {t}"),
        });
    }
    let matching = if parts.is_empty() {
        "everything".to_owned()
    } else {
        parts.join(", ")
    };
    format!(
        "[{:>2}] {what} {} {}: {matching}",
        filter.weight,
        dir_name(filter.direction),
        fam_name(filter.family)
    )
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&describe(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn plan() -> GuardPlan {
        GuardPlan {
            tunnel: InterfaceId::new(0x0006_0000_0000_0007),
            core_program: r"C:\Program Files\DNet Engine\primary-core.exe".into(),
            core_user: "S-1-5-18".into(),
            service_program: r"C:\Program Files\DNet Engine\dnetd.exe".into(),
            service_user: "S-1-5-18".into(),
            control_port: 34_567,
            local_ranges: ["10.0.0.0/8", "192.168.0.0/16", "fe80::/10", "ff00::/8"]
                .iter()
                .map(|r| IpCidr::parse(r).unwrap())
                .collect(),
        }
    }

    fn built() -> Vec<Filter> {
        filters(&plan()).unwrap()
    }

    fn named<'a>(list: &'a [Filter], name: &str) -> &'a Filter {
        list.iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no rule called {name:?}"))
    }

    fn extra(name: &str, family: Family, conditions: Vec<Condition>, weight: u8) -> Filter {
        Filter {
            name: name.into(),
            family,
            direction: Direction::Outbound,
            action: Action::Permit,
            conditions,
            weight,
        }
    }

    // ------------------------------------------------------------------ the list is a guard

    #[test]
    fn the_guard_for_a_good_plan_has_no_leak_in_it_and_nothing_to_verify() {
        assert_eq!(leaks(&built()), Vec::<String>::new());
        assert_eq!(verify(&plan(), &built()), Vec::<String>::new());
    }

    #[test]
    fn everything_else_is_blocked_in_both_directions_and_both_families_and_nothing_sits_below_that()
    {
        let list = built();
        let blocks: Vec<_> = list
            .iter()
            .filter(|f| f.action == Action::Block && f.conditions.is_empty())
            .collect();
        assert_eq!(blocks.len(), 4);
        for family in BOTH_FAMILIES {
            for direction in BOTH_DIRECTIONS {
                assert!(
                    blocks
                        .iter()
                        .any(|b| b.family == family && b.direction == direction),
                    "no block for {family:?} {direction:?}"
                );
            }
        }
        // They are the last four, and the only ones at the lowest weight.
        assert!(list[list.len() - 4..]
            .iter()
            .all(|f| f.weight == BLOCK_WEIGHT));
        assert!(list[..list.len() - 4]
            .iter()
            .all(|f| f.weight > BLOCK_WEIGHT));
    }

    #[test]
    fn every_permit_names_something_and_none_is_a_bare_protocol() {
        for f in built().iter().filter(|f| f.action == Action::Permit) {
            assert!(!f.conditions.is_empty(), "{f}");
            assert!(f.conditions.iter().any(Condition::names_something), "{f}");
        }
    }

    #[test]
    fn the_transport_program_is_let_through_only_by_program_and_account_together() {
        let carrying: Vec<_> = built()
            .into_iter()
            .filter(|f| f.name.starts_with("the transport program"))
            .collect();
        assert_eq!(carrying.len(), 4);
        for f in carrying {
            assert!(f
                .conditions
                .contains(&Condition::Program(plan().core_program)));
            assert!(f.conditions.contains(&Condition::User("S-1-5-18".into())));
        }
    }

    #[test]
    fn every_program_in_the_list_is_named_with_its_account() {
        for f in built() {
            let program = f
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::Program(_)));
            let user = f.conditions.iter().any(|c| matches!(c, Condition::User(_)));
            assert_eq!(program, user, "{f}");
        }
    }

    #[test]
    fn only_the_service_reaches_the_control_port_and_it_is_the_first_rule_looked_at() {
        let list = built();
        let first = &list[0];
        assert_eq!(first.weight, CONTROL_PERMIT_WEIGHT);
        assert!(first
            .conditions
            .contains(&Condition::Program(plan().service_program)));
        assert!(first
            .conditions
            .contains(&Condition::User(plan().service_user)));
        assert!(first.conditions.contains(&Condition::RemotePort(34_567)));

        let loopback = named(&list, "this computer itself (out v4)");
        for family in ["v4", "v6"] {
            let block = named(
                &list,
                &format!("everyone else to the control port ({family})"),
            );
            assert_eq!(block.action, Action::Block);
            assert_eq!(block.direction, Direction::Outbound);
            assert!(same_conditions(
                &block.conditions,
                &[
                    Condition::Loopback,
                    Condition::Tcp,
                    Condition::RemotePort(34_567)
                ]
            ));
            // Above the permit for this computer itself, below the service's own.
            assert!(block.weight > loopback.weight);
            assert!(block.weight < first.weight);
        }
    }

    #[test]
    fn the_local_network_stays_reachable_by_the_ranges_it_was_given_and_only_those() {
        // The request for an address is scoped to its own two destinations (tested below); every other permit that
        // names an address names a given local range.
        let reachable: BTreeSet<String> = built()
            .into_iter()
            .filter(|f| !f.name.starts_with("asking for an address"))
            .flat_map(|f| f.conditions)
            .filter_map(|c| match c {
                Condition::Remote(r) => Some(r.to_string()),
                _ => None,
            })
            .collect();
        let given: BTreeSet<String> = plan().local_ranges.iter().map(|r| r.to_string()).collect();
        assert_eq!(reachable, given);
    }

    #[test]
    fn only_an_account_a_program_can_run_as_may_own_a_permit() {
        // Review 2026-11-10, finding 6: the firewall matches an account against the groups in a process's token,
        // so a group such as Administrators, Interactive or an integrity level would let almost anything through.
        for ok in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "S-1-5-21-1-2-3-1001",
            "S-1-5-21-4016204387-3008203602-4053404650-1001",
        ] {
            assert!(specific_account(ok), "{ok}");
        }
        for bad in [
            "S-1-1-0",
            "S-1-5-4",
            "S-1-5-6",
            "S-1-5-7",
            "S-1-5-11",
            "S-1-5-32-544",
            "S-1-5-32-545",
            "S-1-16-12288",
            "S-1-3-0",
            "S-1-5-21-1-2-3-513",
            "S-1-5-21-1-2-3-500",
            "S-1-5-21-1-2-3-999",
            "S-1-5-21-1",
            "S-1-5-80",
            "S-1-5-18-1",
            "S-1-5-",
            "",
        ] {
            assert!(!specific_account(bad), "{bad:?}");
        }
    }

    #[test]
    fn asking_for_an_address_is_sent_only_where_such_a_request_goes() {
        // Review 2026-11-10, finding 5: the request to join a network is allowed on its two ports, but only to the
        // broadcast address (v4) or the all-DHCP-agents group (v6); a program that binds the port cannot use it to
        // reach an arbitrary address. The answers are inbound and carry nothing out.
        let list = built();
        for (name, only) in [
            ("asking for an address (v4)", "255.255.255.255/32"),
            ("asking for an address (v6)", "ff02::1:2/128"),
        ] {
            let f = list.iter().find(|f| f.name.starts_with(name)).expect(name);
            let remote: Vec<String> = f
                .conditions
                .iter()
                .filter_map(|c| match c {
                    Condition::Remote(r) => Some(r.to_string()),
                    _ => None,
                })
                .collect();
            assert_eq!(remote, vec![only.to_string()], "{name}");
        }
    }

    #[test]
    fn an_address_can_still_be_asked_for_and_neighbours_found() {
        let list = built();
        let present = |n: &str| list.iter().any(|f| f.name.starts_with(n));
        assert!(present("asking for an address (v4)"));
        assert!(present("asking for an address (v6)"));
        for t in 133..=137 {
            assert!(present(&format!("neighbour discovery {t} (out)")), "{t}");
            assert!(present(&format!("neighbour discovery {t} (in)")), "{t}");
        }
    }

    #[test]
    fn the_same_plan_always_gives_the_same_list_highest_weight_first() {
        let a = built();
        let b = built();
        assert_eq!(a, b);
        assert!(a.windows(2).all(|w| w[0].weight >= w[1].weight));
    }

    // ------------------------------------------------------------------ the lint can fail

    /// Added after mutation testing: the checks for "something blocks everything else" and "something keeps other
    /// programs off the control port" were only tried with everything removed at once, so a check that ignored
    /// the direction, the family, the conditions or the weight went unnoticed. Each of the four blocks, and each
    /// family's control-port block, must be missed on its own, and a look-alike must not stand in for it.
    #[test]
    fn each_block_is_needed_on_its_own_and_a_look_alike_does_not_stand_in() {
        let is_block_of_everything = |f: &Filter, family: Family, direction: Direction| {
            f.action == Action::Block
                && f.conditions.is_empty()
                && f.family == family
                && f.direction == direction
        };
        for family in BOTH_FAMILIES {
            for direction in BOTH_DIRECTIONS {
                let wanted = format!(
                    "nothing blocks everything else ({} {})",
                    dir_name(direction),
                    fam_name(family)
                );
                // Gone: exactly that one is reported.
                let mut gone = built();
                gone.retain(|f| !is_block_of_everything(f, family, direction));
                assert_eq!(leaks(&gone), vec![wanted.clone()]);
                // Changed so that it is no longer the block of everything else: it does not count.
                let mut with_condition = built();
                for f in &mut with_condition {
                    if is_block_of_everything(f, family, direction) {
                        f.conditions = vec![Condition::Tcp];
                    }
                }
                assert!(
                    leaks(&with_condition).contains(&wanted),
                    "a block with a condition"
                );
                let mut above_the_floor = built();
                for f in &mut above_the_floor {
                    if is_block_of_everything(f, family, direction) {
                        f.weight = BLOCK_WEIGHT + 1;
                    }
                }
                assert!(
                    leaks(&above_the_floor).contains(&wanted),
                    "a block above the floor"
                );
            }
        }
    }

    #[test]
    fn each_familys_control_port_block_is_needed_on_its_own_and_a_look_alike_does_not_stand_in() {
        let is_control_block = |f: &Filter, family: Family| {
            f.action == Action::Block
                && f.family == family
                && f.direction == Direction::Outbound
                && f.weight > BLOCK_WEIGHT
                && f.conditions.contains(&Condition::Loopback)
        };
        for family in BOTH_FAMILIES {
            let wanted = format!(
                "nothing keeps other programs off the control port ({})",
                fam_name(family)
            );
            let mut gone = built();
            gone.retain(|f| !is_control_block(f, family));
            assert_eq!(
                leaks(&gone),
                vec![wanted.clone()],
                "removed for {family:?} only"
            );

            let mut inbound = built();
            for f in &mut inbound {
                if is_control_block(f, family) {
                    f.direction = Direction::Inbound;
                }
            }
            assert!(leaks(&inbound).contains(&wanted), "inbound does not count");

            let mut at_the_floor = built();
            for f in &mut at_the_floor {
                if is_control_block(f, family) {
                    f.weight = BLOCK_WEIGHT;
                }
            }
            assert!(
                leaks(&at_the_floor).contains(&wanted),
                "a block at the floor does not count"
            );
        }
    }

    #[test]
    fn a_rule_reads_as_words_with_its_weight_direction_and_family() {
        for f in built() {
            let words = f.to_string();
            assert_eq!(words, describe(&f));
            assert!(words.contains(dir_name(f.direction)), "{words}");
            assert!(words.contains(fam_name(f.family)), "{words}");
            assert!(words.len() > 10, "{words}");
        }
    }

    #[test]
    fn the_shortest_full_path_is_accepted_and_every_malformed_start_is_not() {
        assert!(
            full_path(r"C:\a"),
            "four bytes is the shortest path that names a file"
        );
        assert!(!full_path(r"C:\"), "no file name");
        // Each wrong in exactly one way, so a check that weakened any one of them is noticed.
        assert!(!full_path(r"1:\a"), "not a drive letter");
        assert!(!full_path(r"Cx\a"), "no colon");
        assert!(!full_path(r"C:xa"), "no backslash after the colon");
        assert!(!full_path(r"C:/a"), "a forward slash");
    }

    #[test]
    fn a_list_without_its_blocks_leaks_and_says_where() {
        let mut list = built();
        list.retain(|f| !(f.action == Action::Block && f.conditions.is_empty()));
        let found = leaks(&list);
        assert_eq!(
            found
                .iter()
                .filter(|l| l.contains("nothing blocks everything else"))
                .count(),
            4
        );
    }

    #[test]
    fn a_permit_of_everything_is_a_leak() {
        let mut list = built();
        list.push(extra("oops", Family::V4, Vec::new(), PERMIT_WEIGHT));
        assert!(leaks(&list)
            .iter()
            .any(|l| l.contains("`oops` permits everything")));
    }

    #[test]
    fn a_permit_that_is_only_a_protocol_is_a_leak() {
        let mut list = built();
        list.push(extra(
            "all udp",
            Family::V4,
            vec![Condition::Udp],
            PERMIT_WEIGHT,
        ));
        assert!(leaks(&list).iter().any(|l| l.contains("only a protocol")));
    }

    #[test]
    fn a_program_permit_without_the_account_is_a_leak() {
        let mut list = built();
        list.push(extra(
            "any program by name",
            Family::V4,
            vec![Condition::Program(r"C:\Temp\x.exe".into())],
            PERMIT_WEIGHT,
        ));
        assert!(leaks(&list).iter().any(|l| l.contains("not the account")));
    }

    #[test]
    fn a_program_permit_to_the_control_port_without_the_account_is_a_leak_too() {
        let mut list = built();
        list.push(extra(
            "a program to the port",
            Family::V4,
            vec![
                Condition::Program(r"C:\Temp\x.exe".into()),
                Condition::Loopback,
                Condition::Tcp,
                Condition::RemotePort(34_567),
            ],
            CONTROL_PERMIT_WEIGHT,
        ));
        assert!(leaks(&list).iter().any(|l| l.contains("not the account")));
    }

    #[test]
    fn a_permit_at_the_weight_of_the_block_never_applies_and_is_said_so() {
        let mut list = built();
        list.push(extra(
            "too low",
            Family::V4,
            vec![Condition::Loopback],
            BLOCK_WEIGHT,
        ));
        assert!(leaks(&list)
            .iter()
            .any(|l| l.contains("not above the block")));
    }

    #[test]
    fn a_list_that_forgets_the_control_port_leaks() {
        let mut list = built();
        list.retain(|f| !f.name.starts_with("everyone else to the control port"));
        assert_eq!(
            leaks(&list)
                .iter()
                .filter(|l| l.contains("control port"))
                .count(),
            2
        );
    }

    #[test]
    fn a_control_port_block_that_is_inbound_or_not_tcp_does_not_count() {
        for change in [0, 1] {
            let mut list = built();
            for f in list
                .iter_mut()
                .filter(|f| f.name.starts_with("everyone else to the control port"))
            {
                if change == 0 {
                    f.direction = Direction::Inbound;
                } else {
                    f.conditions.retain(|c| *c != Condition::Tcp);
                }
            }
            assert_eq!(
                leaks(&list)
                    .iter()
                    .filter(|l| l.contains("off the control port"))
                    .count(),
                2,
                "change {change}"
            );
        }
    }

    #[test]
    fn a_duplicated_rule_is_noticed_whatever_its_name_and_the_order_of_its_conditions() {
        let mut list = built();
        let mut copy = named(&list, "the transport program (out v4)").clone();
        copy.name = "copy".into();
        copy.conditions.reverse();
        list.push(copy);
        assert!(leaks(&list)
            .iter()
            .any(|l| l.contains("`copy` is a duplicate")));
    }

    #[test]
    fn a_permit_for_a_range_that_is_not_local_is_a_leak() {
        let mut list = built();
        list.push(extra(
            "anywhere",
            Family::V4,
            vec![Condition::Remote(IpCidr::parse("0.0.0.0/0").unwrap())],
            PERMIT_WEIGHT,
        ));
        assert!(leaks(&list)
            .iter()
            .any(|l| l.contains("`anywhere`") && l.contains("not a local range")));
    }

    // ------------------------------------------------------------------ verify: what the plan asked for

    #[test]
    fn a_well_formed_permit_nobody_asked_for_passes_the_lint_but_not_verify() {
        let unasked = [
            extra(
                "https anywhere",
                Family::V4,
                vec![Condition::RemotePort(443)],
                PERMIT_WEIGHT,
            ),
            extra(
                "everyone",
                Family::V4,
                vec![Condition::User("S-1-1-0".into())],
                PERMIT_WEIGHT,
            ),
            extra(
                "echo",
                Family::V6,
                vec![Condition::IcmpV6(128)],
                PERMIT_WEIGHT,
            ),
            extra(
                "some adapter",
                Family::V4,
                vec![Condition::Interface(InterfaceId::new(99))],
                PERMIT_WEIGHT,
            ),
            extra(
                "very heavy",
                Family::V4,
                vec![Condition::Loopback, Condition::Udp],
                200,
            ),
        ];
        for rule in unasked {
            let name = rule.name.clone();
            let mut list = built();
            list.push(rule);
            assert_eq!(
                leaks(&list),
                Vec::<String>::new(),
                "{name}: the lint alone is blind to it, which is why verify exists"
            );
            assert!(
                verify(&plan(), &list)
                    .iter()
                    .any(|l| l.contains(&format!("`{name}`")) && l.contains("not part of the plan")),
                "{name}"
            );
        }
    }

    #[test]
    fn verify_names_a_rule_that_is_missing_or_changed() {
        let mut list = built();
        list.retain(|f| f.name != "this computer itself (out v4)");
        let found = verify(&plan(), &list);
        assert!(found
            .iter()
            .any(|l| l.contains("is missing or changed")
                && l.contains("this computer itself (out v4)")));

        let mut list = built();
        let at = list
            .iter()
            .position(|f| f.name == "everyone else to the control port (v4)")
            .unwrap();
        list[at].weight = 1;
        let found = verify(&plan(), &list);
        assert!(found
            .iter()
            .any(|l| l.contains("is missing or changed") && l.contains("control port (v4)")));
        assert!(found.iter().any(|l| l.contains("not part of the plan")));
    }

    #[test]
    fn verify_ignores_the_order_of_rules_and_of_conditions_and_the_names() {
        let mut list = built();
        list.reverse();
        for f in &mut list {
            f.conditions.reverse();
            f.name = format!("renamed {}", f.name);
        }
        assert_eq!(verify(&plan(), &list), Vec::<String>::new());
    }

    #[test]
    fn verify_of_a_plan_that_cannot_be_used_says_so() {
        let mut p = plan();
        p.control_port = 0;
        assert!(verify(&p, &built())
            .iter()
            .any(|l| l.contains("the plan cannot be used")));
    }

    // ------------------------------------------------------------------ the guard

    #[test]
    fn a_guard_holds_exactly_the_filters_of_a_plan_that_passes() {
        let guard = Guard::build(&plan()).unwrap();
        assert_eq!(guard.filters(), built().as_slice());
        let mut bad = plan();
        bad.core_program = "x.exe".into();
        assert!(matches!(
            Guard::build(&bad),
            Err(GuardError::NotAFullPath(_))
        ));
    }

    // ------------------------------------------------------------------ bad plans are refused

    #[test]
    fn a_program_that_is_not_a_full_path_on_a_local_drive_is_refused() {
        for bad in [
            "",
            "primary-core.exe",
            r"..\primary-core.exe",
            r"C:\a\..\b.exe",
            r"C:\a\.\b.exe",
            r"C:\a\\b.exe",
            r"C:\a.\b.exe",
            r"C:\a \b.exe",
            r"C:\*.exe",
            r"C:\a|b.exe",
            "C:foo.exe",
            "C:/a/b.exe",
            r"C:\Program Files\DNet Engine/../../x.exe",
            r"C:\a.exe:stream",
            r"C:\dir\\",
            r"C:\dir\",
            r"C:\",
            "C:\\a\nb.exe",
            r"\a\b.exe",
            r"\\evil\share\core.exe",
            r"\\.\pipe\x",
            r"\\?\C:\x.exe",
        ] {
            let mut p = plan();
            p.core_program = bad.to_owned();
            assert_eq!(
                filters(&p),
                Err(GuardError::NotAFullPath("transport program")),
                "{bad:?}"
            );
        }
        let mut p = plan();
        p.service_program = "dnetd.exe".to_owned();
        assert_eq!(filters(&p), Err(GuardError::NotAFullPath("service")));
    }

    #[test]
    fn a_full_path_on_any_drive_is_accepted_and_a_share_is_not() {
        let mut p = plan();
        p.core_program = r"E:\DNet Engine\core.exe".to_owned();
        p.service_program = r"D:\DNet\dnetd.exe".to_owned();
        assert!(filters(&p).is_ok());
        p.core_program = r"\\server\share\core.exe".to_owned();
        assert!(filters(&p).is_err());
    }

    #[test]
    fn the_service_and_the_transport_program_must_be_different_and_the_tunnel_must_be_named() {
        let mut p = plan();
        p.service_program = p.core_program.to_uppercase();
        assert_eq!(filters(&p), Err(GuardError::SameProgram));
        let mut p = plan();
        p.tunnel = InterfaceId::new(0);
        assert_eq!(filters(&p), Err(GuardError::NoTunnel));
    }

    #[test]
    fn an_account_must_be_one_specific_security_identifier() {
        for bad in [
            "*",
            "Everyone",
            "SYSTEM",
            "S-1-1-0",
            "S-1-5-7",
            "S-1-5-11",
            "S-1-5-32-545",
            " S-1-5-18",
            "S-1-5-18 ",
            "S-1-5",
            "S-1-5-",
            "S-1-5-18-x",
            "s-1-5-18",
        ] {
            let mut p = plan();
            p.core_user = bad.to_owned();
            let outcome = filters(&p);
            assert!(
                matches!(
                    outcome,
                    Err(GuardError::NotAnAccount("transport program", _))
                        | Err(GuardError::NoAccount("transport program"))
                ),
                "{bad:?} gave {outcome:?}"
            );
        }
        for good in ["S-1-5-18", "S-1-5-80-1234-5678-9", "S-1-5-21-1-2-3-1001"] {
            let mut p = plan();
            p.core_user = good.to_owned();
            p.service_user = good.to_owned();
            assert!(filters(&p).is_ok(), "{good}");
        }
    }

    #[test]
    fn an_unnamed_account_and_a_missing_port_are_refused() {
        let mut p = plan();
        p.core_user = "  ".to_owned();
        assert_eq!(filters(&p), Err(GuardError::NoAccount("transport program")));
        let mut p = plan();
        p.service_user = String::new();
        assert_eq!(filters(&p), Err(GuardError::NoAccount("service")));
        let mut p = plan();
        p.service_user = "Everyone".to_owned();
        assert_eq!(
            filters(&p),
            Err(GuardError::NotAnAccount("service", "Everyone".to_owned()))
        );
        let mut p = plan();
        p.control_port = 0;
        assert_eq!(filters(&p), Err(GuardError::NoPort));
    }

    #[test]
    fn a_range_that_is_not_local_is_refused_so_a_default_route_cannot_be_slipped_in() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "8.8.8.0/24",
            "10.0.0.0/7",
            "172.0.0.0/8",
            "2001:db8::/32",
            "fe00::/9",
            "224.0.0.0/3",
            "169.254.0.0/15",
        ] {
            let mut p = plan();
            p.local_ranges = vec![IpCidr::parse(bad).unwrap()];
            assert_eq!(
                filters(&p),
                Err(GuardError::RangeNotLocal(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_range_inside_the_built_in_local_list_is_accepted_whole_or_narrowed() {
        for good in [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.255.255.255/32",
            "172.20.0.0/14",
            "192.168.1.0/24",
            "169.254.0.0/16",
            "224.0.0.251/32",
            "fe80::1/128",
            "ff02::/16",
        ] {
            let mut p = plan();
            p.local_ranges = vec![IpCidr::parse(good).unwrap()];
            assert!(filters(&p).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_range_given_twice_is_listed_once() {
        let mut p = plan();
        let ten = IpCidr::parse("10.0.0.0/8").unwrap();
        p.local_ranges = vec![ten.clone(), ten];
        let list = filters(&p).unwrap();
        // One rule per direction, not two.
        assert_eq!(
            list.iter()
                .filter(|f| f.name.starts_with("the local range"))
                .count(),
            2
        );
        assert_eq!(leaks(&list), Vec::<String>::new());
        assert_eq!(verify(&p, &list), Vec::<String>::new());
    }

    #[test]
    fn the_built_in_local_list_makes_a_guard_with_no_leak_in_it() {
        let mut p = plan();
        p.local_ranges = local_ranges();
        assert_eq!(p.local_ranges.len(), 7, "the bypass list has seven ranges");
        let guard = Guard::build(&p).unwrap();
        assert_eq!(leaks(guard.filters()), Vec::<String>::new());
    }

    #[test]
    fn a_rule_reads_as_one_plain_line() {
        let list = built();
        let block = list.last().unwrap();
        assert!(describe(block).contains("block"));
        assert!(describe(block).contains("everything"));
        let service = describe(&list[0]);
        assert!(service.starts_with("[15] permit out"), "{service}");
        assert!(service.contains("dnetd.exe"), "{service}");
    }
}
