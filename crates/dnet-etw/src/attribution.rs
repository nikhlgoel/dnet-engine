//! T075 — what one connect event says: which program asked to connect, from which port, to whom
//! (data-model §7, ADR-0001, research R7).
//!
//! Per-process routing needs to know which program a connection belongs to, and the only mechanism that
//! fits without a kernel driver is to listen to the operating system's own network provider for connect
//! events and read the process id out of them. This module is the reading, kept free of any ETW type so it
//! can be tested without a trace session, elevation or a network.
//!
//! # Three rules, each one a bug that was already found
//!
//! 1. **The process id comes from the event payload, never from the trace header.** Microsoft documents the
//!    header's process id as unreliable for network events: the event may be logged on another thread of
//!    another process. The payload's `PID` is the program that made the call.
//! 2. **Ports arrive in network byte order (big-endian).** The parser reads a 16-bit field in the machine's
//!    own order, so a value the kernel wrote big-endian comes out byte-swapped. SPIKE-O6 run 1 read them
//!    as they came and attributed 1 connection in 200; run 2 swapped them and attributed 200 in 200
//!    (ADR-0001). [`RawConnect`] holds the ports **as parsed**, and [`decode`] does the swap, so there is
//!    exactly one place where it happens. Addresses are different: they are byte arrays, kept in the order
//!    the kernel wrote them, which is the order an IP address is read in.
//! 3. **The result is best effort, and says so.** There is no `Attribution::Exact`. A connect event can be
//!    missed (a session that was not yet running, events dropped under load), a process id can be reused,
//!    and the clock between the event and its use is not zero. The type is named
//!    [`BestEffortAttribution`] so that no call site can forget it.

use std::net::{IpAddr, SocketAddr};

/// The provider that reports connects: `Microsoft-Windows-Kernel-Network`.
pub const PROVIDER_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// `TcpIpConnect` for IPv4.
pub const EVENT_TCP_CONNECT_V4: u16 = 12;
/// `TcpIpConnect` for IPv6.
pub const EVENT_TCP_CONNECT_V6: u16 = 28;

/// Whether `event_id` is a connect this module reads.
pub fn is_connect(event_id: u16) -> bool {
    event_id == EVENT_TCP_CONNECT_V4 || event_id == EVENT_TCP_CONNECT_V6
}

/// A TCP connection by its two ends. (Connect events are TCP; the protocol is implied.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// An address with an IPv4-mapped IPv6 form turned into the IPv4 address it is, so one connection has one
/// spelling whichever way the stack reported it.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

impl FiveTuple {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            local: SocketAddr::new(canonical(local.ip()), local.port()),
            remote: SocketAddr::new(canonical(remote.ip()), remote.port()),
        }
    }
}

/// A connect event's fields, **exactly as the parser returned them**: `sport` and `dport` are the 16-bit
/// values read in the machine's own byte order from a field the kernel wrote in network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawConnect {
    pub event_id: u16,
    /// From the event payload.
    pub pid: u32,
    pub saddr: IpAddr,
    pub daddr: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

/// Which program was seen connecting where. Best effort: see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BestEffortAttribution {
    pub tuple: FiveTuple,
    pub pid: u32,
}

/// Why an event was not turned into an attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("event {0} is not a connect event")]
    NotAConnect(u16),
    /// The addresses are not of the family the event id says.
    #[error("the addresses do not match the event's family")]
    AddressFamily,
    /// Process 0 is the idle process; no program connects as it.
    #[error("the event names no process")]
    NoProcess,
    #[error("a port is zero")]
    ZeroPort,
}

/// Read a connect event. The one place where the ports are put right.
pub fn decode(raw: RawConnect) -> Result<BestEffortAttribution, DecodeError> {
    let family_ok = match raw.event_id {
        EVENT_TCP_CONNECT_V4 => raw.saddr.is_ipv4() && raw.daddr.is_ipv4(),
        EVENT_TCP_CONNECT_V6 => raw.saddr.is_ipv6() && raw.daddr.is_ipv6(),
        other => return Err(DecodeError::NotAConnect(other)),
    };
    if !family_ok {
        return Err(DecodeError::AddressFamily);
    }
    if raw.pid == 0 {
        return Err(DecodeError::NoProcess);
    }
    // The kernel wrote these big-endian; the parser read them in the machine's order (ADR-0001, run 2).
    let sport = raw.sport.swap_bytes();
    let dport = raw.dport.swap_bytes();
    if sport == 0 || dport == 0 {
        return Err(DecodeError::ZeroPort);
    }
    Ok(BestEffortAttribution {
        tuple: FiveTuple::new(
            SocketAddr::new(raw.saddr, sport),
            SocketAddr::new(raw.daddr, dport),
        ),
        pid: raw.pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// What the parser hands back for a port the kernel wrote in network order.
    fn as_parsed(port: u16) -> u16 {
        u16::from_ne_bytes(port.to_be_bytes())
    }

    fn connect(pid: u32, sport: u16, dport: u16) -> RawConnect {
        RawConnect {
            event_id: EVENT_TCP_CONNECT_V4,
            pid,
            saddr: v4(192, 168, 1, 20),
            daddr: v4(93, 184, 216, 34),
            sport: as_parsed(sport),
            dport: as_parsed(dport),
        }
    }

    #[test]
    fn adr_0001_ports_are_put_into_host_order_so_the_connection_is_the_one_that_was_made() {
        // Not palindromes: a port that reads the same both ways would pass whether or not it was swapped.
        for (sport, dport) in [
            (51234, 443),
            (1, 80),
            (65535, 8443),
            (49152, 53),
            (0x1234, 0xabcd),
        ] {
            let decoded = decode(connect(4321, sport, dport)).unwrap();
            assert_eq!(decoded.tuple.local.port(), sport, "local {sport}");
            assert_eq!(decoded.tuple.remote.port(), dport, "remote {dport}");
        }
    }

    #[test]
    fn the_swap_matters_reading_the_ports_as_they_came_gives_the_wrong_connection() {
        // The run-1 mistake, shown: what the parser returned is not the port.
        let port = 51234u16;
        if cfg!(target_endian = "little") {
            assert_ne!(as_parsed(port), port);
            let decoded = decode(connect(4321, port, 443)).unwrap();
            assert_ne!(decoded.tuple.local.port(), as_parsed(port));
        }
    }

    #[test]
    fn the_process_id_is_the_payloads_and_is_carried_unchanged() {
        for pid in [4u32, 1234, 65_536, u32::MAX] {
            assert_eq!(decode(connect(pid, 50000, 443)).unwrap().pid, pid);
        }
    }

    #[test]
    fn addresses_keep_the_order_the_kernel_wrote_them_in() {
        let decoded = decode(connect(1, 50000, 443)).unwrap();
        assert_eq!(decoded.tuple.local.ip(), v4(192, 168, 1, 20));
        assert_eq!(decoded.tuple.remote.ip(), v4(93, 184, 216, 34));
    }

    #[test]
    fn an_ipv6_connect_is_read_the_same_way() {
        let raw = RawConnect {
            event_id: EVENT_TCP_CONNECT_V6,
            pid: 77,
            saddr: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            daddr: IpAddr::V6("2606:4700::1111".parse::<Ipv6Addr>().unwrap()),
            sport: as_parsed(40000),
            dport: as_parsed(443),
        };
        let decoded = decode(raw).unwrap();
        assert_eq!(decoded.tuple.local.to_string(), "[2001:db8::1]:40000");
        assert_eq!(decoded.tuple.remote.to_string(), "[2606:4700::1111]:443");
    }

    #[test]
    fn an_ipv4_connection_reported_in_mapped_form_is_the_same_connection() {
        let plain = decode(connect(1, 50000, 443)).unwrap().tuple;
        let mapped = decode(RawConnect {
            event_id: EVENT_TCP_CONNECT_V6,
            pid: 1,
            saddr: "::ffff:192.168.1.20".parse().unwrap(),
            daddr: "::ffff:93.184.216.34".parse().unwrap(),
            sport: as_parsed(50000),
            dport: as_parsed(443),
        })
        .unwrap()
        .tuple;
        assert_eq!(plain, mapped);
    }

    #[test]
    fn what_is_not_a_connect_or_not_coherent_is_refused() {
        let mut raw = connect(1, 50000, 443);
        raw.event_id = 11;
        assert_eq!(decode(raw), Err(DecodeError::NotAConnect(11)));
        assert!(!is_connect(11) && is_connect(12) && is_connect(28));

        // A v4 event carrying v6 addresses, and the reverse.
        let mut raw = connect(1, 50000, 443);
        raw.saddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(decode(raw), Err(DecodeError::AddressFamily));
        let mut raw = connect(1, 50000, 443);
        raw.event_id = EVENT_TCP_CONNECT_V6;
        assert_eq!(decode(raw), Err(DecodeError::AddressFamily));

        assert_eq!(decode(connect(0, 50000, 443)), Err(DecodeError::NoProcess));
        let mut raw = connect(1, 50000, 443);
        raw.sport = 0;
        assert_eq!(decode(raw), Err(DecodeError::ZeroPort));
        let mut raw = connect(1, 50000, 443);
        raw.dport = 0;
        assert_eq!(decode(raw), Err(DecodeError::ZeroPort));
    }

    #[test]
    fn the_type_says_what_it_is() {
        // No variant or constructor claims certainty; the name is the reminder.
        let shown = format!("{:?}", decode(connect(1, 50000, 443)).unwrap());
        assert!(shown.starts_with("BestEffortAttribution"), "{shown}");
    }
}
