// SPDX-License-Identifier: GPL-3.0-or-later
//! T203 — which connections that were already open are ended when the tunnel comes up.
//!
//! **The problem, measured.** A connection that is open when the tunnel comes up keeps its address from the physical
//! network card and keeps going out of that card: nothing makes the system look again. In the lab a long-lived
//! HTTPS connection opened before the connect still reported the computer's own address for as long as it was kept
//! busy, through the connect, after the tunnel's program was stopped, and after the disconnect. The kill switch does
//! not stop it either: its rules decide whether a *new* connection may be made, and this one was made long ago.
//!
//! **What is done about it.** When the tunnel is up, a connection that a new one to the same place would now send
//! *into the tunnel*, but which is still on its old address, is dropped (the system's own call for it, which sends
//! nothing to the other end), and the program that held it makes a new one, which goes through the tunnel. That is
//! all this module decides; it reads nothing and ends nothing, so the choice is tested on every machine and the
//! Windows half (`dnet_netstate::flow_end`) only gathers the facts and carries the choice out.
//!
//! **What is deliberately left alone** (each of these is a way to cut a person off that did not need cutting):
//! connections that are not carrying anything now (listening, finished), a connection on the tunnel's own address (it
//! is already carried), anything to this computer itself, anything a new connection would *not* send into the tunnel
//! (the local network, a printer, a router; the host route to the server is one of these), a connection somebody else
//! opened *to* this computer (the other end already knows its address, so nothing is revealed, and ending it would only
//! cut a person off), and everything the product's own programs hold, whoever they talk to: the carrier's connection to
//! its server must never be ended, and its address is not always the one the service knows (a name that resolves to
//! several, a probe of another server).
//!
//! **A budget.** The pass asks the system one question per distinct remote address, and a program can make many. It
//! asks at most [`MAX_QUESTIONS`] and stops when it is told its time is up, and says that it stopped.
//!
//! **Not covered, said plainly.** Only TCP over IPv4 is ended: the system has no call that ends an IPv6 connection,
//! and a datagram "connection" (QUIC, a call, a game) has nothing to end. Those keep working outside the tunnel
//! until they stop of their own accord.
//!
//! Pure logic: no I/O.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// The most distinct remote addresses a pass asks the system about.
pub const MAX_QUESTIONS: usize = 1024;

/// The state of a TCP connection, as the system numbers them (`MIB_TCP_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    /// A number this version does not know. Never ended: what is not understood is not touched.
    Unknown(u32),
}

impl TcpState {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            other => Self::Unknown(other),
        }
    }

    /// Whether the connection is one a program is using or about to use. A listening socket, a finished connection
    /// and one the system is already deleting carry nothing that could go out of the wrong card.
    fn is_in_use(self) -> bool {
        matches!(
            self,
            Self::SynSent
                | Self::SynReceived
                | Self::Established
                | Self::FinWait1
                | Self::FinWait2
                | Self::CloseWait
                | Self::Closing
                | Self::LastAck
        )
    }
}

/// One IPv4 TCP connection, with the facts the system alone can give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlow {
    pub state: TcpState,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    /// The process that holds it.
    pub owner: u32,
    /// Whether somebody else opened it *to* a port this computer listens on.
    pub accepted: bool,
    /// Whether a **new** connection to `remote` would now be sent into the tunnel (the system's own answer, asked
    /// after the tunnel's routes are in).
    pub would_use_tunnel: bool,
}

/// What must be left alone however the rest reads.
#[derive(Debug, Clone, Default)]
pub struct Keep {
    /// The tunnel adapter's own addresses: a connection on one of them is already carried.
    pub tunnel: Vec<Ipv4Addr>,
    /// The servers the carrier talks to.
    pub servers: Vec<Ipv4Addr>,
    /// The processes that are the product's own programs (the transport programs and the service): whatever they hold
    /// is never ended.
    pub ours: Vec<u32>,
}

/// Whether to end this connection.
pub fn should_end(flow: &TcpFlow, keep: &Keep) -> bool {
    flow.state.is_in_use()
        && flow.would_use_tunnel
        && !flow.accepted
        && !keep.ours.contains(&flow.owner)
        && !keep.tunnel.contains(&flow.local)
        && !keep.servers.contains(&flow.remote)
        && !is_this_computer(flow.local)
        && !is_this_computer(flow.remote)
        && !flow.remote.is_broadcast()
        && !flow.remote.is_multicast()
}

/// An address that is not another computer: loopback and the unspecified address.
fn is_this_computer(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// One row of the system's table of TCP connections with their owners (`MIB_TCPROW_OWNER_PID`), as it sits in memory.
/// Addresses and ports are in network byte order, so they are kept as the words they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTcpRow {
    pub state: u32,
    pub local_addr: u32,
    pub local_port: u32,
    pub remote_addr: u32,
    pub remote_port: u32,
    pub owner: u32,
}

/// The number of 32-bit words in a row: state, two addresses, two ports and the owner.
const ROW_WORDS: usize = 6;

/// Read the system's table (`MIB_TCPTABLE_OWNER_PID`: a count, then that many rows) from its words. A count larger
/// than the buffer holds is read as far as the buffer goes, never past it, and a buffer too short to hold the count
/// is empty: a table that cannot be read ends nothing.
pub fn parse_tcp_table(words: &[u32]) -> Vec<RawTcpRow> {
    let Some((&count, rest)) = words.split_first() else {
        return Vec::new();
    };
    let wanted = usize::try_from(count).unwrap_or(usize::MAX);
    rest.as_chunks::<ROW_WORDS>()
        .0
        .iter()
        .take(wanted)
        .map(|row| RawTcpRow {
            state: row[0],
            local_addr: row[1],
            local_port: row[2],
            remote_addr: row[3],
            remote_port: row[4],
            owner: row[5],
        })
        .collect()
}

/// The address of a row's `local_addr` or `remote_addr` word. The system keeps it in network byte order, which is the
/// byte order of the memory, so the word's native-endian bytes are the address's octets.
pub fn address_of(word: u32) -> Ipv4Addr {
    Ipv4Addr::from(word.to_ne_bytes())
}

/// The port of a row's `local_port` or `remote_port` word: the low 16 bits, in network byte order.
pub fn port_of(word: u32) -> u16 {
    u16::from_be(word as u16)
}

/// What a pass chose, and how far it got.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// Connections that were in use and were looked at.
    pub examined: usize,
    /// The rows to end.
    pub to_end: Vec<RawTcpRow>,
    /// Whether the pass stopped before looking at everything (too many questions, or out of time).
    pub stopped_early: bool,
}

/// Choose the rows to end. `would_use_tunnel` answers, for a remote address, whether a new connection to it would now
/// go into the tunnel (and must say `false` when it cannot tell); it is asked once per distinct address and at most
/// [`MAX_QUESTIONS`] times. `out_of_time` is asked before each question and ends the pass when it says so.
pub fn select(
    rows: &[RawTcpRow],
    keep: &Keep,
    mut would_use_tunnel: impl FnMut(Ipv4Addr) -> bool,
    mut out_of_time: impl FnMut() -> bool,
) -> Selection {
    // The ports this computer listens on: a connection to one of them was opened by somebody else.
    let listening: HashSet<u16> = rows
        .iter()
        .filter(|row| TcpState::from_code(row.state) == TcpState::Listen)
        .map(|row| port_of(row.local_port))
        .collect();
    let mut asked: HashMap<Ipv4Addr, bool> = HashMap::new();
    let mut result = Selection::default();
    for row in rows {
        let flow = TcpFlow {
            state: TcpState::from_code(row.state),
            local: address_of(row.local_addr),
            remote: address_of(row.remote_addr),
            owner: row.owner,
            accepted: listening.contains(&port_of(row.local_port)),
            would_use_tunnel: true,
        };
        // Everything but the route is checked first, so that a question is asked only about a connection that could
        // be ended and a flood of connections that never could costs nothing.
        if !should_end(&flow, keep) {
            continue;
        }
        result.examined += 1;
        let tunnel = if let Some(known) = asked.get(&flow.remote) {
            *known
        } else {
            if asked.len() >= MAX_QUESTIONS || out_of_time() {
                result.stopped_early = true;
                break;
            }
            let answer = would_use_tunnel(flow.remote);
            asked.insert(flow.remote, answer);
            answer
        };
        if tunnel {
            result.to_end.push(*row);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// A stale direct connection: in use, on the card's address, to a public host a new one would send into the tunnel.
    fn stale() -> TcpFlow {
        TcpFlow {
            state: TcpState::Established,
            local: ip(192, 168, 1, 20),
            remote: ip(1, 1, 1, 1),
            owner: 4000,
            accepted: false,
            would_use_tunnel: true,
        }
    }

    fn keep() -> Keep {
        Keep {
            tunnel: vec![ip(172, 19, 0, 1)],
            servers: vec![ip(203, 0, 113, 9)],
            ours: vec![111, 222],
        }
    }

    #[test]
    fn a_stale_direct_connection_is_ended() {
        assert!(should_end(&stale(), &keep()));
    }

    #[test]
    fn every_state_a_program_is_using_is_ended_and_no_other() {
        let in_use = [3, 4, 5, 6, 7, 8, 9, 10];
        for code in 1..=12 {
            let state = TcpState::from_code(code);
            let ended = should_end(&TcpFlow { state, ..stale() }, &keep());
            assert_eq!(ended, in_use.contains(&code), "state {code} ({state:?})");
        }
    }

    #[test]
    fn a_state_nobody_knows_is_not_touched() {
        for code in [0, 13, 99, u32::MAX] {
            let flow = TcpFlow {
                state: TcpState::from_code(code),
                ..stale()
            };
            assert!(!should_end(&flow, &keep()), "code {code}");
        }
    }

    #[test]
    fn a_connection_a_new_one_would_not_send_into_the_tunnel_is_left_alone() {
        // The local network, a printer, the router, the host route to the server: the system keeps them on the card.
        let flow = TcpFlow {
            would_use_tunnel: false,
            ..stale()
        };
        assert!(!should_end(&flow, &keep()));
    }

    #[test]
    fn a_connection_on_the_tunnels_own_address_is_already_carried() {
        let flow = TcpFlow {
            local: ip(172, 19, 0, 1),
            ..stale()
        };
        assert!(!should_end(&flow, &keep()));
    }

    #[test]
    fn the_carriers_own_connection_to_its_server_is_never_ended() {
        let flow = TcpFlow {
            remote: ip(203, 0, 113, 9),
            ..stale()
        };
        assert!(!should_end(&flow, &keep()));
    }

    #[test]
    fn whatever_the_products_own_programs_hold_is_never_ended_whoever_it_is_to() {
        // A server whose name resolves to several addresses, or a probe of another server: not the one the service
        // knows, but the carrier's all the same.
        for owner in [111, 222] {
            let flow = TcpFlow {
                owner,
                remote: ip(198, 51, 100, 77),
                ..stale()
            };
            assert!(!should_end(&flow, &keep()), "owner {owner}");
        }
    }

    #[test]
    fn a_connection_somebody_else_opened_to_this_computer_is_left_alone() {
        let flow = TcpFlow {
            accepted: true,
            ..stale()
        };
        assert!(!should_end(&flow, &keep()));
    }

    #[test]
    fn nothing_to_this_computer_itself_is_ended() {
        for (local, remote) in [
            (ip(127, 0, 0, 1), ip(127, 0, 0, 1)),
            (ip(192, 168, 1, 20), ip(127, 0, 0, 1)),
            (ip(0, 0, 0, 0), ip(1, 1, 1, 1)),
            (ip(192, 168, 1, 20), ip(0, 0, 0, 0)),
        ] {
            let flow = TcpFlow {
                local,
                remote,
                ..stale()
            };
            assert!(!should_end(&flow, &keep()), "{local} -> {remote}");
        }
    }

    #[test]
    fn broadcast_and_multicast_are_not_connections_to_end() {
        for remote in [ip(255, 255, 255, 255), ip(224, 0, 0, 251)] {
            let flow = TcpFlow { remote, ..stale() };
            assert!(!should_end(&flow, &keep()), "{remote}");
        }
    }

    #[test]
    fn with_nothing_to_keep_only_the_facts_of_the_flow_decide() {
        assert!(should_end(&stale(), &Keep::default()));
    }

    #[test]
    fn an_address_is_read_in_the_order_the_system_keeps_it() {
        // 192.168.1.20 in network byte order, as the word the table holds: the bytes in memory are c0 a8 01 14.
        let word = u32::from_ne_bytes([192, 168, 1, 20]);
        assert_eq!(address_of(word), ip(192, 168, 1, 20));
    }

    #[test]
    fn a_port_is_read_from_the_low_half_in_network_order() {
        // Port 443 in network byte order is the bytes 01 bb; the system keeps it in the low 16 bits of a word.
        let word = u32::from(443u16.to_be());
        assert_eq!(port_of(word), 443);
        assert_eq!(port_of(0), 0);
    }

    fn row(state: u32, local: Ipv4Addr, port: u16, remote: Ipv4Addr, owner: u32) -> RawTcpRow {
        RawTcpRow {
            state,
            local_addr: u32::from_ne_bytes(local.octets()),
            local_port: u32::from(port.to_be()),
            remote_addr: u32::from_ne_bytes(remote.octets()),
            remote_port: u32::from(443u16.to_be()),
            owner,
        }
    }

    #[test]
    fn a_table_is_read_row_by_row() {
        let words = [
            2, // count
            5, 1, 2, 3, 4, 100, // the first row
            11, 5, 6, 7, 8, 200, // the second
        ];
        let rows = parse_tcp_table(&words);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            RawTcpRow {
                state: 5,
                local_addr: 1,
                local_port: 2,
                remote_addr: 3,
                remote_port: 4,
                owner: 100
            }
        );
        assert_eq!(rows[1].state, 11);
        assert_eq!(rows[1].remote_addr, 7);
        assert_eq!(rows[1].owner, 200);
    }

    #[test]
    fn a_count_larger_than_the_buffer_is_read_only_as_far_as_the_buffer_goes() {
        let words = [1_000_000, 5, 1, 2, 3, 4, 100, 5, 1, 2];
        // One whole row; the three words that follow it are not a second one.
        assert_eq!(parse_tcp_table(&words).len(), 1);
    }

    #[test]
    fn a_count_smaller_than_the_buffer_stops_at_the_count() {
        let words = [1, 5, 1, 2, 3, 4, 100, 5, 1, 2, 3, 4, 100];
        assert_eq!(parse_tcp_table(&words).len(), 1);
    }

    #[test]
    fn an_empty_or_countless_buffer_is_no_connections() {
        assert!(parse_tcp_table(&[]).is_empty());
        assert!(parse_tcp_table(&[0]).is_empty());
        assert!(parse_tcp_table(&[3]).is_empty());
    }

    // ---- the whole pass, with the system's answers made up

    fn public() -> Ipv4Addr {
        ip(93, 184, 216, 34)
    }

    #[test]
    fn a_pass_chooses_only_the_stale_connection_among_many_kinds() {
        let me = ip(192, 168, 1, 20);
        let rows = [
            row(5, me, 50_000, public(), 4000),                // stale: ended
            row(5, ip(172, 19, 0, 1), 50_001, public(), 4000), // already on the tunnel
            row(5, me, 50_002, ip(192, 168, 1, 1), 4000), // the router: the system keeps it on the card
            row(5, me, 50_003, public(), 111),            // the product's own
            row(2, me, 3389, ip(0, 0, 0, 0), 900),        // listening
            row(5, me, 3389, ip(8, 8, 8, 8), 900),        // somebody's remote session in
            row(11, me, 50_004, public(), 4000),          // finished
        ];
        let selection = select(
            &rows,
            &keep(),
            |remote| remote == public(), // only the public address would go into the tunnel
            || false,
        );
        assert_eq!(selection.to_end, vec![rows[0]]);
        assert!(!selection.stopped_early);
    }

    #[test]
    fn a_route_that_cannot_be_found_ends_nothing() {
        let rows = [row(5, ip(192, 168, 1, 20), 50_000, public(), 4000)];
        let selection = select(&rows, &keep(), |_| false, || false);
        assert!(selection.to_end.is_empty());
        assert_eq!(selection.examined, 1);
    }

    #[test]
    fn the_system_is_asked_once_per_remote_address_however_many_connections_there_are() {
        let me = ip(192, 168, 1, 20);
        let rows: Vec<_> = (0..40u16)
            .map(|i| row(5, me, 50_000 + i, public(), 4000))
            .collect();
        let mut questions = 0;
        let selection = select(
            &rows,
            &keep(),
            |_| {
                questions += 1;
                true
            },
            || false,
        );
        assert_eq!(questions, 1);
        assert_eq!(selection.to_end.len(), 40);
    }

    #[test]
    fn a_connection_that_could_never_be_ended_costs_no_question() {
        let me = ip(192, 168, 1, 20);
        let rows = [
            row(5, me, 50_000, public(), 111),          // the product's own
            row(2, me, 3389, ip(0, 0, 0, 0), 900),      // listening
            row(5, me, 50_001, ip(127, 0, 0, 1), 4000), // this computer
        ];
        let mut questions = 0;
        select(
            &rows,
            &keep(),
            |_| {
                questions += 1;
                true
            },
            || false,
        );
        assert_eq!(questions, 0);
    }

    #[test]
    fn a_pass_asks_no_more_than_the_budget_and_says_it_stopped() {
        let me = ip(192, 168, 1, 20);
        // More distinct remote addresses than the budget allows.
        let rows: Vec<_> = (0..(MAX_QUESTIONS as u32 + 50))
            .map(|i| {
                let remote = Ipv4Addr::from(0x5DB8_0000 + i); // 93.184.x.y: public
                row(5, me, 40_000, remote, 4000)
            })
            .collect();
        let mut questions = 0;
        let selection = select(
            &rows,
            &keep(),
            |_| {
                questions += 1;
                true
            },
            || false,
        );
        assert_eq!(questions, MAX_QUESTIONS);
        assert!(selection.stopped_early);
        assert_eq!(selection.to_end.len(), MAX_QUESTIONS);
    }

    #[test]
    fn a_pass_that_is_out_of_time_stops_and_says_so() {
        let me = ip(192, 168, 1, 20);
        let rows: Vec<_> = (0..10u32)
            .map(|i| row(5, me, 40_000, Ipv4Addr::from(0x5DB8_0000 + i), 4000))
            .collect();
        let mut turns = 0;
        let selection = select(
            &rows,
            &keep(),
            |_| true,
            || {
                turns += 1;
                turns > 3
            },
        );
        assert!(selection.stopped_early);
        assert_eq!(selection.to_end.len(), 3);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn any_ip() -> impl Strategy<Value = Ipv4Addr> {
            any::<u32>().prop_map(Ipv4Addr::from)
        }

        proptest! {
            /// The one promise that matters most: a connection a new one would keep on the card is never ended.
            #[test]
            fn nothing_that_stays_on_the_card_is_ever_ended(
                state in 0u32..20, local in any_ip(), remote in any_ip(), owner in any::<u32>()
            ) {
                let flow = TcpFlow {
                    state: TcpState::from_code(state),
                    local,
                    remote,
                    owner,
                    accepted: false,
                    would_use_tunnel: false,
                };
                prop_assert!(!should_end(&flow, &Keep::default()));
            }

            /// Nothing the carrier needs: its server is never ended whatever else is true.
            #[test]
            fn the_carriers_server_is_never_ended(
                state in 0u32..20, local in any_ip(), server in any_ip(), tunnel_route in any::<bool>()
            ) {
                let flow = TcpFlow {
                    state: TcpState::from_code(state),
                    local,
                    remote: server,
                    owner: 7,
                    accepted: false,
                    would_use_tunnel: tunnel_route,
                };
                let keep = Keep { servers: vec![server], ..Keep::default() };
                prop_assert!(!should_end(&flow, &keep));
            }

            /// Nothing the product's own programs hold is ever ended, whatever else is true.
            #[test]
            fn what_the_products_programs_hold_is_never_ended(
                state in 0u32..20, local in any_ip(), remote in any_ip(), owner in any::<u32>(),
                tunnel_route in any::<bool>()
            ) {
                let flow = TcpFlow {
                    state: TcpState::from_code(state),
                    local,
                    remote,
                    owner,
                    accepted: false,
                    would_use_tunnel: tunnel_route,
                };
                let keep = Keep { ours: vec![owner], ..Keep::default() };
                prop_assert!(!should_end(&flow, &keep));
            }

            /// Nothing on the tunnel's own address is ever ended.
            #[test]
            fn what_is_already_on_the_tunnel_is_never_ended(
                state in 0u32..20, remote in any_ip(), tunnel in any_ip()
            ) {
                let flow = TcpFlow {
                    state: TcpState::from_code(state),
                    local: tunnel,
                    remote,
                    owner: 5,
                    accepted: false,
                    would_use_tunnel: true,
                };
                let keep = Keep { tunnel: vec![tunnel], ..Keep::default() };
                prop_assert!(!should_end(&flow, &keep));
            }

            /// Nothing to this computer, and no multicast, whatever the rest says: the whole of 127/8 and 224/4.
            #[test]
            fn this_computer_and_multicast_are_never_ended(
                host in 0u32..0x0100_0000, group in 0u32..0x1000_0000, local in any_ip()
            ) {
                for remote in [
                    Ipv4Addr::from(0x7F00_0000 | host),
                    Ipv4Addr::from(0xE000_0000 | group),
                ] {
                    let flow = TcpFlow {
                        state: TcpState::Established,
                        local,
                        remote,
                        owner: 5,
                        accepted: false,
                        would_use_tunnel: true,
                    };
                    prop_assert!(!should_end(&flow, &Keep::default()), "{remote}");
                }
            }

            /// A whole pass never ends a row that the single-row decision would keep.
            #[test]
            fn a_pass_agrees_with_the_decision_for_every_row(
                words in proptest::collection::vec(any::<u32>(), 0..120), tunnel_route in any::<bool>()
            ) {
                let rows = parse_tcp_table(&words);
                let keep = Keep { tunnel: vec![ip(172, 19, 0, 1)], servers: vec![ip(203, 0, 113, 9)], ours: vec![1, 2] };
                let selection = select(&rows, &keep, |_| tunnel_route, || false);
                let listening: HashSet<u16> = rows.iter()
                    .filter(|r| TcpState::from_code(r.state) == TcpState::Listen)
                    .map(|r| port_of(r.local_port)).collect();
                for ended in &selection.to_end {
                    let flow = TcpFlow {
                        state: TcpState::from_code(ended.state),
                        local: address_of(ended.local_addr),
                        remote: address_of(ended.remote_addr),
                        owner: ended.owner,
                        accepted: listening.contains(&port_of(ended.local_port)),
                        would_use_tunnel: tunnel_route,
                    };
                    prop_assert!(should_end(&flow, &keep));
                }
            }

            /// The table reader never reads past its buffer, whatever count it is told.
            #[test]
            fn a_table_is_never_read_past_its_buffer(words in proptest::collection::vec(any::<u32>(), 0..64)) {
                let rows = parse_tcp_table(&words);
                prop_assert!(rows.len() * ROW_WORDS < words.len().max(1));
            }
        }
    }
}
