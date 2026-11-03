//! T169 step d — who is listening on a local port, asked of the operating system.
//!
//! The service sends the core's control secret to a loopback port it chose a moment before the core bound it
//! (`session_switch::pick_control_port`). Another program on the machine could take that port in between, and on
//! Windows a second bind can succeed when the other program asks for address reuse. The secret would then go to it.
//! So before the first request the service asks the system which process listens on the port, and sends nothing
//! unless **every** listener that a connection to `127.0.0.1:port` could reach belongs to the core it started.
//!
//! The parsing of the system's table is a pure function (tested on any machine, including with a buffer that lies
//! about its own length); only the call that fetches the table is Windows-only.

use std::net::Ipv4Addr;

/// One row of the system's table of listening IPv4 sockets that this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    pub address: Ipv4Addr,
    pub port: u16,
    pub process: u32,
}

/// The size of one row of `MIB_TCPTABLE_OWNER_PID`: state, local address, local port, remote address, remote
/// port, owning process: six 32-bit values.
const ROW: usize = 24;
/// The most rows read, so a table that claims millions cannot make the service build a huge list. A machine does
/// not listen on that many ports.
const MAX_ROWS: usize = 65_536;

/// Read a `MIB_TCPTABLE_OWNER_PID` buffer: a count, then that many rows. A count larger than the buffer holds is
/// read as far as the buffer goes and no further.
pub fn parse_listener_table(buffer: &[u8]) -> Vec<Listener> {
    let Some(count) = buffer
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    else {
        return Vec::new();
    };
    let rows = &buffer[4..];
    let available = rows.len() / ROW;
    let count = (count as usize).min(available).min(MAX_ROWS);
    (0..count)
        .map(|i| {
            let row = &rows[i * ROW..(i + 1) * ROW];
            let word = |n: usize| u32::from_le_bytes(row[n * 4..n * 4 + 4].try_into().unwrap());
            Listener {
                // Stored in network order: the first octet is the lowest byte.
                address: Ipv4Addr::from(word(1).to_le_bytes()),
                // The low 16 bits, in network order.
                port: u16::from_be((word(2) & 0xffff) as u16),
                process: word(5),
            }
        })
        .collect()
}

/// The processes that listen where a connection to `127.0.0.1:port` could arrive: sockets bound to the loopback
/// address or to every address.
pub fn processes_reachable_on_loopback(table: &[Listener], port: u16) -> Vec<u32> {
    table
        .iter()
        .filter(|l| {
            l.port == port && (l.address == Ipv4Addr::LOCALHOST || l.address.is_unspecified())
        })
        .map(|l| l.process)
        .collect()
}

/// Whether the core `process` is the only thing that a connection to `127.0.0.1:port` can reach. False when
/// nothing listens (the core is not up yet, or has gone), and false when anything else does as well.
pub fn only_this_process_listens(table: &[Listener], port: u16, process: u32) -> bool {
    let owners = processes_reachable_on_loopback(table, port);
    !owners.is_empty() && owners.iter().all(|owner| *owner == process)
}

/// The system's table of listening IPv4 sockets. Windows only; elsewhere it is empty, which reads as "nothing is
/// known to listen" and so as a refusal.
#[cfg(windows)]
pub fn listening_sockets() -> std::io::Result<Vec<Listener>> {
    use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut size = 0u32;
    // The first call only reports the size; the table can grow between the two calls, so the second is retried.
    // SAFETY: a null table with a size pointer is the documented way to ask for the size.
    let mut status = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            u32::from(AF_INET.0),
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    for _ in 0..5 {
        if status != ERROR_INSUFFICIENT_BUFFER.0 && status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        // Room to spare for rows added meanwhile.
        let mut buffer = vec![0u8; size as usize + 4096];
        let mut given = buffer.len() as u32;
        // SAFETY: `buffer` is `given` bytes long and lives across the call.
        status = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &mut given,
                false,
                u32::from(AF_INET.0),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == 0 {
            buffer.truncate(given as usize);
            return Ok(parse_listener_table(&buffer));
        }
        size = given;
    }
    Err(std::io::Error::other(
        "the table of listening sockets kept growing",
    ))
}

#[cfg(not(windows))]
pub fn listening_sockets() -> std::io::Result<Vec<Listener>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table as the system lays it out: a count, then rows.
    fn table(rows: &[(Ipv4Addr, u16, u32)]) -> Vec<u8> {
        let mut out = (rows.len() as u32).to_le_bytes().to_vec();
        for (address, port, process) in rows {
            out.extend_from_slice(&2u32.to_le_bytes()); // state: listening
            out.extend_from_slice(&address.octets()); // local address, network order
            out.extend_from_slice(&u32::from(port.to_be()).to_le_bytes()); // local port
            out.extend_from_slice(&0u32.to_le_bytes()); // remote address
            out.extend_from_slice(&0u32.to_le_bytes()); // remote port
            out.extend_from_slice(&process.to_le_bytes());
        }
        out
    }

    const LOOP: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    #[test]
    fn a_table_is_read_row_by_row() {
        let parsed =
            parse_listener_table(&table(&[(LOOP, 29090, 4242), (ANY, 80, 4), (LAN, 443, 99)]));
        assert_eq!(
            parsed,
            vec![
                Listener {
                    address: LOOP,
                    port: 29090,
                    process: 4242
                },
                Listener {
                    address: ANY,
                    port: 80,
                    process: 4
                },
                Listener {
                    address: LAN,
                    port: 443,
                    process: 99
                },
            ]
        );
    }

    #[test]
    fn a_buffer_that_is_empty_short_or_lying_about_its_length_never_reads_past_its_end() {
        assert!(parse_listener_table(&[]).is_empty());
        assert!(parse_listener_table(&[1, 0]).is_empty());
        // Claims a million rows, holds two.
        let mut lying = table(&[(LOOP, 1, 1), (LOOP, 2, 2)]);
        lying[..4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert_eq!(parse_listener_table(&lying).len(), 2);
        // Claims two rows, holds one and a half.
        let mut half = table(&[(LOOP, 1, 1), (LOOP, 2, 2)]);
        half.truncate(4 + ROW + ROW / 2);
        half[..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse_listener_table(&half).len(), 1);
        // The biggest possible claim.
        let mut huge = table(&[(LOOP, 1, 1)]);
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_listener_table(&huge).len(), 1);
    }

    #[test]
    fn only_the_core_listening_on_the_port_passes() {
        let core = 4242;
        // The core alone, on the loopback address.
        assert!(only_this_process_listens(
            &parse_listener_table(&table(&[(LOOP, 29090, core)])),
            29090,
            core
        ));
        // Nothing listens: the core is not up, or is gone.
        assert!(!only_this_process_listens(&[], 29090, core));
        // Something else listens on the same loopback port.
        for rows in [
            vec![(LOOP, 29090, 666)],
            vec![(LOOP, 29090, core), (LOOP, 29090, 666)],
            // A listener on every address would receive the connection too.
            vec![(LOOP, 29090, core), (ANY, 29090, 666)],
            vec![(ANY, 29090, 666)],
        ] {
            assert!(
                !only_this_process_listens(&parse_listener_table(&table(&rows)), 29090, core),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn listeners_a_loopback_connection_cannot_reach_do_not_count() {
        let core = 4242;
        // Another program on a LAN address, or on another port, is not where the secret would go.
        let rows = [
            (LOOP, 29090, core),
            (LAN, 29090, 666),
            (LOOP, 29091, 666),
            (ANY, 80, 4),
        ];
        assert!(only_this_process_listens(
            &parse_listener_table(&table(&rows)),
            29090,
            core
        ));
    }

    #[test]
    fn the_port_is_read_in_the_right_byte_order() {
        // 29090 is 0x71A2; read the wrong way round it would be 0xA271 = 41585.
        let parsed = parse_listener_table(&table(&[(LOOP, 29090, 1)]));
        assert_eq!(parsed[0].port, 29090);
        assert_ne!(parsed[0].port, 29090u16.swap_bytes());
    }

    #[cfg(windows)]
    #[test]
    fn the_real_table_names_this_process_as_the_owner_of_a_port_it_listens_on() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let table = listening_sockets().expect("the system's table");
        assert!(
            only_this_process_listens(&table, port, std::process::id()),
            "{:?}",
            processes_reachable_on_loopback(&table, port)
        );
        // And it is not someone else.
        assert!(!only_this_process_listens(
            &table,
            port,
            std::process::id().wrapping_add(1)
        ));
        drop(listener);
        let after = listening_sockets().unwrap();
        assert!(!only_this_process_listens(&after, port, std::process::id()));
    }
}
