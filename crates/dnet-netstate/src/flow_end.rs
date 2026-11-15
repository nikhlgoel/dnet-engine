// SPDX-License-Identifier: GPL-3.0-or-later
//! T203 — end the connections that were open before the tunnel came up and would now be sent into it.
//!
//! The choice of which connections is `dnet_core::flow_end` (pure, tested everywhere); this is the half that asks the
//! system for the facts and carries the choice out. See that module for why, and for what is left alone.
//!
//! **What it calls.** `GetExtendedTcpTable` (every IPv4 TCP connection, with its owner), `GetBestRoute2` (where a new
//! connection to a remote address would go now), `GetUnicastIpAddressTable` (the tunnel's own addresses),
//! `QueryFullProcessImageNameW` (which program holds a connection, to leave the product's own alone) and
//! `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB`, which deletes the connection's control block **without sending
//! anything to the other end**: a reset sent out of the physical card would itself be a packet to the destination,
//! which is what is being stopped. The program that held the connection finds it closed and makes a new one, which
//! goes through the tunnel. `SetTcpEntry` needs administrator rights, which the service has.
//!
//! It never fails a connection: a table that cannot be read ends nothing, an adapter with no address yet ends nothing,
//! a route that cannot be found ends nothing, a pass that runs out of time stops where it is, and a connection that
//! cannot be ended is counted and left.

#![cfg(windows)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dnet_core::flow_end::{parse_tcp_table, select, Keep, RawTcpRow};
use dnet_core::rule_eval::normalize_application;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetExtendedTcpTable, GetUnicastIpAddressTable, SetTcpEntry, MIB_TCPROW_LH,
    MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::error::NetstateError;
use crate::win_route::best_route_to;

/// What one pass did, as counts only: an address of a destination is not something a log should hold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ended {
    /// Connections that were in use and could have been ended.
    pub examined: usize,
    /// Connections ended.
    pub ended: usize,
    /// Connections that should have been ended and could not be.
    pub failed: usize,
    /// Whether the pass stopped before looking at everything (too many remote addresses, or out of time).
    pub stopped_early: bool,
}

/// End every IPv4 TCP connection that a new one would now send into the tunnel (`tunnel_luid`) but which is still on
/// its old address, except what the product's own programs hold (`programs`, by full path, and this process), the
/// carrier's connection to `servers`, and what somebody else opened to this computer. Gives up after `budget`.
pub fn end_direct_connections(
    tunnel_luid: u64,
    servers: &[Ipv4Addr],
    programs: &[PathBuf],
    budget: Duration,
) -> Result<Ended, NetstateError> {
    let started = Instant::now();
    let tunnel = tunnel_addresses(tunnel_luid)?;
    // An adapter with no address yet (the address is assigned a moment after the adapter appears) cannot say which
    // connections are already carried, and every connection made through it since would look stale: end nothing.
    if tunnel.is_empty() {
        return Err(NetstateError::Operation(
            "the tunnel adapter has no IPv4 address yet".to_owned(),
        ));
    }
    let rows = read_tcp_table()?;
    let keep = Keep {
        tunnel,
        servers: servers.to_vec(),
        ours: our_processes(&rows, programs),
    };
    let selection = select(
        &rows,
        &keep,
        // A route that cannot be found is not a reason to cut anything.
        |remote| {
            best_route_to(IpAddr::V4(remote)).is_ok_and(|route| route.interface_luid == tunnel_luid)
        },
        || started.elapsed() >= budget,
    );
    let mut report = Ended {
        examined: selection.examined,
        stopped_early: selection.stopped_early,
        ..Ended::default()
    };
    for row in &selection.to_end {
        if delete_control_block(row) {
            report.ended += 1;
        } else {
            report.failed += 1;
        }
    }
    Ok(report)
}

/// The ids of the processes in the table that are the product's own programs, plus this one.
fn our_processes(rows: &[RawTcpRow], programs: &[PathBuf]) -> Vec<u32> {
    let wanted: HashSet<String> = programs
        .iter()
        .filter_map(|path| path.to_str())
        .map(normalize_application)
        .collect();
    let me = std::process::id();
    let mut ours = vec![me];
    let mut seen: HashSet<u32> = HashSet::new();
    for row in rows {
        if row.owner == me || !seen.insert(row.owner) {
            continue;
        }
        if image_path(row.owner).is_some_and(|path| wanted.contains(&normalize_application(&path)))
        {
            ours.push(row.owner);
        }
    }
    ours
}

/// The full path of the program a process runs, if it can be read (a protected process cannot be, and is then not
/// ours).
fn image_path(process: u32) -> Option<String> {
    if process == 0 {
        return None;
    }
    // SAFETY: a limited-information handle to a process id; closed below on every path.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process) }.ok()?;
    let mut buffer = vec![0u16; 1024];
    let mut length = u32::try_from(buffer.len()).unwrap_or(1024);
    // SAFETY: `buffer` holds `length` UTF-16 units and lives across the call; `handle` is open.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    // SAFETY: `handle` was opened above and is not used again.
    let _ = unsafe { CloseHandle(handle) };
    result.ok()?;
    buffer.truncate(length as usize);
    String::from_utf16(&buffer).ok()
}

/// The system's table of IPv4 TCP connections.
fn read_tcp_table() -> Result<Vec<RawTcpRow>, NetstateError> {
    let mut size = 0u32;
    // The first call only reports the size; the table can grow between the two calls, so the second is retried.
    // SAFETY: a null table with a size pointer is the documented way to ask for the size.
    let mut status = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            u32::from(AF_INET.0),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    for _ in 0..5 {
        if status != ERROR_INSUFFICIENT_BUFFER.0 && status != 0 {
            return Err(NetstateError::Operation(format!(
                "could not list the TCP connections (win32 error {status})"
            )));
        }
        // Whole words, with room to spare for rows added meanwhile.
        let mut words = vec![0u32; (size as usize).div_ceil(4) + 2048];
        let mut given = u32::try_from(words.len() * 4).unwrap_or(u32::MAX);
        // SAFETY: `words` is `given` bytes long, suitably aligned, and lives across the call.
        status = unsafe {
            GetExtendedTcpTable(
                Some(words.as_mut_ptr().cast()),
                &mut given,
                false,
                u32::from(AF_INET.0),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status == 0 {
            words.truncate((given as usize / 4).min(words.len()));
            return Ok(parse_tcp_table(&words));
        }
        size = given;
    }
    Err(NetstateError::Operation(
        "the table of TCP connections kept changing size".to_owned(),
    ))
}

/// The tunnel adapter's own IPv4 addresses.
fn tunnel_addresses(tunnel_luid: u64) -> Result<Vec<Ipv4Addr>, NetstateError> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: `table` is a valid out-pointer; on success it owns a table freed below.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if status != NO_ERROR || table.is_null() {
        return Err(NetstateError::Operation(format!(
            "could not list the addresses of the network cards (win32 error {})",
            status.0
        )));
    }
    let mut found = Vec::new();
    // SAFETY: `table` is non-null and holds `NumEntries` rows after the header; the pointer to the first row is taken
    // from the table's own address, which covers all of them; the rows are read before the table is freed, and the
    // address family of each is checked before the member that goes with it is read.
    unsafe {
        let first = std::ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
        let rows = std::slice::from_raw_parts(first, (*table).NumEntries as usize);
        for row in rows {
            if row.InterfaceLuid.Value == tunnel_luid && row.Address.si_family == AF_INET {
                found.push(Ipv4Addr::from(
                    row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ));
            }
        }
        FreeMibTable(table as *const _);
    }
    Ok(found)
}

/// Delete one connection's control block. True when the system says it is done.
fn delete_control_block(row: &RawTcpRow) -> bool {
    let entry = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            dwState: MIB_TCP_STATE_DELETE_TCB.0 as u32,
        },
        dwLocalAddr: row.local_addr,
        dwLocalPort: row.local_port,
        dwRemoteAddr: row.remote_addr,
        dwRemotePort: row.remote_port,
    };
    // SAFETY: `entry` is a fully initialised row that lives across the call; the call only reads it.
    unsafe { SetTcpEntry(&entry) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnet_core::flow_end::{address_of, port_of, TcpState};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// A connection to this computer, both ends: the client's port and the server's, as the system keeps them.
    fn loopback_pair() -> (TcpStream, TcpStream, u16, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let port = client.local_addr().unwrap().port();
        (client, server, port, server_port)
    }

    fn find_client(rows: &[RawTcpRow], port: u16) -> RawTcpRow {
        *rows
            .iter()
            .find(|row| {
                port_of(row.local_port) == port
                    && address_of(row.local_addr) == Ipv4Addr::LOCALHOST
                    && address_of(row.remote_addr) == Ipv4Addr::LOCALHOST
            })
            .expect("the connection just made is in the table")
    }

    /// The row layout is read right: a real connection made here shows up, established, with both its ports and its
    /// owner where the reader expects them. (If a word were read from the wrong place, this would not find it.)
    #[test]
    fn a_real_connection_is_found_in_the_table_with_its_addresses_ports_and_owner() {
        let (_client, _server, port, server_port) = loopback_pair();
        let rows = read_tcp_table().unwrap();
        let mine = find_client(&rows, port);
        assert_eq!(TcpState::from_code(mine.state), TcpState::Established);
        assert_eq!(port_of(mine.remote_port), server_port);
        assert_eq!(mine.owner, std::process::id());
    }

    /// A process is found by the program it runs, and process 0 is nobody's.
    #[test]
    fn a_process_is_found_by_the_program_it_runs() {
        let me = std::env::current_exe().unwrap();
        let found = image_path(std::process::id()).expect("this process's own path is readable");
        assert_eq!(
            normalize_application(&found),
            normalize_application(me.to_str().unwrap())
        );
        assert_eq!(image_path(0), None);
    }

    /// The owners in the table that run one of the product's programs are found by path; one that does not is not.
    #[test]
    fn the_owners_that_are_the_products_programs_are_found() {
        let (_client, _server, port, _) = loopback_pair();
        let rows = read_tcp_table().unwrap();
        let mine = find_client(&rows, port);
        // The pass's own process is always kept, so a different owner shows the lookup by path: system process 4 is
        // not any program that was named.
        let other = RawTcpRow { owner: 4, ..mine };
        let nobody = our_processes(
            &[other],
            &[PathBuf::from(r"C:\Program Files\Nothing\x.exe")],
        );
        assert!(!nobody.contains(&4));
        assert!(nobody.contains(&std::process::id()));
    }

    /// An adapter that does not exist has no addresses, and a pass that cannot tell which connections are already
    /// carried by the tunnel ends nothing and says why.
    #[test]
    fn a_pass_with_no_tunnel_ends_nothing_and_leaves_a_local_connection_working() {
        let (mut client, mut server, _port, _) = loopback_pair();
        let outcome = end_direct_connections(0, &[], &[], Duration::from_secs(2));
        assert!(outcome.is_err(), "{outcome:?}");
        server.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
    }

    /// The call itself: deleting a connection's control block closes it for the program that holds it. Needs
    /// administrator rights (`SetTcpEntry`), so it runs with `cargo test -- --ignored` in an elevated shell.
    #[test]
    #[ignore = "needs an elevated shell"]
    fn deleting_a_control_block_closes_the_connection_for_its_program() {
        let (mut client, _server, port, _) = loopback_pair();
        let rows = read_tcp_table().unwrap();
        let row = find_client(&rows, port);
        assert!(delete_control_block(&row), "the system refused");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        let outcome = client.read(&mut byte);
        assert!(
            outcome.is_err() || outcome.unwrap() == 0,
            "the connection still works after its control block was deleted"
        );
    }
}
