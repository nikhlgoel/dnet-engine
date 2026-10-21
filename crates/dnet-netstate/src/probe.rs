//! T134 — measuring one path: how long a connection to the user's own endpoint takes through it.
//!
//! The failover logic (T082) decides on smoothed quality (T081), and quality needs samples. A path
//! that is not carrying traffic still has to be measured, or "the other path is better" would be a
//! guess. So the probe leaves through a chosen adapter whatever the routing table prefers:
//!
//! - **Pinned, not routed.** On Windows the socket is pinned to the adapter with `IP_UNICAST_IF`.
//!   A plain connect would follow the default route and measure the carrying path every time, which
//!   is the one thing a probe of a *different* path must not do.
//! - **The user's own endpoint, nothing else.** No project-operated or public host is contacted
//!   (Constitution: no shared infrastructure). The target is a TCP port the endpoint serves.
//! - **A refusal is an answer.** A closed port that sends back a reset proves the host and the path
//!   work, with a real round-trip time, exactly as the reachability check treats it. Silence, or no
//!   route at all through that adapter, is a lost sample.
//!
//! The portable part, [`sample_of`], decides what an outcome means and is tested on its own. The
//! Windows part, [`probe_tcp`], does the pinned connect.

use std::io;
use std::time::Duration;

use dnet_core::quality::PathSample;

/// How long a probe waits for the endpoint before the sample is a loss.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// What came of one connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The connection was made.
    Connected,
    /// The host answered with a refusal: reachable, nothing listening.
    Refused,
    /// Nothing came back in time.
    TimedOut,
    /// It failed another way, such as no route through this adapter.
    Failed,
}

impl ConnectOutcome {
    /// What an I/O error from a connect attempt means.
    pub fn of_error(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => Self::Refused,
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TimedOut,
            _ => Self::Failed,
        }
    }
}

/// The sample an outcome is worth, given how long it took.
pub fn sample_of(outcome: ConnectOutcome, elapsed: Duration) -> PathSample {
    match outcome {
        ConnectOutcome::Connected | ConnectOutcome::Refused => {
            PathSample::Answered { rtt: elapsed }
        }
        ConnectOutcome::TimedOut | ConnectOutcome::Failed => PathSample::Lost,
    }
}

#[cfg(windows)]
pub use windows_probe::{interface_index, probe_tcp};

#[cfg(windows)]
mod windows_probe {
    use std::net::SocketAddrV4;
    use std::os::windows::io::AsRawSocket;
    use std::time::{Duration, Instant};

    use dnet_core::quality::PathSample;
    use tokio::net::TcpSocket;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET};

    use super::{sample_of, ConnectOutcome};
    use crate::error::NetstateError;

    /// The index of the interface with this LUID, if it exists.
    pub fn interface_index(luid: u64) -> Option<u32> {
        let luid = NET_LUID_LH { Value: luid };
        let mut index = 0u32;
        // SAFETY: both pointers are to live locals.
        let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        (status == NO_ERROR && index != 0).then_some(index)
    }

    /// Pin a socket's outbound interface (IPv4: the index, in network byte order).
    fn pin(socket: &TcpSocket, index: u32) -> Result<(), NetstateError> {
        let raw = SOCKET(socket.as_raw_socket() as usize);
        let value = index.to_be_bytes();
        // SAFETY: `raw` is a socket this function's caller owns for the whole call, and `value`
        // is a live four-byte buffer.
        let status = unsafe { setsockopt(raw, IPPROTO_IP.0, IP_UNICAST_IF, Some(&value)) };
        if status == 0 {
            Ok(())
        } else {
            Err(NetstateError::Operation(
                "could not pin the probe to the adapter".to_owned(),
            ))
        }
    }

    /// Time a TCP connection to `target` that leaves through the adapter with LUID `interface`.
    ///
    /// `Err` means the probe could not be set up at all (the adapter is gone, or the socket option
    /// was refused), which is not a measurement of the path and must not be recorded as a loss.
    pub async fn probe_tcp(
        interface: u64,
        target: SocketAddrV4,
        timeout: Duration,
    ) -> Result<PathSample, NetstateError> {
        let index = interface_index(interface)
            .ok_or_else(|| NetstateError::Operation("the adapter no longer exists".to_owned()))?;
        let socket = TcpSocket::new_v4().map_err(|e| {
            NetstateError::Operation(format!("could not open a probe socket ({})", e.kind()))
        })?;
        pin(&socket, index)?;

        let started = Instant::now();
        let outcome = match tokio::time::timeout(timeout, socket.connect(target.into())).await {
            Ok(Ok(_stream)) => ConnectOutcome::Connected,
            Ok(Err(error)) => ConnectOutcome::of_error(&error),
            Err(_) => ConnectOutcome::TimedOut,
        };
        Ok(sample_of(outcome, started.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_connection_and_a_refusal_are_both_answers_with_the_time_they_took() {
        assert_eq!(
            sample_of(ConnectOutcome::Connected, ms(42)),
            PathSample::Answered { rtt: ms(42) }
        );
        assert_eq!(
            sample_of(ConnectOutcome::Refused, ms(18)),
            PathSample::Answered { rtt: ms(18) },
            "a reset proves the host and the path work"
        );
    }

    #[test]
    fn silence_and_a_failed_route_are_lost() {
        assert_eq!(
            sample_of(ConnectOutcome::TimedOut, ms(3000)),
            PathSample::Lost
        );
        assert_eq!(sample_of(ConnectOutcome::Failed, ms(1)), PathSample::Lost);
    }

    #[test]
    fn io_errors_are_classified_by_what_they_say_about_the_far_end() {
        use io::ErrorKind::*;
        for (kind, expected) in [
            (ConnectionRefused, ConnectOutcome::Refused),
            (ConnectionReset, ConnectOutcome::Refused),
            (TimedOut, ConnectOutcome::TimedOut),
            (WouldBlock, ConnectOutcome::TimedOut),
            (NetworkUnreachable, ConnectOutcome::Failed),
            (HostUnreachable, ConnectOutcome::Failed),
            (AddrNotAvailable, ConnectOutcome::Failed),
            (PermissionDenied, ConnectOutcome::Failed),
        ] {
            assert_eq!(
                ConnectOutcome::of_error(&io::Error::from(kind)),
                expected,
                "{kind:?}"
            );
        }
    }

    /// An unreachable network must never read as an answer: it would make a dead path look alive.
    #[test]
    fn no_route_is_never_an_answer() {
        let outcome = ConnectOutcome::of_error(&io::Error::from(io::ErrorKind::NetworkUnreachable));
        assert!(matches!(sample_of(outcome, ms(1)), PathSample::Lost));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

    use super::*;
    use crate::paths;

    /// The loopback pseudo-interface's LUID: always present, needs no network.
    fn loopback() -> u64 {
        let (interfaces, _) = paths::read().unwrap();
        interfaces
            .iter()
            .find(|i| i.name.to_ascii_lowercase().contains("loopback"))
            .expect("every Windows machine has a loopback interface")
            .luid
    }

    #[tokio::test]
    async fn a_listening_port_answers_through_a_pinned_interface() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());

        let sample = probe_tcp(loopback(), target, CONNECT_TIMEOUT)
            .await
            .unwrap();

        assert!(matches!(sample, PathSample::Answered { .. }), "{sample:?}");
    }

    #[tokio::test]
    async fn a_closed_port_is_a_refusal_and_therefore_an_answer() {
        // Bind and drop: the port is closed now.
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);

        let sample = probe_tcp(loopback(), target, CONNECT_TIMEOUT)
            .await
            .unwrap();

        assert!(matches!(sample, PathSample::Answered { .. }), "{sample:?}");
    }

    #[tokio::test]
    async fn an_adapter_that_does_not_exist_is_an_error_not_a_loss() {
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
        // A LUID no adapter has.
        let result = probe_tcp(u64::MAX, target, CONNECT_TIMEOUT).await;
        assert!(
            result.is_err(),
            "a probe that could not be made measured nothing"
        );
    }

    /// The pin must govern the route. Pinned to loopback, a documentation address (TEST-NET-3) has
    /// no route, so the connect fails at once and sends nothing. If the pin did nothing, the connect
    /// would follow the default route and wait out the whole timeout; the two differ by seconds.
    #[tokio::test]
    async fn pinning_to_an_adapter_with_no_route_fails_at_once_instead_of_using_the_default_route()
    {
        let target = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 9);
        let started = std::time::Instant::now();

        let sample = probe_tcp(loopback(), target, Duration::from_millis(2500))
            .await
            .unwrap();

        assert_eq!(sample, PathSample::Lost);
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "took {:?}: the connect was not confined to the pinned adapter",
            started.elapsed()
        );
    }

    #[test]
    fn the_loopback_adapter_has_an_index() {
        assert!(interface_index(loopback()).is_some());
        assert_eq!(interface_index(u64::MAX), None);
    }
}
