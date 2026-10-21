//! T136 — the first hop: an echo to a path's gateway.
//!
//! The one measurement that needs no cooperation from the endpoint, the tunnel or the far network:
//! a gateway is on the same link, and the link is where weak Wi-Fi, a saturated access point and a
//! dropped association show first. It cannot say whether the internet beyond is reachable (that is
//! what the endpoint probe is for), and many gateways do not answer echoes at all, so `probe_plan`
//! treats a gateway that has never answered as unmeasurable rather than as down.
//!
//! **No pinning is needed.** A gateway is on-link on exactly one adapter's subnet, so an echo to it
//! can only leave through that adapter, whatever the default route says.
//!
//! The Windows ICMP helper (`IcmpSendEcho`) works for an unprivileged process and blocks, so the
//! call runs on a blocking thread and is bounded by its own timeout.

#[cfg(windows)]
pub use windows_echo::echo_gateway;

#[cfg(windows)]
mod windows_echo {
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dnet_core::probe_plan::Observation;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    use crate::error::NetstateError;

    /// `IP_SUCCESS`: the reply is an echo reply, not an error from a router on the way.
    const IP_SUCCESS: u32 = 0;

    /// The payload of the echo: 32 bytes, the size `ping` uses.
    const PAYLOAD: [u8; 32] = *b"abcdefghijklmnopqrstuvwabcdefghi";

    /// One echo to `gateway`. `Silent` covers no reply in time and an error reply (unreachable, TTL
    /// exceeded): neither shows a working first hop. `Err` is only for being unable to ask at all.
    pub async fn echo_gateway(
        gateway: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Observation, NetstateError> {
        tokio::task::spawn_blocking(move || echo_blocking(gateway, timeout))
            .await
            .map_err(|_| NetstateError::Operation("the echo task was cancelled".to_owned()))?
    }

    fn echo_blocking(gateway: Ipv4Addr, timeout: Duration) -> Result<Observation, NetstateError> {
        // SAFETY: no arguments; the handle is closed on every path below.
        let handle = unsafe { IcmpCreateFile() }.map_err(|e| {
            NetstateError::Operation(format!("could not open an echo handle ({e})"))
        })?;

        // Room for one reply, the echoed payload, and the 8 bytes of ICMP error the API may append.
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 64];
        let wait_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        // The address as the API wants it: the four octets in memory order.
        let destination = u32::from_ne_bytes(gateway.octets());

        // SAFETY: `PAYLOAD` and `reply` are live buffers of the lengths passed; the call blocks
        // until it returns, so neither is used after being freed.
        let replies = unsafe {
            IcmpSendEcho(
                handle,
                destination,
                PAYLOAD.as_ptr() as *const c_void,
                PAYLOAD.len() as u16,
                None,
                reply.as_mut_ptr() as *mut c_void,
                reply.len() as u32,
                wait_ms,
            )
        };
        // SAFETY: the handle was created above and is not used again.
        let _ = unsafe { IcmpCloseHandle(handle) };

        if replies == 0 {
            return Ok(Observation::Silent);
        }
        // SAFETY: the API wrote at least one `ICMP_ECHO_REPLY` at the start of `reply`; read
        // unaligned because a byte buffer makes no promise about alignment.
        let echo: ICMP_ECHO_REPLY =
            unsafe { std::ptr::read_unaligned(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
        if echo.Status == IP_SUCCESS {
            Ok(Observation::Answered(Duration::from_millis(u64::from(
                echo.RoundTripTime,
            ))))
        } else {
            Ok(Observation::Silent)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn the_loopback_address_answers_an_echo() {
            let seen = echo_gateway(Ipv4Addr::LOCALHOST, Duration::from_secs(2))
                .await
                .unwrap();
            assert!(matches!(seen, Observation::Answered(_)), "{seen:?}");
        }

        /// The unspecified address is no host: whatever the system makes of it, it is not a first
        /// hop that answered.
        #[tokio::test]
        async fn the_unspecified_address_is_never_an_answer() {
            let seen = echo_gateway(Ipv4Addr::UNSPECIFIED, Duration::from_millis(500)).await;
            assert!(!matches!(seen, Ok(Observation::Answered(_))), "{seen:?}");
        }
    }
}
