//! T080 — learning that the network changed, without polling (research.md §R9).
//!
//! Windows tells a program when interfaces, addresses or routes change; asking every few seconds
//! would be slower to notice and a steady cost while idle (SC-014). Two pieces:
//!
//! - [`settled`], portable and pure: one real change arrives as a burst of events (a Wi-Fi roam can
//!   raise a dozen in a few hundred milliseconds), and acting on each would make the machine look
//!   unstable to the failover logic. `settled` waits for the burst to go quiet and reports it once.
//! - [`ChangeSource`], Windows only: registers with the IP Helper API and turns each callback into
//!   a unit signal on a channel. The callback runs on a system thread and does nothing but that
//!   signal. It holds no lock, allocates nothing and never blocks, because Windows runs it inside
//!   its own notification machinery.
//!
//! The signal carries no detail. What changed is found by looking at the machine afterwards
//! (`paths`); a notification only says that it is worth looking.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

/// How long the network must stay quiet before a burst counts as over.
pub const QUIET: Duration = Duration::from_millis(750);

/// The longest a burst is waited out. A network that never stops changing is reported anyway.
pub const LONGEST: Duration = Duration::from_secs(5);

/// What one settled burst looked like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    /// How many raw events the burst held.
    pub events: u32,
    /// Whether the burst was cut off at the longest wait while still going.
    pub cut_off: bool,
}

/// Wait for a change, then for the burst it belongs to to go quiet.
///
/// Returns `None` only when the source has closed and nothing was waiting. Events that arrive after
/// this returns belong to the next call. A source that closes in the middle of a burst still
/// reports the burst: the change happened.
pub async fn settled(
    events: &mut mpsc::Receiver<()>,
    quiet: Duration,
    longest: Duration,
) -> Option<Settled> {
    events.recv().await?;
    let hard_stop = Instant::now() + longest;
    let mut count = 1u32;
    loop {
        let quiet_until = (Instant::now() + quiet).min(hard_stop);
        tokio::select! {
            more = events.recv() => match more {
                Some(()) => count = count.saturating_add(1),
                None => return Some(Settled { events: count, cut_off: false }),
            },
            () = sleep_until(quiet_until) => {
                let cut_off = Instant::now() >= hard_stop;
                return Some(Settled { events: count, cut_off });
            }
        }
    }
}

// ------------------------------------------------------------------ the Windows source

#[cfg(windows)]
pub use windows_source::ChangeSource;

#[cfg(windows)]
mod windows_source {
    use std::ffi::c_void;

    use tokio::sync::mpsc;
    use windows::Win32::Foundation::{BOOLEAN, HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2,
        NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    use crate::error::NetstateError;

    /// What the callbacks reach. Leaked on purpose, see [`ChangeSource::start`].
    struct Context {
        tx: mpsc::Sender<()>,
    }

    /// The whole callback: say "something changed" and return. `try_send` never blocks, and a full
    /// channel means a signal is already waiting, so dropping this one loses nothing.
    unsafe fn signal(context: *const c_void) {
        // SAFETY: `context` is the pointer `start` passed, which is never freed.
        if let Some(context) = unsafe { (context as *const Context).as_ref() } {
            let _ = context.tx.try_send(());
        }
    }

    unsafe extern "system" fn on_interface(
        context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        unsafe { signal(context) }
    }

    unsafe extern "system" fn on_route(
        context: *const c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        unsafe { signal(context) }
    }

    unsafe extern "system" fn on_address(
        context: *const c_void,
        _row: *const MIB_UNICASTIPADDRESS_ROW,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        unsafe { signal(context) }
    }

    /// A registration for interface, route and address changes, both IP families. Dropping it
    /// cancels them.
    pub struct ChangeSource {
        handles: Vec<HANDLE>,
    }

    // SAFETY: a notification handle is an opaque token that `CancelMibChangeNotify2` accepts from
    // any thread; this type holds nothing else.
    unsafe impl Send for ChangeSource {}

    impl ChangeSource {
        /// Start listening. The receiver gets one `()` per callback, coalesced to at most one
        /// waiting; pass it to [`settled`](super::settled).
        ///
        /// The sender the callbacks use is **leaked**: one small allocation per call, and this is
        /// called once per service run. Freeing it would be a use-after-free if Windows were still
        /// inside a callback when `CancelMibChangeNotify2` returned, and a program that tells
        /// the whole machine's networking what to do can afford sixteen bytes.
        pub fn start() -> Result<(Self, mpsc::Receiver<()>), NetstateError> {
            let (tx, rx) = mpsc::channel(1);
            let context: *const Context = Box::into_raw(Box::new(Context { tx }));
            let context = context as *const c_void;
            // Not an initial notification: the caller reads the current state itself.
            let no_initial = BOOLEAN(0);

            let mut source = ChangeSource {
                handles: Vec::with_capacity(3),
            };
            // If a later registration fails, dropping `source` cancels the earlier ones.
            let mut register = |what: &str, call: &dyn Fn(*mut HANDLE) -> u32| {
                let mut handle = HANDLE::default();
                let status = call(&mut handle);
                if status != NO_ERROR.0 {
                    return Err(NetstateError::Operation(format!(
                        "could not subscribe to {what} changes (error {status})"
                    )));
                }
                source.handles.push(handle);
                Ok(())
            };
            // SAFETY: each callback matches its registration's signature, and `context` outlives
            // every callback (it is never freed).
            register("interface", &|h| unsafe {
                NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), Some(context), no_initial, h)
                    .0
            })?;
            register("route", &|h| unsafe {
                NotifyRouteChange2(AF_UNSPEC, Some(on_route), context, no_initial, h).0
            })?;
            register("address", &|h| unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(on_address),
                    Some(context),
                    no_initial,
                    h,
                )
                .0
            })?;
            Ok((source, rx))
        }
    }

    impl Drop for ChangeSource {
        fn drop(&mut self) {
            for handle in self.handles.drain(..) {
                // SAFETY: a handle this type registered and has not cancelled.
                let _ = unsafe { CancelMibChangeNotify2(handle) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: Duration = Duration::from_millis(500);
    const L: Duration = Duration::from_secs(5);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[tokio::test(start_paused = true)]
    async fn one_event_is_reported_once_it_has_been_quiet() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(()).await.unwrap();
        let t0 = Instant::now();

        let got = settled(&mut rx, Q, L).await;

        assert_eq!(
            got,
            Some(Settled {
                events: 1,
                cut_off: false
            })
        );
        assert_eq!(t0.elapsed(), Q);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_is_one_report_made_after_the_last_event() {
        let (tx, mut rx) = mpsc::channel(8);
        let t0 = Instant::now();
        // Six events, at 0, 100, ... 500 ms.
        tokio::spawn(async move {
            for _ in 0..6 {
                tx.send(()).await.unwrap();
                tokio::time::sleep(ms(100)).await;
            }
            // Keep the sender alive past the report.
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let got = settled(&mut rx, Q, L).await.unwrap();

        assert_eq!(got.events, 6);
        assert!(!got.cut_off);
        assert_eq!(
            t0.elapsed(),
            ms(500) + Q,
            "quiet for Q after the last event"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pause_shorter_than_the_quiet_time_does_not_split_a_burst() {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            tx.send(()).await.unwrap();
            tokio::time::sleep(ms(400)).await;
            tx.send(()).await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let got = settled(&mut rx, Q, L).await.unwrap();

        assert_eq!(got.events, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pause_longer_than_the_quiet_time_makes_two_reports() {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            tx.send(()).await.unwrap();
            tokio::time::sleep(ms(700)).await;
            tx.send(()).await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let first = settled(&mut rx, Q, L).await.unwrap();
        let second = settled(&mut rx, Q, L).await.unwrap();

        assert_eq!((first.events, second.events), (1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_that_never_settles_is_reported_at_the_longest_wait() {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            loop {
                if tx.send(()).await.is_err() {
                    return;
                }
                tokio::time::sleep(ms(100)).await;
            }
        });
        let t0 = Instant::now();

        let got = settled(&mut rx, Q, L).await.unwrap();

        assert!(got.cut_off);
        assert_eq!(t0.elapsed(), L);
        assert!(got.events >= 40, "{}", got.events);
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_source_with_nothing_waiting_ends_the_watch() {
        let (tx, mut rx) = mpsc::channel::<()>(8);
        drop(tx);
        assert_eq!(settled(&mut rx, Q, L).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_that_closes_mid_burst_still_reports_the_burst() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(()).await.unwrap();
        tx.send(()).await.unwrap();
        drop(tx);

        let got = settled(&mut rx, Q, L).await;

        assert_eq!(
            got,
            Some(Settled {
                events: 2,
                cut_off: false
            })
        );
        assert_eq!(
            settled(&mut rx, Q, L).await,
            None,
            "and then the watch ends"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_happening_waits_for_ever_rather_than_reporting() {
        let (_tx, mut rx) = mpsc::channel::<()>(8);
        let waited = tokio::time::timeout(Duration::from_secs(3600), settled(&mut rx, Q, L)).await;
        assert!(waited.is_err(), "an idle network is not a change");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// Change and restore the loopback pseudo-interface's metric: a real interface change that
    /// affects nothing anyone routes through. Needs an elevated shell.
    fn flip_loopback_metric() {
        let script = "Set-NetIPInterface -InterfaceIndex 1 -AddressFamily IPv4 -InterfaceMetric 76;                       Set-NetIPInterface -InterfaceIndex 1 -AddressFamily IPv4 -AutomaticMetric Enabled";
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .status()
            .expect("could not start powershell");
        assert!(
            status.success(),
            "changing the loopback metric failed; is this shell elevated?"
        );
    }

    /// Registering, dropping, and doing it again leaves nothing behind and does not crash.
    #[tokio::test]
    async fn registering_and_dropping_over_and_over_is_clean() {
        for _ in 0..50 {
            let (source, receiver) = ChangeSource::start().expect("subscribing needs no elevation");
            drop(source);
            drop(receiver);
        }
    }

    #[tokio::test]
    #[ignore = "changes an interface metric; run elevated: cargo test -p dnet-netstate -- --ignored"]
    async fn a_real_interface_change_is_signalled() {
        let (source, mut receiver) = ChangeSource::start().unwrap();
        // Whatever the machine was doing a moment ago is not what is being tested.
        tokio::time::sleep(Duration::from_millis(500)).await;
        while receiver.try_recv().is_ok() {}

        flip_loopback_metric();

        let got = tokio::time::timeout(
            Duration::from_secs(20),
            settled(&mut receiver, QUIET, LONGEST),
        )
        .await
        .expect("no notification arrived within 20 s of a real interface change");
        assert!(got.is_some_and(|s| s.events >= 1));
        drop(source);
    }

    /// The negative control: once the source is dropped, the same change signals nothing.
    #[tokio::test]
    #[ignore = "changes an interface metric; run elevated: cargo test -p dnet-netstate -- --ignored"]
    async fn nothing_is_signalled_after_the_source_is_dropped() {
        let (source, mut receiver) = ChangeSource::start().unwrap();
        drop(source);
        // Anything already queued before the drop is not a signal from the change.
        while receiver.try_recv().is_ok() {}

        flip_loopback_metric();

        let waited = tokio::time::timeout(
            Duration::from_secs(5),
            settled(
                &mut receiver,
                Duration::from_millis(300),
                Duration::from_secs(2),
            ),
        )
        .await;
        assert!(
            waited.is_err(),
            "a dropped source still signalled: the cancel did nothing"
        );
    }
}
