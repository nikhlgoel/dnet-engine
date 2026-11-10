//! T162 — "the machine woke up", from the system's own power messages.
//!
//! The service control handler runs on a thread of the system's, not in the async world, and the
//! network watches live and die with each tunnel. This is the small seam between them: the handler
//! calls [`announce`], and each watch holds a [`Resumes`] from [`subscribe`] and waits on it. It is a
//! counter, so an announcement is never lost between two looks, and several announcements while a
//! watch is busy are one wake-up, which is all a re-read of the network needs.
//!
//! The power messages are one of two signals. They are not relied on alone, because on Modern
//! Standby they are not dependable; the tick-gap detector (`dnet_core::tick_gap`) is the other, and
//! either one makes the loop look at the network again.

use std::sync::OnceLock;

use tokio::sync::{mpsc, watch};

use crate::session_switch::{nudge, NudgePlan, SessionProbe};

/// Where resumes are announced and listened for. One lives for the whole process ([`announce`] and
/// [`subscribe`] use it); a test makes its own, so tests never hear each other.
pub struct Hub(watch::Sender<u64>);

impl Hub {
    pub fn new() -> Self {
        Self(watch::channel(0).0)
    }

    /// Say that the machine resumed. Safe to call from any thread, at any time, any number of times.
    pub fn announce(&self) {
        self.0.send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Start listening. Resumes announced before this call are not seen: a watch starts after the
    /// network was last looked at.
    pub fn subscribe(&self) -> Resumes {
        Resumes(self.0.subscribe())
    }
}

fn hub() -> &'static Hub {
    static HUB: OnceLock<Hub> = OnceLock::new();
    HUB.get_or_init(Hub::new)
}

/// [`Hub::announce`] on the process's hub.
#[cfg_attr(not(windows), allow(dead_code))] // the service control handler is Windows-only
pub fn announce() {
    hub().announce();
}

/// [`Hub::subscribe`] on the process's hub.
#[cfg_attr(not(windows), allow(dead_code))] // the Windows network watch is the one caller
pub fn subscribe() -> Resumes {
    hub().subscribe()
}

/// How hard to try to wake the session after a resume: the carrier's connection may have died in
/// the sleep and have to be made again, which takes longer than a switch does.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn nudge_plan_after_resume() -> NudgePlan {
    NudgePlan {
        every: std::time::Duration::from_millis(500),
        within: std::time::Duration::from_secs(30),
    }
}

/// On every resume: make the network watch look again (`changes`), and, when the connection is a
/// session, send small connection attempts through it until one is answered, so a carrier that died
/// in the sleep is made again at once and not at the next thing the person tries. Ends when the
/// watch is gone.
#[cfg_attr(not(windows), allow(dead_code))]
pub async fn forward_resumes<P: SessionProbe>(
    mut resumes: Resumes,
    changes: mpsc::Sender<()>,
    probe: Option<P>,
    plan: NudgePlan,
) {
    loop {
        tokio::select! {
            () = changes.closed() => return,
            woke = resumes.next() => match woke {
                Some(()) => {
                    // Full means a look is already waiting, which is as good.
                    let _ = changes.try_send(());
                    if let Some(probe) = &probe {
                        let outcome = nudge(probe, plan).await;
                        tracing::info!(?outcome, "the session was nudged after the machine resumed");
                    }
                }
                None => return,
            },
        }
    }
}

/// A way to wait for the next resume.
pub struct Resumes(watch::Receiver<u64>);

impl Resumes {
    /// Wait for a resume. Cancel-safe. `None` never happens while the process lives; the type keeps
    /// the caller honest about a closed channel anyway.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub async fn next(&mut self) -> Option<()> {
        self.0.changed().await.ok()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn woke(resumes: &mut Resumes, within: Duration) -> bool {
        tokio::time::timeout(within, resumes.next()).await == Ok(Some(()))
    }

    #[tokio::test(start_paused = true)]
    async fn a_resume_wakes_a_subscriber() {
        let hub = Hub::new();
        let mut resumes = hub.subscribe();
        hub.announce();
        assert!(woke(&mut resumes, Duration::from_secs(1)).await);
    }

    /// The process's own hub, which the service control handler and every network watch use: what one announces,
    /// the other hears.
    #[tokio::test(start_paused = true)]
    async fn the_process_wide_announcement_reaches_the_process_wide_subscriber() {
        let mut resumes = subscribe();
        announce();
        assert!(woke(&mut resumes, Duration::from_secs(1)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_wakes_a_subscriber_that_was_not_announced_to() {
        let hub = Hub::new();
        let mut resumes = hub.subscribe();
        assert!(!woke(&mut resumes, Duration::from_secs(60)).await);
    }

    /// A resume announced while the watch is busy is not lost, and a burst of them is one wake-up.
    #[tokio::test(start_paused = true)]
    async fn announcements_made_while_busy_are_kept_and_coalesce() {
        let hub = Hub::new();
        let mut resumes = hub.subscribe();
        hub.announce();
        hub.announce();
        hub.announce();
        assert!(woke(&mut resumes, Duration::from_secs(1)).await);
        assert!(
            !woke(&mut resumes, Duration::from_secs(1)).await,
            "three announcements are one wake-up"
        );
        // And the next resume after that is seen again.
        hub.announce();
        assert!(woke(&mut resumes, Duration::from_secs(1)).await);
    }

    /// A watch that starts after a resume does not wake for it: the network was read after it.
    #[tokio::test(start_paused = true)]
    async fn a_resume_before_subscribing_is_not_seen() {
        let hub = Hub::new();
        hub.announce();
        let mut resumes = hub.subscribe();
        assert!(!woke(&mut resumes, Duration::from_secs(1)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn every_subscriber_hears_it() {
        let hub = Hub::new();
        let (mut a, mut b) = (hub.subscribe(), hub.subscribe());
        hub.announce();
        assert!(woke(&mut a, Duration::from_secs(1)).await);
        assert!(woke(&mut b, Duration::from_secs(1)).await);
    }

    // ------------------------------------------------------------------ forwarding

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A session that answers only from the `answers_from`th attempt on, counting every attempt.
    struct Session {
        attempts: Arc<AtomicU32>,
        answers_from: u32,
    }

    impl SessionProbe for Session {
        async fn attempt(&self) -> bool {
            self.attempts.fetch_add(1, Ordering::SeqCst) + 1 >= self.answers_from
        }
    }

    fn quick() -> NudgePlan {
        NudgePlan {
            every: Duration::from_millis(100),
            within: Duration::from_secs(2),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_resume_makes_the_watch_look_again_and_nudges_the_session_until_it_answers() {
        let hub = Hub::new();
        let (tx, mut rx) = mpsc::channel(1);
        let attempts = Arc::new(AtomicU32::new(0));
        let probe = Session {
            attempts: Arc::clone(&attempts),
            answers_from: 4,
        };
        let task = tokio::spawn(forward_resumes(hub.subscribe(), tx, Some(probe), quick()));

        hub.announce();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv()).await,
            Ok(Some(()))
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        // It stopped at the first answer: four attempts, not twenty.
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        task.abort();
    }

    /// Without a session (the other kinds of connection) a resume only makes the watch look again.
    #[tokio::test(start_paused = true)]
    async fn with_no_session_a_resume_only_makes_the_watch_look() {
        let hub = Hub::new();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(forward_resumes::<Session>(
            hub.subscribe(),
            tx,
            None,
            quick(),
        ));
        hub.announce();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv()).await,
            Ok(Some(()))
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_never_answers_is_given_up_on_within_the_plan() {
        let hub = Hub::new();
        let (tx, mut rx) = mpsc::channel(1);
        let attempts = Arc::new(AtomicU32::new(0));
        let probe = Session {
            attempts: Arc::clone(&attempts),
            answers_from: u32::MAX,
        };
        let task = tokio::spawn(forward_resumes(hub.subscribe(), tx, Some(probe), quick()));
        hub.announce();
        rx.recv().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        let tried = attempts.load(Ordering::SeqCst);
        assert!(
            (10..=25).contains(&tried),
            "{tried} attempts in a 2 s plan every 100 ms"
        );
        // And it is ready for the next resume.
        hub.announce();
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(attempts.load(Ordering::SeqCst) > tried);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_forwarder_ends_when_the_watch_is_gone() {
        let hub = Hub::new();
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(forward_resumes::<Session>(
            hub.subscribe(),
            tx,
            None,
            quick(),
        ));
        drop(rx);
        assert!(tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .is_ok());
    }

    #[test]
    fn the_real_plan_waits_long_enough_for_a_carrier_to_be_made_again() {
        let plan = nudge_plan_after_resume();
        assert!(plan.within >= Duration::from_secs(20));
        assert!(plan.every >= Duration::from_millis(250));
    }
}
