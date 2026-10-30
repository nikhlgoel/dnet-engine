//! T148 — while the person has left it on, a connection that failed is tried again (FR-036; spec edge
//! case "the machine sleeps and wakes on a different network").
//!
//! The engine leaves a failed connection failed until someone connects again. With T147 a service that
//! resumes at start-up before the network is up (Wi-Fi often joins only after sign-in) would fail and
//! stay failed, and the person who left it on would find it off. So, while the remembered intent is on
//! and nothing is connected or being connected, the service connects again: after 15 s, then 30 s,
//! 1 min, 2 min, and every 5 min after that; and sooner when the network changes, but not within a
//! minute of the last attempt for that reason, because a failed attempt's own teardown changes the
//! network and must not drive the next one.
//!
//! It connects only through the same orchestrator and the same request a person makes, and only while
//! the intent is on. A person's disconnect forgets the intent under the lock a retry takes, so no retry
//! can follow it.

use std::sync::Weak;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

/// What one look at the service found, and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Not left on, or the service may not connect in this run: nothing to keep trying.
    Idle,
    /// Connected.
    Healthy,
    /// A connection is being made; look again soon, without counting an attempt.
    InProgress,
    /// It was failed or down while left on, and a connect was started.
    Attempted,
}

/// How often to try.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    /// The wait before the first retry, and between looks while nothing needs doing.
    pub first: Duration,
    /// The longest wait between attempts.
    pub cap: Duration,
    /// The shortest time after an attempt that a network change may start another.
    pub min_gap: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            first: Duration::from_secs(15),
            cap: Duration::from_secs(5 * 60),
            min_gap: Duration::from_secs(60),
        }
    }
}

/// The waiting between attempts: doubling from twice `first` to `cap`, back to `first` once healthy (so a
/// connection that drops is retried at the next look, within `first`).
#[derive(Debug, Clone)]
pub struct Backoff {
    pace: Pace,
    delay: Duration,
    last_attempt: Option<Instant>,
}

impl Backoff {
    pub fn new(pace: Pace) -> Self {
        Self {
            pace,
            delay: pace.first,
            last_attempt: None,
        }
    }

    /// How long to wait before the next look, given what this one found.
    pub fn after(&mut self, tick: Tick, now: Instant) -> Duration {
        match tick {
            Tick::Attempted => {
                self.last_attempt = Some(now);
                self.delay = (self.delay * 2).min(self.pace.cap);
                self.delay
            }
            Tick::InProgress => self.pace.first,
            Tick::Healthy | Tick::Idle => {
                self.delay = self.pace.first;
                self.pace.first
            }
        }
    }

    /// Whether a network change at `now` may start an attempt.
    pub fn change_may_retry(&self, now: Instant) -> bool {
        self.last_attempt
            .is_none_or(|last| now.duration_since(last) >= self.pace.min_gap)
    }
}

/// Something that can be asked to retry. The service, in production.
pub trait Retry: Send + Sync {
    fn retry_if_left_on(&self) -> Tick;
}

/// Keep trying for as long as `target` exists. `changes` signals a network change (raw, unsettled);
/// `None` where there is no source of them.
pub async fn run<T: Retry + ?Sized>(
    target: Weak<T>,
    mut changes: Option<mpsc::Receiver<()>>,
    pace: Pace,
) {
    use dnet_netstate::notify::{settled, LONGEST, QUIET};

    let mut backoff = Backoff::new(pace);
    let mut deadline = Instant::now() + pace.first;
    loop {
        let by_change = tokio::select! {
            () = sleep_until(deadline) => false,
            change = async {
                match changes.as_mut() {
                    Some(rx) => settled(rx, QUIET, LONGEST).await,
                    None => std::future::pending().await,
                }
            } => {
                if change.is_none() {
                    // The source has gone; the timer alone carries on.
                    changes = None;
                    continue;
                }
                true
            }
        };
        let now = Instant::now();
        if by_change && !backoff.change_may_retry(now) {
            continue;
        }
        let Some(target) = target.upgrade() else {
            return;
        };
        let tick = target.retry_if_left_on();
        drop(target);
        deadline = now + backoff.after(tick, now);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn attempts_back_off_to_the_cap_and_reset_once_healthy() {
        let now = Instant::now();
        let mut backoff = Backoff::new(Pace::default());
        let waits: Vec<u64> = (0..7)
            .map(|_| backoff.after(Tick::Attempted, now).as_secs())
            .collect();
        assert_eq!(waits, [30, 60, 120, 240, 300, 300, 300]);
        // Looking while a connection is being made neither counts nor resets.
        assert_eq!(backoff.after(Tick::InProgress, now).as_secs(), 15);
        assert_eq!(backoff.after(Tick::Attempted, now).as_secs(), 300);
        assert_eq!(backoff.after(Tick::Healthy, now).as_secs(), 15);
        assert_eq!(backoff.after(Tick::Attempted, now).as_secs(), 30);
        assert_eq!(backoff.after(Tick::Idle, now).as_secs(), 15);
        assert_eq!(backoff.after(Tick::Attempted, now).as_secs(), 30);
    }

    #[test]
    fn a_network_change_may_start_an_attempt_only_a_minute_after_the_last() {
        let start = Instant::now();
        let mut backoff = Backoff::new(Pace::default());
        assert!(backoff.change_may_retry(start));
        backoff.after(Tick::Attempted, start);
        assert!(!backoff.change_may_retry(start + Duration::from_secs(59)));
        assert!(backoff.change_may_retry(start + Duration::from_secs(60)));
    }

    /// A target that records when it was asked and answers from a script.
    struct Scripted {
        answers: Mutex<Vec<Tick>>,
        asked: Mutex<Vec<Duration>>,
        start: Instant,
        calls: AtomicUsize,
    }

    impl Scripted {
        fn new(answers: Vec<Tick>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers),
                asked: Mutex::new(Vec::new()),
                start: Instant::now(),
                calls: AtomicUsize::new(0),
            })
        }
        fn asked_at(&self) -> Vec<u64> {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .map(|d| d.as_secs())
                .collect()
        }
    }

    impl Retry for Scripted {
        fn retry_if_left_on(&self) -> Tick {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.asked.lock().unwrap().push(self.start.elapsed());
            let mut answers = self.answers.lock().unwrap();
            if answers.is_empty() {
                Tick::Attempted
            } else {
                answers.remove(0)
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failing_for_ten_minutes_costs_five_attempts_not_forty() {
        let target = Scripted::new(vec![]);
        let task = tokio::spawn(run(
            Arc::downgrade(&target) as Weak<dyn Retry>,
            None,
            Pace::default(),
        ));
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(target.asked_at(), [15, 45, 105, 225, 465]);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_change_brings_the_next_attempt_forward_but_not_twice_a_minute() {
        let target = Scripted::new(vec![]);
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(run(
            Arc::downgrade(&target) as Weak<dyn Retry>,
            Some(rx),
            Pace::default(),
        ));
        // First attempt at 15 s; the next would be at 45 s.
        tokio::time::sleep(Duration::from_secs(20)).await;
        // A change at 20 s (an attempt's own teardown, say) is too soon after the one at 15 s.
        tx.send(()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(target.asked_at(), [15, 45]);
        // Now at 50 s; the next is due at 105 s.
        tokio::time::sleep(Duration::from_secs(56)).await;
        assert_eq!(target.asked_at(), [15, 45, 105]);
        // The next is due at 225 s. A change at 170 s (65 s after the last) is acted on once it settles.
        tokio::time::sleep(Duration::from_secs(64)).await;
        tx.send(()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let asked = target.asked_at();
        assert_eq!(asked.len(), 4, "{asked:?}");
        assert!((170..=172).contains(&asked[3]), "{asked:?}");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_or_off_is_only_looked_at() {
        let target = Scripted::new(vec![Tick::Idle; 100]);
        let task = tokio::spawn(run(
            Arc::downgrade(&target) as Weak<dyn Retry>,
            None,
            Pace::default(),
        ));
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert_eq!(target.asked_at(), [15, 30, 45, 60]);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn it_stops_when_the_service_is_gone() {
        let target = Scripted::new(vec![]);
        let task = tokio::spawn(run(
            Arc::downgrade(&target) as Weak<dyn Retry>,
            None,
            Pace::default(),
        ));
        drop(target);
        tokio::time::sleep(Duration::from_secs(16)).await;
        assert!(task.is_finished());
    }
}
