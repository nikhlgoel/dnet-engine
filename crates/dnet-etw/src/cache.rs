// SPDX-License-Identifier: GPL-3.0-or-later
//! T076 — remembering who connected, for a short while, and nothing more (data-model §7).
//!
//! An attribution is only useful in the moments after the connect that produced it: the program that
//! connected is the program the connection belongs to, and the rule that applies to it is looked up right
//! then. So the cache is short-lived by design:
//!
//! - **Short TTL.** An entry older than [`DEFAULT_TTL`] is not trusted, whether or not it has been evicted
//!   yet. A source port is reused, a process id is reused, and a stale answer is worse than none.
//! - **Bounded.** However fast connections arrive, the cache never holds more than its capacity; the oldest
//!   go first. A burst of connections cannot grow it without limit.
//! - **A miss is "no application rule matched", never a guess.** [`Resolution::NoApplicationRuleMatched`]
//!   is what a lookup that finds nothing returns, and it is exactly what the caller does with it: the
//!   connection is judged by its destination alone. There is no nearest match, no port-only fallback, no
//!   "probably the same program as last time". Only the exact connection (both ends) is recognised.
//!
//! Time is passed in, so every behaviour is tested without waiting.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::attribution::{BestEffortAttribution, FiveTuple};

/// How long an attribution is trusted, in the real cache.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);
/// Most connections remembered at once, in the real cache.
pub const DEFAULT_CAPACITY: usize = 4096;

/// What a lookup comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// A connect event named this program for exactly this connection, recently. Best effort.
    Application(u32),
    /// Nothing is known. Not "the program is unknown": the answer is that **no application rule matches
    /// this connection**, and it is judged by destination.
    NoApplicationRuleMatched,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    pid: u32,
    at: Instant,
}

/// The connections seen recently and the programs that made them.
#[derive(Debug)]
pub struct AttributionCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<FiveTuple, Entry>,
    /// Insertion order, oldest first. A tuple that is seen again is pushed again; the older record is
    /// recognised as stale when it reaches the front (its time no longer matches the entry's).
    order: VecDeque<(FiveTuple, Instant)>,
}

impl Default for AttributionCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }
}

impl AttributionCache {
    /// A cache holding at most `capacity` connections (at least one), each for at most `ttl`.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn expired(&self, at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(at) >= self.ttl
    }

    /// Note an attribution seen at `now`. A connection seen again replaces the earlier answer for it.
    pub fn insert(&mut self, attribution: BestEffortAttribution, now: Instant) {
        self.evict_expired(now);
        // Make room, oldest first. A record whose time no longer matches its entry is a refreshed
        // connection's old record: dropping it frees nothing, so keep going.
        while self.entries.len() >= self.capacity && !self.entries.contains_key(&attribution.tuple)
        {
            let Some((tuple, at)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&tuple).is_some_and(|e| e.at == at) {
                self.entries.remove(&tuple);
            }
        }
        self.entries.insert(
            attribution.tuple,
            Entry {
                pid: attribution.pid,
                at: now,
            },
        );
        self.order.push_back((attribution.tuple, now));
    }

    /// Who made this connection, if a connect event said so recently. Exactly this connection: both ends.
    pub fn resolve(&self, tuple: &FiveTuple, now: Instant) -> Resolution {
        match self.entries.get(tuple) {
            Some(entry) if !self.expired(entry.at, now) => Resolution::Application(entry.pid),
            _ => Resolution::NoApplicationRuleMatched,
        }
    }

    /// Drop everything older than the TTL. Returns how many connections were forgotten.
    pub fn evict_expired(&mut self, now: Instant) -> usize {
        let mut forgotten = 0;
        while let Some((tuple, at)) = self.order.front().copied() {
            if !self.expired(at, now) {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&tuple).is_some_and(|e| e.at == at) {
                self.entries.remove(&tuple);
                forgotten += 1;
            }
        }
        forgotten
    }

    /// How many connections are remembered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A cache shared between the trace's callback thread (which inserts) and whoever looks up.
#[derive(Debug, Clone, Default)]
pub struct SharedCache(Arc<Mutex<AttributionCache>>);

impl SharedCache {
    pub fn new(cache: AttributionCache) -> Self {
        Self(Arc::new(Mutex::new(cache)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AttributionCache> {
        // A panic in the callback thread must not take lookups down with it.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert(&self, attribution: BestEffortAttribution) {
        self.lock().insert(attribution, Instant::now());
    }

    pub fn resolve(&self, tuple: &FiveTuple) -> Resolution {
        self.lock().resolve(tuple, Instant::now())
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn tuple(local_port: u16, remote_port: u16) -> FiveTuple {
        FiveTuple::new(
            SocketAddr::from(([192, 168, 1, 20], local_port)),
            SocketAddr::from(([93, 184, 216, 34], remote_port)),
        )
    }

    fn seen(local_port: u16, pid: u32) -> BestEffortAttribution {
        BestEffortAttribution {
            tuple: tuple(local_port, 443),
            pid,
        }
    }

    const TTL: Duration = Duration::from_secs(10);

    fn cache(capacity: usize) -> AttributionCache {
        AttributionCache::new(TTL, capacity)
    }

    #[test]
    fn a_connection_just_seen_resolves_to_the_program_that_made_it() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 4321), t0);
        assert_eq!(
            c.resolve(&tuple(50000, 443), t0 + Duration::from_secs(1)),
            Resolution::Application(4321)
        );
    }

    #[test]
    fn an_answer_older_than_the_ttl_is_not_trusted_even_before_it_is_evicted() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 4321), t0);
        assert_eq!(c.len(), 1, "still held");
        assert_eq!(
            c.resolve(&tuple(50000, 443), t0 + TTL - Duration::from_millis(1)),
            Resolution::Application(4321)
        );
        assert_eq!(
            c.resolve(&tuple(50000, 443), t0 + TTL),
            Resolution::NoApplicationRuleMatched
        );
        assert_eq!(c.len(), 1, "resolving does not change the cache");
    }

    #[test]
    fn a_miss_is_no_application_rule_matched_never_a_guess() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 4321), t0);
        // Close, but not this connection: another local port, another remote port, another remote host.
        for other in [
            tuple(50001, 443),
            tuple(50000, 444),
            FiveTuple::new(
                SocketAddr::from(([192, 168, 1, 20], 50000)),
                SocketAddr::from(([93, 184, 216, 35], 443)),
            ),
            FiveTuple::new(
                SocketAddr::from(([192, 168, 1, 21], 50000)),
                SocketAddr::from(([93, 184, 216, 34], 443)),
            ),
        ] {
            assert_eq!(c.resolve(&other, t0), Resolution::NoApplicationRuleMatched);
        }
        assert_eq!(
            cache(8).resolve(&tuple(1, 2), t0),
            Resolution::NoApplicationRuleMatched
        );
    }

    #[test]
    fn a_connection_seen_again_replaces_the_earlier_answer() {
        // A port is reused by another program: the newer answer wins.
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 111), t0);
        c.insert(seen(50000, 222), t0 + Duration::from_secs(2));
        assert_eq!(
            c.resolve(&tuple(50000, 443), t0 + Duration::from_secs(3)),
            Resolution::Application(222)
        );
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn seeing_a_connection_again_extends_its_life_and_the_old_record_does_not_evict_it() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 111), t0);
        c.insert(seen(50000, 111), t0 + Duration::from_secs(8));
        // The first record is now past its TTL, but the connection was refreshed.
        c.evict_expired(t0 + Duration::from_secs(12));
        assert_eq!(
            c.resolve(&tuple(50000, 443), t0 + Duration::from_secs(12)),
            Resolution::Application(111)
        );
    }

    #[test]
    fn eviction_forgets_what_is_too_old_and_keeps_what_is_not() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 1), t0);
        c.insert(seen(50001, 2), t0 + Duration::from_secs(6));
        let forgotten = c.evict_expired(t0 + Duration::from_secs(11));
        assert_eq!(forgotten, 1);
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.resolve(&tuple(50001, 443), t0 + Duration::from_secs(11)),
            Resolution::Application(2)
        );
    }

    #[test]
    fn inserting_evicts_the_expired_first() {
        let mut c = cache(8);
        let t0 = Instant::now();
        c.insert(seen(50000, 1), t0);
        c.insert(seen(50001, 2), t0 + TTL + Duration::from_secs(1));
        assert_eq!(
            c.len(),
            1,
            "the old one was dropped when the new one arrived"
        );
    }

    #[test]
    fn however_fast_connections_arrive_the_cache_never_holds_more_than_its_capacity() {
        let mut c = cache(100);
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let port = 1024 + (i % 60_000) as u16;
            c.insert(
                BestEffortAttribution {
                    tuple: tuple(port, 443 + (i % 7) as u16),
                    pid: i + 1,
                },
                t0 + Duration::from_micros(u64::from(i)),
            );
            assert!(c.len() <= 100, "{} after {i}", c.len());
        }
        assert_eq!(c.len(), 100);
    }

    #[test]
    fn when_full_the_oldest_go_first_and_the_newest_stay() {
        let mut c = cache(3);
        let t0 = Instant::now();
        for (i, port) in [50000u16, 50001, 50002, 50003].into_iter().enumerate() {
            c.insert(
                seen(port, i as u32 + 1),
                t0 + Duration::from_millis(i as u64),
            );
        }
        let now = t0 + Duration::from_secs(1);
        assert_eq!(
            c.resolve(&tuple(50000, 443), now),
            Resolution::NoApplicationRuleMatched,
            "the oldest was dropped"
        );
        for port in [50001u16, 50002, 50003] {
            assert!(matches!(
                c.resolve(&tuple(port, 443), now),
                Resolution::Application(_)
            ));
        }
    }

    #[test]
    fn a_refreshed_connection_is_not_dropped_for_being_first_in_line() {
        let mut c = cache(2);
        let t0 = Instant::now();
        c.insert(seen(50000, 1), t0);
        c.insert(seen(50001, 2), t0 + Duration::from_millis(1));
        // 50000 is seen again, so it is the newest; 50001 is now the oldest.
        c.insert(seen(50000, 1), t0 + Duration::from_millis(2));
        c.insert(seen(50002, 3), t0 + Duration::from_millis(3));
        let now = t0 + Duration::from_secs(1);
        assert!(matches!(
            c.resolve(&tuple(50000, 443), now),
            Resolution::Application(1)
        ));
        assert_eq!(
            c.resolve(&tuple(50001, 443), now),
            Resolution::NoApplicationRuleMatched
        );
        assert!(matches!(
            c.resolve(&tuple(50002, 443), now),
            Resolution::Application(3)
        ));
    }

    #[test]
    fn a_capacity_of_zero_still_holds_one() {
        let mut c = AttributionCache::new(TTL, 0);
        c.insert(seen(50000, 1), Instant::now());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn the_shared_cache_is_the_same_cache_from_every_clone_and_survives_a_poisoned_lock() {
        let shared = SharedCache::new(AttributionCache::new(Duration::from_secs(60), 8));
        let writer = shared.clone();
        let t = tuple(50000, 443);
        assert_eq!(shared.resolve(&t), Resolution::NoApplicationRuleMatched);
        writer.insert(seen(50000, 4321));
        assert_eq!(shared.resolve(&t), Resolution::Application(4321));
        assert!(!shared.is_empty());

        // A thread that panics while holding the lock does not make the cache unusable.
        let poisoner = shared.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.0.lock().unwrap();
            panic!("a callback panicked");
        })
        .join();
        assert_eq!(shared.resolve(&t), Resolution::Application(4321));
        assert_eq!(shared.len(), 1);
    }
}
