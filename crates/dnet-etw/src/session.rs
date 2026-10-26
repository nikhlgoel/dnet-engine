//! T074 — the real-time ETW session on `Microsoft-Windows-Kernel-Network` (ADR-0001, research R7).
//!
//! The session subscribes to the provider, and for every TCP connect event (IPv4 and IPv6) reads the
//! payload, decodes it ([`crate::attribution::decode`]: the process id from the payload, the ports put into
//! host order) and records it in a shared [`SharedCache`]. Nothing else in the product touches ETW.
//!
//! - **No API polling, no kernel driver** (the constitution's constraint): this is a subscription to events
//!   the operating system already produces.
//! - **Needs elevation**, because starting a trace session does. The service runs as SYSTEM and has it. A
//!   start that fails says so; the product then carries on without application rules (they are best
//!   effort by design) and the interface says that they are not being applied.
//! - **Cheap by measurement**: SPIKE-O6 run 2 measured 0.000 % of a 16-core machine over a 7,689-event
//!   window and 100 % attribution of the connects it made (ADR-0001). That is a measurement of one machine,
//!   not a promise.
//! - **Counters, not logs.** What was seen, attributed and undecodable is counted ([`Counters`]); the
//!   callback logs nothing per event, because a line per connection would be the destination log that the
//!   diagnostics rules forbid (FR-035).
//!
//! A panic or a slow consumer here must not affect traffic: the callback only decodes and inserts, and the
//! session is separate from the tunnel.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;

use crate::attribution::{decode, is_connect, RawConnect, PROVIDER_GUID};
use crate::cache::SharedCache;

/// The name the session is created under. One per machine; a second start with the same name fails.
pub const SESSION_NAME: &str = "DNetEngineAttribution";

/// Why a session could not be started.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Usually: the process is not elevated.
    #[error("the ETW session could not be started (this needs an elevated process): {0}")]
    Start(String),
}

/// What the session has seen. Only counts.
#[derive(Debug, Default)]
pub struct Counters {
    /// Connect events delivered.
    pub connects_seen: AtomicU64,
    /// Of those, recorded in the cache.
    pub attributed: AtomicU64,
    /// Of those, not usable (a field would not parse, or did not make sense).
    pub undecodable: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.connects_seen.load(Ordering::Relaxed),
            self.attributed.load(Ordering::Relaxed),
            self.undecodable.load(Ordering::Relaxed),
        )
    }
}

/// Read the fields of a connect event from its payload, **exactly as parsed** (see [`RawConnect`]).
fn read(record: &EventRecord, locator: &SchemaLocator) -> Option<RawConnect> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    // The process id is the PAYLOAD's `PID`, never the header's (research R7, ADR-0001).
    let pid: u32 = parser.try_parse("PID").ok()?;
    let saddr: IpAddr = parser.try_parse("saddr").ok()?;
    let daddr: IpAddr = parser.try_parse("daddr").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    Some(RawConnect {
        event_id: record.event_id(),
        pid,
        saddr,
        daddr,
        sport,
        dport,
    })
}

fn on_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    cache: &SharedCache,
    counters: &Counters,
) {
    if !is_connect(record.event_id()) {
        return;
    }
    counters.connects_seen.fetch_add(1, Ordering::Relaxed);
    match read(record, locator).map(decode) {
        Some(Ok(attribution)) => {
            cache.insert(attribution);
            counters.attributed.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            counters.undecodable.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A running session. Stopped when dropped.
pub struct EtwSession {
    trace: Option<UserTrace>,
    worker: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl EtwSession {
    /// Start listening, filling `cache`.
    pub fn start(cache: SharedCache) -> Result<Self, SessionError> {
        let counters = Arc::new(Counters::default());
        let callback_counters = Arc::clone(&counters);
        let provider = Provider::by_guid(PROVIDER_GUID)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                on_event(record, locator, &cache, &callback_counters);
            })
            .build();
        // `TraceError` is `Debug` but not `Display`.
        let (trace, handle) = UserTrace::new()
            .named(String::from(SESSION_NAME))
            .enable(provider)
            .start()
            .map_err(|e| SessionError::Start(format!("{e:?}")))?;
        let worker = std::thread::spawn(move || {
            let _ = UserTrace::process_from_handle(handle);
        });
        Ok(Self {
            trace: Some(trace),
            worker: Some(worker),
            counters,
        })
    }

    /// What the session has seen so far.
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// Stop listening.
    pub fn stop(mut self) {
        self.shut_down();
    }

    fn shut_down(&mut self) {
        if let Some(trace) = self.trace.take() {
            if let Err(e) = trace.stop() {
                tracing::warn!(error = ?e, "the ETW session did not stop cleanly");
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.shut_down();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    use super::*;
    use crate::attribution::FiveTuple;
    use crate::cache::Resolution;

    /// Starts a real trace session, which needs an **elevated** shell:
    /// `cargo test -p dnet-etw -- --ignored --nocapture`. Makes 50 loopback connections and expects almost
    /// every one to be attributed to this process (ADR-0001 measured 100 %).
    #[test]
    #[ignore = "needs an elevated shell: starts a real ETW session"]
    fn live_connects_made_by_this_process_are_attributed_to_it() {
        let cache = SharedCache::default();
        let session = EtwSession::start(cache.clone()).expect("run this from an elevated shell");
        let counters = session.counters();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || for _ in listener.incoming().flatten() {});

        let mut tuples = Vec::new();
        let mut keep = Vec::new();
        for _ in 0..50 {
            let stream = TcpStream::connect(address).unwrap();
            tuples.push(FiveTuple::new(
                stream.local_addr().unwrap(),
                stream.peer_addr().unwrap(),
            ));
            keep.push(stream);
            std::thread::sleep(Duration::from_millis(20));
        }
        // Events are delivered a little after the connects.
        std::thread::sleep(Duration::from_millis(2500));

        let me = std::process::id();
        let hits = tuples
            .iter()
            .filter(|t| cache.resolve(t) == Resolution::Application(me))
            .count();
        let (seen, attributed, undecodable) = counters.snapshot();
        println!("connects seen {seen}, attributed {attributed}, undecodable {undecodable}; {hits}/50 of ours resolved");
        session.stop();
        assert!(
            hits * 100 >= tuples.len() * 95,
            "only {hits} of {} connections were attributed to this process",
            tuples.len()
        );
        assert_eq!(undecodable, 0, "an event that would not decode");
    }
}
