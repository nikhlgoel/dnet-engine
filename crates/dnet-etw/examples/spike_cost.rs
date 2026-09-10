//! T021 / SPIKE-O6 — measure ETW attribution cost and coverage.
//!
//! **This decides whether per-process routing (FR-023) ships in v1 at all.**
//!
//! Two questions, both of which must be answered by measurement rather than hope:
//!
//! 1. **Cost** — does a real-time consumer on `Microsoft-Windows-Kernel-Network`
//!    stay inside the idle-CPU budget (SC-014: <1% of a four-core machine)?
//! 2. **Coverage** — what proportion of outbound connections are actually
//!    attributed to the correct PID at connect time?
//!
//! Coverage is measured against **ground truth**: this process opens a known
//! number of TCP connections to a local listener, and we count how many come back
//! from ETW with our own PID and the expected port. Counting "events parsed
//! successfully" would measure parse success, not coverage, and would flatter the
//! result.
//!
//! Requires Administrator. Run:
//!   cargo build --release --example spike_cost -p dnet-etw
//!   Start-Process -Verb RunAs .\target\release\examples\spike_cost.exe
//!
//! If cost breaches SC-014 or coverage is too low to be useful, per-process
//! routing is cut from v1 and only destination rules ship. That outcome is a
//! success for this spike, not a failure.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
// `process_from_handle` lives on TraceTrait, so the trait must be in scope.
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;

/// Microsoft-Windows-Kernel-Network.
const PROVIDER_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// `TcpIpConnect` — an outbound TCP connection attempt.
/// IPv4 is event id 12; the IPv6 counterpart is 28.
const EVENT_TCP_CONNECT_V4: u16 = 12;
const EVENT_TCP_CONNECT_V6: u16 = 28;

/// How many known connections to make when measuring coverage.
const GROUND_TRUTH_CONNECTIONS: usize = 200;

/// How long to observe ambient traffic when measuring cost.
const COST_WINDOW: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Stats {
    /// Every connect event seen, from any process.
    events_total: AtomicU64,
    /// Events where the payload yielded a usable PID and 5-tuple.
    events_parsed: AtomicU64,
    /// Events whose PID could not be read from the payload.
    events_pid_missing: AtomicU64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SPIKE-O6 — ETW attribution cost and coverage");
    println!("=============================================");
    println!();

    let self_pid = std::process::id();
    println!("Process id: {self_pid}");
    println!("Provider:   Microsoft-Windows-Kernel-Network ({PROVIDER_GUID})");
    println!("Events:     TcpIpConnect (id {EVENT_TCP_CONNECT_V4} v4, {EVENT_TCP_CONNECT_V6} v6)");
    println!();

    let stats = Arc::new(Stats::default());
    // Ports observed for THIS process, used for the coverage measurement.
    let own_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));

    let cb_stats = Arc::clone(&stats);
    let cb_ports = Arc::clone(&own_ports);

    let provider = Provider::by_guid(PROVIDER_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            if id != EVENT_TCP_CONNECT_V4 && id != EVENT_TCP_CONNECT_V6 {
                return;
            }
            cb_stats.events_total.fetch_add(1, Ordering::Relaxed);

            let Ok(schema) = locator.event_schema(record) else {
                cb_stats.events_pid_missing.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let parser = Parser::create(record, &schema);

            // CRITICAL: the PID is read from the EVENT PAYLOAD, never from
            // EVENT_TRACE_HEADER. Microsoft documents the header ProcessId as
            // unreliable for network events, because some are logged by separate
            // threads. Using it would produce silently wrong attribution — the
            // worst possible failure for a routing decision.
            let pid: Option<u32> = parser.try_parse("PID").ok();
            let sport: Option<u16> = parser.try_parse("sport").ok();
            let dport: Option<u16> = parser.try_parse("dport").ok();

            match (pid, sport, dport) {
                (Some(pid), Some(sport), Some(_dport)) => {
                    cb_stats.events_parsed.fetch_add(1, Ordering::Relaxed);
                    if pid == self_pid {
                        if let Ok(mut set) = cb_ports.lock() {
                            set.insert(sport);
                        }
                    }
                }
                _ => {
                    cb_stats.events_pid_missing.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
        .build();

    println!("Starting ETW session (requires Administrator)...");
    let (trace, handle) = match UserTrace::new()
        .named(String::from("DNetSpikeO6"))
        .enable(provider)
        .start()
    {
        Ok(v) => v,
        // TraceError implements Debug but not Display, so format it with {:?}
        // rather than converting it into a boxed error.
        Err(e) => {
            eprintln!();
            eprintln!("FAILED to start the ETW session: {e:?}");
            eprintln!();
            eprintln!("This almost always means the process is not elevated.");
            eprintln!("Run it as Administrator:");
            eprintln!("  Start-Process -Verb RunAs .\\target\\release\\examples\\spike_cost.exe");
            return Err("could not start ETW session (Administrator required)".into());
        }
    };
    std::thread::spawn(move || {
        let _ = UserTrace::process_from_handle(handle);
    });
    println!("Session started.");
    println!();

    // ---------------------------------------------------------------- cost
    println!("[1/2] Cost — observing ambient traffic for {}s.", COST_WINDOW.as_secs());
    println!("      Keep your normal workload running.");

    let cpu_before = process_cpu_time();
    let wall_before = Instant::now();
    std::thread::sleep(COST_WINDOW);
    let cpu_used = process_cpu_time() - cpu_before;
    let wall = wall_before.elapsed();

    let total = stats.events_total.load(Ordering::Relaxed);
    let parsed = stats.events_parsed.load(Ordering::Relaxed);
    let missing = stats.events_pid_missing.load(Ordering::Relaxed);

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as f64;
    let cpu_pct_one_core = (cpu_used.as_secs_f64() / wall.as_secs_f64()) * 100.0;
    let cpu_pct_machine = cpu_pct_one_core / cores;

    println!();
    println!("      Wall time          {:.1} s", wall.as_secs_f64());
    println!("      CPU consumed       {:.3} s", cpu_used.as_secs_f64());
    println!("      CPU, one core      {:.3} %", cpu_pct_one_core);
    println!("      CPU, {cores}-core machine  {:.3} %", cpu_pct_machine);
    println!("      Connect events     {total} ({:.1}/s)", total as f64 / wall.as_secs_f64());
    println!("      Parsed with PID    {parsed}");
    println!("      PID unreadable     {missing}");
    println!();

    // ------------------------------------------------------------ coverage
    println!("[2/2] Coverage — making {GROUND_TRUTH_CONNECTIONS} known connections.");

    own_ports.lock().unwrap().clear();
    let expected = make_known_connections(GROUND_TRUTH_CONNECTIONS)?;

    // Allow the ETW pipeline to drain; real-time delivery is buffered.
    std::thread::sleep(Duration::from_secs(3));

    let observed = own_ports.lock().unwrap().clone();
    let matched = expected.iter().filter(|p| observed.contains(p)).count();
    let coverage = (matched as f64 / expected.len() as f64) * 100.0;

    println!();
    println!("      Connections made   {}", expected.len());
    println!("      Attributed to us   {matched}");
    println!("      Coverage           {coverage:.1} %");
    println!();

    if let Err(e) = trace.stop() {
        eprintln!("warning: failed to stop the ETW session cleanly: {e:?}");
    }

    // ------------------------------------------------------------- verdict
    println!("Verdict");
    println!("-------");
    let cost_ok = cpu_pct_machine < 1.0;
    let coverage_ok = coverage >= 95.0;

    println!(
        "  Cost      {:.3} % of a {cores}-core machine  {}",
        cpu_pct_machine,
        if cost_ok { "PASS (SC-014 <1%)" } else { "FAIL (SC-014 <1%)" }
    );
    println!(
        "  Coverage  {coverage:.1} %  {}",
        if coverage_ok { "PASS (>=95%)" } else { "FAIL (<95%)" }
    );
    println!();
    if cost_ok && coverage_ok {
        println!("  SPIKE-O6 PASSES. Per-process routing (FR-023) stays in v1 scope,");
        println!("  labelled best-effort per Constitution Principle VI.");
    } else {
        println!("  SPIKE-O6 FAILS. Per-process routing (FR-023) is CUT from v1;");
        println!("  only destination rules ship. Record the decision in");
        println!("  docs/adr/0001-etw-attribution.md.");
    }
    Ok(())
}

/// Opens `n` TCP connections to a local listener and returns the source ports
/// actually used. These are the ground truth for the coverage measurement.
fn make_known_connections(n: usize) -> std::io::Result<Vec<u16>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 8];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"ok");
            }
        }
    });

    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                if let Ok(local) = s.local_addr() {
                    ports.push(local.port());
                }
                let _ = s.write_all(b"ping");
                let mut buf = [0u8; 8];
                let _ = s.read(&mut buf);
            }
            Err(e) => eprintln!("      connection failed: {e}"),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(ports)
}

/// Total CPU time (kernel + user) consumed by this process.
fn process_cpu_time() -> Duration {
    use std::mem::zeroed;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    unsafe {
        let mut creation: FILETIME = zeroed();
        let mut exit: FILETIME = zeroed();
        let mut kernel: FILETIME = zeroed();
        let mut user: FILETIME = zeroed();
        if GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
        .is_err()
        {
            return Duration::ZERO;
        }
        let to_ns = |ft: FILETIME| -> u64 {
            (((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64) * 100
        };
        Duration::from_nanos(to_ns(kernel) + to_ns(user))
    }
}
