//! T021 / SPIKE-O6 — measure ETW attribution cost and coverage. **Instrument v2.**
//!
//! **This decides whether per-process routing (FR-023) ships in v1.**
//!
//! Run 1 (2026-09-10) reported 0.5% coverage and 1 ambient connect event in 30 s.
//! That run could not tell apart three explanations, so v2 is designed to separate
//! them in a single run rather than issue a verdict it cannot support:
//!
//! 1. **Loopback special-casing.** Run 1's ground truth only connected to 127.0.0.1.
//!    v2 measures loopback and a remote destination as separate classes. The verdict
//!    uses the remote class, because remote traffic is what the product routes.
//! 2. **Port byte order.** `sport`/`dport` may be carried in network byte order.
//!    Reading them as native-endian `u16` misses every port except byte-palindromes,
//!    about 0.4% of the ephemeral range — close to run 1's 0.5%. v2 checks both byte
//!    orders and reports which one matched.
//! 3. **A silent session.** v2 builds a histogram of every event id the provider
//!    delivers, and gives no verdict if the session receives nothing.
//!
//! Requires Administrator:
//!   cargo build --release --example spike_cost -p dnet-etw
//!   .\target\release\examples\spike_cost.exe [--target HOST:PORT] [--skip-remote]
//!
//! The remote class opens ordinary outbound TCP connections: by default 200 to
//! 1.1.1.1:443, 50 ms apart — about the load of opening a few web pages. Use
//! --target to pick another destination, or --skip-remote to measure loopback only.
//! A loopback-only run gives no verdict.
//!
//! Exit codes: 0 PASS · 1 FAIL · 2 INSTRUMENT INVALID (no verdict).

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
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

/// `TcpIpConnect` ("connection attempted"): IPv4 is event 12, IPv6 is event 28.
const EVENT_TCP_CONNECT_V4: u16 = 12;
const EVENT_TCP_CONNECT_V6: u16 = 28;

const GROUND_TRUTH_CONNECTIONS: usize = 200;
const CONNECT_SPACING: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const COST_WINDOW: Duration = Duration::from_secs(30);
/// Real-time delivery is buffered; wait this long for events to arrive.
const DRAIN: Duration = Duration::from_secs(3);
const LIVENESS_BURST: usize = 20;
const DEFAULT_REMOTE_TARGET: &str = "1.1.1.1:443";

/// Below this many events in the cost window, the CPU figure only describes an
/// idle session, not attribution under load, and is reported that way.
const MIN_EVENTS_FOR_REPRESENTATIVE_COST: u64 = 50;

const COST_THRESHOLD_PCT: f64 = 1.0;
const COVERAGE_THRESHOLD_PCT: f64 = 95.0;

/// What the ETW callback has seen. The ETW thread writes it; main reads it.
#[derive(Default)]
struct Observed {
    /// Every event id the provider delivered, with counts.
    histogram: Mutex<BTreeMap<u16, u64>>,
    /// Connect events (ids 12 and 28) from any process.
    connects_total: AtomicU64,
    /// Connect events whose payload PID is this process.
    connects_own_pid: AtomicU64,
    /// Connect events whose PID or port could not be parsed.
    connects_unparsed: AtomicU64,
    /// `sport` values from this process's connect events, exactly as parsed.
    own_ports_raw: Mutex<HashSet<u16>>,
}

impl Observed {
    fn histogram_total(&self) -> u64 {
        self.histogram
            .lock()
            .expect("histogram mutex poisoned")
            .values()
            .sum()
    }
}

/// Measurements for one class of ground-truth connections.
struct ClassResult {
    name: &'static str,
    made: usize,
    failed: usize,
    /// Connect events carrying our PID, whatever their port.
    own_pid_events: u64,
    matched_raw: usize,
    matched_swapped: usize,
}

impl ClassResult {
    fn best_matched(&self) -> usize {
        self.matched_raw.max(self.matched_swapped)
    }

    fn coverage_pct(&self) -> f64 {
        if self.made == 0 {
            return 0.0;
        }
        self.best_matched() as f64 / self.made as f64 * 100.0
    }

    /// What the numbers say about the cause, in plain terms.
    fn interpretation(&self) -> &'static str {
        let made = self.made as f64;
        if self.made == 0 {
            "no connections completed; nothing was measured"
        } else if (self.own_pid_events as f64) < made * 0.05 {
            "the provider did not emit connect events for this traffic"
        } else if self.best_matched() as f64 >= made * 0.95 {
            "events were emitted and attributed correctly"
        } else {
            "events carrying our PID arrived but ports did not match: a parsing \
             problem, not a provider coverage problem"
        }
    }
}

struct Args {
    target: String,
    skip_remote: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        target: DEFAULT_REMOTE_TARGET.to_string(),
        skip_remote: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => {
                if let Some(t) = it.next() {
                    args.target = t;
                }
            }
            "--skip-remote" => args.skip_remote = true,
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }
    args
}

fn on_event(record: &EventRecord, locator: &SchemaLocator, obs: &Observed, self_pid: u32) {
    let id = record.event_id();
    if let Ok(mut h) = obs.histogram.lock() {
        *h.entry(id).or_insert(0) += 1;
    }
    if id != EVENT_TCP_CONNECT_V4 && id != EVENT_TCP_CONNECT_V6 {
        return;
    }
    obs.connects_total.fetch_add(1, Ordering::Relaxed);

    let Ok(schema) = locator.event_schema(record) else {
        obs.connects_unparsed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let parser = Parser::create(record, &schema);

    // The PID comes from the EVENT PAYLOAD, never EVENT_TRACE_HEADER. Microsoft
    // documents the header ProcessId as unreliable for network events (R7).
    let pid: Option<u32> = parser.try_parse("PID").ok();
    let sport: Option<u16> = parser.try_parse("sport").ok();

    match (pid, sport) {
        (Some(pid), Some(sport)) => {
            if pid == self_pid {
                obs.connects_own_pid.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut s) = obs.own_ports_raw.lock() {
                    s.insert(sport);
                }
            }
        }
        _ => {
            obs.connects_unparsed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn main() {
    // ETW and GetProcessTimes exist only on Windows; off Windows this example only type-checks.
    if !cfg!(windows) {
        eprintln!("spike_cost measures ETW and runs only on Windows");
        std::process::exit(2);
    }
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let args = parse_args();
    let self_pid = std::process::id();

    println!("SPIKE-O6 — ETW attribution cost and coverage (instrument v2)");
    println!("=============================================================");
    println!("Process id:  {self_pid}");
    println!("Provider:    Microsoft-Windows-Kernel-Network ({PROVIDER_GUID})");
    println!("Connect ids: {EVENT_TCP_CONNECT_V4} (v4), {EVENT_TCP_CONNECT_V6} (v6)");
    if args.skip_remote {
        println!("Remote:      skipped (loopback-only run gives no verdict)");
    } else {
        println!("Remote:      {}", args.target);
    }
    println!();

    let obs = Arc::new(Observed::default());
    let cb_obs = Arc::clone(&obs);
    let provider = Provider::by_guid(PROVIDER_GUID)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_event(r, l, &cb_obs, self_pid))
        .build();

    println!("Starting ETW session (requires Administrator)...");
    let (trace, handle) = match UserTrace::new()
        .named(String::from("DNetSpikeO6v2"))
        .enable(provider)
        .start()
    {
        Ok(v) => v,
        Err(e) => {
            // TraceError implements Debug but not Display.
            eprintln!("FAILED to start the ETW session: {e:?}");
            eprintln!("This almost always means the process is not elevated.");
            return 2;
        }
    };
    std::thread::spawn(move || {
        let _ = UserTrace::process_from_handle(handle);
    });

    let remote_addr = if args.skip_remote {
        None
    } else {
        match args
            .target
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
        {
            Some(addr) => Some(addr),
            None => {
                eprintln!(
                    "INSTRUMENT INVALID: could not resolve --target {}",
                    args.target
                );
                return 2;
            }
        }
    };

    // ------------------------------------------------------------ liveness
    println!("[0/3] Liveness — confirming the session receives events at all.");
    let before = obs.histogram_total();
    let loopback = match LoopbackListener::start() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("INSTRUMENT INVALID: could not start loopback listener: {e}");
            return 2;
        }
    };
    for _ in 0..LIVENESS_BURST {
        let _ = match remote_addr {
            Some(addr) => connect_remote(addr),
            None => loopback.connect(),
        };
    }
    std::thread::sleep(DRAIN);
    let delivered = obs.histogram_total() - before;
    println!("      Events delivered during burst: {delivered}");
    if delivered == 0 {
        println!();
        println!("INSTRUMENT INVALID: the session received no events of any id.");
        println!("No verdict is possible. Check the provider GUID and elevation.");
        stop(trace);
        return 2;
    }
    println!();

    // ---------------------------------------------------------------- cost
    println!(
        "[1/3] Cost — observing ambient traffic for {}s. Keep your workload running.",
        COST_WINDOW.as_secs()
    );
    let events_before = obs.histogram_total();
    let connects_before = obs.connects_total.load(Ordering::Relaxed);
    let cpu_before = process_cpu_time();
    let wall_before = Instant::now();
    std::thread::sleep(COST_WINDOW);
    let cpu_used = process_cpu_time().saturating_sub(cpu_before);
    let wall = wall_before.elapsed();
    let window_events = obs.histogram_total() - events_before;
    let window_connects = obs.connects_total.load(Ordering::Relaxed) - connects_before;

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) as f64;
    let cpu_pct_machine = cpu_used.as_secs_f64() / wall.as_secs_f64() * 100.0 / cores;
    let cost_representative = window_events >= MIN_EVENTS_FOR_REPRESENTATIVE_COST;

    println!("      CPU, {cores}-core machine   {cpu_pct_machine:.3} %");
    println!("      Events (all ids)        {window_events}");
    println!("      Connect events          {window_connects}");
    if !cost_representative {
        println!(
            "      NOTE: fewer than {MIN_EVENTS_FOR_REPRESENTATIVE_COST} events — this CPU figure \
             describes an idle session, not attribution under load."
        );
    }
    print_histogram(&obs);
    println!();

    // ------------------------------------------------------------ coverage
    println!(
        "[2/3] Coverage — loopback class ({GROUND_TRUTH_CONNECTIONS} connections to 127.0.0.1)."
    );
    let loop_result = measure_class("loopback", &obs, || loopback.connect());
    print_class(&loop_result);

    let remote_result = remote_addr.map(|addr| {
        println!(
            "[3/3] Coverage — remote class ({GROUND_TRUTH_CONNECTIONS} connections to {addr})."
        );
        let r = measure_class("remote", &obs, || connect_remote(addr));
        print_class(&r);
        r
    });

    stop(trace);
    println!(
        "Unparsed connect events overall: {}",
        obs.connects_unparsed.load(Ordering::Relaxed)
    );
    println!();

    verdict(
        &loop_result,
        remote_result.as_ref(),
        cpu_pct_machine,
        cost_representative,
    )
}

fn verdict(
    loop_result: &ClassResult,
    remote: Option<&ClassResult>,
    cpu_pct: f64,
    cost_representative: bool,
) -> i32 {
    println!("Verdict");
    println!("-------");

    for r in std::iter::once(loop_result).chain(remote) {
        if r.matched_swapped > r.matched_raw.saturating_mul(2) && r.matched_swapped > 0 {
            println!(
                "  FINDING ({}): ports arrive in NETWORK byte order. Attribution must \
                 swap sport/dport (T075).",
                r.name
            );
        }
    }

    let Some(remote) = remote else {
        println!("  No verdict: loopback-only run. Re-run without --skip-remote.");
        return 2;
    };
    if remote.made == 0 {
        println!("  INSTRUMENT INVALID: no remote connection completed; nothing was measured.");
        return 2;
    }

    let coverage = remote.coverage_pct();
    let coverage_ok = coverage >= COVERAGE_THRESHOLD_PCT;
    let cost_ok = cpu_pct < COST_THRESHOLD_PCT;

    println!(
        "  Coverage  {coverage:.1} % on remote traffic  {}",
        if coverage_ok {
            "PASS (>=95%)"
        } else {
            "FAIL (<95%)"
        }
    );
    println!(
        "  Cost      {cpu_pct:.3} %  {}",
        match (cost_ok, cost_representative) {
            (true, true) => "PASS (<1%)",
            (false, _) => "FAIL (>=1%)",
            (true, false) => "NOT ESTABLISHED (too few events in the window)",
        }
    );
    println!();

    if !coverage_ok {
        println!(
            "  SPIKE-O6 FAILS on remote coverage: {}.",
            remote.interpretation()
        );
        println!("  Per the pre-registered rule, FR-023 is cut from v1 — unless the");
        println!("  interpretation above points to a parsing problem, which is fixable.");
        return 1;
    }
    if !cost_ok {
        println!("  SPIKE-O6 FAILS on cost. FR-023 is cut from v1.");
        return 1;
    }
    if !cost_representative {
        println!("  Coverage passes, but cost is NOT ESTABLISHED. Re-run the cost window");
        println!("  under heavier traffic (active downloads or many tabs) before deciding.");
        return 2;
    }
    println!("  SPIKE-O6 PASSES. FR-023 stays in v1, labelled best-effort (Principle VI).");
    0
}

fn measure_class(
    name: &'static str,
    obs: &Observed,
    connect: impl Fn() -> std::io::Result<u16>,
) -> ClassResult {
    obs.own_ports_raw
        .lock()
        .expect("port set mutex poisoned")
        .clear();
    let own_before = obs.connects_own_pid.load(Ordering::Relaxed);

    let mut expected = Vec::with_capacity(GROUND_TRUTH_CONNECTIONS);
    let mut failed = 0;
    for _ in 0..GROUND_TRUTH_CONNECTIONS {
        match connect() {
            Ok(port) => expected.push(port),
            Err(_) => failed += 1,
        }
        std::thread::sleep(CONNECT_SPACING);
    }
    std::thread::sleep(DRAIN);

    let own_pid_events = obs.connects_own_pid.load(Ordering::Relaxed) - own_before;
    let seen = obs
        .own_ports_raw
        .lock()
        .expect("port set mutex poisoned")
        .clone();
    let matched_raw = expected.iter().filter(|p| seen.contains(p)).count();
    let matched_swapped = expected
        .iter()
        .filter(|p| seen.contains(&p.swap_bytes()))
        .count();

    ClassResult {
        name,
        made: expected.len(),
        failed,
        own_pid_events,
        matched_raw,
        matched_swapped,
    }
}

fn print_class(r: &ClassResult) {
    println!(
        "      Connections completed      {} ({} failed)",
        r.made, r.failed
    );
    println!("      Connect events, our PID    {}", r.own_pid_events);
    println!("      Port matches, native order {}", r.matched_raw);
    println!("      Port matches, byte-swapped {}", r.matched_swapped);
    println!("      Coverage (best order)      {:.1} %", r.coverage_pct());
    println!("      Interpretation             {}", r.interpretation());
    println!();
}

fn print_histogram(obs: &Observed) {
    let h = obs.histogram.lock().expect("histogram mutex poisoned");
    if h.is_empty() {
        println!("      Event id histogram: empty");
        return;
    }
    let summary: Vec<String> = h.iter().map(|(id, n)| format!("{id}:{n}")).collect();
    println!("      Event id histogram (id:count) {}", summary.join(" "));
}

fn stop(trace: UserTrace) {
    if let Err(e) = trace.stop() {
        eprintln!("warning: failed to stop the ETW session cleanly: {e:?}");
    }
}

/// A local listener that accepts and immediately answers connections.
struct LoopbackListener {
    addr: SocketAddr,
}

impl LoopbackListener {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut buf = [0u8; 8];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"ok");
            }
        });
        Ok(Self { addr })
    }

    fn connect(&self) -> std::io::Result<u16> {
        let mut s = TcpStream::connect(self.addr)?;
        let port = s.local_addr()?.port();
        let _ = s.write_all(b"ping");
        Ok(port)
    }
}

fn connect_remote(addr: SocketAddr) -> std::io::Result<u16> {
    let s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    Ok(s.local_addr()?.port())
}

/// Off Windows `main` exits before any measurement, so this is never reached.
#[cfg(not(windows))]
fn process_cpu_time() -> Duration {
    unreachable!("spike_cost exits before measuring off Windows")
}

/// Total CPU time (kernel + user) this process has consumed.
#[cfg(windows)]
fn process_cpu_time() -> Duration {
    use std::mem::zeroed;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    // SAFETY: GetProcessTimes writes only to the four FILETIME out-pointers, each
    // of which points at a live, properly aligned stack value for the whole call.
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
