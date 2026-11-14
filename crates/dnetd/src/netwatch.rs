// SPDX-License-Identifier: GPL-3.0-or-later
//! T138 — watching the network while a tunnel is up, and moving it when it should move.
//!
//! This is the daemon half of failover. The decisions are made by pure code in `dnet-core`
//! (`PathMonitor`: which path is best and when to leave one; `ProbePlanner`: which measurement may be
//! believed); the facts come from `dnet-netstate` (what changed, what the paths are, what a probe
//! saw). This module is the loop that joins them, written against [`NetworkWatch`] so that every
//! behaviour is tested with a fake machine and the clock paused.
//!
//! **Two kinds of profile.** AmneziaWG's path can be *steered*: its endpoint host route is ours, so
//! pointing it at another gateway and rebinding moves the tunnel (T083, AW-03). The primary core's
//! profiles bind to whatever path the system uses, and a route pinned against that would fight the
//! core, so for them the loop does not decide anything: it notices which adapter the tunnel is
//! actually on and reports when that changes, so the user is told (FR-016b) and nothing is hidden.
//!
//! **A slow probe never delays a lost link.** A probe may take seconds. Probes run as tasks of
//! their own and report back through the loop's `select!`; the system's own change notifications
//! are handled the moment they arrive, which is when a link is lost.
//!
//! **A failed move is not assumed to have happened.** If rewriting the route or rebinding fails, the
//! monitor is put back on the path the tunnel is still on and no change is reported; another move is
//! not attempted for [`HOLD_AFTER_FAILURE`], so a broken step is not retried every second.
//!
//! The loop ends when its attempt is superseded (the tunnel was replaced or stopped), like the live
//! monitor beside it.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use dnet_core::degraded::Change;
use dnet_core::failover::{Decision, FailoverConfig};
use dnet_core::ids::InterfaceId;
use dnet_core::path::{NetworkPath, PathRole};
use dnet_core::path_monitor::{GatewayChange, PathMonitor, ProbeCadence};
use dnet_core::probe_plan::{Availability, Observation, ProbePlanner, Strategy, Verdict};
use dnet_core::profile::Carrier;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::telemetry::Telemetry;

/// How long after a move that failed before another is tried.
pub const HOLD_AFTER_FAILURE: Duration = Duration::from_secs(30);

/// What a probe needs to know about the path it measures. Owned, so a probe can run on a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeTarget {
    pub interface: InterfaceId,
    pub gateway: Option<Ipv4Addr>,
}

/// Runs one measurement. Cloned onto each probe task.
pub trait PathProber: Clone + Send + Sync + 'static {
    /// `None` means the measurement could not even be attempted (nothing to aim at, the adapter
    /// vanished): not a loss, and not a reason to believe anything about the path.
    fn observe(
        &self,
        target: ProbeTarget,
        strategy: Strategy,
    ) -> impl Future<Output = Option<Observation>> + Send;
}

/// What the loop needs from the machine and from the tunnel it is watching.
pub trait NetworkWatch: Send + 'static {
    type Prober: PathProber;

    fn prober(&self) -> Self::Prober;

    /// Wait for the system to say the network changed (already settled). `None`: no more will
    /// come. Must be cancel-safe: the loop races it against other events.
    fn changes(&mut self) -> impl Future<Output = Option<()>> + Send;

    /// The machine's paths now.
    fn paths(&mut self) -> Result<Vec<NetworkPath>, String>;

    /// The adapter the tunnel's packets leave through now, if it can be told.
    fn carrying_now(&mut self, paths: &[NetworkPath]) -> Option<InterfaceId>;

    /// What the system calls each network (for Wi-Fi, the network name), for those it has a name
    /// for. Read on every refresh, because a laptop roams: the same adapter, another network. The
    /// names are untrusted text, cleaned before they are sent anywhere.
    fn names(&mut self) -> HashMap<InterfaceId, String> {
        HashMap::new()
    }

    /// How the active profile is carried, for choosing what to measure.
    fn carrier(&self) -> Carrier;

    /// Whether the endpoint serves a TCP port to aim a probe at.
    fn endpoint_tcp(&self) -> bool;

    /// Whether the loop may move the tunnel (AmneziaWG), or only watch it.
    fn can_steer(&self) -> bool;

    /// Whether the profile can only be carried on a path with a gateway.
    fn needs_gateway(&self) -> bool;

    /// Make `to` carry the tunnel: rewrite the host route to its gateway, then rebind (AW-03).
    fn carry_over(&mut self, to: &NetworkPath) -> impl Future<Output = Result<(), String>> + Send;
}

/// A watch that watches nothing, for a test `Effects` that has none to offer. It has no values, so
/// none of its methods can ever run.
#[cfg(test)]
pub enum NoWatch {}

/// The prober of [`NoWatch`].
#[cfg(test)]
#[derive(Clone)]
pub enum NoProber {}

#[cfg(test)]
impl PathProber for NoProber {
    async fn observe(&self, _: ProbeTarget, _: Strategy) -> Option<Observation> {
        match *self {}
    }
}

#[cfg(test)]
impl NetworkWatch for NoWatch {
    type Prober = NoProber;

    fn prober(&self) -> NoProber {
        match *self {}
    }
    async fn changes(&mut self) -> Option<()> {
        match *self {}
    }
    fn paths(&mut self) -> Result<Vec<NetworkPath>, String> {
        match *self {}
    }
    fn carrying_now(&mut self, _: &[NetworkPath]) -> Option<InterfaceId> {
        match *self {}
    }
    fn carrier(&self) -> Carrier {
        match *self {}
    }
    fn endpoint_tcp(&self) -> bool {
        match *self {}
    }
    fn can_steer(&self) -> bool {
        match *self {}
    }
    fn needs_gateway(&self) -> bool {
        match *self {}
    }
    async fn carry_over(&mut self, _: &NetworkPath) -> Result<(), String> {
        match *self {}
    }
}

/// Where the loop publishes what it knows, for `GetPaths`, and under which connection attempt: a
/// loop of an older attempt can neither overwrite nor clear what a newer one published.
#[derive(Clone)]
pub struct Board {
    pub telemetry: Telemetry,
    pub attempt: u64,
}

/// Clears the board when the loop ends, however it ends.
struct Cleared(Board);

impl Drop for Cleared {
    fn drop(&mut self) {
        self.0.telemetry.clear_paths(self.0.attempt);
    }
}

/// The carrying path changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMove {
    pub from: Option<InterfaceId>,
    pub to: InterfaceId,
}

/// How the loop is paced and judged.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub failover: FailoverConfig,
    pub cadence: ProbeCadence,
    /// How often the loop looks for probes that are due and decides, even with nothing changed.
    pub tick: Duration,
    /// How long the loop goes without reading the machine, whatever the system has announced. The
    /// announcements are the fast path; this is the safety net for one that is missed, or for a
    /// subscription the system refused.
    pub refresh_every: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            failover: FailoverConfig::default(),
            cadence: ProbeCadence::default(),
            tick: Duration::from_secs(1),
            refresh_every: Duration::from_secs(30),
        }
    }
}

struct Loop<W: NetworkWatch> {
    watch: W,
    steer: bool,
    carrier: Carrier,
    endpoint_tcp: bool,
    needs_gateway: bool,
    monitor: PathMonitor,
    planner: ProbePlanner,
    prober: W::Prober,
    probes: JoinSet<(InterfaceId, Strategy, Option<Observation>)>,
    /// Strategies still to try for a path whose probe is in flight.
    remaining: HashMap<InterfaceId, VecDeque<Strategy>>,
    moved: mpsc::Sender<PathMove>,
    /// What the user should be told about the carrying path being poor, or recovered (T084).
    told: mpsc::Sender<Change>,
    board: Board,
    /// What the system calls each network, as of the last refresh.
    names: HashMap<InterfaceId, String>,
    /// The adapter last reported as carrying.
    reported: Option<InterfaceId>,
    hold_until: Option<Instant>,
    /// Whether the first look at the machine has been taken.
    started: bool,
    /// When the machine was last read.
    refreshed_at: Instant,
}

/// Watch the network until `alive` says the attempt is over. Changes of the carrying path are sent
/// to `moved`; a carrying path that is poor with no way out, and its recovery, to `told` (T084); what
/// is known of the networks to `board` (T144), which is cleared when the loop ends.
///
/// Only a steered profile is measured, so only for one can the path be called poor: the others are
/// observed, and an observed path has no quality to speak of (probes are real packets, and nothing
/// would act on the answer).
pub async fn run<W: NetworkWatch>(
    watch: W,
    settings: Settings,
    alive: impl Fn() -> bool,
    moved: mpsc::Sender<PathMove>,
    told: mpsc::Sender<Change>,
    board: Board,
) {
    let _cleared = Cleared(board.clone());
    let mut l = Loop {
        steer: watch.can_steer(),
        carrier: watch.carrier(),
        endpoint_tcp: watch.endpoint_tcp(),
        needs_gateway: watch.needs_gateway(),
        prober: watch.prober(),
        monitor: PathMonitor::new(settings.failover).with_cadence(settings.cadence),
        planner: ProbePlanner::new(),
        probes: JoinSet::new(),
        remaining: HashMap::new(),
        moved,
        told,
        board,
        names: HashMap::new(),
        reported: None,
        hold_until: None,
        started: false,
        refreshed_at: Loop::<W>::now(),
        watch,
    };
    let mut tick = tokio::time::interval(settings.tick);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut changes_open = true;

    if !l.refresh().await {
        return;
    }
    l.publish();
    loop {
        if !alive() {
            return;
        }
        tokio::select! {
            change = l.watch.changes(), if changes_open => match change {
                Some(()) => {
                    if !l.refresh().await { return; }
                }
                None => changes_open = false,
            },
            Some(done) = l.probes.join_next(), if !l.probes.is_empty() => {
                if let Ok((path, strategy, seen)) = done {
                    l.probe_finished(path, strategy, seen);
                }
            }
            _ = tick.tick() => {}
        }
        if !alive() {
            return;
        }
        if Loop::<W>::now().saturating_duration_since(l.refreshed_at) >= settings.refresh_every
            && !l.refresh().await
        {
            return;
        }
        if l.steer {
            l.start_probes();
            if !l.decide().await {
                return;
            }
        }
        l.publish();
    }
}

impl<W: NetworkWatch> Loop<W> {
    fn now() -> Instant {
        // Tokio's clock, so a test that pauses time controls this too.
        tokio::time::Instant::now().into_std()
    }

    /// Read the machine and bring the monitor up to date. `false` when the report channel is gone.
    async fn refresh(&mut self) -> bool {
        self.refreshed_at = Self::now();
        let observed = match self.watch.paths() {
            Ok(paths) => paths,
            Err(why) => {
                tracing::warn!(%why, "could not read the network paths");
                return true;
            }
        };
        let carrying = self.watch.carrying_now(&observed);
        self.names = self.watch.names();
        let observed = self.capable(observed);

        // What was learned about a gateway holds only for that gateway.
        for old in self.monitor.paths() {
            let new = observed.iter().find(|p| p.interface_id == old.interface_id);
            if new.is_none_or(|p| p.gateway != old.gateway) {
                self.planner.forget_gateway(old.interface_id);
            }
        }
        let delta = self.monitor.paths_changed(observed);
        let now = Self::now();

        if !self.steer {
            return self.follow(carrying).await;
        }
        if !self.started {
            self.started = true;
            if let Some(path) = carrying {
                self.monitor.set_carrying(path, now);
                return self.report(None, path).await;
            }
        }
        if let Some(change) = delta.carrying_gateway {
            self.new_gateway(change).await;
        }
        true
    }

    /// Paths this profile can be carried on. A profile that needs a gateway cannot use one that
    /// has none, so it is not offered as an alternative.
    fn capable(&self, mut paths: Vec<NetworkPath>) -> Vec<NetworkPath> {
        if self.needs_gateway {
            for path in &mut paths {
                if path.gateway.is_none() {
                    path.role = PathRole::Unusable;
                }
            }
        }
        paths
    }

    /// For a profile that is not steered: note where the tunnel really is, and say when that changes.
    /// The monitor is told too, so the networks are published with the right one marked as carrying
    /// (it makes no decision of its own here: nothing evaluates it for a profile that is only
    /// observed).
    async fn follow(&mut self, carrying: Option<InterfaceId>) -> bool {
        match carrying {
            Some(path) if self.reported != Some(path) => {
                self.monitor.set_carrying(path, Self::now());
                let from = self.reported;
                self.report(from, path).await
            }
            _ => true,
        }
    }

    /// Put what is known of the networks where the control pipe can read it.
    fn publish(&self) {
        let mut snapshot = self.monitor.snapshot(Self::now());
        for path in &mut snapshot.paths {
            path.name = self.names.get(&path.id).cloned();
        }
        self.board
            .telemetry
            .publish_paths(self.board.attempt, snapshot);
    }

    async fn report(&mut self, from: Option<InterfaceId>, to: InterfaceId) -> bool {
        self.reported = Some(to);
        self.moved.send(PathMove { from, to }).await.is_ok()
    }

    /// The carrying adapter has a new gateway: the host route still points at the old router.
    async fn new_gateway(&mut self, change: GatewayChange) {
        let Some(path) = self
            .monitor
            .paths()
            .iter()
            .find(|p| p.interface_id == change.interface)
            .cloned()
        else {
            return;
        };
        if let Err(why) = self.watch.carry_over(&path).await {
            tracing::warn!(%why, "the tunnel could not follow the new gateway");
            self.hold_until = Some(Self::now() + HOLD_AFTER_FAILURE);
        }
    }

    /// Hand out the probes that are due, one task each.
    fn start_probes(&mut self) {
        let now = Self::now();
        for id in self.monitor.due_probes(now) {
            if self.remaining.contains_key(&id) {
                continue; // the last probe of this path is still running
            }
            let Some(path) = self.monitor.paths().iter().find(|p| p.interface_id == id) else {
                continue;
            };
            let order = self.planner.order(Availability {
                carrier: self.carrier,
                endpoint_tcp: self.endpoint_tcp,
                gateway: path.gateway.is_some(),
            });
            if order.is_empty() {
                continue;
            }
            self.remaining.insert(id, order.into());
            self.spawn_next(id);
        }
    }

    fn spawn_next(&mut self, id: InterfaceId) {
        let Some(strategy) = self.remaining.get_mut(&id).and_then(VecDeque::pop_front) else {
            self.remaining.remove(&id);
            return;
        };
        let gateway = self
            .monitor
            .paths()
            .iter()
            .find(|p| p.interface_id == id)
            .and_then(|p| match p.gateway {
                Some(IpAddr::V4(g)) => Some(g),
                _ => None,
            });
        let (prober, target) = (
            self.prober.clone(),
            ProbeTarget {
                interface: id,
                gateway,
            },
        );
        self.probes
            .spawn(async move { (id, strategy, prober.observe(target, strategy).await) });
    }

    fn probe_finished(&mut self, id: InterfaceId, strategy: Strategy, seen: Option<Observation>) {
        let verdict = seen.map(|o| self.planner.judge(strategy, id, o));
        match verdict {
            Some(Verdict::Sample(sample)) => {
                self.monitor.observe(id, sample, Self::now());
                self.remaining.remove(&id);
            }
            // Not attempted, or silence that means nothing: try what is left.
            Some(Verdict::NoInformation) | None => self.spawn_next(id),
        }
    }

    /// Ask the monitor, and carry out a move. `false` when the report channel is gone.
    async fn decide(&mut self) -> bool {
        let now = Self::now();
        if self.hold_until.is_some_and(|until| now < until) {
            return true;
        }
        self.hold_until = None;
        let decision = self.monitor.evaluate(now);
        // After the decision, on the same tick: a move just made is already reflected, and a path
        // the machine would have left by now is exactly what is worth telling the user about.
        if let Some(change) = self.monitor.report(now) {
            if self.told.send(change).await.is_err() {
                return false;
            }
        }
        let Decision::Move { from, to, .. } = decision else {
            return true;
        };
        let Some(path) = self
            .monitor
            .paths()
            .iter()
            .find(|p| p.interface_id == to)
            .cloned()
        else {
            return true;
        };
        match self.watch.carry_over(&path).await {
            Ok(()) => self.report(from, to).await,
            Err(why) => {
                tracing::warn!(%why, "the tunnel could not be moved to the other path");
                // Not moved: the tunnel is where it was, and the monitor must say so.
                if let Some(back) = from {
                    self.monitor.set_carrying(back, now);
                }
                self.hold_until = Some(now + HOLD_AFTER_FAILURE);
                true
            }
        }
    }
}

/// T162 — tell the loop when the machine was frozen (a sleep the system did not announce).
///
/// Ticks every `period`; when a tick comes much later than it should on either of the two clocks
/// `clocks` reads (monotonic, then wall, each as time since any fixed point), everything known about
/// the network is stale, so one change is sent, which makes the loop read the paths and measure them
/// again, exactly as it does when the system reports a change. The system's own power messages are
/// not relied on (`dnet_core::tick_gap`). Ends when the receiver is gone.
pub async fn report_gaps(
    changes: mpsc::Sender<()>,
    period: Duration,
    mut clocks: impl FnMut() -> (Duration, Duration),
) {
    let mut detector =
        dnet_core::tick_gap::TickGap::new(period, dnet_core::tick_gap::DEFAULT_TOLERANCE);
    let mut ticker = tokio::time::interval(period);
    // A tick that was missed is not made up with a burst: the point is the gap itself.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = changes.closed() => return,
            _ = ticker.tick() => {}
        }
        let (monotonic, wall) = clocks();
        if let Some(gap) = detector.tick(monotonic, wall) {
            tracing::info!(
                late_secs = gap.late_by.as_secs(),
                "the machine was not running for a while; the network is looked at again"
            );
            // Full means a change is already waiting to be read, which is as good.
            let _ = changes.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use dnet_core::degraded::{Degradation, NoMove};
    use dnet_core::path::PathRole as Role;
    use dnet_core::path::{PathKind, PathQuality};
    use dnet_core::quality::QualityBand;
    use tokio::task::JoinHandle;

    use super::*;

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }

    fn gw(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)))
    }

    /// A path as the system reports it.
    fn path(n: u64, kind: PathKind, pref: i32, gateway: Option<IpAddr>, up: bool) -> NetworkPath {
        NetworkPath {
            interface_id: id(n),
            kind,
            gateway,
            quality: PathQuality::unmeasured(),
            role: if up {
                PathRole::Standby
            } else {
                PathRole::Unusable
            },
            preference: pref,
        }
    }

    fn wifi(up: bool) -> NetworkPath {
        path(1, PathKind::Wifi, 10, gw(1), up)
    }
    fn wired(up: bool) -> NetworkPath {
        path(2, PathKind::Ethernet, 20, gw(2), up)
    }

    /// The machine the loop is watching, shared with the test.
    struct World {
        paths: Vec<NetworkPath>,
        carrying: Option<InterfaceId>,
        carried: Vec<(InterfaceId, Option<IpAddr>)>,
        fail_carry: bool,
        observed: Vec<(InterfaceId, Strategy)>,
        /// Every target a probe was asked about, with the gateway it was given.
        targets: Vec<ProbeTarget>,
        /// What a probe sees; anything not listed is an answer in 10 ms.
        answers: HashMap<(InterfaceId, Strategy), Option<Observation>>,
        probe_takes: Duration,
        /// How long a carry-over takes before it is done and recorded.
        carry_takes: Duration,
        /// What the system calls each network.
        names: HashMap<InterfaceId, String>,
    }

    impl World {
        fn new(paths: Vec<NetworkPath>, carrying: Option<u64>) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Self {
                paths,
                carrying: carrying.map(id),
                carried: Vec::new(),
                fail_carry: false,
                observed: Vec::new(),
                targets: Vec::new(),
                answers: HashMap::new(),
                probe_takes: Duration::ZERO,
                carry_takes: Duration::ZERO,
                names: HashMap::new(),
            }))
        }
    }

    #[derive(Clone)]
    struct FakeProber(Arc<Mutex<World>>);

    impl PathProber for FakeProber {
        fn observe(
            &self,
            target: ProbeTarget,
            strategy: Strategy,
        ) -> impl Future<Output = Option<Observation>> + Send {
            let world = Arc::clone(&self.0);
            async move {
                let (takes, answer) = {
                    let mut w = world.lock().unwrap();
                    w.observed.push((target.interface, strategy));
                    w.targets.push(target);
                    let answer = w
                        .answers
                        .get(&(target.interface, strategy))
                        .copied()
                        .unwrap_or(Some(Observation::Answered(Duration::from_millis(10))));
                    (w.probe_takes, answer)
                };
                tokio::time::sleep(takes).await;
                answer
            }
        }
    }

    struct Fake {
        world: Arc<Mutex<World>>,
        changes: mpsc::Receiver<()>,
        profile: Profile,
    }

    impl NetworkWatch for Fake {
        type Prober = FakeProber;

        fn prober(&self) -> FakeProber {
            FakeProber(Arc::clone(&self.world))
        }
        fn changes(&mut self) -> impl Future<Output = Option<()>> + Send {
            self.changes.recv()
        }
        fn paths(&mut self) -> Result<Vec<NetworkPath>, String> {
            Ok(self.world.lock().unwrap().paths.clone())
        }
        fn carrying_now(&mut self, _paths: &[NetworkPath]) -> Option<InterfaceId> {
            self.world.lock().unwrap().carrying
        }
        fn names(&mut self) -> HashMap<InterfaceId, String> {
            self.world.lock().unwrap().names.clone()
        }
        fn carrier(&self) -> Carrier {
            self.profile.carrier
        }
        fn endpoint_tcp(&self) -> bool {
            self.profile.endpoint_tcp
        }
        fn can_steer(&self) -> bool {
            self.profile.steer
        }
        fn needs_gateway(&self) -> bool {
            self.profile.needs_gateway
        }
        fn carry_over(
            &mut self,
            to: &NetworkPath,
        ) -> impl Future<Output = Result<(), String>> + Send {
            let world = Arc::clone(&self.world);
            let (interface, gateway) = (to.interface_id, to.gateway);
            async move {
                let takes = world.lock().unwrap().carry_takes;
                tokio::time::sleep(takes).await;
                let mut w = world.lock().unwrap();
                w.carried.push((interface, gateway));
                if w.fail_carry {
                    Err("the route could not be rewritten".to_owned())
                } else {
                    w.carrying = Some(interface);
                    Ok(())
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Profile {
        carrier: Carrier,
        endpoint_tcp: bool,
        steer: bool,
        needs_gateway: bool,
    }

    /// AmneziaWG: UDP, steerable, needs a gateway.
    const AWG: Profile = Profile {
        carrier: Carrier::Udp,
        endpoint_tcp: false,
        steer: true,
        needs_gateway: true,
    };

    struct Harness {
        world: Arc<Mutex<World>>,
        poke: Option<mpsc::Sender<()>>,
        moves: mpsc::Receiver<PathMove>,
        /// What the user is told about the carrying path being poor (T084).
        told: mpsc::Receiver<Change>,
        /// What the control pipe would answer `GetPaths` with.
        telemetry: Telemetry,
        alive: Arc<AtomicBool>,
        task: JoinHandle<()>,
    }

    fn start(world: Arc<Mutex<World>>, profile: Profile) -> Harness {
        let (poke, changes) = mpsc::channel(8);
        let (moved, moves) = mpsc::channel(16);
        let (tell, told) = mpsc::channel(16);
        let telemetry = Telemetry::new();
        let alive = Arc::new(AtomicBool::new(true));
        let fake = Fake {
            world: Arc::clone(&world),
            changes,
            profile,
        };
        let flag = Arc::clone(&alive);
        let task = tokio::spawn(run(
            fake,
            Settings::default(),
            move || flag.load(Ordering::SeqCst),
            moved,
            tell,
            Board {
                telemetry: telemetry.clone(),
                attempt: 1,
            },
        ));
        Harness {
            world,
            poke: Some(poke),
            moves,
            told,
            telemetry,
            alive,
            task,
        }
    }

    async fn secs(n: u64) {
        tokio::time::sleep(Duration::from_secs(n)).await;
    }

    impl Harness {
        async fn next_move(&mut self) -> PathMove {
            tokio::time::timeout(Duration::from_secs(5), self.moves.recv())
                .await
                .expect("a move was expected within 5 s")
                .expect("the loop is still running")
        }
        fn no_move_pending(&mut self) -> bool {
            self.moves.try_recv().is_err()
        }
        /// The next thing the user was told about the carrying path, within `within` seconds.
        async fn next_told(&mut self, within: u64) -> Change {
            tokio::time::timeout(Duration::from_secs(within), self.told.recv())
                .await
                .expect("the user should have been told something by now")
                .expect("the loop is still running")
        }
        /// Make every probe of `path` come back as silence, or answered again.
        fn path_goes_quiet(&self, path: u64, quiet: bool) {
            let answer = if quiet {
                Observation::Silent
            } else {
                Observation::Answered(Duration::from_millis(10))
            };
            self.world
                .lock()
                .unwrap()
                .answers
                .insert((id(path), Strategy::Gateway), Some(answer));
        }
        fn set_paths(&self, paths: Vec<NetworkPath>) {
            self.world.lock().unwrap().paths = paths;
        }
        async fn changed(&self) {
            self.poke
                .as_ref()
                .expect("the change source is still open")
                .send(())
                .await
                .unwrap();
        }
    }

    // ------------------------------------------------------------------ the first look

    #[tokio::test(start_paused = true)]
    async fn the_first_look_reports_the_path_the_tunnel_is_on() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);

        assert_eq!(
            h.next_move().await,
            PathMove {
                from: None,
                to: id(1)
            }
        );
    }

    // ------------------------------------------------------------------ a lost link

    #[tokio::test(start_paused = true)]
    async fn a_lost_link_moves_the_tunnel_to_the_other_path_and_only_then_says_so() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        world.lock().unwrap().carry_takes = Duration::from_secs(1);
        let mut h = start(world, AWG);
        h.next_move().await;

        h.set_paths(vec![wifi(false), wired(true)]);
        h.changed().await;

        let moved = h.next_move().await;
        assert_eq!(
            moved,
            PathMove {
                from: Some(id(1)),
                to: id(2)
            }
        );
        // By the time the move is reported the route has already been carried over (AW-03).
        assert_eq!(h.world.lock().unwrap().carried, [(id(2), gw(2))]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_move_that_fails_is_neither_reported_nor_retried_at_once() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        h.world.lock().unwrap().fail_carry = true;

        h.set_paths(vec![wifi(false), wired(true)]);
        h.changed().await;
        secs(10).await;

        assert_eq!(
            h.world.lock().unwrap().carried.len(),
            1,
            "tried once, then held"
        );
        assert!(h.no_move_pending(), "nothing was reported: nothing moved");

        // The step works again; after the hold the move is made and reported.
        h.world.lock().unwrap().fail_carry = false;
        secs(HOLD_AFTER_FAILURE.as_secs()).await;
        assert_eq!(
            h.next_move().await,
            PathMove {
                from: Some(id(1)),
                to: id(2)
            }
        );
    }

    // ------------------------------------------------------------------ a new router

    #[tokio::test(start_paused = true)]
    async fn a_new_gateway_on_the_carrying_adapter_rebinds_without_reporting_a_move() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;

        h.set_paths(vec![path(1, PathKind::Wifi, 10, gw(77), true), wired(true)]);
        h.changed().await;
        secs(2).await;

        assert_eq!(
            h.world.lock().unwrap().carried,
            [(id(1), gw(77))],
            "the host route follows the new router"
        );
        assert!(
            h.no_move_pending(),
            "the tunnel is still on the same adapter"
        );
    }

    // ------------------------------------------------------------------ profiles that are only watched

    #[tokio::test(start_paused = true)]
    async fn a_primary_core_profile_is_watched_not_steered() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Udp,
                endpoint_tcp: true,
                steer: false,
                needs_gateway: false,
            },
        );
        assert_eq!(
            h.next_move().await,
            PathMove {
                from: None,
                to: id(1)
            }
        );

        // The system moves the tunnel to the cable.
        h.world.lock().unwrap().carrying = Some(id(2));
        h.changed().await;

        assert_eq!(
            h.next_move().await,
            PathMove {
                from: Some(id(1)),
                to: id(2)
            }
        );
        secs(120).await;
        let w = h.world.lock().unwrap();
        assert!(w.carried.is_empty(), "the loop never steered it");
        assert!(
            w.observed.is_empty(),
            "and measured nothing: it decides nothing"
        );
    }

    // ------------------------------------------------------------------ probes

    #[tokio::test(start_paused = true)]
    async fn probes_follow_the_cadence_and_fall_back_when_the_endpoint_says_nothing() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        {
            let mut w = world.lock().unwrap();
            for p in [1, 2] {
                w.answers
                    .insert((id(p), Strategy::Endpoint), Some(Observation::Silent));
            }
        }
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Tcp,
                endpoint_tcp: true,
                steer: true,
                needs_gateway: true,
            },
        );
        h.next_move().await;

        secs(25).await;

        let w = h.world.lock().unwrap();
        let count = |p: u64, s: Strategy| w.observed.iter().filter(|o| **o == (id(p), s)).count();
        // The carrying path every 10 s (t=0, 10, 20); the other every 30 s (t=0).
        assert_eq!(count(1, Strategy::Gateway), 3, "{:?}", w.observed);
        assert_eq!(count(2, Strategy::Gateway), 1, "{:?}", w.observed);
        // The endpoint was tried first each time, and its silence, never heard, meant nothing.
        assert_eq!(count(1, Strategy::Endpoint), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_udp_tunnel_is_never_measured_with_a_tcp_connection() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Udp,
                endpoint_tcp: true,
                steer: true,
                needs_gateway: true,
            },
        );
        h.next_move().await;
        secs(40).await;

        let w = h.world.lock().unwrap();
        assert!(!w.observed.is_empty());
        assert!(w.observed.iter().all(|(_, s)| *s == Strategy::Gateway));
    }

    /// A probe may take seconds; a lost link must not wait for it.
    #[tokio::test(start_paused = true)]
    async fn a_slow_probe_does_not_delay_a_lost_link() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        world.lock().unwrap().probe_takes = Duration::from_secs(60);
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(2).await; // probes are now in flight and will be for a minute

        h.set_paths(vec![wifi(false), wired(true)]);
        h.changed().await;

        let t0 = tokio::time::Instant::now();
        let moved = h.next_move().await;
        assert_eq!(moved.to, id(2));
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "moved after {:?}",
            t0.elapsed()
        );
    }

    // ------------------------------------------------------------------ capability

    #[tokio::test(start_paused = true)]
    async fn a_profile_that_needs_a_gateway_is_never_moved_to_a_path_without_one() {
        let on_link = path(3, PathKind::Cellular, 0, None, true);
        let world = World::new(vec![wifi(true), on_link.clone()], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;

        h.set_paths(vec![wifi(false), on_link]);
        h.changed().await;
        secs(60).await;

        assert!(h.world.lock().unwrap().carried.is_empty());
        assert!(h.no_move_pending());
    }

    // ------------------------------------------------------------------ ending

    #[tokio::test(start_paused = true)]
    async fn the_loop_ends_when_its_attempt_is_over() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;

        h.alive.store(false, Ordering::SeqCst);
        secs(2).await;

        assert!(h.task.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_ends_when_nobody_is_listening_for_its_reports() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        let moves = std::mem::replace(&mut h.moves, mpsc::channel(1).1);
        drop(moves);

        h.set_paths(vec![wifi(false), wired(true)]);
        h.changed().await;
        secs(5).await;

        assert!(h.task.is_finished());
    }

    /// The announcements are the fast path, not the only one: a change nobody announced is found.
    #[tokio::test(start_paused = true)]
    async fn a_change_the_system_never_announced_is_found_by_the_slow_read() {
        // The alternative is *less* preferred, so nothing but the lost link can make the loop leave
        // Wi-Fi: a preferred path that proves itself would be returned to by itself (FR-017), and
        // that would make this test pass for the wrong reason.
        let backup = |up| path(2, PathKind::Ethernet, 0, gw(2), up);
        let world = World::new(vec![wifi(true), backup(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;

        // The link is lost and no change is ever signalled.
        h.set_paths(vec![wifi(false), backup(true)]);
        secs(25).await;
        assert!(h.no_move_pending(), "not yet: the slow read is every 30 s");
        secs(10).await;

        assert_eq!(
            h.next_move().await,
            PathMove {
                from: Some(id(1)),
                to: id(2)
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_with_no_more_changes_does_not_end_the_watch() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        let before = h.world.lock().unwrap().observed.len();

        // The change source is gone for good: the receiver now sees `None`.
        h.poke = None;
        secs(35).await;

        assert!(
            h.world.lock().unwrap().observed.len() > before,
            "probing carries on"
        );
        assert!(!h.task.is_finished());
    }

    // ------------------------------------------------------------------ a poor path with no way out (T084)

    #[tokio::test(start_paused = true)]
    async fn a_connection_on_the_only_network_going_bad_is_reported_with_the_reason() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(25).await; // the gateway answers: the path is known to be good, and measured
        assert!(
            h.told.try_recv().is_err(),
            "nothing to say about a good path"
        );

        h.path_goes_quiet(1, true);

        // Silence from a gateway that has been answering is loss; after two losses the path is
        // poor, and after it has stayed so for the machine's own patience the user is told.
        assert_eq!(
            h.next_told(120).await,
            Change::Degraded(Degradation {
                path: id(1),
                band: QualityBand::Poor,
                staying: NoMove::OnlyPath,
            })
        );
        assert!(
            h.no_move_pending(),
            "there was nowhere to move, and nothing was claimed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_user_is_told_when_the_network_has_recovered() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(25).await;
        h.path_goes_quiet(1, true);
        assert!(matches!(h.next_told(120).await, Change::Degraded(_)));
        // It may get worse before it gets better; only the recovery matters here.
        h.path_goes_quiet(1, false);

        let mut told = None;
        for _ in 0..6 {
            match h.next_told(300).await {
                Change::Recovered { path } => {
                    told = Some(path);
                    break;
                }
                Change::Degraded(_) => continue,
            }
        }
        assert_eq!(told, Some(id(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_profile_that_is_only_observed_is_never_called_degraded() {
        // Its path is not probed (nothing steers it, and a probe is a real packet), so there is no
        // measurement to base a claim on. Silence here is absence of evidence, not evidence.
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Udp,
                endpoint_tcp: true,
                steer: false,
                needs_gateway: false,
            },
        );
        h.next_move().await;
        h.path_goes_quiet(1, true);
        secs(300).await;
        assert!(h.told.try_recv().is_err());
    }

    // ------------------------------------------------------------------ what the interface is shown (T144)

    #[tokio::test(start_paused = true)]
    async fn the_loop_publishes_the_networks_it_watches_with_the_carrying_one_marked() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(3).await;

        let snap = h.telemetry.paths().expect("the networks are being watched");

        assert_eq!(snap.paths.len(), 2);
        let role = |n: u64| snap.paths.iter().find(|p| p.id == id(n)).unwrap().role;
        assert_eq!(role(1), Role::Carrying);
        assert_eq!(role(2), Role::Standby);
    }

    #[tokio::test(start_paused = true)]
    async fn the_names_the_system_gives_reach_the_published_networks() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        world
            .lock()
            .unwrap()
            .names
            .insert(id(1), "Hostel-5G".to_owned());
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(3).await;

        let snap = h.telemetry.paths().unwrap();
        let name = |n: u64| {
            snap.paths
                .iter()
                .find(|p| p.id == id(n))
                .unwrap()
                .name
                .clone()
        };
        assert_eq!(name(1).as_deref(), Some("Hostel-5G"));
        assert_eq!(
            name(2),
            None,
            "a network the system has no name for has none"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_move_is_reflected_in_what_is_published() {
        let world = World::new(vec![wifi(true), wired(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        h.set_paths(vec![wifi(false), wired(true)]);
        h.changed().await;
        h.next_move().await;
        secs(3).await;

        let snap = h.telemetry.paths().unwrap();
        let carrying: Vec<u64> = snap
            .paths
            .iter()
            .filter(|p| p.role == Role::Carrying)
            .map(|p| p.id.luid())
            .collect();
        assert_eq!(carrying, [2]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_measurements_reach_the_published_networks_once_probes_have_answered() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(25).await;

        let snap = h.telemetry.paths().unwrap();
        let p = &snap.paths[0];
        assert!(p.measured);
        assert!(!p.trace_ms.is_empty());
        assert_eq!(p.band, Some(QualityBand::Good));
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_published_after_the_loop_ends() {
        let world = World::new(vec![wifi(true)], Some(1));
        let mut h = start(world, AWG);
        h.next_move().await;
        secs(3).await;
        assert!(h.telemetry.paths().is_some());

        h.alive.store(false, Ordering::SeqCst);
        h.changed().await;
        let _ = (&mut h.task).await;

        assert_eq!(
            h.telemetry.paths(),
            None,
            "the networks are no longer watched"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_profile_that_is_only_followed_still_shows_which_network_carries() {
        let world = World::new(vec![wifi(true), wired(true)], Some(2));
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Udp,
                endpoint_tcp: true,
                steer: false,
                needs_gateway: false,
            },
        );
        h.next_move().await;
        secs(3).await;

        let snap = h.telemetry.paths().unwrap();
        let carrying: Vec<u64> = snap
            .paths
            .iter()
            .filter(|p| p.role == Role::Carrying)
            .map(|p| p.id.luid())
            .collect();
        assert_eq!(
            carrying,
            [2],
            "the tunnel is on the cable, whatever the preference"
        );
        assert!(
            snap.paths.iter().all(|p| !p.measured),
            "nothing is probed for an observed profile, so nothing is called measured"
        );
    }

    /// A profile that is only followed reports where the tunnel is when that changes, and says nothing while it stays
    /// where it was: a network event that leaves the tunnel on the same adapter is not a move.
    #[tokio::test(start_paused = true)]
    async fn a_followed_tunnel_that_stays_where_it_is_is_not_reported_again() {
        let world = World::new(vec![wifi(true), wired(true)], Some(2));
        let mut h = start(
            world,
            Profile {
                carrier: Carrier::Udp,
                endpoint_tcp: true,
                steer: false,
                needs_gateway: false,
            },
        );
        assert_eq!(h.next_move().await.to, id(2));
        secs(3).await;
        for _ in 0..3 {
            h.changed().await;
            secs(3).await;
        }
        assert!(
            h.no_move_pending(),
            "the tunnel did not move, so nothing is reported"
        );
    }

    /// A probe is told the IPv4 gateway of the path it measures, and of that path only: another network's gateway, an
    /// IPv6 gateway or no gateway at all is no gateway to ping.
    #[tokio::test(start_paused = true)]
    async fn each_probe_is_given_the_ipv4_gateway_of_its_own_path_and_none_for_other_kinds() {
        let v6: IpAddr = "fe80::1".parse().unwrap();
        let paths = vec![
            wifi(true),
            wired(true),
            path(3, PathKind::Cellular, 5, Some(v6), true),
            path(4, PathKind::Other, 1, None, true),
        ];
        let world = World::new(paths.clone(), Some(1));
        let h = start(world, AWG);
        secs(20).await;
        let targets = h.world.lock().unwrap().targets.clone();
        let given = |n: u64| -> Vec<Option<std::net::Ipv4Addr>> {
            targets
                .iter()
                .filter(|t| t.interface == id(n))
                .map(|t| t.gateway)
                .collect()
        };
        let v4_of = |p: &NetworkPath| match p.gateway {
            Some(IpAddr::V4(g)) => Some(g),
            _ => None,
        };
        for (n, path) in [(1u64, &paths[0]), (2, &paths[1]), (3, &paths[2])] {
            let seen = given(n);
            assert!(!seen.is_empty(), "path {n} was never probed");
            assert!(
                seen.iter().all(|g| *g == v4_of(path)),
                "path {n} was given {seen:?}, its own is {:?}",
                v4_of(path)
            );
        }
        assert!(v4_of(&paths[0]).is_some() && v4_of(&paths[0]) != v4_of(&paths[1]));
        assert!(
            given(3).iter().all(Option::is_none),
            "an IPv6 gateway is not a gateway to ping"
        );
    }

    // ------------------------------------------------------------------ T162: a frozen machine

    /// Clocks that advance one second per tick, except that the machine "sleeps" for `jump` seconds
    /// before tick number `at` (counting from 1): both clocks, or only the wall clock.
    fn scripted_clocks(
        at: u64,
        jump: u64,
        wall_only: bool,
    ) -> impl FnMut() -> (Duration, Duration) {
        let mut tick = 0u64;
        let (mut mono, mut wall) = (0u64, 1_000_000u64);
        move || {
            tick += 1;
            mono += 1;
            wall += 1;
            if tick == at {
                wall += jump;
                if !wall_only {
                    mono += jump;
                }
            }
            (Duration::from_secs(mono), Duration::from_secs(wall))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_frozen_machine_makes_the_loop_look_at_the_network_again_once() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(report_gaps(
            tx,
            Duration::from_secs(1),
            scripted_clocks(10, 600, false),
        ));

        // Nothing for the nine steady ticks; then one change for the gap.
        assert!(tokio::time::timeout(Duration::from_secs(8), rx.recv())
            .await
            .is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await,
            Ok(Some(()))
        );
        // And no second one while time passes normally.
        assert!(tokio::time::timeout(Duration::from_secs(60), rx.recv())
            .await
            .is_err());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_sleep_only_the_wall_clock_counted_is_noticed_too() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(report_gaps(
            tx,
            Duration::from_secs(1),
            scripted_clocks(3, 1_800, true),
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), rx.recv()).await,
            Ok(Some(()))
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_machine_that_never_freezes_never_sends_a_change() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(report_gaps(
            tx,
            Duration::from_secs(1),
            scripted_clocks(u64::MAX, 0, false),
        ));
        assert!(tokio::time::timeout(Duration::from_secs(600), rx.recv())
            .await
            .is_err());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_watcher_ends_when_nobody_is_listening() {
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(report_gaps(
            tx,
            Duration::from_secs(1),
            scripted_clocks(u64::MAX, 0, false),
        ));
        drop(rx);
        assert!(tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .is_ok());
    }
}
