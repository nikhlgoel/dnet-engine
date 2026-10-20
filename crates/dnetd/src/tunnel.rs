//! T126 step 2 — bringing one tunnel up and taking it down, with nothing left half-done.
//!
//! The ordered sequences already exist and are tested where they live: `start_cores` (reap, then
//! the AmneziaWG core and its adapter, then the primary core), `bring_up` (host route before peer),
//! `tear_down` (peer before route) and `shutdown_all` (cores before undo replay). This module
//! composes them for one connection and owns what composition adds:
//!
//! - **A failed start leaves nothing running.** If the cores start and the peer cannot be
//!   configured, or the second core fails after the first is up, everything already started is taken
//!   down again before the failure is reported. A connect that fails must not leave a core holding
//!   the adapter or a route in the table; the next attempt would then fail for a reason nobody can
//!   see.
//! - **Only one tunnel at a time.** Starting while one is up takes the old one down first, so the
//!   orchestrator's ordering (stop, then start) cannot be bypassed by a caller that forgets it.
//! - **A stop is thorough and idempotent.** Peer, then route, then cores, then undo replay (kill
//!   before undo, so a core cannot re-add a route the replay removed). Stopping when nothing is up
//!   does nothing. A step that fails does not skip the steps after it: leaving state mutated is the
//!   worse outcome.
//!
//! Everything the OS does is behind [`TunnelHost`], whose real implementation is Windows-only.

use std::net::IpAddr;

use dnet_core::profile::CoreBinding;
use dnet_core::session::FailureCause;
use dnet_netstate::host_route::{bring_up, tear_down, HostRoute, TunnelBringup};
use dnet_netstate::NetstateError;
use dnet_supervisor::error::SupervisorError;
use dnet_supervisor::reap::start_cores;
use dnet_supervisor::runtime::CoreRuntime;
use dnet_supervisor::shutdown::shutdown_all;
use tokio::sync::Mutex;

use crate::plan::TunnelPlan;

/// What carrying a tunnel out needs from the machine.
pub trait TunnelHost: Send + Sync + 'static {
    type Runtime: CoreRuntime + Send + Sync + 'static;
    type Bringup: TunnelBringup + Send + Sync + 'static;

    /// The physical default gateway the endpoint host route goes through. Read once per start.
    fn gateway(&self) -> Result<IpAddr, NetstateError>;

    /// Write the primary core's configuration where only the service can read it, and build the
    /// objects that run this plan's cores and (for AmneziaWG) configure its peer. Does not start
    /// anything. `Err` is a message for the user, never a credential.
    fn prepare(&self, plan: &TunnelPlan) -> Result<Prepared<Self::Runtime, Self::Bringup>, String>;

    /// Remove what [`prepare`](Self::prepare) wrote. The configuration holds credentials, and the
    /// core has read it once it is up (or has failed to come up), so it must not outlive that.
    /// Called after every attempt to start the cores, whatever the outcome, and when stopping.
    /// Removing what is not there is not an error.
    fn discard_config(&self);
}

/// The objects one connection runs on.
pub struct Prepared<R, T> {
    pub runtime: R,
    /// Present for an AmneziaWG profile only.
    pub bringup: Option<T>,
}

/// A tunnel that is up.
struct Running<R, T> {
    runtime: R,
    /// The peer and the host route that guards it, for AmneziaWG.
    peer: Option<(T, HostRoute)>,
    /// Bringing the peer up has been started, so taking it down has something to undo. Until then
    /// there is no route to remove and possibly no control pipe to send to.
    peer_touched: bool,
}

/// The tunnel that is up, if any, and how to start and stop one.
pub struct Tunnels<H: TunnelHost> {
    host: H,
    active: Mutex<Option<Running<H::Runtime, H::Bringup>>>,
}

fn cause_of(error: &SupervisorError, started: CoreBinding) -> FailureCause {
    match error {
        SupervisorError::CoreFailedPersistently(core) => {
            FailureCause::CoreFailedPersistently { core: *core }
        }
        SupervisorError::Spawn { core, .. } | SupervisorError::NotReady { core, .. } => {
            FailureCause::CoreFailedPersistently { core: *core }
        }
        // Reaping, killing and the adapter wait name no core of their own: it is the one being
        // started.
        SupervisorError::Runtime(_) => FailureCause::CoreFailedPersistently { core: started },
    }
}

impl<H: TunnelHost> Tunnels<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            active: Mutex::new(None),
        }
    }

    /// Whether a tunnel is up.
    #[cfg(test)]
    pub async fn is_up(&self) -> bool {
        self.active.lock().await.is_some()
    }

    /// Bring the plan's tunnel up. On `Err` nothing of it is left running.
    pub async fn start(&self, plan: &TunnelPlan) -> Result<(), FailureCause> {
        let mut active = self.active.lock().await;
        if let Some(previous) = active.take() {
            tracing::warn!("a tunnel was still up when another was started; taking it down first");
            take_down(previous).await;
        }

        // Before anything is started, so a machine with no way out fails without side effects.
        let gateway = self.host.gateway().map_err(|error| {
            tracing::warn!(%error, "no default gateway");
            FailureCause::NoUsablePath
        })?;
        let prepared = self.host.prepare(plan).map_err(|detail| {
            tracing::error!(%detail, "could not prepare the connection");
            FailureCause::ConfigurationInvalid { detail }
        })?;

        let peer = match (prepared.bringup, &plan.awg) {
            (Some(bringup), Some(_)) => {
                Some((bringup, HostRoute::for_endpoint(&plan.bypass, gateway)))
            }
            _ => None,
        };
        let mut running = Running {
            runtime: prepared.runtime,
            peer,
            peer_touched: false,
        };

        let started = start_cores(&running.runtime, plan.core).await;
        // Read by the core by now, or never going to be.
        self.host.discard_config();
        if let Err(error) = started {
            tracing::error!(%error, "the cores did not start");
            take_down(running).await;
            return Err(cause_of(&error, plan.core));
        }
        if let Some((bringup, route)) = &running.peer {
            running.peer_touched = true;
            if let Err(error) = bring_up(bringup, route).await {
                tracing::error!(%error, "the tunnel peer could not be configured");
                take_down(running).await;
                // The peer is configured through the AmneziaWG core's control pipe.
                return Err(FailureCause::CoreFailedPersistently {
                    core: CoreBinding::AmneziaWgCore,
                });
            }
        }
        *active = Some(running);
        Ok(())
    }

    /// Take the tunnel down. Does nothing if none is up.
    pub async fn stop(&self) {
        if let Some(running) = self.active.lock().await.take() {
            take_down(running).await;
            self.host.discard_config();
        }
    }
}

/// Peer, route, cores, undo: in that order, every step attempted whatever happened before it.
async fn take_down<R: CoreRuntime, T: TunnelBringup>(running: Running<R, T>) {
    if let (true, Some((bringup, route))) = (running.peer_touched, &running.peer) {
        if let Err(error) = tear_down(bringup, route).await {
            tracing::error!(%error, "the tunnel peer or its host route could not be removed");
        }
    }
    if let Err(error) = shutdown_all(&running.runtime).await {
        tracing::error!(%error, "the cores could not all be stopped, or state could not be restored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex as StdMutex};

    use dnet_config::amneziawg::{ObfuscationParams, PeerConfig, PrivateKey};
    use dnet_config::ActiveEndpointBypass;
    use dnet_core::endpoint::EndpointAddress;

    use crate::plan::AwgTunnel;

    type Log = Arc<StdMutex<Vec<String>>>;

    fn note(log: &Log, what: impl Into<String>) {
        log.lock().unwrap().push(what.into());
    }

    #[derive(Clone, Default)]
    struct Faults {
        reap: bool,
        spawn_primary: bool,
        adapter: bool,
        install_route: bool,
        start_peer: bool,
        kill_primary: bool,
    }

    struct FakeRuntime {
        log: Log,
        faults: Faults,
    }

    impl CoreRuntime for FakeRuntime {
        async fn reap_orphans(&self) -> Result<(), SupervisorError> {
            note(&self.log, "reap");
            if self.faults.reap {
                return Err(SupervisorError::Runtime("denied".into()));
            }
            Ok(())
        }
        async fn spawn_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
            note(&self.log, format!("spawn:{core:?}"));
            if self.faults.spawn_primary && core == CoreBinding::PrimaryCore {
                return Err(SupervisorError::NotReady {
                    core,
                    detail: "exited".into(),
                });
            }
            Ok(())
        }
        async fn await_adapter(&self) -> Result<(), SupervisorError> {
            note(&self.log, "adapter");
            if self.faults.adapter {
                return Err(SupervisorError::NotReady {
                    core: CoreBinding::AmneziaWgCore,
                    detail: "no adapter".into(),
                });
            }
            Ok(())
        }
        async fn kill_core(&self, core: CoreBinding) -> Result<(), SupervisorError> {
            note(&self.log, format!("kill:{core:?}"));
            if self.faults.kill_primary && core == CoreBinding::PrimaryCore {
                return Err(SupervisorError::Runtime("still running".into()));
            }
            Ok(())
        }
        async fn replay_undo(&self) -> Result<(), SupervisorError> {
            note(&self.log, "undo");
            Ok(())
        }
    }

    struct FakeBringup {
        log: Log,
        faults: Faults,
    }

    impl TunnelBringup for FakeBringup {
        async fn install_host_route(&self, route: &HostRoute) -> Result<(), NetstateError> {
            note(
                &self.log,
                format!("route+:{}:{}", route.destination(), route.gateway()),
            );
            if self.faults.install_route {
                return Err(NetstateError::Operation("denied".into()));
            }
            Ok(())
        }
        async fn remove_host_route(&self, _: &HostRoute) -> Result<(), NetstateError> {
            note(&self.log, "route-");
            Ok(())
        }
        async fn rewrite_host_route(
            &self,
            _: &HostRoute,
            _: &HostRoute,
        ) -> Result<(), NetstateError> {
            note(&self.log, "route~");
            Ok(())
        }
        async fn start_tunnel(&self) -> Result<(), NetstateError> {
            note(&self.log, "peer+");
            if self.faults.start_peer {
                return Err(NetstateError::Operation("pipe closed".into()));
            }
            Ok(())
        }
        async fn stop_tunnel(&self) -> Result<(), NetstateError> {
            note(&self.log, "peer-");
            Ok(())
        }
        async fn rebind_tunnel(&self, _: IpAddr) -> Result<(), NetstateError> {
            note(&self.log, "rebind");
            Ok(())
        }
    }

    struct FakeHost {
        discarded: Arc<StdMutex<u32>>,
        log: Log,
        faults: Faults,
        gateway: Result<IpAddr, NetstateError>,
        prepare: Result<(), String>,
    }

    impl FakeHost {
        fn new(log: &Log) -> Self {
            Self {
                discarded: Arc::default(),
                log: log.clone(),
                faults: Faults::default(),
                gateway: Ok("192.168.1.1".parse().unwrap()),
                prepare: Ok(()),
            }
        }
        fn with(mut self, f: impl FnOnce(&mut Faults)) -> Self {
            f(&mut self.faults);
            self
        }
    }

    impl TunnelHost for FakeHost {
        type Runtime = FakeRuntime;
        type Bringup = FakeBringup;

        fn gateway(&self) -> Result<IpAddr, NetstateError> {
            note(&self.log, "gateway");
            self.gateway.clone()
        }
        fn discard_config(&self) {
            note(&self.log, "discard");
            *self.discarded.lock().unwrap() += 1;
        }
        fn prepare(&self, plan: &TunnelPlan) -> Result<Prepared<FakeRuntime, FakeBringup>, String> {
            note(&self.log, "prepare");
            self.prepare.clone()?;
            Ok(Prepared {
                runtime: FakeRuntime {
                    log: self.log.clone(),
                    faults: self.faults.clone(),
                },
                bringup: plan.awg.as_ref().map(|_| FakeBringup {
                    log: self.log.clone(),
                    faults: self.faults.clone(),
                }),
            })
        }
    }

    fn plan(core: CoreBinding) -> TunnelPlan {
        let address = EndpointAddress::new("203.0.113.10", 51820).unwrap();
        TunnelPlan::for_tests(
            core,
            ActiveEndpointBypass::new(&address),
            (core == CoreBinding::AmneziaWgCore).then(|| AwgTunnel {
                address: "10.66.0.2".parse().unwrap(),
                prefix_len: 24,
                private_key: PrivateKey::new("00"),
                obfuscation: ObfuscationParams {
                    jc: 4,
                    jmin: 40,
                    jmax: 70,
                    s1: 15,
                    s2: 20,
                    h1: 1,
                    h2: 2,
                    h3: 3,
                    h4: 4,
                },
                peer: PeerConfig {
                    public_key: "cd".into(),
                    endpoint: "203.0.113.10:51820".into(),
                    allowed_ips: vec!["0.0.0.0/0".into()],
                    persistent_keepalive: Some(25),
                },
            }),
        )
    }

    fn log() -> Log {
        Log::default()
    }

    fn seen(log: &Log) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    // ------------------------------------------------------------------ starting

    #[tokio::test]
    async fn amneziawg_starts_in_the_order_that_prevents_the_loop() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log));

        tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap();

        // Orphans first, the adapter before the primary core that binds to it, and the host route
        // before the peer that would otherwise send straight into the tunnel.
        assert_eq!(
            seen(&log),
            [
                "gateway",
                "prepare",
                "reap",
                "spawn:AmneziaWgCore",
                "adapter",
                "spawn:PrimaryCore",
                "discard",
                "route+:203.0.113.10:192.168.1.1",
                "peer+",
            ]
        );
        assert!(tunnels.is_up().await);
    }

    #[tokio::test]
    async fn a_primary_core_profile_starts_one_core_and_touches_no_route() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log));

        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap();

        assert_eq!(
            seen(&log),
            ["gateway", "prepare", "reap", "spawn:PrimaryCore", "discard"]
        );
    }

    #[tokio::test]
    async fn no_default_gateway_fails_before_anything_is_started() {
        let log = log();
        let mut host = FakeHost::new(&log);
        host.gateway = Err(NetstateError::Operation("no route".into()));
        let tunnels = Tunnels::new(host);

        let error = tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap_err();

        assert_eq!(error, FailureCause::NoUsablePath);
        assert_eq!(seen(&log), ["gateway"]);
        assert!(!tunnels.is_up().await);
    }

    #[tokio::test]
    async fn a_configuration_that_cannot_be_prepared_fails_before_anything_is_started() {
        let log = log();
        let mut host = FakeHost::new(&log);
        host.prepare = Err("the configuration file could not be written".into());
        let tunnels = Tunnels::new(host);

        let error = tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            FailureCause::ConfigurationInvalid {
                detail: "the configuration file could not be written".into()
            }
        );
        assert_eq!(seen(&log), ["gateway", "prepare"]);
    }

    // ------------------------------------------------------------------ failed starts

    #[tokio::test]
    async fn a_core_that_fails_to_start_leaves_nothing_running() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log).with(|f| f.spawn_primary = true));

        let error = tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            FailureCause::CoreFailedPersistently {
                core: CoreBinding::PrimaryCore
            }
        );
        // The AmneziaWG core that did start is killed, and the undo journal replayed. No route
        // was installed, so none is removed.
        let log = seen(&log);
        let start = log.iter().position(|e| e == "spawn:PrimaryCore").unwrap();
        assert_eq!(
            &log[start + 1..],
            ["discard", "kill:PrimaryCore", "kill:AmneziaWgCore", "undo"]
        );
        assert!(!tunnels.is_up().await);
    }

    #[tokio::test]
    async fn a_peer_that_cannot_be_configured_takes_the_route_and_both_cores_down() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log).with(|f| f.start_peer = true));

        let error = tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            FailureCause::CoreFailedPersistently {
                core: CoreBinding::AmneziaWgCore
            }
        );
        let log = seen(&log);
        let failed = log.iter().position(|e| e == "peer+").unwrap();
        assert_eq!(
            &log[failed + 1..],
            [
                "peer-",
                "route-",
                "kill:PrimaryCore",
                "kill:AmneziaWgCore",
                "undo"
            ]
        );
        assert!(!tunnels.is_up().await);
    }

    #[tokio::test]
    async fn a_host_route_that_cannot_be_installed_never_starts_the_peer() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log).with(|f| f.install_route = true));

        tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap_err();

        assert!(!seen(&log).contains(&"peer+".to_string()));
        assert!(seen(&log).contains(&"undo".to_string()));
        assert!(!tunnels.is_up().await);
    }

    #[tokio::test]
    async fn an_unreapable_orphan_is_reported_as_the_core_being_started() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log).with(|f| f.reap = true));

        let error = tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            FailureCause::CoreFailedPersistently {
                core: CoreBinding::AmneziaWgCore
            }
        );
    }

    // ------------------------------------------------------------------ stopping

    #[tokio::test]
    async fn stopping_removes_the_peer_then_the_route_then_the_cores_then_replays_undo() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log));
        tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap();
        log.lock().unwrap().clear();

        tunnels.stop().await;

        assert_eq!(
            seen(&log),
            [
                "peer-",
                "route-",
                "kill:PrimaryCore",
                "kill:AmneziaWgCore",
                "undo",
                "discard"
            ]
        );
        assert!(!tunnels.is_up().await);
    }

    #[tokio::test]
    async fn stopping_when_nothing_is_up_does_nothing() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log));

        tunnels.stop().await;
        tunnels.stop().await;

        assert!(seen(&log).is_empty());
    }

    #[tokio::test]
    async fn a_core_that_will_not_die_does_not_stop_the_undo_replay() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log).with(|f| f.kill_primary = true));
        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap();
        log.lock().unwrap().clear();

        tunnels.stop().await;

        assert!(seen(&log).contains(&"undo".to_string()), "{:?}", seen(&log));
        assert!(!tunnels.is_up().await, "the tunnel is not kept as up");
    }

    #[tokio::test]
    async fn starting_over_a_running_tunnel_takes_it_down_first() {
        let log = log();
        let tunnels = Tunnels::new(FakeHost::new(&log));
        tunnels
            .start(&plan(CoreBinding::AmneziaWgCore))
            .await
            .unwrap();
        log.lock().unwrap().clear();

        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap();

        let log = seen(&log);
        let undo = log.iter().position(|e| e == "undo").unwrap();
        let reap = log.iter().rposition(|e| e == "reap").unwrap();
        assert!(
            undo < reap,
            "the old tunnel is gone before the new one starts: {log:?}"
        );
        assert!(tunnels.is_up().await);
    }

    // ------------------------------------------------------------------ the credentials file

    /// The configuration holds credentials. It goes as soon as the core has read it, so it is not
    /// on disk for the whole time the tunnel is up.
    #[tokio::test]
    async fn the_configuration_is_discarded_as_soon_as_the_cores_are_up() {
        let log = log();
        let host = FakeHost::new(&log);
        let discarded = host.discarded.clone();
        let tunnels = Tunnels::new(host);

        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap();

        assert_eq!(*discarded.lock().unwrap(), 1);
        let log = seen(&log);
        let spawn = log.iter().position(|e| e == "spawn:PrimaryCore").unwrap();
        let discard = log.iter().position(|e| e == "discard").unwrap();
        assert!(
            discard > spawn,
            "discarded only once the core had read it: {log:?}"
        );
    }

    #[tokio::test]
    async fn the_configuration_is_discarded_when_the_cores_fail_to_start() {
        let log = log();
        let host = FakeHost::new(&log).with(|f| f.spawn_primary = true);
        let discarded = host.discarded.clone();
        let tunnels = Tunnels::new(host);

        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap_err();

        assert_eq!(*discarded.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn the_configuration_is_discarded_again_when_stopping() {
        let log = log();
        let host = FakeHost::new(&log);
        let discarded = host.discarded.clone();
        let tunnels = Tunnels::new(host);
        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap();

        tunnels.stop().await;

        assert_eq!(*discarded.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn nothing_is_discarded_when_nothing_was_prepared() {
        let log = log();
        let mut host = FakeHost::new(&log);
        host.gateway = Err(NetstateError::Operation("no route".into()));
        let discarded = host.discarded.clone();
        let tunnels = Tunnels::new(host);

        tunnels
            .start(&plan(CoreBinding::PrimaryCore))
            .await
            .unwrap_err();
        tunnels.stop().await;

        assert_eq!(*discarded.lock().unwrap(), 0);
    }
}
