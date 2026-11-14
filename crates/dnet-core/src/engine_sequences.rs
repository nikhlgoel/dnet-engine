// SPDX-License-Identifier: GPL-3.0-or-later
//! Random sequences of events against the connection engine, with what must hold after every one of them.
//!
//! The engine's own tests are scenarios somebody thought of. This is for the ones nobody did: thousands of sequences
//! of the engine's inputs (connect, disconnect, a race ending, a tunnel coming up or failing, live checks, endpoint
//! probes, a changing environment, paths moving, connectivity changing) in orders that make no sense, against
//! different sets of profiles and endpoints. A fixed seed makes a failure reproducible, and it prints the sequence.
//!
//! What must hold, taken from the engine's own documentation and the project's rules:
//!
//! - **It never panics.** The engine is the part of the service that decides; a panic there ends the decisions.
//! - **There is never more than one tunnel.** An action starts a tunnel only if none is running, where "running" is
//!   what the actions say: started and not stopped.
//! - **A phase and the tunnel agree.** Starting and Connected have one running; Idle, Failed, Probing and Recovering
//!   have none. So a disconnect or a failure never leaves a tunnel behind, and a connection never claims to be up
//!   without one.
//! - **A disconnect always ends idle.**
//! - **A failure always has words for the person** (`explain`).
//!
//! Pure logic: no I/O, no clock but the one it is given.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use crate::degraded::{Change, Degradation, NoMove};
use crate::endpoint::Endpoint;
use crate::endpoint_health::fixtures::{degraded, healthy, unreachable};
use crate::engine::{Action, Engine, Environment, Input, Phase};
use crate::failure::{explain, Reach};
use crate::health::ProbeOutcome;
use crate::ids::{EndpointId, InterfaceId, ProfileId};
use crate::probe::{ProfileProbe, RaceDecision};
use crate::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use crate::quality::QualityBand;
use crate::session::FailureCause;
use crate::tier::FailoverTier;

/// A small, fast, fixed generator: the same seed gives the same sequence on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

const PROFILES: [(&str, ProfileKind); 3] = [
    ("awg", ProfileKind::AmneziaWg),
    ("hy2", ProfileKind::Hysteria2),
    ("reality", ProfileKind::VlessReality),
];

/// Names a sequence may mention: the three real ones, and one that does not exist.
const NAMES: [&str; 4] = ["awg", "hy2", "reality", "ghost"];

fn profile_id(rng: &mut Rng) -> ProfileId {
    ProfileId::new(NAMES[rng.below(NAMES.len())])
}

fn engine_for(rng: &mut Rng) -> (Engine, Vec<EndpointId>) {
    let profiles: Vec<ConnectionProfile> = PROFILES
        .iter()
        .filter(|_| rng.chance(80))
        .map(|(name, kind)| {
            ConnectionProfile::new(ProfileId::new(*name), *kind, ProfileParams::new())
        })
        .collect();
    let mut endpoints: Vec<Endpoint> = Vec::new();
    // Usually one to three, mostly good; sometimes none, sometimes all bad.
    let count = if rng.chance(5) { 0 } else { 1 + rng.below(3) };
    for n in 0..count {
        let label = format!("endpoint-{n}");
        endpoints.push(match rng.below(10) {
            0..=5 => healthy(&label, 20 + rng.below(100) as u64),
            6 | 7 => degraded(&label, 300),
            _ => unreachable(&label),
        });
    }
    let ids = endpoints.iter().map(Endpoint::id).collect();
    (Engine::new(profiles, endpoints), ids)
}

/// The move that makes progress from `phase`: what a well-behaved daemon would report next. Mixed with chaos, it takes a
/// sequence deep (connected, blocked, recovering) instead of bouncing off the first failure.
fn natural(rng: &mut Rng, phase: &Phase) -> Input {
    match phase {
        Phase::Idle | Phase::Failed(_) => Input::Connect { profile: None },
        Phase::Probing | Phase::Recovering => Input::RaceFinished {
            decision: if rng.chance(85) {
                RaceDecision::Selected {
                    profile: ProfileId::new(PROFILES[rng.below(PROFILES.len())].0),
                    tier: FailoverTier::Tier2,
                    bits_per_sec: 20_000_000,
                }
            } else {
                RaceDecision::NoneUsable
            },
            results: Vec::new(),
        },
        Phase::Starting { .. } => {
            if rng.chance(85) {
                Input::TunnelUp
            } else {
                Input::StartFailed(FailureCause::NoEndpointReachable)
            }
        }
        // Mostly failing checks: three in a row is a block, which is the road to Recovering. Now and then the
        // transport process exits instead (T182): restarted twice, and the third is the other road to Recovering.
        Phase::Connected { .. } if rng.chance(15) => core_exited(rng),
        Phase::Connected { .. } => Input::LiveCheck(if rng.chance(70) {
            crate::reprobe::LiveCheck::Failed
        } else {
            crate::reprobe::LiveCheck::Passed
        }),
    }
}

fn core_exited(rng: &mut Rng) -> Input {
    Input::CoreExited {
        code: rng.chance(60).then(|| rng.below(256) as i32),
    }
}

fn input(rng: &mut Rng, endpoints: &[EndpointId], phase: &Phase) -> Input {
    if rng.chance(55) {
        return natural(rng, phase);
    }
    match rng.below(15) {
        13 => core_exited(rng),
        0 | 1 => Input::Connect {
            profile: rng.chance(35).then(|| profile_id(rng)),
        },
        2 => Input::Disconnect,
        3 | 4 => {
            let decision = match rng.below(4) {
                0 => RaceDecision::Pending,
                1 => RaceDecision::NoneUsable,
                _ => RaceDecision::Selected {
                    profile: profile_id(rng),
                    tier: if rng.chance(50) {
                        FailoverTier::Tier1
                    } else {
                        FailoverTier::Tier2
                    },
                    bits_per_sec: rng.below(200) as u64 * 1_000_000,
                },
            };
            let results = (0..rng.below(4))
                .map(|_| {
                    let probe = match rng.below(3) {
                        0 => ProfileProbe::HandshakeFailed,
                        1 => ProfileProbe::HandshakeOnly,
                        _ => ProfileProbe::Transferred {
                            bytes: rng.below(5_000_000) as u64,
                            elapsed: Duration::from_millis(1 + rng.below(3_000) as u64),
                        },
                    };
                    (profile_id(rng), probe)
                })
                .collect();
            Input::RaceFinished { decision, results }
        }
        5 | 6 => Input::TunnelUp,
        7 => Input::StartFailed(match rng.below(4) {
            0 => FailureCause::NoUsablePath,
            1 => FailureCause::NoEndpointReachable,
            2 => FailureCause::AllProfilesBlocked,
            _ => FailureCause::ConfigurationInvalid {
                detail: "a made-up problem".to_owned(),
            },
        }),
        8 | 9 => Input::LiveCheck(if rng.chance(50) {
            crate::reprobe::LiveCheck::Passed
        } else {
            crate::reprobe::LiveCheck::Failed
        }),
        10 => {
            // An endpoint of the engine, or one it has never heard of.
            let endpoint = if !endpoints.is_empty() && rng.chance(85) {
                endpoints[rng.below(endpoints.len())]
            } else {
                EndpointId::new()
            };
            let outcome = if rng.chance(50) {
                ProbeOutcome::Ok {
                    rtt: Duration::from_millis(1 + rng.below(900) as u64),
                    loss: rng.chance(30),
                }
            } else {
                ProbeOutcome::Failed
            };
            Input::EndpointProbe { endpoint, outcome }
        }
        // Mostly a healthy machine, sometimes a bad one: a hostile environment on every other step would end every
        // sequence in Failed.
        11 => Input::Environment(Environment {
            privileged: rng.chance(96),
            usable_paths: if rng.chance(8) { 0 } else { 1 + rng.below(2) },
            captive_portal: rng.chance(6),
            configuration_error: rng
                .chance(4)
                .then(|| "the configuration is broken".to_owned()),
        }),
        12 => {
            if rng.chance(60) {
                Input::PathChanged {
                    from: rng
                        .chance(60)
                        .then(|| InterfaceId::new(rng.below(4) as u64)),
                    to: InterfaceId::new(rng.below(4) as u64),
                }
            } else if rng.chance(50) {
                Input::Connectivity(Change::Degraded(Degradation {
                    path: InterfaceId::new(rng.below(4) as u64),
                    band: if rng.chance(50) {
                        QualityBand::Poor
                    } else {
                        QualityBand::Unusable
                    },
                    staying: NoMove::OnlyPath,
                }))
            } else {
                Input::Connectivity(Change::Recovered {
                    path: InterfaceId::new(rng.below(4) as u64),
                })
            }
        }
        _ => Input::Reach(
            (0..rng.below(4))
                .map(|_| match rng.below(3) {
                    0 => Reach::Reachable,
                    1 => Reach::Unreachable,
                    _ => Reach::Unknown,
                })
                .collect(),
        ),
    }
}

/// What the actions say is running: a tunnel started and not stopped.
#[derive(Default)]
struct Model {
    tunnel: bool,
}

impl Model {
    fn apply(&mut self, actions: &[Action]) -> Result<(), String> {
        for action in actions {
            match action {
                Action::StartTunnel { .. } => {
                    if self.tunnel {
                        return Err("a tunnel was started while another was still running".into());
                    }
                    self.tunnel = true;
                }
                Action::StopTunnel => self.tunnel = false,
                _ => {}
            }
        }
        Ok(())
    }

    fn agrees_with(&self, phase: &Phase) -> Result<(), String> {
        let wanted = matches!(phase, Phase::Starting { .. } | Phase::Connected { .. });
        if self.tunnel != wanted {
            return Err(format!(
                "the phase is {phase:?} but a tunnel is {}",
                if self.tunnel {
                    "running"
                } else {
                    "not running"
                }
            ));
        }
        if let Phase::Failed(cause) = phase {
            let words = explain(cause);
            if words.title.trim().is_empty() || words.action.trim().is_empty() {
                return Err(format!("{cause:?} has no words for the person"));
            }
        }
        Ok(())
    }
}

/// How many steps ended in each phase: Idle, Probing, Starting, Connected, Recovering, Failed.
type Visits = [usize; 6];

fn slot(phase: &Phase) -> usize {
    match phase {
        Phase::Idle => 0,
        Phase::Probing => 1,
        Phase::Starting { .. } => 2,
        Phase::Connected { .. } => 3,
        Phase::Recovering => 4,
        Phase::Failed(_) => 5,
    }
}

/// One sequence. `Err` names the first invariant that broke, with every input so far.
fn run(seed: u64, steps: usize, visits: &mut Visits) -> Result<(), String> {
    let mut rng = Rng(seed | 1);
    let (mut engine, endpoints) = engine_for(&mut rng);
    let mut model = Model::default();
    let mut trace: Vec<String> = Vec::new();
    let mut now = Instant::now();
    for _ in 0..steps {
        let next = input(&mut rng, &endpoints, engine.phase());
        now += Duration::from_millis(rng.below(90_000) as u64);
        trace.push(format!("{next:?}"));
        let disconnecting = matches!(next, Input::Disconnect);
        let actions = engine.step(next, now);
        visits[slot(engine.phase())] += 1;
        let verdict = model
            .apply(&actions)
            .and_then(|()| model.agrees_with(engine.phase()))
            .and_then(|()| {
                if disconnecting && *engine.phase() != Phase::Idle {
                    Err(format!("a disconnect ended in {:?}", engine.phase()))
                } else {
                    Ok(())
                }
            });
        if let Err(problem) = verdict {
            return Err(format!(
                "seed {seed}: {problem}\nafter these inputs:\n  {}",
                trace.join("\n  ")
            ));
        }
    }
    Ok(())
}

#[test]
fn no_sequence_of_events_panics_or_leaves_a_tunnel_and_a_phase_disagreeing() {
    let mut failures: Vec<String> = Vec::new();
    let mut visits: Visits = [0; 6];
    for seed in 1..=4_000u64 {
        match catch_unwind(AssertUnwindSafe(|| run(seed, 60, &mut visits))) {
            Ok(Ok(())) => {}
            Ok(Err(problem)) => failures.push(problem),
            Err(_) => failures.push(format!("seed {seed}: the engine panicked")),
        }
        if failures.len() >= 3 {
            break;
        }
    }
    assert!(
        failures.is_empty(),
        "{} sequence(s) broke an invariant; the first:\n{}",
        failures.len(),
        failures[0]
    );
    // The sequences must really have gone everywhere, or "nothing broke" says little: every phase, many times.
    let names = [
        "Idle",
        "Probing",
        "Starting",
        "Connected",
        "Recovering",
        "Failed",
    ];
    for (name, count) in names.iter().zip(visits) {
        assert!(
            count >= 2_000,
            "the sequences ended a step in {name} only {count} times: {visits:?}"
        );
    }
}

/// The check has to be able to fail, or the test above proves nothing: a model that is deliberately wrong about what
/// "running" means must be caught within a few sequences.
#[test]
fn the_check_notices_a_phase_and_a_tunnel_that_disagree() {
    let mut model = Model::default();
    assert!(model.agrees_with(&Phase::Idle).is_ok());
    model.tunnel = true;
    assert!(model.agrees_with(&Phase::Idle).is_err());
    assert!(model
        .apply(&[Action::StartTunnel {
            profile: ProfileId::new("hy2"),
            endpoint: EndpointId::new(),
        }])
        .is_err());
}
