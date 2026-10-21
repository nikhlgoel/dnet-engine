//! T135 — choosing how to measure a path, and what a probe's silence means.
//!
//! There is no probe that works against every endpoint on every network, and measuring wrongly is
//! worse than not measuring: a probe that fails for a reason that has nothing to do with the path
//! would make a healthy path look dead and send the connection somewhere worse. So the rules are
//! about *when a probe's result may be believed*:
//!
//! - **Measure what the tunnel uses.** An endpoint probe is a TCP connection. It speaks for a path
//!   only when the active profile is carried over TCP. If the tunnel is UDP and a network blocks TCP
//!   to the endpoint, a failed TCP probe says nothing about whether the tunnel works there. For a UDP
//!   profile only the first hop can be measured (an authenticated handshake, the one honest UDP
//!   probe, would make the server re-point the live session at the probe's address, so it is out).
//! - **Silence counts only from a probe that has been heard.** A strategy that has never answered
//!   (the endpoint ignores pings, a gateway drops echoes) is *inapplicable*, not *failing*: its
//!   silence is no information, and the next strategy is tried. Once it has answered, silence is a
//!   real loss. Without this, the first network that drops a kind of probe would read as permanently
//!   dead.
//! - **Calibration has a scope.** Whether the endpoint answers is true of the endpoint, for every
//!   path. Whether a gateway answers is true of that gateway, for that path: one gateway answering
//!   echoes says nothing about another. Both are forgotten when the thing they were learned about
//!   changes (a new gateway, a different endpoint or carrier).
//!
//! A path nothing can measure stays unmeasured, which the failover logic treats as "not evidence
//! enough to move to", and which still moves when its link is lost. Pure logic: no I/O.

use std::collections::HashSet;
use std::time::Duration;

use crate::ids::InterfaceId;
use crate::profile::Carrier;
use crate::quality::PathSample;

/// A way of measuring a path, in order of preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// A connection to the endpoint's TCP port: the path as the tunnel uses it.
    Endpoint,
    /// An echo to the path's gateway: the first hop, which is where weak Wi-Fi and a congested
    /// access point show.
    Gateway,
}

/// What can be measured for one path right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Availability {
    /// How the active profile is carried.
    pub carrier: Carrier,
    /// Whether the endpoint serves a TCP port at all.
    pub endpoint_tcp: bool,
    /// Whether the path has a gateway to echo.
    pub gateway: bool,
}

/// What one probe saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Answered(Duration),
    Silent,
}

/// What a probe amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A real measurement.
    Sample(PathSample),
    /// Nothing can be concluded; try the next strategy.
    NoInformation,
}

/// What has been heard so far.
#[derive(Debug, Clone, Default)]
pub struct ProbePlanner {
    endpoint_heard: bool,
    gateways_heard: HashSet<InterfaceId>,
}

impl ProbePlanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// The strategies to try for a path, best first. Empty when nothing can be measured.
    pub fn order(&self, available: Availability) -> Vec<Strategy> {
        let mut order = Vec::with_capacity(2);
        if available.carrier == Carrier::Tcp && available.endpoint_tcp {
            order.push(Strategy::Endpoint);
        }
        if available.gateway {
            order.push(Strategy::Gateway);
        }
        order
    }

    /// What an observation means for `path`.
    pub fn judge(&mut self, strategy: Strategy, path: InterfaceId, seen: Observation) -> Verdict {
        let answered = matches!(seen, Observation::Answered(_));
        let heard_before = match strategy {
            Strategy::Endpoint => {
                let before = self.endpoint_heard;
                self.endpoint_heard |= answered;
                before
            }
            Strategy::Gateway => {
                let before = self.gateways_heard.contains(&path);
                if answered {
                    self.gateways_heard.insert(path);
                }
                before
            }
        };
        match seen {
            Observation::Answered(rtt) => Verdict::Sample(PathSample::Answered { rtt }),
            Observation::Silent if heard_before => Verdict::Sample(PathSample::Lost),
            Observation::Silent => Verdict::NoInformation,
        }
    }

    /// The endpoint, or the way it is reached, changed: what was learned about it no longer holds.
    pub fn forget_endpoint(&mut self) {
        self.endpoint_heard = false;
    }

    /// The path's gateway changed or the path went away.
    pub fn forget_gateway(&mut self, path: InterfaceId) {
        self.gateways_heard.remove(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> InterfaceId {
        InterfaceId::new(n)
    }

    fn ms(n: u64) -> Observation {
        Observation::Answered(Duration::from_millis(n))
    }

    fn avail(carrier: Carrier, endpoint_tcp: bool, gateway: bool) -> Availability {
        Availability {
            carrier,
            endpoint_tcp,
            gateway,
        }
    }

    // ------------------------------------------------------------------ what to try

    #[test]
    fn a_tcp_tunnel_is_measured_at_the_endpoint_first_then_the_first_hop() {
        let p = ProbePlanner::new();
        assert_eq!(
            p.order(avail(Carrier::Tcp, true, true)),
            [Strategy::Endpoint, Strategy::Gateway]
        );
    }

    /// The point of the module: a TCP probe does not speak for a UDP tunnel.
    #[test]
    fn a_udp_tunnel_is_never_measured_with_a_tcp_connection() {
        let p = ProbePlanner::new();
        assert_eq!(
            p.order(avail(Carrier::Udp, true, true)),
            [Strategy::Gateway]
        );
        assert!(p.order(avail(Carrier::Udp, true, false)).is_empty());
    }

    #[test]
    fn without_a_tcp_port_or_a_gateway_there_is_less_to_try() {
        let p = ProbePlanner::new();
        assert_eq!(
            p.order(avail(Carrier::Tcp, false, true)),
            [Strategy::Gateway]
        );
        assert_eq!(
            p.order(avail(Carrier::Tcp, true, false)),
            [Strategy::Endpoint]
        );
        assert!(p.order(avail(Carrier::Tcp, false, false)).is_empty());
    }

    // ------------------------------------------------------------------ what silence means

    #[test]
    fn an_answer_is_a_sample_with_its_round_trip_time() {
        let mut p = ProbePlanner::new();
        assert_eq!(
            p.judge(Strategy::Endpoint, id(1), ms(40)),
            Verdict::Sample(PathSample::Answered {
                rtt: Duration::from_millis(40)
            })
        );
    }

    #[test]
    fn silence_from_a_strategy_never_heard_is_no_information() {
        let mut p = ProbePlanner::new();
        assert_eq!(
            p.judge(Strategy::Endpoint, id(1), Observation::Silent),
            Verdict::NoInformation
        );
        assert_eq!(
            p.judge(Strategy::Gateway, id(1), Observation::Silent),
            Verdict::NoInformation
        );
    }

    #[test]
    fn silence_after_the_strategy_has_answered_is_a_loss() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Endpoint, id(1), ms(40));
        assert_eq!(
            p.judge(Strategy::Endpoint, id(1), Observation::Silent),
            Verdict::Sample(PathSample::Lost)
        );
    }

    #[test]
    fn the_endpoint_answering_on_one_path_makes_its_silence_on_another_a_loss() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Endpoint, id(1), ms(40));
        assert_eq!(
            p.judge(Strategy::Endpoint, id(2), Observation::Silent),
            Verdict::Sample(PathSample::Lost),
            "the endpoint is known to answer; this path does not reach it"
        );
    }

    /// One gateway answering echoes says nothing about another that drops them.
    #[test]
    fn a_gateway_that_never_answered_is_not_judged_by_another_that_did() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Gateway, id(1), ms(3));
        assert_eq!(
            p.judge(Strategy::Gateway, id(2), Observation::Silent),
            Verdict::NoInformation
        );
        assert_eq!(
            p.judge(Strategy::Gateway, id(1), Observation::Silent),
            Verdict::Sample(PathSample::Lost)
        );
    }

    // ------------------------------------------------------------------ forgetting

    #[test]
    fn a_new_endpoint_has_to_be_heard_again() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Endpoint, id(1), ms(40));
        p.forget_endpoint();
        assert_eq!(
            p.judge(Strategy::Endpoint, id(1), Observation::Silent),
            Verdict::NoInformation
        );
    }

    #[test]
    fn a_new_gateway_has_to_be_heard_again() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Gateway, id(1), ms(3));
        p.forget_gateway(id(1));
        assert_eq!(
            p.judge(Strategy::Gateway, id(1), Observation::Silent),
            Verdict::NoInformation
        );
    }

    #[test]
    fn forgetting_one_gateway_leaves_the_others() {
        let mut p = ProbePlanner::new();
        p.judge(Strategy::Gateway, id(1), ms(3));
        p.judge(Strategy::Gateway, id(2), ms(3));
        p.forget_gateway(id(1));
        assert_eq!(
            p.judge(Strategy::Gateway, id(2), Observation::Silent),
            Verdict::Sample(PathSample::Lost)
        );
    }

    // ------------------------------------------------------------------ rounds, end to end

    /// Try the strategies in order until one is informative, as the daemon will.
    fn measure(
        p: &mut ProbePlanner,
        path: u64,
        available: Availability,
        mut run: impl FnMut(Strategy) -> Observation,
    ) -> Option<PathSample> {
        for strategy in p.order(available) {
            let seen = run(strategy);
            if let Verdict::Sample(sample) = p.judge(strategy, id(path), seen) {
                return Some(sample);
            }
        }
        None
    }

    #[test]
    fn an_endpoint_that_ignores_probes_still_leaves_the_first_hop_to_measure() {
        let mut p = ProbePlanner::new();
        let a = avail(Carrier::Tcp, true, true);

        let sample = measure(&mut p, 1, a, |s| match s {
            Strategy::Endpoint => Observation::Silent,
            Strategy::Gateway => ms(4),
        });

        assert_eq!(
            sample,
            Some(PathSample::Answered {
                rtt: Duration::from_millis(4)
            })
        );
    }

    #[test]
    fn once_the_endpoint_has_answered_its_silence_outranks_a_healthy_first_hop() {
        let mut p = ProbePlanner::new();
        let a = avail(Carrier::Tcp, true, true);
        // Heard on path 1.
        measure(&mut p, 1, a, |s| match s {
            Strategy::Endpoint => ms(30),
            Strategy::Gateway => ms(3),
        });

        // On path 2 the first hop is fine but the endpoint cannot be reached: a loss, not a pass.
        let sample = measure(&mut p, 2, a, |s| match s {
            Strategy::Endpoint => Observation::Silent,
            Strategy::Gateway => ms(3),
        });

        assert_eq!(sample, Some(PathSample::Lost));
    }

    #[test]
    fn a_path_nothing_can_measure_yields_no_sample_at_all() {
        let mut p = ProbePlanner::new();
        let a = avail(Carrier::Udp, true, true);

        let sample = measure(&mut p, 1, a, |_| Observation::Silent);

        assert_eq!(
            sample, None,
            "a gateway that drops echoes, never heard: unmeasured"
        );
    }

    #[test]
    fn a_udp_tunnel_is_judged_by_the_first_hop_whatever_the_tcp_port_does() {
        let mut p = ProbePlanner::new();
        let a = avail(Carrier::Udp, true, true);
        let mut asked = Vec::new();

        let sample = measure(&mut p, 1, a, |s| {
            asked.push(s);
            ms(5)
        });

        assert_eq!(asked, [Strategy::Gateway], "the TCP port was never touched");
        assert!(matches!(sample, Some(PathSample::Answered { .. })));
    }
}
