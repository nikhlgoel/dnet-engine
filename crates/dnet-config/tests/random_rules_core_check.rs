// SPDX-License-Identifier: GPL-3.0-or-later
//! Any rule a person can add must produce a configuration the **pinned primary-core binary** accepts.
//!
//! `pinned_core_check.rs` runs the real core over a matrix of profiles with the built-in rules. The rules a person
//! adds are the open-ended input: a domain, a domain and everything under it, an address range, each sent through
//! the tunnel or around it. The rule model decides what is a rule; the core decides what it can run. A rule the
//! model takes and the core refuses would turn a saved setting into a connection that cannot start. This makes
//! many rule sets from a seeded generator (the same every run, so a failure can be repeated), keeps the ones the
//! model accepts, and asks the real core about each configuration. Skips, loudly, without the vendored binary.

use std::path::PathBuf;
use std::process::Command;

use dnet_config::primary::{generate_primary_core_config, to_json, FakeIpHalf, PrimaryCoreInput};
use dnet_config::ActiveEndpointBypass;
use dnet_core::builtin_rules::builtin_rules_for;
use dnet_core::doh_block::Policy;
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use dnet_core::rule::{IpCidr, RoutingRule, RuleAction, RuleMatcher};

fn pinned_core() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/primary-core/primary-core.exe");
    (cfg!(windows) && exe.is_file()).then_some(exe)
}

/// xorshift64*: a fixed seed gives the same sets every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn label(rng: &mut Rng) -> String {
    const MID: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    const EDGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let length = 1 + rng.below(20) as usize;
    (0..length)
        .map(|i| {
            let pool = if i == 0 || i + 1 == length { EDGE } else { MID };
            *rng.pick(pool) as char
        })
        .collect()
}

fn domain(rng: &mut Rng) -> String {
    const EDGES: &[&str] = &[
        "a.b",
        "xn--bcher-kva.example",
        "1.2.3.example",
        "EXAMPLE.COM",
        "Mixed.Case.Example.Org",
        "example.com.",
        "a-b.c-d.example",
        "localhost.localdomain",
        "x.y.z.example.co.uk",
    ];
    if rng.below(5) == 0 {
        return (*rng.pick(EDGES)).to_owned();
    }
    let labels = 2 + rng.below(3) as usize;
    let mut parts: Vec<String> = (0..labels).map(|_| label(rng)).collect();
    parts.push(["com", "net", "org", "io", "example", "co"][rng.below(6) as usize].to_owned());
    parts.join(".")
}

fn cidr(rng: &mut Rng) -> String {
    if rng.below(3) == 0 {
        let groups: Vec<String> = (0..8)
            .map(|_| format!("{:x}", rng.below(0x1_0000)))
            .collect();
        format!("{}/{}", groups.join(":"), rng.below(129))
    } else {
        format!(
            "{}.{}.{}.{}/{}",
            rng.below(256),
            rng.below(256),
            rng.below(256),
            rng.below(256),
            rng.below(33)
        )
    }
}

/// One matcher the model may or may not accept.
fn matcher(rng: &mut Rng) -> Option<RuleMatcher> {
    match rng.below(3) {
        0 => Some(RuleMatcher::Domain(domain(rng))),
        1 => Some(RuleMatcher::DomainSuffix(domain(rng))),
        _ => IpCidr::parse(&cidr(rng)).ok().map(RuleMatcher::IpCidr),
    }
}

#[test]
fn every_user_rule_the_model_accepts_makes_a_configuration_the_pinned_core_accepts() {
    let Some(core) = pinned_core() else {
        eprintln!("SKIPPED: vendor/primary-core not fetched (cargo run -p xtask -- fetch-vendor)");
        return;
    };
    let profile = ConnectionProfile::new(
        ProfileId::new("a"),
        ProfileKind::AmneziaWg,
        ProfileParams::new(),
    );
    let endpoint = EndpointAddress::new("203.0.113.9", 51820).unwrap();
    let mut rng = Rng(0x00D3_7E57_C0DE_0001);
    let (mut accepted, mut refused) = (0usize, 0usize);

    for trial in 0..100 {
        let policy = if trial % 2 == 0 {
            Policy::Block
        } else {
            Policy::Allow
        };
        let mut rules = builtin_rules_for(Some(&endpoint), policy);
        let wanted = 1 + rng.below(12) as usize;
        let mut precedence = 200u32;
        let mut made = Vec::new();
        for _ in 0..wanted {
            let Some(matcher) = matcher(&mut rng) else {
                refused += 1;
                continue;
            };
            let action = if rng.below(2) == 0 {
                RuleAction::Tunnel
            } else {
                RuleAction::Bypass
            };
            match RoutingRule::user(matcher.clone(), action, precedence) {
                Ok(rule) => {
                    accepted += 1;
                    precedence += 1;
                    made.push(format!("{action:?} {matcher:?}"));
                    rules.push(rule);
                }
                Err(_) => refused += 1,
            }
        }
        let half = if trial % 4 < 2 {
            FakeIpHalf::Low
        } else {
            FakeIpHalf::High
        };
        let config = generate_primary_core_config(PrimaryCoreInput {
            active_profile: &profile,
            endpoint_bypass: &ActiveEndpointBypass::new(&endpoint),
            rules: &rules,
            amneziawg_adapter: Some("dnet-awg0"),
            primary_transport: None,
            fakeip: half,
        })
        .unwrap_or_else(|e| {
            panic!("trial {trial}: the generator refused rules the model made: {e}\n{made:#?}")
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("primary-core.json");
        std::fs::write(&path, to_json(&config)).unwrap();
        let out = Command::new(&core)
            .args(["check", "-c"])
            .arg(&path)
            .arg("--disable-color")
            .output()
            .expect("running the pinned core");
        assert!(
            out.status.success(),
            "trial {trial}: the pinned core rejected a configuration made from rules the model accepted:\n{made:#?}\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // The sweep tried a real number of rules (a guard against it passing by trying almost nothing). The model may
    // refuse some or none of what the generator makes; that is the model's business, not this test's.
    assert!(
        accepted >= 200,
        "only {accepted} rules were accepted ({refused} refused)"
    );
}
