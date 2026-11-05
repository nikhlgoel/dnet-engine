//! Pure domain logic: endpoints, profiles, paths, rules, health, sessions.
//!
//! No I/O and no Windows API, so every invariant is unit-testable without a machine,
//! a network, or the supervised processes.
//!
//! See `specs/001-network-resilience-client/data-model.md`.

pub mod builtin_rules;
pub mod catalogue;
pub mod credential;
pub mod degraded;
pub mod doh_block;
pub mod doh_consent;
pub mod endpoint;
pub mod endpoint_health;
pub mod engine;
#[cfg(test)]
mod engine_sequences;
pub mod error;
pub mod failover;
pub mod failure;
pub mod fakeip;
pub mod feed;
pub mod guard;
pub mod health;
pub mod hostname;
pub mod ids;
pub mod migrate;
pub mod origin;
pub mod path;
pub mod path_monitor;
pub mod portal;
pub mod portal_expiry;
pub mod posture;
pub mod probe;
pub mod probe_plan;
pub mod profile;
pub mod profile_start;
pub mod quality;
pub mod registry;
pub mod reprobe;
pub mod rule;
pub mod rule_eval;
pub mod selection;
pub mod session;
pub mod survival_evidence;
pub mod telemetry;
pub mod tick_gap;
pub mod tier;
pub mod transport_params;
