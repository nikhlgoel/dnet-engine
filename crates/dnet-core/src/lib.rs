//! Pure domain logic: endpoints, profiles, paths, rules, health, sessions.
//!
//! No I/O and no Windows API, so every invariant is unit-testable without a machine,
//! a network, or the supervised processes.
//!
//! See `specs/001-network-resilience-client/data-model.md`.

pub mod builtin_rules;
pub mod catalogue;
pub mod credential;
pub mod endpoint;
pub mod error;
pub mod feed;
pub mod health;
pub mod hostname;
pub mod ids;
pub mod path;
pub mod posture;
pub mod profile;
pub mod profile_start;
pub mod rule;
pub mod session;
pub mod tier;
pub mod transport_params;
