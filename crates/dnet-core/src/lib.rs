//! Pure domain logic: endpoints, profiles, paths, rules, health, sessions.
//!
//! No I/O and no Windows API, so every invariant is unit-testable without a machine,
//! a network, or the supervised processes.
//!
//! See `specs/001-network-resilience-client/data-model.md`.

pub mod credential;
pub mod endpoint;
pub mod error;
pub mod health;
pub mod ids;
pub mod path;
pub mod profile;
pub mod rule;
pub mod session;
pub mod tier;
