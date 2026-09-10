//! Pure domain logic: profiles, endpoints, health, failover.
//!
//! No I/O and no Windows API, so every invariant is unit-testable without a machine,
//! a network, or the supervised processes.
//!
//! See `specs/001-network-resilience-client/data-model.md`.

pub mod health;
pub mod profile;
pub mod session;
pub mod tier;
