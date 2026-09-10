//! Named-pipe protocol, framing, and the authorization boundary.
//!
//! This crate is the privilege boundary between the unprivileged tray and the
//! LocalSystem service (Constitution Principle V).
//!
//! Contract: `specs/001-network-resilience-client/contracts/ipc-protocol.md`.

pub mod authz;
pub mod frame;
pub mod protocol;
pub mod server;
