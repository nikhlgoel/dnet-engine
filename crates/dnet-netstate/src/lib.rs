//! Interfaces, routes, DNS, change notification, and restoration guarantees.
//!
//! See `specs/001-network-resilience-client/` for the governing specification.

pub mod adapter;
pub mod error;
pub mod host_route;
pub mod win_bringup;
pub mod win_route;

pub use error::NetstateError;
pub use host_route::{bring_up, on_carrying_path_change, tear_down, HostRoute, TunnelBringup};
