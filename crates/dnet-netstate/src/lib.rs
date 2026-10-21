//! Interfaces, routes, DNS, change notification, and restoration guarantees.
//!
//! See `specs/001-network-resilience-client/` for the governing specification.

pub mod adapter;
pub mod echo;
pub mod error;
pub mod host_route;
pub mod notify;
pub mod paths;
pub mod probe;
pub mod undo;
pub mod undo_file;
pub mod win_bringup;
pub mod win_route;

pub use error::NetstateError;
pub use host_route::{
    bring_up, move_to_gateway, on_carrying_path_change, tear_down, HostRoute, TunnelBringup,
};
