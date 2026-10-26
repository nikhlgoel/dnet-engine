//! ETW real-time session; connect-time PID attribution.
//!
//! See `specs/001-network-resilience-client/` for the governing specification, and
//! `docs/adr/0001-etw-attribution.md` for the measurement that decided this exists and the byte-order
//! finding that every decoder here depends on.
//!
//! - [`attribution`] (T075): what one connect event says. Pure; the process id is the payload's, the ports
//!   are put into host order, and the result is named for what it is: [`BestEffortAttribution`].
//! - [`cache`] (T076): who connected recently, for a short time and a bounded number of connections. A
//!   miss is "no application rule matched", never a guess. Pure.
//! - `session` (T074, Windows only): the real-time trace on `Microsoft-Windows-Kernel-Network` that fills
//!   the cache. Needs elevation.
//! - `process` (Windows only): a process id to the path of its executable.
//!
//! Nothing here is wired into `dnetd` yet: the daemon starts the session, and fills the `application` of
//! `dnet_core::rule_eval::Flow` from the cache, when per-process rules are connected to the tunnel.

pub mod attribution;
pub mod cache;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod session;

pub use attribution::{BestEffortAttribution, FiveTuple, RawConnect};
pub use cache::{AttributionCache, Resolution, SharedCache};
