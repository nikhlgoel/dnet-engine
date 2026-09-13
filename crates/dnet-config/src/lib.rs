//! Generates configuration for the supervised transport cores.
//!
//! `dnetd` generates configuration for two supervised processes and never patches,
//! forks, or links either. This crate turns pure `dnet-core` domain state into that
//! configuration, deterministically (CC-09), so generation is a testable pure function.
//!
//! **Naming obligation (binding).** The primary transport core is referred to here — in
//! types, config keys, tags, and paths — as `primary_core` / `PrimaryCore`, never by its
//! vendor name (contract §Naming, enforced by `xtask lint-branding`).
//!
//! **Schema note.** The concrete JSON key names the primary core consumes are fixed by
//! its pinned version; this crate encodes that mapping and asserts the *logic* (a rule
//! becomes the right kind of route entry, Brutal appears only when enabled, Profile A
//! binds to the AmneziaWG adapter and nothing else, output is byte-deterministic). The
//! mapping to the exact pinned schema is verified end-to-end at the SPIKE-R4 gate (T055)
//! against the real core, not guessed at here.
//!
//! See `specs/001-network-resilience-client/contracts/core-config.md`.

pub mod amneziawg;
pub mod bind;
pub mod brutal;
pub mod endpoint_bypass;
pub mod error;
pub mod hysteria2;
pub mod primary;
pub mod reality;
pub mod secret;
pub mod tls;
pub mod uapi;
pub mod uapi_pipe;
pub mod write;

pub use endpoint_bypass::ActiveEndpointBypass;
pub use error::ConfigError;
pub use primary::{
    generate_primary_core_config, to_json, PrimaryCoreConfig, PrimaryCoreInput, PrimaryTransport,
};
