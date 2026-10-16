//! Probing connection profiles (T059, FR-004, HV-12).
//!
//! `dnet-core::probe` decides what a measurement means and which profile wins. This crate makes
//! the measurements. Each probe runs one profile in its own core process behind a loopback SOCKS
//! proxy (`dnet_config::probe`), fetches a known amount of data from a known origin through it,
//! and reports what happened. Several probes run at once, so profiles are raced without any of
//! them touching the machine's routing.
//!
//! - [`socks5`]: the smallest SOCKS5 client that can do the job.
//! - [`measure`]: one transfer through a proxy, reported as a `dnet_core::probe::ProfileProbe`.
//! - [`race`]: runs a probe per profile concurrently and applies the winner rule.
//! - [`runner`]: the real thing, spawning a core per probe.

pub mod measure;
pub mod race;
pub mod runner;
pub mod socks5;
