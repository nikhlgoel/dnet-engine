// SPDX-License-Identifier: GPL-3.0-or-later
//! Cloud provisioning, server bootstrap, keepalive, cleanup.
//!
//! See `specs/001-network-resilience-client/` for the governing specification, and
//! `contracts/provisioning.md` for the contract this crate implements (PR-01…PR-16).
//!
//! Nothing here talks to a real cloud. A job runs against a [`provider::Provider`], and the contract tests
//! (PRV-01…PRV-09) run it against a mock that creates nothing. A concrete provider is one implementation
//! of that trait.

pub mod bootstrap;
pub mod capacity;
pub mod cleanup;
pub mod client_keys;
pub mod credential;
pub mod devices;
pub mod fairness;
pub mod keepalive;
pub mod ledger;
pub mod manual;
#[doc(hidden)]
pub mod mock;
pub mod provider;
pub mod revoke;
pub mod sanitize;
pub mod secret;
pub mod server_pins;
pub mod stages;
pub mod verify;
