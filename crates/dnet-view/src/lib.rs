//! T100 — what the window is told, and what it may ask for (ADR-0007 R4).
//!
//! The window is a web view, and a web view is a place where text from the outside world is drawn. It never
//! touches the control pipe. This crate is the other side of that door: it asks the service through the typed
//! `dnet-ipc` client, decodes the replies with the typed decoders (which refuse what contradicts itself), and
//! hands the window small view-models in the shape its own parser expects. Nothing here draws anything, opens
//! a window or knows what Tauri is, so all of it is tested without a screen and builds on every platform; only
//! [`link::PipeLink`], which opens the Windows named pipe, is Windows-only.
//!
//! What is said, and in whose words:
//!
//! - A failure arrives as its cause and is given its title, detail and action by [`dnet_core::failure::explain`],
//!   the same words `dnetctl` shows (FR-039). There is no failure the window cannot name.
//! - A refusal is the service's own `detail`, cleaned and bounded, never a message of this crate's making.
//! - Nothing is invented for a service that cannot say. A service that predates `GetPaths` or `GetStats`
//!   (T144) yields a view that says nothing is being watched, which the window shows as "not measured", not as
//!   fine.
//!
//! The shapes are pinned by golden files in `tests/fixtures`, which the window's own tests parse with the
//! window's own parser, so the two sides cannot drift apart without a test failing on one of them.

pub mod approver;
pub mod bridge;
pub mod events;
pub mod link;
pub mod lists;
pub mod outcome;
pub mod session;
pub mod snapshot;
pub mod text;
pub mod tray;

pub use bridge::Bridge;
pub use link::Link;
