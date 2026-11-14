// SPDX-License-Identifier: GPL-3.0-or-later
//! T100, T101 — the tray icon and the window (ADR-0007).
//!
//! This is glue, and it is kept thin: what it decides is in `dnet-view` where it is tested without a window
//! (the words, the rules, every command's meaning), and what it draws is in the web view. What is left here is
//! the part that has to be the operating system's: a native tray (R1), a window that exists only while it is
//! wanted (R2), and the commands the web view may give (R4).
//!
//! - **R1.** The tray and its menu are native and depend on no JavaScript: the state, the one control, "Open",
//!   and "Quit this app (the connection stays up)". Quitting this app leaves the service, and so the
//!   connection, exactly as it was.
//! - **R2.** The login start (`--background`) has no window; any other start opens one, and a second copy asks the
//!   first to (`single`). "Open" creates it hidden and shows it when the page has loaded. Closing it hides it; after
//!   a grace period nobody reopened it in, the web view is destroyed. While it is hidden nothing is sent to it.
//! - **R4.** The web view never touches the control pipe: its commands are the functions in `shell`, each of
//!   which goes through `dnet_view::Bridge`.
//!
//! The service is reached over the control pipe, which only the service owns: a pipe made by any other
//! program is refused. `--allow-unprivileged-service` lifts that for a development run of an unprivileged
//! `dnetd`, and says so on standard error.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
compile_error!("the DNet Engine window is Windows-only until ADR-0005 (Linux) is approved");

#[cfg(windows)]
mod shell;
#[cfg(windows)]
mod single;

#[cfg(windows)]
fn main() {
    shell::run();
}
