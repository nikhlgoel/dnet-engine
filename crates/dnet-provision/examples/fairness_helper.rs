// SPDX-License-Identifier: GPL-3.0-or-later
//! Prints the fairness helper program, exactly as the scripts install it on a server, so a test outside Rust can run
//! the real thing against a real kernel (`testing/fairness`).

fn main() {
    print!("{}", dnet_provision::fairness::helper());
}
