//! DNet Engine privileged background service (`dnetd`).
//!
//! Runs as LocalSystem. It is the only component permitted to alter routing, DNS,
//! or adapter state (Constitution Principle V).
//!
//! See `specs/001-network-resilience-client/` for the governing specification.

fn main() -> anyhow::Result<()> {
    // Service lifecycle lands in T036; recovery replay in T038.
    Ok(())
}
