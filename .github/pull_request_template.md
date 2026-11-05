## What this changes

<!-- One or two sentences, and the task from specs/001-network-resilience-client/tasks.md (for example T123). -->

## How it was checked

<!-- What you ran and what it showed. Paste the result line, not "should work". -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo run -p xtask -- lint-branding`
- [ ] Window changes: `pnpm check && pnpm test && pnpm build` in `apps/dnet-tray`

## Before merging

- [ ] A test failed first, for the right reason
- [ ] The task's note in `tasks.md` (and any contract or ADR) is updated
- [ ] No endpoint, key or institution-specific value is hardcoded
- [ ] If this touches the IPC boundary, privileged operations, keys or credentials, routing or DNS, the
      undo path, the profile feed or core configuration: what was reviewed is written below

<!-- Security review notes, if any -->
