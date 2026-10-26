#!/bin/bash
# Runs inside the container, with the source tar on stdin. See Invoke-LinuxChecks.ps1.
set -e
mkdir -p /work/src && cd /work/src
tar -xf -
export CARGO_TARGET_DIR=/work/target
echo "== clippy (stable, -D warnings)";   cargo clippy --workspace --all-targets -- -D warnings
echo "== tests (stable)";                  cargo test --workspace --no-fail-fast
echo "== check (MSRV 1.88)";               cargo +1.88.0 check --workspace --all-targets
echo "== lint-branding";                   cargo run -q -p xtask -- lint-branding
echo "ALL LINUX CHECKS PASSED"
