# A clean Ubuntu to build and test the workspace on Linux (CLAUDE.md: a change must not break the Linux
# build; ADR-0005 proposes Linux as a second platform). Nothing here runs the product: `dnetd` refuses to
# run off Windows. It builds, lints and runs the portable tests.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config ca-certificates curl git python3 \
 && apt-get clean

# Stable for the checks CI runs, and the MSRV (CLAUDE.md: Rust 1.88).
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
 && rustup component add clippy rustfmt \
 && rustup toolchain install 1.88.0 --profile minimal

WORKDIR /work
