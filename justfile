test:
    cargo test --workspace

build:
    cargo build --workspace

build-contracts:
    stellar contract build --package perch-interpreter

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

# Build the RPN bench contract to metered wasm.
bench-build:
    cargo build -p perch-bench-rpn --target wasm32v1-none --release

# Run the metered RPN benchmark — the instruction-count canary for the frozen
# v1 format. Reference numbers: crates/perch-program/BENCH.md.
bench: bench-build
    cargo test -p perch-bench --test metered -- --ignored --nocapture

# Flux refinement verification of perch-program (nidohq/soroban-flux). Runs
# under flux's pinned nightly toolchain; the repo's stable pin is untouched —
# the flux attributes are no-ops in normal builds. Setup: see
# https://github.com/nidohq/soroban-flux (`just flux-setup` there).
flux:
    PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly-2026-02-05 FLUXFLAGS="-Fpointer-width=32 -Fcheck-overflow=strict -Fcache=target/flux-cache" cargo flux -p perch-program
