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
