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

# Build the wire-format bench contracts (issue #2) to metered wasm.
bench-build:
    cargo build -p perch-bench-arena -p perch-bench-rpn --target wasm32v1-none --release

# Run the metered arena-vs-RPN benchmark; numbers land in crates/perch-program/BENCH.md.
bench: bench-build
    cargo test -p perch-bench --test metered -- --ignored --nocapture
