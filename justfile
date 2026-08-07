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
