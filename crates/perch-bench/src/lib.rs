//! Harness-only crate for the wire-format benchmark
//! (<https://github.com/stellar-registry/perch/issues/2>).
//!
//! The measurement lives in `tests/metered.rs`, which is `#[ignore]`d in
//! plain `cargo test` because it needs the bench contract wasms built
//! first. Run it via `just bench`. Results and analysis: see
//! `crates/perch-program/BENCH.md`.
