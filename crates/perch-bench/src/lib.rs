//! Harness-only crate for the metered RPN benchmark — the
//! instruction-count canary for the frozen v1 wire format (originally the
//! decision benchmark of
//! <https://github.com/stellar-registry/perch/issues/2>).
//!
//! The measurement lives in `tests/metered.rs`, which is `#[ignore]`d in
//! plain `cargo test` because it needs the bench contract wasm built
//! first. Run it via `just bench`. Decision numbers and analysis: see
//! `crates/perch-program/BENCH.md`.
