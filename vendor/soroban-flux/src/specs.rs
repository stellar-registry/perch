//! Extern specs for `soroban-sdk` types (`Vec`, `Bytes`, `BytesN<N>`, `U256`,
//! `Env`).
//!
//! Populated as each spec is proven out against the probe crate (M0) — see
//! `crates/probe-sdk26/src/extern_specs.rs` for the staging ground. Extern
//! structs are opaque-only, methods cannot use `self`, and impl blocks must
//! mirror the SDK's exact generics/bounds, so each entry lands only once it
//! verifies.
//!
//! TRUST: every spec in this module is an axiom about `soroban-sdk` behavior,
//! not something Flux checks — keep each one minimal and obviously true.
