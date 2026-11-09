//! Flux refinement-type bridge for Soroban smart contracts.
//!
//! This crate is the single dependency a Soroban (or plain Rust) crate adds to
//! write Flux specifications: it re-exports the `flux-rs` attribute macros
//! (which erase to no-ops under normal `cargo build` — zero runtime cost, no
//! nightly required), shared refinement predicates, refined newtypes, and
//! extern specs for `soroban-sdk` types.
//!
//! # Trust boundary
//!
//! Flux verifies **source-level arithmetic, bounds, and state-machine logic in
//! macro-free Rust**. It does NOT verify: `Env`/host functions, storage
//! round-trips, `#[contractimpl]`-generated dispatch and `TryFromVal` glue,
//! `require_auth`, cross-contract calls, or the source→wasm compilation gap.
//! The prescribed consumer architecture: keep refinement logic in plain
//! library functions, keep `#[contractimpl]` blocks as thin trusted
//! marshalling. Every `#[trusted]` item in this crate carries a `/// TRUST:`
//! comment stating the axiom being assumed.

#![no_std]

pub mod bn254;
pub mod defs;
pub mod prelude;
pub mod specs;
pub mod types;

// Escape hatch: the raw flux-rs surface for anything the prelude doesn't
// re-export.
pub use flux_rs;
