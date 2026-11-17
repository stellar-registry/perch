//! Poseidon hash function implementation.
//!
//! This module provides the original Poseidon hash function matching circom's
//! implementation for compatibility with zero-knowledge proof systems.

pub(crate) mod params;
mod sponge;

pub use sponge::{PoseidonConfig, PoseidonSponge};
