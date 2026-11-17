//! Poseidon2 hash function implementation.
//!
//! This module provides the Poseidon2 hash function matching noir's
//! implementation for compatibility with zero-knowledge proof systems.

pub(crate) mod params;
mod sponge;

pub use sponge::{Poseidon2Config, Poseidon2Sponge};
