#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod debug;
pub mod ec;
pub mod field;
pub mod hash;
pub mod relations;
pub mod shplemini;
pub mod sumcheck;
pub mod transcript;
pub mod types;
pub mod utils;
pub mod verifier;
// Perch delta: the UltraKeccakZKFlavor verifier (see NOTICE).
pub mod zk;

pub const PROOF_FIELDS: usize = 456;
pub const PROOF_BYTES: usize = PROOF_FIELDS * 32;

pub use verifier::{UltraHonkVerifier, VerifyError, VkLoadError};
pub use zk::{UltraHonkZkVerifier, ZK_PROOF_BYTES, ZK_PROOF_FIELDS};
