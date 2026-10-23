//! `perch-zk-adapter`: the ZK recovery contract a controller enrolls and
//! cross-calls.
//!
//! It implements `perch-recovery-interface`'s `ZkAdapterInterface`: given the
//! controller's structured [`RecoveryStatement`], the enrolled [`ZkBinding`]
//! (pool, enrollment id, circuit id), and the submitted [`ZkEvidence`], it
//!
//! 1. refuses a binding that names another circuit;
//! 2. projects the statement onto the circuit's account, enrollment, and
//!    digest fields (`zk_statement_fields`);
//! 3. refuses a non-canonical root or nullifier;
//! 4. refuses a proof that is not [`PROOF_BYTES`] long;
//! 5. asks the enrolled pool whether it retains `(tree_id, root)`;
//! 6. checks the zero-knowledge proof against
//!    `root || nullifier || statement_hash` with this circuit's verification
//!    key and the `UltraKeccakZKFlavor` verifier in
//!    `vendor/ultrahonk-soroban-verifier`: NethermindEth's audited UltraHonk
//!    verifier plus perch's ZK delta (its `src/zk.rs`; see its NOTICE). Both
//!    are compiled in.
//!
//! The verifier is part of this wasm rather than a second contract the
//! adapter calls: the public-input layout is specific to the VK, so a new
//! circuit is a new adapter anyway, and an embedded verifier leaves no
//! address to pin or misconfigure. The raw verifier is still exposed as
//! `verify_proof` (`ProofVerifierInterface`, the same ABI as Nido's
//! constructorless `nido-recovery-verifier`).
//!
//! No constructor, no storage, no admin, no upgrade path: an instance's
//! behavior is a pure function of its wasm hash. See `docs/zk/README.md`.
//!
//! [`RecoveryStatement`]: perch_recovery_interface::RecoveryStatement
//! [`ZkBinding`]: perch_recovery_interface::zk::ZkBinding
//! [`ZkEvidence`]: perch_recovery_interface::zk::ZkEvidence
#![no_std]

/// Version of this adapter's semantics. A new version is a new wasm and
/// therefore a new address.
pub const VERSION: u32 = 1;

/// Merkle depth the compiled-in circuit proves (`tree_depth()`). Must equal
/// the enrolled pool's `depth()`.
#[cfg(not(feature = "tree-depth-24"))]
pub const CIRCUIT_DEPTH: u32 = 32;
#[cfg(feature = "tree-depth-24")]
pub const CIRCUIT_DEPTH: u32 = 24;

/// Size of a zero-knowledge UltraHonk proof (bb 0.87.0 `--zk`, keccak oracle:
/// 507 fields). A non-ZK proof (456 fields) is refused by length.
pub const PROOF_BYTES: u32 = ultrahonk_soroban_verifier::ZK_PROOF_BYTES as u32;

mod contract;

pub use contract::{PerchZkAdapter, PerchZkAdapterClient};

#[cfg(test)]
mod test;
