use crate::{CIRCUIT_DEPTH, PROOF_BYTES, VERSION};
use perch_recovery_interface::zk::{
    is_canonical_field, public_inputs, zk_statement_fields, MembershipPoolClient,
    ProofVerifierError, ZkAdapterError, ZkBinding, ZkEvidence,
};
use perch_recovery_interface::RecoveryStatement;
use perch_zk_primitives::Hasher;
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

/// The verification key of `circuits/perch_zk_recovery` (or its depth-24
/// variant): `bb write_vk --scheme ultra_honk --oracle_hash keccak` output,
/// pinned by `circuits/manifest.json`.
#[cfg(not(feature = "tree-depth-24"))]
const VK: &[u8] = include_bytes!("../vk/perch_zk_recovery.vk");
#[cfg(feature = "tree-depth-24")]
const VK: &[u8] = include_bytes!("../vk/perch_zk_recovery_d24.vk");

#[contract]
pub struct PerchZkAdapter;

fn verifier(e: &Env) -> Option<UltraHonkVerifier> {
    UltraHonkVerifier::new(e, &Bytes::from_slice(e, VK)).ok()
}

#[contractimpl]
impl PerchZkAdapter {
    /// See [`VERSION`](crate::VERSION).
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// `ZkAdapterInterface::tree_depth`: see
    /// [`CIRCUIT_DEPTH`](crate::CIRCUIT_DEPTH). The controller checks it
    /// against the pool's `depth()` when a ZK factor is enrolled.
    pub fn tree_depth(_e: &Env) -> u32 {
        CIRCUIT_DEPTH
    }

    /// The compiled-in verification key.
    pub fn vk(e: &Env) -> Bytes {
        Bytes::from_slice(e, VK)
    }

    /// `sha256` of the compiled-in verification key: the circuit identity an
    /// account's configuration names in its ZK binding.
    pub fn circuit_id(e: &Env) -> BytesN<32> {
        e.crypto().sha256(&Self::vk(e)).to_bytes()
    }

    /// `ZkAdapterInterface::verify`. Writes nothing; nullifier bookkeeping
    /// and evidence freshness are the controller's.
    pub fn verify(
        e: &Env,
        statement: RecoveryStatement,
        binding: ZkBinding,
        evidence: ZkEvidence,
    ) -> Result<(), ZkAdapterError> {
        if binding.circuit_id != Self::circuit_id(e) {
            return Err(ZkAdapterError::CircuitMismatch);
        }
        let fields = zk_statement_fields(e, &statement, &binding.enrollment_id)
            .map_err(|_| ZkAdapterError::InvalidStatement)?;
        if !is_canonical_field(&evidence.root.to_array())
            || !is_canonical_field(&evidence.nullifier.to_array())
        {
            return Err(ZkAdapterError::NonCanonicalField);
        }
        if evidence.proof.len() != PROOF_BYTES {
            return Err(ZkAdapterError::MalformedProof);
        }

        // Only a root the enrolled pool itself produced for this tree.
        match MembershipPoolClient::new(e, &binding.pool)
            .try_is_known_root(&evidence.tree_id, &evidence.root)
        {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Err(ZkAdapterError::UnknownRoot),
            _ => return Err(ZkAdapterError::PoolUnavailable),
        }

        let statement_hash = Hasher::new(e).statement_hash(&fields);
        let inputs = public_inputs(e, &evidence.root, &evidence.nullifier, &statement_hash);
        let verifier = verifier(e).ok_or(ZkAdapterError::VerifierUnavailable)?;
        verifier
            .verify(&evidence.proof, &inputs)
            .map_err(|_| ZkAdapterError::ProofRejected)
    }

    /// `ProofVerifierInterface::verify_proof`: the raw verifier, for callers
    /// that assemble public inputs themselves. Same ABI and error codes as
    /// Nido's `nido-recovery-verifier`.
    pub fn verify_proof(
        e: &Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), ProofVerifierError> {
        if proof_bytes.len() != PROOF_BYTES {
            return Err(ProofVerifierError::ProofParseError);
        }
        let verifier = verifier(e).ok_or(ProofVerifierError::VkParseError)?;
        verifier
            .verify(&proof_bytes, &public_inputs)
            .map_err(|_| ProofVerifierError::VerificationFailed)
    }
}
