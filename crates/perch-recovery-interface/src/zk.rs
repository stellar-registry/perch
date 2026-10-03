//! The ZK adapter boundary: what the recovery controller hands a ZK adapter,
//! what the adapter checks, and how a statement becomes circuit inputs.
//!
//! Three contracts sit behind one enrolled ZK factor, each constructorless
//! and immutable (`docs/recovery/spec.md`, "ZK adapter boundary"):
//!
//! - the **adapter** ([`ZkAdapterInterface`]) — the only contract the
//!   controller calls. It receives the *structured* [`RecoveryStatement`]
//!   (never a bare digest), so it derives the account and the statement
//!   digest from one value and cannot be handed an inconsistent pair. It
//!   checks the root against the enrolled pool, assembles the circuit's
//!   public inputs, and calls its build-pinned verifier. It is stateless:
//!   nullifier bookkeeping belongs to the controller.
//! - the **verifier** ([`ProofVerifierInterface`]) — a VK-baked,
//!   backend-specific proof checker (UltraHonk for the one supported
//!   backend), ABI-compatible with Nido's constructorless
//!   `nido-recovery-verifier`.
//! - the **membership pool** ([`MembershipPoolInterface`]) — account-bound
//!   commitments in rolling Merkle trees; the adapter only asks it whether a
//!   `(tree_id, root)` pair is acceptable.
//!
//! A second backend implements [`ZkAdapterInterface`] differently (its own
//! verifier, its own projection) without any change to the controller.

use crate::encode::contract_id;
use crate::statement::{RecoveryStatement, StatementError};
use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env};
use soroban_sdk_tools::scerr;

/// The BN254 scalar field modulus `r`, big-endian. Every circuit input and
/// output is an element of this field.
pub const BN254_SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Domain-tag labels. Each tag is `BE(sha256(label)) mod r` — Nido's
/// `nido/recovery/v1/<x>` derivation rule with perch v2 labels, so no v1
/// proof, leaf, or nullifier can be reinterpreted under v2.
pub const DOM_LEAF_LABEL: &str = "perch/recovery/zk/v2/leaf";
pub const DOM_BIND_LABEL: &str = "perch/recovery/zk/v2/bind";
pub const DOM_NULLIFIER_LABEL: &str = "perch/recovery/zk/v2/nullifier";
pub const DOM_AUTH_LABEL: &str = "perch/recovery/zk/v2/auth";

/// `inner = Poseidon2(DOM_LEAF, secret)`: the commitment a client computes.
pub const DOM_LEAF: [u8; 32] = [
    0x19, 0x81, 0xde, 0x3e, 0x07, 0x70, 0x96, 0x13, 0x86, 0x22, 0x72, 0xed, 0xb5, 0xff, 0x4f, 0xab,
    0x54, 0x57, 0x37, 0x38, 0x2d, 0x14, 0x05, 0xfe, 0x8d, 0x09, 0x70, 0xdc, 0x7d, 0x4d, 0x7e, 0xd6,
];
/// `leaf = Poseidon2(DOM_BIND, account_hi, account_lo, enrollment_hi,
/// enrollment_lo, inner)`: what the pool stores (it computes this itself
/// from the authorizing account; a caller never supplies a wrapped leaf).
pub const DOM_BIND: [u8; 32] = [
    0x20, 0xae, 0x61, 0x72, 0xaf, 0x8b, 0xed, 0x19, 0xc9, 0x21, 0xe9, 0x1e, 0x21, 0x64, 0x11, 0x98,
    0x66, 0x10, 0x35, 0x61, 0x6a, 0x6a, 0x4d, 0x73, 0x33, 0x46, 0x85, 0x35, 0x01, 0xfd, 0x07, 0xc5,
];
/// `nullifier = Poseidon2(DOM_NULLIFIER, account_hi, account_lo,
/// enrollment_hi, enrollment_lo, secret)`: one per enrolled credential.
pub const DOM_NULLIFIER: [u8; 32] = [
    0x02, 0x80, 0xc3, 0x17, 0x0f, 0x4a, 0xbb, 0x83, 0x89, 0x83, 0x8a, 0x5c, 0x28, 0x0d, 0xbd, 0xac,
    0x8b, 0xfd, 0x7c, 0x75, 0xfc, 0xb7, 0x80, 0xa9, 0x48, 0x5d, 0x93, 0xaf, 0x55, 0x3a, 0xb8, 0x40,
];
/// `statement_hash = Poseidon2(DOM_AUTH, account_hi, account_lo,
/// enrollment_hi, enrollment_lo, digest_hi, digest_lo)`: the third public
/// input. See [`ZkStatementFields::auth_preimage`].
pub const DOM_AUTH: [u8; 32] = [
    0x04, 0xe4, 0xc9, 0x9c, 0x74, 0x77, 0x37, 0x9c, 0x7e, 0x47, 0xc9, 0x38, 0x01, 0x70, 0xe3, 0xfb,
    0x1e, 0x7c, 0x56, 0x5a, 0xfe, 0x67, 0xdd, 0x56, 0x21, 0x6d, 0xf9, 0x98, 0x61, 0xf1, 0xfb, 0x3c,
];

/// Public-input blob length: `root || nullifier || statement_hash`, 32
/// bytes each, in the circuit's `pub` parameter order. Unchanged from
/// Nido's `zk_recovery_doc` layout.
pub const PUBLIC_INPUTS_LEN: u32 = 96;

/// Whether `x` (big-endian) is a canonical field element, i.e. `x < r`.
///
/// The adapter must refuse a non-canonical root or nullifier *before*
/// verifying: the verifier reduces inputs mod `r`, so `n` and `n + r` would
/// both verify while the controller stores them under different keys — two
/// spends of one credential.
pub fn is_canonical_field(x: &[u8; 32]) -> bool {
    for (a, m) in x.iter().zip(BN254_SCALAR_MODULUS.iter()) {
        if a != m {
            return a < m;
        }
    }
    false
}

/// Big-endian 16/16 split into two zero-extended 32-byte field elements,
/// each `< 2^128 < r` — Nido's `split16` convention.
pub fn split_hi_lo(x: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&x[..16]);
    lo[16..].copy_from_slice(&x[16..]);
    (hi, lo)
}

/// The field elements a statement contributes to the circuit, in
/// [`Self::auth_preimage`] order.
///
/// The circuit needs the account and the enrollment id as separate inputs
/// because it recomputes the leaf and the nullifier from them; everything
/// else (network, controller, action, configuration, subject, timing)
/// enters through the 32-byte statement digest. The statement can therefore
/// grow or change without changing the circuit, while the proof still binds
/// every field of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkStatementFields {
    pub account_hi: [u8; 32],
    pub account_lo: [u8; 32],
    pub enrollment_hi: [u8; 32],
    pub enrollment_lo: [u8; 32],
    pub digest_hi: [u8; 32],
    pub digest_lo: [u8; 32],
}

impl ZkStatementFields {
    /// `[DOM_AUTH, account_hi, account_lo, enrollment_hi, enrollment_lo,
    /// digest_hi, digest_lo]` — the arity-7 Poseidon2 preimage of the
    /// `statement_hash` public input.
    pub fn auth_preimage(&self) -> [[u8; 32]; 7] {
        [
            DOM_AUTH,
            self.account_hi,
            self.account_lo,
            self.enrollment_hi,
            self.enrollment_lo,
            self.digest_hi,
            self.digest_lo,
        ]
    }
}

/// Project `statement` and the enrolled `enrollment_id` onto circuit field
/// elements. The account comes from the same statement the digest is
/// computed over, so the two can never disagree.
pub fn zk_statement_fields(
    e: &Env,
    statement: &RecoveryStatement,
    enrollment_id: &BytesN<32>,
) -> Result<ZkStatementFields, StatementError> {
    let account = contract_id(e, &statement.account).ok_or(StatementError::AccountNotContract)?;
    let digest = statement.digest(e)?.to_array();
    let (account_hi, account_lo) = split_hi_lo(&account);
    let (enrollment_hi, enrollment_lo) = split_hi_lo(&enrollment_id.to_array());
    let (digest_hi, digest_lo) = split_hi_lo(&digest);
    Ok(ZkStatementFields {
        account_hi,
        account_lo,
        enrollment_hi,
        enrollment_lo,
        digest_hi,
        digest_lo,
    })
}

/// `root || nullifier || statement_hash`, the verifier's public-input blob.
pub fn public_inputs(
    e: &Env,
    root: &BytesN<32>,
    nullifier: &BytesN<32>,
    statement_hash: &BytesN<32>,
) -> Bytes {
    let mut out = Bytes::new(e);
    out.extend_from_array(&root.to_array());
    out.extend_from_array(&nullifier.to_array());
    out.extend_from_array(&statement_hash.to_array());
    out
}

/// Which enrolled ZK factor a statement is checked against. The controller
/// builds this from its stored configuration — never from caller input.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkBinding {
    /// The enrolled membership pool. Roots are accepted only from this pool.
    pub pool: Address,
    /// The enrolled credential's id, bound into its leaf and its nullifier.
    /// A leaf enrolled under any other id — including the account's own
    /// earlier enrollments — cannot satisfy a proof for this binding.
    pub enrollment_id: BytesN<32>,
    /// The circuit identity the enrolling document named. The adapter
    /// refuses any binding whose `circuit_id` is not its own.
    pub circuit_id: BytesN<32>,
}

/// One ZK proof as submitted.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkEvidence {
    /// The pool tree the proof's Merkle path is in.
    pub tree_id: u32,
    /// The root the proof was generated against; must be acceptable to the
    /// enrolled pool for `tree_id`.
    pub root: BytesN<32>,
    /// The credential's nullifier (the circuit's second public input).
    pub nullifier: BytesN<32>,
    /// The serialized proof.
    pub proof: Bytes,
}

/// Everything [`ZkAdapterInterface::verify`] can refuse. Each is a refusal
/// of this evidence only; none is a statement about the account.
#[scerr]
pub enum ZkAdapterError {
    /// The binding names a circuit this adapter does not verify.
    CircuitMismatch,
    /// The statement cannot be projected (its account or controller is not
    /// a contract address).
    InvalidStatement,
    /// The root or nullifier is not a canonical field element.
    NonCanonicalField,
    /// The enrolled pool does not accept `(tree_id, root)`.
    UnknownRoot,
    /// The enrolled pool could not be called.
    PoolUnavailable,
    /// The proof is not the length/shape the circuit produces.
    MalformedProof,
    /// The verifier rejected the proof.
    ProofRejected,
    /// The verifier could not be called or failed to parse its own key.
    VerifierUnavailable,
}

/// The controller-facing ZK boundary. Implementations are constructorless,
/// immutable, stateless, and pin their verifier at build time.
#[allow(unused)]
#[contractclient(name = "ZkAdapterClient")]
pub trait ZkAdapterInterface {
    /// The circuit identity this adapter verifies: `sha256` of the verifier's
    /// embedded verification key.
    fn circuit_id(e: &Env) -> BytesN<32>;

    /// `Ok(())` iff `evidence` proves knowledge of the credential enrolled
    /// as `binding.enrollment_id` for `statement.account`, against a root the
    /// enrolled pool accepts, for exactly this statement. Writes nothing.
    ///
    /// Required checks, in order: `binding.circuit_id` is this adapter's;
    /// root and nullifier are canonical field elements; the pool accepts
    /// `(evidence.tree_id, evidence.root)`; the proof verifies against
    /// [`public_inputs`] built from the root, the nullifier, and
    /// `Poseidon2(`[`ZkStatementFields::auth_preimage`]`)`.
    fn verify(
        e: &Env,
        statement: RecoveryStatement,
        binding: ZkBinding,
        evidence: ZkEvidence,
    ) -> Result<(), ZkAdapterError>;
}

/// The membership pool's read surface the adapter depends on. Insertion,
/// rollover, and renewal are the pool's own interface
/// (`docs/recovery/spec.md`, "Membership pool").
#[allow(unused)]
#[contractclient(name = "MembershipPoolClient")]
pub trait MembershipPoolInterface {
    /// Whether `root` is an acceptable root of tree `tree_id`: the final
    /// root of a sealed tree, or one of the active tree's retained recent
    /// roots.
    fn is_known_root(e: &Env, tree_id: u32, root: BytesN<32>) -> bool;
}

/// A backend verifier's refusals. Same names, order, and codes (1, 2, 3)
/// as Nido's constructorless `nido-recovery-verifier`, so either can sit
/// behind an adapter unchanged.
#[scerr]
pub enum ProofVerifierError {
    VkParseError,
    ProofParseError,
    VerificationFailed,
}

/// A VK-baked proof verifier (the UltraHonk backend's shape).
#[allow(unused)]
#[contractclient(name = "ProofVerifierClient")]
pub trait ProofVerifierInterface {
    fn verify_proof(
        e: &Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), ProofVerifierError>;
}

#[cfg(test)]
mod test;
