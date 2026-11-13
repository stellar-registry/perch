//! The account's authorization types: its [`Signer`], the [`AuthPayload`]
//! `__check_auth` takes, the [`ContextRule`] its views return, and the
//! [`SmartAccountError`] codes a wallet reads from a refused authorization.
//!
//! Each has the name, fields or cases, and doc comments of OpenZeppelin's
//! type of the same name (`stellar-accounts`, at the workspace's pinned
//! rev), so its XDR and its contract-spec entry are identical to that
//! type's: a value written as one reads as the other, and wallets and
//! bindings see the same interface. `SmartAccountError` keeps only the codes
//! `__check_auth` refuses with. `tests/openzeppelin.rs` checks all of this
//! against OpenZeppelin's types.
//!
//! The doc comments are part of the spec entries, so they stay OpenZeppelin's
//! word for word; notes about Perch go in `//` comments.
#![no_std]

use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Map, String, Vec};

/// Represents different types of signers in the smart account system.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signer {
    /// A delegated signer that uses built-in signature verification.
    Delegated(Address),
    /// An external signer with custom verification logic.
    /// Contains the verifier contract address and the public key data.
    External(Address, Bytes),
}

/// The authorization payload passed to `__check_auth`, bundling cryptographic
/// proofs with context rule selection.
///
/// This struct carries two distinct pieces of information that are both
/// required for authorization but cannot be derived from each other:
///
/// - `signers` maps each [`Signer`] to its raw signature bytes, providing
///   cryptographic proof that the signer actually signed the transaction
///   payload. A context rule stores which signer *identities* are authorized
///   (via `signer_ids`), but the rule does not contain the signatures
///   themselves — those must be supplied here.
///
/// - `context_rule_ids` tells the system which rule to validate for each auth
///   context. Because multiple rules can exist for the same context type, the
///   caller must explicitly select one per context rather than relying on
///   auto-discovery. Each entry is aligned by index with the `auth_contexts`
///   passed to `__check_auth`.
///
/// The length of `context_rule_ids` must equal the number of auth contexts;
/// a mismatch is rejected with
/// [`SmartAccountError::ContextRuleIdsLengthMismatch`].
///
/// **Important:** `context_rule_ids` are bound into the digest that signers
/// authenticate against: `auth_digest = sha256(signature_payload ||
/// context_rule_ids.to_xdr())`. Signers must sign `auth_digest`, not the
/// raw `signature_payload` from the host. This prevents rule-selection
/// downgrade attacks.
// In Perch's account, `signature_payload` above is the host's payload
// already bound to the account's address (`bind_payload` in perch-smart-account).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AuthPayload {
    /// Signature data mapped to each signer.
    pub signers: Map<Signer, Bytes>,
    /// Per-context rule IDs, aligned by index with `auth_contexts`.
    pub context_rule_ids: Vec<u32>,
}

/// Types of contexts that can be authorized by smart account rules.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextRuleType {
    /// Default rules that can authorize any context.
    Default,
    /// Rules specific to calling a particular contract.
    CallContract(Address),
    /// Rules specific to creating a contract with a particular WASM hash.
    CreateContract(BytesN<32>),
    /// Rules specific to creating a contract from the executable reference that
    /// `owner` stores under `tag`.
    CreateContractExternalRef(Address, String),
}

/// A complete context rule defining authorization requirements.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContextRule {
    /// Unique identifier for the context rule.
    pub id: u32,
    /// The type of context this rule applies to.
    pub context_type: ContextRuleType,
    /// Human-readable name for the context rule.
    pub name: String,
    /// List of signers authorized by this rule.
    pub signers: Vec<Signer>,
    /// Global registry IDs for each signer, positionally aligned with
    /// `signers`.
    pub signer_ids: Vec<u32>,
    /// List of policy contracts that must be satisfied.
    pub policies: Vec<Address>,
    /// Global registry IDs for each policy, positionally aligned with
    /// `policies`.
    pub policy_ids: Vec<u32>,
    /// Optional expiration ledger sequence for the rule.
    pub valid_until: Option<u32>,
}

/// Error codes for smart account operations.
// OZ's codes, names, and doc comments for the refusals a wallet reads from
// `__check_auth`.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SmartAccountError {
    /// The specified context rule does not exist.
    ContextRuleNotFound = 3000,
    /// The provided context cannot be validated against any rule.
    UnvalidatedContext = 3002,
    /// External signature verification failed.
    ExternalVerificationFailed = 3003,
    /// context_rule_ids length does not match auth_contexts length.
    ContextRuleIdsLengthMismatch = 3014,
    /// A signer in `AuthPayload` is not part of any selected context rule.
    UnauthorizedSigner = 3016,
}
