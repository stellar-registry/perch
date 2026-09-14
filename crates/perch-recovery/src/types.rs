//! Storage types for the recovery controller.
//!
//! Enrolled configuration is stored as-is from the compiler's wire type
//! (`perch_doc_compiler::CompiledRecoveryConfig`) — no separate controller-side
//! config type exists, so there is exactly one place the shape is defined.

use soroban_sdk::{contracttype, Address, BytesN, Vec};

/// Which action a proposal or evidence submission is for. Domain-separates
/// initiation from cancellation from reconfiguration: evidence collected for
/// one action never satisfies another, even for the same attempt or account.
#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub enum Action {
    /// Restore access after key loss: target is the current document with
    /// designated credentials replaced.
    LostKey,
    /// Restore an approved baseline after suspected compromise.
    Compromise,
    /// Cancel the identified attempt.
    Cancel,
    /// Change the enrolled recovery configuration itself.
    Reconfigure,
}

/// A recovery attempt's lifecycle state. `Expired` is deliberately not a
/// variant — it is derived from `expires_at` vs. the current ledger sequence
/// (see [`crate::contract::is_live`]), so no separate transition can ever
/// desync it from the stored timing fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub enum AttemptState {
    /// Declared; waiting for its mode's evidence to be satisfied.
    CollectingEvidence,
    /// Evidence satisfied; waiting out the timelock delay, then completable
    /// until it expires.
    AuthorizedPending,
    /// Consumed by a successful completion.
    Completed,
    /// Consumed by cancellation.
    Cancelled,
}

/// An account's single live-or-terminal recovery attempt. An account has at
/// most one `Attempt` in storage at a time; `begin_attempt` refuses to
/// replace a live one and replaces (releasing its nullifier) a terminal or
/// expired one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub struct Attempt {
    /// Monotonic per-account id — the proposal commitment's nonce.
    pub id: u64,
    pub action: Action,
    /// `sha256` of the exact bytes the caller must submit as `apply_doc`'s
    /// `doc_json` argument to complete this attempt. Frozen at
    /// `begin_attempt` and never recomputed — completion hashes the raw
    /// argument bytes it receives (it runs *before* `apply_doc`'s body, as
    /// part of authorization, so it has no access to the compiler's
    /// canonical `doc_hash`, which is only computed afterward). Whoever
    /// declares this value and whoever later submits the completion call
    /// must agree on the exact byte serialization — in practice, both sides
    /// should use the canonical bytes (`perch_ir::canonical_json` /
    /// `perch-js`'s `canonicalJson`) for consistency with `doc_hash`
    /// elsewhere in the system, but nothing here enforces that; a
    /// byte-for-byte match against whatever was declared is all that's
    /// checked.
    pub target_doc_hash: BytesN<32>,
    /// Credential fingerprints this attempt replaces (a subset of the
    /// enrolled config's `replaceable`, chosen by the caller at initiation —
    /// see `docs/recovery/`). Appended to the account's permanent revoked set
    /// on completion.
    pub replaced_credentials: Vec<BytesN<32>>,
    /// Ledger sequence `begin_attempt` ran at.
    pub created_at: u32,
    /// Ledger sequence at or after which a still-`CollectingEvidence` attempt
    /// is no longer live (see [`crate::contract::is_live`]) — bounds how long
    /// a permissionless `begin_*_attempt` call can hold `guard_apply_doc`'s
    /// unconditional live-attempt block open while no evidence ever arrives.
    /// Fixed at `begin_attempt` to `created_at + expiry_ledgers`; irrelevant
    /// once the attempt leaves `CollectingEvidence`.
    pub evidence_deadline: u32,
    /// Ledger sequence at or after which this attempt becomes completable,
    /// once authorized. `0` (unset) while `CollectingEvidence`.
    pub executable_after: u32,
    /// Ledger sequence at or after which an authorized attempt lapses.
    /// `0` (unset) while `CollectingEvidence`.
    pub expires_at: u32,
    /// Guardian addresses that have submitted approval for this attempt's
    /// initiation. Cancellation evidence is tracked separately (its own
    /// action domain — see [`crate::storage`]'s `cancel_tally`).
    pub guardian_approvals: Vec<Address>,
    /// Whether a valid initiation proof has been submitted for this attempt.
    pub zk_verified: bool,
    /// Nullifier consumed by this attempt's ZK evidence, if any (zero or one
    /// entry) — released back to unspent if the attempt is replaced before
    /// promotion, spent permanently on completion.
    pub nullifier: Vec<BytesN<32>>,
    pub state: AttemptState,
}
