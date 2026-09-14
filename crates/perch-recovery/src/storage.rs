//! Typed storage handles, via `soroban-sdk-tools`' `#[contractstorage]` (see
//! `crates/perch-smart-account/src/lib.rs` for the same convention). All
//! persistent — recovery state must outlive the enrolling account's own
//! `applied_doc` bumps, and TTL is extended explicitly wherever a write
//! matters (see each call site in `contract.rs`).

use crate::types::Attempt;
use perch_doc_compiler::CompiledRecoveryConfig;
use soroban_sdk::{Address, BytesN, Vec};
use soroban_sdk_tools::{contractstorage, PersistentMap};

#[contractstorage]
#[allow(dead_code)] // the field names only derive storage keys + accessors
pub struct RecoveryStorage {
    /// Enrolled configuration per account. Written only by `install` (after
    /// `guard_apply_doc` has already authorized the change — see
    /// `contract.rs`'s module docs on why the gate can't live here).
    pub config: PersistentMap<Address, CompiledRecoveryConfig>,
    /// The account's single live-or-terminal attempt, if any.
    pub attempt: PersistentMap<Address, Attempt>,
    /// Monotonic per-account attempt-id counter — the proposal commitment's
    /// nonce. Never reused, even across terminal attempts.
    pub next_attempt_id: PersistentMap<Address, u64>,
    /// Cumulative cancellations across the account's whole history (§2.2's
    /// griefing bound), never reset by a new attempt.
    pub cancels_used: PersistentMap<Address, u32>,
    /// Guardian cancel-evidence for one `(account, attempt_id)` — a
    /// deliberately separate domain from `Attempt::guardian_approvals`
    /// (initiation evidence never counts toward cancellation, per §2.2).
    pub cancel_tally: PersistentMap<(Address, u64), Vec<Address>>,
    /// Whether a valid ZK cancellation proof has been verified for one
    /// `(account, attempt_id)`. Tracked separately from `cancel_tally` so
    /// `Combined` mode can require both factors before cancelling (§2.2) —
    /// each factor's own evidence is recorded independently and
    /// `cancel_attempt` only fires once the mode's full set is present.
    pub zk_cancel_verified: PersistentMap<(Address, u64), bool>,
    /// Permanent, append-only fingerprints of every credential this account
    /// has ever had recovery-revoked. A later attempt — even from an old
    /// baseline — must never reintroduce one of these.
    pub revoked: PersistentMap<Address, Vec<BytesN<32>>>,
    /// Global (not per-account) spent-nullifier set — a ZK nullifier's
    /// uniqueness is cross-account by design.
    pub nullifier: PersistentMap<BytesN<32>, bool>,
}
