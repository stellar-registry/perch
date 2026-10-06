//! Controller state records (`docs/recovery/spec.md` §6).

use perch_recovery_interface::credential::Credential;
use perch_recovery_interface::RecoveryAction;
use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};

/// Which evidence an attempt-bound submission counts toward.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EvidenceDomain {
    /// The attempt's own `LostKey`/`Compromise` statement (T2-T4).
    Initiate = 0,
    /// The attempt's `Cancel` statement (T6).
    Cancel = 1,
}

/// What recovery currently restricts for an account (the controller's
/// `activity_gate` view, for clients; the account enforces the freeze from
/// its own mirror).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityGate {
    /// The authorized, live attempt, if any. While it is set, policy
    /// changes and upgrades are refused in both profiles.
    pub authorized_attempt: Option<u64>,
    /// `Protected` with an authorized attempt: the account authorizes
    /// nothing but that attempt's completion.
    pub frozen: bool,
    /// The authorized attempt's `expires_at`; `0` when none is authorized.
    pub until: u32,
}

/// An attempt's stored state. `Expired` is not a state, and neither is
/// invalidation by an epoch change or a sibling's authorization: those are
/// derived from the ledger, the account's epoch, and its `invalidate_below`
/// (see `contract::is_live`), so no transition can leave them out of date.
/// Only a stale lost-key source is recorded ([`AttemptState::Invalidated`]).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptState {
    /// Opened; collecting initiation evidence. Blocks nothing.
    Collecting,
    /// The condition was satisfied: timelock, then completion window.
    Authorized,
    /// Completed by the account's `apply_doc`.
    Completed,
    /// Cancelled by evidence (T6) or, under `Loss`, by the owner (T7).
    Cancelled,
    /// A lost-key attempt whose condition was met after the account's
    /// document moved off its source (T4). Recorded by the evidence call
    /// that found it, which succeeds: a refusal would roll the check back
    /// and leave the attempt promotable once the document changed back.
    Invalidated,
}

/// One lost-key or compromise recovery attempt (spec §6.3 T1).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// Per-account, never reused.
    pub id: u64,
    /// `LostKey` or `Compromise`.
    pub action: RecoveryAction,
    /// The epoch the attempt was opened under; it is dead under any other.
    pub epoch: u64,
    pub created_at: u32,
    /// Last ledger (inclusive) initiation evidence is accepted.
    pub evidence_deadline: u32,
    /// The `Cancel` statement's freshness bound: never earlier than the
    /// attempt's last live ledger.
    pub cancel_until: u32,
    /// Set at authorization; `0` while collecting.
    pub authorized_at: u32,
    /// First completable ledger; `0` while collecting.
    pub executable_after: u32,
    /// First ledger the authorized attempt is no longer live; `0` while
    /// collecting.
    pub expires_at: u32,
    /// Lost-key: the applied document's hash at T1. Compromise: the
    /// baseline's hash.
    pub source_doc_hash: BytesN<32>,
    /// The derived target's canonical hash.
    pub target_doc_hash: BytesN<32>,
    /// The derived target's recovery `config_hash` (the current one, or the
    /// current one with the declared ZK rotation).
    pub target_config_hash: BytesN<32>,
    /// `ReplacementSet::hash` of the declared replacements.
    pub replacements_hash: BytesN<32>,
    /// The credentials occupying the replaced signer slots in the source
    /// (the baseline's, for compromise), keys canonicalized. The completion
    /// returns them for the account to revoke (spec §8).
    pub replaced: Vec<Credential>,
    pub state: AttemptState,
    /// Distinct enrolled guardians that approved the initiation statement.
    pub guardians: Vec<Address>,
    /// The nullifier of the initiation proof, once one was accepted. A
    /// completion spends it.
    pub zk_nullifier: Option<BytesN<32>>,
    /// Distinct enrolled guardians that approved the cancel statement.
    pub cancel_guardians: Vec<Address>,
    /// Whether a cancellation proof was accepted.
    pub cancel_zk: bool,
}

/// Evidence recorded for one `Reconfigure` or `Upgrade` statement digest
/// (spec §5). Consumed by `rcv_sync`/`rcv_upgrade`, which rebuild the digest
/// from the change actually being made.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeApproval {
    pub guardians: Vec<Address>,
    pub zk: bool,
}

impl ChangeApproval {
    /// No evidence recorded.
    pub fn empty(e: &Env) -> Self {
        Self {
            guardians: Vec::new(e),
            zk: false,
        }
    }
}

/// Written by `enforce` when the recovery rule authorizes the completing
/// `apply_doc`, and consumed by that same invocation's `rcv_sync`
/// (spec T5). Its presence is what makes an `apply_doc` a completion.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionMarker {
    pub attempt_id: u64,
    pub target_doc_hash: BytesN<32>,
    /// The ledger `enforce` ran in. A marker from an earlier ledger is
    /// stale.
    pub ledger: u32,
}
