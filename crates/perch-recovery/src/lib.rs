//! `perch-recovery`: the shared account-recovery controller for opt-in
//! account recovery, generalizing a companion smart-account implementation's
//! validated experiment ([nidohq/nido#206]) into a perch crate. Guardian-only,
//! ZK-only, and combined recovery modes; general (not just additive)
//! reconfigure under `Protected`; `config_hash` commitment; constructorless
//! deployment. See `docs/recovery/` for the full design, governance, and the
//! open release-blocking pending-activity-policy gate.
//!
//! [nidohq/nido#206]: https://github.com/nidohq/nido/pull/206
//!
//! Mirrors `perch-doc-compiler`'s split: the error type, the evidence type,
//! and a client-only cross-contract interface are always available; the
//! actual controller (storage, the ZK statement/adapter, the `Policy` impl
//! and entry points) sits behind the default `contract` feature, so
//! `perch-smart-account` links no controller logic into account wasm — only
//! the client it cross-calls the *adopted* instance through.
#![no_std]

extern crate alloc;

use perch_doc_compiler::CompiledRecoveryConfig;
use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, Vec};
use soroban_sdk_tools::scerr;

/// Everything the controller's entry points can refuse.
#[scerr]
pub enum RecoveryError {
    /// No `RecoveryConfig` is enrolled for this account.
    NotEnrolled,
    /// `apply_doc` was attempted while a live (not completed/cancelled, not
    /// expired) attempt exists for this account.
    AttemptPending,
    /// No attempt exists, or it is terminal/expired.
    NoLiveAttempt,
    /// The attempt exists but its mode's evidence is not yet satisfied.
    AttemptNotAuthorized,
    /// An authorized attempt's timelock has not elapsed yet.
    AttemptNotExecutableYet,
    /// An authorized attempt has lapsed past its expiry.
    AttemptExpired,
    /// The document being applied does not hash to the attempt's committed
    /// target.
    WrongTarget,
    /// The same guardian already approved this evidence.
    AlreadyApproved,
    /// The address is not a member of the enrolled guardian set.
    NotAGuardian,
    /// The enrolled mode has no guardian factor at all.
    ModeHasNoGuardians,
    /// The enrolled mode has no ZK factor at all.
    ModeHasNoZk,
    /// The account's lifetime cancellation cap has been reached.
    MaxCancelsReached,
    /// A declared replaceable credential is not in the enrolled
    /// configuration's `replaceable` set.
    CredentialNotReplaceable,
    /// The nullifier has already been spent (by this account or another —
    /// nullifier uniqueness is global by design).
    NullifierAlreadySpent,
    /// The verifier rejected the proof.
    ZkProofInvalid,
    /// A `Protected` reconfiguration (including disabling recovery) was
    /// attempted without the currently-enrolled condition's evidence.
    ReconfigureEvidenceRequired,
    /// Suspected-compromise recovery was attempted with no baseline enrolled.
    NoBaselineEnrolled,
    /// A suspected-compromise attempt's target does not match the enrolled
    /// baseline's committed hash.
    TargetNotBaseline,
    /// A context rule attached this policy with the wrong shape (non-empty
    /// signers, or not scoped to the smart account calling itself).
    MalformedContextRule,
    /// Computing this attempt's timelock/expiry ledger sequence would
    /// overflow `u32`.
    TimelockOverflow,
}

/// Evidence accompanying an `apply_doc` call that changes a `Protected`
/// recovery configuration (including removing it). Ignored when no change is
/// being made, or the currently-enrolled profile is `Loss`. See
/// `docs/recovery/controller-governance.md`.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ReconfigureEvidence {
    /// A quorum-sized subset of the currently-enrolled guardian set, each of
    /// which must independently authorize this exact call (the host rejects
    /// the whole invocation if any named address didn't actually sign).
    pub guardians: Vec<Address>,
    /// Zero or one `(nullifier, proof)` pair, for a ZK-capable enrolled
    /// mode — two parallel `Option`s rather than one
    /// `Option<(BytesN<32>, Bytes)>` (or a dedicated struct) because a tuple
    /// isn't a `#[contracttype]`-representable field type and a wrapper
    /// struct would hit the same `Option<contracttype>` limitation
    /// `CompiledRule::install` documents — `BytesN<32>`/`Bytes` are
    /// host-builtin types, so a plain `Option` works for each individually.
    /// `require_zk_evidence` requires both present or both absent.
    pub zk_nullifier: Option<BytesN<32>>,
    pub zk_proof: Option<Bytes>,
}

/// Cross-contract client, generated independently of the deployable (see
/// module docs) — a consumer that only needs to cross-call an *adopted*
/// controller instance links no storage, ZK-adapter, or `Policy`-lifecycle
/// code at all. Every entry point `perch-smart-account`'s `apply_doc` calls
/// lives here; anything else (initiation, evidence submission, cancellation,
/// read-only queries) is only reachable with the `contract` feature on,
/// since only a recovering party or guardian — never the account's own
/// wasm — calls those.
#[allow(unused)]
#[contractclient(name = "RecoveryControllerClient")]
trait RecoveryControllerClientInterface {
    fn guard_apply_doc(
        e: &Env,
        account: Address,
        new_recovery: Vec<CompiledRecoveryConfig>,
        evidence: ReconfigureEvidence,
    ) -> Result<(), RecoveryError>;
}

#[cfg(feature = "contract")]
mod contract;
#[cfg(feature = "contract")]
mod storage;
#[cfg(feature = "contract")]
pub mod types;
#[cfg(feature = "contract")]
pub mod zk;

#[cfg(feature = "contract")]
pub use contract::{
    PerchRecovery, PerchRecoveryClient, RecoveryAuthorized, RecoveryCancelled, RecoveryCompleted,
};
