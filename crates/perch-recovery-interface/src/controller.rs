//! The account-facing half of the recovery controller: the invoker-only
//! hooks the account calls (spec §10, §12, §15), what they return, and every
//! refusal a controller can produce.
//!
//! **No hook calls back into the account.** Soroban refuses to re-enter a
//! contract already on the call stack, and the account is on the stack for
//! every hook it calls. The account therefore passes each hook what it needs
//! (the compiled document hash and configuration, the approval freshness
//! bound, the upgrade step), and the controller reaches the account only from
//! its own external entry points (evidence submission, `begin_*`,
//! `publish_baseline`) through [`crate::account::RecoveryAccountClient`].

use crate::config::CompiledRecoveryConfig;
use crate::credential::Credential;
use crate::statement::UpgradeSubject;
use soroban_sdk::{contractclient, contracttype, Address, BytesN, Env, Vec};
use soroban_sdk_tools::scerr;

/// Everything a recovery controller can refuse. Codes are sequential from 1
/// in declaration order and are wire format: append new variants at the
/// end, never reorder.
#[scerr]
pub enum RecoveryError {
    /// No configuration is enrolled for this account at this controller.
    NotEnrolled,
    /// An attempt is authorized and live: begin, policy changes, and
    /// upgrades are refused until it completes, is cancelled, or expires.
    AttemptAuthorized,
    /// No attempt with this id exists for the account.
    NoSuchAttempt,
    /// The attempt is terminal, expired, from an older epoch, or
    /// invalidated by a sibling's authorization.
    AttemptNotLive,
    /// Initiation evidence for an attempt that is no longer collecting.
    AttemptNotCollecting,
    /// Completion before `executable_after`.
    NotExecutableYet,
    /// The completion context, or the compiled document hash, does not match
    /// the authorized attempt's target.
    WrongTarget,
    /// The address is not an enrolled guardian.
    NotAGuardian,
    /// This guardian or factor already counted for this statement.
    AlreadyCounted,
    /// The enrolled mode has no guardian factor.
    ModeHasNoGuardians,
    /// The enrolled mode has no ZK factor.
    ModeHasNoZk,
    /// The adapter refused the proof (its `ZkAdapterError` says why).
    ZkEvidenceRejected,
    /// The proof's nullifier is spent.
    NullifierSpent,
    /// The statement's freshness bound has passed or reaches too far.
    EvidenceExpired,
    /// The statement cannot be encoded (a non-contract account or
    /// controller).
    InvalidStatement,
    /// Recorded approvals do not satisfy the enrolled condition for this
    /// reconfiguration or upgrade.
    ConditionNotMet,
    /// The account's `max-cancels` is used up.
    MaxCancelsReached,
    /// Owner cancellation is only available under `Loss`.
    OwnerCancelRefused,
    /// The replacement set breaks a §7.3 rule, or derivation refused it.
    InvalidReplacements,
    /// The target or a replacement contains a revoked credential.
    CredentialRevoked,
    /// The ZK enrollment id was enrolled for this account before (the
    /// controller checks the account's `is_enrolled_id` at T1; the pure
    /// `derive_target` cannot see the account's history).
    EnrollmentIdReused,
    /// Compromise recovery with no baseline enrolled.
    NoBaseline,
    /// Compromise recovery before the baseline's content was published.
    BaselineNotPublished,
    /// The published document does not hash to the enrolled baseline.
    BaselineMismatch,
    /// The adapter's circuit id or tree depth does not match the enrolled
    /// factor and pool.
    ZkWiringMismatch,
    /// The ZK factor changed without a new enrollment id.
    ZkFactorChangedInPlace,
    /// The configuration is malformed (for example, the account is one of
    /// its own guardians, or the quorum is out of range).
    InvalidConfiguration,
    /// An upgrade request recorded under an older epoch.
    StaleUpgrade,
    /// A ledger-sequence computation overflowed `u32`.
    LedgerOverflow,
    /// The policy was attached to a context rule of the wrong shape.
    MalformedContextRule,
    /// A credential the replacement set replaces still appears in the
    /// target (a swap or a no-op replacement, spec §7.3 rule 8).
    ReplacedCredentialRetained,
}

/// What `rcv_sync` did, so the account knows which of its own effects to
/// apply (spec §10).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Nothing about recovery changed.
    Unchanged,
    /// A configuration was enrolled at this controller.
    Enrolled,
    /// The enrolled configuration was replaced.
    Reconfigured,
    /// The configuration was removed from this controller (recovery
    /// removed, or the account switched to another controller).
    Removed,
    /// The authorized attempt completed in this invocation. The account
    /// inserts the new leaf if the enrollment id changed, records the
    /// enrollment id, revokes [`Completion::revocations`] (spec §8), clears
    /// its pending upgrade, and clears its freeze mirror.
    Completed(Completion),
}

impl SyncOutcome {
    /// Whether the account's recovery generation must advance (spec §12):
    /// every outcome except `Unchanged` is a recovery-configuration
    /// transition that invalidates a queued upgrade.
    pub fn bumps_generation(&self) -> bool {
        !matches!(self, SyncOutcome::Unchanged)
    }
}

/// What a completion hands back to the account.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The attempt that completed.
    pub attempt_id: u64,
    /// The credentials that occupied the replaced signer slots **in the
    /// attempt's source document**, as derived at T1: the applied document
    /// for lost-key, the baseline for compromise. The account fingerprints
    /// them over canonical keys and revokes them together with every
    /// credential the completion removed from its current document. Without
    /// these, a baseline credential replaced by a compromise recovery, and
    /// already absent from the current document, would stay unrevoked and
    /// could be restored by a later recovery from the same baseline.
    pub replaced: Vec<Credential>,
}

/// Which phase of an account upgrade `rcv_upgrade` is checking (spec §12).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpgradeStep {
    /// `schedule_upgrade`: refuse during an authorized window; under
    /// `Protected`, require recorded approvals of this subject valid through
    /// the given ledger.
    Schedule(UpgradeSubject, u32),
    /// `execute_upgrade` of a request recorded at this epoch: refuse during
    /// an authorized window or if the epoch moved, then bump the epoch.
    Execute(u64),
}

/// The invoker-only hooks the account calls on its adopted controller. Each
/// starts with `account.require_auth()`, which only the account's own code
/// can satisfy: the account refuses these names in `__check_auth` and
/// `execute` (`crate::account::RESERVED_INVOKER_ONLY_FNS`).
#[allow(unused)]
#[contractclient(name = "RecoveryHooksClient")]
pub trait RecoveryHooksInterface {
    /// Called by every `apply_doc`, before any context rule is touched, with
    /// the compiled document's canonical hash, its recovery member (zero or
    /// one entry), and the freshness bound of any recorded reconfiguration
    /// approvals. Decides and writes; returns what the account must do.
    fn rcv_sync(
        e: &Env,
        account: Address,
        doc_hash: BytesN<32>,
        recovery: Vec<CompiledRecoveryConfig>,
        approval_valid_until: u32,
    ) -> Result<SyncOutcome, RecoveryError>;

    /// A `Loss` owner's cancellation of `attempt_id` (T7). Never counted
    /// toward `max-cancels`.
    fn rcv_cancel(e: &Env, account: Address, attempt_id: u64) -> Result<(), RecoveryError>;

    /// Checks an upgrade step and returns the account's epoch at this
    /// controller after it (the epoch a scheduled request records).
    fn rcv_upgrade(e: &Env, account: Address, step: UpgradeStep) -> Result<u64, RecoveryError>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_codes_are_sequential_from_one() {
        assert_eq!(RecoveryError::NotEnrolled as u32, 1);
        assert_eq!(RecoveryError::AttemptAuthorized as u32, 2);
        assert_eq!(RecoveryError::MalformedContextRule as u32, 30);
        assert_eq!(RecoveryError::ReplacedCredentialRetained as u32, 31);
    }
}
