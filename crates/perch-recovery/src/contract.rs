//! The recovery controller: `docs/recovery/spec.md`'s state machine (§6),
//! completion and reconfiguration (§10), nullifiers (§11), and the
//! controller's half of account upgrades (§12).
//!
//! Who reaches what:
//!
//! - **Invoker-only hooks** (`rcv_sync`, `rcv_cancel`, `rcv_upgrade`, and
//!   the OZ `Policy` hooks `install`, `uninstall`, `enforce`) start with
//!   `account.require_auth()`. A perch account satisfies that only as the
//!   direct invoker: its `__check_auth` refuses these names, so no signature
//!   reaches them (spec §15, perch #90). They never call back into the
//!   account, which is on the call stack and cannot be re-entered.
//! - **Permissionless entry points** (`begin_*`, `submit_zk`,
//!   `submit_zk_change`, `publish_baseline`, `renew`) carry no authority:
//!   evidence is what authorizes, and the controller builds every statement
//!   from its own state.
//! - **Guardian entry points** (`submit_guardian`, `approve_change`) bind
//!   the guardian's `require_auth_for_args((digest,))` to one statement.
//!   Their names are not reserved, so guardians that are perch accounts can
//!   sign them.
//!
//! The controller is constructorless and immutable: no admin, no setter, no
//! upgrade path. It keeps only per-account, per-attempt, per-nullifier, and
//! per-digest storage.

use crate::storage::RecoveryStorage;
use crate::types::{
    ActivityGate, Attempt, AttemptState, ChangeApproval, CompletionMarker, EvidenceDomain,
};
use perch_doc_compiler::{admin_survives, DocCompilerClient};
use perch_recovery_interface::account::RecoveryAccountClient;
use perch_recovery_interface::config::{CompiledRecoveryConfig, CompiledZkFactor, RecoveryProfile};
use perch_recovery_interface::controller::{RecoveryError, SyncOutcome, UpgradeStep};
use perch_recovery_interface::credential::ReplacementSet;
use perch_recovery_interface::zk::{MembershipPoolClient, ZkAdapterClient, ZkEvidence};
use perch_recovery_interface::{
    AttemptSubject, CancelSubject, ConfigBinding, ConfigChange, RecoveryAction, RecoveryStatement,
    StatementError, StatementSubject, StatementTiming,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{
    contract, contractevent, contractimpl, panic_with_error, Address, Bytes, BytesN, Env, IntoVal,
    Symbol, TryFromVal, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

/// T1: an attempt was opened.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptBegun {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    pub action: RecoveryAction,
    pub target_doc_hash: BytesN<32>,
}

/// T4: an attempt's condition was satisfied.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptAuthorized {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    pub executable_after: u32,
    pub expires_at: u32,
}

/// T6/T7: an attempt was cancelled.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptCancelled {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    /// Whether this cancellation counted toward `max-cancels`.
    pub counted: bool,
}

/// T5: an attempt completed and its target was applied.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCompleted {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    pub target_doc_hash: BytesN<32>,
}

/// T9: the account's configuration at this controller changed (enrolled,
/// reconfigured, or removed), or an upgrade executed. `config_hash` is the
/// configuration now stored, if any.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochAdvanced {
    #[topic]
    pub account: Address,
    pub epoch: u64,
    pub config_hash: Option<BytesN<32>>,
}

/// Evidence for a `Reconfigure` or `Upgrade` statement was recorded.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeEvidenceRecorded {
    #[topic]
    pub account: Address,
    pub digest: BytesN<32>,
}

#[contract]
pub struct PerchRecovery;

#[contractimpl]
impl Policy for PerchRecovery {
    /// The configuration hash the recovery rule is installed for.
    type AccountParams = BytesN<32>;

    /// Bookkeeping only: `rcv_sync` already wrote the configuration, earlier
    /// in the same `apply_doc`. Checks that the recovery rule has the
    /// required shape and was installed for the stored configuration.
    fn install(
        e: &Env,
        install_params: BytesN<32>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        assert_recovery_rule(e, &context_rule, &smart_account);
        let config = RecoveryStorage::get_config(e, &smart_account)
            .unwrap_or_else(|| panic_with_error!(e, RecoveryError::NotEnrolled));
        if config.config_hash != install_params {
            panic_with_error!(e, RecoveryError::InvalidConfiguration);
        }
    }

    /// T5: authorize the completing `apply_doc`. The recovery rule has no
    /// signers, so this is the whole check: the context must be this
    /// account's `apply_doc` of the authorized attempt's exact target bytes,
    /// inside the completion window. It then leaves a marker that only the
    /// same invocation's `rcv_sync` consumes.
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if !authenticated_signers.is_empty() {
            panic_with_error!(e, RecoveryError::MalformedContextRule);
        }
        assert_recovery_rule(e, &context_rule, &smart_account);
        if let Err(err) = authorize_completion(e, &context, &smart_account) {
            panic_with_error!(e, err);
        }
    }

    /// Writes nothing: OZ discards `uninstall` failures, so it can gate
    /// nothing, and removal is decided by `rcv_sync`. Invoker-only like every
    /// hook, so no signature can call it either.
    fn uninstall(_e: &Env, _context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
    }
}

#[contractimpl]
impl PerchRecovery {
    // ----------------------------------------------------------------------
    // Invoker-only hooks
    // ----------------------------------------------------------------------

    /// The recovery side of the account's `apply_doc` (spec §10). Called
    /// before any context rule changes. Classifies the call as exactly one of
    /// completion, no change, enrollment, reconfiguration, or removal, and
    /// writes this controller's state for it.
    pub fn rcv_sync(
        e: &Env,
        account: Address,
        doc_hash: BytesN<32>,
        recovery: Vec<CompiledRecoveryConfig>,
        approval_valid_until: u32,
    ) -> Result<SyncOutcome, RecoveryError> {
        account.require_auth();
        let new = recovery.first();
        let stored = RecoveryStorage::get_config(e, &account);

        if let Some(marker) = RecoveryStorage::get_completing(e, &account) {
            RecoveryStorage::remove_completing(e, &account);
            return complete(e, &account, &marker, new.as_ref(), &doc_hash);
        }

        if authorized_live(e, &account).is_some() {
            return Err(RecoveryError::AttemptAuthorized);
        }

        let here = e.current_contract_address();
        let Some(stored) = stored else {
            // No configuration here: an enrollment, or nothing to do.
            let Some(new) = new else {
                return Ok(SyncOutcome::Unchanged);
            };
            if new.controller != here {
                return Err(RecoveryError::InvalidConfiguration);
            }
            check_config(&account, &new)?;
            check_zk_wiring(e, None, new.zk())?;
            store_config(e, &account, &new);
            return Ok(SyncOutcome::Enrolled);
        };

        if let Some(n) = &new {
            if n.controller == here && n.config_hash == stored.config_hash {
                return Ok(SyncOutcome::Unchanged);
            }
        }

        // Reconfiguration, removal, or a switch to another controller,
        // judged by the configuration enrolled here now.
        let change = match &new {
            Some(n) => ConfigChange::Set(n.config_hash.clone()),
            None => ConfigChange::Remove,
        };
        if stored.profile == RecoveryProfile::Protected {
            require_condition(
                e,
                &account,
                &stored,
                StatementSubject::Reconfigure(change),
                approval_valid_until,
            )?;
        }
        match new {
            Some(n) if n.controller == here => {
                check_config(&account, &n)?;
                check_zk_wiring(e, stored.zk(), n.zk())?;
                store_config(e, &account, &n);
                Ok(SyncOutcome::Reconfigured)
            }
            _ => {
                RecoveryStorage::remove_config(e, &account);
                RecoveryStorage::remove_authorized(e, &account);
                let epoch = bump_epoch(e, &account);
                EpochAdvanced {
                    account: account.clone(),
                    epoch,
                    config_hash: None,
                }
                .publish(e);
                Ok(SyncOutcome::Removed)
            }
        }
    }

    /// T7: a `Loss` owner cancels an attempt, through the account's
    /// `cancel_recovery`. Never counted toward `max-cancels`.
    pub fn rcv_cancel(e: &Env, account: Address, attempt_id: u64) -> Result<(), RecoveryError> {
        account.require_auth();
        let config = require_config(e, &account)?;
        if config.profile != RecoveryProfile::Loss {
            return Err(RecoveryError::OwnerCancelRefused);
        }
        let mut attempt = load_live(e, &account, attempt_id)?;
        cancel(e, &account, &config, &mut attempt, false)
    }

    /// The controller's half of the account's upgrade entry points
    /// (spec §12). Both steps are refused while an attempt is authorized.
    /// `Schedule` checks the recorded condition under `Protected` and
    /// returns the epoch the request binds; `Execute` refuses a request
    /// recorded under another epoch, then bumps the epoch and returns the
    /// new one.
    pub fn rcv_upgrade(e: &Env, account: Address, step: UpgradeStep) -> Result<u64, RecoveryError> {
        account.require_auth();
        let config = require_config(e, &account)?;
        if authorized_live(e, &account).is_some() {
            return Err(RecoveryError::AttemptAuthorized);
        }
        match step {
            UpgradeStep::Schedule(subject, approval_valid_until) => {
                if config.profile == RecoveryProfile::Protected {
                    require_condition(
                        e,
                        &account,
                        &config,
                        StatementSubject::Upgrade(subject),
                        approval_valid_until,
                    )?;
                }
                Ok(epoch_of(e, &account))
            }
            UpgradeStep::Execute(recorded_epoch) => {
                if recorded_epoch != epoch_of(e, &account) {
                    return Err(RecoveryError::StaleUpgrade);
                }
                let epoch = bump_epoch(e, &account);
                EpochAdvanced {
                    account: account.clone(),
                    epoch,
                    config_hash: Some(config.config_hash),
                }
                .publish(e);
                Ok(epoch)
            }
        }
    }

    // ----------------------------------------------------------------------
    // Attempts (T1-T4, T6)
    // ----------------------------------------------------------------------

    /// T1, lost-key: the target is the applied document with `replacements`
    /// applied. Permissionless. Returns the attempt id.
    pub fn begin_lost_key(
        e: &Env,
        account: Address,
        replacements: ReplacementSet,
    ) -> Result<u64, RecoveryError> {
        begin(e, account, RecoveryAction::LostKey, replacements)
    }

    /// T1, compromise: the target is the published baseline's signers and
    /// rules, with the current recovery member and `replacements` applied.
    /// Permissionless. Returns the attempt id.
    pub fn begin_compromise(
        e: &Env,
        account: Address,
        replacements: ReplacementSet,
    ) -> Result<u64, RecoveryError> {
        begin(e, account, RecoveryAction::Compromise, replacements)
    }

    /// T2: one guardian's approval of an attempt's statement in `domain`.
    /// The guardian authorizes `require_auth_for_args((digest,))` for
    /// exactly that statement.
    pub fn submit_guardian(
        e: &Env,
        account: Address,
        attempt_id: u64,
        domain: EvidenceDomain,
        guardian: Address,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let set = config
            .guardians()
            .ok_or(RecoveryError::ModeHasNoGuardians)?;
        if !set.guardians.contains(&guardian) {
            return Err(RecoveryError::NotAGuardian);
        }
        let mut attempt = load_live(e, &account, attempt_id)?;
        let counted = match domain {
            EvidenceDomain::Initiate => {
                if attempt.state != AttemptState::Collecting {
                    return Err(RecoveryError::AttemptNotCollecting);
                }
                &mut attempt.guardians
            }
            EvidenceDomain::Cancel => &mut attempt.cancel_guardians,
        };
        if counted.contains(&guardian) {
            return Err(RecoveryError::AlreadyCounted);
        }
        counted.push_back(guardian.clone());

        let statement = attempt_statement(e, &account, &config, &attempt, domain)?;
        check_fresh(e, &statement)?;
        let digest = digest(e, &statement)?;
        guardian.require_auth_for_args(Vec::from_array(e, [digest.into_val(e)]));

        after_evidence(e, &account, &config, &mut attempt, domain)
    }

    /// T3: a ZK proof for an attempt's statement in `domain`.
    /// Permissionless: the proof is the authorization.
    pub fn submit_zk(
        e: &Env,
        account: Address,
        attempt_id: u64,
        domain: EvidenceDomain,
        evidence: ZkEvidence,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let factor = config.zk().ok_or(RecoveryError::ModeHasNoZk)?;
        let mut attempt = load_live(e, &account, attempt_id)?;
        match domain {
            EvidenceDomain::Initiate => {
                if attempt.state != AttemptState::Collecting {
                    return Err(RecoveryError::AttemptNotCollecting);
                }
                if attempt.zk_nullifier.is_some() {
                    return Err(RecoveryError::AlreadyCounted);
                }
            }
            EvidenceDomain::Cancel => {
                if attempt.cancel_zk {
                    return Err(RecoveryError::AlreadyCounted);
                }
            }
        }
        let statement = attempt_statement(e, &account, &config, &attempt, domain)?;
        check_fresh(e, &statement)?;
        verify_zk(e, factor, &statement, &evidence)?;
        match domain {
            EvidenceDomain::Initiate => attempt.zk_nullifier = Some(evidence.nullifier),
            EvidenceDomain::Cancel => attempt.cancel_zk = true,
        }
        after_evidence(e, &account, &config, &mut attempt, domain)
    }

    // ----------------------------------------------------------------------
    // Reconfiguration and upgrade evidence (spec §5)
    // ----------------------------------------------------------------------

    /// One guardian's approval of a `Reconfigure` or `Upgrade` statement,
    /// fresh until `valid_until`. Recorded by digest for the consuming
    /// `rcv_sync`/`rcv_upgrade`.
    pub fn approve_change(
        e: &Env,
        account: Address,
        subject: StatementSubject,
        valid_until: u32,
        guardian: Address,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let set = config
            .guardians()
            .ok_or(RecoveryError::ModeHasNoGuardians)?;
        if !set.guardians.contains(&guardian) {
            return Err(RecoveryError::NotAGuardian);
        }
        let statement = change_statement_for(e, &account, &config, subject, valid_until)?;
        check_fresh(e, &statement)?;
        let digest = digest(e, &statement)?;
        let mut record = RecoveryStorage::get_approval(e, &(account.clone(), digest.clone()))
            .unwrap_or_else(|| ChangeApproval::empty(e));
        if record.guardians.contains(&guardian) {
            return Err(RecoveryError::AlreadyCounted);
        }
        guardian.require_auth_for_args(Vec::from_array(e, [digest.into_val(e)]));
        record.guardians.push_back(guardian);
        store_approval(e, &account, &digest, &record, valid_until);
        Ok(())
    }

    /// A ZK proof for a `Reconfigure` or `Upgrade` statement, fresh until
    /// `valid_until`. Permissionless. Does not spend the nullifier.
    pub fn submit_zk_change(
        e: &Env,
        account: Address,
        subject: StatementSubject,
        valid_until: u32,
        evidence: ZkEvidence,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let factor = config.zk().ok_or(RecoveryError::ModeHasNoZk)?;
        let statement = change_statement_for(e, &account, &config, subject, valid_until)?;
        check_fresh(e, &statement)?;
        let digest = digest(e, &statement)?;
        let mut record = RecoveryStorage::get_approval(e, &(account.clone(), digest.clone()))
            .unwrap_or_else(|| ChangeApproval::empty(e));
        if record.zk {
            return Err(RecoveryError::AlreadyCounted);
        }
        verify_zk(e, factor, &statement, &evidence)?;
        record.zk = true;
        store_approval(e, &account, &digest, &record, valid_until);
        Ok(())
    }

    /// Store the enrolled baseline's canonical bytes (spec §3.5).
    /// Permissionless: `doc_json` must compile, through the account's own
    /// compiler, to exactly the enrolled baseline hash and keep an admin
    /// rule. Publishing changes no authority.
    pub fn publish_baseline(
        e: &Env,
        account: Address,
        doc_json: Bytes,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let baseline = config.baseline.ok_or(RecoveryError::NoBaseline)?;
        let compiler = RecoveryAccountClient::new(e, &account).doc_compiler();
        let compiled = DocCompilerClient::new(e, &compiler)
            .try_compile_doc(&doc_json)
            .map_err(|_| RecoveryError::BaselineMismatch)?
            .map_err(|_| RecoveryError::BaselineMismatch)?;
        if compiled.doc_hash != baseline || !admin_survives(&compiled.rules) {
            return Err(RecoveryError::BaselineMismatch);
        }
        let key = (account, baseline);
        RecoveryStorage::set_baseline(e, &key, &compiled.canonical);
        RecoveryStorage::extend_baseline_ttl(e, &key, max_ttl(e), max_ttl(e));
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Views
    // ----------------------------------------------------------------------

    /// The account's configuration at this controller.
    pub fn config(e: &Env, account: Address) -> Option<CompiledRecoveryConfig> {
        RecoveryStorage::get_config(e, &account)
    }

    /// The account's configuration epoch (spec §3.3).
    pub fn epoch(e: &Env, account: Address) -> u64 {
        epoch_of(e, &account)
    }

    /// The id the next `begin_*` will assign.
    pub fn next_attempt_id(e: &Env, account: Address) -> u64 {
        RecoveryStorage::get_next_attempt(e, &account).unwrap_or(0)
    }

    /// An attempt's stored record, live or not.
    pub fn attempt(e: &Env, account: Address, attempt_id: u64) -> Option<Attempt> {
        load(e, &account, attempt_id)
    }

    /// Whether an attempt is live (spec §6.2).
    pub fn attempt_live(e: &Env, account: Address, attempt_id: u64) -> bool {
        load(e, &account, attempt_id).is_some_and(|a| is_live(e, &account, &a))
    }

    /// What recovery currently restricts for the account.
    pub fn activity_gate(e: &Env, account: Address) -> ActivityGate {
        let frozen_profile = RecoveryStorage::get_config(e, &account)
            .is_some_and(|c| c.profile == RecoveryProfile::Protected);
        match authorized_live(e, &account) {
            Some(a) => ActivityGate {
                authorized_attempt: Some(a.id),
                frozen: frozen_profile,
                until: a.expires_at,
            },
            None => ActivityGate {
                authorized_attempt: None,
                frozen: false,
                until: 0,
            },
        }
    }

    /// The exact statement evidence for an attempt must sign or prove in
    /// `domain`.
    pub fn statement(
        e: &Env,
        account: Address,
        attempt_id: u64,
        domain: EvidenceDomain,
    ) -> Result<RecoveryStatement, RecoveryError> {
        let config = require_config(e, &account)?;
        let attempt = load(e, &account, attempt_id).ok_or(RecoveryError::NoSuchAttempt)?;
        attempt_statement(e, &account, &config, &attempt, domain)
    }

    /// The exact statement a `Reconfigure` or `Upgrade` approval must sign
    /// or prove.
    pub fn change_statement(
        e: &Env,
        account: Address,
        subject: StatementSubject,
        valid_until: u32,
    ) -> Result<RecoveryStatement, RecoveryError> {
        let config = require_config(e, &account)?;
        change_statement_for(e, &account, &config, subject, valid_until)
    }

    /// Recorded evidence for a change statement digest.
    pub fn change_evidence(e: &Env, account: Address, digest: BytesN<32>) -> ChangeApproval {
        RecoveryStorage::get_approval(e, &(account, digest))
            .unwrap_or_else(|| ChangeApproval::empty(e))
    }

    /// The account that spent `nullifier`, if any.
    pub fn nullifier_spent(e: &Env, nullifier: BytesN<32>) -> Option<Address> {
        RecoveryStorage::get_nullifier(e, &nullifier)
    }

    /// The published content of the enrolled baseline, if any.
    pub fn baseline(e: &Env, account: Address) -> Option<Bytes> {
        let hash = RecoveryStorage::get_config(e, &account)?.baseline?;
        RecoveryStorage::get_baseline(e, &(account, hash))
    }

    /// Extend every persistent entry the account's recovery depends on to
    /// the network maximum (spec T10). Permissionless; changes no meaning.
    pub fn renew(e: &Env, account: Address) {
        let ttl = max_ttl(e);
        if let Some(config) = RecoveryStorage::get_config(e, &account) {
            RecoveryStorage::extend_config_ttl(e, &account, ttl, ttl);
            if let Some(hash) = config.baseline {
                let key = (account.clone(), hash);
                if RecoveryStorage::has_baseline(e, &key) {
                    RecoveryStorage::extend_baseline_ttl(e, &key, ttl, ttl);
                }
            }
        }
        if RecoveryStorage::has_epoch(e, &account) {
            RecoveryStorage::extend_epoch_ttl(e, &account, ttl, ttl);
        }
        if RecoveryStorage::has_next_attempt(e, &account) {
            RecoveryStorage::extend_next_attempt_ttl(e, &account, ttl, ttl);
        }
        if RecoveryStorage::has_invalidate_below(e, &account) {
            RecoveryStorage::extend_invalidate_below_ttl(e, &account, ttl, ttl);
        }
        if RecoveryStorage::has_cancels(e, &account) {
            RecoveryStorage::extend_cancels_ttl(e, &account, ttl, ttl);
        }
        if let Some(id) = RecoveryStorage::get_authorized(e, &account) {
            RecoveryStorage::extend_authorized_ttl(e, &account, ttl, ttl);
            let key = (account.clone(), id);
            if RecoveryStorage::has_attempt(e, &key) {
                RecoveryStorage::extend_attempt_ttl(e, &key, ttl, ttl);
            }
        }
    }

    /// Extend a spent nullifier's record to the network maximum.
    pub fn renew_nullifier(e: &Env, nullifier: BytesN<32>) {
        if RecoveryStorage::has_nullifier(e, &nullifier) {
            RecoveryStorage::extend_nullifier_ttl(e, &nullifier, max_ttl(e), max_ttl(e));
        }
    }
}

// --------------------------------------------------------------------------
// Transitions
// --------------------------------------------------------------------------

fn begin(
    e: &Env,
    account: Address,
    action: RecoveryAction,
    replacements: ReplacementSet,
) -> Result<u64, RecoveryError> {
    let config = require_config(e, &account)?;
    if authorized_live(e, &account).is_some() {
        return Err(RecoveryError::AttemptAuthorized);
    }
    let replacements_hash = replacements
        .hash(e)
        .map_err(|_| RecoveryError::InvalidReplacements)?;
    if config.zk().is_some() != (replacements.zk_enrollment.len() == 1) {
        return Err(RecoveryError::InvalidReplacements);
    }

    let view = RecoveryAccountClient::new(e, &account);
    let current = view.applied_doc().ok_or(RecoveryError::NotEnrolled)?;
    let source = match action {
        RecoveryAction::Compromise => {
            let hash = config.baseline.clone().ok_or(RecoveryError::NoBaseline)?;
            RecoveryStorage::get_baseline(e, &(account.clone(), hash))
                .ok_or(RecoveryError::BaselineNotPublished)?
        }
        _ => current.clone(),
    };
    let source_doc_hash: BytesN<32> = e.crypto().sha256(&source).to_bytes();

    let derived = DocCompilerClient::new(e, &view.doc_compiler())
        .try_derive_target(&source, &current, &action, &replacements)
        .map_err(|_| RecoveryError::InvalidReplacements)?
        .map_err(|_| RecoveryError::InvalidReplacements)?;
    for fingerprint in derived.fingerprints.iter() {
        if view.is_revoked(&fingerprint) {
            return Err(RecoveryError::CredentialRevoked);
        }
    }
    if let Some(z) = replacements.zk_enrollment.first() {
        if view.is_enrolled_id(&z.id) {
            return Err(RecoveryError::EnrollmentIdReused);
        }
    }

    let id = RecoveryStorage::get_next_attempt(e, &account).unwrap_or(0);
    RecoveryStorage::set_next_attempt(e, &account, &(id + 1));
    RecoveryStorage::extend_next_attempt_ttl(e, &account, max_ttl(e), max_ttl(e));

    let now = e.ledger().sequence();
    let evidence_deadline = add(now, config.expiry_ledgers)?;
    let cancel_until = add(
        add(evidence_deadline, config.delay_ledgers)?,
        config.expiry_ledgers,
    )?;
    let attempt = Attempt {
        id,
        action,
        epoch: epoch_of(e, &account),
        created_at: now,
        evidence_deadline,
        cancel_until,
        authorized_at: 0,
        executable_after: 0,
        expires_at: 0,
        source_doc_hash,
        target_doc_hash: derived.doc_hash.clone(),
        target_config_hash: derived.config_hash,
        replacements_hash,
        state: AttemptState::Collecting,
        guardians: Vec::new(e),
        zk_nullifier: None,
        cancel_guardians: Vec::new(e),
        cancel_zk: false,
    };
    save(e, &account, &attempt);
    AttemptBegun {
        account,
        attempt_id: id,
        action,
        target_doc_hash: derived.doc_hash,
    }
    .publish(e);
    Ok(id)
}

/// Record evidence, then promote (T4) or cancel (T6) if the domain's
/// condition is now satisfied.
fn after_evidence(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    attempt: &mut Attempt,
    domain: EvidenceDomain,
) -> Result<(), RecoveryError> {
    match domain {
        EvidenceDomain::Initiate => {
            if initiation_met(config, attempt) {
                promote(e, account, config, attempt)?;
            }
        }
        EvidenceDomain::Cancel => {
            if cancellation_met(config, attempt) {
                return cancel(e, account, config, attempt, true);
            }
        }
    }
    save(e, account, attempt);
    Ok(())
}

/// T4. Fixes the attempt's windows, invalidates every sibling in O(1), and
/// under `Protected` freezes the account.
fn promote(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    attempt: &mut Attempt,
) -> Result<(), RecoveryError> {
    if authorized_live(e, account).is_some() {
        return Err(RecoveryError::AttemptAuthorized);
    }
    let view = RecoveryAccountClient::new(e, account);
    if attempt.action == RecoveryAction::LostKey
        && view.applied_doc_hash() != Some(attempt.source_doc_hash.clone())
    {
        return Err(RecoveryError::AttemptNotLive);
    }
    let now = e.ledger().sequence();
    attempt.state = AttemptState::Authorized;
    attempt.authorized_at = now;
    attempt.executable_after = add(now, config.delay_ledgers)?;
    attempt.expires_at = add(attempt.executable_after, config.expiry_ledgers)?;

    let next = RecoveryStorage::get_next_attempt(e, account).unwrap_or(0);
    RecoveryStorage::set_invalidate_below(e, account, &next);
    RecoveryStorage::extend_invalidate_below_ttl(e, account, max_ttl(e), max_ttl(e));
    RecoveryStorage::set_authorized(e, account, &attempt.id);
    RecoveryStorage::extend_authorized_ttl(e, account, max_ttl(e), max_ttl(e));

    if config.profile == RecoveryProfile::Protected {
        view.rcv_gate(&attempt.id, &attempt.expires_at);
    }
    AttemptAuthorized {
        account: account.clone(),
        attempt_id: attempt.id,
        executable_after: attempt.executable_after,
        expires_at: attempt.expires_at,
    }
    .publish(e);
    Ok(())
}

/// T6 (`counted`) and T7. Cancelling a collecting attempt never counts.
fn cancel(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    attempt: &mut Attempt,
    counted: bool,
) -> Result<(), RecoveryError> {
    let was_authorized = attempt.state == AttemptState::Authorized;
    let counts = counted && was_authorized;
    if counts {
        let used = RecoveryStorage::get_cancels(e, account).unwrap_or(0);
        if used >= config.max_cancels {
            return Err(RecoveryError::MaxCancelsReached);
        }
        RecoveryStorage::set_cancels(e, account, &(used + 1));
        RecoveryStorage::extend_cancels_ttl(e, account, max_ttl(e), max_ttl(e));
    }
    attempt.state = AttemptState::Cancelled;
    save(e, account, attempt);
    if was_authorized {
        RecoveryStorage::remove_authorized(e, account);
        // T7 runs inside the account's own invocation and is `Loss`-only, so
        // no freeze exists to clear and the account is never re-entered.
        if config.profile == RecoveryProfile::Protected {
            RecoveryAccountClient::new(e, account).rcv_gate(&attempt.id, &0);
        }
    }
    AttemptCancelled {
        account: account.clone(),
        attempt_id: attempt.id,
        counted: counts,
    }
    .publish(e);
    Ok(())
}

/// The `enforce` half of T5.
fn authorize_completion(
    e: &Env,
    context: &Context,
    account: &Address,
) -> Result<(), RecoveryError> {
    let Context::Contract(ContractContext {
        contract,
        fn_name,
        args,
    }) = context
    else {
        return Err(RecoveryError::WrongTarget);
    };
    if contract != account || *fn_name != Symbol::new(e, "apply_doc") {
        return Err(RecoveryError::WrongTarget);
    }
    let target = args
        .first()
        .and_then(|v| Bytes::try_from_val(e, &v).ok())
        .ok_or(RecoveryError::WrongTarget)?;
    require_config(e, account)?;
    let attempt = authorized_live(e, account).ok_or(RecoveryError::AttemptNotLive)?;
    if e.ledger().sequence() < attempt.executable_after {
        return Err(RecoveryError::NotExecutableYet);
    }
    let hash: BytesN<32> = e.crypto().sha256(&target).to_bytes();
    if hash != attempt.target_doc_hash {
        return Err(RecoveryError::WrongTarget);
    }
    RecoveryStorage::set_completing(
        e,
        account,
        &CompletionMarker {
            attempt_id: attempt.id,
            target_doc_hash: hash,
        },
    );
    Ok(())
}

/// The `rcv_sync` half of T5 (spec §10, "Completion").
fn complete(
    e: &Env,
    account: &Address,
    marker: &CompletionMarker,
    new: Option<&CompiledRecoveryConfig>,
    doc_hash: &BytesN<32>,
) -> Result<SyncOutcome, RecoveryError> {
    let mut attempt = authorized_live(e, account).ok_or(RecoveryError::AttemptNotLive)?;
    if attempt.id != marker.attempt_id
        || attempt.target_doc_hash != marker.target_doc_hash
        || *doc_hash != attempt.target_doc_hash
    {
        return Err(RecoveryError::WrongTarget);
    }
    let new = new.ok_or(RecoveryError::WrongTarget)?;
    if new.controller != e.current_contract_address()
        || new.config_hash != attempt.target_config_hash
    {
        return Err(RecoveryError::WrongTarget);
    }
    if let Some(nullifier) = &attempt.zk_nullifier {
        if RecoveryStorage::has_nullifier(e, nullifier) {
            return Err(RecoveryError::NullifierSpent);
        }
        RecoveryStorage::set_nullifier(e, nullifier, account);
        RecoveryStorage::extend_nullifier_ttl(e, nullifier, max_ttl(e), max_ttl(e));
    }
    attempt.state = AttemptState::Completed;
    save(e, account, &attempt);
    RecoveryStorage::remove_authorized(e, account);
    store_config(e, account, new);
    RecoveryCompleted {
        account: account.clone(),
        attempt_id: attempt.id,
        target_doc_hash: attempt.target_doc_hash,
    }
    .publish(e);
    Ok(SyncOutcome::Completed(attempt.id))
}

// --------------------------------------------------------------------------
// Conditions and statements
// --------------------------------------------------------------------------

fn initiation_met(config: &CompiledRecoveryConfig, a: &Attempt) -> bool {
    config
        .guardians()
        .is_none_or(|g| a.guardians.len() >= g.quorum)
        && config.zk().is_none_or(|_| a.zk_nullifier.is_some())
}

fn cancellation_met(config: &CompiledRecoveryConfig, a: &Attempt) -> bool {
    config
        .guardians()
        .is_none_or(|g| a.cancel_guardians.len() >= g.quorum)
        && config.zk().is_none_or(|_| a.cancel_zk)
}

/// The recorded evidence for `subject` must satisfy the enrolled condition
/// (spec §5). The statement is rebuilt from this controller's state and the
/// change being made, so evidence for any other change does not count.
fn require_condition(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    subject: StatementSubject,
    valid_until: u32,
) -> Result<(), RecoveryError> {
    let statement = change_statement_for(e, account, config, subject, valid_until)?;
    check_fresh(e, &statement)?;
    let digest = digest(e, &statement)?;
    let record = RecoveryStorage::get_approval(e, &(account.clone(), digest))
        .ok_or(RecoveryError::ConditionNotMet)?;
    if let Some(set) = config.guardians() {
        let counted = record
            .guardians
            .iter()
            .filter(|g| set.guardians.contains(g))
            .count() as u32;
        if counted < set.quorum {
            return Err(RecoveryError::ConditionNotMet);
        }
    }
    if config.zk().is_some() && !record.zk {
        return Err(RecoveryError::ConditionNotMet);
    }
    Ok(())
}

fn statement(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    epoch: u64,
    valid_until_ledger: u32,
    subject: StatementSubject,
) -> RecoveryStatement {
    RecoveryStatement {
        network_id: e.ledger().network_id(),
        account: account.clone(),
        controller: e.current_contract_address(),
        config: ConfigBinding {
            epoch,
            config_hash: config.config_hash.clone(),
        },
        timing: StatementTiming {
            delay_ledgers: config.delay_ledgers,
            expiry_ledgers: config.expiry_ledgers,
            valid_until_ledger,
        },
        subject,
    }
}

fn initiation_statement(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    a: &Attempt,
) -> RecoveryStatement {
    let subject = AttemptSubject {
        attempt_id: a.id,
        source_doc_hash: a.source_doc_hash.clone(),
        target_doc_hash: a.target_doc_hash.clone(),
        replacements_hash: a.replacements_hash.clone(),
    };
    let subject = match a.action {
        RecoveryAction::Compromise => StatementSubject::Compromise(subject),
        _ => StatementSubject::LostKey(subject),
    };
    statement(e, account, config, a.epoch, a.evidence_deadline, subject)
}

fn attempt_statement(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    a: &Attempt,
    domain: EvidenceDomain,
) -> Result<RecoveryStatement, RecoveryError> {
    let initiation = initiation_statement(e, account, config, a);
    match domain {
        EvidenceDomain::Initiate => Ok(initiation),
        EvidenceDomain::Cancel => Ok(statement(
            e,
            account,
            config,
            a.epoch,
            a.cancel_until,
            StatementSubject::Cancel(CancelSubject {
                attempt_id: a.id,
                attempt_statement: digest(e, &initiation)?,
            }),
        )),
    }
}

fn change_statement_for(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    subject: StatementSubject,
    valid_until: u32,
) -> Result<RecoveryStatement, RecoveryError> {
    if !matches!(
        subject,
        StatementSubject::Reconfigure(_) | StatementSubject::Upgrade(_)
    ) {
        return Err(RecoveryError::InvalidStatement);
    }
    Ok(statement(
        e,
        account,
        config,
        epoch_of(e, account),
        valid_until,
        subject,
    ))
}

fn digest(e: &Env, statement: &RecoveryStatement) -> Result<BytesN<32>, RecoveryError> {
    statement.digest(e).map_err(statement_error)
}

fn check_fresh(e: &Env, statement: &RecoveryStatement) -> Result<(), RecoveryError> {
    statement
        .check_fresh(e.ledger().sequence())
        .map_err(statement_error)
}

fn statement_error(err: StatementError) -> RecoveryError {
    match err {
        StatementError::EvidenceExpired | StatementError::EvidenceWindowTooLong => {
            RecoveryError::EvidenceExpired
        }
        _ => RecoveryError::InvalidStatement,
    }
}

/// The adapter must accept the proof for the enrolled binding, and its
/// nullifier must be unspent (spec §11). Accepting a proof never changes the
/// nullifier's record.
fn verify_zk(
    e: &Env,
    factor: &CompiledZkFactor,
    statement: &RecoveryStatement,
    evidence: &ZkEvidence,
) -> Result<(), RecoveryError> {
    ZkAdapterClient::new(e, &factor.adapter)
        .try_verify(statement, &factor.binding(), evidence)
        .map_err(|_| RecoveryError::ZkEvidenceRejected)?
        .map_err(|_| RecoveryError::ZkEvidenceRejected)?;
    if RecoveryStorage::has_nullifier(e, &evidence.nullifier) {
        return Err(RecoveryError::NullifierSpent);
    }
    Ok(())
}

/// A configuration this controller can serve (spec §15): the account is not
/// one of its own guardians (its `__check_auth` would run while this
/// controller is on the stack collecting the approval, and could not freeze
/// itself out of approving its own recovery), and the quorum is reachable.
fn check_config(account: &Address, config: &CompiledRecoveryConfig) -> Result<(), RecoveryError> {
    if let Some(set) = config.guardians() {
        if set.guardians.contains(account) || set.quorum == 0 || set.quorum > set.guardians.len() {
            return Err(RecoveryError::InvalidConfiguration);
        }
    }
    Ok(())
}

/// A new ZK factor must be provable at all (spec §3.4): its adapter verifies
/// the named circuit, at the named pool's depth.
fn check_zk_wiring(
    e: &Env,
    old: Option<&CompiledZkFactor>,
    new: Option<&CompiledZkFactor>,
) -> Result<(), RecoveryError> {
    let Some(new) = new else {
        return Ok(());
    };
    if old == Some(new) {
        return Ok(());
    }
    let adapter = ZkAdapterClient::new(e, &new.adapter);
    let circuit_ok = adapter
        .try_circuit_id()
        .is_ok_and(|r| r.is_ok_and(|id| id == new.circuit_id));
    let adapter_depth = adapter.try_tree_depth().ok().and_then(|r| r.ok());
    let pool_depth = MembershipPoolClient::new(e, &new.pool)
        .try_depth()
        .ok()
        .and_then(|r| r.ok());
    if !circuit_ok || adapter_depth.is_none() || adapter_depth != pool_depth {
        return Err(RecoveryError::ZkWiringMismatch);
    }
    Ok(())
}

// --------------------------------------------------------------------------
// State helpers
// --------------------------------------------------------------------------

fn max_ttl(e: &Env) -> u32 {
    e.storage().max_ttl()
}

fn add(a: u32, b: u32) -> Result<u32, RecoveryError> {
    a.checked_add(b).ok_or(RecoveryError::LedgerOverflow)
}

fn require_config(e: &Env, account: &Address) -> Result<CompiledRecoveryConfig, RecoveryError> {
    RecoveryStorage::get_config(e, account).ok_or(RecoveryError::NotEnrolled)
}

fn epoch_of(e: &Env, account: &Address) -> u64 {
    RecoveryStorage::get_epoch(e, account).unwrap_or(0)
}

fn bump_epoch(e: &Env, account: &Address) -> u64 {
    let next = epoch_of(e, account) + 1;
    RecoveryStorage::set_epoch(e, account, &next);
    RecoveryStorage::extend_epoch_ttl(e, account, max_ttl(e), max_ttl(e));
    next
}

/// Store a configuration and bump the epoch, which kills every attempt and
/// every piece of evidence from before (spec §3.3).
fn store_config(e: &Env, account: &Address, config: &CompiledRecoveryConfig) {
    RecoveryStorage::set_config(e, account, config);
    RecoveryStorage::extend_config_ttl(e, account, max_ttl(e), max_ttl(e));
    let epoch = bump_epoch(e, account);
    EpochAdvanced {
        account: account.clone(),
        epoch,
        config_hash: Some(config.config_hash.clone()),
    }
    .publish(e);
}

fn store_approval(
    e: &Env,
    account: &Address,
    digest: &BytesN<32>,
    record: &ChangeApproval,
    valid_until: u32,
) {
    let key = (account.clone(), digest.clone());
    RecoveryStorage::set_approval(e, &key, record);
    let live_for = valid_until
        .saturating_sub(e.ledger().sequence())
        .saturating_add(1)
        .min(max_ttl(e));
    RecoveryStorage::extend_approval_ttl(e, &key, live_for, live_for);
    ChangeEvidenceRecorded {
        account: account.clone(),
        digest: digest.clone(),
    }
    .publish(e);
}

fn load(e: &Env, account: &Address, attempt_id: u64) -> Option<Attempt> {
    let key = (account.clone(), attempt_id);
    RecoveryStorage::get_attempt(e, &key).or_else(|| RecoveryStorage::get_collecting(e, &key))
}

fn load_live(e: &Env, account: &Address, attempt_id: u64) -> Result<Attempt, RecoveryError> {
    let attempt = load(e, account, attempt_id).ok_or(RecoveryError::NoSuchAttempt)?;
    if !is_live(e, account, &attempt) {
        return Err(RecoveryError::AttemptNotLive);
    }
    Ok(attempt)
}

/// Collecting attempts live in temporary storage for their evidence window;
/// an attempt that was ever authorized moves to persistent storage.
fn save(e: &Env, account: &Address, attempt: &Attempt) {
    let key = (account.clone(), attempt.id);
    let ever_authorized = matches!(
        attempt.state,
        AttemptState::Authorized | AttemptState::Completed
    ) || RecoveryStorage::has_attempt(e, &key);
    if ever_authorized {
        RecoveryStorage::remove_collecting(e, &key);
        RecoveryStorage::set_attempt(e, &key, attempt);
        RecoveryStorage::extend_attempt_ttl(e, &key, max_ttl(e), max_ttl(e));
    } else {
        RecoveryStorage::set_collecting(e, &key, attempt);
        let live_for = attempt
            .cancel_until
            .saturating_sub(e.ledger().sequence())
            .saturating_add(1)
            .min(max_ttl(e));
        RecoveryStorage::extend_collecting_ttl(e, &key, live_for, live_for);
    }
}

/// Spec §6.2: an attempt is live while its epoch is current, it is not
/// terminal, it was not invalidated by a sibling's authorization, and its
/// phase's window is open.
fn is_live(e: &Env, account: &Address, a: &Attempt) -> bool {
    if a.epoch != epoch_of(e, account) {
        return false;
    }
    let now = e.ledger().sequence();
    match a.state {
        AttemptState::Collecting => {
            a.id >= RecoveryStorage::get_invalidate_below(e, account).unwrap_or(0)
                && now <= a.evidence_deadline
        }
        AttemptState::Authorized => {
            RecoveryStorage::get_authorized(e, account) == Some(a.id) && now < a.expires_at
        }
        AttemptState::Completed | AttemptState::Cancelled => false,
    }
}

fn authorized_live(e: &Env, account: &Address) -> Option<Attempt> {
    let id = RecoveryStorage::get_authorized(e, account)?;
    let attempt = RecoveryStorage::get_attempt(e, &(account.clone(), id))?;
    is_live(e, account, &attempt).then_some(attempt)
}

/// The recovery rule is a zero-signer rule scoped to the account itself.
fn assert_recovery_rule(e: &Env, rule: &ContextRule, account: &Address) {
    if !rule.signers.is_empty()
        || rule.context_type != ContextRuleType::CallContract(account.clone())
    {
        panic_with_error!(e, RecoveryError::MalformedContextRule);
    }
}
