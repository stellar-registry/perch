//! The recovery controller: an OZ smart-account [`Policy`] plus the
//! initiation/evidence/cancellation/reconfigure entry points. See
//! `docs/recovery/controller-governance.md` for the full design.
//!
//! **Why the security gate is not in `install`/`uninstall`:** OZ's
//! `remove_context_rule` calls a policy's `uninstall` via `try_uninstall` and
//! discards the result even if it panics (`stellar_accounts::smart_account::
//! storage::remove_context_rule` — confirmed by reading the pinned dependency
//! directly), so a policy cannot rely on `uninstall` to block its own
//! removal. The real gate is [`guard_apply_doc`], called by
//! `perch-smart-account`'s `apply_doc` **before** any context rule is
//! touched — see that crate for the call site. `install`/`uninstall` here are
//! therefore plain bookkeeping, not authorization.

use crate::storage::RecoveryStorage;
use crate::types::{Action, Attempt, AttemptState};
use crate::zk::{self, ZkVerifierClient};
use crate::{ReconfigureEvidence, RecoveryError};
use perch_doc_compiler::{
    CompiledGuardianSet, CompiledRecoveryConfig, CompiledRecoveryMode, CompiledZkVerifierConfig,
    RecoveryProfile,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractevent, contractimpl, panic_with_error, Address, Bytes, BytesN, Env, IntoVal,
    Symbol, TryFromVal, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

/// Emitted when an attempt completes and installs its target document.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCompleted {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    pub target_doc_hash: BytesN<32>,
}

/// Emitted when an attempt is cancelled.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCancelled {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
}

/// Emitted when an attempt's evidence is satisfied and it becomes pending.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorized {
    #[topic]
    pub account: Address,
    pub attempt_id: u64,
    pub executable_after: u32,
    pub expires_at: u32,
}

const TTL_THRESHOLD: u32 = 1;

/// The network's current maximum persistent-entry TTL — the longest any
/// extension in this module can buy, recomputed at each call site rather
/// than pinned to a constant so it tracks the live network configuration
/// (see `Env::storage().max_ttl()`'s own doc comment). This is deliberately
/// *not* "forever": a persistent entry with no further activity still
/// expires once this many ledgers pass with no renewal. [`PerchRecovery::renew`]
/// is the explicit, permissionless keep-alive for exactly that gap — see
/// `docs/recovery/controller-governance.md`'s "Keeping permanent state
/// alive" section.
fn max_ttl(e: &Env) -> u32 {
    e.storage().max_ttl()
}

#[contract]
pub struct PerchRecovery;

#[contractimpl]
impl Policy for PerchRecovery {
    type AccountParams = CompiledRecoveryConfig;

    /// Write the enrolled configuration. `install`/`enforce`/`uninstall` are
    /// exported functions on this contract like any other — reachable by a
    /// direct call from anyone, not only via OZ's real install flow — so this
    /// first line is load-bearing, not defensive boilerplate: it makes a
    /// direct, forged call fail before touching storage. It succeeds for free
    /// on the real path (`smart_account`'s own wasm is the direct invoker
    /// when `apply_doc` re-installs its context rules — Soroban's
    /// invoker-contract authorization, `require_auth`'s first-checked path,
    /// grants this without a signature) and fails for any caller that isn't
    /// `smart_account` itself. The reconfiguration gate already ran upstream
    /// (see module docs) — this only shape-checks the rule it's attached to
    /// and stores the value.
    fn install(
        e: &Env,
        install_params: CompiledRecoveryConfig,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        assert_self_zero_signer_rule(e, &context_rule, &smart_account);
        RecoveryStorage::set_config(e, &smart_account, &install_params);
        RecoveryStorage::extend_config_ttl(e, &smart_account, TTL_THRESHOLD, max_ttl(e));
    }

    /// Variant A completion: authorize `apply_doc` exactly when a live,
    /// authorized, unexpired attempt targets exactly the document being
    /// applied. Consumes the attempt atomically as a side effect of
    /// authorization succeeding — `perch-smart-account`'s own
    /// `guard_apply_doc` pre-check relies on `has_pending` already reading
    /// `false` by the time it runs, which only holds because this mutation
    /// happens here, during auth evaluation, before `apply_doc`'s body runs.
    fn enforce(
        e: &Env,
        context: Context,
        _authenticated_signers: Vec<Signer>,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        complete(e, &context, &smart_account);
    }

    /// Deliberately a no-op — see module docs on why this cannot be the
    /// security gate.
    fn uninstall(_e: &Env, _context_rule: ContextRule, _smart_account: Address) {}
}

fn assert_self_zero_signer_rule(e: &Env, rule: &ContextRule, smart_account: &Address) {
    if !rule.signers.is_empty()
        || rule.context_type != ContextRuleType::CallContract(smart_account.clone())
    {
        panic_with_error!(e, RecoveryError::MalformedContextRule);
    }
}

fn complete(e: &Env, context: &Context, smart_account: &Address) {
    // Same reasoning as `install`: `enforce` is a directly-callable exported
    // function, and `context` is an ordinary argument the caller fully
    // controls — nothing about receiving a `Context::Contract` value proves
    // it reflects a real invocation. Without this, anyone who knows (or
    // reconstructs) the pending attempt's target document bytes could call
    // `enforce` directly with a forged `context`, consuming the attempt
    // (revoking credentials, spending its nullifier) without `apply_doc`'s
    // body ever having run. This succeeds for free on the real path — OZ's
    // `do_check_auth`, itself running because `apply_doc` required
    // `smart_account`'s own auth, is the direct invoker of this cross-call —
    // and fails for a direct, unrelated caller.
    smart_account.require_auth();
    let Context::Contract(ContractContext {
        contract,
        fn_name,
        args,
    }) = context
    else {
        panic_with_error!(e, RecoveryError::WrongTarget);
    };
    if contract != smart_account || *fn_name != Symbol::new(e, "apply_doc") {
        panic_with_error!(e, RecoveryError::WrongTarget);
    }
    let Some(doc_json_val) = args.first() else {
        panic_with_error!(e, RecoveryError::WrongTarget);
    };
    let Ok(doc_json) = Bytes::try_from_val(e, &doc_json_val) else {
        panic_with_error!(e, RecoveryError::WrongTarget);
    };
    let doc_hash: BytesN<32> = e.crypto().sha256(&doc_json).to_bytes();

    let mut attempt = RecoveryStorage::get_attempt(e, smart_account)
        .unwrap_or_else(|| panic_with_error!(e, RecoveryError::NoLiveAttempt));
    if attempt.state != AttemptState::AuthorizedPending {
        panic_with_error!(e, RecoveryError::AttemptNotAuthorized);
    }
    let now = e.ledger().sequence();
    if now < attempt.executable_after {
        panic_with_error!(e, RecoveryError::AttemptNotExecutableYet);
    }
    if now >= attempt.expires_at {
        panic_with_error!(e, RecoveryError::AttemptExpired);
    }
    if doc_hash != attempt.target_doc_hash {
        panic_with_error!(e, RecoveryError::WrongTarget);
    }

    // Atomic: mark completed, revoke every replaced credential permanently,
    // spend the nullifier (if any). If installing the document itself later
    // fails, this whole invocation — including this mutation — reverts with
    // it (Soroban transaction atomicity), so there is no path where the
    // attempt is consumed without the document actually installing.
    attempt.state = AttemptState::Completed;
    let mut revoked = RecoveryStorage::get_revoked(e, smart_account).unwrap_or_else(|| Vec::new(e));
    for c in attempt.replaced_credentials.iter() {
        if !revoked.contains(&c) {
            revoked.push_back(c);
        }
    }
    RecoveryStorage::set_revoked(e, smart_account, &revoked);
    RecoveryStorage::extend_revoked_ttl(e, smart_account, TTL_THRESHOLD, max_ttl(e));
    if let Some(n) = attempt.nullifier.first() {
        RecoveryStorage::set_nullifier(e, &n, &true);
        RecoveryStorage::extend_nullifier_ttl(e, &n, TTL_THRESHOLD, max_ttl(e));
    }
    RecoveryCompleted {
        account: smart_account.clone(),
        attempt_id: attempt.id,
        target_doc_hash: attempt.target_doc_hash.clone(),
    }
    .publish(e);
    RecoveryStorage::set_attempt(e, smart_account, &attempt);
}

#[contractimpl]
impl PerchRecovery {
    /// Called by `perch-smart-account`'s `apply_doc`, before any context rule
    /// is touched, whenever a recovery controller is currently enrolled for
    /// `account`. See module docs for why this — not `install`/`uninstall` —
    /// is the actual security gate.
    ///
    /// Blocks unconditionally while a live attempt exists — this holds
    /// regardless of the account's chosen pending-activity policy (see
    /// `docs/recovery/pending-activity-policy.md`, a separate, still-open
    /// question about *ordinary* activity during a pending attempt). This
    /// also reads `false` for a legitimate completion call, because
    /// `enforce` already consumed the attempt during auth evaluation, before
    /// this runs.
    ///
    /// Otherwise: no change is always fine; a first enrollment (`old` is
    /// `None`) is always fine; a change while `old.profile == Loss` is
    /// always fine (ordinary admin authorization, already established by
    /// `apply_doc`'s own `require_auth`, is enough); a change while
    /// `old.profile == Protected` — including removing recovery — requires
    /// `evidence` to satisfy the *currently* enrolled condition over a
    /// digest binding this exact transition. This generalizes a companion
    /// smart-account implementation's validated strictly-additive-only
    /// reconfigure (which remains reachable as the common case) to a fully
    /// general rule — see `docs/recovery/controller-governance.md`.
    pub fn guard_apply_doc(
        e: &Env,
        account: Address,
        new_recovery: Vec<CompiledRecoveryConfig>,
        evidence: ReconfigureEvidence,
    ) -> Result<(), RecoveryError> {
        // Also directly callable like `install`/`enforce` above — without
        // this, anyone who obtains valid reconfigure evidence (e.g. by
        // observing the real `apply_doc` transaction before it lands) could
        // call this entry point standalone, burning a one-time ZK nullifier
        // or a guardian's signature with no document ever changing —
        // front-running and denial-of-service against the real
        // reconfiguration. Succeeds for free on the real path:
        // `perch-smart-account`'s `apply_doc` is the direct invoker of this
        // cross-call, before it touches any context rule.
        account.require_auth();
        if let Some(attempt) = RecoveryStorage::get_attempt(e, &account) {
            if is_live(e, &attempt) {
                return Err(RecoveryError::AttemptPending);
            }
        }

        let old = RecoveryStorage::get_config(e, &account);
        // Renew here too (not only via `require_config`, which this function
        // deliberately doesn't use since it must distinguish "no config" from
        // "config present") — every `apply_doc` call reaches this point, so
        // this is the read path that actually needs to keep an enrolled
        // `Protected` config from expiring into a false "first enrollment"
        // (which would let a reconfiguration skip the evidence requirement).
        if old.is_some() {
            RecoveryStorage::extend_config_ttl(e, &account, TTL_THRESHOLD, max_ttl(e));
        }
        let new = new_recovery.first();

        if config_matches(&old, new.as_ref()) {
            return Ok(());
        }
        let Some(old_cfg) = old else {
            return Ok(()); // first enrollment
        };
        if old_cfg.profile == RecoveryProfile::Loss {
            return Ok(());
        }

        // Protected: require the current condition's evidence over a digest
        // binding (old config, proposed new config-or-removal).
        let old_hash = config_hash_of(e, &old_cfg);
        let new_hash = new.as_ref().map(|c| config_hash_of(e, c));
        let digest = zk::statement(
            e,
            &account,
            &e.current_contract_address(),
            &Action::Reconfigure,
            &old_hash,
            new_hash.as_ref(),
            0,
            0,
        );

        let guardians = guardian_set(&old_cfg.mode);
        let zk_cfg = zk_config(&old_cfg.mode);

        if let Some(g) = guardians {
            require_guardian_quorum(e, g, &evidence.guardians, &digest)?;
        }
        if let Some(z) = zk_cfg {
            require_zk_evidence(e, z, &evidence, &digest)?;
        }
        if guardians.is_none() && zk_cfg.is_none() {
            // Unreachable given RecoveryMode's own shape (every variant has a
            // guardian factor, a ZK factor, or both) — defense in depth.
            return Err(RecoveryError::ReconfigureEvidenceRequired);
        }
        Ok(())
    }

    /// Declare intent to restore access after key loss: target is the
    /// current approved document with `replaced_credentials` replaced.
    /// Permissionless — declaring intent carries no authority; the mode's
    /// evidence is what authorizes anything. Refuses a live existing
    /// attempt; replaces (releasing its nullifier) a terminal or expired one.
    pub fn begin_lost_key_attempt(
        e: &Env,
        account: Address,
        target_doc_hash: BytesN<32>,
        replaced_credentials: Vec<BytesN<32>>,
    ) -> Result<u64, RecoveryError> {
        begin_attempt(
            e,
            account,
            Action::LostKey,
            target_doc_hash,
            replaced_credentials,
        )
    }

    /// Declare intent to restore the enrolled baseline after suspected
    /// compromise, with `replaced_credentials` replaced. Requires a baseline
    /// to be enrolled, and `target_doc_hash` to equal it exactly — a
    /// compromise attempt targets *the* approved baseline, never a
    /// caller-chosen document (that's what `begin_lost_key_attempt` is for).
    /// See `begin_lost_key_attempt` for the shared mechanics.
    pub fn begin_compromise_attempt(
        e: &Env,
        account: Address,
        target_doc_hash: BytesN<32>,
        replaced_credentials: Vec<BytesN<32>>,
    ) -> Result<u64, RecoveryError> {
        let config = require_config(e, &account)?;
        let Some(baseline) = config.baseline.first() else {
            return Err(RecoveryError::NoBaselineEnrolled);
        };
        if baseline != target_doc_hash {
            return Err(RecoveryError::TargetNotBaseline);
        }
        begin_attempt(
            e,
            account,
            Action::Compromise,
            target_doc_hash,
            replaced_credentials,
        )
    }

    /// A guardian approves this account's pending attempt's initiation. The
    /// guardian's signature is bound to a digest bound to *this exact*
    /// attempt (id, action, target, enrolled config) — not just to the fixed
    /// `(account, guardian)` argument pair — so a delayed or replayed
    /// signature can never be redirected to authorize a different attempt
    /// than the guardian actually approved.
    pub fn submit_guardian_approval(
        e: &Env,
        account: Address,
        guardian: Address,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let g = guardian_set(&config.mode).ok_or(RecoveryError::ModeHasNoGuardians)?;
        if !g.guardians.contains(&guardian) {
            return Err(RecoveryError::NotAGuardian);
        }
        let mut attempt = require_attempt(e, &account)?;
        if attempt.state != AttemptState::CollectingEvidence {
            return Err(RecoveryError::AttemptNotAuthorized);
        }
        if !is_live(e, &attempt) {
            return Err(RecoveryError::NoLiveAttempt);
        }
        if attempt.guardian_approvals.contains(&guardian) {
            return Err(RecoveryError::AlreadyApproved);
        }
        let cfg_hash = config_hash_of(e, &config);
        let digest = zk::statement(
            e,
            &account,
            &e.current_contract_address(),
            &attempt.action,
            &cfg_hash,
            Some(&attempt.target_doc_hash),
            attempt.id,
            config.delay_ledgers,
        );
        guardian.require_auth_for_args(Vec::from_array(e, [digest.into_val(e)]));
        attempt.guardian_approvals.push_back(guardian);
        maybe_promote(e, &account, &config, &mut attempt)?;
        RecoveryStorage::set_attempt(e, &account, &attempt);
        RecoveryStorage::extend_attempt_ttl(e, &account, TTL_THRESHOLD, max_ttl(e));
        Ok(())
    }

    /// Submit a ZK initiation proof. Permissionless — the proof is the
    /// authorization. `nullifier` is the prover-revealed nullifier; the
    /// controller recomputes the statement itself from the attempt's own
    /// frozen commitment, never trusting a caller-supplied statement.
    pub fn submit_zk_proof(
        e: &Env,
        account: Address,
        nullifier: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let z = zk_config(&config.mode).ok_or(RecoveryError::ModeHasNoZk)?;
        let mut attempt = require_attempt(e, &account)?;
        if attempt.state != AttemptState::CollectingEvidence {
            return Err(RecoveryError::AttemptNotAuthorized);
        }
        if attempt.zk_verified {
            return Ok(()); // idempotent re-submission
        }
        if !is_live(e, &attempt) {
            return Err(RecoveryError::NoLiveAttempt);
        }
        if RecoveryStorage::get_nullifier(e, &nullifier).unwrap_or(false) {
            return Err(RecoveryError::NullifierAlreadySpent);
        }
        let cfg_hash = config_hash_of(e, &config);
        let stmt = zk::statement(
            e,
            &account,
            &e.current_contract_address(),
            &attempt.action,
            &cfg_hash,
            Some(&attempt.target_doc_hash),
            attempt.id,
            config.delay_ledgers,
        );
        if !ZkVerifierClient::new(e, &z.verifier).verify_proof(&stmt, &nullifier, &proof, &z.pool) {
            return Err(RecoveryError::ZkProofInvalid);
        }
        // Reserved immediately, not deferred to `complete` — otherwise the
        // same nullifier could pass this check again for a second, separate
        // account-bound statement before either attempt completes (`complete`
        // never re-checks the global set, only writes it).
        RecoveryStorage::set_nullifier(e, &nullifier, &true);
        RecoveryStorage::extend_nullifier_ttl(e, &nullifier, TTL_THRESHOLD, max_ttl(e));
        attempt.zk_verified = true;
        let mut nul = Vec::new(e);
        nul.push_back(nullifier);
        attempt.nullifier = nul;
        maybe_promote(e, &account, &config, &mut attempt)?;
        RecoveryStorage::set_attempt(e, &account, &attempt);
        RecoveryStorage::extend_attempt_ttl(e, &account, TTL_THRESHOLD, max_ttl(e));
        Ok(())
    }

    /// A guardian approves cancellation of this account's identified attempt.
    /// Own action domain — initiation approvals never count here.
    /// Only actually cancels once the mode's full cancellation evidence set
    /// is present: for `Combined`, reaching guardian quorum here is not
    /// enough by itself — a verified ZK cancellation proof is also required
    /// (see `cancellation_satisfied`).
    pub fn submit_guardian_cancel(
        e: &Env,
        account: Address,
        guardian: Address,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let g = guardian_set(&config.mode).ok_or(RecoveryError::ModeHasNoGuardians)?;
        if !g.guardians.contains(&guardian) {
            return Err(RecoveryError::NotAGuardian);
        }
        let mut attempt = require_attempt(e, &account)?;
        if !is_live(e, &attempt) {
            return Err(RecoveryError::NoLiveAttempt);
        }
        // Bound to this exact attempt and the cancellation domain — the same
        // digest shape `submit_zk_cancel` verifies a proof against below —
        // not just the fixed `(account, guardian)` arguments, so a delayed
        // signature can't be redirected to cancel a different, later attempt
        // than the one the guardian actually signed for.
        let cfg_hash = config_hash_of(e, &config);
        let digest = zk::statement(
            e,
            &account,
            &e.current_contract_address(),
            &Action::Cancel,
            &cfg_hash,
            None,
            attempt.id,
            config.delay_ledgers,
        );
        guardian.require_auth_for_args(Vec::from_array(e, [digest.into_val(e)]));
        let key = (account.clone(), attempt.id);
        let mut tally = RecoveryStorage::get_cancel_tally(e, &key).unwrap_or_else(|| Vec::new(e));
        if tally.contains(&guardian) {
            return Err(RecoveryError::AlreadyApproved);
        }
        tally.push_back(guardian);
        RecoveryStorage::set_cancel_tally(e, &key, &tally);
        RecoveryStorage::extend_cancel_tally_ttl(e, &key, TTL_THRESHOLD, max_ttl(e));
        let guardian_quorum_reached = tally.len() >= g.quorum;
        if guardian_quorum_reached {
            let zk_cancel_verified =
                RecoveryStorage::get_zk_cancel_verified(e, &key).unwrap_or(false);
            if cancellation_satisfied(&config.mode, true, zk_cancel_verified) {
                cancel_attempt(e, &account, &mut attempt)?;
            }
        }
        Ok(())
    }

    /// Submit a ZK cancellation proof for this account's identified attempt.
    /// Own action domain (`Action::Cancel`) — an initiation proof never
    /// satisfies this, and vice versa. Only actually cancels once the mode's
    /// full cancellation evidence set is present: for `Combined`, a valid
    /// proof here is not enough by itself — a guardian quorum on this same
    /// attempt is also required (see `cancellation_satisfied`).
    pub fn submit_zk_cancel(
        e: &Env,
        account: Address,
        nullifier: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), RecoveryError> {
        let config = require_config(e, &account)?;
        let z = zk_config(&config.mode).ok_or(RecoveryError::ModeHasNoZk)?;
        let mut attempt = require_attempt(e, &account)?;
        if !is_live(e, &attempt) {
            return Err(RecoveryError::NoLiveAttempt);
        }
        if RecoveryStorage::get_nullifier(e, &nullifier).unwrap_or(false) {
            return Err(RecoveryError::NullifierAlreadySpent);
        }
        let cfg_hash = config_hash_of(e, &config);
        let stmt = zk::statement(
            e,
            &account,
            &e.current_contract_address(),
            &Action::Cancel,
            &cfg_hash,
            None,
            attempt.id,
            config.delay_ledgers,
        );
        if !ZkVerifierClient::new(e, &z.verifier).verify_proof(&stmt, &nullifier, &proof, &z.pool) {
            return Err(RecoveryError::ZkProofInvalid);
        }
        RecoveryStorage::set_nullifier(e, &nullifier, &true);
        RecoveryStorage::extend_nullifier_ttl(e, &nullifier, TTL_THRESHOLD, max_ttl(e));
        let key = (account.clone(), attempt.id);
        RecoveryStorage::set_zk_cancel_verified(e, &key, &true);
        RecoveryStorage::extend_zk_cancel_verified_ttl(e, &key, TTL_THRESHOLD, max_ttl(e));
        let guardian_quorum_reached = match guardian_set(&config.mode) {
            Some(g) => {
                RecoveryStorage::get_cancel_tally(e, &key)
                    .unwrap_or_else(|| Vec::new(e))
                    .len()
                    >= g.quorum
            }
            None => false,
        };
        if cancellation_satisfied(&config.mode, guardian_quorum_reached, true) {
            cancel_attempt(e, &account, &mut attempt)?;
        }
        Ok(())
    }

    /// The enrolled configuration, if any.
    pub fn get_config(e: &Env, account: Address) -> Option<CompiledRecoveryConfig> {
        RecoveryStorage::get_config(e, &account)
    }

    /// `sha256(to_xdr(config))` of the enrolled configuration, if any — the
    /// scoped commitment a proof's statement binds, distinct from the whole
    /// document's own `doc_hash` (which already covers this configuration
    /// too — see `docs/recovery/schema.md`).
    pub fn config_hash(e: &Env, account: Address) -> Option<BytesN<32>> {
        RecoveryStorage::get_config(e, &account).map(|c| config_hash_of(e, &c))
    }

    /// The account's current attempt, if any (live or terminal — callers
    /// checking liveness should also consult [`Self::has_pending`]).
    pub fn get_attempt(e: &Env, account: Address) -> Option<Attempt> {
        RecoveryStorage::get_attempt(e, &account)
    }

    /// Whether a live (not completed/cancelled, not expired) attempt exists.
    pub fn has_pending(e: &Env, account: Address) -> bool {
        RecoveryStorage::get_attempt(e, &account).is_some_and(|a| is_live(e, &a))
    }

    /// Extend every one of `account`'s existing recovery entries — enrolled
    /// config, current/most recent attempt (and its nullifier, if spent),
    /// permanent revoked set, and the lifetime counters — to the network's
    /// current maximum TTL. Permissionless and idempotent: it only ever
    /// extends state that's already there, never changes what it means, so
    /// anyone (a keeper script, a wallet's own background job) can call this
    /// periodically for an account with no other recovery activity. Soroban
    /// persistent entries have a finite maximum TTL — nothing renews them on
    /// its own absent an explicit touch like this one, or the account
    /// otherwise using recovery (`require_config`'s own read-path renewal
    /// covers the busier entries already). See
    /// `docs/recovery/controller-governance.md`'s "Keeping permanent state
    /// alive" section.
    pub fn renew(e: &Env, account: Address) {
        let ttl = max_ttl(e);
        if RecoveryStorage::has_config(e, &account) {
            RecoveryStorage::extend_config_ttl(e, &account, TTL_THRESHOLD, ttl);
        }
        if let Some(attempt) = RecoveryStorage::get_attempt(e, &account) {
            RecoveryStorage::extend_attempt_ttl(e, &account, TTL_THRESHOLD, ttl);
            if let Some(n) = attempt.nullifier.first() {
                RecoveryStorage::extend_nullifier_ttl(e, &n, TTL_THRESHOLD, ttl);
            }
        }
        if RecoveryStorage::has_revoked(e, &account) {
            RecoveryStorage::extend_revoked_ttl(e, &account, TTL_THRESHOLD, ttl);
        }
        if RecoveryStorage::has_cancels_used(e, &account) {
            RecoveryStorage::extend_cancels_used_ttl(e, &account, TTL_THRESHOLD, ttl);
        }
        if RecoveryStorage::has_next_attempt_id(e, &account) {
            RecoveryStorage::extend_next_attempt_id_ttl(e, &account, TTL_THRESHOLD, ttl);
        }
    }
}

fn require_config(e: &Env, account: &Address) -> Result<CompiledRecoveryConfig, RecoveryError> {
    let config = RecoveryStorage::get_config(e, account).ok_or(RecoveryError::NotEnrolled)?;
    // Renews on every real use (every begin/approve/proof/cancel call), not
    // just on install — an enrolled config that nobody ever touches for
    // longer than the network's max TTL would otherwise silently expire,
    // and `guard_apply_doc` treats a missing config as "first enrollment"
    // (no evidence required), which would let a `Protected` account's
    // reconfiguration gate quietly fail open. See [`PerchRecovery::renew`]
    // for the explicit keep-alive covering accounts with no such activity.
    RecoveryStorage::extend_config_ttl(e, account, TTL_THRESHOLD, max_ttl(e));
    Ok(config)
}

fn require_attempt(e: &Env, account: &Address) -> Result<Attempt, RecoveryError> {
    RecoveryStorage::get_attempt(e, account).ok_or(RecoveryError::NoLiveAttempt)
}

/// Live = not terminal, and not past its current phase's deadline. A
/// `CollectingEvidence` attempt is live until `evidence_deadline` — without
/// this bound, a single permissionless `begin_*_attempt` call would block
/// every ordinary `apply_doc` (via `guard_apply_doc`'s unconditional
/// live-attempt check) indefinitely, since nothing else forces the mode's
/// evidence to ever actually arrive.
fn is_live(e: &Env, attempt: &Attempt) -> bool {
    match attempt.state {
        AttemptState::CollectingEvidence => e.ledger().sequence() < attempt.evidence_deadline,
        AttemptState::AuthorizedPending => e.ledger().sequence() < attempt.expires_at,
        AttemptState::Completed | AttemptState::Cancelled => false,
    }
}

fn guardian_set(mode: &CompiledRecoveryMode) -> Option<&CompiledGuardianSet> {
    match mode {
        CompiledRecoveryMode::GuardianOnly(g) | CompiledRecoveryMode::Combined(g, _) => Some(g),
        CompiledRecoveryMode::ZkOnly(_) => None,
    }
}

fn zk_config(mode: &CompiledRecoveryMode) -> Option<&CompiledZkVerifierConfig> {
    match mode {
        CompiledRecoveryMode::ZkOnly(z) | CompiledRecoveryMode::Combined(_, z) => Some(z),
        CompiledRecoveryMode::GuardianOnly(_) => None,
    }
}

fn config_hash_of(e: &Env, cfg: &CompiledRecoveryConfig) -> BytesN<32> {
    e.crypto().sha256(&cfg.clone().to_xdr(e)).to_bytes()
}

fn config_matches(
    old: &Option<CompiledRecoveryConfig>,
    new: Option<&CompiledRecoveryConfig>,
) -> bool {
    match (old, new) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn initiation_satisfied(mode: &CompiledRecoveryMode, attempt: &Attempt) -> bool {
    match mode {
        CompiledRecoveryMode::GuardianOnly(g) => attempt.guardian_approvals.len() >= g.quorum,
        CompiledRecoveryMode::ZkOnly(_) => attempt.zk_verified,
        CompiledRecoveryMode::Combined(g, _) => {
            attempt.guardian_approvals.len() >= g.quorum && attempt.zk_verified
        }
    }
}

/// Mirrors `initiation_satisfied` for the cancellation domain:
/// `GuardianOnly`/`ZkOnly` need only their own factor, `Combined` needs both
/// a guardian quorum AND a valid ZK cancellation proof for the same attempt —
/// neither factor alone may cancel a `Combined`-mode attempt.
fn cancellation_satisfied(
    mode: &CompiledRecoveryMode,
    guardian_quorum_reached: bool,
    zk_cancel_verified: bool,
) -> bool {
    match mode {
        CompiledRecoveryMode::GuardianOnly(_) => guardian_quorum_reached,
        CompiledRecoveryMode::ZkOnly(_) => zk_cancel_verified,
        CompiledRecoveryMode::Combined(_, _) => guardian_quorum_reached && zk_cancel_verified,
    }
}

fn maybe_promote(
    e: &Env,
    account: &Address,
    config: &CompiledRecoveryConfig,
    attempt: &mut Attempt,
) -> Result<(), RecoveryError> {
    if attempt.state == AttemptState::CollectingEvidence
        && initiation_satisfied(&config.mode, attempt)
    {
        let now = e.ledger().sequence();
        attempt.state = AttemptState::AuthorizedPending;
        attempt.executable_after = now
            .checked_add(config.delay_ledgers)
            .ok_or(RecoveryError::TimelockOverflow)?;
        attempt.expires_at = attempt
            .executable_after
            .checked_add(config.expiry_ledgers)
            .ok_or(RecoveryError::TimelockOverflow)?;
        RecoveryAuthorized {
            account: account.clone(),
            attempt_id: attempt.id,
            executable_after: attempt.executable_after,
            expires_at: attempt.expires_at,
        }
        .publish(e);
    }
    Ok(())
}

fn begin_attempt(
    e: &Env,
    account: Address,
    action: Action,
    target_doc_hash: BytesN<32>,
    replaced_credentials: Vec<BytesN<32>>,
) -> Result<u64, RecoveryError> {
    let config = require_config(e, &account)?;
    for c in replaced_credentials.iter() {
        if !config.replaceable.contains(&c) {
            return Err(RecoveryError::CredentialNotReplaceable);
        }
    }
    if let Some(existing) = RecoveryStorage::get_attempt(e, &account) {
        if is_live(e, &existing) {
            return Err(RecoveryError::AttemptPending);
        }
        // Stale (terminal or expired), and not a completed attempt: release
        // its nullifier before replacing it, so the same secret can be used
        // again. A `Completed` attempt's nullifier stays spent permanently
        // (see `Attempt::nullifier`'s documented invariant) — completion
        // itself already extends the nullifier's own TTL as the durable
        // record of that.
        if existing.state != AttemptState::Completed {
            if let Some(n) = existing.nullifier.first() {
                RecoveryStorage::set_nullifier(e, &n, &false);
            }
        }
    }
    let id = RecoveryStorage::get_next_attempt_id(e, &account).unwrap_or(0);
    RecoveryStorage::set_next_attempt_id(e, &account, &(id + 1));
    // The nonce must never be reused (a replayed id would let old per-attempt
    // evidence/statements collide with a new attempt) — extend on every
    // write, not just at install, so this counter can't silently reset to 0
    // via TTL expiry during long account inactivity.
    RecoveryStorage::extend_next_attempt_id_ttl(e, &account, TTL_THRESHOLD, max_ttl(e));

    let created_at = e.ledger().sequence();
    let attempt = Attempt {
        id,
        action,
        target_doc_hash,
        replaced_credentials,
        created_at,
        // Bounds how long a permissionless `begin_*_attempt` call can hold
        // `guard_apply_doc`'s unconditional live-attempt block open while no
        // evidence arrives — see `is_live`. Reuses `expiry_ledgers` (already
        // the account's own configured "how long this recovery gets" budget)
        // rather than adding a new schema field for the same kind of window.
        evidence_deadline: created_at
            .checked_add(config.expiry_ledgers)
            .ok_or(RecoveryError::TimelockOverflow)?,
        executable_after: 0,
        expires_at: 0,
        guardian_approvals: Vec::new(e),
        zk_verified: false,
        nullifier: Vec::new(e),
        state: AttemptState::CollectingEvidence,
    };
    RecoveryStorage::set_attempt(e, &account, &attempt);
    RecoveryStorage::extend_attempt_ttl(e, &account, TTL_THRESHOLD, max_ttl(e));
    Ok(id)
}

fn cancel_attempt(e: &Env, account: &Address, attempt: &mut Attempt) -> Result<(), RecoveryError> {
    let used = RecoveryStorage::get_cancels_used(e, account).unwrap_or(0);
    let config = require_config(e, account)?;
    if used >= config.max_cancels {
        return Err(RecoveryError::MaxCancelsReached);
    }
    RecoveryStorage::set_cancels_used(e, account, &(used + 1));
    // A lifetime griefing-cancellation cap only bounds anything if it can't
    // silently reset to 0 via TTL expiry — extend on every write.
    RecoveryStorage::extend_cancels_used_ttl(e, account, TTL_THRESHOLD, max_ttl(e));
    attempt.state = AttemptState::Cancelled;
    if let Some(n) = attempt.nullifier.first() {
        RecoveryStorage::set_nullifier(e, &n, &false);
    }
    RecoveryStorage::set_attempt(e, account, attempt);
    RecoveryCancelled {
        account: account.clone(),
        attempt_id: attempt.id,
    }
    .publish(e);
    Ok(())
}

fn require_guardian_quorum(
    e: &Env,
    g: &CompiledGuardianSet,
    submitted: &Vec<Address>,
    digest: &BytesN<32>,
) -> Result<(), RecoveryError> {
    let mut counted = Vec::new(e);
    for addr in submitted.iter() {
        if !g.guardians.contains(&addr) || counted.contains(&addr) {
            continue;
        }
        // The host aborts the whole transaction if `addr` did not actually
        // authorize this exact digest — a claimed-but-unsigned address never
        // silently passes.
        addr.require_auth_for_args(Vec::from_array(e, [digest.into_val(e)]));
        counted.push_back(addr);
    }
    if counted.len() < g.quorum {
        return Err(RecoveryError::ReconfigureEvidenceRequired);
    }
    Ok(())
}

fn require_zk_evidence(
    e: &Env,
    z: &CompiledZkVerifierConfig,
    evidence: &ReconfigureEvidence,
    digest: &BytesN<32>,
) -> Result<(), RecoveryError> {
    let (Some(nullifier), Some(proof)) = (evidence.zk_nullifier.first(), evidence.zk_proof.first())
    else {
        return Err(RecoveryError::ReconfigureEvidenceRequired);
    };
    if RecoveryStorage::get_nullifier(e, &nullifier).unwrap_or(false) {
        return Err(RecoveryError::NullifierAlreadySpent);
    }
    if !ZkVerifierClient::new(e, &z.verifier).verify_proof(digest, &nullifier, &proof, &z.pool) {
        return Err(RecoveryError::ZkProofInvalid);
    }
    RecoveryStorage::set_nullifier(e, &nullifier, &true);
    RecoveryStorage::extend_nullifier_ttl(e, &nullifier, TTL_THRESHOLD, max_ttl(e));
    Ok(())
}
