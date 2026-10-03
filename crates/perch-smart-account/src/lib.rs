//! The perch smart-account trait: **authorization data changes exactly one
//! way — [`PerchSmartAccount::apply_doc`]**.
//!
//! [`PerchSmartAccount`] extends OZ's `CustomAccountInterface` + `SmartAccount`
//! (the evaluation machinery) and exports a document-shaped surface instead of
//! OZ's piecemeal mutation API. A deployable implements `SmartAccount`
//! *without* exporting it — so `add_context_rule`, `add_signer`, `add_policy`,
//! … never exist as entry points — and exports this trait: doc-only is
//! structural, not conventional. [`impl_perch_smart_account!`] expands to all
//! of that, so a deployable is a struct, a constructor, and one macro call.
//! (Rust cannot default supertrait items from a subtrait — the macro is how
//! the supertrait boilerplate lives here instead of in every contract.)
//!
//! State and computation are split: parsing + compiling live in the
//! **stateless** shared `perch-doc-compiler` contract; this trait holds the
//! **stateful** half — the account's rule set and applied `doc_hash`.
//! `apply_doc` sends the document's JSON bytes to the compiler, refuses any
//! result that could lock the admin out, atomically replaces the whole rule
//! set, and stores the canonical `doc_hash` so anyone can check
//! installed == reviewed via [`PerchSmartAccount::applied_doc_hash`].
#![no_std]

use perch_doc_compiler::{
    admin_survives, CompiledDoc, CompiledRule, CompiledZkFactor, DocCompilerClient,
    DocCompilerError, RuleScope,
};
use perch_recovery_interface::account::{
    is_frozen, is_reserved_invoker_only, ACCOUNT_UPGRADE_DELAY_LEDGERS,
};
use perch_recovery_interface::config::{leaf_to_insert, zk_factor_transition_ok};
use perch_recovery_interface::controller::{
    RecoveryError, RecoveryHooksClient, SyncOutcome, UpgradeStep,
};
use perch_recovery_interface::zk::MembershipPoolClient;
use perch_recovery_interface::UpgradeSubject;
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contractevent, contracttrait, contracttype,
    crypto::Hash,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem, PersistentItem, PersistentMap};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;
use stellar_accounts::smart_account::{
    self, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountStorageKey,
};

// Re-exported so `impl_perch_smart_account!` can name them via `$crate::…`
// regardless of the caller's dependency graph.
pub use soroban_sdk;
pub use stellar_accounts;

/// The stateless subregistry (`unverified/perch/stateless`) — the content-addressed
/// deployer the infra derive their address from. Its id is **not hardcoded in
/// source**: `scripts/fetch-infra-wasm.sh` writes it into the git-ignored
/// `wasm/stateless.id`, which is `include_str!`'d here. A missing file is a build
/// error — fetch it first.
pub fn stateless_registry(env: &Env) -> Address {
    Address::from_str(env, include_str!("../wasm/stateless.id").trim())
}

/// Content-addressed resolvers for the shared infra, named like
/// `import_contract_client!`. Each `infra::<name>::address(env)` derives
/// `deployer(stateless_id, sha256(wasm))` fully offline, with **both** the
/// stateless registry id (from `wasm/stateless.id`) and the wasm hash (from
/// `wasm/<name>.wasm`) baked at build time from the fetched, git-ignored cache
/// (`scripts/fetch-infra-wasm.sh`; a missing file is a build error). Pinned ⇒ a
/// registry republish can't change a deployed account's behavior (`installed ==
/// reviewed`), and only the names live in source. Grouped in a module so the
/// derived names don't collide with the `perch_doc_compiler` crate.
pub mod infra {
    perch_registry_resolve::registry_contract!(perch_doc_compiler);
    perch_registry_resolve::registry_contract!(perch_interpreter);

    // Published to `unverified/perch/stateless` and `deploy_stateless`\'d like
    // the two above; its wasm is downloaded by NAME from the stateless registry
    // (`stellar registry download` — it has no name-salted perch-registry
    // instance for `contract fetch` to pull from).
    perch_registry_resolve::registry_contract!(perch_spending_limit);
}

/// Everything the account's entry points can refuse. Compiler and controller
/// failures flatten in via `#[from_contract_client]`, converted by `??`.
#[scerr]
pub enum PerchAccountError {
    /// The compiled document contains no policy-free self-admin rule with at
    /// least one signer. Applying it could lock the admin out; refused
    /// (anti-brick).
    AdminLockout,
    /// The document names a credential in the account's revoked set
    /// (`docs/recovery/spec.md` §8).
    RevokedCredential,
    /// The document names a ZK enrollment id this account enrolled before
    /// (spec §3.4).
    EnrollmentReused,
    /// The document changes the ZK factor without a new enrollment id
    /// (spec §3.4: the factor stays unchanged or carries a new id).
    ZkFactorChangedInPlace,
    /// `execute` was asked to call an invoker-only hook (spec §15).
    ReservedFunction,
    /// The account has no adopted recovery controller.
    RecoveryNotEnrolled,
    /// No upgrade is scheduled.
    NoPendingUpgrade,
    /// The request id is not the pending upgrade's.
    UpgradeRequestMismatch,
    /// The upgrade delay has not elapsed.
    UpgradeNotReady,
    /// A ledger computation overflowed `u32`.
    TimingOverflow,
    #[from_contract_client]
    Compiler(DocCompilerError),
    #[from_contract_client]
    Recovery(RecoveryError),
}

// scerr's composed (root) mode predates sdk 27's spec-shaking marker; the
// no-op impl is the trait's documented default, and root mode emits its own
// flattened error spec. (Upstream candidate for soroban-sdk-tools.)
impl soroban_sdk::SpecShakingMarker for PerchAccountError {}

/// Why `__check_auth` refused before evaluating any rule.
#[scerr]
pub enum PerchAuthError {
    /// A context names an invoker-only hook (spec §15): these are reachable
    /// only from the account's own flows, never by signature.
    ReservedFunction,
    /// A `Protected` recovery attempt is authorized: the account authorizes
    /// nothing but that attempt's completion (spec §9).
    AccountFrozen,
}

/// The `Protected` freeze, mirrored from the adopted controller through
/// [`PerchSmartAccount::rcv_gate`]: while `ledger < until`, the account
/// authorizes nothing but `attempt_id`'s completion.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeGate {
    pub attempt_id: u64,
    /// The authorized attempt's `expires_at`.
    pub until: u32,
}

/// The shared infra an account resolves, pinned when it was built (see
/// [`infra`]): what a deployment check compares with its manifest.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfraPins {
    pub doc_compiler: Address,
    pub interpreter: Address,
    pub spending_limit: Address,
}

/// A scheduled account upgrade (spec §12).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRequest {
    pub request_id: u64,
    pub wasm_hash: BytesN<32>,
    /// The adopted controller's epoch at scheduling (`0` without one). Any
    /// change makes the request stale.
    pub epoch: u64,
    /// The controller adopted at scheduling, if any.
    pub controller: Option<Address>,
    /// First ledger `execute_upgrade` may run.
    pub executable_at: u32,
}

/// Emitted after a document is applied: the new canonical `doc_hash`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocApplied {
    #[topic]
    pub doc_hash: BytesN<32>,
}

/// Emitted when a recovery completion revokes a credential.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub fingerprint: BytesN<32>,
}

/// Emitted when the adopted controller sets (`until > 0`) or clears the
/// `Protected` freeze.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeChanged {
    pub attempt_id: u64,
    pub until: u32,
}

/// Emitted when an upgrade is scheduled.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeScheduled {
    #[topic]
    pub request_id: u64,
    pub wasm_hash: BytesN<32>,
    pub executable_at: u32,
}

/// Emitted when a scheduled upgrade is dropped: cancelled, replaced by a
/// newer request, found stale at execution, or cleared by a recovery.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeDropped {
    #[topic]
    pub request_id: u64,
}

/// Emitted when an upgrade executes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeExecuted {
    #[topic]
    pub request_id: u64,
    pub wasm_hash: BytesN<32>,
}

#[contractstorage]
#[allow(dead_code)] // the field names only derive storage keys + accessors
struct PerchStorage {
    /// Canonical `doc_hash` of the currently applied policy document.
    applied_doc: InstanceItem<BytesN<32>>,
    /// The applied document's canonical bytes.
    applied_doc_bytes: PersistentItem<Bytes>,
    /// Fingerprints of the applied document's credentials (what a recovery
    /// completion revokes when its target drops them).
    applied_fingerprints: PersistentItem<Vec<BytesN<32>>>,
    /// The adopted recovery controller (the applied document's
    /// `recovery.controller`), if any.
    recovery_controller: InstanceItem<Address>,
    /// The context-rule id of the zero-signer recovery rule, if any.
    recovery_rule: InstanceItem<u32>,
    /// The `Protected` freeze, if an attempt is authorized.
    gate: InstanceItem<FreezeGate>,
    /// The applied document's ZK factor, if its mode has one.
    current_zk: InstanceItem<CompiledZkFactor>,
    /// Permanent, append-only revoked credential fingerprints (spec §8).
    revoked: PersistentMap<BytesN<32>, bool>,
    /// Permanent, append-only set of ZK enrollment ids this account has
    /// enrolled (spec §3.4).
    enrolled_ids: PersistentMap<BytesN<32>, bool>,
    /// The scheduled upgrade, if any.
    pending_upgrade: InstanceItem<UpgradeRequest>,
    /// The next upgrade request id. Never reused.
    next_upgrade_id: InstanceItem<u64>,
}

/// The doc-only smart account surface. Implementers get OZ evaluation from
/// the supertraits and exactly one write path for authorization data from
/// here, plus the controlled capabilities a wallet needs: execution through
/// the account, full document reads, recovery cancellation, and delayed
/// upgrades.
#[contracttrait]
pub trait PerchSmartAccount: CustomAccountInterface + SmartAccount {
    /// Apply a policy document — **the only way authorization changes**.
    /// The two shared, immutable infra contracts (the stateless doc compiler
    /// and the interpreter) are derived from the build-time-pinned
    /// [`stateless_registry`] (see [`infra`]), never passed in. Replaces the
    /// entire rule set atomically and returns the canonical `doc_hash`.
    ///
    /// Authorized by the owner (any ordinary rule scoped to the account),
    /// or, for a recovery completion only, by the zero-signer recovery rule
    /// whose controller checks the exact target. On an account with an
    /// adopted controller, the controller's `rcv_sync` classifies the call
    /// before any rule changes and refuses what the profile does not allow
    /// (`docs/recovery/spec.md` §10). `approval_valid_until` is the
    /// freshness bound a `Protected` reconfiguration's recorded approvals
    /// were given for; it is ignored otherwise.
    fn apply_doc(
        e: &Env,
        doc_json: Bytes,
        approval_valid_until: u32,
    ) -> Result<BytesN<32>, PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();

        let compiled: CompiledDoc =
            DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
                .try_compile_doc(&doc_json)??;
        if !admin_survives(&compiled.rules) {
            return Err(PerchAccountError::AdminLockout);
        }
        for fingerprint in compiled.fingerprints.iter() {
            if PerchStorage::has_revoked(e, &fingerprint) {
                return Err(PerchAccountError::RevokedCredential);
            }
        }

        let new_recovery = compiled.recovery.first();
        let new_zk = new_recovery.as_ref().and_then(|r| r.zk().cloned());
        let current_zk = PerchStorage::get_current_zk(e);
        if !zk_factor_transition_ok(current_zk.as_ref(), new_zk.as_ref()) {
            return Err(PerchAccountError::ZkFactorChangedInPlace);
        }
        let insert = leaf_to_insert(current_zk.as_ref(), new_zk.as_ref()).cloned();
        if let Some(leaf) = &insert {
            if PerchStorage::has_enrolled_ids(e, &leaf.enrollment_id) {
                return Err(PerchAccountError::EnrollmentReused);
            }
        }

        // The recovery gate runs before any context rule is touched: OZ's
        // `remove_context_rule` swallows a policy's `uninstall` failure, so
        // only this call can refuse a change.
        let old_controller = PerchStorage::get_recovery_controller(e);
        let mut outcome = SyncOutcome::Unchanged;
        if let Some(controller) = &old_controller {
            outcome = RecoveryHooksClient::new(e, controller).try_rcv_sync(
                &me,
                &compiled.doc_hash,
                &compiled.recovery,
                &approval_valid_until,
            )??;
        }
        if let Some(next) = &new_recovery {
            if old_controller.as_ref() != Some(&next.controller) {
                RecoveryHooksClient::new(e, &next.controller).try_rcv_sync(
                    &me,
                    &compiled.doc_hash,
                    &compiled.recovery,
                    &approval_valid_until,
                )??;
            }
        }

        replace_rules(e, &compiled);

        if let Some(leaf) = &insert {
            MembershipPoolClient::new(e, &leaf.pool).rcv_insert(
                &me,
                &leaf.enrollment_id,
                &leaf.commitment,
            );
            PerchStorage::set_enrolled_ids(e, &leaf.enrollment_id, &true);
            extend_persistent(e, |ttl| {
                PerchStorage::extend_enrolled_ids_ttl(e, &leaf.enrollment_id, ttl, ttl)
            });
        }
        match &new_zk {
            Some(next) => PerchStorage::set_current_zk(e, next),
            None => PerchStorage::remove_current_zk(e),
        }

        if let SyncOutcome::Completed(_) = outcome {
            complete_recovery(e, &compiled.fingerprints);
        }

        PerchStorage::set_applied_doc(e, &compiled.doc_hash);
        PerchStorage::set_applied_doc_bytes(e, &compiled.canonical);
        PerchStorage::set_applied_fingerprints(e, &compiled.fingerprints);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_applied_doc_bytes_ttl(e, ttl, ttl);
            PerchStorage::extend_applied_fingerprints_ttl(e, ttl, ttl);
        });
        DocApplied {
            doc_hash: compiled.doc_hash.clone(),
        }
        .publish(e);
        Ok(compiled.doc_hash)
    }

    /// Call `target_fn` on `target` as this account (the account becomes
    /// the invoker, so `target`'s `require_auth` of this account passes).
    /// Requires the account's authorization of this exact call. Refuses the
    /// invoker-only hook names: otherwise whoever can authorize `execute`
    /// could reach a controller, policy, or pool hook as the account
    /// (spec §15).
    fn execute(
        e: &Env,
        target: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
    ) -> Result<Val, PerchAccountError> {
        e.current_contract_address().require_auth();
        if is_reserved_invoker_only(e, &target_fn) {
            return Err(PerchAccountError::ReservedFunction);
        }
        Ok(e.invoke_contract::<Val>(&target, &target_fn, target_args))
    }

    /// The applied document's canonical bytes, or `None` before the first
    /// `apply_doc`. `sha256` of them is [`Self::applied_doc_hash`].
    fn applied_doc(e: &Env) -> Option<Bytes> {
        PerchStorage::get_applied_doc_bytes(e)
    }

    /// The canonical `doc_hash` of the currently applied policy document, or
    /// `None` if only the constructor's admin rule exists. Anyone can check
    /// installed == reviewed.
    fn applied_doc_hash(e: &Env) -> Option<BytesN<32>> {
        PerchStorage::get_applied_doc(e)
    }

    /// The doc compiler this account pins at build time.
    fn doc_compiler(e: &Env) -> Address {
        infra::perch_doc_compiler::address(e)
    }

    /// Every shared contract this account pins at build time.
    fn infra(e: &Env) -> InfraPins {
        InfraPins {
            doc_compiler: infra::perch_doc_compiler::address(e),
            interpreter: infra::perch_interpreter::address(e),
            spending_limit: infra::perch_spending_limit::address(e),
        }
    }

    /// Whether a credential fingerprint is permanently revoked.
    fn is_revoked(e: &Env, fingerprint: BytesN<32>) -> bool {
        PerchStorage::has_revoked(e, &fingerprint)
    }

    /// Whether this account ever enrolled a ZK enrollment id.
    fn is_enrolled_id(e: &Env, enrollment_id: BytesN<32>) -> bool {
        PerchStorage::has_enrolled_ids(e, &enrollment_id)
    }

    /// The adopted recovery controller, if any.
    fn recovery_controller(e: &Env) -> Option<Address> {
        PerchStorage::get_recovery_controller(e)
    }

    /// The `Protected` freeze, if one was set and has not been cleared. It
    /// is in force while the current ledger is below `until`.
    fn recovery_gate(e: &Env) -> Option<FreezeGate> {
        PerchStorage::get_gate(e)
    }

    /// Invoker-only: the adopted controller sets (`frozen_until > 0`) or
    /// clears (`0`) the `Protected` freeze for `attempt_id`. The account
    /// mirrors the freeze rather than asking the controller from
    /// `__check_auth`, because an account approving as a guardian through
    /// the same controller instance runs `__check_auth` while that
    /// controller is on the call stack, and the host refuses re-entry.
    fn rcv_gate(e: &Env, attempt_id: u64, frozen_until: u32) -> Result<(), PerchAccountError> {
        let controller = PerchStorage::get_recovery_controller(e)
            .ok_or(PerchAccountError::RecoveryNotEnrolled)?;
        controller.require_auth();
        if frozen_until == 0 {
            if PerchStorage::get_gate(e).is_some_and(|g| g.attempt_id == attempt_id) {
                PerchStorage::remove_gate(e);
            }
        } else {
            PerchStorage::set_gate(
                e,
                &FreezeGate {
                    attempt_id,
                    until: frozen_until,
                },
            );
        }
        FreezeChanged {
            attempt_id,
            until: frozen_until,
        }
        .publish(e);
        Ok(())
    }

    /// A `Loss` owner's cancellation of a recovery attempt (spec T7). The
    /// controller refuses it under `Protected`.
    fn cancel_recovery(e: &Env, attempt_id: u64) -> Result<(), PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();
        let controller = PerchStorage::get_recovery_controller(e)
            .ok_or(PerchAccountError::RecoveryNotEnrolled)?;
        RecoveryHooksClient::new(e, &controller).try_rcv_cancel(&me, &attempt_id)??;
        Ok(())
    }

    /// Schedule an upgrade to `wasm_hash`, executable after
    /// [`ACCOUNT_UPGRADE_DELAY_LEDGERS`] (spec §12). Owner authorization;
    /// under `Protected` also the condition's recorded approval of
    /// `Upgrade { request_id, wasm_hash }` fresh until
    /// `approval_valid_until` (`next_upgrade_request_id` names the id to
    /// approve). Refused while a recovery attempt is authorized. Replaces any
    /// earlier request. Returns the request id.
    fn schedule_upgrade(
        e: &Env,
        wasm_hash: BytesN<32>,
        approval_valid_until: u32,
    ) -> Result<u64, PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();
        let request_id = PerchStorage::get_next_upgrade_id(e).unwrap_or(0);
        PerchStorage::set_next_upgrade_id(e, &(request_id + 1));
        let controller = PerchStorage::get_recovery_controller(e);
        let epoch = match &controller {
            Some(c) => RecoveryHooksClient::new(e, c).try_rcv_upgrade(
                &me,
                &UpgradeStep::Schedule(
                    UpgradeSubject {
                        request_id,
                        wasm_hash: wasm_hash.clone(),
                    },
                    approval_valid_until,
                ),
            )??,
            None => 0,
        };
        let executable_at = e
            .ledger()
            .sequence()
            .checked_add(ACCOUNT_UPGRADE_DELAY_LEDGERS)
            .ok_or(PerchAccountError::TimingOverflow)?;
        drop_pending_upgrade(e);
        PerchStorage::set_pending_upgrade(
            e,
            &UpgradeRequest {
                request_id,
                wasm_hash: wasm_hash.clone(),
                epoch,
                controller,
                executable_at,
            },
        );
        UpgradeScheduled {
            request_id,
            wasm_hash,
            executable_at,
        }
        .publish(e);
        Ok(request_id)
    }

    /// Execute the pending upgrade once its delay has elapsed. Owner
    /// authorization. If the adopted controller or its epoch changed since
    /// scheduling (a reconfiguration, removal, completed recovery, or other
    /// upgrade), the request is stale: it is cleared and `false` returned.
    /// Otherwise the controller bumps the epoch (refusing during an
    /// authorized attempt), the Wasm is replaced after this invocation, and
    /// `true` is returned.
    fn execute_upgrade(e: &Env, request_id: u64) -> Result<bool, PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();
        let request =
            PerchStorage::get_pending_upgrade(e).ok_or(PerchAccountError::NoPendingUpgrade)?;
        if request.request_id != request_id {
            return Err(PerchAccountError::UpgradeRequestMismatch);
        }
        if e.ledger().sequence() < request.executable_at {
            return Err(PerchAccountError::UpgradeNotReady);
        }
        let controller = PerchStorage::get_recovery_controller(e);
        drop_pending_upgrade(e);
        if controller != request.controller {
            return Ok(false);
        }
        if let Some(c) = &controller {
            match RecoveryHooksClient::new(e, c)
                .try_rcv_upgrade(&me, &UpgradeStep::Execute(request.epoch))
            {
                Ok(Ok(_)) => {}
                Err(Ok(RecoveryError::StaleUpgrade)) => return Ok(false),
                other => {
                    other??;
                }
            }
        }
        UpgradeExecuted {
            request_id,
            wasm_hash: request.wasm_hash.clone(),
        }
        .publish(e);
        e.deployer().update_current_contract_wasm(request.wasm_hash);
        Ok(true)
    }

    /// Cancel the pending upgrade. Owner authorization.
    fn cancel_upgrade(e: &Env) -> Result<(), PerchAccountError> {
        e.current_contract_address().require_auth();
        if !PerchStorage::has_pending_upgrade(e) {
            return Err(PerchAccountError::NoPendingUpgrade);
        }
        drop_pending_upgrade(e);
        Ok(())
    }

    /// The scheduled upgrade, if any.
    fn pending_upgrade(e: &Env) -> Option<UpgradeRequest> {
        PerchStorage::get_pending_upgrade(e)
    }

    /// The id the next `schedule_upgrade` will assign: what `Protected`
    /// approvers approve.
    fn next_upgrade_request_id(e: &Env) -> u64 {
        PerchStorage::get_next_upgrade_id(e).unwrap_or(0)
    }

    /// Extend the account's instance, applied document, and the named
    /// revoked-set and enrolled-id entries to the network maximum.
    /// Permissionless; changes no meaning.
    fn renew(e: &Env, fingerprints: Vec<BytesN<32>>, enrollment_ids: Vec<BytesN<32>>) {
        extend_persistent(e, |ttl| {
            e.storage().instance().extend_ttl(ttl, ttl);
            if PerchStorage::has_applied_doc_bytes(e) {
                PerchStorage::extend_applied_doc_bytes_ttl(e, ttl, ttl);
            }
            if PerchStorage::has_applied_fingerprints(e) {
                PerchStorage::extend_applied_fingerprints_ttl(e, ttl, ttl);
            }
            for f in fingerprints.iter() {
                if PerchStorage::has_revoked(e, &f) {
                    PerchStorage::extend_revoked_ttl(e, &f, ttl, ttl);
                }
            }
            for id in enrollment_ids.iter() {
                if PerchStorage::has_enrolled_ids(e, &id) {
                    PerchStorage::extend_enrolled_ids_ttl(e, &id, ttl, ttl);
                }
            }
        });
    }

    /// Read-only rule surface, re-exposed here because `SmartAccount` itself
    /// is deliberately not exported by doc-only accounts.
    fn get_context_rules_count(e: &Env) -> u32 {
        smart_account::get_context_rules_count(e)
    }

    /// See [`Self::get_context_rules_count`].
    fn get_context_rule(e: &Env, context_rule_id: u32) -> ContextRule {
        smart_account::get_context_rule(e, context_rule_id)
    }
}

/// The account's `__check_auth`: the reserved-name guard and the
/// `Protected` freeze run before OZ evaluates any rule (spec §9, §15).
///
/// - Any context naming an invoker-only hook is refused, on any contract,
///   so no signature can satisfy a hook's `account.require_auth()`.
/// - While the freeze is in force the only authorizable thing is one
///   `apply_doc` context on this account that selects the recovery rule,
///   which the controller's `enforce` then checks. This covers every path
///   that reaches `__check_auth`: direct authorization, `execute` and every
///   other entry point (each requires the account's own authorization), and
///   CAP-0071 delegation, where the host hands this account the delegating
///   account's contexts.
pub fn check_auth(
    e: &Env,
    signature_payload: &Hash<32>,
    signatures: &AuthPayload,
    auth_contexts: &Vec<Context>,
) -> Result<(), soroban_sdk::Error> {
    for context in auth_contexts.iter() {
        if let Context::Contract(ContractContext { fn_name, .. }) = &context {
            if is_reserved_invoker_only(e, fn_name) {
                return Err(PerchAuthError::ReservedFunction.into());
            }
        }
    }
    if let Some(gate) = PerchStorage::get_gate(e) {
        if is_frozen(e.ledger().sequence(), gate.until)
            && !is_completion(e, signatures, auth_contexts)
        {
            return Err(PerchAuthError::AccountFrozen.into());
        }
    }
    smart_account::do_check_auth(e, signature_payload, signatures, auth_contexts)
        .map_err(Into::into)
}

/// One `apply_doc` context on this account, selecting the recovery rule.
fn is_completion(e: &Env, signatures: &AuthPayload, contexts: &Vec<Context>) -> bool {
    let Some(rule) = PerchStorage::get_recovery_rule(e) else {
        return false;
    };
    if contexts.len() != 1 || signatures.context_rule_ids != Vec::from_array(e, [rule]) {
        return false;
    }
    matches!(
        contexts.get_unchecked(0),
        Context::Contract(ContractContext { contract, fn_name, .. })
            if contract == e.current_contract_address() && fn_name == Symbol::new(e, "apply_doc")
    )
}

/// A completed recovery revokes every credential the applied document had
/// and the target drops (spec §8), lifts the freeze, and drops any pending
/// upgrade (spec §12).
fn complete_recovery(e: &Env, target_fingerprints: &Vec<BytesN<32>>) {
    let before = PerchStorage::get_applied_fingerprints(e).unwrap_or(Vec::new(e));
    for fingerprint in before.iter() {
        if !target_fingerprints.contains(&fingerprint) {
            PerchStorage::set_revoked(e, &fingerprint, &true);
            extend_persistent(e, |ttl| {
                PerchStorage::extend_revoked_ttl(e, &fingerprint, ttl, ttl)
            });
            CredentialRevoked { fingerprint }.publish(e);
        }
    }
    PerchStorage::remove_gate(e);
    drop_pending_upgrade(e);
}

fn drop_pending_upgrade(e: &Env) {
    if let Some(request) = PerchStorage::get_pending_upgrade(e) {
        PerchStorage::remove_pending_upgrade(e);
        UpgradeDropped {
            request_id: request.request_id,
        }
        .publish(e);
    }
}

fn extend_persistent(e: &Env, f: impl FnOnce(u32)) {
    f(e.storage().max_ttl());
}

/// Replace the entire rule set in one invocation: there is no observable
/// half-migrated state. The recovery rule is not one of `doc.rules`: it is a
/// zero-signer self-scoped rule whose only policy is the adopted controller,
/// installed for the compiled configuration's hash.
fn replace_rules(e: &Env, compiled: &CompiledDoc) {
    let interpreter = infra::perch_interpreter::address(e);
    let next_id: u32 = e
        .storage()
        .instance()
        .get(&SmartAccountStorageKey::NextId)
        .unwrap_or(0);
    for id in 0..next_id {
        if e.storage()
            .persistent()
            .has(&SmartAccountStorageKey::ContextRuleData(id))
        {
            smart_account::remove_context_rule(e, id);
        }
    }
    for rule in compiled.rules.iter() {
        install_rule(e, &interpreter, &rule);
    }
    match compiled.recovery.first() {
        Some(recovery) => {
            let mut policies: Map<Address, Val> = Map::new(e);
            policies.set(
                recovery.controller.clone(),
                recovery.config_hash.into_val(e),
            );
            let rule = smart_account::add_context_rule(
                e,
                &ContextRuleType::CallContract(e.current_contract_address()),
                &String::from_str(e, "recovery"),
                None,
                &Vec::new(e),
                &policies,
            );
            PerchStorage::set_recovery_rule(e, &rule.id);
            PerchStorage::set_recovery_controller(e, &recovery.controller);
        }
        None => {
            PerchStorage::remove_recovery_rule(e);
            PerchStorage::remove_recovery_controller(e);
        }
    }
}

/// Constructor helper: install rule 0, "admin", scoped
/// `CallContract(self)` — the admin signers may manage this account (i.e.
/// call `apply_doc`) and nothing else. Every other capability arrives via an
/// applied, doc-reviewed rule set.
pub fn install_admin(e: &Env, admin_signers: &Vec<Signer>) {
    smart_account::add_context_rule(
        e,
        &ContextRuleType::CallContract(e.current_contract_address()),
        &String::from_str(e, "admin"),
        None,
        admin_signers,
        &Map::new(e),
    );
}

/// Map one compiled rule onto OZ storage, via the same library call
/// `__check_auth` evaluates against.
fn install_rule(e: &Env, interpreter: &Address, rule: &CompiledRule) {
    let scope = match &rule.scope {
        RuleScope::SelfAdmin => ContextRuleType::CallContract(e.current_contract_address()),
        RuleScope::Contract(addr) => ContextRuleType::CallContract(addr.clone()),
    };
    let mut policies: Map<Address, Val> = Map::new(e);
    if let Some(install) = rule.install.first() {
        policies.set(interpreter.clone(), install.into_val(e));
    }
    // A capped rule also attaches OZ `spending_limit` (the stateful cumulative
    // cap the interpreter cannot express), keyed by its content-addressed
    // address — resolved offline like the interpreter, never admin-supplied. OZ
    // enforces every attached policy (AND): the interpreter's per-call program
    // AND the rolling cap must pass. The metered token is this rule's
    // `CallContract` scope (validation pins `token == scope`).
    if let Some(cap) = rule.cap.first() {
        let spending_limit = infra::perch_spending_limit::address(e);
        let params = SpendingLimitAccountParams {
            spending_limit: cap.spending_limit,
            period_ledgers: cap.period_ledgers,
        };
        policies.set(spending_limit, params.into_val(e));
    }
    smart_account::add_context_rule(
        e,
        &scope,
        &rule.name,
        rule.valid_until,
        &rule.signers,
        &policies,
    );
}

use soroban_sdk::IntoVal;

/// Expand the full deployable surface for `$ty`: the `CustomAccountInterface`
/// impl (`__check_auth` → [`check_auth`] → OZ `do_check_auth`), a **non-exported**
/// `SmartAccount` impl (the mutation entry points don't exist on-chain), and
/// the exported [`PerchSmartAccount`] trait. Rust cannot put supertrait
/// items' defaults on a subtrait, so this macro is where that boilerplate
/// lives — a deployable is a struct, a constructor, and this call.
#[macro_export]
macro_rules! impl_perch_smart_account {
    ($ty:ident) => {
        // Same-name imports: soroban's macros derive symbol names from the
        // trait path as written, so the impl headers must use bare
        // identifiers. (These land in the invoking module's namespace —
        // don't import the same names yourself.)
        use $crate::soroban_sdk::auth::CustomAccountInterface;
        use $crate::stellar_accounts::smart_account::SmartAccount;
        use $crate::PerchSmartAccount;

        #[$crate::soroban_sdk::contractimpl]
        impl CustomAccountInterface for $ty {
            type Error = $crate::soroban_sdk::Error;
            type Signature = $crate::stellar_accounts::smart_account::AuthPayload;

            fn __check_auth(
                e: $crate::soroban_sdk::Env,
                signature_payload: $crate::soroban_sdk::crypto::Hash<32>,
                signatures: $crate::stellar_accounts::smart_account::AuthPayload,
                auth_contexts: $crate::soroban_sdk::Vec<$crate::soroban_sdk::auth::Context>,
            ) -> Result<(), Self::Error> {
                $crate::check_auth(&e, &signature_payload, &signatures, &auth_contexts)
            }
        }

        /// Satisfies the supertrait WITHOUT exporting entry points: OZ's
        /// mutation surface does not exist on this contract.
        impl SmartAccount for $ty {}

        #[$crate::soroban_sdk::contractimpl(contracttrait)]
        impl PerchSmartAccount for $ty {}
    };
}
