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
//! result that could lock the admin out, brings the installed rules to the
//! compiled document in one invocation (changing only the rules that differ,
//! `rules`), and stores the canonical `doc_hash` so anyone can check
//! installed == reviewed via [`PerchSmartAccount::applied_doc_hash`].
#![no_std]

use perch_doc_compiler::{
    admin_survives, CompiledDoc, CompiledZkFactor, DocCompilerClient, DocCompilerError,
};
use perch_recovery_interface::account::{is_frozen, is_reserved_invoker_only, UpgradeReadiness};
use perch_recovery_interface::config::{leaf_to_insert, zk_factor_transition_ok};
use perch_recovery_interface::controller::{
    RecoveryError, RecoveryHooksClient, SyncOutcome, UpgradeStep,
};
use perch_recovery_interface::credential::{revocations, Credential};
use perch_recovery_interface::zk::MembershipPoolClient;
use perch_recovery_interface::UpgradeSubject;
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contractevent, contracttrait, contracttype,
    crypto::Hash,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem, PersistentItem, PersistentMap};
use stellar_accounts::smart_account::{
    self, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount,
};

mod rules;
pub use rules::{InstalledPolicy, InstalledRule};

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
    /// A completion handed back a credential that cannot be fingerprinted.
    InvalidCredential,
    /// The recovery generation moved since the upgrade was scheduled
    /// (spec §12). The request stays pending but can never execute.
    StaleUpgrade,
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

/// A scheduled account upgrade (spec §12), bound to the account's recovery
/// generation.
pub use perch_recovery_interface::account::UpgradeRequest;

/// Emitted after a document is applied: the new canonical `doc_hash`, and
/// what changed in the rule set. The rule, signer, and policy mutations
/// emit nothing themselves (OZ's `_no_events` variants), so this is the
/// whole record of the change; `applied_doc` serves the document.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocApplied {
    #[topic]
    pub doc_hash: BytesN<32>,
    pub rules_added: u32,
    pub rules_removed: u32,
    pub rules_edited: u32,
    pub signers_added: u32,
    pub signers_removed: u32,
    pub policies_added: u32,
    pub policies_removed: u32,
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
    /// The recovery generation (spec §12): advanced by every recovery
    /// transition at any controller and by every executed upgrade. Never
    /// reset; it continues through periods without recovery.
    recovery_generation: InstanceItem<u64>,
    /// Every context rule currently installed, as installed. `apply_doc`
    /// reconciles the compiled document against these records alone, so its
    /// cost (and a completion's) is bounded by the document caps rather than
    /// by how many rules the account ever had, and an unchanged rule is not
    /// touched at all (`rules`).
    installed_rules: PersistentItem<Vec<InstalledRule>>,
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
        apply(e, doc_json, approval_valid_until, rules::Mode::Cheapest)
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
        let controller_epoch = match &PerchStorage::get_recovery_controller(e) {
            Some(c) => Some(RecoveryHooksClient::new(e, c).try_rcv_upgrade(
                &me,
                &UpgradeStep::Schedule(
                    UpgradeSubject {
                        request_id,
                        wasm_hash: wasm_hash.clone(),
                    },
                    approval_valid_until,
                ),
            )??),
            None => None,
        };
        let request = UpgradeRequest::schedule(
            request_id,
            wasm_hash.clone(),
            generation(e),
            controller_epoch,
            e.ledger().sequence(),
        )
        .ok_or(PerchAccountError::TimingOverflow)?;
        drop_pending_upgrade(e);
        PerchStorage::set_pending_upgrade(e, &request);
        UpgradeScheduled {
            request_id,
            wasm_hash,
            executable_at: request.executable_at,
        }
        .publish(e);
        Ok(request_id)
    }

    /// Execute the pending upgrade once its delay has elapsed. Owner
    /// authorization. If the recovery generation moved since scheduling
    /// (any enrollment, reconfiguration, removal, controller switch,
    /// completed recovery, or executed upgrade), the request is stale and
    /// the call refuses with `StaleUpgrade`. The refusal leaves the request
    /// in place, since a failed invocation keeps none of its writes; it can
    /// never execute, because the generation never decreases, and stays
    /// until `schedule_upgrade` replaces it, `cancel_upgrade` removes it, or
    /// a completion clears it. Otherwise the controller, if one is adopted,
    /// checks its epoch and bumps it (refusing during an authorized
    /// attempt), the generation advances, and the Wasm is replaced after
    /// this invocation.
    fn execute_upgrade(e: &Env, request_id: u64) -> Result<(), PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();
        let request =
            PerchStorage::get_pending_upgrade(e).ok_or(PerchAccountError::NoPendingUpgrade)?;
        if request.request_id != request_id {
            return Err(PerchAccountError::UpgradeRequestMismatch);
        }
        match request.readiness(e.ledger().sequence(), generation(e)) {
            UpgradeReadiness::Stale => return Err(PerchAccountError::StaleUpgrade),
            UpgradeReadiness::NotYet => return Err(PerchAccountError::UpgradeNotReady),
            UpgradeReadiness::Ready => {}
        }
        drop_pending_upgrade(e);
        if let Some(c) = &PerchStorage::get_recovery_controller(e) {
            // The generation matched, so the controller was adopted at
            // scheduling too and its epoch was recorded; the controller
            // checks that epoch as well.
            let epoch = request
                .controller_epoch
                .ok_or(PerchAccountError::StaleUpgrade)?;
            RecoveryHooksClient::new(e, c).try_rcv_upgrade(&me, &UpgradeStep::Execute(epoch))??;
        }
        advance_generation(e);
        UpgradeExecuted {
            request_id,
            wasm_hash: request.wasm_hash.clone(),
        }
        .publish(e);
        e.deployer().update_current_contract_wasm(request.wasm_hash);
        Ok(())
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

    /// The account's recovery generation (spec §12).
    fn recovery_generation(e: &Env) -> u64 {
        generation(e)
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

    /// Every context rule the account has installed, with its OZ id. The
    /// document's rules are matched against these by `apply_doc`.
    fn installed_rules(e: &Env) -> Vec<InstalledRule> {
        PerchStorage::get_installed_rules(e).unwrap_or(Vec::new(e))
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

/// A completed recovery revokes the union of the credentials it replaced in
/// its source (the baseline's, for compromise) and every credential the
/// applied document had that the target drops (spec §8,
/// `credential::revocations`). It lifts the freeze and drops any pending
/// upgrade (spec §12).
fn complete_recovery(
    e: &Env,
    replaced: &Vec<Credential>,
    target_fingerprints: &Vec<BytesN<32>>,
) -> Result<(), PerchAccountError> {
    let mut replaced_fingerprints = Vec::new(e);
    for credential in replaced.iter() {
        replaced_fingerprints.push_back(
            credential
                .fingerprint(e)
                .map_err(|_| PerchAccountError::InvalidCredential)?,
        );
    }
    let before = PerchStorage::get_applied_fingerprints(e).unwrap_or(Vec::new(e));
    for fingerprint in revocations(e, &replaced_fingerprints, &before, target_fingerprints).iter() {
        PerchStorage::set_revoked(e, &fingerprint, &true);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_revoked_ttl(e, &fingerprint, ttl, ttl)
        });
        CredentialRevoked { fingerprint }.publish(e);
    }
    PerchStorage::remove_gate(e);
    drop_pending_upgrade(e);
    Ok(())
}

fn generation(e: &Env) -> u64 {
    PerchStorage::get_recovery_generation(e).unwrap_or(0)
}

fn advance_generation(e: &Env) {
    PerchStorage::set_recovery_generation(e, &(generation(e) + 1));
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

/// `apply_doc`'s body. `mode` is [`rules::Mode::Cheapest`] except in tests
/// ([`testutils`]), which force one reconciliation path or the full replace.
fn apply(
    e: &Env,
    doc_json: Bytes,
    approval_valid_until: u32,
    mode: rules::Mode,
) -> Result<BytesN<32>, PerchAccountError> {
    let me = e.current_contract_address();
    me.require_auth();

    let compiled: CompiledDoc = DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
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
    // Every outcome other than `Unchanged`, on either side of a
    // controller switch, advances the recovery generation (spec §12).
    let old_controller = PerchStorage::get_recovery_controller(e);
    let mut outcome = SyncOutcome::Unchanged;
    if let Some(controller) = &old_controller {
        outcome = RecoveryHooksClient::new(e, controller).try_rcv_sync(
            &me,
            &compiled.doc_hash,
            &compiled.recovery,
            &approval_valid_until,
        )??;
        if outcome.bumps_generation() {
            advance_generation(e);
        }
    }
    if let Some(next) = &new_recovery {
        if old_controller.as_ref() != Some(&next.controller) {
            let enrolled = RecoveryHooksClient::new(e, &next.controller).try_rcv_sync(
                &me,
                &compiled.doc_hash,
                &compiled.recovery,
                &approval_valid_until,
            )??;
            if enrolled.bumps_generation() {
                advance_generation(e);
            }
        }
    }

    let delta = apply_rules(e, &compiled, mode);

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
    if PerchStorage::get_current_zk(e) != new_zk {
        match &new_zk {
            Some(next) => PerchStorage::set_current_zk(e, next),
            None => PerchStorage::remove_current_zk(e),
        }
    }

    if let SyncOutcome::Completed(completion) = outcome {
        complete_recovery(e, &completion.replaced, &compiled.fingerprints)?;
    }

    if PerchStorage::get_applied_doc(e).as_ref() != Some(&compiled.doc_hash) {
        PerchStorage::set_applied_doc(e, &compiled.doc_hash);
        PerchStorage::set_applied_doc_bytes(e, &compiled.canonical);
        PerchStorage::set_applied_fingerprints(e, &compiled.fingerprints);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_applied_doc_bytes_ttl(e, ttl, ttl);
            PerchStorage::extend_applied_fingerprints_ttl(e, ttl, ttl);
        });
    }
    DocApplied {
        doc_hash: compiled.doc_hash.clone(),
        rules_added: delta.rules_added,
        rules_removed: delta.rules_removed,
        rules_edited: delta.rules_edited,
        signers_added: delta.signers_added,
        signers_removed: delta.signers_removed,
        policies_added: delta.policies_added,
        policies_removed: delta.policies_removed,
    }
    .publish(e);
    Ok(compiled.doc_hash)
}

/// Test-only reference implementations, compiled only with the `testutils`
/// feature (never into a deployable).
#[cfg(feature = "testutils")]
pub mod testutils {
    use super::*;
    pub use crate::rules::{Cost, Mode, PlannedRule, Step};

    /// `apply_doc` with every rule removed and re-added, as before the delta
    /// apply: the oracle the delta is checked against. Everything else
    /// (compile, revocation, recovery sync, completion effects) is shared
    /// with `apply_doc`.
    pub fn apply_doc_full_replace(
        e: &Env,
        doc_json: Bytes,
        approval_valid_until: u32,
    ) -> Result<BytesN<32>, PerchAccountError> {
        apply(e, doc_json, approval_valid_until, Mode::FullReplace)
    }

    /// `apply_doc` with every changed rule reconciled by `mode` rather than
    /// by the cheaper path: prices each path on its own.
    pub fn apply_doc_with(
        e: &Env,
        doc_json: Bytes,
        approval_valid_until: u32,
        mode: Mode,
    ) -> Result<BytesN<32>, PerchAccountError> {
        apply(e, doc_json, approval_valid_until, mode)
    }

    /// What applying `doc_json` would do to each rule slot, and what the cost
    /// model prices it at, without applying it. Run as the account
    /// (`env.as_contract`).
    pub fn plan_doc(e: &Env, doc_json: Bytes, mode: Mode) -> Vec<PlannedRule> {
        let compiled: CompiledDoc =
            DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
                .compile_doc(&doc_json);
        let current = PerchStorage::get_installed_rules(e).unwrap_or(Vec::new(e));
        let (desired, params) = rules::desired(e, &compiled);
        rules::plan(e, &current, &desired, &params, mode)
    }
}

/// Bring the installed rules to the compiled document's in one invocation,
/// touching only rules that differ (`rules::reconcile`); there is no
/// observable half-migrated state. The recovery rule is not one of
/// `doc.rules`: it is a zero-signer self-scoped rule whose only policy is the
/// adopted controller, installed for the compiled configuration's hash.
fn apply_rules(e: &Env, compiled: &CompiledDoc, mode: rules::Mode) -> rules::DeltaSummary {
    let current = PerchStorage::get_installed_rules(e).unwrap_or(Vec::new(e));
    let (desired, params) = rules::desired(e, compiled);
    let (next, sum) = rules::reconcile(e, &current, &desired, &params, mode);
    if next != current {
        PerchStorage::set_installed_rules(e, &next);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_installed_rules_ttl(e, ttl, ttl)
        });
    }
    let recovery_rule = next.iter().find(|r| r.recovery).map(|r| r.id);
    if PerchStorage::get_recovery_rule(e) != recovery_rule {
        match recovery_rule {
            Some(id) => PerchStorage::set_recovery_rule(e, &id),
            None => PerchStorage::remove_recovery_rule(e),
        }
    }
    let controller = compiled.recovery.first().map(|r| r.controller);
    if PerchStorage::get_recovery_controller(e) != controller {
        match &controller {
            Some(c) => PerchStorage::set_recovery_controller(e, c),
            None => PerchStorage::remove_recovery_controller(e),
        }
    }
    sum
}

/// Constructor helper: install rule 0, "admin", scoped
/// `CallContract(self)` — the admin signers may manage this account (i.e.
/// call `apply_doc`) and nothing else. Every other capability arrives via an
/// applied, doc-reviewed rule set.
pub fn install_admin(e: &Env, admin_signers: &Vec<Signer>) {
    let rule = smart_account::add_context_rule(
        e,
        &ContextRuleType::CallContract(e.current_contract_address()),
        &String::from_str(e, "admin"),
        None,
        admin_signers,
        &Map::new(e),
    );
    PerchStorage::set_installed_rules(
        e,
        &Vec::from_array(e, [rules::admin_rule(e, rule.id, admin_signers)]),
    );
    extend_persistent(e, |ttl| {
        PerchStorage::extend_installed_rules_ttl(e, ttl, ttl)
    });
}

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
