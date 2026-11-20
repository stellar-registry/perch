//! The perch smart-account trait: **authorization data changes only by
//! applying documents** — the account document through
//! [`PerchSmartAccount::apply_doc`], grant documents through
//! [`PerchSmartAccount::apply_grant`] and its removal entry points.
//!
//! [`PerchSmartAccount`] extends soroban's `CustomAccountInterface` and
//! exports a document-shaped surface: there is no piecemeal mutation API
//! (`add_context_rule`, `add_signer`, `add_policy`, …) at all, so doc-only is
//! structural, not conventional. [`impl_perch_smart_account!`] expands to the
//! `__check_auth` impl and this trait, so a deployable is a struct, a
//! constructor, and one macro call. (Rust cannot default supertrait items
//! from a subtrait — the macro is how the supertrait boilerplate lives here
//! instead of in every contract.)
//!
//! State and computation are split: parsing + compiling live in the
//! **stateless** shared `perch-doc-compiler` contract; this trait holds the
//! **stateful** half — the account's rule set and applied `doc_hash`.
//! `apply_doc` sends the document's JSON bytes to the compiler, refuses any
//! result that could lock the admin out, brings the installed rules to the
//! compiled document in one invocation (changing only the rules that differ,
//! `rules`), and stores the canonical `doc_hash` so anyone can check
//! installed == reviewed via [`PerchSmartAccount::applied_doc_hash`].
//!
//! The account document holds the account's own rules, recovery, and
//! everything a recovery restores. App grants can instead live in grant
//! documents, one per grant id, each compiled the same way, reconciled
//! against its own records, and refused if it reaches the account itself,
//! its recovery, or its guardian approvals at any controller, or is not in
//! normal form. A grant document's text is not stored: its records and
//! signer ids give it back, checked against its `doc_hash`. A recovery
//! completion wipes every grant at once by advancing a generation that
//! `__check_auth` checks (`docs/recovery/spec.md` §7.6).
//!
//! The account's own records are its rule registry (`rules`): rule ids from
//! its counter, and each rule's name, policies, and the rule-eval rule that
//! decides what it allows, which holds its scope, signers, and expiry.
//! `__check_auth` decides every authorization with rule-core's
//! `rule_eval::check_auth` over those stored rules (`rule_set`, `gate`), and
//! the account's `authenticate` (`auth`) checks the signers. The signer,
//! payload, and context-rule types are `perch-account-types`', the XDR and
//! contract-spec twins of OZ's. A recovery completion is decided by the
//! recovery controller alone: the account checks the payload as OZ's
//! `do_check_auth` did, over its own record of the recovery rule, and asks
//! the controller's `rcv_complete` about each context
//! ([`authorize_completion`]).
//!
//! Doc comments on the account's entry points, contract types, events, and
//! errors are compiled into its wasm's contract spec, which counts against
//! the network's contract-size limit. They are kept to a line or two; the
//! longer notes are in `docs/account-interface.md`, linked from `//`
//! comments, which stay out of the wasm.
#![no_std]

extern crate alloc;

use perch_doc_compiler::{
    CompiledDoc, CompiledZkFactor, DocCompilerClient, DocCompilerError, RuleScope,
};
use perch_recovery_interface::account::{
    is_frozen, is_guardian_approval, is_reserved_invoker_only, UpgradeReadiness,
};
use perch_recovery_interface::config::{leaf_to_insert, zk_factor_transition_ok};
use perch_recovery_interface::controller::{
    RecoveryError, RecoveryHooksClient, SyncOutcome, UpgradeStep,
};
use perch_recovery_interface::credential::{revocations, Credential};
use perch_recovery_interface::zk::MembershipPoolClient;
use perch_recovery_interface::{address_payload, UpgradeSubject};
/// The stored rule-eval rule ([`PerchSmartAccount::rule_set`]),
/// re-exported so a deployable can name it for `impl_perch_smart_account!`.
pub use perch_rule_eval::StoredRule;
use perch_rule_eval::{ModelPred, StoredRecord};
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contractevent, contracttrait, contracttype,
    crypto::Hash,
    Address, Bytes, BytesN, ContractExecutable, Env, Executable, String, Symbol, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem, PersistentItem, PersistentMap};

mod auth;
mod gate;
mod rule_set;
mod rules;
pub use auth::{authorize_completion, SMART_ACCOUNT_EXTEND_AMOUNT, SMART_ACCOUNT_TTL_THRESHOLD};
pub use perch_account_types::{
    AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccountError,
};
pub use rules::{
    InstalledPolicy, InstalledRule, RuleRecord, RuleSet, MAX_EXTERNAL_KEY_SIZE, MAX_NAME_SIZE,
    MAX_POLICIES, MAX_SIGNERS,
};

// Re-exported so `impl_perch_smart_account!` can name it via `$crate::…`
// regardless of the caller's dependency graph.
pub use soroban_sdk;

/// The registry Perch's verified verifiers are `deploy_stateless`'d from,
/// `perch/verifiers`, derived like [`constructorless_registry`] from the
/// committed `wasm/verifiers.path`: the registry a document's
/// `verifier-name` resolves in (`perch_doc_compiler`).
pub fn verifier_registry(env: &Env) -> Address {
    verifiers::registry(env)
}

/// Whether `verifier` is a contract `perch/verifiers` deployed: its code is
/// a wasm, and it sits at that wasm's content address in the registry,
/// where only the registry's `deploy_stateless` of a published hash puts a
/// contract. No call: the address and the code it runs say it.
pub fn is_verified_verifier(env: &Env, verifier: &Address) -> bool {
    match verifier.executable() {
        Some(Executable::Wasm(hash)) => {
            env.deployer()
                .with_address(verifier_registry(env), hash)
                .deployed_address()
                == *verifier
        }
        _ => false,
    }
}

mod verifiers {
    perch_registry_resolve::registry_contract! {
        mod: registry,
        path_file: "wasm/verifiers.path",
    }
    pub use registry::registry;
}

/// The registry the infra was `deploy_stateless`'d from — the content-addressed
/// deployer the infra derive their address from: the deployment manifest's
/// `registry.id` (`deployments/<network>.json`) for the current network. It is
/// **not hardcoded in source**: the committed `wasm/registry.path` names the
/// Stellar Registry root's deployer and salt and the named deploys below it,
/// and every hop is derived under the ledger's network id, so one build
/// resolves each network's own registry.
pub fn constructorless_registry(env: &Env) -> Address {
    infra::perch_doc_compiler::registry(env)
}

/// Content-addressed resolvers for the shared infra, named like
/// `import_contract_client!`. Each `infra::<name>::address(env)` derives
/// `deployer(constructorless_registry(env), sha256(wasm))` fully offline, with
/// **both** the registry's derivation (`wasm/registry.path`) and the wasm
/// hash (`wasm/<name>.sha256`) baked at build time from the committed
/// pins (`wasm/README.md`; a missing file is a build error). Pinned ⇒ a
/// registry republish can't change a deployed account's behavior (`installed ==
/// reviewed`), and only the names live in source. Grouped in a module so the
/// derived names don't collide with the `perch_doc_compiler` crate.
pub mod infra {
    perch_registry_resolve::registry_contract!(perch_doc_compiler);
    perch_registry_resolve::registry_contract!(perch_interpreter);

    // Published and `deploy_stateless`\'d into the same registry as the two
    // above: one registry path derives all three, so on each network they
    // must share a registry (canonically perch/constructorless under that
    // network's Stellar Registry root).
    perch_registry_resolve::registry_contract!(perch_spending_limit);
}

/// Everything the account's entry points can refuse. Compiler and controller
/// failures flatten in via `#[from_contract_client]`, converted by `??`.
#[scerr]
pub enum PerchAccountError {
    /// The document keeps no constraint-free, never-expiring self-admin rule
    /// with a signer (anti-brick).
    // docs/account-interface.md, "Errors".
    AdminLockout,
    /// The document names a revoked credential.
    // docs/recovery/spec.md §8.
    RevokedCredential,
    /// The document reuses a ZK enrollment id this account enrolled before.
    // Spec §3.4, like the next one.
    EnrollmentReused,
    /// The document changes the ZK factor without a new enrollment id.
    ZkFactorChangedInPlace,
    /// `execute` was asked to call an invoker-only hook.
    // Spec §15.
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
    /// A completion returned a credential that cannot be fingerprinted.
    InvalidCredential,
    /// The recovery generation moved since scheduling; the request can never
    /// execute.
    // docs/account-interface.md, "Upgrades".
    StaleUpgrade,
    /// The doc compiler refused the document (its `DocCompilerError` says
    /// why).
    #[from_contract_client]
    Compiler(DocCompilerError),
    /// The adopted recovery controller refused the call (its `RecoveryError`
    /// says why).
    #[from_contract_client]
    Recovery(RecoveryError),
    /// The account is not at `apply_doc`'s `expected_revision`.
    StaleRevision,
    /// A completed recovery would overflow the grant generation.
    GenerationExhausted,
    /// A grant document has a `recovery` member, a self-admin rule, a rule
    /// on the account or its recovery contracts, a guardian approval, or a
    /// token-admin function.
    // docs/account-interface.md, "Errors".
    GrantEscalation,
    /// No grant document has this grant id.
    UnknownGrant,
    /// `gc_grant` was given a live grant; `remove_grant` removes it.
    GrantLive,
    /// The document names a credential from a grant a recovery has wiped.
    // Spec §7.6.
    WipedCredential,
    /// The compiled document's model is missing, duplicated, unreadable, or
    /// does not match its rules.
    // docs/account-interface.md, "Errors".
    ModelInvalid,
    /// A rule other than the recovery rule asks for no signer (INV-1).
    UnguardedRule,
    /// A grant document is not in normal form, or has a rule already
    /// expired.
    // docs/account-interface.md, "apply_grant".
    NotNormalForm,
    /// A constructor admin signer's verifier is not one `perch/verifiers`
    /// deployed.
    // docs/account-interface.md, "Constructor".
    UnverifiedVerifier,
}

/// Why `__check_auth` refused before evaluating any rule.
#[scerr]
pub enum PerchAuthError {
    /// A context names an invoker-only hook (spec §15): these are reachable
    /// only from the account's own flows, never by signature.
    ReservedFunction,
    /// A `Protected` recovery attempt is authorized: the account authorizes
    /// nothing but that attempt's completion (spec §9).
    AccountFrozen,
    /// A selected rule belongs to a grant document a recovery completion
    /// wiped: the generation its stored rule carries is not the account's
    /// (spec §7.6).
    StaleGrant,
    /// A selected grant rule's context calls the recovery controller or
    /// the ZK adapter or pool of the applied recovery member, any of which
    /// may have been adopted after the grant was applied, or casts a
    /// guardian approval on any contract (spec §7.6).
    GrantEscalation,
    /// rule-eval refuses the authorization, or it chooses the recovery rule
    /// outside a completion (`gate`).
    RuleEvalRefused,
}

/// A grant document as the account stores it, a tuple: the grant generation
/// it was applied under, its `doc_hash`, the grant's position in the grant
/// index, its rules ([`RuleSet`]: the signer table, each signer once, and
/// each rule's record holding its stored rule), the document's signer ids in
/// declaration order, and each signer's `verifier-name` (empty where it has
/// none; the list empty when no signer has one), which with the records give
/// back its canonical text.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredGrant(
    pub u64,
    pub BytesN<32>,
    pub u32,
    pub RuleSet,
    pub Vec<String>,
    pub Vec<String>,
);

impl StoredGrant {
    /// The grant generation it was applied under.
    fn gen(&self) -> u64 {
        self.0
    }

    /// Its signer table.
    fn signers(&self) -> Vec<Signer> {
        self.3 .0.clone()
    }

    /// Its rules' records.
    fn rules(&self) -> Vec<RuleRecord> {
        self.3 .1.clone()
    }

    /// The grant as the `grant` view gives it.
    fn record(&self, e: &Env) -> GrantRecord {
        GrantRecord {
            gen: self.0,
            doc_hash: self.1.clone(),
            rules: rules::installed_view(e, &self.3 .0, &self.3 .1, None),
        }
    }
}

/// A grant document as applied.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRecord {
    /// The grant generation it was applied under; wiped once
    /// `grant_generation` moves past it.
    // docs/account-interface.md, "Types".
    pub gen: u64,
    /// Its canonical `doc_hash`.
    pub doc_hash: BytesN<32>,
    /// Every context rule it installed, with its id.
    pub rules: Vec<InstalledRule>,
}

/// The `Protected` freeze: while `ledger < until`, the account authorizes
/// only `attempt_id`'s completion.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeGate {
    /// The authorized attempt.
    pub attempt_id: u64,
    /// The authorized attempt's `expires_at`.
    pub until: u32,
}

/// The shared infra contracts this account pins at build time.
// A deployment check compares them with its manifest; see [`infra`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfraPins {
    pub doc_compiler: Address,
    pub interpreter: Address,
    pub spending_limit: Address,
}

/// What rule selection and signing need for the account document, read at one
/// ledger.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountConfiguration {
    /// The revision every other field belongs to.
    pub revision: u64,
    /// The applied document's `doc_hash`, if any.
    pub doc_hash: Option<BytesN<32>>,
    /// Every installed admin context rule, with its id.
    pub rules: Vec<InstalledRule>,
    /// The adopted recovery controller, if any.
    pub recovery_controller: Option<Address>,
    /// The recovery rule's id, if installed.
    pub recovery_rule: Option<u32>,
    /// The `Protected` freeze: zero or one entries.
    // docs/account-interface.md, "Types".
    pub gate: Vec<FreezeGate>,
    /// The recovery generation.
    pub recovery_generation: u64,
    /// The shared infra the account pins.
    pub infra: InfraPins,
}

/// Constants of this wasm a wallet checks before building for the account.
// docs/account-interface.md, "Types".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCapabilities {
    /// The interface version.
    pub interface_version: u32,
    /// How `doc_hash` is computed: `canon_v1`.
    pub doc_identity: Symbol,
    /// What signers sign: `addr_oz_v1`, bound to the account's address.
    pub auth_digest: Symbol,
    /// `one_tx` (account document) and `grant_v1` (grant documents).
    pub apply_modes: Vec<Symbol>,
    /// The `AccountConfiguration` layout version.
    pub snapshot_version: u32,
}

/// Domain tag binding a Perch account's authorization digest to the account's
/// own address (the `addr_oz_v1` scheme [`AccountCapabilities::auth_digest`]
/// names).
///
/// Soroban's `signature_payload` for a non-delegated custom-account credential
/// (`HashIdPreimage::SorobanAuthorization`) binds the network, nonce,
/// expiration, and invocation, but not the address of the account whose
/// `__check_auth` runs, and the host's per-account nonce namespace prevents
/// reuse only *within* one account. OZ then layers only the selected rule ids
/// into the signed digest. Without this binding, two accounts that share an
/// `External` key and matching rule ids demand a byte-identical digest, so a
/// signature collected for one is replayable on the other. [`bind_payload`]
/// folds the account's own 32-byte contract id into the payload before OZ
/// layers the rule ids on top, so the digest an `External` signer authenticates
/// against is unique to this account. The `Signer::Delegated` (CAP-0071) path
/// never consumes this digest — the host validates it under
/// `SorobanAuthorizationWithAddress`, which is already address-bound — so this
/// changes nothing for delegated signers.
pub const AUTH_ADDR_DOMAIN: &[u8] = b"perch/account/auth-addr-v1";

/// `AUTH_ADDR_DOMAIN || account_id || signature_payload`: the one preimage
/// both binding wrappers hash, so they can never drift.
fn auth_preimage(e: &Env, account_id: &[u8; 32], signature_payload: &BytesN<32>) -> Bytes {
    let mut preimage = Bytes::from_slice(e, AUTH_ADDR_DOMAIN);
    preimage.extend_from_array(account_id);
    preimage.extend_from_array(&signature_payload.to_array());
    preimage
}

/// Fold `account_id` (a 32-byte contract id) into `signature_payload`:
/// `sha256(AUTH_ADDR_DOMAIN || account_id || signature_payload)`. The pure,
/// account-context-free core of [`bind_payload`]; off-chain signers
/// (`perch-js`, `perch-deploy`) reproduce exactly this. `perch-js`'s
/// `signingDigest` and `perch-testkit`'s `auth_digest` are pinned against the
/// on-chain result by `integration-tests/tests/auth_vectors.rs`.
pub fn bind_signature_payload(
    e: &Env,
    account_id: &BytesN<32>,
    signature_payload: &BytesN<32>,
) -> BytesN<32> {
    e.crypto()
        .sha256(&auth_preimage(e, &account_id.to_array(), signature_payload))
        .to_bytes()
}

/// [`bind_signature_payload`] for `account`, reading its 32-byte contract id
/// from the address. For off-account callers (test helpers, host-side signers)
/// that build the digest without being inside the account's `__check_auth`.
pub fn bind_signature_payload_for_account(
    e: &Env,
    account: &Address,
    signature_payload: &BytesN<32>,
) -> BytesN<32> {
    let id = address_payload(e, account)
        .map(|(_, id)| id)
        .unwrap_or([0u8; 32]);
    bind_signature_payload(e, &BytesN::from_array(e, &id), signature_payload)
}

/// [`bind_signature_payload`] for the account currently executing: its own
/// contract id is read from `e.current_contract_address()`.
fn bind_payload(e: &Env, signature_payload: &Hash<32>) -> Hash<32> {
    let me = e.current_contract_address();
    // A deployed account is always a `C...` contract, so `address_payload`
    // yields its 32-byte contract id.
    let id = address_payload(e, &me)
        .map(|(_, id)| id)
        .unwrap_or([0u8; 32]);
    e.crypto()
        .sha256(&auth_preimage(e, &id, &signature_payload.to_bytes()))
}

/// The account's consumer interface version: the views
/// ([`PerchSmartAccount::revision`], [`PerchSmartAccount::configuration`],
/// [`PerchSmartAccount::document`], [`PerchSmartAccount::capabilities`]) and
/// `apply_doc`'s `expected_revision`. Version 2 adds grant documents
/// ([`PerchSmartAccount::apply_grant`] and the grant views); since then
/// `configuration` and `installed_rules` cover the account document only.
///
/// Version 4 adds the signer-table views [`PerchSmartAccount::rule_signers`]
/// and [`PerchSmartAccount::grant_signers`].
pub const INTERFACE_VERSION: u32 = 4;
/// The layout of [`AccountConfiguration`] and of the stored rules
/// [`PerchSmartAccount::rule_set`] and [`PerchSmartAccount::grant_rule_set`]
/// return. Version 3 stores rules compactly (`perch_rule_eval::StoredRule`):
/// a tuple, `string-in` values as strings, and signers as positions in the
/// signer table those views' companions return.
pub const SNAPSHOT_VERSION: u32 = 3;

/// A scheduled account upgrade (spec §12), bound to the account's recovery
/// generation.
pub use perch_recovery_interface::account::UpgradeRequest;

/// Emitted after the account document is applied: its `doc_hash`, the revision,
/// and what changed in the rule set.
// docs/account-interface.md, "Events".
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocApplied {
    #[topic]
    pub doc_hash: BytesN<32>,
    pub revision: u64,
    pub rules_added: u32,
    pub rules_removed: u32,
    pub rules_edited: u32,
    pub signers_added: u32,
    pub signers_removed: u32,
    pub policies_added: u32,
    pub policies_removed: u32,
}

/// Emitted after a grant document is applied: its grant id, `doc_hash`, grant
/// generation, and what changed in its rule set.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantApplied {
    #[topic]
    pub grant: u32,
    pub doc_hash: BytesN<32>,
    pub gen: u64,
    pub rules_added: u32,
    pub rules_removed: u32,
    pub rules_edited: u32,
    pub signers_added: u32,
    pub signers_removed: u32,
    pub policies_added: u32,
    pub policies_removed: u32,
}

/// Emitted when a grant document and its rules are removed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRemoved {
    #[topic]
    pub grant: u32,
    /// The grant generation it was applied under.
    pub gen: u64,
    pub rules_removed: u32,
}

/// Emitted when a completed recovery advances the grant generation to `gen`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantsWiped {
    pub gen: u64,
}

/// Emitted when a recovery completion revokes a credential.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub fingerprint: BytesN<32>,
}

/// Emitted when the controller sets (`until > 0`) or clears the freeze.
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
    /// The first ledger it may execute.
    pub executable_at: u32,
}

/// Event emitted when a context rule is added.
// The constructor's, for its admin rule: OZ's registry event, so indexers
// that find accounts by it still do.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRuleAdded {
    #[topic]
    pub context_rule_id: u32,
    pub name: String,
    pub context_type: ContextRuleType,
    pub valid_until: Option<u32>,
    pub signer_ids: Vec<u32>,
    pub policy_ids: Vec<u32>,
}

/// Emitted when a scheduled upgrade is dropped.
// docs/account-interface.md, "Events".
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
    /// The grant generation (spec §7.6): advanced by one by every completed
    /// recovery, by nothing else. Absent reads as 0. Never reset or
    /// decreased. A grant rule authorizes only while the generation its
    /// stored rule carries is this one.
    grant_generation: InstanceItem<u64>,
    /// The id the next installed context rule gets. Absent reads as 0.
    /// Never reused: a removed rule's id is never given to another
    /// (`rules::allocate`).
    next_rule_id: InstanceItem<u32>,
    /// The account document's rules, as installed: each one's record, holding
    /// the rule-eval rule `__check_auth` evaluates for it (`rules`,
    /// `rule_set`), the recovery rule last when there is one. Written by the
    /// constructor and `apply_doc`, which reconciles the compiled document
    /// against these records alone, so its cost (and a completion's) is
    /// bounded by the document caps rather than by how many rules the
    /// account ever had, and an unchanged rule is not touched at all.
    rule_set: PersistentItem<RuleSet>,
    /// The next upgrade request id. Never reused.
    next_upgrade_id: InstanceItem<u64>,
    /// The configuration revision: 0 after the constructor, advanced by one
    /// in every successful `apply_doc` and every executed upgrade, by nothing
    /// else. Never decreases.
    revision: InstanceItem<u64>,
    /// Each grant document's record and rules, by grant id. `apply_grant`
    /// reconciles a grant document against its own record alone.
    grants: PersistentMap<u32, StoredGrant>,
    /// What each capped rule has spent in its window, by rule id, as
    /// rule-eval charges it in `__check_auth` (`gate`). Absent reads as
    /// nothing spent. Dropped when an apply removes or replaces its rule or
    /// changes its cap (`gate::drop_records`), and with its grant
    /// (`drop_grant`).
    spend_records: PersistentMap<u32, StoredRecord>,
    /// The grant id of every context rule a grant document installed, by rule
    /// id: its tag. The account document's rules carry none. No rule id is
    /// reused (`next_rule_id`), so a tag never outlives its rule into
    /// another.
    grant_tags: PersistentMap<u32, u32>,
    /// How many grant ids have a record: the length of `grant_index`.
    grant_count: InstanceItem<u32>,
    /// Every grant id with a record, by position `0..grant_count`: what
    /// `grants` lists. Each grant's record holds its position. A removal
    /// moves the last id into the freed position, so adding or removing a
    /// grant writes O(1) entries however many exist.
    grant_index: PersistentMap<u32, u32>,
    /// The credential index (spec §7.6): for every credential fingerprint a
    /// grant document named, the last grant generation one named it
    /// under. Once the grant generation has moved past it, no document may
    /// name that credential again. Never removed.
    grant_credentials: PersistentMap<BytesN<32>, u64>,
}

/// The doc-only smart account surface: documents are the only write path
/// for authorization data, the account document ([`Self::apply_doc`]) and
/// grant documents ([`Self::apply_grant`]). Plus the controlled
/// capabilities a wallet needs: execution through the account, full
/// document reads, recovery cancellation, and delayed upgrades.
#[contracttrait]
pub trait PerchSmartAccount: CustomAccountInterface {
    /// Apply the account document and return its `doc_hash`. Owner
    /// authorization, or the recovery rule for a completion. Refuses
    /// `StaleRevision` unless the account is at `expected_revision`, if given.
    /// `approval_valid_until` bounds a `Protected` reconfiguration's approvals.
    // docs/account-interface.md, "apply_doc".
    fn apply_doc(
        e: &Env,
        doc_json: Bytes,
        approval_valid_until: u32,
        expected_revision: Option<u64>,
    ) -> Result<BytesN<32>, PerchAccountError> {
        apply(
            e,
            doc_json,
            approval_valid_until,
            expected_revision,
            rules::Mode::Delta,
        )
    }

    /// Call `target_fn` on `target` as this account. Owner authorization;
    /// refuses invoker-only hooks.
    // docs/account-interface.md, "Calls as the account".
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

    /// The applied account document's canonical bytes, if any.
    // docs/account-interface.md, "Views".
    fn applied_doc(e: &Env) -> Option<Bytes> {
        PerchStorage::get_applied_doc_bytes(e)
    }

    /// The applied account document's canonical `doc_hash`, if any.
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

    /// The last grant generation a grant document named this credential under,
    /// if any.
    // docs/account-interface.md, "Views".
    fn credential_generation(e: &Env, fingerprint: BytesN<32>) -> Option<u64> {
        PerchStorage::get_grant_credentials(e, &fingerprint)
    }

    /// Whether this account ever enrolled a ZK enrollment id.
    fn is_enrolled_id(e: &Env, enrollment_id: BytesN<32>) -> bool {
        PerchStorage::has_enrolled_ids(e, &enrollment_id)
    }

    /// The adopted recovery controller, if any.
    fn recovery_controller(e: &Env) -> Option<Address> {
        PerchStorage::get_recovery_controller(e)
    }

    /// The `Protected` freeze, if set; in force while the ledger is below
    /// `until`.
    fn recovery_gate(e: &Env) -> Option<FreezeGate> {
        PerchStorage::get_gate(e)
    }

    /// Invoker-only: the adopted controller sets (`frozen_until > 0`) or clears
    /// (`0`) the `Protected` freeze.
    // docs/account-interface.md, "Recovery hooks".
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

    /// A `Loss` owner's cancellation of a recovery attempt.
    // docs/account-interface.md, "Recovery hooks".
    fn cancel_recovery(e: &Env, attempt_id: u64) -> Result<(), PerchAccountError> {
        let me = e.current_contract_address();
        me.require_auth();
        let controller = PerchStorage::get_recovery_controller(e)
            .ok_or(PerchAccountError::RecoveryNotEnrolled)?;
        RecoveryHooksClient::new(e, &controller).try_rcv_cancel(&me, &attempt_id)??;
        Ok(())
    }

    /// Schedule an upgrade to `wasm_hash` after the upgrade delay, replacing
    /// any pending one, and return its id. Owner authorization; under
    /// `Protected`, also approvals fresh until `approval_valid_until`.
    // docs/account-interface.md, "Upgrades".
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

    /// Execute the pending upgrade once its delay has passed. Owner
    /// authorization. Refuses `StaleUpgrade` if the recovery generation moved
    /// since scheduling.
    // docs/account-interface.md, "Upgrades".
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
        advance_revision(e);
        UpgradeExecuted {
            request_id,
            wasm_hash: request.wasm_hash.clone(),
        }
        .publish(e);
        e.deployer()
            .update_current_contract(ContractExecutable::Wasm(request.wasm_hash));
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

    /// The id the next `schedule_upgrade` assigns.
    fn next_upgrade_request_id(e: &Env) -> u64 {
        PerchStorage::get_next_upgrade_id(e).unwrap_or(0)
    }

    /// The account's recovery generation.
    // docs/account-interface.md, "Upgrades".
    fn recovery_generation(e: &Env) -> u64 {
        generation(e)
    }

    /// The grant generation: advanced only by completed recoveries. A grant
    /// applied under another is wiped.
    // docs/account-interface.md, "Views".
    fn grant_generation(e: &Env) -> u64 {
        grant_generation(e)
    }

    /// The configuration revision: advanced by every `apply_doc` and executed
    /// upgrade; never repeats.
    // docs/account-interface.md, "Views".
    fn revision(e: &Env) -> u64 {
        revision(e)
    }

    /// The account document's configuration, read at one ledger.
    fn configuration(e: &Env) -> AccountConfiguration {
        AccountConfiguration {
            revision: revision(e),
            doc_hash: PerchStorage::get_applied_doc(e),
            rules: admin_rules(e),
            recovery_controller: PerchStorage::get_recovery_controller(e),
            recovery_rule: PerchStorage::get_recovery_rule(e),
            gate: match PerchStorage::get_gate(e) {
                Some(g) => Vec::from_array(e, [g]),
                None => Vec::new(e),
            },
            recovery_generation: generation(e),
            infra: Self::infra(e),
        }
    }

    /// The applied account document's canonical bytes, with the revision they
    /// belong to.
    fn document(e: &Env) -> (u64, Option<Bytes>) {
        (revision(e), PerchStorage::get_applied_doc_bytes(e))
    }

    /// Constants of this wasm: interface and snapshot versions, digest schemes,
    /// and apply modes.
    fn capabilities(e: &Env) -> AccountCapabilities {
        AccountCapabilities {
            interface_version: INTERFACE_VERSION,
            doc_identity: Symbol::new(e, "canon_v1"),
            auth_digest: Symbol::new(e, "addr_oz_v1"),
            apply_modes: Vec::from_array(e, [Symbol::new(e, "one_tx"), Symbol::new(e, "grant_v1")]),
            snapshot_version: SNAPSHOT_VERSION,
        }
    }

    /// Extend the account's instance, document, and the named revoked and
    /// enrolled entries to the maximum TTL. Permissionless.
    // docs/account-interface.md, "Views".
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

    /// Every context rule the account document installed, with its id.
    fn installed_rules(e: &Env) -> Vec<InstalledRule> {
        admin_rules(e)
    }

    /// The rule-eval rules `__check_auth` evaluates, aligned with
    /// `installed_rules`, their signers positions in `rule_signers`.
    // docs/account-interface.md, "Views".
    fn rule_set(e: &Env) -> Vec<StoredRule> {
        stored_rules(e, &rule_set_of(e).1)
    }

    /// The signer table of the account document's stored rules: each signer
    /// once, at the position `rule_set` names it by.
    // docs/account-interface.md, "Views".
    fn rule_signers(e: &Env) -> Vec<Signer> {
        rule_set_of(e).0
    }

    /// The count of context rules, grants' and expired ones included.
    // docs/account-interface.md, "Views".
    fn get_context_rules_count(e: &Env) -> u32 {
        let mut count = rule_set_of(e).1.len();
        for grant in Self::grants(e, 0, u32::MAX).iter() {
            count += PerchStorage::get_grants(e, &grant).map_or(0, |r| r.rules().len());
        }
        count
    }

    /// The context rule with this id; panics if there is none.
    // docs/account-interface.md, "Views".
    fn get_context_rule(e: &Env, context_rule_id: u32) -> ContextRule {
        let set = match PerchStorage::get_grant_tags(e, &context_rule_id) {
            Some(grant) => PerchStorage::get_grants(e, &grant).map(|r| r.3),
            None => PerchStorage::get_rule_set(e),
        };
        let recovery = PerchStorage::get_recovery_rule(e) == Some(context_rule_id);
        let found = set.and_then(|set| {
            let record = set.1.iter().find(|r| r.id() == context_rule_id)?;
            Some(record.installed(e, &set.0, recovery))
        });
        match found {
            Some(rule) => rule.context_rule(e),
            None => soroban_sdk::panic_with_error!(
                e,
                soroban_sdk::Error::from(SmartAccountError::ContextRuleNotFound)
            ),
        }
    }

    /// Apply a grant document under `grant` and return its `doc_hash`. Owner
    /// authorization.
    // docs/account-interface.md, "apply_grant".
    fn apply_grant(e: &Env, grant: u32, doc_json: Bytes) -> Result<BytesN<32>, PerchAccountError> {
        apply_grant_doc(e, grant, doc_json)
    }

    /// Remove the grant document under `grant` and its rules. Owner
    /// authorization.
    fn remove_grant(e: &Env, grant: u32) -> Result<(), PerchAccountError> {
        e.current_contract_address().require_auth();
        let record = PerchStorage::get_grants(e, &grant).ok_or(PerchAccountError::UnknownGrant)?;
        drop_grant(e, grant, &record);
        Ok(())
    }

    /// Remove a grant document a recovery wiped, and its rules.
    /// Permissionless.
    // docs/account-interface.md, "Removing grants".
    fn gc_grant(e: &Env, grant: u32) -> Result<(), PerchAccountError> {
        let record = PerchStorage::get_grants(e, &grant).ok_or(PerchAccountError::UnknownGrant)?;
        if record.gen() == grant_generation(e) {
            return Err(PerchAccountError::GrantLive);
        }
        drop_grant(e, grant, &record);
        Ok(())
    }

    /// The grant document under `grant` as applied, if any.
    fn grant(e: &Env, grant: u32) -> Option<GrantRecord> {
        PerchStorage::get_grants(e, &grant).map(|s| s.record(e))
    }

    /// The rule-eval rules of the grant document under `grant`, aligned with
    /// its record's rules, their signers positions in `grant_signers`.
    fn grant_rule_set(e: &Env, grant: u32) -> Vec<StoredRule> {
        match PerchStorage::get_grants(e, &grant) {
            Some(s) => stored_rules(e, &s.rules()),
            None => Vec::new(e),
        }
    }

    /// The signer table of the grant document under `grant`, if any: each
    /// signer once, at the position `grant_rule_set` names it by, in the
    /// order its rules first name them.
    // docs/account-interface.md, "Views".
    fn grant_signers(e: &Env, grant: u32) -> Option<Vec<Signer>> {
        PerchStorage::get_grants(e, &grant).map(|s| s.signers())
    }

    /// The signer ids of the grant document under `grant`, in declaration
    /// order, if any: with its rules, they give back its canonical text.
    // docs/account-interface.md, "Views".
    fn grant_signer_ids(e: &Env, grant: u32) -> Option<Vec<String>> {
        PerchStorage::get_grants(e, &grant).map(|s| s.4)
    }

    /// Each signer's `verifier-name` in the grant document under `grant`,
    /// aligned with `grant_signer_ids`, if any: empty where a signer has
    /// none, and no entries when no signer has one.
    // docs/account-interface.md, "Views".
    fn grant_verifier_names(e: &Env, grant: u32) -> Option<Vec<String>> {
        PerchStorage::get_grants(e, &grant).map(|s| s.5)
    }

    /// How many grant ids have a record, wiped ones included.
    fn grant_count(e: &Env) -> u32 {
        PerchStorage::get_grant_count(e).unwrap_or(0)
    }

    /// The grant ids at index positions `start..start + count`, wiped ones
    /// included.
    // docs/account-interface.md, "Views".
    fn grants(e: &Env, start: u32, count: u32) -> Vec<u32> {
        let end = Self::grant_count(e).min(start.saturating_add(count));
        let mut ids = Vec::new(e);
        for i in start..end {
            ids.push_back(PerchStorage::get_grant_index(e, &i).unwrap());
        }
        ids
    }
}

/// The account's `__check_auth`: the reserved-name guard, the `Protected`
/// freeze, and the excluded-contract gate for grant rules run before any
/// rule is evaluated (spec §7.6, §9, §15); then the recovery controller
/// decides a recovery completion, and rule-eval's `check_auth` over the
/// stored rule sets, with `authenticate` checking every signer, decides
/// anything else (`gate`).
///
/// - Any context naming an invoker-only hook is refused, on any contract,
///   so no signature can satisfy a hook's `account.require_auth()`.
/// - While the freeze is in force the only authorizable thing is one
///   `apply_doc` context on this account that selects the recovery rule,
///   which the controller's `rcv_complete` then checks. This covers every
///   path that reaches `__check_auth`: direct authorization, `execute` and
///   every other entry point (each requires the account's own
///   authorization), and CAP-0071 delegation, where the host hands this
///   account the delegating account's contexts.
/// - A selected rule a grant document installed is refused for a call on
///   the current recovery controller, ZK adapter or pool, or for a guardian
///   approval or a token-admin function ([`TOKEN_ADMIN_FNS`]) on any
///   contract (`GrantEscalation`), on every path the same way.
/// - A context chosen under a capped rule, account or grant, or under a
///   grant rule for a token function whose argument 0 is the owner
///   (`transfer`, `transfer_from`, `approve`, `burn`, `burn_from`, matched
///   by name), is refused unless argument 0 is this account
///   (`RuleEvalRefused`), as a CAP-0071 delegate too. A grant rule for any
///   other function matches as its argument predicates say.
/// - rule-eval's `check_auth` over the stored rule sets refuses what it does
///   not accept: a chosen grant rule whose stored rule carries another
///   grant generation than the account's, from a grant document a
///   recovery completion wiped, with `StaleGrant`, anything else with
///   `RuleEvalRefused` (a chosen id that names no installed rule with
///   `ContextRuleNotFound`); once every signer has authenticated,
///   the spending records it charged are stored. A recovery completion (one
///   `apply_doc` context on this account selecting the recovery rule) is
///   left to the controller's `rcv_complete` ([`authorize_completion`]), so
///   recovery never depends on the evaluator; any other authorization
///   choosing the recovery rule is refused. The constructor stores the admin
///   rule set and every `apply_doc` replaces it; without one, nothing but a
///   completion is authorized (`RuleEvalRefused`).
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
    let recovery = PerchStorage::get_recovery_rule(e);
    let completion = is_completion(e, recovery, signatures, auth_contexts);
    if let Some(gate) = PerchStorage::get_gate(e) {
        if is_frozen(e.ledger().sequence(), gate.until) && !completion {
            return Err(PerchAuthError::AccountFrozen.into());
        }
    }
    // A grant rule never authorizes a call on the excluded set, which may
    // have been adopted after its grant was applied (spec §7.6), and never
    // casts a guardian approval, at whatever controller (§2), or calls a
    // token-admin function, on whatever contract (§7.6). An account
    // document's rule has no tag. A tag is extended on read, as its grant's
    // record is (`gate`), so the two live together.
    for (i, id) in signatures.context_rule_ids.iter().enumerate() {
        if PerchStorage::has_grant_tags(e, &id) {
            if let Some(Context::Contract(ContractContext {
                contract, fn_name, ..
            })) = auth_contexts.get(i as u32)
            {
                if excluded_contract(e, &contract)
                    || is_guardian_approval(e, &fn_name)
                    || is_token_admin(e, &fn_name)
                {
                    return Err(PerchAuthError::GrantEscalation.into());
                }
            }
            PerchStorage::extend_grant_tags_ttl(
                e,
                &id,
                SMART_ACCOUNT_TTL_THRESHOLD,
                SMART_ACCOUNT_EXTEND_AMOUNT,
            );
        }
    }
    if let Some(id) = recovery.filter(|_| completion) {
        return authorize_completion(e, id, signatures, auth_contexts);
    }
    let admin = PerchStorage::get_rule_set(e).ok_or(PerchAuthError::RuleEvalRefused)?;
    // Bind the digest to this account's address before OZ layers the selected
    // rule ids on top, so an `External` signature cannot be replayed on another
    // account that shares the key and rule ids (`AUTH_ADDR_DOMAIN`).
    let bound = bind_payload(e, signature_payload);
    gate::authorize(e, &admin, recovery, &bound, signatures, auth_contexts)
}

/// One `apply_doc` context on this account, selecting the recovery rule
/// (`recovery`).
fn is_completion(
    e: &Env,
    recovery: Option<u32>,
    signatures: &AuthPayload,
    contexts: &Vec<Context>,
) -> bool {
    let Some(rule) = recovery else {
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
/// `credential::revocations`). It advances the grant generation, which wipes
/// every grant document in one write however many exist (spec §7.6), lifts
/// the freeze, and drops any pending upgrade (spec §12).
fn complete_recovery(
    e: &Env,
    replaced: &Vec<Credential>,
    target_fingerprints: &Vec<BytesN<32>>,
) -> Result<(), PerchAccountError> {
    let next = grant_generation(e)
        .checked_add(1)
        .ok_or(PerchAccountError::GenerationExhausted)?;
    PerchStorage::set_grant_generation(e, &next);
    GrantsWiped { gen: next }.publish(e);
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

/// `apply_grant`'s body.
fn apply_grant_doc(e: &Env, grant: u32, doc_json: Bytes) -> Result<BytesN<32>, PerchAccountError> {
    let me = e.current_contract_address();
    me.require_auth();
    let compiled: CompiledDoc = DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
        .try_compile_doc(&doc_json)??;
    check_grant(e, &me, &compiled)?;
    let gen = grant_generation(e);
    let mut excluded = Vec::new(e);
    if let Some(c) = PerchStorage::get_recovery_controller(e) {
        excluded.push_back(c);
    }
    if let Some(z) = PerchStorage::get_current_zk(e) {
        excluded.push_back(z.adapter);
        excluded.push_back(z.pool);
    }
    let excluded: alloc::vec::Vec<Address> = excluded.iter().collect();
    let (signers, rule_set) = rule_set::lowered_grant(e, &compiled, &excluded, gen)?;
    check_normal(e, &me, &compiled)?;
    for fingerprint in compiled.fingerprints.iter() {
        if PerchStorage::has_revoked(e, &fingerprint) {
            return Err(PerchAccountError::RevokedCredential);
        }
    }
    // The credential index: refuse a credential a wiped grant named, and
    // record the rest under this generation.
    let mut unrecorded = Vec::new(e);
    for fingerprint in compiled.fingerprints.iter() {
        match PerchStorage::get_grant_credentials(e, &fingerprint) {
            Some(g) if g < gen => return Err(PerchAccountError::WipedCredential),
            Some(g) if g == gen => {}
            _ => unrecorded.push_back(fingerprint),
        }
    }
    extend_persistent(e, |ttl| {
        for fingerprint in unrecorded.iter() {
            PerchStorage::set_grant_credentials(e, &fingerprint, &gen);
            PerchStorage::extend_grant_credentials_ttl(e, &fingerprint, ttl, ttl);
        }
    });

    let record = PerchStorage::get_grants(e, &grant);
    let stored = record
        .as_ref()
        .map(|r| r.3.clone())
        .unwrap_or(RuleSet::empty(e));
    let current = rules::installed(e, &stored.0, &stored.1, None);
    let (desired, params) = rules::desired(e, &compiled);
    let (next, sum) = rules::reconcile(e, &current, &desired, &params, rules::Mode::Delta);
    let records = rules::records(e, &next, &rule_set);
    gate::drop_records(e, &stored.1, &records);

    // Every rule in a record is tagged with the grant, so only a new id
    // needs a tag.
    for c in current.iter() {
        if !next.iter().any(|n| n.id == c.id) {
            PerchStorage::remove_grant_tags(e, &c.id);
        }
    }
    extend_persistent(e, |ttl| {
        for n in next.iter() {
            if !current.iter().any(|c| c.id == n.id) {
                PerchStorage::set_grant_tags(e, &n.id, &grant);
                PerchStorage::extend_grant_tags_ttl(e, &n.id, ttl, ttl);
            }
        }
    });

    let pos = match &record {
        Some(r) => r.2,
        None => index_insert(e, grant),
    };
    let mut signer_ids = Vec::new(e);
    for s in compiled.model.get_unchecked(0).signers.iter() {
        signer_ids.push_back(s.id);
    }
    let named = compiled.verifier_names.iter().any(|n| !n.is_empty());
    let applied = StoredGrant(
        gen,
        compiled.doc_hash.clone(),
        pos,
        RuleSet(signers, records),
        signer_ids,
        if named {
            compiled.verifier_names.clone()
        } else {
            Vec::new(e)
        },
    );
    if record.as_ref() != Some(&applied) {
        PerchStorage::set_grants(e, &grant, &applied);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_grants_ttl(e, &grant, ttl, ttl)
        });
    }
    GrantApplied {
        grant,
        doc_hash: compiled.doc_hash.clone(),
        gen,
        rules_added: sum.rules_added,
        rules_removed: sum.rules_removed,
        rules_edited: sum.rules_edited,
        signers_added: sum.signers_added,
        signers_removed: sum.signers_removed,
        policies_added: sum.policies_added,
        policies_removed: sum.policies_removed,
    }
    .publish(e);
    Ok(compiled.doc_hash)
}

/// Refuse a compiled document that would reach past a grant: a recovery
/// member, a rule scoped to the account itself (every `self-admin` rule)
/// or to a contract of the excluded set (spec §7.6; the compiler checks the
/// ZK adapter and pool only within one document, spec §15 rule 3). A rule
/// whose `functions` names a guardian approval (§2) or a token-admin
/// function ([`TOKEN_ADMIN_FNS`]) is refused by `rule_set::lowered_grant`;
/// one that leaves its functions unrestricted is refused them in
/// `__check_auth` instead.
fn check_grant(e: &Env, me: &Address, compiled: &CompiledDoc) -> Result<(), PerchAccountError> {
    if !compiled.recovery.is_empty() {
        return Err(PerchAccountError::GrantEscalation);
    }
    for rule in compiled.rules.iter() {
        let RuleScope::Contract(target) = &rule.scope else {
            return Err(PerchAccountError::GrantEscalation);
        };
        if target == me || excluded_contract(e, target) {
            return Err(PerchAccountError::GrantEscalation);
        }
    }
    Ok(())
}

/// Refuse a grant document that is not in normal form (`NotNormalForm`):
/// one the compiler does not find in normal form
/// ([`CompiledDoc::normal_form`]), or with a rule already expired or an
/// `address-eq` naming the account, which the account alone can see. Every
/// grant document it applies then lowers to records from which its rules,
/// with its signer ids, rebuild its canonical text.
fn check_normal(e: &Env, me: &Address, compiled: &CompiledDoc) -> Result<(), PerchAccountError> {
    if !compiled.normal_form {
        return Err(PerchAccountError::NotNormalForm);
    }
    for rule in compiled.rules.iter() {
        if rules::expired(e, rule.valid_until) {
            return Err(PerchAccountError::NotNormalForm);
        }
    }
    for model in compiled.model.iter() {
        for rule in model.rules.iter() {
            for arg in rule.args.into_iter().flatten() {
                if matches!(&arg.pred, ModelPred::AddressEq(a) if a == me) {
                    return Err(PerchAccountError::NotNormalForm);
                }
            }
        }
    }
    Ok(())
}

/// The Stellar Asset Contract's admin functions. No grant (grant
/// document) calls them: they act with the token admin's authority, which
/// no argument names, so admin powers stay with the account document (spec
/// §7.6). Like guardian approvals they are matched by name on any contract.
pub const TOKEN_ADMIN_FNS: [&str; 4] = ["mint", "clawback", "set_admin", "set_authorized"];

/// Whether `fn_name` is in [`TOKEN_ADMIN_FNS`].
pub fn is_token_admin(e: &Env, fn_name: &Symbol) -> bool {
    TOKEN_ADMIN_FNS
        .iter()
        .any(|name| Symbol::new(e, name) == *fn_name)
}

/// The token functions whose argument 0 is the address whose authority
/// they use: the owner, or the spender of `transfer_from` and `burn_from`.
/// They are matched by name on any contract, since a grant cannot know
/// whether a contract is a SEP-41 token: under a grant, a call on a
/// non-token contract exporting one of these names with another argument 0
/// is refused.
pub const OWNER_FNS: [&str; 5] = ["transfer", "transfer_from", "approve", "burn", "burn_from"];

/// Whether `contract` is in the applied account document's excluded set,
/// beyond the account itself: its adopted recovery controller and its ZK
/// factor's adapter and pool (spec §7.6). No grant rule may reach them.
fn excluded_contract(e: &Env, contract: &Address) -> bool {
    PerchStorage::get_recovery_controller(e).is_some_and(|c| c == *contract)
        || PerchStorage::get_current_zk(e)
            .is_some_and(|z| *contract == z.adapter || *contract == z.pool)
}

/// Refuse a document naming a credential a grant document named under a
/// grant generation before `gen` (`WipedCredential`): a recovery
/// completion has ended that generation, and with it every grant the
/// credential carried (spec §7.6). Before the first completion nothing can
/// be wiped, so nothing is read.
fn check_unwiped(
    e: &Env,
    fingerprints: &Vec<BytesN<32>>,
    gen: u64,
) -> Result<(), PerchAccountError> {
    if gen == 0 {
        return Ok(());
    }
    for fingerprint in fingerprints.iter() {
        if PerchStorage::get_grant_credentials(e, &fingerprint).is_some_and(|g| g < gen) {
            return Err(PerchAccountError::WipedCredential);
        }
    }
    Ok(())
}

/// Remove `grant`'s record and rules (their tags and spending records with
/// it), and its index position.
fn drop_grant(e: &Env, grant: u32, record: &StoredGrant) {
    for r in record.rules().iter() {
        PerchStorage::remove_grant_tags(e, &r.id());
        gate::drop_record(e, r.id());
    }
    PerchStorage::remove_grants(e, &grant);
    index_remove(e, record.2);
    GrantRemoved {
        grant,
        gen: record.gen(),
        rules_removed: record.rules().len(),
    }
    .publish(e);
}

/// Append `grant` to the index and return its position.
fn index_insert(e: &Env, grant: u32) -> u32 {
    let n = PerchStorage::get_grant_count(e).unwrap_or(0);
    PerchStorage::set_grant_index(e, &n, &grant);
    PerchStorage::set_grant_count(e, &(n + 1));
    extend_persistent(e, |ttl| {
        PerchStorage::extend_grant_index_ttl(e, &n, ttl, ttl)
    });
    n
}

/// Swap-remove the grant at position `at` from the index: the last id takes
/// its position, and that grant's record is rewritten with it.
fn index_remove(e: &Env, at: u32) {
    let last = PerchStorage::get_grant_count(e).unwrap_or(0) - 1;
    if at != last {
        let moved = PerchStorage::get_grant_index(e, &last).unwrap();
        let mut record = PerchStorage::get_grants(e, &moved).unwrap();
        record.2 = at;
        PerchStorage::set_grant_index(e, &at, &moved);
        PerchStorage::set_grants(e, &moved, &record);
        extend_persistent(e, |ttl| {
            PerchStorage::extend_grant_index_ttl(e, &at, ttl, ttl);
            PerchStorage::extend_grants_ttl(e, &moved, ttl, ttl);
        });
    }
    PerchStorage::remove_grant_index(e, &last);
    PerchStorage::set_grant_count(e, &last);
}

/// The account document's rules as stored (none before the constructor).
fn rule_set_of(e: &Env) -> RuleSet {
    PerchStorage::get_rule_set(e).unwrap_or(RuleSet::empty(e))
}

/// The account document's rules as installed, the recovery rule marked.
fn admin_rules(e: &Env) -> Vec<InstalledRule> {
    let set = rule_set_of(e);
    rules::installed_view(e, &set.0, &set.1, PerchStorage::get_recovery_rule(e))
}

/// The stored rules of `records`, in order.
fn stored_rules(e: &Env, records: &Vec<RuleRecord>) -> Vec<StoredRule> {
    let mut out = Vec::new(e);
    for r in records.iter() {
        out.push_back(r.rule());
    }
    out
}

fn generation(e: &Env) -> u64 {
    PerchStorage::get_recovery_generation(e).unwrap_or(0)
}

fn advance_generation(e: &Env) {
    PerchStorage::set_recovery_generation(e, &(generation(e) + 1));
}

fn grant_generation(e: &Env) -> u64 {
    PerchStorage::get_grant_generation(e).unwrap_or(0)
}

fn revision(e: &Env) -> u64 {
    PerchStorage::get_revision(e).unwrap_or(0)
}

fn advance_revision(e: &Env) -> u64 {
    let next = revision(e) + 1;
    PerchStorage::set_revision(e, &next);
    next
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

/// `apply_doc`'s body. `mode` is [`rules::Mode::Delta`] except in tests
/// ([`testutils`]), which force the full replace.
fn apply(
    e: &Env,
    doc_json: Bytes,
    approval_valid_until: u32,
    expected_revision: Option<u64>,
    mode: rules::Mode,
) -> Result<BytesN<32>, PerchAccountError> {
    let me = e.current_contract_address();
    me.require_auth();
    if expected_revision.is_some_and(|r| r != revision(e)) {
        return Err(PerchAccountError::StaleRevision);
    }

    let compiled: CompiledDoc = DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
        .try_compile_doc(&doc_json)??;
    let rule_set = rule_set::lowered(e, &compiled)?;
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

    // The recovery gate runs before any context rule is touched, and only
    // this call can refuse a change: removing the recovery rule calls no
    // controller hook.
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
    // A completion's target is the controller's, not the authorizer's
    // choice: refusing it here would let a credential a thief once named in a grant
    // block every later recovery.
    if !matches!(outcome, SyncOutcome::Completed(_)) {
        check_unwiped(e, &compiled.fingerprints, grant_generation(e))?;
    }

    let delta = apply_rules(e, &compiled, &rule_set, mode);

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
        revision: advance_revision(e),
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
    use crate::rules::Mode;

    /// `apply_doc` with every rule removed and added again under a new id:
    /// the oracle the delta is checked against. Everything else (compile,
    /// revocation, recovery sync, completion effects) is shared with
    /// `apply_doc`.
    pub fn apply_doc_full_replace(
        e: &Env,
        doc_json: Bytes,
        approval_valid_until: u32,
        expected_revision: Option<u64>,
    ) -> Result<BytesN<32>, PerchAccountError> {
        apply(
            e,
            doc_json,
            approval_valid_until,
            expected_revision,
            Mode::FullReplace,
        )
    }

    /// Set the grant generation. Run as the account (`env.as_contract`).
    pub fn set_grant_generation(e: &Env, generation: u64) {
        PerchStorage::set_grant_generation(e, &generation);
    }

    /// Replace the admin records' stored rules with `rule_set`, in order, and
    /// their signer table with `signers`, the table `rule_set` names its
    /// signers in; panics unless it holds one rule per record. Run as the
    /// account (`env.as_contract`).
    pub fn set_rule_set(e: &Env, signers: &Vec<Signer>, rule_set: &Vec<StoredRule>) {
        let set = rule_set_of(e);
        PerchStorage::set_rule_set(
            e,
            &RuleSet(signers.clone(), with_rules(e, &set.1, rule_set)),
        );
    }

    /// Replace the stored rules and signer table of the grant document under
    /// `grant`, as [`set_rule_set`] does the account document's. Run as the
    /// account (`env.as_contract`).
    pub fn set_grant_rule_set(
        e: &Env,
        grant: u32,
        signers: &Vec<Signer>,
        rule_set: &Vec<StoredRule>,
    ) {
        let mut stored = PerchStorage::get_grants(e, &grant).expect("a grant record");
        stored.3 = RuleSet(signers.clone(), with_rules(e, &stored.3 .1, rule_set));
        PerchStorage::set_grants(e, &grant, &stored);
    }

    fn with_rules(e: &Env, records: &Vec<RuleRecord>, rules: &Vec<StoredRule>) -> Vec<RuleRecord> {
        assert_eq!(records.len(), rules.len(), "one stored rule per record");
        let mut out = Vec::new(e);
        for (record, rule) in records.iter().zip(rules.iter()) {
            out.push_back(RuleRecord(record.0, record.1, record.2, rule));
        }
        out
    }

    /// Overwrite the admin records and their signer table. Run as the
    /// account (`env.as_contract`).
    pub fn set_rule_records(e: &Env, set: &RuleSet) {
        PerchStorage::set_rule_set(e, set);
    }

    /// Install `rule`, whose signers are positions in `signers`, as an
    /// account-document rule named `name`, under a new id, which it returns:
    /// a record with no policy, as `apply_doc` records a document rule,
    /// appended to the admin records, its signers added to their table. Run
    /// as the account (`env.as_contract`).
    pub fn install_rule(e: &Env, name: &str, rule: &StoredRule, signers: &Vec<Signer>) -> u32 {
        let id = rules::allocate(e);
        let mut set = rule_set_of(e);
        let mut rule = rule.clone();
        let mut positions = Vec::new(e);
        for at in rule.3.iter() {
            let signer = signers.get(at).expect("a position in `signers`");
            let p = match set.0.first_index_of(&signer) {
                Some(p) => p,
                None => {
                    set.0.push_back(signer);
                    set.0.len() - 1
                }
            };
            positions.push_back(p);
        }
        rule.3 = positions;
        set.1
            .push_back(RuleRecord(id, String::from_str(e, name), Vec::new(e), rule));
        PerchStorage::set_rule_set(e, &set);
        id
    }

    /// Remove account-document rule `id`'s record. Run as the account
    /// (`env.as_contract`).
    pub fn remove_rule(e: &Env, id: u32) {
        let mut set = rule_set_of(e);
        if let Some(i) = set.1.iter().position(|r| r.id() == id) {
            set.1.remove(i as u32);
        }
        PerchStorage::set_rule_set(e, &set);
    }

    /// The id the next installed rule gets: every id below it was given
    /// once. Run as the account (`env.as_contract`).
    pub fn next_rule_id(e: &Env) -> u32 {
        PerchStorage::get_next_rule_id(e).unwrap_or(0)
    }

    /// The spending record the account keeps for rule `rule_id`, if
    /// rule-eval has charged it since its rule took its cap. Run as the
    /// account (`env.as_contract`).
    pub fn spend_record(e: &Env, rule_id: u32) -> Option<StoredRecord> {
        PerchStorage::get_spend_records(e, &rule_id)
    }
}

/// Bring the installed rules to the compiled document's in one invocation,
/// touching only rules that differ (`rules::reconcile`); there is no
/// observable half-migrated state. The recovery rule is not one of
/// `doc.rules`: it is a zero-signer self-scoped rule whose only policy is the
/// adopted controller, installed for the compiled configuration's hash.
/// Each record holds its rule of `rule_set` (`rule_set::lowered`), whose
/// order the reconcile keeps, and the spending records the new records no
/// longer keep are dropped (`gate::drop_records`).
fn apply_rules(
    e: &Env,
    compiled: &CompiledDoc,
    rule_set: &rule_set::Stored,
    mode: rules::Mode,
) -> rules::DeltaSummary {
    let stored = rule_set_of(e);
    let current = rules::installed(e, &stored.0, &stored.1, PerchStorage::get_recovery_rule(e));
    let (desired, params) = rules::desired(e, compiled);
    let (next, sum) = rules::reconcile(e, &current, &desired, &params, mode);
    let set = RuleSet(rule_set.0.clone(), rules::records(e, &next, &rule_set.1));
    gate::drop_records(e, &stored.1, &set.1);
    if set != stored {
        PerchStorage::set_rule_set(e, &set);
        extend_persistent(e, |ttl| PerchStorage::extend_rule_set_ttl(e, ttl, ttl));
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

/// Constructor helper: install rule 0, "admin", a policy-free rule scoped
/// `CallContract(self)`, as its record and the rule-eval rule it enforces. A
/// rule scoped to the account authorizes every account entry point that
/// requires the account's own authorization (`apply_doc`, the
/// grant-document entry points, `execute`, the upgrade and recovery-cancel
/// entry points), so the admin signers hold full owner authority. Every
/// other rule arrives via an applied, doc-reviewed document.
///
/// The signers are held to the install-time limits (`rules::check`),
/// refused (`UnverifiedVerifier`) if an external one's verifier is not one
/// `perch/verifiers` deployed ([`is_verified_verifier`]), as an account
/// document's must be, and refused if two are one key
/// (`auth::check_distinct`), and the rule is announced as OZ's registry
/// announces one (`ContextRuleAdded`).
pub fn install_account_rules(e: &Env, admin_signers: &Vec<Signer>) {
    let rule = rules::admin_rule(e, rules::allocate(e), admin_signers);
    rules::check(e, &rule);
    for signer in admin_signers.iter() {
        if let Signer::External(verifier, _) = &signer {
            if !is_verified_verifier(e, verifier) {
                soroban_sdk::panic_with_error!(e, PerchAccountError::UnverifiedVerifier);
            }
        }
    }
    auth::check_distinct(e, admin_signers);
    let record = RuleRecord(
        rule.id,
        rule.name.clone(),
        Vec::new(e),
        rule_set::admin(e, admin_signers),
    );
    PerchStorage::set_rule_set(
        e,
        &RuleSet(admin_signers.clone(), Vec::from_array(e, [record])),
    );
    extend_persistent(e, |ttl| PerchStorage::extend_rule_set_ttl(e, ttl, ttl));
    ContextRuleAdded {
        context_rule_id: rule.id,
        name: rule.name,
        context_type: rule.context_type,
        valid_until: None,
        signer_ids: rules::positions(e, admin_signers.len()),
        policy_ids: Vec::new(e),
    }
    .publish(e);
}

/// Expand the full deployable surface for `$ty`: the `CustomAccountInterface`
/// impl (`__check_auth` → [`check_auth`]) and the exported
/// [`PerchSmartAccount`] trait. Rust cannot put supertrait items' defaults on
/// a subtrait, so this macro is where that boilerplate lives — a deployable
/// is a struct, a constructor, and this call.
#[macro_export]
macro_rules! impl_perch_smart_account {
    ($ty:ident) => {
        // Same-name imports: soroban's macros derive symbol names from the
        // trait path as written, so the impl headers must use bare
        // identifiers. (These land in the invoking module's namespace —
        // don't import the same names yourself.)
        use $crate::soroban_sdk::auth::CustomAccountInterface;
        use $crate::PerchSmartAccount;

        #[$crate::soroban_sdk::contractimpl]
        impl CustomAccountInterface for $ty {
            type Error = $crate::soroban_sdk::Error;
            type Signature = $crate::AuthPayload;

            /// Decide whether this account authorizes `auth_contexts`.
            // Refuse reserved invoker-only names and, under a `Protected`
            // freeze, everything but the authorized completion; then decide
            // a recovery completion by the controller alone, and anything
            // else with rule-eval over a digest bound to this account, as
            // `perch_smart_account::check_auth` documents.
            fn __check_auth(
                e: $crate::soroban_sdk::Env,
                signature_payload: $crate::soroban_sdk::crypto::Hash<32>,
                signatures: $crate::AuthPayload,
                auth_contexts: $crate::soroban_sdk::Vec<$crate::soroban_sdk::auth::Context>,
            ) -> Result<(), Self::Error> {
                $crate::check_auth(&e, &signature_payload, &signatures, &auth_contexts)
            }
        }

        #[$crate::soroban_sdk::contractimpl(contracttrait)]
        impl PerchSmartAccount for $ty {}
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{BytesN, Env};

    // Folding the account id into the signed preimage (AUTH_ADDR_DOMAIN) is
    // what makes an External signer's digest unique per account: two accounts
    // sharing a key and a signature payload must still demand different
    // digests, so a signature collected for one cannot authorize the other.
    // The digest is also deterministic for a fixed account + payload. Its
    // on-chain/off-chain agreement is pinned by
    // integration-tests/tests/auth_vectors.rs; its end-to-end replay refusal
    // by integration-tests/tests/auth_binding.rs.
    #[test]
    fn binds_signature_digest_to_the_account_id() {
        let e = Env::default();
        let payload = BytesN::from_array(&e, &[7u8; 32]);
        let account_a = BytesN::from_array(&e, &[0xAA; 32]);
        let account_b = BytesN::from_array(&e, &[0xBB; 32]);

        let digest_a = bind_signature_payload(&e, &account_a, &payload);
        let digest_b = bind_signature_payload(&e, &account_b, &payload);
        assert_ne!(
            digest_a, digest_b,
            "a shared payload must not yield a shared digest across accounts"
        );
        assert_eq!(
            digest_a,
            bind_signature_payload(&e, &account_a, &payload),
            "digest must be deterministic for a fixed account and payload"
        );
    }

    // Each `PerchStorage` field's ledger key, as `contractstorage` derives it
    // from the field name: a map's key is `[Symbol(name), key]`, an item's
    // `Symbol(name)`. Renaming a field moves its entries to a new key and
    // leaves the old ones unread on every deployed account, so a rename must
    // change this list on purpose.
    #[test]
    fn the_storage_keys_are_the_committed_list() {
        use crate::perch_storage_keys__::*;
        use soroban_sdk::{Symbol, TryFromVal, Val, Vec};
        use soroban_sdk_tools::key::StorageKey;
        let e = Env::default();
        let item = |k: Val| Symbol::try_from_val(&e, &k).unwrap();
        let map = |k: Val| item(Vec::<Val>::try_from_val(&e, &k).unwrap().get(0).unwrap());
        let id = BytesN::from_array(&e, &[0; 32]);
        let keys = [
            (item(AppliedDoc.to_key(&e)), "AppliedDoc"),
            (item(AppliedDocBytes.to_key(&e)), "AppliedDocBytes"),
            (item(AppliedFingerprints.to_key(&e)), "AppliedFingerprints"),
            (item(RecoveryController.to_key(&e)), "RecoveryController"),
            (item(RecoveryRule.to_key(&e)), "RecoveryRule"),
            (item(Gate.to_key(&e)), "Gate"),
            (item(CurrentZk.to_key(&e)), "CurrentZk"),
            (map(Revoked::from(id.clone()).to_key(&e)), "Revoked"),
            (map(EnrolledIds::from(id.clone()).to_key(&e)), "EnrolledIds"),
            (item(PendingUpgrade.to_key(&e)), "PendingUpgrade"),
            (item(RecoveryGeneration.to_key(&e)), "RecoveryGeneration"),
            (item(GrantGeneration.to_key(&e)), "GrantGeneration"),
            (item(NextRuleId.to_key(&e)), "NextRuleId"),
            (item(RuleSet.to_key(&e)), "RuleSet"),
            (item(NextUpgradeId.to_key(&e)), "NextUpgradeId"),
            (item(Revision.to_key(&e)), "Revision"),
            (map(Grants::from(0).to_key(&e)), "Grants"),
            (map(SpendRecords::from(0).to_key(&e)), "SpendRecords"),
            (map(GrantTags::from(0).to_key(&e)), "GrantTags"),
            (item(GrantCount.to_key(&e)), "GrantCount"),
            (map(GrantIndex::from(0).to_key(&e)), "GrantIndex"),
            (
                map(GrantCredentials::from(id).to_key(&e)),
                "GrantCredentials",
            ),
        ];
        for (key, name) in keys {
            assert_eq!(key, Symbol::new(&e, name));
        }
    }
}
