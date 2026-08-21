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

use perch_doc_compiler::{CompiledDoc, CompiledRule, DocCompilerError, RuleScope};
use soroban_sdk::{
    auth::CustomAccountInterface, contractevent, contracttrait, Address, Bytes, BytesN, Env, Map,
    String, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem};
use stellar_accounts::smart_account::{
    self, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountStorageKey,
};

// Re-exported so `impl_perch_smart_account!` can name them via `$crate::…`
// regardless of the caller's dependency graph.
pub use soroban_sdk;
pub use stellar_accounts;

/// The perch registry (`unverified/perch`) — the account's own registry and the
/// single pinned anchor (a contract id, not a wasm hash). The `stateless`
/// subregistry derives from it by name-salt; the compiler + interpreter derive
/// from `stateless` by the sha256 of their **local wasm file** (see the
/// `wasm_file:` invocations below), pinned at build time.
// TODO(mainnet): feature-gate PERCH_REGISTRY per network.
pub const PERCH_REGISTRY: &str = "CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7";

// The `stateless` subregistry: name-salt(perch registry, "stateless").
perch_registry_resolve::registry_contract! {
    mod: stateless,
    deploy_name: "stateless",
}

// Compiler + interpreter: content-addressed off `stateless`, hash **pinned** to
// the sha256 of the local wasm file (resolved at build time by the macro). The
// files are fetched from the registry into `wasm/` (see `scripts/fetch-infra-wasm.sh`
// and `wasm/README.md`); a missing file is a build error telling you to fetch it.
// Pinned ⇒ a registry republish cannot change a deployed account's behavior
// (`installed == reviewed` holds), and nothing but the wasm bytes + names lives
// in source — no hand-copied hashes, no generated code.
perch_registry_resolve::registry_contract! {
    mod: compiler,
    wasm_name: "perch-doc-compiler",
    client: perch_doc_compiler::DocCompilerClient,
    wasm_file: "wasm/perch-doc-compiler.wasm",
}
// Address-only: the interpreter is used solely as a rule's policy-map key, so no
// client type is named and no interpreter code links into the account.
perch_registry_resolve::registry_contract! {
    mod: interpreter,
    wasm_name: "perch-interpreter",
    wasm_file: "wasm/perch-interpreter.wasm",
}

/// Everything `apply_doc` can refuse. Compiler failures flatten in via
/// `#[from_contract_client]` — the account's error space includes every
/// `DocCompilerError` variant, without gaps, converted by `??`.
#[scerr]
pub enum PerchAccountError {
    /// The compiled document contains no policy-free self-admin rule with at
    /// least one signer. Applying it could lock the admin out; refused
    /// (anti-brick).
    AdminLockout,
    #[from_contract_client]
    Compiler(DocCompilerError),
}

// scerr's composed (root) mode predates sdk 27's spec-shaking marker; the
// no-op impl is the trait's documented default, and root mode emits its own
// flattened error spec. (Upstream candidate for soroban-sdk-tools.)
impl soroban_sdk::SpecShakingMarker for PerchAccountError {}

/// Emitted after a document is applied: the new canonical `doc_hash`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocApplied {
    #[topic]
    pub doc_hash: BytesN<32>,
}

#[contractstorage]
#[allow(dead_code)] // the field names only derive storage keys + accessors
struct PerchStorage {
    /// Canonical `doc_hash` of the currently applied policy document.
    applied_doc: InstanceItem<BytesN<32>>,
}

/// The doc-only smart account surface. Implementers get OZ evaluation from
/// the supertraits and exactly one write path from here.
#[contracttrait]
pub trait PerchSmartAccount: CustomAccountInterface + SmartAccount {
    /// Apply a policy document — **the only way authorization changes**.
    /// Takes just the document's JSON bytes; the two shared, immutable infra
    /// contracts (the stateless doc compiler and the interpreter) are *derived*
    /// from the pinned [`PERCH_REGISTRY`] — the `stateless` subregistry by
    /// name-salt, then each infra's content-addressed address
    /// `deployer(stateless, wasm_hash)` where `wasm_hash` is the build-time
    /// sha256 of the pinned local wasm — computed offline (no cross-contract
    /// call), never passed in. Replaces the entire rule set atomically and
    /// returns the canonical `doc_hash`. Runs under the account's own
    /// authorization: the admin rule must approve the call.
    fn apply_doc(e: &Env, doc_json: Bytes) -> Result<BytesN<32>, PerchAccountError> {
        e.current_contract_address().require_auth();

        // Resolve the infra offline: derive the `stateless` subregistry from the
        // pinned perch registry (name-salt), then each infra address as
        // `deployer(stateless, pinned_wasm_hash).deployed_address()`. Pinned (not
        // runtime-fetched), so a registry republish can't change what a deployed
        // account runs; no admin-supplied addresses to vouch for.
        let perch_registry = Address::from_str(e, PERCH_REGISTRY);
        let stateless = stateless::address(e, &perch_registry);
        let interpreter = interpreter::address(e, &stateless);

        // Stateless compile: parse, validate, network-bind, lower. Every
        // compiler refusal surfaces here as a typed error.
        let compiled: CompiledDoc =
            compiler::client(e, &stateless).try_compile_doc(&doc_json)??;

        ensure_admin_survives(&compiled)?;

        // Replace the entire rule set. One invocation — all-or-nothing;
        // there is no observable half-migrated state.
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

        PerchStorage::set_applied_doc(e, &compiled.doc_hash);
        DocApplied {
            doc_hash: compiled.doc_hash.clone(),
        }
        .publish(e);
        Ok(compiled.doc_hash)
    }

    /// The canonical `doc_hash` of the currently applied policy document, or
    /// `None` if only the constructor's admin-root rule exists. Read-only:
    /// anyone can check installed == reviewed.
    fn applied_doc_hash(e: &Env) -> Option<BytesN<32>> {
        PerchStorage::get_applied_doc(e)
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

/// Constructor helper: install rule 0, "admin-root", scoped
/// `CallContract(self)` — the admin signers may manage this account (i.e.
/// call `apply_doc`) and nothing else. Every other capability arrives via an
/// applied, doc-reviewed rule set.
pub fn install_admin_root(e: &Env, admin_signers: &Vec<Signer>) {
    smart_account::add_context_rule(
        e,
        &ContextRuleType::CallContract(e.current_contract_address()),
        &String::from_str(e, "admin-root"),
        None,
        admin_signers,
        &Map::new(e),
    );
}

/// Anti-brick (INV-2): the incoming rule set must contain at least one
/// policy-free self-admin rule with a signer, or the admin path could depend
/// on the interpreter — refuse before touching anything.
fn ensure_admin_survives(compiled: &CompiledDoc) -> Result<(), PerchAccountError> {
    let ok = compiled.rules.iter().any(|r| {
        matches!(r.scope, RuleScope::SelfAdmin) && !r.signers.is_empty() && r.install.is_empty()
    });
    if ok {
        Ok(())
    } else {
        Err(PerchAccountError::AdminLockout)
    }
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
/// impl (`__check_auth` → OZ `do_check_auth`), a **non-exported**
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
            type Error = $crate::stellar_accounts::smart_account::SmartAccountError;
            type Signature = $crate::stellar_accounts::smart_account::AuthPayload;

            fn __check_auth(
                e: $crate::soroban_sdk::Env,
                signature_payload: $crate::soroban_sdk::crypto::Hash<32>,
                signatures: $crate::stellar_accounts::smart_account::AuthPayload,
                auth_contexts: $crate::soroban_sdk::Vec<$crate::soroban_sdk::auth::Context>,
            ) -> Result<(), Self::Error> {
                $crate::stellar_accounts::smart_account::do_check_auth(
                    &e,
                    &signature_payload,
                    &signatures,
                    &auth_contexts,
                )
            }
        }

        /// Satisfies the supertrait WITHOUT exporting entry points: OZ's
        /// mutation surface does not exist on this contract.
        impl SmartAccount for $ty {}

        #[$crate::soroban_sdk::contractimpl(contracttrait)]
        impl PerchSmartAccount for $ty {}
    };
}
