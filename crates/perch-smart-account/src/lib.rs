//! The perch smart-account trait: **authorization data changes exactly one
//! way — [`PerchSmartAccount::apply_doc`]**.
//!
//! [`PerchSmartAccount`] extends OZ's `CustomAccountInterface` + `SmartAccount`
//! (the evaluation machinery) and exports a document-shaped surface instead of
//! OZ's piecemeal mutation API. A deployable implements `SmartAccount`
//! *without* exporting it — so `add_context_rule`, `add_signer`, `add_policy`,
//! … never exist as entry points — and exports this trait: doc-only is
//! structural, not conventional.
//!
//! `apply_doc` parses the document's JSON bytes (fail closed), validates,
//! checks the document names this network, compiles, refuses any document
//! that could lock the admin out, atomically replaces the whole rule set, and
//! stores the canonical `doc_hash` so anyone can check installed == reviewed
//! via [`PerchSmartAccount::applied_doc_hash`] — a read-only call.
#![no_std]

extern crate alloc;

use perch_compile::{compile, CompileConfig, LoweredRule, Plan, ScopeSpec, SignerSpec};
use perch_ir::PolicyDoc;
use soroban_sdk::{
    auth::CustomAccountInterface, contractevent, contracttrait, Address, Bytes, BytesN, Env,
    IntoVal, Map, String, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem};
use stellar_accounts::smart_account::{
    self, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountStorageKey,
};

/// Everything `apply_doc` can refuse — every path is fail-closed.
/// (`#[scerr]` assigns sequential codes from 1, in variant order.)
#[scerr]
pub enum PerchAccountError {
    /// The submitted document bytes are not UTF-8.
    DocNotUtf8,
    /// The document failed fail-closed parsing (unknown field, bad shape,
    /// unsupported version, duplicate key, …).
    DocParse,
    /// The document failed semantic validation (dangling signer ref,
    /// malformed address or key, ambiguous empty list, …).
    DocInvalid,
    /// The document names no network, or a network that is not this chain.
    WrongNetwork,
    /// The document cannot be lowered to rules (unsupported rule shape).
    DocCompile,
    /// The document contains no policy-free self-admin rule with at least one
    /// signer. Applying it could lock the admin out; refused (anti-brick).
    AdminLockout,
    /// The document carries a cumulative cap, which needs the `spending_limit`
    /// policy address — not yet appliable on-chain.
    CapUnsupported,
}

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
    /// Takes the document's JSON bytes and the shared perch interpreter's
    /// address; replaces the entire rule set atomically and returns the
    /// canonical `doc_hash`. Runs under the account's own authorization: the
    /// admin rule must approve the call.
    fn apply_doc(
        e: &Env,
        doc_json: Bytes,
        interpreter: Address,
    ) -> Result<BytesN<32>, PerchAccountError> {
        e.current_contract_address().require_auth();

        let doc = parse_checked(e, &doc_json)?;
        let plan = compile_checked(e, &doc)?;
        replace_rules(e, &plan, &interpreter)?;

        // The canonical identity — the hash the reviewer approved.
        // Canonicalization makes the submitted formatting irrelevant: a
        // pretty-printed file and its minified twin apply to the same hash.
        let canonical = perch_ir::canonical_json(&doc);
        let hash: BytesN<32> = e
            .crypto()
            .sha256(&Bytes::from_slice(e, canonical.as_bytes()))
            .to_bytes();
        PerchStorage::set_applied_doc(e, &hash);
        DocApplied {
            doc_hash: hash.clone(),
        }
        .publish(e);
        Ok(hash)
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

/// Bytes → parsed, validated, network-bound document. Anything not
/// understood is an error, never a skip; a testnet document can never be
/// applied on mainnet (or vice versa).
fn parse_checked(e: &Env, doc_json: &Bytes) -> Result<PolicyDoc, PerchAccountError> {
    let mut buf = alloc::vec![0u8; doc_json.len() as usize];
    doc_json.copy_into_slice(&mut buf);
    let json = core::str::from_utf8(&buf).map_err(|_| PerchAccountError::DocNotUtf8)?;

    let doc = perch_ir::from_json(json).map_err(|_| PerchAccountError::DocParse)?;
    perch_ir::validate(&doc).map_err(|_| PerchAccountError::DocInvalid)?;

    let net = doc
        .network
        .as_ref()
        .ok_or(PerchAccountError::WrongNetwork)?;
    let named: BytesN<32> = e
        .crypto()
        .sha256(&Bytes::from_slice(e, net.as_bytes()))
        .to_bytes();
    if named != e.ledger().network_id() {
        return Err(PerchAccountError::WrongNetwork);
    }
    Ok(doc)
}

/// Compile and refuse anything unsafe to apply. The config's wasm-hash pin is
/// advisory metadata for off-chain plans; on-chain the interpreter binding is
/// the explicit, admin-authorized `interpreter` argument.
fn compile_checked(e: &Env, doc: &PolicyDoc) -> Result<Plan, PerchAccountError> {
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
    };
    let plan = compile(e, doc, &cfg).map_err(|_| PerchAccountError::DocCompile)?;

    // Anti-brick (INV-2): the incoming rule set must contain at least one
    // policy-free self-admin rule with a signer, or the admin path could
    // depend on the interpreter — refuse before touching anything.
    let admin_survives = plan.rules.iter().any(|r| {
        matches!(r.scope, ScopeSpec::SelfAdmin)
            && !r.signers.is_empty()
            && r.install.is_none()
            && r.cap.is_none()
    });
    if !admin_survives {
        return Err(PerchAccountError::AdminLockout);
    }
    if plan.rules.iter().any(|r| r.cap.is_some()) {
        return Err(PerchAccountError::CapUnsupported);
    }
    Ok(plan)
}

/// Replace the entire rule set. One invocation — all-or-nothing; there is no
/// observable half-migrated state.
fn replace_rules(e: &Env, plan: &Plan, interpreter: &Address) -> Result<(), PerchAccountError> {
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
    for rule in plan.rules.iter() {
        install_rule(e, interpreter, rule)?;
    }
    Ok(())
}

/// Map one lowered rule onto OZ storage: scope + signers + optional
/// interpreter program, installed via the same library call `__check_auth`
/// evaluates against.
fn install_rule(
    e: &Env,
    interpreter: &Address,
    rule: &LoweredRule,
) -> Result<(), PerchAccountError> {
    let scope = match &rule.scope {
        ScopeSpec::SelfAdmin => ContextRuleType::CallContract(e.current_contract_address()),
        ScopeSpec::Contract(addr) => ContextRuleType::CallContract(Address::from_str(e, addr)),
    };
    let mut signers: Vec<Signer> = Vec::new(e);
    for s in rule.signers.iter() {
        signers.push_back(match s {
            SignerSpec::Delegated { address } => Signer::Delegated(Address::from_str(e, address)),
            SignerSpec::External { verifier, key_hex } => {
                Signer::External(Address::from_str(e, verifier), hex_bytes(e, key_hex)?)
            }
        });
    }
    let mut policies: Map<Address, Val> = Map::new(e);
    if let Some(install) = &rule.install {
        policies.set(interpreter.clone(), install.clone().into_val(e));
    }
    smart_account::add_context_rule(
        e,
        &scope,
        &String::from_str(e, &rule.name),
        rule.valid_until,
        &signers,
        &policies,
    );
    Ok(())
}

/// Decode a validated hex key. Validation already guarantees hex; still fail
/// closed here rather than trust it.
fn hex_bytes(e: &Env, s: &str) -> Result<Bytes, PerchAccountError> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(PerchAccountError::DocInvalid);
    }
    let nib = |c: u8| -> Result<u8, PerchAccountError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(PerchAccountError::DocInvalid),
        }
    };
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Ok(Bytes::from_slice(e, &out))
}
