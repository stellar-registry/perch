//! The perch smart account: author of the perch wasm releases and manager of
//! the `unverified/perch` subregistry.
//!
//! **Authorization data changes exactly one way: [`PerchAccount::apply_doc`].**
//! The account is an OZ smart-account composition for *evaluation*
//! (`__check_auth` → `do_check_auth`), but OZ's piecemeal mutation surface
//! (`add_context_rule`, `add_signer`, `add_policy`, …) is disabled — every
//! mutator entry point rejects with [`PerchAccountError::UseApplyDoc`]. A
//! policy change is: review a document, then submit its bytes in one call.
//! `apply_doc` parses (fail closed), validates, checks the document names this
//! network, compiles, refuses any document that could lock the admin out, and
//! atomically replaces the whole rule set — storing the canonical `doc_hash`
//! so anyone can check installed == reviewed via [`PerchAccount::applied_doc_hash`].
//!
//! The account is deliberately not upgradeable and has no execution entry
//! point: replacing it means deploying a new account and moving registry name
//! ownership.
#![no_std]

extern crate alloc;

use perch_compile::{compile, CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
#[allow(unused_imports)]
// Address/Val/Symbol/BytesN are used by the SmartAccount default-fn macro expansion.
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, Address, Bytes, BytesN, Env, IntoVal, Map, String, Symbol, Val, Vec,
};
#[allow(unused_imports)] // ContextRule is used by the SmartAccount default-fn macro expansion.
use stellar_accounts::smart_account::{
    self, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountError,
    SmartAccountStorageKey,
};

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PerchAccountError {
    /// Piecemeal rule mutation is disabled on this account. Author a policy
    /// document and submit it whole via `apply_doc`.
    UseApplyDoc = 100,
    /// The submitted document bytes are not UTF-8.
    DocNotUtf8 = 101,
    /// The document failed fail-closed parsing (unknown field, bad shape,
    /// unsupported version, duplicate key, …).
    DocParse = 102,
    /// The document failed semantic validation (dangling signer ref, malformed
    /// address or key, ambiguous empty list, …).
    DocInvalid = 103,
    /// The document names no network, or a network that is not this chain.
    WrongNetwork = 104,
    /// The document cannot be lowered to rules (unsupported rule shape).
    DocCompile = 105,
    /// The document contains no policy-free self-admin rule with at least one
    /// signer. Applying it could lock the admin out; refused (anti-brick).
    AdminLockout = 106,
    /// The document carries a cumulative cap, which needs the `spending_limit`
    /// policy address — not yet appliable on-chain. Fail closed.
    CapUnsupported = 107,
}

#[contracttype]
enum PerchDataKey {
    /// Canonical `doc_hash` of the currently applied policy document.
    AppliedDoc,
}

/// Emitted after a document is applied: the new canonical `doc_hash`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocApplied {
    #[topic]
    pub doc_hash: BytesN<32>,
}

#[contract]
pub struct PerchAccount;

#[contractimpl]
impl PerchAccount {
    /// Installs rule id 0: "admin-root", scoped `CallContract(self)` — the
    /// admin signers may manage this account (i.e. call `apply_doc`) and
    /// nothing else. Every other capability arrives via an applied,
    /// doc-reviewed rule set.
    pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::CallContract(e.current_contract_address()),
            &String::from_str(e, "admin-root"),
            None,
            &admin_signers,
            &Map::new(e),
        );
    }

    /// Apply a policy document — **the only way this account's authorization
    /// changes**. Takes the document's JSON bytes and the shared perch
    /// interpreter's address; replaces the entire rule set atomically and
    /// returns the canonical `doc_hash` (also stored, see
    /// [`Self::applied_doc_hash`]).
    ///
    /// Fail-closed at every step: non-UTF-8, unparseable, invalid,
    /// wrong-network, or unlowerable documents are rejected; so is any
    /// document without a policy-free self-admin rule (anti-brick — you cannot
    /// lock yourself out with an edit). Runs under the account's own
    /// authorization: the admin rule must approve the call.
    pub fn apply_doc(e: &Env, doc_json: Bytes, interpreter: Address) -> BytesN<32> {
        e.current_contract_address().require_auth();

        // Bytes → str, fail closed.
        let mut buf = alloc::vec![0u8; doc_json.len() as usize];
        doc_json.copy_into_slice(&mut buf);
        let json = match core::str::from_utf8(&buf) {
            Ok(s) => s,
            Err(_) => panic_with_error!(e, PerchAccountError::DocNotUtf8),
        };

        // Parse + validate — anything not understood is an error, never a skip.
        let doc = match perch_ir::from_json(json) {
            Ok(d) => d,
            Err(_) => panic_with_error!(e, PerchAccountError::DocParse),
        };
        if perch_ir::validate(&doc).is_err() {
            panic_with_error!(e, PerchAccountError::DocInvalid);
        }

        // The document must be written for THIS network: its `network` string
        // must hash to the chain's network id. A testnet document can never be
        // applied on mainnet (or vice versa).
        match &doc.network {
            Some(net) => {
                let named: BytesN<32> = e
                    .crypto()
                    .sha256(&Bytes::from_slice(e, net.as_bytes()))
                    .to_bytes();
                if named != e.ledger().network_id() {
                    panic_with_error!(e, PerchAccountError::WrongNetwork);
                }
            }
            None => panic_with_error!(e, PerchAccountError::WrongNetwork),
        }

        // Compile. The config's wasm-hash pin is advisory metadata for
        // off-chain plans; on-chain the interpreter binding is the explicit,
        // admin-authorized `interpreter` argument.
        let cfg = CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
        };
        let plan = match compile(e, &doc, &cfg) {
            Ok(p) => p,
            Err(_) => panic_with_error!(e, PerchAccountError::DocCompile),
        };

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
            panic_with_error!(e, PerchAccountError::AdminLockout);
        }
        if plan.rules.iter().any(|r| r.cap.is_some()) {
            panic_with_error!(e, PerchAccountError::CapUnsupported);
        }

        // Replace the entire rule set. One invocation — all-or-nothing; there
        // is no observable half-migrated state.
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
            install_rule(e, &interpreter, rule);
        }

        // Store + return the canonical identity — the hash the reviewer
        // approved. Canonicalization makes the submitted formatting
        // irrelevant: a pretty-printed file and its minified twin apply to
        // the same doc_hash.
        let canonical = perch_ir::canonical_json(&doc);
        let hash: BytesN<32> = e
            .crypto()
            .sha256(&Bytes::from_slice(e, canonical.as_bytes()))
            .to_bytes();
        e.storage().instance().set(&PerchDataKey::AppliedDoc, &hash);
        DocApplied {
            doc_hash: hash.clone(),
        }
        .publish(e);
        hash
    }

    /// The canonical `doc_hash` of the currently applied policy document, or
    /// `None` if only the constructor's admin-root rule exists. Read-only:
    /// anyone can check installed == reviewed.
    pub fn applied_doc_hash(e: &Env) -> Option<BytesN<32>> {
        e.storage().instance().get(&PerchDataKey::AppliedDoc)
    }
}

/// Map one lowered rule onto OZ storage: scope + signers + optional
/// interpreter program, installed via the same library call `__check_auth`
/// evaluates against.
fn install_rule(e: &Env, interpreter: &Address, rule: &LoweredRule) {
    let scope = match &rule.scope {
        ScopeSpec::SelfAdmin => ContextRuleType::CallContract(e.current_contract_address()),
        ScopeSpec::Contract(addr) => ContextRuleType::CallContract(Address::from_str(e, addr)),
    };
    let mut signers: Vec<Signer> = Vec::new(e);
    for s in rule.signers.iter() {
        signers.push_back(match s {
            SignerSpec::Delegated { address } => Signer::Delegated(Address::from_str(e, address)),
            SignerSpec::External { verifier, key_hex } => {
                Signer::External(Address::from_str(e, verifier), hex_bytes(e, key_hex))
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
}

/// Decode a validated hex key. Validation already guarantees hex; still fail
/// closed here rather than trust it.
fn hex_bytes(e: &Env, s: &str) -> Bytes {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        panic_with_error!(e, PerchAccountError::DocInvalid);
    }
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic_with_error!(e, PerchAccountError::DocInvalid),
        }
    };
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i]) << 4) | nib(b[i + 1]));
        i += 2;
    }
    Bytes::from_slice(e, &out)
}

#[contractimpl]
impl CustomAccountInterface for PerchAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

/// OZ's `SmartAccount` trait, with **every mutator disabled**: the read-only
/// getters keep their library defaults, and each state-changing entry point
/// rejects with [`PerchAccountError::UseApplyDoc`]. The one write path is
/// [`PerchAccount::apply_doc`].
#[contractimpl(contracttrait)]
impl SmartAccount for PerchAccount {
    fn add_context_rule(
        e: &Env,
        _context_type: ContextRuleType,
        _name: String,
        _valid_until: Option<u32>,
        _signers: Vec<Signer>,
        _policies: Map<Address, Val>,
    ) -> ContextRule {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn update_context_rule_name(e: &Env, _context_rule_id: u32, _name: String) -> ContextRule {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn update_context_rule_valid_until(
        e: &Env,
        _context_rule_id: u32,
        _valid_until: Option<u32>,
    ) -> ContextRule {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn remove_context_rule(e: &Env, _context_rule_id: u32) {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn add_signer(e: &Env, _context_rule_id: u32, _signer: Signer) -> u32 {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn remove_signer(e: &Env, _context_rule_id: u32, _signer_id: u32) {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn add_policy(e: &Env, _context_rule_id: u32, _policy: Address, _install_param: Val) -> u32 {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }

    fn remove_policy(e: &Env, _context_rule_id: u32, _policy_id: u32) {
        panic_with_error!(e, PerchAccountError::UseApplyDoc)
    }
}
