#![no_std]
//! SPIKE ONLY (throwaway, never published): the minimum versioned rule
//! backend Codex proposed, to measure how its operations scale.
//!
//! - Rules are stored one per key, `Rule(version, rule_id)`, and reference
//!   stable principal ids, never credentials.
//! - One `Bindings` entry maps principal id -> credential (`Signer`) plus
//!   the credential's fingerprint. Rotating a credential rewrites only it.
//! - A version is prepared in batches (`begin`, then `prepare` per batch,
//!   each batch compiled on-chain by the release doc compiler), folding each
//!   rule's provenance hash into a running commitment. It grants nothing
//!   until `activate` checks the approved commitment and flips `Active`.
//! - `restore` reactivates a recorded baseline version with new bindings
//!   and revokes the replaced and the thief's credentials, without touching
//!   any rule entry.
//! - `__check_auth` loads only the rules the payload selects, binds
//!   `(version, rule_ids)` into the signed digest, authenticates through
//!   OZ's `smart_account::authenticate` (the verifier contracts), evaluates
//!   each selected rule's program through the stateless `perch-vspike-eval`
//!   (the interpreter's `rpn::eval`), and keeps spending counters keyed by a
//!   stable rule key, outside every version.
//!
//! Shortcuts (deliberate, see the spike report): no Protected freeze, no
//! reserved-name guard, no recovery controller (a stand-in address
//! authorizes `restore` and `publish_baseline` is self-authorized), no
//! version garbage collection, no principal-mapping proof between the
//! compiled batch and the stored rules (only program, provenance, scope,
//! cap, and signer count are cross-checked), a fixed-window spending
//! counter instead of OZ's rolling history.

use perch_doc_compiler::{CompiledDoc, DocCompilerClient, RuleScope};
use perch_program::RpnProgram;
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, symbol_short,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, IntoVal, Map, TryFromVal, Val, Vec,
};
use stellar_accounts::smart_account::{authenticate, Signer};
use stellar_accounts::verifiers::VerifierClient;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    StaleVersion = 1,
    RuleIdsMismatch = 2,
    NoSuchRule = 3,
    WrongScope = 4,
    Expired = 5,
    UnauthorizedSigner = 6,
    NotEnoughSigners = 7,
    Denied = 8,
    CapExceeded = 9,
    NotAllowed = 10,
    VersionExists = 11,
    NoSuchVersion = 12,
    BatchOverflow = 13,
    BatchMismatch = 14,
    Incomplete = 15,
    CommitmentMismatch = 16,
    NoAdmin = 17,
    Revoked = 18,
    NoBaseline = 19,
    BadPrincipal = 20,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Scope {
    SelfAdmin,
    Contract(Address),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Cap {
    pub limit: i128,
    pub period: u32,
}

/// One compiled rule of one version. Immutable once written.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct StoredRule {
    /// Stable identity for mutable state (the spending counter):
    /// `sha256(name)`. Survives versions, rotation, and restore.
    pub key: BytesN<32>,
    pub scope: Scope,
    /// Principal ids (indexes into `Bindings`).
    pub principals: Vec<u32>,
    /// Zero or one interpreter program.
    pub program: Vec<RpnProgram>,
    /// Zero or one spending cap.
    pub cap: Vec<Cap>,
    pub valid_until: Option<u32>,
    /// `perch_ir::rule_hash` of the source rule (names, not credentials).
    pub rule_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VersionMeta {
    pub n_rules: u32,
    pub uploaded: u32,
    pub n_principals: u32,
    /// Running commitment: `sha256(acc || rule_hash)` per rule, seeded with
    /// the principal-name table's hash and the counts.
    pub acc: BytesN<32>,
    pub admin_ok: bool,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub signer: Signer,
    /// Fingerprint over the verifier's canonical key.
    pub fp: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Active {
    pub version: u32,
    pub commitment: BytesN<32>,
    pub epoch: u32,
    /// `sha256(xdr(bindings))`.
    pub bindings_hash: BytesN<32>,
    /// The approved identity: `sha256(commitment || bindings_hash)`.
    pub doc_id: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Window {
    pub start: u32,
    pub spent: i128,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BaselineRec {
    pub version: u32,
    pub commitment: BytesN<32>,
    /// The baseline's credentials, revoked when a compromise restores it.
    pub fps: Vec<BytesN<32>>,
}

#[contracttype]
#[derive(Clone)]
pub enum Key {
    Active,
    Eval,
    Compiler,
    Controller,
    Version(u32),
    Rule(u32, u32),
    /// Canonical bytes of one prepared batch (what `applied_doc` serves
    /// today, split per batch).
    Doc(u32, u32),
    Bindings,
    Counter(BytesN<32>),
    Revoked(BytesN<32>),
    Baseline,
}

/// The signature: which version and rules, and each principal's signature.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VAuth {
    pub version: u32,
    pub rule_ids: Vec<u32>,
    pub signers: Map<u32, Bytes>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPrepared {
    #[topic]
    pub version: u32,
    pub first: u32,
    pub count: u32,
    pub batch_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Activated {
    #[topic]
    pub doc_id: BytesN<32>,
    pub version: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingsChanged {
    #[topic]
    pub doc_id: BytesN<32>,
    pub epoch: u32,
    pub changed: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub fingerprint: BytesN<32>,
}

const VERSION_DOMAIN: &[u8] = b"perch/vspike/version";
const CRED_DOMAIN: &[u8] = b"perch/vspike/credential";

fn max_ttl(e: &Env) -> u32 {
    e.storage().max_ttl()
}

fn pset<K: IntoVal<Env, Val>, V: IntoVal<Env, Val>>(e: &Env, k: &K, v: &V) {
    let ttl = max_ttl(e);
    e.storage().persistent().set(k, v);
    e.storage().persistent().extend_ttl(k, ttl, ttl);
}

fn pget<K: IntoVal<Env, Val>, V: TryFromVal<Env, Val>>(e: &Env, k: &K) -> Option<V> {
    e.storage().persistent().get(k)
}

fn active(e: &Env) -> Active {
    e.storage().instance().get(&Key::Active).unwrap()
}

/// Fingerprints over each verifier's canonical key: one
/// `batch_canonicalize_key` call per run of same-verifier signers.
fn fingerprints(e: &Env, signers: &Vec<Signer>) -> Vec<BytesN<32>> {
    let mut out = Vec::new(e);
    let mut i = 0;
    while i < signers.len() {
        match signers.get_unchecked(i) {
            Signer::External(verifier, _) => {
                let mut keys: Vec<Val> = Vec::new(e);
                let mut j = i;
                while j < signers.len() {
                    match signers.get_unchecked(j) {
                        Signer::External(v, k) if v == verifier => {
                            keys.push_back(k.into_val(e));
                            j += 1;
                        }
                        _ => break,
                    }
                }
                let canon = VerifierClient::new(e, &verifier).batch_canonicalize_key(&keys);
                for c in canon.iter() {
                    let mut pre = Bytes::from_slice(e, CRED_DOMAIN);
                    pre.append(&Signer::External(verifier.clone(), c).to_xdr(e));
                    out.push_back(e.crypto().sha256(&pre).to_bytes());
                }
                i = j;
            }
            s @ Signer::Delegated(_) => {
                let mut pre = Bytes::from_slice(e, CRED_DOMAIN);
                pre.append(&s.to_xdr(e));
                out.push_back(e.crypto().sha256(&pre).to_bytes());
                i += 1;
            }
        }
    }
    out
}

fn bindings_of(e: &Env, signers: &Vec<Signer>) -> Vec<Binding> {
    let fps = fingerprints(e, signers);
    let mut out = Vec::new(e);
    for (s, fp) in signers.iter().zip(fps.iter()) {
        out.push_back(Binding { signer: s, fp });
    }
    out
}

fn identity(e: &Env, commitment: &BytesN<32>, bindings: &Vec<Binding>) -> (BytesN<32>, BytesN<32>) {
    let bindings_hash = e.crypto().sha256(&bindings.clone().to_xdr(e)).to_bytes();
    let mut pre = Bytes::from_array(e, &commitment.to_array());
    pre.extend_from_array(&bindings_hash.to_array());
    (bindings_hash, e.crypto().sha256(&pre).to_bytes())
}

fn seed(e: &Env, n_rules: u32, n_principals: u32, principals_hash: &BytesN<32>) -> BytesN<32> {
    let mut pre = Bytes::from_slice(e, VERSION_DOMAIN);
    pre.extend_from_array(&n_rules.to_be_bytes());
    pre.extend_from_array(&n_principals.to_be_bytes());
    pre.extend_from_array(&principals_hash.to_array());
    e.crypto().sha256(&pre).to_bytes()
}

fn fold(e: &Env, acc: &BytesN<32>, rule_hash: &BytesN<32>) -> BytesN<32> {
    let mut pre = Bytes::from_array(e, &acc.to_array());
    pre.extend_from_array(&rule_hash.to_array());
    e.crypto().sha256(&pre).to_bytes()
}

fn is_admin(r: &StoredRule) -> bool {
    r.scope == Scope::SelfAdmin
        && !r.principals.is_empty()
        && r.program.is_empty()
        && r.cap.is_empty()
}

fn revoke_all(e: &Env, fps: &Vec<BytesN<32>>, keep: &Vec<BytesN<32>>) {
    for fp in fps.iter() {
        if keep.contains(&fp) {
            continue;
        }
        let k = Key::Revoked(fp.clone());
        if !e.storage().persistent().has(&k) {
            pset(e, &k, &true);
            CredentialRevoked { fingerprint: fp }.publish(e);
        }
    }
}

fn refuse_revoked(e: &Env, fps: &Vec<BytesN<32>>) {
    for fp in fps.iter() {
        if e.storage().persistent().has(&Key::Revoked(fp)) {
            panic_with_error!(e, Error::Revoked);
        }
    }
}

fn spend(e: &Env, rule: &StoredRule, cap: &Cap, context: &Context) {
    let Context::Contract(ContractContext { fn_name, args, .. }) = context else {
        panic_with_error!(e, Error::NotAllowed);
    };
    if fn_name != &symbol_short!("transfer") {
        panic_with_error!(e, Error::NotAllowed);
    }
    let amount = args
        .get(2)
        .and_then(|v| i128::try_from_val(e, &v).ok())
        .unwrap_or_else(|| panic_with_error!(e, Error::NotAllowed));
    if amount < 0 {
        panic_with_error!(e, Error::NotAllowed);
    }
    let key = Key::Counter(rule.key.clone());
    let now = e.ledger().sequence();
    let mut w: Window = pget(e, &key).unwrap_or(Window {
        start: now,
        spent: 0,
    });
    if now >= w.start.saturating_add(cap.period) {
        w = Window {
            start: now,
            spent: 0,
        };
    }
    if w.spent + amount > cap.limit {
        panic_with_error!(e, Error::CapExceeded);
    }
    w.spent += amount;
    pset(e, &key, &w);
}

fn scope_matches(e: &Env, scope: &Scope, context: &Context) -> bool {
    match context {
        Context::Contract(ContractContext { contract, .. }) => match scope {
            Scope::SelfAdmin => contract == &e.current_contract_address(),
            Scope::Contract(a) => a == contract,
        },
        _ => false,
    }
}

#[contract]
pub struct VAccount;

#[contractimpl]
impl VAccount {
    /// Version 0: one self-admin rule naming principal 0.
    pub fn __constructor(
        e: Env,
        eval: Address,
        compiler: Address,
        controller: Address,
        signers: Vec<Signer>,
    ) {
        e.storage().instance().set(&Key::Eval, &eval);
        e.storage().instance().set(&Key::Compiler, &compiler);
        e.storage().instance().set(&Key::Controller, &controller);
        let admin = StoredRule {
            key: e
                .crypto()
                .sha256(&Bytes::from_slice(&e, b"admin"))
                .to_bytes(),
            scope: Scope::SelfAdmin,
            principals: Vec::from_array(&e, [0u32]),
            program: Vec::new(&e),
            cap: Vec::new(&e),
            valid_until: None,
            rule_hash: BytesN::from_array(&e, &[0; 32]),
        };
        let acc = fold(
            &e,
            &seed(&e, 1, signers.len(), &BytesN::from_array(&e, &[0; 32])),
            &admin.rule_hash,
        );
        pset(&e, &Key::Rule(0, 0), &admin);
        pset(
            &e,
            &Key::Version(0),
            &VersionMeta {
                n_rules: 1,
                uploaded: 1,
                n_principals: signers.len(),
                acc: acc.clone(),
                admin_ok: true,
            },
        );
        let bindings = bindings_of(&e, &signers);
        pset(&e, &Key::Bindings, &bindings);
        let (bindings_hash, doc_id) = identity(&e, &acc, &bindings);
        e.storage().instance().set(
            &Key::Active,
            &Active {
                version: 0,
                commitment: acc,
                epoch: 0,
                bindings_hash,
                doc_id,
            },
        );
        e.storage().instance().extend_ttl(max_ttl(&e), max_ttl(&e));
    }

    /// Open a version of `n_rules` rules over `n_principals` principals
    /// whose names hash to `principals_hash`.
    pub fn begin(
        e: Env,
        version: u32,
        n_rules: u32,
        n_principals: u32,
        principals_hash: BytesN<32>,
    ) {
        e.current_contract_address().require_auth();
        let k = Key::Version(version);
        if e.storage().persistent().has(&k) {
            panic_with_error!(&e, Error::VersionExists);
        }
        pset(
            &e,
            &k,
            &VersionMeta {
                n_rules,
                uploaded: 0,
                n_principals,
                acc: seed(&e, n_rules, n_principals, &principals_hash),
                admin_ok: false,
            },
        );
    }

    /// Upload the next batch of `version`'s rules. With a non-empty
    /// `batch_doc`, the release compiler compiles it in this transaction and
    /// every stored rule must match its compiled twin (program, provenance,
    /// scope, cap, signer count).
    pub fn prepare(e: Env, version: u32, rules: Vec<StoredRule>, batch_doc: Bytes) {
        e.current_contract_address().require_auth();
        let vk = Key::Version(version);
        let mut meta: VersionMeta =
            pget(&e, &vk).unwrap_or_else(|| panic_with_error!(&e, Error::NoSuchVersion));
        if meta.uploaded + rules.len() > meta.n_rules {
            panic_with_error!(&e, Error::BatchOverflow);
        }
        let batch_hash = if batch_doc.is_empty() {
            BytesN::from_array(&e, &[0; 32])
        } else {
            let compiler: Address = e.storage().instance().get(&Key::Compiler).unwrap();
            let compiled: CompiledDoc =
                DocCompilerClient::new(&e, &compiler).compile_doc(&batch_doc);
            if compiled.rules.len() != rules.len() {
                panic_with_error!(&e, Error::BatchMismatch);
            }
            for (stored, c) in rules.iter().zip(compiled.rules.iter()) {
                let scope_ok = match (&stored.scope, &c.scope) {
                    (Scope::SelfAdmin, RuleScope::SelfAdmin) => true,
                    (Scope::Contract(a), RuleScope::Contract(b)) => a == b,
                    _ => false,
                };
                let program_ok = match (stored.program.first(), c.install.first()) {
                    (None, None) => true,
                    (Some(p), Some(i)) => p == i.program && stored.rule_hash == i.doc_hash,
                    _ => false,
                };
                let cap_ok = match (stored.cap.first(), c.cap.first()) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        a.limit == b.spending_limit && a.period == b.period_ledgers
                    }
                    _ => false,
                };
                if !scope_ok || !program_ok || !cap_ok || stored.principals.len() != c.signers.len()
                {
                    panic_with_error!(&e, Error::BatchMismatch);
                }
            }
            pset(&e, &Key::Doc(version, meta.uploaded), &compiled.canonical);
            compiled.doc_hash
        };
        let first = meta.uploaded;
        for r in rules.iter() {
            for p in r.principals.iter() {
                if p >= meta.n_principals {
                    panic_with_error!(&e, Error::BadPrincipal);
                }
            }
            if is_admin(&r) {
                meta.admin_ok = true;
            }
            meta.acc = fold(&e, &meta.acc, &r.rule_hash);
            pset(&e, &Key::Rule(version, meta.uploaded), &r);
            meta.uploaded += 1;
        }
        pset(&e, &vk, &meta);
        BatchPrepared {
            version,
            first,
            count: rules.len(),
            batch_hash,
        }
        .publish(&e);
    }

    /// Activate a fully prepared version whose commitment is the approved
    /// one. Touches no rule entry.
    pub fn activate(e: Env, version: u32, expected: BytesN<32>) -> BytesN<32> {
        e.current_contract_address().require_auth();
        let meta: VersionMeta = pget(&e, &Key::Version(version))
            .unwrap_or_else(|| panic_with_error!(&e, Error::NoSuchVersion));
        if meta.uploaded != meta.n_rules {
            panic_with_error!(&e, Error::Incomplete);
        }
        if meta.acc != expected {
            panic_with_error!(&e, Error::CommitmentMismatch);
        }
        if !meta.admin_ok {
            panic_with_error!(&e, Error::NoAdmin);
        }
        let mut a = active(&e);
        if meta.n_principals > binding_count(&e, &a) {
            panic_with_error!(&e, Error::BadPrincipal);
        }
        let mut pre = Bytes::from_array(&e, &meta.acc.to_array());
        pre.extend_from_array(&a.bindings_hash.to_array());
        a.version = version;
        a.commitment = meta.acc;
        a.doc_id = e.crypto().sha256(&pre).to_bytes();
        e.storage().instance().set(&Key::Active, &a);
        Activated {
            doc_id: a.doc_id.clone(),
            version,
        }
        .publish(&e);
        a.doc_id
    }

    /// Bind principal `pid` to `signer`. Independent of how many rules name
    /// `pid`.
    pub fn rotate(e: Env, pid: u32, signer: Signer) -> BytesN<32> {
        e.current_contract_address().require_auth();
        let mut bindings: Vec<Binding> = pget(&e, &Key::Bindings).unwrap();
        if pid >= bindings.len() {
            panic_with_error!(&e, Error::BadPrincipal);
        }
        let fresh = bindings_of(&e, &Vec::from_array(&e, [signer]));
        refuse_revoked(&e, &Vec::from_array(&e, [fresh.get_unchecked(0).fp]));
        bindings.set(pid, fresh.get_unchecked(0));
        pset(&e, &Key::Bindings, &bindings);
        let mut a = active(&e);
        let (bindings_hash, doc_id) = identity(&e, &a.commitment, &bindings);
        a.epoch += 1;
        a.bindings_hash = bindings_hash;
        a.doc_id = doc_id;
        e.storage().instance().set(&Key::Active, &a);
        BindingsChanged {
            doc_id: a.doc_id.clone(),
            epoch: a.epoch,
            changed: 1,
        }
        .publish(&e);
        a.doc_id
    }

    /// Replace the whole binding table (a thief's every-key swap, or a
    /// reconfiguration that adds principals).
    pub fn set_bindings(e: Env, signers: Vec<Signer>) -> BytesN<32> {
        e.current_contract_address().require_auth();
        let bindings = bindings_of(&e, &signers);
        refuse_revoked(&e, &fps_of(&e, &bindings));
        pset(&e, &Key::Bindings, &bindings);
        let mut a = active(&e);
        let (bindings_hash, doc_id) = identity(&e, &a.commitment, &bindings);
        a.epoch += 1;
        a.bindings_hash = bindings_hash;
        a.doc_id = doc_id;
        e.storage().instance().set(&Key::Active, &a);
        BindingsChanged {
            doc_id: a.doc_id.clone(),
            epoch: a.epoch,
            changed: signers.len(),
        }
        .publish(&e);
        a.doc_id
    }

    /// Record the active version and credentials as the compromise
    /// baseline (stand-in for the controller's `publish_baseline`).
    pub fn publish_baseline(e: Env) {
        e.current_contract_address().require_auth();
        let a = active(&e);
        let bindings: Vec<Binding> = pget(&e, &Key::Bindings).unwrap();
        pset(
            &e,
            &Key::Baseline,
            &BaselineRec {
                version: a.version,
                commitment: a.commitment,
                fps: fps_of(&e, &bindings),
            },
        );
    }

    /// Compromise completion: reactivate the baseline version under
    /// `replacements`, revoking the baseline's replaced credentials and
    /// every current (thief) credential the replacements drop. No rule
    /// entry is read or written; spending counters are untouched.
    pub fn restore(e: Env, replacements: Vec<Signer>) -> BytesN<32> {
        let controller: Address = e.storage().instance().get(&Key::Controller).unwrap();
        controller.require_auth();
        let base: BaselineRec =
            pget(&e, &Key::Baseline).unwrap_or_else(|| panic_with_error!(&e, Error::NoBaseline));
        let meta: VersionMeta = pget(&e, &Key::Version(base.version))
            .unwrap_or_else(|| panic_with_error!(&e, Error::NoSuchVersion));
        if meta.acc != base.commitment || meta.uploaded != meta.n_rules {
            panic_with_error!(&e, Error::CommitmentMismatch);
        }
        if replacements.len() < meta.n_principals {
            panic_with_error!(&e, Error::BadPrincipal);
        }
        let current: Vec<Binding> = pget(&e, &Key::Bindings).unwrap();
        let next = bindings_of(&e, &replacements);
        let keep: Vec<BytesN<32>> = fps_of(&e, &next);
        refuse_revoked(&e, &keep);
        revoke_all(&e, &base.fps, &keep);
        revoke_all(&e, &fps_of(&e, &current), &keep);
        pset(&e, &Key::Bindings, &next);
        let (bindings_hash, doc_id) = identity(&e, &base.commitment, &next);
        let mut a = active(&e);
        a.version = base.version;
        a.commitment = base.commitment;
        a.epoch += 1;
        a.bindings_hash = bindings_hash;
        a.doc_id = doc_id.clone();
        e.storage().instance().set(&Key::Active, &a);
        Activated {
            doc_id: doc_id.clone(),
            version: base.version,
        }
        .publish(&e);
        doc_id
    }

    pub fn active(e: Env) -> Active {
        active(&e)
    }

    pub fn version(e: Env, version: u32) -> Option<VersionMeta> {
        pget(&e, &Key::Version(version))
    }

    pub fn rule(e: Env, version: u32, rule_id: u32) -> Option<StoredRule> {
        pget(&e, &Key::Rule(version, rule_id))
    }

    pub fn bindings(e: Env) -> Vec<Binding> {
        pget(&e, &Key::Bindings).unwrap()
    }

    pub fn window(e: Env, key: BytesN<32>) -> Option<Window> {
        pget(&e, &Key::Counter(key))
    }

    pub fn is_revoked(e: Env, fp: BytesN<32>) -> bool {
        e.storage().persistent().has(&Key::Revoked(fp))
    }
}

fn binding_count(e: &Env, _a: &Active) -> u32 {
    let b: Vec<Binding> = pget(e, &Key::Bindings).unwrap();
    b.len()
}

#[contractimpl]
impl CustomAccountInterface for VAccount {
    type Error = Error;
    type Signature = VAuth;

    fn __check_auth(
        e: Env,
        payload: Hash<32>,
        sig: VAuth,
        contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let a = active(&e);
        if sig.version != a.version {
            return Err(Error::StaleVersion);
        }
        if sig.rule_ids.len() != contexts.len() {
            return Err(Error::RuleIdsMismatch);
        }
        // Only the selected rules are loaded.
        let mut rules: Vec<StoredRule> = Vec::new(&e);
        for (id, context) in sig.rule_ids.iter().zip(contexts.iter()) {
            let r: StoredRule = pget(&e, &Key::Rule(a.version, id)).ok_or(Error::NoSuchRule)?;
            if let Some(until) = r.valid_until {
                if until < e.ledger().sequence() {
                    return Err(Error::Expired);
                }
            }
            if !scope_matches(&e, &r.scope, &context) {
                return Err(Error::WrongScope);
            }
            rules.push_back(r);
        }
        // `(version, rule_ids)` bound into what the signers sign.
        let mut pre = payload.to_bytes().to_bytes();
        pre.append(&(sig.version, sig.rule_ids.clone()).to_xdr(&e));
        let digest = e.crypto().sha256(&pre);

        let bindings: Vec<Binding> = pget(&e, &Key::Bindings).unwrap();
        for (pid, sig_data) in sig.signers.iter() {
            if !rules.iter().any(|r| r.principals.contains(pid)) {
                return Err(Error::UnauthorizedSigner);
            }
            let b = bindings.get(pid).ok_or(Error::UnauthorizedSigner)?;
            authenticate(&e, &digest, &b.signer, &sig_data);
        }

        let eval: Address = e.storage().instance().get(&Key::Eval).unwrap();
        let me = e.current_contract_address();
        for (r, context) in rules.iter().zip(contexts.iter()) {
            let matched = r
                .principals
                .iter()
                .filter(|p| sig.signers.contains_key(*p))
                .count() as u32;
            if r.program.is_empty() && r.cap.is_empty() {
                if matched != r.principals.len() {
                    return Err(Error::NotEnoughSigners);
                }
                continue;
            }
            if matched == 0 {
                return Err(Error::NotEnoughSigners);
            }
            if let Some(p) = r.program.first() {
                let ok: bool = e.invoke_contract(
                    &eval,
                    &soroban_sdk::Symbol::new(&e, "evaluate"),
                    soroban_sdk::vec![
                        &e,
                        p.into_val(&e),
                        context.into_val(&e),
                        matched.into_val(&e),
                        me.into_val(&e)
                    ],
                );
                if !ok {
                    return Err(Error::Denied);
                }
            }
            if let Some(cap) = r.cap.first() {
                spend(&e, &r, &cap, &context);
            }
        }
        Ok(())
    }
}

fn fps_of(e: &Env, bindings: &Vec<Binding>) -> Vec<BytesN<32>> {
    Vec::from_iter(e, bindings.iter().map(|b| b.fp))
}
