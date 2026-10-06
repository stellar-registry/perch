//! The perch document compiler: a **stateless** deployable contract that turns
//! a policy document's JSON bytes into compiled rules plus the canonical
//! `doc_hash` — nothing else. It reads no storage and writes no storage;
//! deployed once per network, immutable, and shared by every perch account,
//! exactly like the interpreter.
//!
//! The split keeps state and computation apart: this contract owns *parsing
//! and compiling* (the JSON parser and the lowering logic live here, in one
//! audited place), while the smart account owns *the policy documents* — the
//! stored rule set and the applied `doc_hash`. Accounts call [`compile_doc`]
//! from `apply_doc` and apply the returned rules, so account wasm carries no
//! parser or compiler at all.
//!
//! Fail-closed at every step: non-UTF-8, unparseable, invalid, wrong-network,
//! or unlowerable documents are typed errors, never partial output.
//!
//! [`compile_doc`]: PerchDocCompiler::compile_doc
#![no_std]

extern crate alloc;

use perch_program::InstallParams;
use perch_recovery_interface::credential::{Credential, ReplacementSet};
use perch_recovery_interface::RecoveryAction;
use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, String, Vec};
use soroban_sdk_tools::scerr;
use stellar_accounts::smart_account::Signer;

/// The compiled recovery wire types, defined once in
/// `perch-recovery-interface` and re-exported here for the compiler's
/// consumers.
pub use perch_recovery_interface::config::{
    CompiledGuardianSet, CompiledRecoveryConfig, CompiledRecoveryMode, CompiledZkFactor,
    RecoveryProfile,
};

#[cfg(feature = "contract")]
use perch_compile::{compile, CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
#[cfg(feature = "contract")]
use perch_recovery_interface::config;
#[cfg(feature = "contract")]
use soroban_sdk::{contract, contractimpl, IntoVal, Map, Val};

/// Document caps (`docs/recovery/spec.md` §7.5): the compiler refuses a
/// document with more declared signers, more rules, or longer canonical
/// bytes than these, on every `compile_doc` and `derive_target`. They bound
/// the worst-case recovery completion (every removed credential revoked,
/// every rule replaced or edited by `apply_doc`'s diff). Sized against the
/// measured budget
/// (`docs/recovery/budgets.md`, "Document caps"): the costliest document
/// they admit stays within 75% of every per-transaction limit through
/// enrollment, a lost-key or compromise completion, and a reconfiguration.
/// The binding limit is CPU instructions: with OZ's per-item events
/// suppressed (the quiet-events experiment), events no longer bind.
pub const MAX_DOC_SIGNERS: u32 = 6;
/// See [`MAX_DOC_SIGNERS`].
pub const MAX_DOC_RULES: u32 = 12;
/// See [`MAX_DOC_SIGNERS`].
pub const MAX_DOC_CANONICAL_BYTES: u32 = 8_192;
/// The longest rule name, in bytes: OZ's context-rule name limit. Checked
/// here so that a document that compiles also installs: a compromise
/// baseline is only published, never applied, until its recovery completes.
pub const MAX_RULE_NAME_BYTES: u32 = stellar_accounts::smart_account::MAX_NAME_SIZE;

// A rule can name every declared signer; OZ installs at most `MAX_SIGNERS`
// per rule.
const _: () = assert!(MAX_DOC_SIGNERS <= stellar_accounts::smart_account::MAX_SIGNERS);

/// Everything `compile_doc` can refuse. (`#[scerr]` assigns sequential codes
/// from 1, in variant order.)
#[scerr]
pub enum DocCompilerError {
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
    /// The document exceeds a document cap ([`MAX_DOC_SIGNERS`],
    /// [`MAX_DOC_RULES`], [`MAX_DOC_CANONICAL_BYTES`],
    /// [`MAX_RULE_NAME_BYTES`]).
    DocTooLarge,
    /// A signer's verifier could not canonicalize its key, so the credential
    /// cannot be fingerprinted for revocation.
    KeyNotCanonicalizable,
    /// `derive_target`: the current document enrolls no recovery.
    NotEnrolled,
    /// `derive_target`: the replacement set breaks spec §7.3 rules 1-3 (not
    /// canonical, empty for lost-key, a signer id that is not replaceable or
    /// not declared in the source, or a change of credential kind or
    /// verifier), or the action is not a recovery attempt.
    ReplacementRefused,
    /// `derive_target`: the ZK enrollment is missing for a ZK mode, present
    /// for a guardian-only mode, or reuses the enrolled id.
    ZkEnrollmentMismatch,
    /// `derive_target`: the target has no policy-free self-admin rule with a
    /// signer (the anti-brick check).
    AdminLockout,
}

/// Where a compiled rule applies. `SelfAdmin` is account-agnostic: the
/// applying account resolves it to its own address.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RuleScope {
    SelfAdmin,
    Contract(Address),
}

/// One rule, compiled to the exact shapes OZ's `add_context_rule` takes:
/// resolved addresses, OZ `Signer`s, and (for constrained rules) the
/// interpreter program as `InstallParams`.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledRule {
    pub name: String,
    pub scope: RuleScope,
    pub signers: Vec<Signer>,
    pub valid_until: Option<u32>,
    /// Zero or one entries — a `Vec` rather than `Option<CompiledCap>`-style
    /// `Option` because `InstallParams` is itself a `#[contracttype]` struct,
    /// and `#[contracttype]`'s derive macro has no `ScVal`/spec conversion
    /// for `Option<T>` where `T` is a custom struct or enum (confirmed
    /// directly: it fails to compile with "the trait bound `ScVal:
    /// TryFrom<&Option<T>>` is not satisfied" — `Option<u32>` on
    /// `valid_until` above works because `u32` is a host-builtin type with
    /// its own direct `ScVal` conversion, not because `Option` itself is the
    /// problem). Empty ⇒ policy-free rule.
    pub install: Vec<InstallParams>,
    /// Zero or one entries (a `Vec` for the same reason as `install` —
    /// `CompiledCap` is itself a `#[contracttype]` struct). Present ⇒ also
    /// attach OZ `spending_limit` with these params — the cumulative cap the
    /// stateless interpreter cannot express. The applier resolves the
    /// policy's content-addressed address and keys it into the rule's policy
    /// map beside the interpreter; the tracked token is the rule's `Contract`
    /// scope (validation pins `token == scope`).
    pub cap: Vec<CompiledCap>,
}

/// A cumulative spend cap lowered to OZ `spending_limit`'s install params
/// (`SpendingLimitAccountParams`). The tracked token is the rule's scope
/// contract, so it is not carried here.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledCap {
    /// Cumulative amount ceiling over the rolling window.
    pub spending_limit: i128,
    /// Rolling-window length in ledgers.
    pub period_ledgers: u32,
}

/// A compiled document: its canonical identity and the rules it becomes.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledDoc {
    /// `sha256(canonical bytes)` — the hash the reviewer approved. Formatting
    /// of the submitted JSON is irrelevant: a pretty-printed file and its
    /// minified twin compile to the same hash.
    pub doc_hash: BytesN<32>,
    /// The canonical bytes `doc_hash` is the hash of. The account stores
    /// them so anyone, including the recovery controller, can read back the
    /// full applied document.
    pub canonical: Bytes,
    /// The fingerprint (`perch_recovery_interface::credential::Credential::
    /// fingerprint`) of every declared signer's credential, with external
    /// keys canonicalized by their verifier. What revocation compares
    /// (spec §8).
    pub fingerprints: Vec<BytesN<32>>,
    pub rules: Vec<CompiledRule>,
    /// Zero or one entries — a `Vec` because `CompiledRecoveryConfig` is
    /// itself a `#[contracttype]` struct (see [`CompiledRule::install`]'s
    /// doc comment for why `Option<CompiledRecoveryConfig>` doesn't compile
    /// here). Present ⇒ the document enrolls account recovery — the applier
    /// is expected to sync this configuration to the adopted
    /// recovery-controller instance named in it. See `docs/recovery/` for
    /// the full design; wire-compat notes live there too (this is a new
    /// field on an existing constructorless, immutable deployable — a
    /// compiler build carrying it is a new instance, not an in-place change
    /// to any already-deployed one).
    pub recovery: Vec<CompiledRecoveryConfig>,
}

/// What `derive_target` returns: the recovery target the controller binds
/// into an attempt's statement (spec §7.1).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DerivedTarget {
    /// The target's canonical bytes: exactly what the completing `apply_doc`
    /// must submit.
    pub canonical: Bytes,
    pub doc_hash: BytesN<32>,
    /// The target's recovery `config_hash` (the current one, or the current
    /// one with the declared ZK rotation).
    pub config_hash: BytesN<32>,
    /// Fingerprints of every credential in the target (spec §7.3 rule 7).
    pub fingerprints: Vec<BytesN<32>>,
    /// The credentials occupying the replaced signer slots in the source:
    /// the applied document's for lost-key, the baseline's for compromise.
    /// External keys are canonicalized by their verifier, so a credential's
    /// `fingerprint` is the one revocation compares. The controller records
    /// them at T1 and the completion revokes them (spec §8).
    pub replaced: Vec<Credential>,
}

/// Whether a compiled rule set keeps a policy-free self-admin rule with at
/// least one signer — the anti-brick check every applied document and every
/// recovery target must pass, so the admin path never depends on a policy.
pub fn admin_survives(rules: &Vec<CompiledRule>) -> bool {
    rules.iter().any(|r| {
        matches!(r.scope, RuleScope::SelfAdmin)
            && !r.signers.is_empty()
            && r.install.is_empty()
            && r.cap.is_empty()
    })
}

/// Cross-contract client, generated independently of the deployable so
/// consumers (smart accounts) link no compiler code at all — the account's
/// wasm carries neither the JSON parser nor the lowering logic.
#[allow(unused)]
#[contractclient(name = "DocCompilerClient")]
trait DocCompilerClientInterface {
    fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError>;

    fn derive_target(
        e: &Env,
        source_json: Bytes,
        current_json: Bytes,
        action: RecoveryAction,
        replacements: ReplacementSet,
    ) -> Result<DerivedTarget, DocCompilerError>;
}

/// The key-canonicalization half of OZ's verifier interface. Declared here
/// (OZ's own client trait is private) with the same entry point OZ's
/// duplicate-signer check calls, so fingerprints and OZ agree on what one
/// physical key is.
#[cfg(feature = "contract")]
#[allow(unused)]
#[contractclient(name = "KeyCanonicalizerClient")]
trait KeyCanonicalizerInterface {
    fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes>;
}

#[cfg(feature = "contract")]
#[contract]
pub struct PerchDocCompiler;

#[cfg(feature = "contract")]
#[contractimpl]
impl PerchDocCompiler {
    /// JSON bytes in → compiled rules + canonical `doc_hash` out. Pure:
    /// no auth, no storage. The document must name THIS network (its
    /// `network` string must hash to the chain's network id), so a testnet
    /// document can never compile on mainnet or vice versa.
    pub fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
        compile_parsed(e, &parse(&doc_json)?)
    }

    /// Derive a recovery target (`docs/recovery/spec.md` §7): `source_json`
    /// is the account's applied document (lost-key) or the published
    /// baseline (compromise); `current_json` is the applied document, whose
    /// recovery member the target keeps. The target is the source with
    /// exactly the declared replacements and ZK rotation, then validated,
    /// network-bound, capped, compiled, and anti-brick-checked like any
    /// applied document. Pure: no auth, no storage. The controller calls it
    /// when an attempt begins, and completers simulate it to obtain the
    /// canonical bytes.
    pub fn derive_target(
        e: &Env,
        source_json: Bytes,
        current_json: Bytes,
        action: RecoveryAction,
        replacements: ReplacementSet,
    ) -> Result<DerivedTarget, DocCompilerError> {
        use perch_ir::recovery::{self, DeriveAction, DeriveError, Replacement, ZkRotation};

        let action = match action {
            RecoveryAction::LostKey => DeriveAction::LostKey,
            RecoveryAction::Compromise => DeriveAction::Compromise,
            _ => return Err(DocCompilerError::ReplacementRefused),
        };
        let source = parse(&source_json)?;
        let current = parse(&current_json)?;

        let mut declared = alloc::vec::Vec::new();
        for r in replacements.signers.iter() {
            declared.push(Replacement {
                signer_id: to_std_string(&r.signer_id),
                method: to_signer_method(&r.credential),
            });
        }
        let rotation = match replacements.zk_enrollment.len() {
            0 => None,
            1 => {
                let z = replacements.zk_enrollment.get_unchecked(0);
                Some(ZkRotation {
                    enrollment_id: hex::encode(z.id.to_array()),
                    commitment: hex::encode(z.commitment.to_array()),
                })
            }
            _ => return Err(DocCompilerError::ZkEnrollmentMismatch),
        };

        let target =
            recovery::derive_target(&source, &current, action, &declared, rotation.as_ref())
                .map_err(|err| match err {
                    DeriveError::NotEnrolled => DocCompilerError::NotEnrolled,
                    DeriveError::ZkEnrollmentMismatch => DocCompilerError::ZkEnrollmentMismatch,
                    _ => DocCompilerError::ReplacementRefused,
                })?;

        let compiled = compile_parsed(e, &target)?;
        if !admin_survives(&compiled.rules) {
            return Err(DocCompilerError::AdminLockout);
        }
        let replaced_slots: alloc::vec::Vec<perch_ir::SignerDecl> = source
            .signers
            .iter()
            .filter(|s| declared.iter().any(|r| r.signer_id == s.id))
            .cloned()
            .collect();
        let config_hash = compiled
            .recovery
            .first()
            .map(|r| r.config_hash)
            .ok_or(DocCompilerError::NotEnrolled)?;
        Ok(DerivedTarget {
            canonical: compiled.canonical,
            doc_hash: compiled.doc_hash,
            config_hash,
            fingerprints: compiled.fingerprints,
            replaced: canonical_credentials(e, &replaced_slots)?,
        })
    }
}

/// Bytes → validated-shape document, fail closed.
#[cfg(feature = "contract")]
fn parse(doc_json: &Bytes) -> Result<perch_ir::PolicyDoc, DocCompilerError> {
    let mut buf = alloc::vec![0u8; doc_json.len() as usize];
    doc_json.copy_into_slice(&mut buf);
    let json = core::str::from_utf8(&buf).map_err(|_| DocCompilerError::DocNotUtf8)?;
    // Anything not understood is an error, never a skip.
    perch_ir::from_json(json).map_err(|_| DocCompilerError::DocParse)
}

/// Validate, network-bind, cap, lower, canonicalize, and fingerprint a parsed
/// document. Shared by `compile_doc` and `derive_target`, so a derived target
/// passes exactly the checks an applied document does.
#[cfg(feature = "contract")]
fn compile_parsed(e: &Env, doc: &perch_ir::PolicyDoc) -> Result<CompiledDoc, DocCompilerError> {
    perch_ir::validate(doc).map_err(|_| DocCompilerError::DocInvalid)?;

    // Network binding.
    let net = doc.network.as_ref().ok_or(DocCompilerError::WrongNetwork)?;
    let named: BytesN<32> = e
        .crypto()
        .sha256(&Bytes::from_slice(e, net.as_bytes()))
        .to_bytes();
    if named != e.ledger().network_id() {
        return Err(DocCompilerError::WrongNetwork);
    }

    if doc.signers.len() > MAX_DOC_SIGNERS as usize
        || doc.rules.len() > MAX_DOC_RULES as usize
        || doc
            .rules
            .iter()
            .any(|r| r.name.len() > MAX_RULE_NAME_BYTES as usize)
    {
        return Err(DocCompilerError::DocTooLarge);
    }

    // Compile. The config's wasm-hash pin is advisory metadata for
    // off-chain plans; on-chain the account resolves the interpreter itself
    // through its pinned stateless registry (fetch hash → derive address),
    // so this hash is unused here.
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
    };
    let plan = compile(e, doc, &cfg).map_err(|_| DocCompilerError::DocCompile)?;

    let mut rules: Vec<CompiledRule> = Vec::new(e);
    for rule in plan.rules.iter() {
        rules.push_back(to_compiled(e, rule)?);
    }

    let canonical_text = perch_ir::canonical_json(doc);
    if canonical_text.len() > MAX_DOC_CANONICAL_BYTES as usize {
        return Err(DocCompilerError::DocTooLarge);
    }
    let canonical = Bytes::from_slice(e, canonical_text.as_bytes());
    let doc_hash: BytesN<32> = e.crypto().sha256(&canonical).to_bytes();

    let mut recovery: Vec<CompiledRecoveryConfig> = Vec::new(e);
    if let Some(r) = &doc.recovery {
        recovery.push_back(to_compiled_recovery(e, r)?);
    }

    Ok(CompiledDoc {
        doc_hash,
        canonical,
        fingerprints: fingerprints(e, &canonical_credentials(e, &doc.signers)?)?,
        rules,
        recovery,
    })
}

/// The credentials `signers` declare, with every external key canonicalized
/// by its verifier (one batch call per verifier, the call OZ's duplicate
/// signer check makes), so a revoked key cannot return under another
/// encoding of the same key (spec §8).
#[cfg(feature = "contract")]
fn canonical_credentials(
    e: &Env,
    signers: &[perch_ir::SignerDecl],
) -> Result<Vec<Credential>, DocCompilerError> {
    // Batch external keys by verifier, remembering each signer's slot.
    let mut batches: Map<Address, Vec<Val>> = Map::new(e);
    let mut slots: alloc::vec::Vec<(Address, Option<u32>)> = alloc::vec::Vec::new();
    for s in signers {
        match &s.method {
            perch_ir::SignerMethod::Delegated { address } => {
                slots.push((Address::from_str(e, address), None));
            }
            perch_ir::SignerMethod::External { verifier, key } => {
                let verifier = Address::from_str(e, verifier);
                let mut batch = batches.get(verifier.clone()).unwrap_or(Vec::new(e));
                slots.push((verifier.clone(), Some(batch.len())));
                batch.push_back(hex_bytes(e, key)?.into_val(e));
                batches.set(verifier, batch);
            }
        }
    }
    let mut canonical: Map<Address, Vec<Bytes>> = Map::new(e);
    for (verifier, batch) in batches.iter() {
        let keys = KeyCanonicalizerClient::new(e, &verifier)
            .try_batch_canonicalize_key(&batch)
            .map_err(|_| DocCompilerError::KeyNotCanonicalizable)?
            .map_err(|_| DocCompilerError::KeyNotCanonicalizable)?;
        if keys.len() != batch.len() {
            return Err(DocCompilerError::KeyNotCanonicalizable);
        }
        canonical.set(verifier, keys);
    }
    let mut out = Vec::new(e);
    for (address, slot) in slots {
        out.push_back(match slot {
            None => Credential::Delegated(address),
            Some(i) => {
                let key = canonical
                    .get(address.clone())
                    .and_then(|keys| keys.get(i))
                    .ok_or(DocCompilerError::KeyNotCanonicalizable)?;
                Credential::External(address, key)
            }
        });
    }
    Ok(out)
}

/// The fingerprint of each credential (what revocation compares).
#[cfg(feature = "contract")]
fn fingerprints(
    e: &Env,
    credentials: &Vec<Credential>,
) -> Result<Vec<BytesN<32>>, DocCompilerError> {
    let mut out = Vec::new(e);
    for c in credentials.iter() {
        out.push_back(c.fingerprint(e).map_err(|_| DocCompilerError::DocInvalid)?);
    }
    Ok(out)
}

/// A soroban `String` as an owned Rust string (signer ids are validated
/// UTF-8 by `perch_ir` once the target is re-validated).
#[cfg(feature = "contract")]
fn to_std_string(s: &String) -> alloc::string::String {
    let mut buf = alloc::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    alloc::string::String::from_utf8_lossy(&buf).into_owned()
}

/// The document spelling of a replacement credential: strkeys and lowercase
/// hex, exactly what `perch_ir` validates and canonicalizes.
#[cfg(feature = "contract")]
fn to_signer_method(c: &Credential) -> perch_ir::SignerMethod {
    match c {
        Credential::Delegated(address) => perch_ir::SignerMethod::Delegated {
            address: to_std_string(&address.to_string()),
        },
        Credential::External(verifier, key) => {
            let mut raw = alloc::vec![0u8; key.len() as usize];
            key.copy_into_slice(&mut raw);
            perch_ir::SignerMethod::External {
                verifier: to_std_string(&verifier.to_string()),
                key: hex::encode(raw),
            }
        }
    }
}

/// Lower a validated [`perch_ir::RecoveryConfig`] to its wire form, with its
/// `config_hash` (spec §3.2). Precondition: `perch_ir::validate` accepted the
/// document, so every address is shape-valid and every hex field is 32
/// bytes; the decodes below still fail closed.
#[cfg(feature = "contract")]
fn to_compiled_recovery(
    e: &Env,
    r: &perch_ir::RecoveryConfig,
) -> Result<CompiledRecoveryConfig, DocCompilerError> {
    let profile = match r.profile {
        perch_ir::RecoveryProfile::Loss => RecoveryProfile::Loss,
        perch_ir::RecoveryProfile::Protected => RecoveryProfile::Protected,
    };
    let mode = match &r.mode {
        perch_ir::RecoveryMode::GuardianOnly(g) => {
            CompiledRecoveryMode::GuardianOnly(to_compiled_guardian_set(e, g))
        }
        perch_ir::RecoveryMode::ZkOnly(z) => CompiledRecoveryMode::ZkOnly(to_compiled_zk(e, z)?),
        perch_ir::RecoveryMode::Combined(g, z) => {
            CompiledRecoveryMode::Combined(to_compiled_guardian_set(e, g), to_compiled_zk(e, z)?)
        }
    };
    let baseline = match &r.baseline {
        Some(b) => Some(hex_bytes_32(e, &b.doc_hash)?),
        None => None,
    };
    let mut replaceable: Vec<String> = Vec::new(e);
    for id in &r.replaceable {
        replaceable.push_back(String::from_str(e, id));
    }
    let canonical = Bytes::from_slice(e, perch_ir::recovery_canonical_json(r).as_bytes());
    Ok(CompiledRecoveryConfig {
        config_hash: config::config_hash(e, &canonical),
        profile,
        mode,
        controller: Address::from_str(e, &r.controller),
        baseline,
        replaceable,
        delay_ledgers: r.delay_ledgers,
        expiry_ledgers: r.expiry_ledgers,
        max_cancels: r.max_cancels,
    })
}

#[cfg(feature = "contract")]
fn to_compiled_guardian_set(e: &Env, g: &perch_ir::GuardianSet) -> CompiledGuardianSet {
    let mut guardians: Vec<Address> = Vec::new(e);
    for addr in &g.guardians {
        guardians.push_back(Address::from_str(e, addr));
    }
    CompiledGuardianSet {
        guardians,
        quorum: g.quorum,
    }
}

#[cfg(feature = "contract")]
fn to_compiled_zk(e: &Env, z: &perch_ir::ZkFactor) -> Result<CompiledZkFactor, DocCompilerError> {
    Ok(CompiledZkFactor {
        adapter: Address::from_str(e, &z.adapter),
        circuit_id: hex_bytes_32(e, &z.circuit_id)?,
        pool: Address::from_str(e, &z.pool),
        enrollment_id: hex_bytes_32(e, &z.enrollment_id)?,
        commitment: hex_bytes_32(e, &z.commitment)?,
    })
}

/// Lowered rule (host-independent strings) → wire rule (resolved soroban
/// types).
#[cfg(feature = "contract")]
fn to_compiled(e: &Env, rule: &LoweredRule) -> Result<CompiledRule, DocCompilerError> {
    let scope = match &rule.scope {
        ScopeSpec::SelfAdmin => RuleScope::SelfAdmin,
        ScopeSpec::Contract(addr) => RuleScope::Contract(Address::from_str(e, addr)),
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
    let mut install: Vec<InstallParams> = Vec::new(e);
    if let Some(params) = &rule.install {
        install.push_back(params.clone());
    }
    let mut cap: Vec<CompiledCap> = Vec::new(e);
    if let Some(c) = &rule.cap {
        cap.push_back(CompiledCap {
            spending_limit: c.limit,
            period_ledgers: c.period_ledgers,
        });
    }
    Ok(CompiledRule {
        name: String::from_str(e, &rule.name),
        scope,
        signers,
        valid_until: rule.valid_until,
        install,
        cap,
    })
}

/// Decode a validated hex key. Validation already guarantees hex; still fail
/// closed here rather than trust it.
#[cfg(feature = "contract")]
fn hex_bytes(e: &Env, s: &str) -> Result<Bytes, DocCompilerError> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(DocCompilerError::DocInvalid);
    }
    let nib = |c: u8| -> Result<u8, DocCompilerError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DocCompilerError::DocInvalid),
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

/// Decode a validated 64-hex-character string (a SHA-256 digest, e.g. a
/// recovery baseline's `doc-hash`) into fixed 32 bytes. Validation already
/// guarantees the length and hex-ness; still fail closed here rather than
/// trust it.
#[cfg(feature = "contract")]
fn hex_bytes_32(e: &Env, s: &str) -> Result<BytesN<32>, DocCompilerError> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(DocCompilerError::DocInvalid);
    }
    let nib = |c: u8| -> Result<u8, DocCompilerError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DocCompilerError::DocInvalid),
        }
    };
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Ok(BytesN::from_array(e, &out))
}
