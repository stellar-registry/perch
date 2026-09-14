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
use soroban_sdk::{contractclient, contracttype, Address, Bytes, BytesN, Env, String, Vec};
use soroban_sdk_tools::scerr;
use stellar_accounts::smart_account::Signer;

#[cfg(feature = "contract")]
use perch_compile::{compile, CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
#[cfg(feature = "contract")]
use soroban_sdk::{contract, contractimpl};

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
    /// Zero or one entries — a `Vec` rather than `Option` because
    /// `Option<contracttype>` cannot cross the ScVal boundary that testutils
    /// clients use. Empty ⇒ policy-free rule.
    pub install: Vec<InstallParams>,
    /// Zero or one entries (a `Vec` for the same ScVal reason as `install`).
    /// Present ⇒ also attach OZ `spending_limit` with these params — the
    /// cumulative cap the stateless interpreter cannot express. The applier
    /// resolves the policy's content-addressed address and keys it into the
    /// rule's policy map beside the interpreter; the tracked token is the rule's
    /// `Contract` scope (validation pins `token == scope`).
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
    pub rules: Vec<CompiledRule>,
    /// Zero or one entries (a `Vec` for the same ScVal reason as
    /// [`CompiledRule::install`]). Present ⇒ the document enrolls account
    /// recovery — the applier is expected to sync this configuration to the
    /// adopted recovery-controller instance named in it. See
    /// `docs/recovery/` for the full design; wire-compat notes live there too
    /// (this is a new field on an existing constructorless, immutable
    /// deployable — a compiler build carrying it is a new instance, not an
    /// in-place change to any already-deployed one).
    pub recovery: Vec<CompiledRecoveryConfig>,
}

/// Wire form of [`perch_ir::RecoveryConfig`]: resolved addresses and decoded
/// bytes, exactly as [`CompiledRule`] is to [`perch_ir::Rule`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledRecoveryConfig {
    pub profile: RecoveryProfile,
    pub mode: CompiledRecoveryMode,
    pub controller: Address,
    /// Zero or one entries (a `Vec` for the same ScVal reason as
    /// [`CompiledRule::install`]). Present ⇒ suspected-compromise recovery is
    /// enrolled, restoring the document this hash names.
    pub baseline: Vec<BytesN<32>>,
    /// Fingerprint of each replaceable signer's *physical credential*
    /// (`sha256` of a tagged encoding of its `SignerMethod` — verifier+key for
    /// `external`, the address for `delegated`), resolved from
    /// `doc.signers` at compile time — not the document-local signer id
    /// string. Revocation must survive the id being reused for a different
    /// physical key in a later document, so the controller tracks the
    /// credential itself.
    pub replaceable: Vec<BytesN<32>>,
    pub delay_ledgers: u32,
    pub expiry_ledgers: u32,
    pub max_cancels: u32,
    pub pending_activity: PendingActivityPolicy,
}

/// Wire form of [`perch_ir::RecoveryProfile`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryProfile {
    Loss,
    Protected,
}

/// Wire form of [`perch_ir::PendingActivityPolicy`]. No default, same as the
/// document-level type — see its doc comment.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum PendingActivityPolicy {
    Freeze,
    Continue,
}

/// Wire form of [`perch_ir::RecoveryMode`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum CompiledRecoveryMode {
    GuardianOnly(CompiledGuardianSet),
    ZkOnly(CompiledZkVerifierConfig),
    Combined(CompiledGuardianSet, CompiledZkVerifierConfig),
}

/// Wire form of [`perch_ir::GuardianSet`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledGuardianSet {
    pub guardians: Vec<Address>,
    pub quorum: u32,
}

/// Wire form of [`perch_ir::ZkVerifierConfig`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledZkVerifierConfig {
    pub verifier: Address,
    /// Decoded from the document's hex `circuit-id`.
    pub circuit_id: Bytes,
    /// Zero or one entries (a `Vec` for the same ScVal reason as
    /// [`CompiledRule::install`]).
    pub pool: Vec<Address>,
}

/// Cross-contract client, generated independently of the deployable so
/// consumers (smart accounts) link no compiler code at all — the account's
/// wasm carries neither the JSON parser nor the lowering logic.
#[allow(unused)]
#[contractclient(name = "DocCompilerClient")]
trait DocCompilerClientInterface {
    fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError>;
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
        // Bytes → str, fail closed.
        let mut buf = alloc::vec![0u8; doc_json.len() as usize];
        doc_json.copy_into_slice(&mut buf);
        let json = core::str::from_utf8(&buf).map_err(|_| DocCompilerError::DocNotUtf8)?;

        // Parse + validate — anything not understood is an error, never a skip.
        let doc = perch_ir::from_json(json).map_err(|_| DocCompilerError::DocParse)?;
        perch_ir::validate(&doc).map_err(|_| DocCompilerError::DocInvalid)?;

        // Network binding.
        let net = doc.network.as_ref().ok_or(DocCompilerError::WrongNetwork)?;
        let named: BytesN<32> = e
            .crypto()
            .sha256(&Bytes::from_slice(e, net.as_bytes()))
            .to_bytes();
        if named != e.ledger().network_id() {
            return Err(DocCompilerError::WrongNetwork);
        }

        // Compile. The config's wasm-hash pin is advisory metadata for
        // off-chain plans; on-chain the account resolves the interpreter itself
        // through its pinned stateless registry (fetch hash → derive address),
        // so this hash is unused here.
        let cfg = CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
        };
        let plan = compile(e, &doc, &cfg).map_err(|_| DocCompilerError::DocCompile)?;

        let mut rules: Vec<CompiledRule> = Vec::new(e);
        for rule in plan.rules.iter() {
            rules.push_back(to_compiled(e, rule)?);
        }

        let canonical = perch_ir::canonical_json(&doc);
        let doc_hash: BytesN<32> = e
            .crypto()
            .sha256(&Bytes::from_slice(e, canonical.as_bytes()))
            .to_bytes();

        let mut recovery: Vec<CompiledRecoveryConfig> = Vec::new(e);
        if let Some(r) = &doc.recovery {
            recovery.push_back(to_compiled_recovery(e, &doc, r)?);
        }

        Ok(CompiledDoc {
            doc_hash,
            rules,
            recovery,
        })
    }
}

/// Lower a validated [`perch_ir::RecoveryConfig`] to its wire form.
/// Precondition: `perch_ir::validate(doc).is_ok()` (guaranteed by the one
/// caller, [`PerchDocCompiler::compile_doc`]) — every address is shape-valid
/// and `circuit_id`/baseline `doc_hash` are valid hex of the expected length,
/// so the decodes below cannot fail on a document that reached this point.
#[cfg(feature = "contract")]
fn to_compiled_recovery(
    e: &Env,
    doc: &perch_ir::PolicyDoc,
    r: &perch_ir::RecoveryConfig,
) -> Result<CompiledRecoveryConfig, DocCompilerError> {
    let profile = match r.profile {
        perch_ir::RecoveryProfile::Loss => RecoveryProfile::Loss,
        perch_ir::RecoveryProfile::Protected => RecoveryProfile::Protected,
    };
    let pending_activity = match r.pending_activity {
        perch_ir::PendingActivityPolicy::Freeze => PendingActivityPolicy::Freeze,
        perch_ir::PendingActivityPolicy::Continue => PendingActivityPolicy::Continue,
    };
    let mode = match &r.mode {
        perch_ir::RecoveryMode::GuardianOnly(g) => {
            CompiledRecoveryMode::GuardianOnly(to_compiled_guardian_set(e, g))
        }
        perch_ir::RecoveryMode::ZkOnly(z) => {
            CompiledRecoveryMode::ZkOnly(to_compiled_zk_verifier_config(e, z)?)
        }
        perch_ir::RecoveryMode::Combined(g, z) => CompiledRecoveryMode::Combined(
            to_compiled_guardian_set(e, g),
            to_compiled_zk_verifier_config(e, z)?,
        ),
    };
    let mut baseline: Vec<BytesN<32>> = Vec::new(e);
    if let Some(b) = &r.baseline {
        baseline.push_back(hex_bytes_32(e, &b.doc_hash)?);
    }
    // Precondition (validate(doc).is_ok(), guaranteed by the one caller):
    // every `replaceable` id references a declared signer
    // (`UnknownRecoveryReplaceableRef` would already have failed validation),
    // so `.find` cannot miss here.
    let mut replaceable: Vec<BytesN<32>> = Vec::new(e);
    for id in &r.replaceable {
        let decl = doc
            .signers
            .iter()
            .find(|s| &s.id == id)
            .ok_or(DocCompilerError::DocInvalid)?;
        replaceable.push_back(credential_fingerprint(e, &decl.method));
    }
    Ok(CompiledRecoveryConfig {
        profile,
        mode,
        controller: Address::from_str(e, &r.controller),
        baseline,
        replaceable,
        delay_ledgers: r.delay_ledgers,
        expiry_ledgers: r.expiry_ledgers,
        max_cancels: r.max_cancels,
        pending_activity,
    })
}

/// `sha256` of a tagged encoding of a signer's physical credential — the
/// verifier+decoded-key bytes for `external`, the address for `delegated`.
/// Used only to fingerprint a `replaceable` signer's credential identity,
/// never the document-local id string, so revocation survives that id being
/// reused for a different physical key in a later document.
///
/// `key` is hex-decoded to its physical bytes before hashing — `perch-ir`
/// validation already treats hex casing as insignificant for the same
/// physical key (`crates/perch-ir/src/validate.rs`'s `seen_key_material`
/// keys on decoded bytes, not the spelling), so fingerprinting the raw text
/// instead would let the same credential, re-declared with different hex
/// casing, evade a prior revocation entirely.
#[cfg(feature = "contract")]
fn credential_fingerprint(e: &Env, method: &perch_ir::SignerMethod) -> BytesN<32> {
    let mut buf = alloc::vec::Vec::new();
    match method {
        perch_ir::SignerMethod::External { verifier, key } => {
            buf.extend_from_slice(b"external|");
            buf.extend_from_slice(verifier.as_bytes());
            buf.push(b'|');
            // Already validated hex by the time a document reaches the
            // compiler (`perch_ir::validate`) — decode failure here would
            // mean validation was skipped, not a reachable user input.
            buf.extend_from_slice(&hex::decode(key).unwrap_or_default());
        }
        perch_ir::SignerMethod::Delegated { address } => {
            buf.extend_from_slice(b"delegated|");
            buf.extend_from_slice(address.as_bytes());
        }
    }
    e.crypto().sha256(&Bytes::from_slice(e, &buf)).to_bytes()
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
fn to_compiled_zk_verifier_config(
    e: &Env,
    z: &perch_ir::ZkVerifierConfig,
) -> Result<CompiledZkVerifierConfig, DocCompilerError> {
    let mut pool: Vec<Address> = Vec::new(e);
    if let Some(p) = &z.pool {
        pool.push_back(Address::from_str(e, p));
    }
    Ok(CompiledZkVerifierConfig {
        verifier: Address::from_str(e, &z.verifier),
        circuit_id: hex_bytes(e, &z.circuit_id)?,
        pool,
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
