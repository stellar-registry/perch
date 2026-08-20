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
    /// The document carries a cumulative cap, which needs the `spending_limit`
    /// policy address — not yet compilable for on-chain application.
    CapUnsupported,
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
        // off-chain plans; on-chain the interpreter is bound by the account's
        // admin-authorized argument to `apply_doc`, not by this hash.
        let cfg = CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
        };
        let plan = compile(e, &doc, &cfg).map_err(|_| DocCompilerError::DocCompile)?;

        let mut rules: Vec<CompiledRule> = Vec::new(e);
        for rule in plan.rules.iter() {
            if rule.cap.is_some() {
                return Err(DocCompilerError::CapUnsupported);
            }
            rules.push_back(to_compiled(e, rule)?);
        }

        let canonical = perch_ir::canonical_json(&doc);
        let doc_hash: BytesN<32> = e
            .crypto()
            .sha256(&Bytes::from_slice(e, canonical.as_bytes()))
            .to_bytes();
        Ok(CompiledDoc { doc_hash, rules })
    }
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
    Ok(CompiledRule {
        name: String::from_str(e, &rule.name),
        scope,
        signers,
        valid_until: rule.valid_until,
        install,
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
