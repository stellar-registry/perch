//! What Perch's RPN lowering (`perch_compile::compile`) gives a document's
//! rules: the interpreter program and the spending limit's parameters an
//! account upgraded from code that attached those two policies holds for
//! each rule until its first `apply_doc`.
//!
//! [`policies`] reads them off a canonical document. The rule-set check
//! (`rule_set`) compares the account's stored rule-eval rules with their
//! denotation (`denote`), and tests build such an upgraded
//! account from them. [`check_compiled`] checks the doc compiler's rules
//! against the same lowering.

use perch_account_types::Signer;
use perch_compile::{CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
use perch_doc_compiler::{CompiledDoc, RuleScope};
use perch_program::InstallParams;
use soroban_sdk::{Address, Bytes, BytesN, Env};
use std::format;
use std::string::String;
use std::vec::Vec;
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

/// One document rule as the RPN lowering attaches it.
#[derive(Clone, Debug)]
pub struct Policies {
    pub name: String,
    pub valid_until: Option<u32>,
    /// The interpreter's program, `None` for a constraint-free rule.
    pub install: Option<InstallParams>,
    /// The spending limit's parameters, for a capped rule.
    pub cap: Option<SpendingLimitAccountParams>,
}

/// The validated document `canonical` holds.
pub fn doc(canonical: &Bytes) -> Result<perch_ir::PolicyDoc, String> {
    let mut bytes = std::vec![0u8; canonical.len() as usize];
    canonical.copy_into_slice(&mut bytes);
    let json = core::str::from_utf8(&bytes).map_err(|x| format!("document: {x}"))?;
    let doc = perch_ir::from_json(json).map_err(|x| format!("document: {x:?}"))?;
    perch_ir::validate(&doc).map_err(|x| format!("document: {x:?}"))?;
    Ok(doc)
}

fn lowered(e: &Env, doc: &perch_ir::PolicyDoc) -> Result<Vec<LoweredRule>, String> {
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(e, &[0u8; 32]),
    };
    Ok(perch_compile::compile(e, doc, &cfg)
        .map_err(|x| format!("perch_compile::compile: {x:?}"))?
        .rules)
}

/// Each rule of `doc`, in order, as the RPN lowering attaches it.
pub fn policies_of(e: &Env, doc: &perch_ir::PolicyDoc) -> Result<Vec<Policies>, String> {
    Ok(lowered(e, doc)?
        .into_iter()
        .map(|r| Policies {
            name: r.name,
            valid_until: r.valid_until,
            install: r.install,
            cap: r.cap.map(|c| SpendingLimitAccountParams {
                spending_limit: c.limit,
                period_ledgers: c.period_ledgers,
            }),
        })
        .collect())
}

/// [`policies_of`] the document `canonical` holds.
pub fn policies(e: &Env, canonical: &Bytes) -> Result<Vec<Policies>, String> {
    policies_of(e, &doc(canonical)?)
}

/// The doc compiler's rules for `doc` equal the RPN lowering's one for one:
/// the same name, scope, signers in the same order, and last ledger.
pub fn check_compiled(
    e: &Env,
    doc: &perch_ir::PolicyDoc,
    compiled: &CompiledDoc,
) -> Result<(), String> {
    let lowered = lowered(e, doc)?;
    if lowered.len() != compiled.rules.len() as usize {
        return Err(format!(
            "the compiler emits {} rules, the RPN lowering {}",
            compiled.rules.len(),
            lowered.len()
        ));
    }
    for (i, (l, c)) in lowered.iter().zip(compiled.rules.iter()).enumerate() {
        let scope = match &l.scope {
            ScopeSpec::SelfAdmin => RuleScope::SelfAdmin,
            ScopeSpec::Contract(a) => RuleScope::Contract(Address::from_str(e, a)),
        };
        let mut signers = soroban_sdk::Vec::new(e);
        for s in &l.signers {
            signers.push_back(match s {
                SignerSpec::Delegated { address } => {
                    Signer::Delegated(Address::from_str(e, address))
                }
                SignerSpec::External { verifier, key_hex } => Signer::External(
                    Address::from_str(e, verifier),
                    Bytes::from_slice(e, &hex::decode(key_hex).map_err(|x| format!("{x}"))?),
                ),
            });
        }
        if c.name != soroban_sdk::String::from_str(e, &l.name)
            || c.scope != scope
            || c.signers != signers
            || c.valid_until != l.valid_until
        {
            return Err(format!(
                "rule {i}: the compiler emits {c:?}, the RPN lowering {l:?}"
            ));
        }
    }
    Ok(())
}
