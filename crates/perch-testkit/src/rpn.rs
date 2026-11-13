//! What Perch's RPN lowering (`perch_compile::compile`) gives a document's
//! rules: the interpreter program and the spending limit's parameters an
//! account upgraded from code that attached those two policies holds for
//! each rule until its first `apply_doc`.
//!
//! [`policies`] reads them off a canonical document. The rule-set check
//! (`rule_set`) compares the account's stored rule-eval rules with their
//! denotation (`denote`), and tests build such an upgraded
//! account from them. Root-bearing documents are refused by that compiler;
//! [`batch_policies_of`] compares their local projection and composes the
//! original root separately. [`check_compiled`] checks local metadata against
//! that lowering and root metadata against the original document.

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
    /// Independently composed batch condition; never an interpreter policy.
    pub auth_root: Option<perch_ir::AuthRoot>,
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
            auth_root: None,
            valid_until: r.valid_until,
            install: r.install,
            cap: r.cap.map(|c| SpendingLimitAccountParams {
                spending_limit: c.limit,
                period_ledgers: c.period_ledgers,
            }),
        })
        .collect())
}

/// Test-only local-context projection. The legacy compiler refuses roots;
/// this projection checks only its local predicates, never authorization.
pub fn local_projection(doc: &perch_ir::PolicyDoc) -> perch_ir::PolicyDoc {
    let mut local = doc.clone();
    for rule in &mut local.rules {
        rule.auth_root = None;
    }
    local
}

/// Local interpreter predicates composed with the original batch condition.
/// This is comparison evidence, not a legacy installable policy.
pub fn batch_policies_of(e: &Env, doc: &perch_ir::PolicyDoc) -> Result<Vec<Policies>, String> {
    let mut policies = policies_of(e, &local_projection(doc))?;
    for (p, r) in policies.iter_mut().zip(&doc.rules) {
        p.auth_root = r.auth_root.clone();
    }
    Ok(policies)
}

/// Independently encode the document's exact root as a pure batch condition.
pub fn root_of(e: &Env, root: &Option<perch_ir::AuthRoot>) -> Option<rule_eval::AuthRoot> {
    root.as_ref().map(|r| rule_eval::AuthRoot {
        contract: perch_rule_eval::convert::address(e, &Address::from_str(e, &r.contract))
            .expect("validated root contract"),
        function: r.function.as_bytes().to_vec(),
    })
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
    let lowered = lowered(e, &local_projection(doc))?;
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
            || c.auth_root
                != doc.rules[i].auth_root.as_ref().map(|r| {
                    soroban_sdk::Vec::from_array(
                        e,
                        [perch_rule_eval::StoredAuthRoot {
                            contract: Address::from_str(e, &r.contract),
                            function: soroban_sdk::Symbol::new(e, &r.function),
                        }],
                    )
                })
        {
            return Err(format!(
                "rule {i}: the compiler emits {c:?}, the RPN lowering {l:?}"
            ));
        }
    }
    Ok(())
}
