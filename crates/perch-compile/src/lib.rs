//! Lowering from `perch_ir::PolicyDoc` to an executable [`Plan`] — the ordered
//! set of OZ smart-account rules a document becomes, each either policy-free or
//! carrying an interpreter program.
//!
//! Two invariants are the security core of this crate:
//!
//! - **INV-1 (signer sufficiency).** In OZ, attaching any policy to a rule
//!   defers signer-sufficiency checking entirely to the policies, so
//!   `matched_signers` may be empty. Every lowered rule must fail a
//!   zero-signature authorization. Mechanism: a policy-free rule relies on OZ's
//!   native all-signers-must-match; an interpreter-attached rule folds
//!   `MinSigners(n>=1)` into its program.
//! - **INV-2 (liveness).** A constraint-free rule (no function/arg limits)
//!   lowers *policy-free*, so it rides OZ's independently audited signer check
//!   instead of the shared interpreter — a deny-bug in the interpreter can
//!   never brick an account's admin path.
//!
//! Rule expiry lowers to OZ's native `valid_until` (a ledger sequence),
//! enforced before any policy runs; in-program ledger ops are reserved for
//! windows within a live rule.
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/7>

use perch_ir::{ArgPred, PolicyDoc, Principals, Rule, Scope};
use perch_program::{rpn, InstallParams, Op, RpnProgram, ValidationError, PROGRAM_VERSION};
use soroban_sdk::{BytesN, Env, String as SString, Symbol, Vec as SVec};

/// Where a lowered rule applies. `SelfAdmin` is account-agnostic — the applier
/// resolves it to the account's own address at apply time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeSpec {
    Contract(String),
    SelfAdmin,
}

/// A signer on a lowered rule. perch-ir only declares external signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSpec {
    pub verifier: String,
    pub key_hex: String,
}

/// One OZ context rule the document lowers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoweredRule {
    pub name: String,
    pub scope: ScopeSpec,
    pub signers: Vec<SignerSpec>,
    /// From `not-after-ledger`; lowers to OZ `valid_until`.
    pub valid_until: Option<u32>,
    /// `Some` → attach the interpreter with these params; `None` → policy-free
    /// (INV-2), OZ enforces all-signers-must-match natively.
    pub install: Option<InstallParams>,
}

/// The lowered document: the rules plus the pinned interpreter wasm hash
/// (present iff any rule attaches the interpreter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub rules: Vec<LoweredRule>,
    pub interpreter_wasm_hash: Option<BytesN<32>>,
}

/// Configuration the compiler needs beyond the document.
pub struct CompileConfig {
    /// The interpreter contract's wasm hash — pinned into the plan so the
    /// interpreter address is derivable (registry id + this hash).
    pub interpreter_wasm_hash: BytesN<32>,
}

/// Anything a document can express that v1 cannot lower is a typed error rather
/// than a silently degraded rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerError {
    /// A rule references a signer id not declared in `doc.signers`.
    UnknownSignerRef { rule: String, id: String },
    /// A rule shape v1 cannot express (e.g. self-authenticating — needs a
    /// policy-call op the frozen v1 program set does not have).
    Unsupported { rule: String, reason: &'static str },
    /// The lowered program failed structural validation.
    InvalidProgram { rule: String, err: ValidationError },
}

/// Lower a validated document. Precondition: `perch_ir::validate(doc).is_ok()`.
pub fn compile(env: &Env, doc: &PolicyDoc, cfg: &CompileConfig) -> Result<Plan, LowerError> {
    let doc_hash = BytesN::from_array(env, &perch_ir::doc_hash(doc));
    let mut rules = Vec::with_capacity(doc.rules.len());
    let mut any_interpreter = false;

    for rule in &doc.rules {
        let lowered = lower_rule(env, doc, rule, &doc_hash)?;
        if lowered.install.is_some() {
            any_interpreter = true;
        }
        rules.push(lowered);
    }

    Ok(Plan {
        rules,
        interpreter_wasm_hash: any_interpreter.then(|| cfg.interpreter_wasm_hash.clone()),
    })
}

fn lower_rule(
    env: &Env,
    doc: &PolicyDoc,
    rule: &Rule,
    doc_hash: &BytesN<32>,
) -> Result<LoweredRule, LowerError> {
    let scope = match &rule.scope {
        Scope::Contract(c) => ScopeSpec::Contract(c.address.clone()),
        Scope::SelfAdmin(_) => ScopeSpec::SelfAdmin,
    };

    // Resolve the referenced signer ids to their declared verifier + key.
    let signer_ids: &[String] = match &rule.principals {
        Principals::All(all) => &all.signers,
        Principals::SelfAuthenticating(_) => {
            return Err(LowerError::Unsupported {
                rule: rule.name.clone(),
                reason: "self-authenticating rules need a policy-call op not in program v1",
            });
        }
    };
    let mut signers = Vec::with_capacity(signer_ids.len());
    for id in signer_ids {
        let decl = doc.signers.iter().find(|s| &s.id == id).ok_or_else(|| {
            LowerError::UnknownSignerRef {
                rule: rule.name.clone(),
                id: id.clone(),
            }
        })?;
        signers.push(SignerSpec {
            verifier: decl.verifier.clone(),
            key_hex: decl.key.clone(),
        });
    }

    // INV-2: a constraint-free All-rule lowers policy-free.
    let constraint_free = rule.functions.is_none() && rule.args.is_none();
    let install = if constraint_free {
        None
    } else {
        let program = build_program(env, rule, signer_ids.len() as u32)?;
        Some(InstallParams {
            program,
            doc_hash: doc_hash.clone(),
        })
    };

    Ok(LoweredRule {
        name: rule.name.clone(),
        scope,
        signers,
        valid_until: rule.not_after_ledger,
        install,
    })
}

/// Build the interpreter program for a constrained rule: `All(` MinSigners(n) +
/// the function allowlist + each argument predicate `)`.
fn build_program(env: &Env, rule: &Rule, signer_count: u32) -> Result<RpnProgram, LowerError> {
    let mut ops: SVec<Op> = SVec::new(env);

    // INV-1: a constrained (interpreter-attached) rule must fail zero-signature
    // auth. n>=1 because an All-rule always references at least one signer
    // (perch-ir validation rejects empty principals).
    ops.push_back(Op::MinSigners(signer_count.max(1)));
    let mut leaves = 1u32;

    if let Some(funcs) = &rule.functions {
        let mut syms: SVec<Symbol> = SVec::new(env);
        for f in funcs {
            syms.push_back(Symbol::new(env, f));
        }
        ops.push_back(Op::FnIn(syms));
        leaves += 1;
    }

    if let Some(args) = &rule.args {
        for c in args {
            ops.push_back(lower_arg_pred(env, c.index, &c.pred));
            leaves += 1;
        }
    }

    ops.push_back(Op::All(leaves));

    let program = RpnProgram {
        version: PROGRAM_VERSION,
        ops,
    };
    rpn::validate(&program).map_err(|err| LowerError::InvalidProgram {
        rule: rule.name.clone(),
        err,
    })?;
    Ok(program)
}

fn lower_arg_pred(env: &Env, index: u32, pred: &ArgPred) -> Op {
    match pred {
        ArgPred::IsSelf(_) => Op::ArgAddrIsSelf(index),
        ArgPred::AddressEq(p) => {
            Op::ArgAddrEq(index, soroban_sdk::Address::from_str(env, &p.address))
        }
        ArgPred::U32Eq(p) => Op::ArgU32Eq(index, p.value),
        ArgPred::StringIn(p) => {
            let mut set: SVec<SString> = SVec::new(env);
            for v in &p.values {
                set.push_back(SString::from_str(env, v));
            }
            Op::ArgStrIn(index, set)
        }
        ArgPred::StringPrefix(p) => Op::ArgStrPrefix(index, SString::from_str(env, &p.prefix)),
    }
}

#[cfg(test)]
mod tests;
