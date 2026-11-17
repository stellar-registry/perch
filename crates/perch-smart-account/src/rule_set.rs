//! The account's rule sets as rule-core's evaluator reads them.
//!
//! `apply_doc` lowers the compiled admin document's model with
//! `rule_eval::lower`, and `apply_scope` a scoped document's with
//! `rule_eval::lower_scoped` under the account's excluded set and the current
//! scope generation. Each drops the rules `rules::desired` drops as expired
//! and stores the rest as `perch_rule_eval::StoredRule`s, aligned with the
//! records the document installs: the stored rule at index `i` is what the
//! installed rule at index `i` enforces, the admin document's recovery rule
//! last when there is one. The constructor stores its admin rule the same
//! way. `__check_auth` evaluates the rules a payload chooses with
//! `rule_eval::authorize` after OZ (`gate`).

use perch_doc_compiler::CompiledDoc;
use perch_rule_eval::convert::Addresses;
use perch_rule_eval::{
    admin_survives, doc_of_in, guarded, CompiledModel, StoredFunctions, StoredRule,
};
use soroban_sdk::{Address, Env, Vec};
use stellar_accounts::smart_account::Signer;

use crate::{rules, PerchAccountError};

/// The compiled document's one model, if it matches the compiled rules and
/// recovery one for one.
fn model(compiled: &CompiledDoc) -> Result<CompiledModel, PerchAccountError> {
    if compiled.model.len() != 1 {
        return Err(PerchAccountError::ModelInvalid);
    }
    let model = compiled.model.get_unchecked(0);
    if model.rules.len() != compiled.rules.len() || model.recovery.len() != compiled.recovery.len()
    {
        return Err(PerchAccountError::ModelInvalid);
    }
    Ok(model)
}

/// `lowered` (one rule per compiled document rule, then any recovery rule)
/// less the document rules `rules::desired` drops as expired. Refuses a
/// document rule that asks for no signer (INV-1).
fn kept(
    e: &Env,
    compiled: &CompiledDoc,
    lowered: alloc::vec::Vec<rule_eval::Rule>,
) -> Result<alloc::vec::Vec<rule_eval::Rule>, PerchAccountError> {
    let documented = compiled.rules.len() as usize;
    let mut kept = alloc::vec::Vec::new();
    for (i, rule) in lowered.into_iter().enumerate() {
        if i < documented {
            if rules::expired(e, compiled.rules.get_unchecked(i as u32).valid_until) {
                continue;
            }
            if !guarded(&rule) {
                return Err(PerchAccountError::UnguardedRule);
            }
        }
        kept.push(rule);
    }
    Ok(kept)
}

/// `rules` as stored, every address converted back from `known`.
fn stored(
    e: &Env,
    rules: &[rule_eval::Rule],
    known: &Addresses,
) -> Result<Vec<StoredRule>, PerchAccountError> {
    let mut out = Vec::new(e);
    for rule in rules {
        out.push_back(
            StoredRule::from_rule_in(e, rule, known).ok_or(PerchAccountError::ModelInvalid)?,
        );
    }
    Ok(out)
}

/// The rule set the admin document `compiled` asks for on this account, as
/// stored.
///
/// Refuses with `ModelInvalid` when the compiled document carries no model
/// (or more than one), a model soroban-facade cannot read, or one whose
/// rules or recovery do not match the compiled document's one for one; with
/// `UnguardedRule` when a rule other than the recovery rule asks for no
/// signer (INV-1); and with `AdminLockout` when no rule lets its signers
/// manage the account unconditionally and for good.
pub(crate) fn lowered(
    e: &Env,
    compiled: &CompiledDoc,
) -> Result<Vec<StoredRule>, PerchAccountError> {
    let model = model(compiled)?;
    // Every address a lowered rule holds is the account's or one the model
    // names, so the rules convert back to host values by lookup.
    let mut known = Addresses::default();
    let me = known
        .read(e, &e.current_contract_address())
        .ok_or(PerchAccountError::ModelInvalid)?;
    let doc = doc_of_in(e, &model, &mut known).ok_or(PerchAccountError::ModelInvalid)?;
    let kept = kept(e, compiled, rule_eval::lower(&doc, &me))?;
    if !admin_survives(&kept, &me) {
        return Err(PerchAccountError::AdminLockout);
    }
    stored(e, &kept, &known)
}

/// The rule set the scoped document `compiled` asks for on this account
/// under the scope generation `gen`, as stored: every rule carries `gen`.
/// `excluded` is the account's excluded set beyond the account itself: its
/// adopted recovery controller and its ZK factor's adapter and pool.
///
/// Refuses with `ModelInvalid` as [`lowered`] does, with `ScopeEscalation`
/// when rule-eval's scoped lowering refuses the document (a recovery member,
/// or a rule on the account or a contract of the excluded set), and with
/// `UnguardedRule` when a rule asks for no signer (INV-1).
pub(crate) fn lowered_scoped(
    e: &Env,
    compiled: &CompiledDoc,
    excluded: &[Address],
    gen: u64,
) -> Result<Vec<StoredRule>, PerchAccountError> {
    let model = model(compiled)?;
    let mut known = Addresses::default();
    let me = known
        .read(e, &e.current_contract_address())
        .ok_or(PerchAccountError::ModelInvalid)?;
    let mut set = alloc::vec![me.clone()];
    for a in excluded {
        set.push(known.read(e, a).ok_or(PerchAccountError::ModelInvalid)?);
    }
    let doc = doc_of_in(e, &model, &mut known).ok_or(PerchAccountError::ModelInvalid)?;
    let lowered = rule_eval::lower_scoped(&doc, &me, &set, gen)
        .map_err(|_| PerchAccountError::ScopeEscalation)?;
    stored(e, &kept(e, compiled, lowered)?, &known)
}

/// The constructor's admin rule, as stored: every function of the account,
/// no condition, no cap, no last ledger, and every signer required.
pub(crate) fn admin(e: &Env, signers: &Vec<Signer>) -> StoredRule {
    StoredRule {
        contract: e.current_contract_address(),
        functions: StoredFunctions::AnyExcept(Vec::new(e)),
        conds: Vec::new(e),
        signers: signers.clone(),
        threshold: signers.len(),
        cap: Vec::new(e),
        valid_until: None,
        generation: None,
    }
}
