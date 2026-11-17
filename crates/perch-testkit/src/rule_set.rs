//! The account's stored rule-eval rule set (`PerchSmartAccount::rule_set`),
//! checked against the two things it must equal after an apply:
//!
//! - **the lowering**: `rule_eval::lower` of the applied document's model on
//!   the account, less the document rules whose last ledger has passed (the
//!   rules `apply_doc` does not install); before any document, the
//!   constructor's admin rule;
//! - **the installed rules**: for each installed-rule record, in order, the
//!   denotation (`perch_rule_eval::denote`) of what is enforced for it, read
//!   back from where it is enforced: OZ's context rule
//!   (`get_context_rule`: contract, signers in OZ's order, last ledger), the
//!   interpreter's program and the spending limit's parameters for that
//!   rule id. The recovery rule's record must be a zero-signer rule whose one
//!   policy is the adopted controller, and its stored rule rule-eval's
//!   recovery rule.
//!
//! Rules are compared as `StoredRule`s, whose conversion from a
//! `rule_eval::Rule` is one-to-one, so equal mirrors are equal rules.
//!
//! [`check_scope`] checks a scoped document's stored set the same way: the
//! lowering is `rule_eval::lower_scoped` of the scope's model under the
//! generation its record carries, and each denoted rule carries that
//! generation.
//!
//! Run each at the ledger the apply it checks ran at: the lowering's expiry
//! drop is computed at the current ledger.

use perch_account::PerchAccountClient;
use perch_interpreter::PerchInterpreterClient;
use perch_rule_eval::convert::{address, signers};
use perch_rule_eval::{denote, doc_of, model_of, Installed, StoredRule};
use perch_smart_account::infra;
use perch_smart_account::InstalledRule;
use soroban_sdk::{Address, Env};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;
use stellar_accounts::policies::spending_limit::{
    get_spending_limit_data, SpendingLimitAccountParams,
};
use stellar_accounts::smart_account::ContextRuleType;

/// What one [`check`] compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    /// Stored rules, the recovery rule included.
    pub rules: usize,
    /// Installed rules with the interpreter or the spending limit attached.
    pub constrained: usize,
    pub capped: usize,
    pub recovery: bool,
}

fn mirror(e: &Env, r: &rule_eval::Rule, what: &str) -> Result<StoredRule, String> {
    StoredRule::from_rule(e, r).ok_or(format!("{what} has no host form"))
}

/// The rules the lowering of `account`'s applied document gives, less those
/// `apply_doc` drops as expired at the current ledger.
fn lowering(e: &Env, account: &Address, me: &[u8]) -> Result<Vec<StoredRule>, String> {
    let client = PerchAccountClient::new(e, account);
    let Some(canonical) = client.applied_doc() else {
        // The constructor's admin rule.
        let records = client.installed_rules();
        if records.len() != 1 {
            return Err(format!("{} rules and no applied document", records.len()));
        }
        let admin = records.get_unchecked(0);
        let rule = rule_eval::Rule {
            contract: me.to_vec(),
            functions: rule_eval::Functions::AnyExcept(Vec::new()),
            conds: Vec::new(),
            signers: signers(e, &admin.signers).ok_or("the admin's signers")?,
            threshold: admin.signers.len(),
            cap: None,
            valid_until: None,
            generation: None,
        };
        return Ok(std::vec![mirror(e, &rule, "the admin rule")?]);
    };
    let (doc, model) = read_doc(e, &canonical)?;
    unexpired(e, &rule_eval::lower(&model, me), doc.rules.len())
}

/// The canonical document `canonical`, and its model as rule-eval reads it.
fn read_doc(
    e: &Env,
    canonical: &soroban_sdk::Bytes,
) -> Result<(perch_ir::PolicyDoc, rule_eval::Doc), String> {
    let mut bytes = std::vec![0u8; canonical.len() as usize];
    canonical.copy_into_slice(&mut bytes);
    let json = core::str::from_utf8(&bytes).map_err(|x| format!("applied document: {x}"))?;
    let doc = perch_ir::from_json(json).map_err(|x| format!("applied document: {x:?}"))?;
    let model = model_of(e, &doc).map_err(|x| format!("model_of: {x:?}"))?;
    let model = doc_of(e, &model).ok_or("doc_of refuses")?;
    Ok((doc, model))
}

/// `lowered` less the first `documented` rules whose last ledger has passed,
/// as stored.
fn unexpired(
    e: &Env,
    lowered: &[rule_eval::Rule],
    documented: usize,
) -> Result<Vec<StoredRule>, String> {
    let now = e.ledger().sequence();
    let mut out = Vec::new();
    for (i, r) in lowered.iter().enumerate() {
        if i < documented && r.valid_until.is_some_and(|v| v < now) {
            continue;
        }
        out.push(mirror(e, r, &format!("lowered rule {i}"))?);
    }
    Ok(out)
}

/// The stored rule set of `account` equals both the lowering of its applied
/// document and the denotation of its installed rules (module docs).
pub fn check(e: &Env, account: &Address) -> Result<Checked, String> {
    let client = PerchAccountClient::new(e, account);
    let me = address(e, account).ok_or("the account's address")?;
    let stored: Vec<StoredRule> = client.rule_set().iter().collect();
    let records = client.installed_rules();
    let mut checked = Checked {
        rules: stored.len(),
        ..Checked::default()
    };

    let lowered = lowering(e, account, &me)?;
    compare(e, account, &stored, &records, &lowered, None, &mut checked)?;
    Ok(checked)
}

/// The stored rule set of the scoped document under `scope` equals both
/// the scoped lowering of its model and the denotation of the rules its
/// record holds (module docs).
pub fn check_scope(e: &Env, account: &Address, scope: u32) -> Result<Checked, String> {
    let client = PerchAccountClient::new(e, account);
    let me = address(e, account).ok_or("the account's address")?;
    let record = client.scope(&scope).ok_or(format!("no scope {scope}"))?;
    let stored: Vec<StoredRule> = client.scope_rule_set(&scope).iter().collect();
    let canonical = client
        .scope_doc(&scope)
        .ok_or(format!("scope {scope} has no document"))?;
    let (doc, model) = read_doc(e, &canonical)?;
    let mut excluded = std::vec![me.clone()];
    if let Some(c) = client.recovery_controller() {
        excluded.push(address(e, &c).ok_or("the controller's address")?);
    }
    let lowered = rule_eval::lower_scoped(&model, &me, &excluded, record.gen)
        .map_err(|_| format!("scope {scope}: rule-eval's scoped lowering refuses it"))?;
    let lowered = unexpired(e, &lowered, doc.rules.len())?;
    let mut checked = Checked {
        rules: stored.len(),
        ..Checked::default()
    };
    compare(
        e,
        account,
        &stored,
        &record.rules,
        &lowered,
        Some(record.gen),
        &mut checked,
    )?;
    Ok(checked)
}

/// `stored` against `lowered` and against the denotation of each of
/// `records`, read back from OZ and the policies, carrying `generation`.
fn compare(
    e: &Env,
    account: &Address,
    stored: &[StoredRule],
    records: &soroban_sdk::Vec<InstalledRule>,
    lowered: &[StoredRule],
    generation: Option<u64>,
    checked: &mut Checked,
) -> Result<(), String> {
    let client = PerchAccountClient::new(e, account);
    let interpreter = infra::perch_interpreter::address(e);
    let spending_limit = infra::perch_spending_limit::address(e);
    let me = address(e, account).ok_or("the account's address")?;
    if stored.len() != records.len() as usize {
        return Err(format!(
            "{} stored rules for {} installed rules",
            stored.len(),
            records.len()
        ));
    }
    if lowered.len() != stored.len() {
        return Err(format!(
            "{} stored rules, the lowering keeps {}",
            stored.len(),
            lowered.len()
        ));
    }

    for (i, record) in records.iter().enumerate() {
        let oz = client.get_context_rule(&record.id);
        let denoted = if record.recovery {
            let controller = client
                .recovery_controller()
                .ok_or("a recovery rule and no controller")?;
            if !oz.signers.is_empty() || oz.policies != soroban_sdk::vec![e, controller] {
                return Err(format!(
                    "rule {i}: the recovery rule's OZ rule has other signers or policies"
                ));
            }
            checked.recovery = true;
            rule_eval::recovery_rule(&me)
        } else {
            let ContextRuleType::CallContract(contract) = oz.context_type.clone() else {
                return Err(format!("rule {i}: not a contract-call rule"));
            };
            let mut installed = Installed {
                contract,
                signers: oz.signers.clone(),
                valid_until: oz.valid_until,
                program: None,
                cap: None,
            };
            for p in oz.policies.iter() {
                if p == interpreter {
                    let params = PerchInterpreterClient::new(e, &interpreter)
                        .get_program(account, &record.id)
                        .ok_or(format!("rule {i}: the interpreter holds no program"))?;
                    installed.program = Some(params.program);
                } else if p == spending_limit {
                    let data = e.as_contract(&spending_limit, || {
                        get_spending_limit_data(e, record.id, account)
                    });
                    installed.cap = Some(SpendingLimitAccountParams {
                        spending_limit: data.spending_limit,
                        period_ledgers: data.period_ledgers,
                    });
                    checked.capped += 1;
                } else {
                    return Err(format!("rule {i}: an unknown policy"));
                }
            }
            checked.constrained += usize::from(!oz.policies.is_empty());
            let mut rule =
                denote(e, account, &installed).ok_or(format!("rule {i}: denote refuses"))?;
            rule.generation = generation;
            rule
        };
        let denoted = mirror(e, &denoted, &format!("installed rule {i}"))?;
        if stored[i] != lowered[i] {
            return Err(format!(
                "rule {i} ({}): stored {:?}, the lowering {:?}",
                name(&record.name),
                stored[i],
                lowered[i]
            ));
        }
        if stored[i] != denoted {
            return Err(format!(
                "rule {i} ({}): stored {:?}, installed {:?}",
                name(&record.name),
                stored[i],
                denoted
            ));
        }
    }
    Ok(())
}

fn name(s: &soroban_sdk::String) -> String {
    let mut b = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut b);
    String::from_utf8(b).unwrap_or_else(|_| "?".to_string())
}
