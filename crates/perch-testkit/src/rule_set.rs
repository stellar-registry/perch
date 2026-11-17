//! The account's stored rule-eval rule set (`PerchSmartAccount::rule_set`),
//! checked against the two things it must equal after an apply:
//!
//! - **the lowering**: `rule_eval::lower` of the applied document's model on
//!   the account, less the document rules whose last ledger has passed (the
//!   rules `apply_doc` does not install); before any document, the
//!   constructor's admin rule;
//! - **the installed rules**: for each installed-rule record, in order, the
//!   denotation (`denote`) of its context rule (`get_context_rule`:
//!   contract, signers in the record's order, last ledger) with the
//!   interpreter program and spending cap Perch's RPN lowering gives the
//!   same document rule's local projection, composed with its original
//!   exact-root condition (`rpn::batch_policies_of`). Only the local part is
//!   what the interpreter and spending limit enforce when attached. A
//!   document rule must carry no policy. The recovery rule's record must be
//!   a zero-signer rule whose one policy is the adopted controller, and its
//!   stored rule rule-eval's recovery rule.
//! - **OZ's registry**: no rule. A completion reads the recovery rule from
//!   its record.
//!
//! The doc compiler's rules for the applied document are checked against the
//! same local RPN lowering and original root metadata first
//! (`rpn::check_compiled`).
//!
//! Rules are compared as `StoredRule`s, whose conversion from a
//! `rule_eval::Rule` is one-to-one, so equal mirrors are equal rules.
//!
//! [`check_grant`] checks a grant document's stored set the same way: the
//! lowering is `rule_eval::lower_scoped` of the grant's model under the
//! generation its record carries, and each denoted rule carries that
//! generation. The account keeps no grant document's text: the check reads
//! it as [`crate::rebuild`] gives it back from the grant's records and
//! signer ids, which must hash to the stored `doc_hash`, so every grant
//! document a suite applies also rebuilds.
//!
//! Run each at the ledger the apply it checks ran at: the lowering's expiry
//! drop is computed at the current ledger.
//!
//! [`check_records`] checks the spending records the account keeps, which
//! `__check_auth` charges through rule-eval: one only for a rule stored with
//! a cap, none for a rule id no longer installed, and each one's total the
//! sum of its history. What a record holds is checked against rule-core's
//! model records and the recorded baseline (`rule_core_documents.rs`,
//! `rule_eval_baseline.rs`).

use crate::denote::{denote, Installed};
use crate::rpn::{self, Policies};
use perch_account::PerchAccountClient;
use perch_account_types::ContextRuleType;
use perch_doc_compiler::{CompiledDoc, PerchDocCompilerClient};
use perch_rule_eval::convert::{address, signers};
use perch_rule_eval::{doc_of, model_of, StoredRule};
use perch_smart_account::infra;
use perch_smart_account::{InstalledRule, PerchSmartAccount};
use soroban_sdk::{Address, Bytes, Env};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;
use stellar_accounts::smart_account::SmartAccountStorageKey;

/// What one [`check`] compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    /// Stored rules, the recovery rule included.
    pub rules: usize,
    /// Rules the RPN lowering gives an interpreter program or a cap.
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
            auth_root: None,
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
    let attached = match client.applied_doc() {
        Some(d) => Some(attached(e, &d)?),
        None => None,
    };
    compare(
        e,
        account,
        &stored,
        &records,
        &lowered,
        attached.as_deref(),
        None,
        &mut checked,
    )?;
    Ok(checked)
}

/// The doc compiler's output for `canonical`, at the account's pinned
/// compiler.
fn compile(e: &Env, canonical: &Bytes) -> CompiledDoc {
    PerchDocCompilerClient::new(e, &infra::perch_doc_compiler::address(e)).compile_doc(canonical)
}

/// The RPN lowering's policies for each rule of `canonical`, once the doc
/// compiler's rules for it are checked against the same lowering.
fn attached(e: &Env, canonical: &Bytes) -> Result<Vec<Policies>, String> {
    let doc = rpn::doc(canonical)?;
    rpn::check_compiled(e, &doc, &compile(e, canonical))?;
    rpn::batch_policies_of(e, &doc)
}

/// The stored rule set of the grant document under `grant` equals both
/// the scoped lowering of its model and the denotation of the rules its
/// record holds (module docs).
pub fn check_grant(e: &Env, account: &Address, grant: u32) -> Result<Checked, String> {
    let client = PerchAccountClient::new(e, account);
    let me = address(e, account).ok_or("the account's address")?;
    let record = client.grant(&grant).ok_or(format!("no grant {grant}"))?;
    let stored: Vec<StoredRule> = client.grant_rule_set(&grant).iter().collect();
    let canonical = crate::rebuild::grant_text(e, account, grant)
        .map_err(|x| format!("grant {grant}'s text: {x}"))?;
    let canonical = Bytes::from_slice(e, canonical.as_bytes());
    let (doc, model) = read_doc(e, &canonical)?;
    let mut excluded = std::vec![me.clone()];
    if let Some(c) = client.recovery_controller() {
        excluded.push(address(e, &c).ok_or("the controller's address")?);
    }
    let lowered = rule_eval::lower_scoped(&model, &me, &excluded, record.gen)
        .map_err(|_| format!("grant {grant}: rule-eval's scoped lowering refuses it"))?;
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
        Some(&attached(e, &canonical)?),
        Some(record.gen),
        &mut checked,
    )?;
    Ok(checked)
}

/// `stored` against `lowered` and against the denotation of each of
/// `records`, read back from its view with the program and cap `attached` (the
/// RPN lowering of the applied document, `None` before any document) gives
/// it, carrying `generation`.
#[allow(clippy::too_many_arguments)]
fn compare(
    e: &Env,
    account: &Address,
    stored: &[StoredRule],
    records: &soroban_sdk::Vec<InstalledRule>,
    lowered: &[StoredRule],
    attached: Option<&[Policies]>,
    generation: Option<u64>,
    checked: &mut Checked,
) -> Result<(), String> {
    let client = PerchAccountClient::new(e, account);
    let me = address(e, account).ok_or("the account's address")?;
    // The document rules the account installs, in its order: those whose
    // last ledger has not passed.
    let now = e.ledger().sequence();
    let installed: Vec<&Policies> = attached
        .map(|p| {
            p.iter()
                .filter(|r| r.valid_until.is_none_or(|v| v >= now))
                .collect()
        })
        .unwrap_or_default();
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
        let view = client.get_context_rule(&record.id);
        let oz = e.as_contract(account, || {
            e.storage()
                .persistent()
                .has(&SmartAccountStorageKey::ContextRuleData(record.id))
        });
        if oz {
            return Err(format!("rule {i}: OZ's registry holds the rule"));
        }
        let denoted = if record.recovery {
            let controller = client
                .recovery_controller()
                .ok_or("a recovery rule and no controller")?;
            if !view.signers.is_empty() || view.policies != soroban_sdk::vec![e, controller.clone()]
            {
                return Err(format!(
                    "rule {i}: the recovery rule has other signers or policies"
                ));
            }
            if view.valid_until.is_some()
                || view.context_type != ContextRuleType::CallContract(account.clone())
            {
                return Err(format!(
                    "rule {i}: the recovery rule is not an unbounded rule on the account"
                ));
            }
            checked.recovery = true;
            rule_eval::recovery_rule(&me)
        } else {
            let ContextRuleType::CallContract(contract) = view.context_type.clone() else {
                return Err(format!("rule {i}: not a contract-call rule"));
            };
            if !view.policies.is_empty() {
                return Err(format!("rule {i}: a document rule carries a policy"));
            }
            let mut rule = Installed {
                contract,
                signers: view.signers.clone(),
                valid_until: view.valid_until,
                program: None,
                cap: None,
            };
            if attached.is_some() {
                let c = installed
                    .get(i)
                    .ok_or(format!("rule {i}: no document rule installs it"))?;
                if soroban_sdk::String::from_str(e, &c.name) != record.name
                    || c.valid_until != view.valid_until
                {
                    return Err(format!("rule {i}: the document rule is another"));
                }
                rule.program = c.install.as_ref().map(|p| p.program.clone());
                rule.cap = c.cap.clone();
            }
            checked.constrained += usize::from(rule.program.is_some() || rule.cap.is_some());
            checked.capped += usize::from(rule.cap.is_some());
            let mut rule = denote(e, account, &rule).ok_or(format!("rule {i}: denote refuses"))?;
            rule.generation = generation;
            rule.auth_root = installed.get(i).and_then(|p| rpn::root_of(e, &p.auth_root));
            rule
        };
        let denoted = mirror(e, &denoted, &format!("installed rule {i}"))?;
        if record.auth_root != stored[i].auth_root {
            return Err(format!(
                "rule {i}: installed record lost its root constraint"
            ));
        }
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

/// What one [`check_records`] checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Records {
    /// Installed rules stored with a cap, and those holding a spend.
    pub capped: usize,
    pub charged: usize,
}

/// The spending records `account` keeps (module docs): for every rule its
/// account document or a grant document installed, a record only when its
/// stored rule has a cap, its total the sum of its history; and no record
/// for any rule id no longer installed. Reads the account's storage, so it
/// also runs while the account's code is another (`rule_core_documents.rs`
/// swaps it).
pub fn check_records(e: &Env, account: &Address) -> Result<Records, String> {
    type A = perch_account::PerchAccount;
    let rules: Vec<(InstalledRule, StoredRule)> = e.as_contract(account, || {
        let mut rules: Vec<(InstalledRule, StoredRule)> = A::installed_rules(e)
            .iter()
            .zip(A::rule_set(e).iter())
            .collect();
        for grant in A::grants(e, 0, A::grant_count(e)).iter() {
            if let Some(record) = A::grant(e, grant) {
                rules.extend(record.rules.iter().zip(A::grant_rule_set(e, grant).iter()));
            }
        }
        rules
    });
    let mut out = Records::default();
    for (r, stored) in &rules {
        let kept = e.as_contract(account, || {
            perch_smart_account::testutils::spend_record(e, r.id)
        });
        if stored.cap.is_empty() {
            if kept.is_some() {
                return Err(format!(
                    "rule {} ({}): no cap, and a spending record",
                    r.id,
                    name(&r.name)
                ));
            }
            continue;
        }
        out.capped += 1;
        let Some(kept) = kept else {
            continue;
        };
        let sum = kept.history.iter().map(|x| x.amount).sum::<i128>();
        if kept.total != sum {
            return Err(format!(
                "rule {} ({}): a record whose total {} is not its history's {sum}",
                r.id,
                name(&r.name),
                kept.total
            ));
        }
        out.charged += usize::from(!kept.history.is_empty());
    }
    let next = e.as_contract(account, || perch_smart_account::testutils::next_rule_id(e));
    for id in 0..next {
        let kept = e.as_contract(account, || {
            perch_smart_account::testutils::spend_record(e, id)
        });
        if !rules.iter().any(|(r, _)| r.id == id) && kept.is_some() {
            return Err(format!("rule {id}: removed, and a spending record"));
        }
    }
    Ok(out)
}
