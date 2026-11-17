//! rule-core's evaluator as a second check in `__check_auth`.
//!
//! Once OpenZeppelin's `do_check_auth` accepts an authorization, rule-eval's
//! `rule_eval::authorize` must accept it too, over the stored rule-eval rules
//! (`rule_set`) of the rules the payload chooses, at the current ledger and
//! scope generation, under every signer the payload names, and with the
//! account's own spending records. Each chosen OZ id is read as the stored
//! rule at its position: in the admin document's set when it is one of
//! `installed_rules`, in its scope's set when a scoped document installed it
//! (its `ScopeTag`). `authorize` reads only the rules its choices name, so
//! running it over the chosen rules alone gives the verdict and records of
//! running it over the whole stored set. A refusal, a chosen rule with no
//! stored rule, or a batch soroban-facade cannot read refuses the
//! authorization with `RuleEvalRefused`.
//!
//! Every capped rule's record follows the window OpenZeppelin's spending
//! limit keeps for the same rule: `__check_auth` stores what `authorize`
//! charged, and the record is dropped wherever the spending limit is
//! uninstalled from its rule, which ends that window: a changed cap or a
//! removed or replaced rule in `apply_doc` and `apply_scope` (`rules`), and
//! a removed scope.
//!
//! An account with no stored admin set (one upgraded to code that keeps it
//! and not re-applied since) skips the check. A recovery completion never
//! reaches it (`check_auth`).

use alloc::vec::Vec;

use perch_rule_eval::{convert, mirror, StoredRecord};
use soroban_sdk::auth::Context;
use soroban_sdk::{Env, Val, Vec as SVec};
use stellar_accounts::smart_account::{
    AuthPayload, SMART_ACCOUNT_EXTEND_AMOUNT as EXTEND, SMART_ACCOUNT_TTL_THRESHOLD as THRESHOLD,
};

use crate::{extend_persistent, scope_generation, InstalledRule, PerchStorage};

/// Whether rule-eval's `authorize` accepts the authorization OZ accepted,
/// storing every capped chosen rule's record when it does (module docs).
pub(crate) fn authorize(e: &Env, payload: &AuthPayload, contexts: &SVec<Context>) -> bool {
    let Some(admin) = PerchStorage::get_rule_set(e) else {
        return true;
    };
    PerchStorage::extend_rule_set_ttl(e, THRESHOLD, EXTEND);
    let admin = admin.to_vals();
    let mut installed: Option<SVec<InstalledRule>> = None;
    let mut ids: Vec<u32> = Vec::new();
    let mut rules: Vec<rule_eval::Rule> = Vec::new();
    let mut records: Vec<rule_eval::SpendRecord> = Vec::new();
    let mut choices: Vec<u32> = Vec::new();
    for id in payload.context_rule_ids.iter() {
        let j = match ids.iter().position(|x| *x == id) {
            Some(j) => j,
            None => {
                let Some(rule) =
                    stored_rule(e, id, &admin, &mut installed).and_then(|v| mirror::rule(e, v))
                else {
                    return false;
                };
                let record = match rule.cap {
                    Some(_) => record(e, id),
                    None => Some(rule_eval::empty_record()),
                };
                let Some(record) = record else {
                    return false;
                };
                records.push(record);
                rules.push(rule);
                ids.push(id);
                ids.len() - 1
            }
        };
        choices.push(j as u32);
    }
    let Some(contexts) = convert::calls(e, contexts) else {
        return false;
    };
    let Some(signers) = convert::signers(e, &payload.signers.keys()) else {
        return false;
    };
    let Ok(after) = rule_eval::authorize(
        &rules,
        &records,
        &contexts,
        &choices,
        &signers,
        e.ledger().sequence(),
        scope_generation(e),
    ) else {
        return false;
    };
    for (j, rule) in rules.iter().enumerate() {
        if rule.cap.is_some() && !same(&records[j], &after[j]) {
            PerchStorage::set_spend_records(e, &ids[j], &StoredRecord::from_record(e, &after[j]));
            extend_persistent(e, |ttl| {
                PerchStorage::extend_spend_records_ttl(e, &ids[j], ttl, ttl)
            });
        }
    }
    true
}

/// Whether two records hold the same spends and total.
fn same(a: &rule_eval::SpendRecord, b: &rule_eval::SpendRecord) -> bool {
    a.total == b.total
        && a.history.len() == b.history.len()
        && a.history
            .iter()
            .zip(&b.history)
            .all(|(x, y)| x.ledger == y.ledger && x.amount == y.amount)
}

/// The host value of the stored rule OZ rule `id` enforces: the entry at
/// its position in its scope's stored set when a scoped document installed
/// it, otherwise in `admin` at its position in `installed_rules` (read once,
/// into `installed`). Every entry read is extended as OZ extends the rule
/// entry it stands beside.
fn stored_rule(
    e: &Env,
    id: u32,
    admin: &SVec<Val>,
    installed: &mut Option<SVec<InstalledRule>>,
) -> Option<Val> {
    if let Some(tag) = PerchStorage::get_scope_tags(e, &id) {
        let record = PerchStorage::get_scopes(e, &tag.scope)?;
        let set = PerchStorage::get_scope_rule_sets(e, &tag.scope)?;
        PerchStorage::extend_scopes_ttl(e, &tag.scope, THRESHOLD, EXTEND);
        PerchStorage::extend_scope_rule_sets_ttl(e, &tag.scope, THRESHOLD, EXTEND);
        return set.to_vals().get(position(&record.rules, id)?);
    }
    if installed.is_none() {
        *installed = Some(PerchStorage::get_installed_rules(e)?);
        PerchStorage::extend_installed_rules_ttl(e, THRESHOLD, EXTEND);
    }
    admin.get(position(installed.as_ref()?, id)?)
}

fn position(rules: &SVec<InstalledRule>, id: u32) -> Option<u32> {
    rules.iter().position(|r| r.id == id).map(|i| i as u32)
}

/// The spending record the account keeps for OZ rule `id` (absent is
/// nothing spent), read with `mirror::record`.
fn record(e: &Env, id: u32) -> Option<rule_eval::SpendRecord> {
    let key = PerchStorage::new(e).get_perch_storage_spend_records_key(id);
    let storage = e.storage().persistent();
    match storage.get::<Val, Val>(&key) {
        Some(v) => {
            storage.extend_ttl(&key, THRESHOLD, EXTEND);
            mirror::record(e, v)
        }
        None => Some(rule_eval::empty_record()),
    }
}

/// Remove OZ rule `id`'s record, if it has one.
pub(crate) fn drop_record(e: &Env, id: u32) {
    if PerchStorage::has_spend_records(e, &id) {
        PerchStorage::remove_spend_records(e, &id);
    }
}
