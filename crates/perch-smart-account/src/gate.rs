//! rule-core's evaluator as the account's rule check in `__check_auth`.
//!
//! An authorization other than a recovery completion, on an account that
//! stores its admin rule set, is decided by rule-eval's
//! `rule_eval::authorize`, over the stored rule-eval rules (`rule_set`) of
//! the rules the payload chooses, at the current ledger and scope
//! generation, under every signer the payload names, and with the account's
//! own spending records. OpenZeppelin's `authenticate` then checks every one
//! of those signers against OpenZeppelin's digest, so wallets sign the same
//! bytes as before, and the records `authorize` charged are stored.
//! OpenZeppelin's context rules are the registry of rule ids and signers:
//! each chosen OZ id is read as the stored rule at its position, in the
//! admin document's set when it is one of `installed_rules`, in its scope's
//! set when a scoped document installed it (its `ScopeTag`). `authorize`
//! reads only the rules its choices name, so running it over the chosen
//! rules alone gives the verdict and records of running it over the whole
//! stored set. A chosen id that names no installed rule refuses with OZ's
//! `ContextRuleNotFound`, as OZ refuses it, which wallets read as a
//! selection the configuration has since left. A refusal, a chosen recovery
//! rule, or a batch soroban-facade cannot read refuses the authorization
//! with `RuleEvalRefused`. The recovery rule's stored form
//! allows every `apply_doc` the controller could; the controller decides
//! a completion, on OpenZeppelin's path (`check_auth`), and no other
//! authorization may choose it.
//!
//! Each capped rule keeps one record. It is kept across an apply exactly
//! when its rule keeps both its OZ id and its cap: a changed cap, or a
//! removed or replaced rule, drops it in `apply_doc` and `apply_scope`
//! ([`drop_records`]), and removing a scope drops its rules' records. An
//! account's first `apply_doc` with this code, on rules installed with
//! OpenZeppelin's spending limit, starts every record empty.

use alloc::vec::Vec;

use perch_rule_eval::{convert, mirror, StoredRecord, StoredRule};
use soroban_sdk::auth::Context;
use soroban_sdk::crypto::Hash;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{symbol_short, Env, Map, Symbol, TryFromVal, Val, Vec as SVec};
use stellar_accounts::smart_account::{
    self, AuthPayload, SmartAccountError, SMART_ACCOUNT_EXTEND_AMOUNT as EXTEND,
    SMART_ACCOUNT_TTL_THRESHOLD as THRESHOLD,
};

use crate::{extend_persistent, scope_generation, InstalledRule, PerchAuthError, PerchStorage};

fn refused() -> soroban_sdk::Error {
    PerchAuthError::RuleEvalRefused.into()
}

/// Rule-eval's verdict on the authorization, once every payload signer
/// has authenticated, storing every capped chosen rule's record when it
/// accepts (module docs). `admin` is the stored admin set, `recovery` the
/// recovery rule's OZ id, and `bound` the account-bound signature payload.
pub(crate) fn authorize(
    e: &Env,
    admin: &SVec<StoredRule>,
    recovery: Option<u32>,
    bound: &Hash<32>,
    payload: &AuthPayload,
    contexts: &SVec<Context>,
) -> Result<(), soroban_sdk::Error> {
    PerchStorage::extend_rule_set_ttl(e, THRESHOLD, EXTEND);
    let admin = admin.to_vals();
    let mut installed: Option<SVec<InstalledRule>> = None;
    let mut ids: Vec<u32> = Vec::new();
    let mut rules: Vec<rule_eval::Rule> = Vec::new();
    let mut records: Vec<rule_eval::SpendRecord> = Vec::new();
    let mut choices: Vec<u32> = Vec::new();
    for id in payload.context_rule_ids.iter() {
        if recovery == Some(id) {
            return Err(refused());
        }
        let j = match ids.iter().position(|x| *x == id) {
            Some(j) => j,
            None => {
                let v = stored_rule(e, id, &admin, &mut installed)
                    .ok_or(SmartAccountError::ContextRuleNotFound)?;
                let rule = mirror::rule(e, v).ok_or_else(refused)?;
                let record = match rule.cap {
                    Some(_) => record(e, id),
                    None => Some(rule_eval::empty_record()),
                };
                records.push(record.ok_or_else(refused)?);
                rules.push(rule);
                ids.push(id);
                ids.len() - 1
            }
        };
        choices.push(j as u32);
    }
    let contexts = convert::calls(e, contexts).ok_or_else(refused)?;
    let signers = convert::signers(e, &payload.signers.keys()).ok_or_else(refused)?;
    let after = rule_eval::authorize(
        &rules,
        &records,
        &contexts,
        &choices,
        &signers,
        e.ledger().sequence(),
        scope_generation(e),
    )
    .map_err(|_| refused())?;
    // OZ's digest: the bound payload with the chosen ids, so a signature
    // cannot be moved to other rules.
    let mut preimage = bound.to_bytes().to_bytes();
    preimage.append(&payload.context_rule_ids.clone().to_xdr(e));
    let digest = e.crypto().sha256(&preimage);
    for (signer, signature) in payload.signers.iter() {
        smart_account::authenticate(e, &digest, &signer, &signature);
    }
    for (j, rule) in rules.iter().enumerate() {
        if rule.cap.is_some() && !same(&records[j], &after[j]) {
            PerchStorage::set_spend_records(e, &ids[j], &StoredRecord::from_record(e, &after[j]));
            extend_persistent(e, |ttl| {
                PerchStorage::extend_spend_records_ttl(e, &ids[j], ttl, ttl)
            });
        }
    }
    Ok(())
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
/// into `installed`). Every entry read is extended, as the stored sets are
/// what authorizes.
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

/// After an apply took the rules `current` (stored as `before`, when it was
/// stored) to `next` (stored as `after`): drop the record of every rule of
/// `current` that left, or that kept its id under another cap. A rule
/// stored without a cap keeps no record. With no `before` (rules installed
/// by code that kept no stored set), every rule's record is dropped.
pub(crate) fn drop_records(
    e: &Env,
    current: &SVec<InstalledRule>,
    before: Option<&SVec<StoredRule>>,
    next: &SVec<InstalledRule>,
    after: &SVec<StoredRule>,
) {
    let before = before.map(|b| b.to_vals());
    let after = after.to_vals();
    for (i, c) in current.iter().enumerate() {
        let old = before.as_ref().and_then(|b| cap(e, b.get(i as u32)));
        if old.as_ref().is_some_and(|v| v.is_empty()) {
            continue;
        }
        let new = position(next, c.id).and_then(|j| cap(e, after.get(j)));
        if old.is_none() || new != old {
            drop_record(e, c.id);
        }
    }
}

/// The `cap` field of the stored rule whose host value is `v`: its zero or
/// one caps.
fn cap(e: &Env, v: Option<Val>) -> Option<SVec<Val>> {
    let rule = Map::<Symbol, Val>::try_from_val(e, &v?).ok()?;
    SVec::try_from_val(e, &rule.get(symbol_short!("cap"))?).ok()
}
