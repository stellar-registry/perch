//! rule-core's evaluator as the account's rule check in `__check_auth`.
//!
//! An authorization other than a recovery completion, on an account that
//! stores its admin rule set, is decided by rule-eval's
//! `rule_eval::authorize`, over the stored rule-eval rules (`rule_set`) of
//! the rules the payload chooses, at the current ledger and scope
//! generation, under every signer the payload names, and with the account's
//! own spending records. `auth::authenticate` then checks every one of those
//! signers against OpenZeppelin's digest, so wallets sign the bytes they
//! sign for an OpenZeppelin account, and the records `authorize` charged are
//! stored.
//! Each chosen rule id is read as the stored rule its record holds, among
//! the admin document's records, or its scope's when a scoped document
//! installed it (its tag). `authorize` reads only the rules its
//! choices name, so running it over the chosen rules alone gives the verdict
//! and records of running it over the whole stored set. A chosen id that names no installed rule refuses with
//! `ContextRuleNotFound` (#3000), as OZ refuses it, which wallets read as a
//! selection the configuration has since left. rule-eval's refusal of a
//! chosen rule issued under another scope generation (`StaleGeneration`: a
//! scoped rule a recovery completion wiped) refuses with `StaleScope`; any
//! other refusal, a chosen recovery rule, or a batch soroban-facade cannot
//! read refuses the authorization with `RuleEvalRefused`. The recovery rule's stored form
//! allows every `apply_doc` the controller could; the controller decides
//! a completion (`auth::authorize_completion`), and no other authorization
//! may choose it.
//!
//! Each capped rule keeps one record. It is kept across an apply exactly
//! when its rule keeps both its id and its cap: a changed cap, or a
//! removed or replaced rule, drops it in `apply_doc` and `apply_scope`
//! ([`drop_records`]), and removing a scope drops its rules' records.

use alloc::vec::Vec;

use perch_rule_eval::{convert, mirror, StoredCap, StoredRecord};
use soroban_sdk::auth::Context;
use soroban_sdk::crypto::Hash;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{symbol_short, Env, Map, Symbol, TryFromVal, Val, Vec as SVec};

use perch_account_types::{AuthPayload, SmartAccountError};

use crate::auth::{
    authenticate, SMART_ACCOUNT_EXTEND_AMOUNT as EXTEND, SMART_ACCOUNT_TTL_THRESHOLD as THRESHOLD,
};
use crate::{extend_persistent, scope_generation, PerchAuthError, PerchStorage, RuleRecord};

fn refused() -> soroban_sdk::Error {
    PerchAuthError::RuleEvalRefused.into()
}

/// Rule-eval's verdict on the authorization, once every payload signer
/// has authenticated, storing every capped chosen rule's record when it
/// accepts (module docs). `admin` is the admin document's records,
/// `recovery` the recovery rule's id, and `bound` the account-bound
/// signature payload.
pub(crate) fn authorize(
    e: &Env,
    admin: &SVec<RuleRecord>,
    recovery: Option<u32>,
    bound: &Hash<32>,
    payload: &AuthPayload,
    contexts: &SVec<Context>,
) -> Result<(), soroban_sdk::Error> {
    PerchStorage::extend_rule_set_ttl(e, THRESHOLD, EXTEND);
    let admin = admin.to_vals();
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
                let v = stored_rule(e, id, &admin).ok_or(SmartAccountError::ContextRuleNotFound)?;
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
    .map_err(|r| match r {
        rule_eval::Refusal::StaleGeneration => PerchAuthError::StaleScope.into(),
        _ => refused(),
    })?;
    // OZ's digest: the bound payload with the chosen ids, so a signature
    // cannot be moved to other rules.
    let mut preimage = bound.to_bytes().to_bytes();
    preimage.append(&payload.context_rule_ids.clone().to_xdr(e));
    let digest = e.crypto().sha256(&preimage);
    for (signer, signature) in payload.signers.iter() {
        authenticate(e, &digest, &signer, &signature);
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

/// The host value of the stored rule rule `id` enforces: the one its record
/// holds, among its scope's records when a scoped document installed it,
/// otherwise among `admin`. A scope's record is extended as it is read, as
/// the records are what authorizes.
fn stored_rule(e: &Env, id: u32, admin: &SVec<Val>) -> Option<Val> {
    if let Some(scope) = PerchStorage::get_scope_tags(e, &id) {
        let record = PerchStorage::get_scopes(e, &scope)?;
        PerchStorage::extend_scopes_ttl(e, &scope, THRESHOLD, EXTEND);
        return rule_of(e, &record.rules.to_vals(), id);
    }
    rule_of(e, admin, id)
}

/// The `rule` field of the record of rule `id` among `records`, the host
/// values of `RuleRecord`s: each is read as a map of its fields, so the
/// stored rule reaches `mirror::rule` as it is stored.
fn rule_of(e: &Env, records: &SVec<Val>, id: u32) -> Option<Val> {
    for v in records.iter() {
        let record = Map::<Symbol, Val>::try_from_val(e, &v).ok()?;
        let this = u32::try_from_val(e, &record.get(symbol_short!("id"))?).ok()?;
        if this == id {
            return record.get(symbol_short!("rule"));
        }
    }
    None
}

/// The spending record the account keeps for rule `id` (absent is
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

/// Remove rule `id`'s record, if it has one.
pub(crate) fn drop_record(e: &Env, id: u32) {
    if PerchStorage::has_spend_records(e, &id) {
        PerchStorage::remove_spend_records(e, &id);
    }
}

/// After an apply took the records `current` to `next`: drop the spending
/// record of every capped rule of `current` that left, or that kept its id
/// under another cap. A rule stored without a cap keeps no record.
pub(crate) fn drop_records(e: &Env, current: &SVec<RuleRecord>, next: &SVec<RuleRecord>) {
    let next: Vec<(u32, SVec<StoredCap>)> = next.iter().map(|n| (n.id, n.rule.cap)).collect();
    for c in current.iter() {
        if c.rule.cap.is_empty() {
            continue;
        }
        if !next
            .iter()
            .any(|(id, cap)| *id == c.id && *cap == c.rule.cap)
        {
            drop_record(e, c.id);
        }
    }
}
