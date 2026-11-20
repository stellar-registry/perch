//! rule-core's evaluator as the account's rule check in `__check_auth`.
//!
//! An authorization other than a recovery completion, on an account that
//! stores its admin rule set, is decided by rule-eval's
//! `rule_eval::check_auth`, over the stored rule-eval rules (`rule_set`) of
//! the rules the payload chooses, at the current ledger and grant
//! generation, under every signer the payload names, and with the account's
//! own spending records. `auth::authenticate` then checks every one of those
//! signers against OpenZeppelin's digest, so wallets sign the bytes they
//! sign for an OpenZeppelin account, and the records `check_auth` charged are
//! stored.
//!
//! Each chosen rule id is read as the stored rule its record holds, among
//! the account document's records, or its grant's when a grant document
//! installed it (its tag). `check_auth` reads only the rules its choices
//! name, so running it over the chosen rules alone gives the verdict and
//! records of running it over the whole stored set. A chosen id that names
//! no installed rule refuses with `ContextRuleNotFound` (#3000), as OZ
//! refuses it, which wallets read as a selection the configuration has since
//! left. rule-eval's refusal of a chosen rule issued under another grant
//! generation (`StaleGeneration`: a grant rule a recovery completion wiped)
//! refuses with `StaleGrant`; any other refusal, a chosen recovery rule, or
//! a batch soroban-facade cannot read refuses the authorization with
//! `RuleEvalRefused`. The recovery rule's stored form allows every
//! `apply_doc` the controller could; the controller decides a completion
//! (`auth::authorize_completion`), and no other authorization may choose it.
//!
//! A capped rule meters the account's own transfers: a context chosen under
//! a capped rule is refused with `RuleEvalRefused` unless its argument 0 is
//! the account. A context chosen under a grant document's rule (a grant,
//! one carrying a generation) for a token function whose argument 0 is the
//! owner ([`OWNER_FNS`]) is refused the same way. As a CAP-0071 delegate the
//! account is handed the delegating account's contexts
//! (`docs/recovery/cap-0071.md` C2), so neither kind of rule authorizes that
//! account's calls to these functions. A grant's rule for any other function
//! matches as its argument predicates say; a grant author pins the
//! account's argument with `is-self`.
//!
//! Each capped rule keeps one record. It is kept across an apply exactly
//! when its rule keeps both its id and its cap: a changed cap, or a
//! removed or replaced rule, drops it in `apply_doc` and `apply_grant`
//! ([`drop_records`]), and removing a grant drops its rules' records.

use alloc::vec::Vec;

use perch_rule_eval::{convert, mirror, StoredCap, StoredRecord};
use soroban_sdk::auth::Context;
use soroban_sdk::crypto::Hash;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Env, TryFromVal, Val, Vec as SVec};

use perch_account_types::{AuthPayload, Signer, SmartAccountError};

use crate::auth::{
    authenticate, SMART_ACCOUNT_EXTEND_AMOUNT as EXTEND, SMART_ACCOUNT_TTL_THRESHOLD as THRESHOLD,
};
use crate::{
    extend_persistent, grant_generation, PerchAuthError, PerchStorage, RuleRecord, RuleSet,
    OWNER_FNS,
};

fn refused() -> soroban_sdk::Error {
    PerchAuthError::RuleEvalRefused.into()
}

/// Rule-eval's verdict on the authorization, once every payload signer
/// has authenticated, storing every capped chosen rule's record when it
/// accepts (module docs). `admin` is the account document's rules,
/// `recovery` the recovery rule's id, and `bound` the account-bound
/// signature payload.
pub(crate) fn authorize(
    e: &Env,
    admin: &RuleSet,
    recovery: Option<u32>,
    bound: &Hash<32>,
    payload: &AuthPayload,
    contexts: &SVec<Context>,
) -> Result<(), soroban_sdk::Error> {
    PerchStorage::extend_rule_set_ttl(e, THRESHOLD, EXTEND);
    let mut admin = Rules {
        signers: &admin.0,
        records: admin.1.to_vals(),
        table: None,
    };
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
                let rule = stored_rule(e, id, &mut admin)
                    .ok_or(SmartAccountError::ContextRuleNotFound)?
                    .ok_or_else(refused)?;
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
    let me = convert::address(e, &e.current_contract_address()).ok_or_else(refused)?;
    for (ctx, j) in contexts.iter().zip(&choices) {
        let rule = &rules[*j as usize];
        let own = rule.cap.is_some() || (rule.generation.is_some() && owner_fn(ctx));
        if own && !from_self(ctx, &me) {
            return Err(refused());
        }
    }
    let signers = convert::signers(e, &payload.signers.keys()).ok_or_else(refused)?;
    let after = rule_eval::check_auth(
        &rules,
        &records,
        &contexts,
        &choices,
        &signers,
        e.ledger().sequence(),
        grant_generation(e),
    )
    .map_err(|r| match r {
        rule_eval::Refusal::StaleGeneration => PerchAuthError::StaleGrant.into(),
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

/// Whether `ctx` calls one of [`OWNER_FNS`].
fn owner_fn(ctx: &rule_eval::Context) -> bool {
    matches!(ctx, rule_eval::Context::Call { function, .. }
        if OWNER_FNS.iter().any(|n| function.as_slice() == n.as_bytes()))
}

/// Whether `ctx` is a call whose argument 0 is the address `me`.
fn from_self(ctx: &rule_eval::Context, me: &[u8]) -> bool {
    matches!(ctx, rule_eval::Context::Call { args, .. }
        if matches!(args.first(), Some(rule_eval::Val::Address(a)) if a.as_slice() == me))
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

/// The account document's rules as `authorize` reads them: their signer
/// table, their records' host values, and the table in rule-eval's form
/// once a rule of theirs is read.
struct Rules<'a> {
    signers: &'a SVec<Signer>,
    records: SVec<Val>,
    table: Option<Vec<rule_eval::Signer>>,
}

/// The rule rule `id` enforces, read from its record (`None` when it has
/// none) by `mirror::rule` with its records' signer table (`Some(None)` when
/// that refuses it): among its grant's records when a grant document
/// installed it, otherwise among `admin`. A grant's record is extended as it
/// is read, as the records are what authorizes.
fn stored_rule(e: &Env, id: u32, admin: &mut Rules) -> Option<Option<rule_eval::Rule>> {
    if let Some(grant) = PerchStorage::get_grant_tags(e, &id) {
        let record = PerchStorage::get_grants(e, &grant)?;
        PerchStorage::extend_grants_ttl(e, &grant, THRESHOLD, EXTEND);
        let v = rule_of(e, &record.3 .1.to_vals(), id)?;
        return Some(convert::signers(e, &record.3 .0).and_then(|t| mirror::rule(e, v, &t)));
    }
    let v = rule_of(e, &admin.records, id)?;
    if admin.table.is_none() {
        admin.table = convert::signers(e, admin.signers);
    }
    Some(admin.table.as_ref().and_then(|t| mirror::rule(e, v, t)))
}

/// The stored rule of the record of rule `id` among `records`, the host
/// values of `RuleRecord`s: each is read as the tuple it is stored as (id,
/// name, policies, stored rule), so the stored rule reaches `mirror::rule`
/// as it is stored.
fn rule_of(e: &Env, records: &SVec<Val>, id: u32) -> Option<Val> {
    for v in records.iter() {
        let record = SVec::<Val>::try_from_val(e, &v).ok()?;
        let this = u32::try_from_val(e, &record.get(0)?).ok()?;
        if this == id {
            return record.get(3);
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
    let next: Vec<(u32, SVec<StoredCap>)> = next.iter().map(|n| (n.id(), n.rule().cap())).collect();
    for c in current.iter() {
        let cap = c.rule().cap();
        if cap.is_empty() {
            continue;
        }
        if !next.iter().any(|(id, kept)| *id == c.id() && *kept == cap) {
            drop_record(e, c.id());
        }
    }
}
