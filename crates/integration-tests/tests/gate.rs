//! rule-eval as `__check_auth`'s rule check, under ENFORCING authorization
//! (`perch_smart_account::check_auth`; see `support/mod.rs` for the world).
//!
//! rule-eval's `authorize` over the account's stored rule-eval rules decides
//! every authorization but a recovery completion, and the account's
//! `authenticate` checks the signers:
//!
//! - the stored rule alone decides what its rule id allows: one that
//!   allows less refuses (`RuleEvalRefused`), and one that names a signer
//!   the context rule does not lets that signer authorize;
//! - a chosen id that names no installed rule fails with OZ's
//!   `ContextRuleNotFound`, and choosing the recovery rule outside a
//!   completion with `RuleEvalRefused`;
//! - a recovery completion is left to the controller, whatever the stored
//!   set says, and even with none stored, when nothing else is authorized
//!   (`RuleEvalRefused`);
//! - each capped rule's spending record is charged by rule-eval, kept by an
//!   edit that leaves the rule's id and cap alone, and dropped when the cap
//!   changes, the rule is replaced or removed, or its scope is removed.

mod support;

use perch_account::{PerchAccountError, PerchAuthError};
use perch_account_types::{AuthPayload, Signer};
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::RecoveryAction;
use perch_smart_account::testutils::{
    remove_rule_set, set_rule_set, set_scope_rule_set, spend_record,
};
use perch_testkit::rule_set::{check_records, Records};
use soroban_sdk::xdr::{ContractEventBody, ScAddress, ScError, ScVal};
use soroban_sdk::{
    contract, contractimpl, symbol_short, vec, Address, Bytes, BytesN, Env, IntoVal, Symbol,
};
use support::*;

type CallResult<T> = Result<T, Result<PerchAccountError, soroban_sdk::InvokeError>>;

/// A token's `transfer` shape: `from` authorizes, `to` is credited.
#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let key = (symbol_short!("bal"), to);
        let balance: i128 = e.storage().persistent().get(&key).unwrap_or(0);
        e.storage().persistent().set(&key, &(balance + amount));
    }
}

/// The error the account's `__check_auth` failed with in the last
/// invocation, from the host's "failed account authentication" diagnostic.
fn refusal(w: &World) -> Option<ScError> {
    let account: ScAddress = w.account.clone().into();
    w.env.host().get_events().unwrap().0.iter().find_map(|ev| {
        let ContractEventBody::V0(body) = &ev.event.body;
        let ScVal::Vec(Some(data)) = &body.data else {
            return None;
        };
        match data.as_slice() {
            [ScVal::String(msg), ScVal::Address(a), ScVal::Error(err)]
                if msg.to_utf8_string_lossy() == "failed account authentication with error"
                    && *a == account =>
            {
                Some(err.clone())
            }
            _ => None,
        }
    })
}

fn rule_eval_refused() -> Option<ScError> {
    let e: soroban_sdk::Error = PerchAuthError::RuleEvalRefused.into();
    Some(e.try_into().unwrap())
}

/// Replace the stored rule of the rule installed as `name` with `f` of it.
fn restore(w: &World, name: &str, f: impl FnOnce(&mut perch_smart_account::StoredRule)) {
    let wanted = soroban_sdk::String::from_str(&w.env, name);
    let at = w
        .client()
        .installed_rules()
        .iter()
        .position(|r| r.name == wanted)
        .expect("the rule is installed") as u32;
    let mut set = w.client().rule_set();
    let mut rule = set.get(at).unwrap();
    f(&mut rule);
    set.set(at, rule);
    w.env.as_contract(&w.account, || set_rule_set(&w.env, &set));
}

/// The stored rule of `name` asking for one more signer than it has, so
/// rule-eval allows nothing through it.
fn tamper(w: &World, name: &str) {
    restore(w, name, |r| r.threshold = r.signers.len() + 1);
}

/// A document: the owner's admin rule, the default `target` rule, and the
/// capped `transfer` rules `caps` (`(name, limit)`, period 100) on `token`,
/// each signed by `signers` (one of them suffices).
fn capped_doc(w: &World, token: &Address, signers: &[&str], caps: &[(&str, u32)]) -> Bytes {
    let ids: std::vec::Vec<String> = signers.iter().map(|s| format!(r#""{s}""#)).collect();
    let mut rules = std::vec![
        r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string(),
        format!(
            r#"{{"name":"target","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}"#,
            strkey(&w.target)
        ),
    ];
    for (name, limit) in caps {
        rules.push(format!(
            r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","m":1,"signers":[{}]}},"functions":["transfer"],"cap":{{"limit":"{limit}","period-ledgers":100}}}}"#,
            strkey(token),
            ids.join(",")
        ));
    }
    let json = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","address":"{}"}},{{"id":"device","address":"{}"}}],"rules":[{}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(&w.owner),
        strkey(&w.device),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// A scoped document: one capped `transfer` grant `name` on `token` for
/// `key`.
fn capped_grant(w: &World, token: &Address, name: &str, key: &Address, limit: u32) -> Bytes {
    let json = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"k","address":"{}"}}],"rules":[{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","m":1,"signers":["k"]}},"functions":["transfer"],"cap":{{"limit":"{limit}","period-ledgers":100}}}}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(key),
        strkey(token)
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

fn apply_scope(w: &World, scope: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
    let root = w.invocation(
        &w.account,
        "apply_scope",
        std::vec![w.sc(scope), w.sc(doc.clone())],
    );
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    let out = w.client().try_apply_scope(&scope, doc);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

fn remove_scope(w: &World, scope: u32) -> CallResult<()> {
    let root = w.invocation(&w.account, "remove_scope", std::vec![w.sc(scope)]);
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    let out = w.client().try_remove_scope(&scope);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

/// `key` transfers `amount` of `token` from the account through rule `rule`.
fn spend(w: &World, token: &Address, key: &Address, rule: u32, amount: i128) -> bool {
    let to = w.guardians[0].clone();
    let root = w.invocation(
        token,
        "transfer",
        std::vec![w.sc(w.account.clone()), w.sc(to.clone()), w.sc(amount)],
    );
    w.env
        .set_auths(&[w.delegated_entry(&w.account, key, rule, root)]);
    let ok = TokenClient::new(&w.env, token)
        .try_transfer(&w.account, &to, &amount)
        .is_ok();
    w.env.set_auths(&[]);
    ok
}

/// The account's rule-eval record of rule `id`: `(ledger, amount)` history
/// and total; absent is empty.
fn record(w: &World, id: u32) -> (std::vec::Vec<(u32, i128)>, i128) {
    w.env
        .as_contract(&w.account, || spend_record(&w.env, id))
        .map(|r| {
            (
                r.history.iter().map(|x| (x.ledger, x.amount)).collect(),
                r.total,
            )
        })
        .unwrap_or_default()
}

fn records(w: &World) -> Records {
    check_records(&w.env, &w.account).unwrap_or_else(|x| panic!("the spending records: {x}"))
}

#[test]
fn the_stored_rule_alone_decides_what_its_oz_rule_allows() {
    let w = world();
    w.enroll(&w.doc(None));
    assert!(w.activity());
    assert!(
        !w.activity_as(&w.device),
        "the context rule and its stored rule name the owner"
    );

    // A stored rule that allows less: the context rule is unchanged.
    tamper(&w, "target");
    assert!(!w.activity());
    assert_eq!(refusal(&w), rule_eval_refused());

    // A stored rule that names a signer the context rule does not: the
    // signer is only authenticated.
    let device = Signer::Delegated(w.device.clone());
    restore(&w, "target", |r| {
        r.signers.push_back(device);
        r.threshold = 1;
    });
    let oz = w
        .client()
        .get_context_rule(&w.rule_id(&w.account, "target"));
    assert_eq!(oz.signers.len(), 1);
    assert!(w.activity_as(&w.device));

    // Applying a document stores the set anew.
    w.enroll(&w.doc(None));
    assert!(w.activity());
    assert!(!w.activity_as(&w.device));
}

#[test]
fn an_unknown_id_and_the_recovery_rule_outside_a_completion_are_refused() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let check = |ids: soroban_sdk::Vec<u32>| {
        let context = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
            contract: w.target.clone(),
            fn_name: Symbol::new(&w.env, "protected"),
            args: vec![&w.env, w.account.clone().into_val(&w.env)],
        });
        let payload = AuthPayload {
            signers: soroban_sdk::Map::new(&w.env),
            context_rule_ids: ids,
        };
        w.env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(&w.env, &[5; 32]),
            payload.into_val(&w.env),
            &vec![&w.env, context],
        )
    };
    // As OZ refuses a selection the configuration has left.
    assert_eq!(
        check(vec![&w.env, 999]),
        Err(Ok(soroban_sdk::Error::from_contract_error(3000)))
    );
    // The recovery rule's stored form allows any `apply_doc`; only the
    // controller decides one, in a completion.
    assert_eq!(
        check(vec![&w.env, w.rule_id(&w.account, "recovery")]),
        Err(Ok(PerchAuthError::RuleEvalRefused.into()))
    );
}

#[test]
fn a_recovery_completion_is_left_to_the_controller() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    // A stored set under which rule-eval allows nothing at all, the
    // recovery rule included.
    let mut set = w.client().rule_set();
    for i in 0..set.len() {
        let mut rule = set.get(i).unwrap();
        rule.threshold = rule.signers.len() + 1;
        set.set(i, rule);
    }
    w.env.as_contract(&w.account, || set_rule_set(&w.env, &set));
    assert!(!w.activity());

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, id, EvidenceDomain::Initiate);
    w.guardian(1, id, EvidenceDomain::Initiate);
    w.advance(DELAY);
    w.complete(&target)
        .expect("the completion never depends on rule-eval");
    // The completion stored the target's set, which rule-eval evaluates.
    assert!(w.activity_as(&new_owner));
    tamper(&w, "target");
    assert!(!w.activity_as(&new_owner));
}

#[test]
fn without_a_stored_set_the_account_authorizes_nothing_but_a_completion() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    w.env.as_contract(&w.account, || remove_rule_set(&w.env));
    assert!(!w.activity());
    assert_eq!(refusal(&w), rule_eval_refused());

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, id, EvidenceDomain::Initiate);
    w.guardian(1, id, EvidenceDomain::Initiate);
    w.advance(DELAY);
    w.complete(&target)
        .expect("a completion never reads the stored set");
    // The completion stored the target's set.
    assert!(w.activity_as(&new_owner));
}

#[test]
fn a_capped_rules_record_follows_its_id_and_cap() {
    let w = world();
    let token = w.env.register(Token, ());
    w.apply_bytes(&capped_doc(&w, &token, &["owner"], &[("spend", 10)]), 0)
        .unwrap();
    let id = w.rule_id(&w.account, "spend");
    let now = w.ledger();

    // rule-eval charges the spends.
    assert!(spend(&w, &token, &w.owner, id, 6));
    assert!(spend(&w, &token, &w.owner, id, 4));
    assert_eq!(record(&w, id), (std::vec![(now, 6), (now, 4)], 10));
    assert!(!spend(&w, &token, &w.owner, id, 1), "over the cap");
    assert_eq!(refusal(&w), rule_eval_refused());
    assert!(spend(&w, &token, &w.owner, id, 0), "a zero amount");
    assert_eq!(
        records(&w),
        Records {
            capped: 1,
            charged: 1
        }
    );

    // A signer edit keeps the rule, its cap and its record.
    w.apply_bytes(
        &capped_doc(&w, &token, &["owner", "device"], &[("spend", 10)]),
        0,
    )
    .unwrap();
    assert_eq!(w.rule_id(&w.account, "spend"), id);
    assert_eq!(record(&w, id).1, 10);
    records(&w);
    assert!(!spend(&w, &token, &w.device, id, 1), "still at the cap");

    // A changed cap starts the record anew.
    w.apply_bytes(
        &capped_doc(&w, &token, &["owner", "device"], &[("spend", 20)]),
        0,
    )
    .unwrap();
    assert_eq!(w.rule_id(&w.account, "spend"), id);
    assert_eq!(record(&w, id), (std::vec![], 0));
    assert!(spend(&w, &token, &w.device, id, 15));
    records(&w);

    // The window rolls: an entry older than the period is evicted.
    w.advance(100);
    assert!(spend(&w, &token, &w.owner, id, 20));
    assert_eq!(record(&w, id), (std::vec![(now + 100, 20)], 20));
    records(&w);

    // A rule replaced under a new name, then removed: no record outlives
    // its rule.
    w.apply_bytes(
        &capped_doc(&w, &token, &["owner"], &[("spend-more", 20)]),
        0,
    )
    .unwrap();
    let renamed = w.rule_id(&w.account, "spend-more");
    assert_ne!(renamed, id);
    assert_eq!(record(&w, id), (std::vec![], 0));
    assert!(spend(&w, &token, &w.owner, renamed, 3));
    records(&w);
    w.apply_bytes(&capped_doc(&w, &token, &["owner"], &[]), 0)
        .unwrap();
    assert_eq!(record(&w, renamed), (std::vec![], 0));
    assert_eq!(records(&w), Records::default());
}

#[test]
fn a_scoped_capped_grant_is_charged_by_rule_eval_and_its_record_leaves_with_its_scope() {
    let w = world();
    w.enroll(&w.doc(None));
    let token = w.env.register(Token, ());
    let app = w.new_key();
    apply_scope(&w, 3, &capped_grant(&w, &token, "allowance", &app, 10)).unwrap();
    let id = w.client().scope(&3).unwrap().rules.get(0).unwrap().id;
    assert!(w.client().get_context_rule(&id).policies.is_empty());
    assert!(spend(&w, &token, &app, id, 7));
    assert!(!spend(&w, &token, &app, id, 4), "over the cap");
    assert_eq!(record(&w, id).1, 7);
    assert_eq!(
        records(&w),
        Records {
            capped: 1,
            charged: 1
        }
    );

    // A scoped rule whose stored rule allows less is refused by rule-eval.
    let mut set = w.client().scope_rule_set(&3);
    let mut rule = set.get(0).unwrap();
    rule.threshold = 2;
    set.set(0, rule);
    w.env
        .as_contract(&w.account, || set_scope_rule_set(&w.env, 3, &set));
    assert!(!spend(&w, &token, &app, id, 1));
    assert_eq!(refusal(&w), rule_eval_refused());

    remove_scope(&w, 3).unwrap();
    assert_eq!(record(&w, id), (std::vec![], 0));
    assert_eq!(records(&w), Records::default());
}
