//! The account against the OpenZeppelin-backed account it replaces: the
//! same build of `perch-account` from before its rule registry became its
//! own records, when OZ's context-rule registry held its rule ids, rules and
//! signers. That build is loaded from `PERCH_OZ_ACCOUNT_WASM`, and runs
//! against the same infra this source registers natively: build it with
//! `stellar contract build --package perch-account` from the commit before
//! the change, so it pins the same committed infra hashes. It calls its
//! recovery controller through OZ's `Policy` hooks, so it runs in a world of
//! its own beside the controller built from that commit
//! (`PERCH_OZ_CONTROLLER_WASM`), at the address this account's world gives
//! this source's controller.
//!
//! - Generated account documents, grant documents and grant removals, applied
//!   to both: the same outcomes, the same rule ids allocated (the counter
//!   included), the same views (`configuration`, the records, the stored
//!   rule sets, every grant, the rule count, and `get_context_rule` for
//!   every id ever given, its signer and policy ids aside), and the same
//!   events. Each grant's text, which that build stores (`scope_doc`), is
//!   the one this build rebuilds from its records and signer ids
//!   (`perch_testkit::rebuild`). A grant document not in normal form, which
//!   that build applies and this one refuses (`NotNormalForm`), runs on this
//!   build alone, and must change nothing.
//! - Generated authorizations through each account's real `__check_auth`
//!   (`try_invoke_contract_check_auth`) after every step: the same verdict
//!   and error code, completion-shaped selections of the recovery rule
//!   included.
//! - A recovery flow under enforcing authorization, at fixed addresses so
//!   both accounts sign and hash the same bytes: the constructor's
//!   `context_rule_added`, enrollment, a reconfiguration that installs the
//!   recovery rule under a new id, refused and accepted completions, and the
//!   configuration each step leaves.
//!
//! `#[ignore]`d because it needs that build:
//!
//! ```text
//! git archive <base> | tar -x -C <dir>
//! (cd <dir> && stellar contract build --package perch-account --out-dir <out> \
//!   && stellar contract build --package perch-recovery --out-dir <out>)
//! PERCH_OZ_ACCOUNT_WASM=<out>/perch_account.wasm \
//! PERCH_OZ_CONTROLLER_WASM=<out>/perch_recovery.wasm \
//!   cargo test -p perch-integration-tests --test oz_differential -- --ignored --nocapture
//! ```

mod support;

use arbitrary::Unstructured;
use perch_account::{PerchAccountClient, PerchAuthError};
use perch_account_types::{AuthPayload, Signer};
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::account::GUARDIAN_APPROVAL_FNS;
use perch_recovery_interface::RecoveryAction;
use perch_rule_eval::StoredFunctions;
use perch_smart_account::{GrantRecord, PerchAccountError, StoredRule};
use perch_testkit::delta::{
    external_key, raw_entries, render, DeltaWorld, DocModel, GrantOp, KeyModel, FUNCTIONS,
    GRANT_IDS,
};
use proptest::prelude::*;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{ContractEventBody, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal};
use soroban_sdk::{
    contractclient, vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, TryFromVal, Val,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use stellar_accounts::smart_account::SmartAccountStorageKey;
use support::{world_with, Mode, Opts, DELAY};

fn wasm(var: &'static str, cell: &'static OnceLock<std::vec::Vec<u8>>) -> &'static [u8] {
    cell.get_or_init(|| {
        let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} (module docs)"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    })
}

/// The OZ-backed build's bytes.
fn oz_wasm() -> &'static [u8] {
    static WASM: OnceLock<std::vec::Vec<u8>> = OnceLock::new();
    wasm("PERCH_OZ_ACCOUNT_WASM", &WASM)
}

/// The bytes of the controller the OZ-backed build calls.
fn oz_controller() -> &'static [u8] {
    static WASM: OnceLock<std::vec::Vec<u8>> = OnceLock::new();
    wasm("PERCH_OZ_CONTROLLER_WASM", &WASM)
}

fn cases(default: u32) -> u32 {
    std::env::var("PERCH_DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// `v` as XDR, rendered with `account` as `SELF`, so two accounts' values
/// compare.
fn norm<T: IntoVal<Env, Val>>(env: &Env, account: &Address, v: T) -> String {
    let me: ScAddress = account.clone().into();
    let val: Val = v.into_val(env);
    render(&ScVal::try_from_val(env, &val).unwrap(), Some(&me))
}

/// The last invocation's events, every contract's, with `account` as `SELF`;
/// `oz` for the OZ-backed build, whose grant events are renamed as this
/// build names them ([`OzGrants`]).
fn events(env: &Env, account: &Address, oz: bool) -> std::vec::Vec<String> {
    let me: ScAddress = account.clone().into();
    env.events()
        .all()
        .events()
        .iter()
        .map(|e| {
            let ContractEventBody::V0(body) = &e.body;
            let (topics, data) = if oz {
                renamed(&body.topics, &body.data)
            } else {
                (body.topics.to_vec(), body.data.clone())
            };
            let topics: std::vec::Vec<String> =
                topics.iter().map(|t| render(t, Some(&me))).collect();
            let contract = match &e.contract_id {
                Some(c) if ScAddress::Contract(c.clone()) == me => "SELF".to_string(),
                Some(c) => hex::encode(c.0 .0),
                None => String::new(),
            };
            format!("{contract} {topics:?} {}", render(&data, Some(&me)))
        })
        .collect()
}

/// An OZ-backed build's event as this build emits it: `scope_applied`,
/// `scope_removed` and `scopes_wiped` renamed `grant_*`, and the grant id
/// field `scope` renamed `grant`, its map re-sorted as the host sorts it.
fn renamed(topics: &[ScVal], data: &ScVal) -> (std::vec::Vec<ScVal>, ScVal) {
    let sym = |s: &str| ScVal::Symbol(ScSymbol(s.try_into().unwrap()));
    let name = |v: &ScVal| match v {
        ScVal::Symbol(s) => s.0.to_utf8_string_lossy(),
        _ => String::new(),
    };
    let old = topics.first().map(name).unwrap_or_default();
    let new = match old.as_str() {
        "scope_applied" => "grant_applied",
        "scope_removed" => "grant_removed",
        "scopes_wiped" => "grants_wiped",
        _ => return (topics.to_vec(), data.clone()),
    };
    let mut topics = topics.to_vec();
    topics[0] = sym(new);
    let data = match data {
        ScVal::Map(Some(m)) => {
            let mut entries: std::vec::Vec<ScMapEntry> =
                m.0.iter()
                    .map(|e| ScMapEntry {
                        key: if name(&e.key) == "scope" {
                            sym("grant")
                        } else {
                            e.key.clone()
                        },
                        val: e.val.clone(),
                    })
                    .collect();
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            ScVal::Map(Some(ScMap(entries.try_into().unwrap())))
        }
        other => other.clone(),
    };
    (topics, data)
}

/// The id `account` gives its next rule: OZ's `NextId` on the OZ-backed
/// build, the account's own counter on this one.
fn next_id(env: &Env, account: &Address, oz: bool) -> u32 {
    env.as_contract(account, || {
        if oz {
            env.storage()
                .instance()
                .get(&SmartAccountStorageKey::NextId)
                .unwrap_or(0)
        } else {
            perch_smart_account::testutils::next_rule_id(env)
        }
    })
}

/// Everything the views say about `account`, normalized; `oz` for the
/// OZ-backed build, which stores each grant's text and names its grant views
/// as [`OzGrants`] does.
fn views(env: &Env, account: &Address, oz: bool) -> BTreeMap<String, String> {
    let c = PerchAccountClient::new(env, account);
    let old = OzGrantClient::new(env, account);
    let mut out = BTreeMap::new();
    out.insert(
        "configuration".into(),
        norm(env, account, c.configuration()),
    );
    out.insert("rule_set".into(), norm(env, account, c.rule_set()));
    out.insert("applied_doc".into(), format!("{:?}", c.applied_doc()));
    out.insert("count".into(), c.get_context_rules_count().to_string());
    let grants = if oz {
        old.scopes(&0, &u32::MAX)
    } else {
        c.grants(&0, &u32::MAX)
    };
    out.insert("grants".into(), format!("{grants:?}"));
    for s in GRANT_IDS {
        let (record, rule_set) = if oz {
            (old.scope(&s), old.scope_rule_set(&s))
        } else {
            (c.grant(&s), c.grant_rule_set(&s))
        };
        out.insert(format!("grant {s}"), norm(env, account, record));
        out.insert(format!("grant_rule_set {s}"), norm(env, account, rule_set));
        let text: Option<Bytes> = if oz {
            env.invoke_contract(
                account,
                &Symbol::new(env, "scope_doc"),
                vec![env, s.into_val(env)],
            )
        } else {
            perch_testkit::rebuild::read(env, account, s)
                .unwrap()
                .map(|st| perch_testkit::rebuild::text(env, &st).unwrap())
                .map(|t| Bytes::from_slice(env, t.as_bytes()))
        };
        out.insert(format!("grant_doc {s}"), format!("{text:?}"));
    }
    out
}

/// `get_context_rule` for every id below `next`: each rule's fields but its
/// signer and policy ids, and those ids apart.
fn rules_by_id(
    env: &Env,
    account: &Address,
    next: u32,
) -> (std::vec::Vec<String>, std::vec::Vec<String>) {
    let c = PerchAccountClient::new(env, account);
    let mut fields = std::vec::Vec::new();
    let mut ids = std::vec::Vec::new();
    for id in 0..next {
        match c.try_get_context_rule(&id) {
            Ok(Ok(r)) => {
                fields.push(format!(
                    "{id}: {} {:?} {} {} {:?}",
                    norm(env, account, r.context_type),
                    r.name,
                    norm(env, account, r.signers),
                    norm(env, account, r.policies),
                    r.valid_until
                ));
                ids.push(format!("{id}: {:?} {:?}", r.signer_ids, r.policy_ids));
            }
            other => fields.push(format!("{id}: {other:?}")),
        }
    }
    (fields, ids)
}

/// Every signer of `doc` external, on the stand-in verifier that accepts any
/// signature, so a generated authorization can sign as any of them.
fn external(mut doc: DocModel) -> DocModel {
    for s in &mut doc.signers {
        if let KeyModel::Delegated(k) = s.key {
            s.key = KeyModel::External(k);
        }
    }
    doc
}

fn external_op(op: GrantOp) -> GrantOp {
    match op {
        GrantOp::Admin(d) => GrantOp::Admin(external(d)),
        GrantOp::Apply(s, d) => GrantOp::Apply(s, external(d)),
        other => other,
    }
}

fn run(w: &DeltaWorld, account: &Address, op: &GrantOp) -> Result<(), String> {
    match op {
        GrantOp::Admin(d) => w.apply(account, d).map(|_| ()),
        GrantOp::Apply(s, d) => w.apply_grant(account, *s, d).map(|_| ()),
        GrantOp::Remove(s) => w.remove_grant(account, *s),
    }
}

/// [`run`] on the OZ-backed build, through its older grant entry points.
fn run_oz(ow: &DeltaWorld, oz: &Address, op: &GrantOp) -> Result<(), String> {
    let c = OzGrantClient::new(&ow.env, oz);
    match op {
        GrantOp::Admin(d) => ow.apply(oz, d).map(|_| ()),
        GrantOp::Apply(s, d) => {
            let bytes = d.bytes(ow);
            ow.env.cost_estimate().budget().reset_unlimited();
            c.try_apply_scope(s, &bytes)
                .map(|r| r.unwrap())
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        }
        GrantOp::Remove(s) => {
            ow.env.cost_estimate().budget().reset_unlimited();
            c.try_remove_scope(s)
                .map(|r| r.unwrap())
                .map_err(|e| format!("{e:?}"))
        }
    }
}

/// The OZ-backed build is older than the grant names: its grant entry
/// points are `apply_scope`, `remove_scope`, `scope`, `scopes` and
/// `scope_rule_set`, each taking the grant id as `scope`.
#[contractclient(name = "OzGrantClient")]
#[allow(dead_code)]
trait OzGrants {
    fn apply_scope(e: Env, scope: u32, doc_json: Bytes) -> Result<BytesN<32>, PerchAccountError>;
    fn remove_scope(e: Env, scope: u32) -> Result<(), PerchAccountError>;
    fn scope(e: Env, scope: u32) -> Option<GrantRecord>;
    fn scopes(e: Env, start: u32, count: u32) -> soroban_sdk::Vec<u32>;
    fn scope_rule_set(e: Env, scope: u32) -> soroban_sdk::Vec<StoredRule>;
}

/// This build's world (its account is `w.delta`), and the OZ-backed one's:
/// the same pools and addresses, the controller built beside it, and the
/// account, constructed with the same admin.
fn worlds() -> (DeltaWorld, DeltaWorld, Address) {
    let w = DeltaWorld::new();
    let ow = DeltaWorld::with_controller(Some(oz_controller()));
    assert_eq!(ow.controller, w.controller);
    let admin = vec![&ow.env, Signer::Delegated(ow.keys[0].clone())];
    let oz = ow.env.register(oz_wasm(), (admin,));
    (w, ow, oz)
}

/// Run `op` on both accounts and check outcomes, events, ids and views.
/// Returns how many rules' signer or policy ids differ. A grant document
/// this build refuses for its form alone runs on it alone.
fn step(w: &DeltaWorld, ow: &DeltaWorld, oz: &Address, op: &GrantOp) -> (bool, usize) {
    if let GrantOp::Apply(_, d) = op {
        let scoped = d.recovery.is_none() && d.rules.iter().all(|r| r.scope.is_some());
        if scoped && !d.normal_form(w.env.ledger().sequence()) {
            let before = raw_entries(&w.env);
            let out = run(w, &w.delta, op);
            assert!(out.is_err(), "{op:?} not in normal form, applied");
            assert_eq!(raw_entries(&w.env), before, "the refused {op:?} wrote");
            return (false, 0);
        }
    }
    let a = run(w, &w.delta, op);
    let ea = events(&w.env, &w.delta, false);
    let b = run_oz(ow, oz, op);
    let eb = events(&ow.env, oz, true);
    assert_eq!(a, b, "outcome of {op:?}");
    assert_eq!(ea, eb, "events of {op:?}");
    let next = next_id(&w.env, &w.delta, false);
    assert_eq!(next, next_id(&ow.env, oz, true), "ids allocated by {op:?}");
    assert_eq!(
        views(&w.env, &w.delta, false),
        views(&ow.env, oz, true),
        "views after {op:?}"
    );
    let (fa, ia) = rules_by_id(&w.env, &w.delta, next);
    let (fb, ib) = rules_by_id(&ow.env, oz, next);
    assert_eq!(fa, fb, "get_context_rule after {op:?}");
    let differ = ia.iter().zip(&ib).filter(|(x, y)| x != y).count();
    (a.is_ok(), differ)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(32),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Any interleaving of account documents, grant documents and removals
    /// leaves both accounts with the same ids, views and events.
    #[test]
    #[ignore = "needs PERCH_OZ_ACCOUNT_WASM (module docs)"]
    fn generated_documents_give_the_same_ids_views_and_events(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let (w, ow, oz) = worlds();
        let mut differ = 0;
        for (advance, op) in GrantOp::sequence(&mut Unstructured::new(&bytes), 8).unwrap() {
            w.advance(advance);
            ow.advance(advance);
            differ += step(&w, &ow, &oz, &op).1;
        }
        println!("{{\"signer_or_policy_ids_differ\":{differ}}}");
    }

    /// After every step, generated authorizations get the same verdict from
    /// both accounts' `__check_auth`.
    #[test]
    #[ignore = "needs PERCH_OZ_ACCOUNT_WASM (module docs)"]
    fn generated_authorizations_get_the_same_verdicts(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let (w, ow, oz) = worlds();
        let mut u = Unstructured::new(&bytes);
        let ops = GrantOp::sequence(&mut u, 6).unwrap();
        let (mut accepted, mut refused, mut escalations) = (0, 0, 0);
        let escalation = format!("{:?}", soroban_sdk::Error::from(PerchAuthError::GrantEscalation));
        for (advance, op) in ops {
            w.advance(advance);
            ow.advance(advance);
            step(&w, &ow, &oz, &external_op(op));
            for _ in 0..6 {
                let auth = Authorization::generate(&mut u, &w);
                let a = auth.check(&w, &w.delta);
                let b = auth.check(&ow, &oz);
                assert_eq!(a, b, "{auth:?}");
                match &a {
                    Ok(()) => accepted += 1,
                    Err(e) => {
                        refused += 1;
                        escalations += usize::from(e.contains(&escalation));
                    }
                }
            }
        }
        println!(
            "{{\"accepted\":{accepted},\"refused\":{refused},\"grant_escalation\":{escalations}}}"
        );
    }
}

/// An installed rule other than the recovery rule, as a generated
/// authorization aims at it: its id, its contract (the account, or
/// scope-pool contract `on`), its external signers' key-pool indices, and
/// the functions of [`FUNCTIONS`], `apply_doc` and `other` its stored rule
/// allows.
struct Target {
    id: u32,
    on: Option<usize>,
    keys: std::vec::Vec<usize>,
    allows: std::vec::Vec<&'static str>,
}

impl Target {
    /// Every rule of the account document and the grants, with its stored rule.
    fn all(w: &DeltaWorld) -> std::vec::Vec<Target> {
        let c = PerchAccountClient::new(&w.env, &w.delta);
        let mut pairs: std::vec::Vec<(perch_smart_account::InstalledRule, StoredRule)> = c
            .installed_rules()
            .iter()
            .zip(c.rule_set().iter())
            .collect();
        for s in c.grants(&0, &u32::MAX).iter() {
            if let Some(record) = c.grant(&s) {
                pairs.extend(record.rules.iter().zip(c.grant_rule_set(&s).iter()));
            }
        }
        let mut out = std::vec::Vec::new();
        for (record, stored) in pairs {
            if record.recovery {
                continue;
            }
            let perch_account_types::ContextRuleType::CallContract(contract) = record.context_type
            else {
                continue;
            };
            let on = if contract == w.delta {
                None
            } else {
                match w.scopes.iter().position(|a| *a == contract) {
                    Some(i) => Some(i),
                    None => continue,
                }
            };
            let keys = record
                .signers
                .iter()
                .filter_map(|s| match s {
                    Signer::External(_, key) => Some(key.get(0).unwrap_or(1) as usize - 1),
                    Signer::Delegated(_) => None,
                })
                .collect();
            let listed = |f: &str| match &stored.functions {
                StoredFunctions::Only(fs) => fs.contains(Symbol::new(&w.env, f)),
                StoredFunctions::AnyExcept(fs) => !fs.contains(Symbol::new(&w.env, f)),
            };
            let allows: std::vec::Vec<&'static str> = FUNCTIONS
                .iter()
                .copied()
                .chain(["apply_doc", "other"])
                .filter(|f| listed(f))
                .collect();
            if !allows.is_empty() {
                out.push(Target {
                    id: record.id,
                    on,
                    keys,
                    allows,
                });
            }
        }
        out
    }
}

/// One generated `__check_auth` call, built for whichever account checks
/// it (contexts on the account name that account).
#[derive(Debug)]
struct Authorization {
    payload: [u8; 32],
    /// External keys, by key-pool index; `None` is a stranger's key.
    signers: std::vec::Vec<usize>,
    ids: std::vec::Vec<u32>,
    /// `(on the account, else scope-pool contract n; function; amount)`.
    contexts: std::vec::Vec<(Option<usize>, &'static str, i128)>,
    /// One `apply_doc` context on the account with `ids`: the shape of a
    /// recovery completion.
    completion: bool,
}

impl Authorization {
    /// Two in three are aimed at installed rules: each context on a rule's
    /// contract, calling a function it allows, signed by all of its signers
    /// (one dropped in four), so most of these are accepted. The rest pick
    /// ids, contracts, functions (the guardian approvals among them), and
    /// signers at random, and a sixth of those, on an account with
    /// recovery, take the shape of a completion.
    fn generate(u: &mut Unstructured, w: &DeltaWorld) -> Authorization {
        let rules = Target::all(w);
        let c = PerchAccountClient::new(&w.env, &w.delta);
        let recovery = c.configuration().recovery_rule;
        let unknown = next_id(&w.env, &w.delta, false) + 3;
        let payload = [u.arbitrary::<u8>().unwrap_or(0); 32];
        let functions: std::vec::Vec<&'static str> = FUNCTIONS
            .iter()
            .copied()
            .chain(["apply_doc", "other"])
            .chain(GUARDIAN_APPROVAL_FNS)
            .collect();
        let amount = |u: &mut Unstructured| *u.choose(&[0i128, 7, 1_000, 2_500]).unwrap_or(&7);
        let n = u.int_in_range(1..=2).unwrap_or(1);
        let (mut contexts, mut ids, mut signers) = (
            std::vec::Vec::new(),
            std::vec::Vec::new(),
            std::vec::Vec::new(),
        );
        if !rules.is_empty() && u.ratio(2, 3).unwrap_or(true) {
            for _ in 0..n {
                let r = &rules[u.choose_index(rules.len()).unwrap_or(0)];
                let f = r.allows[u.choose_index(r.allows.len()).unwrap_or(0)];
                contexts.push((r.on, f, amount(u)));
                ids.push(r.id);
                for k in &r.keys {
                    if !signers.contains(k) {
                        signers.push(*k);
                    }
                }
            }
            if !signers.is_empty() && u.ratio(1, 4).unwrap_or(false) {
                signers.remove(u.choose_index(signers.len()).unwrap_or(0));
            }
        } else {
            let all: std::vec::Vec<u32> = rules.iter().map(|r| r.id).collect();
            for r in &rules {
                for k in &r.keys {
                    if !signers.contains(k) && u.ratio(2, 3).unwrap_or(true) {
                        signers.push(*k);
                    }
                }
            }
            if u.ratio(1, 10).unwrap_or(false) {
                signers.push(usize::MAX);
            }
            if let Some(r) = recovery.filter(|_| u.ratio(1, 6).unwrap_or(false)) {
                if !u.ratio(1, 2).unwrap_or(false) {
                    signers.clear();
                }
                return Authorization {
                    payload,
                    signers,
                    ids: std::vec![r],
                    contexts: std::vec![(None, "apply_doc", 0)],
                    completion: true,
                };
            }
            for _ in 0..n {
                let on = if u.ratio(1, 4).unwrap_or(false) {
                    None
                } else {
                    Some(u.int_in_range(0..=w.scopes.len() - 1).unwrap_or(0))
                };
                let f = functions[u.choose_index(functions.len()).unwrap_or(0)];
                contexts.push((on, f, amount(u)));
                ids.push(match recovery.filter(|_| u.ratio(1, 10).unwrap_or(false)) {
                    Some(r) => r,
                    None if all.is_empty() || u.ratio(1, 10).unwrap_or(false) => unknown,
                    None => all[u.choose_index(all.len()).unwrap_or(0)],
                });
            }
        }
        if u.ratio(1, 12).unwrap_or(false) {
            ids.push(unknown);
        }
        Authorization {
            payload,
            signers,
            ids,
            contexts,
            completion: false,
        }
    }

    fn check(&self, w: &DeltaWorld, account: &Address) -> Result<(), String> {
        let e = &w.env;
        let mut signers: Map<Signer, Bytes> = Map::new(e);
        for k in &self.signers {
            let key = match *k {
                usize::MAX => [0xEE; 32].to_vec(),
                k => hex::decode(external_key(k)).unwrap(),
            };
            signers.set(
                Signer::External(w.verifier.clone(), Bytes::from_slice(e, &key)),
                Bytes::from_array(e, &[1; 8]),
            );
        }
        let mut ids = soroban_sdk::Vec::new(e);
        for id in &self.ids {
            ids.push_back(*id);
        }
        let mut contexts = soroban_sdk::Vec::new(e);
        for (on, f, amount) in &self.contexts {
            let (contract, args) = if self.completion {
                (
                    account.clone(),
                    vec![
                        e,
                        Bytes::from_array(e, &self.payload).into_val(e),
                        0u32.into_val(e),
                        None::<u64>.into_val(e),
                    ],
                )
            } else {
                let contract = on.map_or(account.clone(), |n| w.scopes[n].clone());
                (
                    contract,
                    vec![
                        e,
                        account.into_val(e),
                        w.keys[1].into_val(e),
                        amount.into_val(e),
                    ],
                )
            };
            contexts.push_back(Context::Contract(ContractContext {
                contract,
                fn_name: Symbol::new(e, f),
                args,
            }));
        }
        let payload = AuthPayload {
            signers,
            context_rule_ids: ids,
        };
        e.cost_estimate().budget().reset_unlimited();
        e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            account,
            &BytesN::from_array(e, &self.payload),
            payload.into_val(e),
            &contexts,
        )
        .map_err(|err| format!("{err:?}"))
    }
}

/// One step of the recovery flow, as a transcript line.
fn line<T: std::fmt::Debug>(what: &str, out: T) -> String {
    format!("{what}: {out:?}")
}

/// The recovery flow under enforcing authorization, on the OZ-backed build
/// (`oz`) or this one, at fixed addresses: its transcript.
fn recovery_transcript(oz: bool) -> std::vec::Vec<String> {
    let w = world_with(Opts {
        fixed_addresses: true,
        skip_snapshot: true,
        account_wasm: oz.then(oz_wasm),
        controller_wasm: oz.then(oz_controller),
        ..Opts::default()
    });
    let mut t = std::vec::Vec::new();
    // The constructor's registry events: OZ's registry also announces each
    // signer it registers, which the account has no registry for.
    let constructed: std::vec::Vec<String> = events(&w.env, &w.account, false)
        .into_iter()
        .filter(|e| !e.contains("signer_registered"))
        .collect();
    t.push(line("constructor", constructed));
    let views = |t: &mut std::vec::Vec<String>, what: &str| {
        let c = w.client();
        t.push(line(&format!("{what} configuration"), c.configuration()));
        t.push(line(&format!("{what} rule_set"), c.rule_set()));
        t.push(line(&format!("{what} count"), c.get_context_rules_count()));
        let recovery = c.configuration().recovery_rule;
        t.push(line(
            &format!("{what} recovery rule"),
            recovery.map(|id| {
                let r = c.get_context_rule(&id);
                (r.id, r.context_type, r.name, r.signers, r.policies)
            }),
        ));
    };

    let mut loss = w.recovery("loss", Mode::Guardian);
    t.push(line("enroll", w.apply(&w.doc(Some(loss.clone())), 0)));
    views(&mut t, "enrolled");
    loss.quorum = 1;
    t.push(line("reconfigure", w.apply(&w.doc(Some(loss)), 0)));
    views(&mut t, "reconfigured");

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, id, EvidenceDomain::Initiate);
    t.push(line("completion before the delay", w.complete(&target)));
    w.advance(DELAY);

    // The recovery rule selected with the owner's signature: the rule has no
    // signer, so the owner is not one of the chosen rules' signers.
    let recovery = w.client().configuration().recovery_rule.unwrap();
    let root = w.invocation(
        &w.account,
        "apply_doc",
        std::vec![w.sc(target.clone()), w.sc(0u32), w.sc(None::<u64>)],
    );
    w.env
        .set_auths(&[w.delegated_entry(&w.account, &w.owner, recovery, root)]);
    let signed = w.client().try_apply_doc(&target, &0, &None);
    w.env.set_auths(&[]);
    t.push(line("completion with a signer", signed.map(|r| r.is_ok())));
    t.push(line("completion", w.complete(&target)));
    views(&mut t, "completed");
    t.push(line("new owner", w.activity_as(&new_owner)));
    t.push(line("old owner", w.activity()));
    t
}

/// The recovery flow, step by step, ends the same on both accounts.
#[test]
#[ignore = "needs PERCH_OZ_ACCOUNT_WASM (module docs)"]
fn a_recovery_flow_reads_the_same() {
    let (perch, oz) = (recovery_transcript(false), recovery_transcript(true));
    for (a, b) in perch.iter().zip(&oz) {
        assert_eq!(a, b);
    }
    assert_eq!(perch.len(), oz.len());
    for l in &perch {
        println!("{l}");
    }
}
