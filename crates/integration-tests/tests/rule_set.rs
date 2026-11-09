//! The account's stored rule-eval rule set (`PerchSmartAccount::rule_set`).
//!
//! The suites that apply documents (`rule_core_documents.rs`,
//! `rule_eval_baseline.rs`, `auth_corpus.rs`, `apply_delta.rs`) check after
//! every apply that the stored set equals the lowering of the document's
//! model and the denotation of what is installed
//! (`perch_testkit::rule_set::check`). This file covers what they do not:
//!
//! - the constructor's admin rule;
//! - a document that only reorders a rule's signers (fork issue #22): the
//!   stored rule, OZ's context rule and the account's record agree on the
//!   new order;
//! - the check reports a stored set that differs from what is installed;
//! - the account's anti-brick check on the stored rules against the one on
//!   the compiled rules, on generated documents;
//! - what the account refuses when the compiled model is missing, does not
//!   match the compiled rules, or lowers to a rule that asks for no signer
//!   or to a set with no admin rule.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_account_types::Signer;
use perch_doc_compiler::{
    admin_survives, CompiledDoc, DocCompilerClient, DocCompilerError, PerchDocCompiler,
};
use perch_interpreter::PerchInterpreter;
use perch_rule_eval::convert::address;
use perch_rule_eval::{doc_of, ModelPrincipals, StoredCond, StoredRule};
use perch_smart_account::testutils::set_rule_set;
use perch_smart_account::{infra, PerchAccountError};
use perch_spending_limit::PerchSpendingLimit;
use perch_testkit::delta::{strkey, DeltaWorld};
use perch_testkit::rule_set::check;
use perch_testkit::FIXTURE_NETWORK;
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Ledger as _};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, Env, Symbol, Vec as SVec};

fn bytes(e: &Env, json: &str) -> Bytes {
    Bytes::from_slice(e, json.as_bytes())
}

fn signer_json(id: &str, a: &Address) -> String {
    format!(r#"{{"id":"{id}","address":"{}"}}"#, strkey(a))
}

fn doc_json(signers: &[String], rules: &[String]) -> String {
    format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        rules.join(",")
    )
}

fn ids(ids: &[&str]) -> String {
    ids.iter()
        .map(|i| format!(r#""{i}""#))
        .collect::<Vec<_>>()
        .join(",")
}

const ADMIN: &str = r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#;

// ---------------------------------------------------------------------------
// The constructor, signer order, and the check itself
// ---------------------------------------------------------------------------

#[test]
fn the_constructor_stores_its_admin_rule() {
    let w = DeltaWorld::new();
    let c = check(&w.env, &w.delta).unwrap();
    assert_eq!(c.rules, 1);
    let stored = PerchAccountClient::new(&w.env, &w.delta).rule_set();
    let admin = stored.get_unchecked(0);
    assert_eq!(admin.contract, w.delta);
    assert_eq!(
        admin.signers,
        soroban_sdk::vec![&w.env, Signer::Delegated(w.keys[0].clone())]
    );
    assert_eq!(admin.threshold, 1);
}

/// Fork issue #22: a document that only reorders a rule's signers. OZ keeps
/// a context rule's signers in the order given, so the reorder is a change:
/// OZ's rule, the account's record and the stored rule all take the new
/// order.
#[test]
fn reordering_a_rules_signers_reorders_it_everywhere() {
    let w = DeltaWorld::new();
    let e = &w.env;
    let account = PerchAccountClient::new(e, &w.delta);
    let signers = [
        signer_json("owner", &w.keys[0]),
        signer_json("a", &w.keys[1]),
        signer_json("b", &w.keys[2]),
    ];
    let rule = |order: &[&str]| {
        format!(
            r#"{{"name":"r1","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":[{}]}}}}"#,
            strkey(&w.scopes[0]),
            ids(order)
        )
    };
    let order_of = |what: &str| -> Vec<Signer> {
        let records = account.installed_rules();
        let i = records
            .iter()
            .position(|r| r.name == soroban_sdk::String::from_str(e, "r1"))
            .unwrap();
        match what {
            "oz" => account
                .get_context_rule(&records.get_unchecked(i as u32).id)
                .signers
                .iter()
                .collect(),
            "record" => records.get_unchecked(i as u32).signers.iter().collect(),
            _ => account
                .rule_set()
                .get_unchecked(i as u32)
                .signers
                .iter()
                .collect(),
        }
    };
    let (a, b) = (
        Signer::Delegated(w.keys[1].clone()),
        Signer::Delegated(w.keys[2].clone()),
    );
    for order in [["a", "b"], ["b", "a"]] {
        account.apply_doc(
            &bytes(e, &doc_json(&signers, &[ADMIN.into(), rule(&order)])),
            &0,
            &None,
        );
        check(e, &w.delta).unwrap();
        let want = if order[0] == "a" {
            vec![a.clone(), b.clone()]
        } else {
            vec![b.clone(), a.clone()]
        };
        for what in ["oz", "record", "stored"] {
            assert_eq!(order_of(what), want, "{what} after {order:?}");
        }
    }
}

/// The check is not vacuous: a stored set that differs from what is
/// installed in a signer's order, a threshold, a condition or its length is
/// reported.
#[test]
fn the_check_reports_a_stored_set_that_differs() {
    let w = DeltaWorld::new();
    let e = &w.env;
    let account = PerchAccountClient::new(e, &w.delta);
    let signers = [
        signer_json("owner", &w.keys[0]),
        signer_json("a", &w.keys[1]),
    ];
    let rule = format!(
        r#"{{"name":"r1","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","signers":["owner","a"],"m":1}},"args":[{{"index":0,"pred":{{"type":"is-self"}}}}]}}"#,
        strkey(&w.scopes[0])
    );
    account.apply_doc(
        &bytes(e, &doc_json(&signers, &[ADMIN.into(), rule])),
        &0,
        &None,
    );
    let good = account.rule_set();
    check(e, &w.delta).unwrap();

    let tampered = |f: &dyn Fn(&mut SVec<StoredRule>)| {
        let mut set = good.clone();
        f(&mut set);
        e.as_contract(&w.delta, || set_rule_set(e, &set));
        let out = check(e, &w.delta);
        e.as_contract(&w.delta, || set_rule_set(e, &good));
        out
    };
    let edit = |set: &mut SVec<StoredRule>, f: &dyn Fn(&mut StoredRule)| {
        let mut r = set.get_unchecked(1);
        f(&mut r);
        set.set(1, r);
    };
    type Tamper<'a> = &'a dyn Fn(&mut SVec<StoredRule>);
    let cases: [(&str, Tamper); 4] = [
        ("signer order", &|s| {
            edit(s, &|r| {
                let (x, y) = (r.signers.get_unchecked(0), r.signers.get_unchecked(1));
                r.signers = soroban_sdk::vec![e, y, x];
            })
        }),
        ("threshold", &|s| edit(s, &|r| r.threshold = 2)),
        ("condition", &|s| {
            edit(s, &|r| {
                r.conds = soroban_sdk::vec![e, StoredCond::ArgI128AtMost(0, i128::MAX)];
            })
        }),
        ("length", &|s| {
            s.pop_back();
        }),
    ];
    for (what, f) in cases {
        assert!(tampered(f).is_err(), "a changed {what} passed");
    }
    check(e, &w.delta).unwrap();
}

// ---------------------------------------------------------------------------
// The anti-brick check, on compiled and on stored rules
// ---------------------------------------------------------------------------

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn percent(&mut self, p: usize) -> bool {
        self.below(100) < p
    }
}

/// A generated rule, and whether it is a self-admin rule asking `m` of its
/// `n` signers with `m == n` under `threshold` principals, every function,
/// no argument predicate and no not-after ledger: the one shape the two
/// checks read differently.
fn generated_rule(r: &mut Rng, w: &DeltaWorld, i: usize, pool: &[&str]) -> (String, bool) {
    let mut picked: Vec<&str> = pool.iter().copied().filter(|_| r.percent(60)).collect();
    if picked.is_empty() {
        picked.push(pool[r.below(pool.len())]);
    }
    let n = picked.len();
    let self_admin = r.percent(75);
    let threshold = r.percent(45);
    let m = if r.percent(50) { n } else { 1 + r.below(n) };
    let functions = r.percent(25);
    let args = r.percent(15);
    let not_after = r.percent(20);
    let cap = !self_admin && r.percent(30);
    let scope = if self_admin {
        r#"{"type":"self-admin"}"#.to_string()
    } else {
        format!(
            r#"{{"type":"contract","address":"{}"}}"#,
            strkey(&w.scopes[0])
        )
    };
    let principals = if threshold {
        format!(
            r#"{{"type":"threshold","signers":[{}],"m":{m}}}"#,
            ids(&picked)
        )
    } else {
        format!(r#"{{"type":"all","signers":[{}]}}"#, ids(&picked))
    };
    let mut out = format!(r#"{{"name":"r{i}","scope":{scope},"principals":{principals}"#);
    if functions {
        out.push_str(if cap {
            r#","functions":["transfer"]"#
        } else {
            r#","functions":["apply_doc","execute"]"#
        });
    }
    if args {
        out.push_str(r#","args":[{"index":0,"pred":{"type":"is-self"}}]"#);
    }
    if not_after {
        out.push_str(r#","not-after-ledger":5000000"#);
    }
    if cap {
        out.push_str(r#","cap":{"limit":"100","period-ledgers":10}"#);
    }
    out.push('}');
    let n_of_n_threshold = self_admin && threshold && m == n && !functions && !args && !not_after;
    (out, n_of_n_threshold)
}

/// The account refuses a document unless it declares a constraint-free,
/// never-expiring self-admin `all` rule with a signer
/// (`perch_rule_eval::admin_declared` on the document the account reads,
/// which equals `perch_doc_compiler::admin_survives` on the compiled
/// document for every generated document) and the stored rules keep a rule
/// on the account asking every one of its signers for every function, with
/// no condition, cap or last ledger (`perch_rule_eval::admin_survives`).
///
/// On generated documents the first implies the second, and the second holds
/// without the first exactly when the document's only such rule is a
/// `threshold` rule asking all `n` of its `n` signers: rule-eval's rules do
/// not tell it from `all`, while the compiled check counts only `all`
/// rules.
#[test]
fn the_anti_brick_check_on_stored_rules_agrees_with_the_compiled_one() {
    let w = DeltaWorld::new();
    let e = &w.env;
    let compiler = DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e));
    let me = address(e, &w.delta).unwrap();
    let pool = ["owner", "a", "b"];
    let signers: Vec<String> = pool
        .iter()
        .enumerate()
        .map(|(i, id)| signer_json(id, &w.keys[i]))
        .collect();
    let mut r = Rng(20_261_103);
    let (mut both, mut neither, mut only_stored, mut compiled_docs) = (0, 0, 0, 0);
    for _ in 0..600 {
        let n = 1 + r.below(3);
        let mut rules = vec![];
        let mut n_of_n = false;
        for i in 0..n {
            let (rule, shape) = generated_rule(&mut r, &w, i, &pool);
            n_of_n |= shape;
            rules.push(rule);
        }
        let json = doc_json(&signers, &rules);
        let Ok(Ok(compiled)) = compiler.try_compile_doc(&bytes(e, &json)) else {
            continue;
        };
        compiled_docs += 1;
        let old = admin_survives(&compiled);
        let model = compiled.model.get_unchecked(0);
        let doc = doc_of(e, &model).unwrap();
        assert_eq!(perch_rule_eval::admin_declared(&doc), old, "{json}");
        let lowered = rule_eval::lower(&doc, &me);
        let new = perch_rule_eval::admin_survives(&lowered, &me);
        assert_eq!(new, old || n_of_n, "{json}");
        match (old, new) {
            (true, true) => both += 1,
            (false, false) => neither += 1,
            (false, true) => only_stored += 1,
            (true, false) => unreachable!(),
        }
    }
    println!(
        "documents compiled: {compiled_docs}, both checks accept: {both}, both refuse: \
         {neither}, only the stored-rule check accepts: {only_stored}"
    );
    assert!(both > 0 && neither > 0 && only_stored > 0);
}

// ---------------------------------------------------------------------------
// Refusals, through a compiler that tampers with its model
// ---------------------------------------------------------------------------

/// The real compiler, with its model changed as the instance's `mode` says.
#[contract]
pub struct TamperingCompiler;

#[contractimpl]
impl TamperingCompiler {
    pub fn set_mode(e: Env, mode: Symbol) {
        e.storage().instance().set(&symbol_short!("mode"), &mode);
    }

    pub fn compile_doc(e: Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
        let mut c = PerchDocCompiler::compile_doc(&e, doc_json)?;
        let mode: Option<Symbol> = e.storage().instance().get(&symbol_short!("mode"));
        let Some(mode) = mode else {
            return Ok(c);
        };
        let mut model = c.model.get_unchecked(0);
        fn edit(
            model: &mut perch_rule_eval::CompiledModel,
            i: u32,
            f: &dyn Fn(&mut perch_rule_eval::ModelRule),
        ) {
            let mut r = model.rules.get_unchecked(i);
            f(&mut r);
            model.rules.set(i, r);
        }
        if mode == symbol_short!("none") {
            c.model = SVec::new(&e);
            return Ok(c);
        } else if mode == symbol_short!("two") {
            c.model.push_back(model);
            return Ok(c);
        } else if mode == symbol_short!("short") {
            model.rules.pop_back();
        } else if mode == symbol_short!("recovery") {
            model.recovery.push_back(perch_rule_eval::ModelRecovery {
                controller: e.current_contract_address(),
                zk: SVec::new(&e),
            });
        } else if mode == symbol_short!("zero") {
            // The second rule asks for none of its signers.
            edit(&mut model, 1, &|r| {
                let ids = match &r.principals {
                    ModelPrincipals::All(ids) | ModelPrincipals::Threshold(ids, _) => ids.clone(),
                };
                r.principals = ModelPrincipals::Threshold(ids, 0);
            });
        } else if mode == symbol_short!("noadmin") {
            // The admin rule lists its functions.
            let f = SVec::from_array(&e, [Symbol::new(&e, "apply_doc")]);
            edit(&mut model, 0, &|r| r.functions = Some(f.clone()));
        }
        c.model = SVec::from_array(&e, [model]);
        Ok(c)
    }
}

struct Tampered {
    env: Env,
    account: Address,
    compiler: Address,
    doc: Bytes,
}

fn tampered() -> Tampered {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1_000;
        l.network_id = network_id;
        l.min_persistent_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let compiler = infra::perch_doc_compiler::address(&env);
    env.register_at(&compiler, TamperingCompiler, ());
    env.register_at(
        &infra::perch_interpreter::address(&env),
        PerchInterpreter,
        (),
    );
    env.register_at(
        &infra::perch_spending_limit::address(&env),
        PerchSpendingLimit,
        (),
    );
    let (owner, other, token) = (
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    );
    let account = env.register(
        PerchAccount,
        (soroban_sdk::vec![&env, Signer::Delegated(owner.clone())],),
    );
    let rule = format!(
        r#"{{"name":"r1","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","signers":["owner","a"],"m":1}},"functions":["transfer"]}}"#,
        strkey(&token)
    );
    let doc = bytes(
        &env,
        &doc_json(
            &[signer_json("owner", &owner), signer_json("a", &other)],
            &[ADMIN.into(), rule],
        ),
    );
    Tampered {
        compiler,
        env,
        account,
        doc,
    }
}

#[test]
fn the_account_refuses_a_model_it_cannot_store() {
    let t = tampered();
    let account = PerchAccountClient::new(&t.env, &t.account);
    let compiler = TamperingCompilerClient::new(&t.env, &t.compiler);
    let before = (
        account.rule_set(),
        account.installed_rules(),
        account.revision(),
    );
    for (mode, want) in [
        ("none", PerchAccountError::ModelInvalid),
        ("two", PerchAccountError::ModelInvalid),
        ("short", PerchAccountError::ModelInvalid),
        ("recovery", PerchAccountError::ModelInvalid),
        ("zero", PerchAccountError::UnguardedRule),
        ("noadmin", PerchAccountError::AdminLockout),
    ] {
        compiler.set_mode(&Symbol::new(&t.env, mode));
        let got = account.try_apply_doc(&t.doc, &0, &None);
        assert_eq!(got, Err(Ok(want)), "{mode}");
        assert_eq!(
            (
                account.rule_set(),
                account.installed_rules(),
                account.revision()
            ),
            before,
            "{mode} changed the account"
        );
    }
    // The same document with its model untouched applies.
    compiler.set_mode(&Symbol::new(&t.env, "ok"));
    account.apply_doc(&t.doc, &0, &None);
    let c = check(&t.env, &t.account).unwrap();
    assert_eq!((c.rules, c.constrained), (2, 1));
}
