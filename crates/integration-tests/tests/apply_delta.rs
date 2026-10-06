//! `apply_doc` applies only what changed between the applied document and
//! the new one (`crates/perch-smart-account/src/rules.rs`), checked against
//! the full replace it replaced. See `perch_testkit::delta` for the harness:
//! a delta account and a full-replace oracle side by side, a byte-driven
//! document generator, and the complete normalized storage of an account.
//!
//! - Oracle equivalence over generated document sequences (proptest, with
//!   shrinking over the generator's bytes).
//! - Algebra: re-applying is a no-op; `A→B→C` ends where `A→C` does;
//!   `A→B→A` restores `A`.
//! - Accounting: the events and the storage writes of each transition are
//!   exactly what the rule diff predicts, and nothing touches an unchanged
//!   rule.
//! - Named cases for the diffs most likely to go wrong.
//!
//! Proptest case counts default low enough for CI; set `PERCH_DELTA_CASES`
//! to run more.

use arbitrary::Unstructured;
use perch_smart_account::InstalledRule;
use perch_testkit::delta::*;
use proptest::prelude::*;
use soroban_sdk::Address;
use std::collections::{BTreeMap, BTreeSet};

fn cases(default: u32) -> u32 {
    std::env::var("PERCH_DELTA_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn config(default: u32) -> ProptestConfig {
    ProptestConfig {
        cases: cases(default),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn gen_doc(bytes: &[u8]) -> DocModel {
    DocModel::generate(&mut Unstructured::new(bytes)).unwrap()
}

fn bytes() -> impl Strategy<Value = std::vec::Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..512)
}

/// Assert two normalized states are equal, naming the first difference.
fn same_state(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>, what: &str) {
    for (k, v) in a {
        assert_eq!(b.get(k), Some(v), "{what}: entry {k} differs");
    }
    for k in b.keys() {
        assert!(a.contains_key(k), "{what}: entry {k} only on one side");
    }
}

fn apply_both(w: &DeltaWorld, d: &DocModel) {
    let delta = w.apply(&w.delta, d);
    let oracle = w.apply(&w.oracle, d);
    assert_eq!(delta.is_ok(), oracle.is_ok(), "delta {delta:?} vs oracle {oracle:?}");
    if let (Err(a), Err(b)) = (&delta, &oracle) {
        assert_eq!(a, b, "both refuse, for the same reason");
    }
    same_state(
        &storage_state(&w.env, &w.delta, History::Keep),
        &storage_state(&w.env, &w.oracle, History::Keep),
        "delta vs full replace",
    );
}

// ---------------------------------------------------------------------------
// Oracle equivalence
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(48))]

    /// For any sequence of documents, the delta account and the
    /// full-replace oracle accept and refuse the same documents and end every
    /// step with identical normalized storage: rules, signers, policies and
    /// their parameters, registries, the canonical applied document, and the
    /// recovery wiring.
    #[test]
    fn delta_apply_matches_full_replace(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let w = DeltaWorld::new();
        for d in DocModel::sequence(&mut Unstructured::new(&bytes), 5).unwrap() {
            apply_both(&w, &d);
        }
    }
}

// ---------------------------------------------------------------------------
// Algebra
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(32))]

    /// Re-applying the applied document writes nothing and emits nothing but
    /// the account's own `DocApplied`.
    #[test]
    fn reapplying_the_applied_document_is_a_no_op(a in bytes()) {
        let w = DeltaWorld::new();
        let a = gen_doc(&a);
        w.apply(&w.delta, &a).unwrap();
        let before = raw_entries(&w.env);
        w.apply(&w.delta, &a).unwrap();
        let events = w.events();
        let written = w.env.cost_estimate().resources().write_entries;
        prop_assert!(events.iter().all(|e| e.name == "doc_applied"), "{events:?}");
        prop_assert_eq!(written, 0);
        prop_assert!(changed(&before, &raw_entries(&w.env)).is_empty());
    }

    /// `A → B → C` ends in the state `A → C` does (history counters aside:
    /// the recovery generation and controller epoch count transitions).
    #[test]
    fn transitions_compose(a in bytes(), b in bytes(), c in bytes()) {
        let (a, b, c) = (gen_doc(&a), gen_doc(&b), gen_doc(&c));
        let long = DeltaWorld::new();
        for d in [&a, &b, &c] {
            long.apply(&long.delta, d).unwrap();
        }
        let short = DeltaWorld::new();
        for d in [&a, &c] {
            short.apply(&short.delta, d).unwrap();
        }
        same_state(
            &storage_state(&long.env, &long.delta, History::Ignore),
            &storage_state(&short.env, &short.delta, History::Ignore),
            "A→B→C vs A→C",
        );
    }

    /// `A → B → A` restores `A`, and a rule unchanged across all three keeps
    /// its id throughout.
    #[test]
    fn a_transition_and_its_reverse_restore_the_state(a in bytes(), b in bytes()) {
        let (a, b) = (gen_doc(&a), gen_doc(&b));
        let w = DeltaWorld::new();
        w.apply(&w.delta, &a).unwrap();
        let state = storage_state(&w.env, &w.delta, History::Ignore);
        let ids_a = w.installed(&w.delta);
        w.apply(&w.delta, &b).unwrap();
        let ids_b = w.installed(&w.delta);
        w.apply(&w.delta, &a).unwrap();
        same_state(&state, &storage_state(&w.env, &w.delta, History::Ignore), "A→B→A vs A");
        for r in ids_a.iter() {
            let unchanged = ids_b.iter().any(|q| same_content(&r, &q));
            if unchanged {
                let back = w.installed(&w.delta).iter().find(|q| same_slot(&r, q)).unwrap();
                prop_assert_eq!(back.id, r.id, "rule {:?} kept its content, so its id", r.name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

/// Rule-membership events an OZ edit emits, with their rule-id topic.
const RULE_EVENTS: [&str; 7] = [
    "context_rule_added",
    "context_rule_removed",
    "context_rule_meta_updated",
    "signer_added",
    "signer_removed",
    "policy_added",
    "policy_removed",
];

fn same_slot(a: &InstalledRule, b: &InstalledRule) -> bool {
    a.recovery == b.recovery
        && (a.recovery || a.name == b.name)
        && a.context_type == b.context_type
}

fn signer_set(r: &InstalledRule) -> BTreeSet<String> {
    r.signers.iter().map(|s| format!("{s:?}")).collect()
}

fn policy_set(r: &InstalledRule) -> BTreeSet<String> {
    r.policies.iter().map(|p| format!("{p:?}")).collect()
}

fn same_content(a: &InstalledRule, b: &InstalledRule) -> bool {
    same_slot(a, b)
        && signer_set(a) == signer_set(b)
        && policy_set(a) == policy_set(b)
        && a.valid_until == b.valid_until
}

/// Check one transition's events and writes against what the diff of the
/// account's rule records predicts.
fn check_accounting(
    w: &DeltaWorld,
    before: &soroban_sdk::Vec<InstalledRule>,
    after: &soroban_sdk::Vec<InstalledRule>,
    events: &[Event],
    changed_keys: &[String],
) {
    let me = contract_hex(&w.delta);
    let ours: std::vec::Vec<&Event> = events.iter().filter(|e| e.contract == me).collect();
    let count = |name: &str, id: u32| {
        ours.iter()
            .filter(|e| e.name == name && e.topics.get(1).map(String::as_str) == Some(&id.to_string()))
            .count()
    };
    let mut expected_rule_events = 0usize;
    // Signers and policies a changed rule names: the only ones registry
    // events may concern.
    let mut touched: BTreeSet<String> = BTreeSet::new();
    let mut untouched_ids: std::vec::Vec<u32> = std::vec::Vec::new();

    for b in before.iter() {
        match after.iter().find(|a| same_slot(&b, a)) {
            Some(a) if same_content(&b, &a) => {
                assert_eq!(a.id, b.id, "unchanged rule {:?} keeps its id", b.name);
                for name in RULE_EVENTS {
                    assert_eq!(count(name, b.id), 0, "unchanged rule {:?}: {name}", b.name);
                }
                untouched_ids.push(b.id);
            }
            Some(a) if a.id == b.id => {
                let (sb, sa) = (signer_set(&b), signer_set(&a));
                let (pb, pa) = (policy_set(&b), policy_set(&a));
                let expect = [
                    ("signer_added", sa.difference(&sb).count()),
                    ("signer_removed", sb.difference(&sa).count()),
                    ("policy_added", pa.difference(&pb).count()),
                    ("policy_removed", pb.difference(&pa).count()),
                    ("context_rule_meta_updated", usize::from(a.valid_until != b.valid_until)),
                    ("context_rule_added", 0),
                    ("context_rule_removed", 0),
                ];
                for (name, n) in expect {
                    assert_eq!(count(name, b.id), n, "in-place edit of {:?}: {name}", b.name);
                    expected_rule_events += n;
                }
                touched.extend(sb.symmetric_difference(&sa).cloned());
                touched.extend(policy_addresses(&b).into_iter().chain(policy_addresses(&a)));
            }
            Some(a) => {
                // Replaced whole: only when nothing on the rule survives and
                // no addition can come first (spec: never an empty rule).
                let kept = signer_set(&b).intersection(&signer_set(&a)).count()
                    + policy_set(&b).intersection(&policy_set(&a)).count();
                let fresh = signer_set(&a).difference(&signer_set(&b)).count()
                    + policy_addresses(&a)
                        .difference(&policy_addresses(&b))
                        .count();
                assert!(
                    kept == 0 && (fresh == 0 || b.signers.len() + a.signers.len() > 15),
                    "rule {:?} was replaced although it could be edited in place",
                    b.name
                );
                assert_eq!(count("context_rule_removed", b.id), 1);
                assert_eq!(count("context_rule_added", a.id), 1);
                expected_rule_events += 2;
                touched.extend(signer_set(&b).into_iter().chain(signer_set(&a)));
                touched.extend(policy_addresses(&b).into_iter().chain(policy_addresses(&a)));
            }
            None => {
                assert_eq!(count("context_rule_removed", b.id), 1, "removed {:?}", b.name);
                expected_rule_events += 1;
                touched.extend(signer_set(&b));
                touched.extend(policy_addresses(&b));
            }
        }
    }
    for a in after.iter() {
        if !before.iter().any(|b| same_slot(&b, &a)) {
            assert_eq!(count("context_rule_added", a.id), 1, "added {:?}", a.name);
            expected_rule_events += 1;
            touched.extend(signer_set(&a));
            touched.extend(policy_addresses(&a));
        }
    }
    let rule_events = ours
        .iter()
        .filter(|e| RULE_EVENTS.contains(&e.name.as_str()))
        .count();
    assert_eq!(rule_events, expected_rule_events, "no event beyond the diff: {ours:?}");

    // Registrations only for signers and policies a changed rule names.
    for e in &ours {
        if e.name == "signer_registered" || e.name == "policy_registered" {
            assert!(
                touched.iter().any(|t| e.data.contains(t.as_str()) || t.contains(&e.data)),
                "registry event for an untouched signer or policy: {e:?}"
            );
        }
    }

    // Nothing keyed by an unchanged rule's id was written: its OZ entry, its
    // interpreter program, its spending-limit state.
    for id in untouched_ids {
        let rule_key = format!("{me}/[ContextRuleData,{id}]");
        let by_id = format!("{me},{id}]");
        for k in changed_keys {
            assert!(
                *k != rule_key && !k.ends_with(&by_id),
                "storage of an unchanged rule (id {id}) was written: {k}"
            );
        }
    }
}

fn policy_addresses(r: &InstalledRule) -> BTreeSet<String> {
    r.policies.iter().map(|p| format!("{:?}", p.policy)).collect()
}

/// Apply `b` over `a` on both accounts; check the delta's accounting, and
/// that it writes no more entries than the full replace.
fn transition(w: &DeltaWorld, a: &DocModel, b: &DocModel) {
    apply_both(w, a);
    let before = w.installed(&w.delta);
    let raw_before = raw_entries(&w.env);
    w.apply(&w.delta, b).unwrap();
    let events = w.events();
    let delta_writes = w.env.cost_estimate().resources().write_entries;
    let changed_keys = changed(&raw_before, &raw_entries(&w.env));
    let after = w.installed(&w.delta);
    check_accounting(w, &before, &after, &events, &changed_keys);
    w.apply(&w.oracle, b).unwrap();
    let oracle_writes = w.env.cost_estimate().resources().write_entries;
    assert!(
        delta_writes <= oracle_writes,
        "delta wrote {delta_writes} entries, full replace {oracle_writes}"
    );
    same_state(
        &storage_state(&w.env, &w.delta, History::Keep),
        &storage_state(&w.env, &w.oracle, History::Keep),
        "after the transition",
    );
}

proptest! {
    #![proptest_config(config(48))]

    /// Every transition emits exactly the events its rule diff predicts,
    /// writes nothing keyed by an unchanged rule, and writes no more entries
    /// than the full replace.
    #[test]
    fn events_and_writes_are_exactly_the_diff(a in bytes(), b in bytes()) {
        let w = DeltaWorld::new();
        transition(&w, &gen_doc(&a), &gen_doc(&b));
    }
}

// ---------------------------------------------------------------------------
// Named cases
// ---------------------------------------------------------------------------

fn delegated(n: usize) -> std::vec::Vec<SignerModel> {
    (0..n)
        .map(|i| SignerModel {
            id: SIGNER_IDS[i],
            key: KeyModel::Delegated(i),
        })
        .collect()
}

fn rule(name: &'static str, scope: Option<usize>, signers: &[usize]) -> RuleModel {
    RuleModel {
        name,
        scope,
        signers: signers.to_vec(),
        threshold: None,
        functions: None,
        not_after: None,
        cap: None,
    }
}

fn admin(signers: &[usize]) -> RuleModel {
    rule("admin", None, signers)
}

fn doc(signers: std::vec::Vec<SignerModel>, rules: std::vec::Vec<RuleModel>) -> DocModel {
    DocModel {
        signers,
        rules,
        recovery: None,
    }
}

/// `b` over `a`, with every check; returns the events and the rule records
/// before and after.
fn case(
    a: &DocModel,
    b: &DocModel,
) -> (
    DeltaWorld,
    std::vec::Vec<Event>,
    soroban_sdk::Vec<InstalledRule>,
    soroban_sdk::Vec<InstalledRule>,
) {
    let w = DeltaWorld::new();
    apply_both(&w, a);
    let before = w.installed(&w.delta);
    transition_after(&w, b, before)
}

fn transition_after(
    w: &DeltaWorld,
    b: &DocModel,
    before: soroban_sdk::Vec<InstalledRule>,
) -> (
    DeltaWorld,
    std::vec::Vec<Event>,
    soroban_sdk::Vec<InstalledRule>,
    soroban_sdk::Vec<InstalledRule>,
) {
    let raw_before = raw_entries(&w.env);
    w.apply(&w.delta, b).unwrap();
    let events = w.events();
    let changed_keys = changed(&raw_before, &raw_entries(&w.env));
    let after = w.installed(&w.delta);
    check_accounting(w, &before, &after, &events, &changed_keys);
    w.apply(&w.oracle, b).unwrap();
    same_state(
        &storage_state(&w.env, &w.delta, History::Keep),
        &storage_state(&w.env, &w.oracle, History::Keep),
        "after the transition",
    );
    // Hand the world back for follow-up assertions.
    let w2 = DeltaWorld {
        env: w.env.clone(),
        delta: w.delta.clone(),
        oracle: w.oracle.clone(),
        keys: w.keys.clone(),
        scopes: w.scopes.clone(),
        guardians: w.guardians.clone(),
        controller: w.controller.clone(),
        verifier: w.verifier.clone(),
        interpreter: w.interpreter.clone(),
        spending_limit: w.spending_limit.clone(),
    };
    (w2, events, before.clone(), after)
}

fn id_of(rules: &soroban_sdk::Vec<InstalledRule>, name: &str) -> u32 {
    rules
        .iter()
        .find(|r| !r.recovery && r.name == soroban_sdk::String::from_str(rules.env(), name))
        .unwrap()
        .id
}

fn names(events: &[Event], account: &Address) -> std::vec::Vec<String> {
    let me = contract_hex(account);
    events
        .iter()
        .filter(|e| e.contract == me && e.name != "doc_applied")
        .map(|e| e.name.clone())
        .collect()
}

#[test]
fn a_rule_keeping_its_name_with_new_functions_changes_only_its_program() {
    let mut a = rule("r1", Some(0), &[0]);
    a.functions = Some(std::vec!["transfer"]);
    let mut b = a.clone();
    b.functions = Some(std::vec!["transfer", "approve"]);
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), a]),
        &doc(delegated(1), std::vec![admin(&[0]), b]),
    );
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(names(&events, &w.delta), ["policy_removed", "policy_added"]);
}

#[test]
fn a_rule_keeping_its_name_with_a_new_scope_is_replaced() {
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), rule("r1", Some(0), &[0])]),
        &doc(delegated(1), std::vec![admin(&[0]), rule("r1", Some(1), &[0])]),
    );
    assert_ne!(id_of(&before, "r1"), id_of(&after, "r1"));
    let n = names(&events, &w.delta);
    assert!(n.contains(&"context_rule_removed".into()) && n.contains(&"context_rule_added".into()));
}

#[test]
fn new_cap_parameters_replace_only_the_spending_limit_policy() {
    let mut a = rule("r1", Some(0), &[0]);
    a.cap = Some((1_000, 100));
    let mut b = a.clone();
    b.cap = Some((2_000, 100));
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), a]),
        &doc(delegated(1), std::vec![admin(&[0]), b]),
    );
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(names(&events, &w.delta), ["policy_removed", "policy_added"]);
}

#[test]
fn adding_a_signer_to_a_rule_emits_only_that_signer() {
    let (w, events, before, after) = case(
        &doc(delegated(2), std::vec![admin(&[0]), rule("r1", Some(0), &[0])]),
        &doc(delegated(2), std::vec![admin(&[0]), rule("r1", Some(0), &[0, 1])]),
    );
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(
        names(&events, &w.delta),
        ["signer_registered", "signer_added"]
    );
}

#[test]
fn a_signer_shared_by_several_rules_changes_in_one_and_stays_in_the_others() {
    let a = doc(
        delegated(2),
        std::vec![admin(&[0, 1]), rule("r1", Some(0), &[1]), rule("r2", Some(1), &[1])],
    );
    let b = doc(
        delegated(2),
        std::vec![admin(&[0, 1]), rule("r1", Some(0), &[0]), rule("r2", Some(1), &[1])],
    );
    let (w, events, before, after) = case(&a, &b);
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    // s1 is still referenced (admin, r2), so it is neither deregistered nor
    // registered again; owner was already registered (admin).
    assert_eq!(names(&events, &w.delta), ["signer_removed", "signer_added"]);
}

#[test]
fn a_policy_shared_by_several_rules_is_edited_in_one_only() {
    let mut r1 = rule("r1", Some(0), &[0]);
    r1.functions = Some(std::vec!["transfer"]);
    let mut r2 = rule("r2", Some(1), &[0]);
    r2.functions = Some(std::vec!["mint"]);
    let mut r1b = r1.clone();
    r1b.functions = Some(std::vec!["approve"]);
    let (w, events, _before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), r1, r2.clone()]),
        &doc(delegated(1), std::vec![admin(&[0]), r1b, r2]),
    );
    // The interpreter stays registered (r2 still uses it): no registry
    // events, just r1's program swap.
    assert_eq!(names(&events, &w.delta), ["policy_removed", "policy_added"]);
    let r2_id = id_of(&after, "r2");
    let interpreter = perch_interpreter::PerchInterpreterClient::new(&w.env, &w.interpreter);
    assert!(interpreter.get_program(&w.delta, &r2_id).is_some());
}

#[test]
fn a_renamed_rule_is_removed_and_added() {
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), rule("r1", Some(0), &[0])]),
        &doc(delegated(1), std::vec![admin(&[0]), rule("r2", Some(0), &[0])]),
    );
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    assert_eq!(
        names(&events, &w.delta),
        ["context_rule_removed", "context_rule_added"]
    );
}

#[test]
fn a_rule_removed_and_added_back_gets_a_new_id_and_the_same_grant() {
    let with = doc(delegated(1), std::vec![admin(&[0]), rule("r1", Some(0), &[0])]);
    let without = doc(delegated(1), std::vec![admin(&[0])]);
    let (w, _, first, _) = case(&with, &without);
    let (_w, _, _, again) = transition_after(&w, &with, w.installed(&w.delta));
    assert_ne!(id_of(&first, "r1"), id_of(&again, "r1"));
}

#[test]
fn a_signer_keeping_its_id_with_a_new_key_is_swapped_in_every_rule_that_names_it() {
    let a = doc(
        delegated(2),
        std::vec![admin(&[0]), rule("r1", Some(0), &[1]), rule("r2", Some(1), &[0, 1])],
    );
    let mut b = a.clone();
    b.signers[1].key = KeyModel::Delegated(9);
    let (w, events, before, after) = case(&a, &b);
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    let n = names(&events, &w.delta);
    assert_eq!(n.iter().filter(|e| *e == "signer_added").count(), 2);
    assert_eq!(n.iter().filter(|e| *e == "signer_removed").count(), 2);
    assert!(!n.iter().any(|e| e.starts_with("context_rule")));
}

#[test]
fn a_one_signer_rule_swaps_its_only_signer_in_place() {
    // The compromise shape: the admin's only key changes. Nothing on the rule
    // survives, so the new key is added before the old one is removed.
    let a = doc(delegated(1), std::vec![admin(&[0])]);
    let mut b = a.clone();
    b.signers[0].key = KeyModel::Delegated(5);
    let (w, events, before, after) = case(&a, &b);
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    assert_eq!(
        names(&events, &w.delta),
        ["signer_registered", "signer_added", "signer_removed", "signer_deregistered"]
    );
}

#[test]
fn minimal_and_maximal_documents_round_trip() {
    let minimal = doc(delegated(1), std::vec![admin(&[0])]);
    let mut rules = std::vec![admin(&[0, 1, 2])];
    for (i, name) in RULE_NAMES.iter().enumerate() {
        let mut r = rule(name, Some(i % SCOPE_POOL), &[i % 16, (i + 1) % 16, (i + 2) % 16]);
        if i % 3 == 0 {
            r.functions = Some(std::vec!["transfer"]);
        }
        if i % 4 == 1 {
            r.cap = Some((1_000, 100));
        }
        rules.push(r);
    }
    let mut maximal = doc(delegated(16), rules);
    maximal.recovery = Some(RecoveryModel {
        quorum: 2,
        delay: 10,
        expiry: 100,
        max_cancels: 3,
    });
    let (w, _, _, after) = case(&minimal, &maximal);
    assert_eq!(after.len(), 17, "16 document rules and the recovery rule");
    let (w, _, _, back) = transition_after(&w, &minimal, w.installed(&w.delta));
    assert_eq!(back.len(), 1);
    let (_w, _, _, again) = transition_after(&w, &maximal, w.installed(&w.delta));
    assert_eq!(again.len(), 17);
}

#[test]
fn reformatting_the_same_document_is_a_no_op() {
    let w = DeltaWorld::new();
    let d = doc(delegated(2), std::vec![admin(&[0]), rule("r1", Some(0), &[1])]);
    w.apply(&w.delta, &d).unwrap();
    let before = raw_entries(&w.env);
    // Insignificant whitespace and member order: the canonical form, and so
    // the document, is unchanged.
    let json = d.json(&w);
    let reformatted = json
        .replacen(r#"{"version":1,"#, "{ \n  \"version\" : 1 ,", 1)
        .replace(r#"{"name":"r1","#, r#"{ "name" : "r1" , "#);
    let out = perch_account::PerchAccountClient::new(&w.env, &w.delta)
        .apply_doc(&soroban_sdk::Bytes::from_slice(&w.env, reformatted.as_bytes()), &0);
    assert_eq!(Some(out), perch_account::PerchAccountClient::new(&w.env, &w.delta).applied_doc_hash());
    assert!(names(&w.events(), &w.delta).is_empty());
    assert!(changed(&before, &raw_entries(&w.env)).is_empty());
}

#[test]
fn reordering_rules_changes_the_document_but_touches_no_rule() {
    let a = doc(
        delegated(2),
        std::vec![admin(&[0]), rule("r1", Some(0), &[1]), rule("r2", Some(1), &[0])],
    );
    let mut b = a.clone();
    b.rules.swap(1, 2);
    let (w, events, before, after) = case(&a, &b);
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    assert!(names(&events, &w.delta).is_empty(), "only the record and the document change");
}

#[test]
fn expiry_changes_are_metadata_updates() {
    let mut a = rule("r1", Some(0), &[0]);
    a.not_after = Some(5_000_000);
    let mut b = a.clone();
    b.not_after = Some(6_000_000);
    let (w, events, ..) = case(
        &doc(delegated(1), std::vec![admin(&[0]), a]),
        &doc(delegated(1), std::vec![admin(&[0]), b]),
    );
    assert_eq!(names(&events, &w.delta), ["context_rule_meta_updated"]);
}

#[test]
fn recovery_changes_edit_only_the_recovery_rule() {
    let mut a = doc(delegated(1), std::vec![admin(&[0]), rule("r1", Some(0), &[0])]);
    a.recovery = Some(RecoveryModel {
        quorum: 1,
        delay: 10,
        expiry: 100,
        max_cancels: 3,
    });
    let mut b = a.clone();
    b.recovery.as_mut().unwrap().quorum = 2;
    let (w, events, before, after) = case(&a, &b);
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    // A zero-signer rule whose only policy changes parameters cannot be
    // edited in place without passing through an empty rule.
    assert_eq!(
        names(&events, &w.delta),
        ["context_rule_removed", "context_rule_added"]
    );
}
