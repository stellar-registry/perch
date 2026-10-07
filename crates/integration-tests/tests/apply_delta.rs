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
use perch_doc_compiler::{MAX_DOC_RULES, MAX_DOC_SIGNERS};
use perch_smart_account::testutils::{Mode, PlannedRule, Step};
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
    assert_eq!(
        delta.is_ok(),
        oracle.is_ok(),
        "delta {delta:?} vs oracle {oracle:?}"
    );
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
        // The one entry an authorized call always writes: its auth nonce.
        prop_assert_eq!(written, 1);
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

fn same_slot(a: &InstalledRule, b: &InstalledRule) -> bool {
    a.recovery == b.recovery && (a.recovery || a.name == b.name) && a.context_type == b.context_type
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

/// The plan's entry for `r`'s slot.
fn planned<'a>(plan: &'a [PlannedRule], r: &InstalledRule) -> &'a PlannedRule {
    plan.iter()
        .find(|p| {
            p.recovery == r.recovery
                && (r.recovery || p.name == r.name)
                && p.context_type == r.context_type
        })
        .unwrap_or_else(|| panic!("no plan for {:?}", r.name))
}

/// Check one transition's events and writes against the plan the cost model
/// made for it: each rule took the step planned, a changed rule took the
/// cheaper path, and its events are exactly that path's.
fn check_accounting(
    w: &DeltaWorld,
    before: &soroban_sdk::Vec<InstalledRule>,
    after: &soroban_sdk::Vec<InstalledRule>,
    plan: &[PlannedRule],
    events: &[Event],
    changed_keys: &[String],
) {
    let me = contract_hex(&w.delta);
    // Quiet-events experiment: the OZ mutations emit nothing, so the
    // account's only event is `DocApplied`, whose summary must be exactly
    // what the plan and the diff of the records say was done.
    let ours: std::vec::Vec<&Event> = events.iter().filter(|e| e.contract == me).collect();
    assert!(
        ours.iter().all(|e| e.name == "doc_applied"),
        "per-item events from the quiet path: {ours:?}"
    );
    let mut expected = Summary::default();
    let mut untouched_ids: std::vec::Vec<u32> = std::vec::Vec::new();

    for b in before.iter() {
        let step = planned(plan, &b).step;
        match after.iter().find(|a| same_slot(&b, a)) {
            Some(a) if same_content(&b, &a) => {
                assert_eq!(step, Step::Keep, "{:?}", b.name);
                assert_eq!(a.id, b.id, "unchanged rule {:?} keeps its id", b.name);
                untouched_ids.push(b.id);
            }
            Some(a) => {
                let p = planned(plan, &b);
                // The cheaper path, the in-place edit on a tie; replacement
                // also when no in-place order exists.
                match step {
                    Step::InPlace => {
                        assert!(p.editable && p.in_place <= p.replace, "{p:?}");
                        assert_eq!(p.cost, p.in_place);
                        assert_eq!(a.id, b.id, "{:?} edited in place keeps its id", b.name);
                        let (sb, sa) = (signer_set(&b), signer_set(&a));
                        let (pb, pa) = (policy_set(&b), policy_set(&a));
                        expected.rules_edited += 1;
                        expected.signers_added += sa.difference(&sb).count();
                        expected.signers_removed += sb.difference(&sa).count();
                        expected.policies_added += pa.difference(&pb).count();
                        expected.policies_removed += pb.difference(&pa).count();
                    }
                    Step::Replace => {
                        assert!(!p.editable || p.in_place > p.replace, "{p:?}");
                        assert_eq!(p.cost, p.replace);
                        assert_ne!(a.id, b.id, "{:?} replaced gets a new id", b.name);
                        expected.rules_removed += 1;
                        expected.rules_added += 1;
                    }
                    other => panic!("changed rule {:?} planned as {other:?}", b.name),
                }
            }
            None => {
                assert_eq!(step, Step::Remove, "{:?}", b.name);
                expected.rules_removed += 1;
            }
        }
    }
    for a in after.iter() {
        if !before.iter().any(|b| same_slot(&b, &a)) {
            assert_eq!(planned(plan, &a).step, Step::Add, "{:?}", a.name);
            expected.rules_added += 1;
        }
    }
    assert_eq!(
        summary(events, &w.delta),
        expected,
        "the summary is the plan"
    );

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

/// The event bytes a plan prices.
fn priced(plan: &[PlannedRule]) -> u32 {
    plan.iter().map(|p| p.cost.events).sum()
}

fn plan_of(
    w: &DeltaWorld,
    account: &Address,
    doc: &DocModel,
    mode: Mode,
) -> std::vec::Vec<PlannedRule> {
    w.plan(account, doc, mode).iter().collect()
}

/// Apply `b` over `a` on both accounts; check the delta's accounting against
/// its plan, that the cost model priced its events to the byte, and that it
/// emits no more event bytes and writes no more entries than the full
/// replace.
fn transition(w: &DeltaWorld, a: &DocModel, b: &DocModel) {
    apply_both(w, a);
    let before = w.installed(&w.delta);
    let plan = plan_of(w, &w.delta, b, Mode::Cheapest);
    let raw_before = raw_entries(&w.env);
    w.apply(&w.delta, b).unwrap();
    let events = w.events();
    let (delta_priced, delta_bytes) = event_bytes(&w.env);
    let delta_writes = w.env.cost_estimate().resources().write_entries;
    let changed_keys = changed(&raw_before, &raw_entries(&w.env));
    let after = w.installed(&w.delta);
    check_accounting(w, &before, &after, &plan, &events, &changed_keys);
    assert_eq!(
        delta_priced,
        priced(&plan),
        "the model prices the events exactly"
    );
    w.apply(&w.oracle, b).unwrap();
    let (_, oracle_bytes) = event_bytes(&w.env);
    let oracle_writes = w.env.cost_estimate().resources().write_entries;
    assert!(
        delta_bytes <= oracle_bytes,
        "delta emitted {delta_bytes} event bytes, full replace {oracle_bytes}"
    );
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

/// `b` over `a` with every changed rule forced down one path, on the oracle
/// account (after `a` by full replace). Returns the plan for that path and
/// the priced event bytes measured; checks the state is the full replace's.
fn forced(a: &DocModel, b: &DocModel, in_place: bool) -> (std::vec::Vec<PlannedRule>, u32) {
    let w = DeltaWorld::new();
    w.apply(&w.oracle, a).unwrap();
    let mode = if in_place {
        Mode::InPlace
    } else {
        Mode::Replace
    };
    let plan = plan_of(&w, &w.oracle, b, mode);
    w.apply_forced(b, in_place).unwrap();
    let (measured, _) = event_bytes(&w.env);
    w.apply(&w.delta, a).unwrap();
    w.apply(&w.delta, b).unwrap();
    same_state(
        &storage_state(&w.env, &w.delta, History::Keep),
        &storage_state(&w.env, &w.oracle, History::Keep),
        "a forced path ends where the cheapest one does",
    );
    (plan, measured)
}

proptest! {
    #![proptest_config(config(48))]

    /// Every transition takes the cheaper path for each changed rule, emits
    /// exactly that path's events (priced to the byte), writes nothing keyed
    /// by an unchanged rule, and emits and writes no more than the full
    /// replace.
    #[test]
    fn events_and_writes_are_exactly_the_diff(a in bytes(), b in bytes()) {
        let w = DeltaWorld::new();
        transition(&w, &gen_doc(&a), &gen_doc(&b));
    }

    /// Both paths the choice compares are priced exactly: forcing every
    /// changed rule in place, or every one replaced, emits exactly the
    /// bytes the model priced for that path, and reaches the same state.
    #[test]
    fn both_paths_are_priced_exactly(a in bytes(), b in bytes()) {
        let (a, b) = (gen_doc(&a), gen_doc(&b));
        for in_place in [true, false] {
            let (plan, measured) = forced(&a, &b, in_place);
            prop_assert_eq!(measured, priced(&plan), "in_place: {}", in_place);
        }
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
    let plan = plan_of(w, &w.delta, b, Mode::Cheapest);
    let raw_before = raw_entries(&w.env);
    w.apply(&w.delta, b).unwrap();
    let events = w.events();
    let (measured, _) = event_bytes(&w.env);
    let changed_keys = changed(&raw_before, &raw_entries(&w.env));
    let after = w.installed(&w.delta);
    check_accounting(w, &before, &after, &plan, &events, &changed_keys);
    assert_eq!(
        measured,
        priced(&plan),
        "the model prices the events exactly"
    );
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

/// The rule-set change `DocApplied` reports, from the rendered events. The
/// OZ mutations emit nothing on the quiet path, so this is the record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Summary {
    rules_added: usize,
    rules_removed: usize,
    rules_edited: usize,
    signers_added: usize,
    signers_removed: usize,
    policies_added: usize,
    policies_removed: usize,
}

fn summary(events: &[Event], account: &Address) -> Summary {
    let me = contract_hex(account);
    let e = events
        .iter()
        .find(|e| e.contract == me && e.name == "doc_applied")
        .expect("apply_doc emits DocApplied");
    let field = |key: &str| -> usize {
        e.data
            .trim_matches(|c| c == '{' || c == '}')
            .split(',')
            .find_map(|kv| kv.strip_prefix(&format!("{key}:")))
            .unwrap_or_else(|| panic!("DocApplied has no {key}: {}", e.data))
            .parse()
            .unwrap()
    };
    Summary {
        rules_added: field("rules_added"),
        rules_removed: field("rules_removed"),
        rules_edited: field("rules_edited"),
        signers_added: field("signers_added"),
        signers_removed: field("signers_removed"),
        policies_added: field("policies_added"),
        policies_removed: field("policies_removed"),
    }
}

/// What the account's `DocApplied` summary says changed, as a sorted
/// multiset of item names (`rule_edited` for a rule edited in place). The
/// delta's order of operations is its own business; the multiset is the
/// contract. Also checks that nothing but `DocApplied` was emitted.
fn names(events: &[Event], account: &Address) -> std::vec::Vec<String> {
    let me = contract_hex(account);
    assert!(
        events
            .iter()
            .filter(|e| e.contract == me)
            .all(|e| e.name == "doc_applied"),
        "per-item events from the quiet path: {events:?}"
    );
    let s = summary(events, account);
    let mut out = std::vec::Vec::new();
    for (name, n) in [
        ("context_rule_added", s.rules_added),
        ("context_rule_removed", s.rules_removed),
        ("rule_edited", s.rules_edited),
        ("signer_added", s.signers_added),
        ("signer_removed", s.signers_removed),
        ("policy_added", s.policies_added),
        ("policy_removed", s.policies_removed),
    ] {
        out.extend(std::iter::repeat_n(name.to_string(), n));
    }
    out.sort();
    out
}

fn sorted(names: &[&str]) -> std::vec::Vec<String> {
    let mut out: std::vec::Vec<String> = names.iter().map(|n| n.to_string()).collect();
    out.sort();
    out
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
    // A policy-only edit: no signer changes, so no signer batch at all. The
    // interpreter is this rule's alone, so OZ deregisters it as the old
    // program goes and registers it again as the new one comes.
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["policy_removed", "policy_added", "rule_edited"])
    );
}

#[test]
fn a_rule_keeping_its_name_with_a_new_scope_is_replaced() {
    let (w, events, before, after) = case(
        &doc(
            delegated(1),
            std::vec![admin(&[0]), rule("r1", Some(0), &[0])],
        ),
        &doc(
            delegated(1),
            std::vec![admin(&[0]), rule("r1", Some(1), &[0])],
        ),
    );
    assert_ne!(id_of(&before, "r1"), id_of(&after, "r1"));
    let n = names(&events, &w.delta);
    assert!(n.contains(&"context_rule_removed".into()) && n.contains(&"context_rule_added".into()));
}

#[test]
fn new_cap_parameters_replace_only_that_rule() {
    let mut a = rule("r1", Some(0), &[0]);
    a.cap = Some((1_000, 100));
    let mut b = a.clone();
    b.cap = Some((2_000, 100));
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), a]),
        &doc(delegated(1), std::vec![admin(&[0]), b]),
    );
    // The cap is part of the rule's text, so both of the rule's policies are
    // reinstalled either way: the spending limit for its new parameters, the
    // interpreter for its new rule-hash provenance. With no events to price
    // (the quiet path), editing the rule's two policies writes less than
    // replacing it, so it keeps its id. The admin rule is not touched.
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&[
            "policy_removed",
            "policy_removed",
            "policy_added",
            "policy_added",
            "rule_edited",
        ])
    );
}

#[test]
fn adding_a_signer_to_a_rule_emits_only_that_signer() {
    let (w, events, before, after) = case(
        &doc(
            delegated(2),
            std::vec![admin(&[0]), rule("r1", Some(0), &[0])],
        ),
        &doc(
            delegated(2),
            std::vec![admin(&[0]), rule("r1", Some(0), &[0, 1])],
        ),
    );
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["signer_added", "rule_edited"])
    );
}

#[test]
fn adding_several_signers_is_one_batch() {
    // Up to the signer cap.
    let n = MAX_DOC_SIGNERS as usize;
    let added = n - 3;
    let all: std::vec::Vec<usize> = (0..n).collect();
    let a = doc(delegated(3), std::vec![admin(&[0, 1, 2])]);
    let b = doc(delegated(n), std::vec![admin(&all)]);
    let w = DeltaWorld::new();
    w.apply(&w.delta, &a).unwrap();
    let plan = plan_of(&w, &w.delta, &b, Mode::Cheapest);
    // One `batch_add_signer`: one rule write, then each new signer's registry
    // and lookup entries.
    assert_eq!(plan[0].step, Step::InPlace);
    assert_eq!(plan[0].cost.writes, 1 + added as u32 * 2);
    let (w, events, before, after) = case(&a, &b);
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    // The summary counts the additions; registrations are not reported.
    let mut expected = std::vec!["signer_added"; added];
    expected.push("rule_edited");
    assert_eq!(names(&events, &w.delta), sorted(&expected));
}

#[test]
fn a_signer_shared_by_several_rules_changes_in_one_and_stays_in_the_others() {
    let a = doc(
        delegated(2),
        std::vec![
            admin(&[0, 1]),
            rule("r1", Some(0), &[1]),
            rule("r2", Some(1), &[1])
        ],
    );
    let b = doc(
        delegated(2),
        std::vec![
            admin(&[0, 1]),
            rule("r1", Some(0), &[0]),
            rule("r2", Some(1), &[1])
        ],
    );
    let (w, events, before, after) = case(&a, &b);
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    // s1 is still referenced (admin, r2), so it is neither deregistered nor
    // registered again; owner was already registered (admin).
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["signer_removed", "signer_added", "rule_edited"])
    );
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
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["policy_removed", "policy_added", "rule_edited"])
    );
    let r2_id = id_of(&after, "r2");
    let interpreter = perch_interpreter::PerchInterpreterClient::new(&w.env, &w.interpreter);
    assert!(interpreter.get_program(&w.delta, &r2_id).is_some());
}

#[test]
fn a_renamed_rule_is_removed_and_added() {
    let (w, events, before, after) = case(
        &doc(
            delegated(1),
            std::vec![admin(&[0]), rule("r1", Some(0), &[0])],
        ),
        &doc(
            delegated(1),
            std::vec![admin(&[0]), rule("r2", Some(0), &[0])],
        ),
    );
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["context_rule_removed", "context_rule_added"])
    );
}

#[test]
fn a_rule_removed_and_added_back_gets_a_new_id_and_the_same_grant() {
    let with = doc(
        delegated(1),
        std::vec![admin(&[0]), rule("r1", Some(0), &[0])],
    );
    let without = doc(delegated(1), std::vec![admin(&[0])]);
    let (w, _, first, _) = case(&with, &without);
    let (_w, _, _, again) = transition_after(&w, &with, w.installed(&w.delta));
    assert_ne!(id_of(&first, "r1"), id_of(&again, "r1"));
}

#[test]
fn a_signer_keeping_its_id_with_a_new_key_is_swapped_in_every_rule_that_names_it() {
    let a = doc(
        delegated(2),
        std::vec![
            admin(&[0]),
            rule("r1", Some(0), &[1]),
            rule("r2", Some(1), &[0, 1])
        ],
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
        sorted(&["signer_added", "signer_removed", "rule_edited"])
    );
}

/// `n` declared signers using keys `first..first + n` of the pool.
fn delegated_keys(n: usize, first: usize) -> std::vec::Vec<SignerModel> {
    (0..n)
        .map(|i| SignerModel {
            id: SIGNER_IDS[i],
            key: KeyModel::Delegated(first + i),
        })
        .collect()
}

/// Every key of an `old`-signer admin rule swapped for `new` fresh keys:
/// the documents, and the plan an in-place-only apply would make.
fn full_swap(old: usize, new: usize) -> PlannedRule {
    let ids: std::vec::Vec<usize> = (0..old).collect();
    let a = doc(delegated_keys(old, 0), std::vec![admin(&ids)]);
    let ids: std::vec::Vec<usize> = (0..new).collect();
    let b = doc(delegated_keys(new, old), std::vec![admin(&ids)]);
    let w = DeltaWorld::new();
    w.apply(&w.delta, &a).unwrap();
    plan_of(&w, &w.delta, &b, Mode::InPlace).remove(0)
}

#[test]
fn an_edit_where_nothing_survives_re_adds_a_changed_policy_after_the_new_ones() {
    // Every part of r1 changes: its signer, its interpreter program (new
    // functions), and a new cap. Nothing survives, so an in-place edit adds
    // the new signer and the new spending limit first, removes the old
    // signer and program, and only then re-adds the interpreter. Forced in
    // place, it must still reach the full replace's state, priced exactly.
    let mut a = rule("r1", Some(0), &[1]);
    a.functions = Some(std::vec!["transfer"]);
    let mut b = rule("r1", Some(0), &[2]);
    b.functions = Some(std::vec!["transfer", "approve"]);
    b.cap = Some((1_000, 100));
    let a = doc(delegated(3), std::vec![admin(&[0]), a]);
    let b = doc(delegated(3), std::vec![admin(&[0]), b]);
    let (plan, measured) = forced(&a, &b, true);
    let r1 = plan.iter().find(|p| p.step == Step::InPlace).unwrap();
    assert!(r1.editable);
    assert_eq!(measured, priced(&plan));
}

#[test]
fn a_full_swap_can_be_edited_in_place_up_to_the_signer_limit() {
    // Nothing survives, so an in-place edit adds before it removes: at the
    // signer cap the peak is twice the cap, and an in-place order exists
    // while that is within OZ's per-rule limit (15), as it is at the caps.
    let n = MAX_DOC_SIGNERS as usize;
    let p = full_swap(n, n);
    assert_eq!(p.editable, 2 * n <= 15);
    assert_eq!(
        p.step,
        if p.editable {
            Step::InPlace
        } else {
            Step::Replace
        }
    );
}

/// The rule `name`'s planned step for `a`→`b` under the cheapest apply, and
/// the priced event bytes measured for the cheapest apply, the in-place
/// edit, and the replacement.
fn crossover(a: &DocModel, b: &DocModel, name: &str) -> (Step, u32, u32, u32) {
    let w = DeltaWorld::new();
    w.apply(&w.delta, a).unwrap();
    let plan = plan_of(&w, &w.delta, b, Mode::Cheapest);
    w.apply(&w.delta, b).unwrap();
    let (cheapest, _) = event_bytes(&w.env);
    let step = plan
        .iter()
        .find(|p| p.name == soroban_sdk::String::from_str(&w.env, name))
        .unwrap()
        .step;
    let (_, in_place) = forced(a, b, true);
    let (_, replaced) = forced(a, b, false);
    (step, cheapest, in_place, replaced)
}

/// Signers `from..from + k` of `a` with fresh keys, ids unchanged: a key
/// rotation, which leaves every rule's text (and so its policies) as is.
fn rotate(a: &DocModel, from: usize, k: usize) -> DocModel {
    let mut b = a.clone();
    for i in from..from + k {
        b.signers[i].key = KeyModel::Delegated(10 + i);
    }
    b
}

/// Rotate 1..=n keys of a rule; at each count the apply emits exactly the
/// cheaper path's bytes. Returns the steps taken.
fn sweep(a: &DocModel, name: &str, from: usize, n: usize) -> std::vec::Vec<Step> {
    let mut steps = std::vec::Vec::new();
    for k in 1..=n {
        let (step, cheapest, in_place, replaced) = crossover(a, &rotate(a, from, k), name);
        assert_eq!(cheapest, in_place.min(replaced), "{k} of {n} keys");
        assert_eq!(
            step == Step::InPlace,
            in_place <= replaced,
            "{k} of {n} keys"
        );
        steps.push(step);
    }
    steps
}

#[test]
#[ignore = "quiet-events experiment: these pin event-priced crossovers; with no OZ events the model chooses by writes"]
fn rotating_the_admin_rules_keys_switches_to_replacement_where_it_is_cheaper() {
    // A policy-free rule: replacing it costs a removal and an addition (100
    // and 332 bytes) plus 288 to deregister and re-register each key it
    // keeps; editing it costs 244 per rotated key. Registering the new keys
    // and deregistering the old costs the same either way. One or two
    // rotated keys: 244 or 488 in place against 1 008 or 720 to replace.
    // All three: 732 against 432.
    let a = doc(delegated(3), std::vec![admin(&[0, 1, 2])]);
    assert_eq!(
        sweep(&a, "admin", 0, 3),
        [Step::InPlace, Step::InPlace, Step::Replace]
    );
}

#[test]
#[ignore = "quiet-events experiment: these pin event-priced crossovers; with no OZ events the model chooses by writes"]
fn rotating_a_capped_rules_keys_switches_to_replacement_where_it_is_cheaper() {
    // A rule with both policies: replacing it also reinstalls and
    // re-registers the interpreter and the spending limit, so in-place edits
    // stay cheaper for more rotated keys.
    // The largest such rule the caps admit: every signer but the admin's.
    let n = MAX_DOC_SIGNERS as usize - 1;
    let keys: std::vec::Vec<usize> = (1..=n).collect();
    let mut capped = rule("r1", Some(0), &keys);
    capped.functions = Some(std::vec!["transfer"]);
    capped.cap = Some((1_000, 100));
    let a = doc(delegated(n + 1), std::vec![admin(&[0]), capped]);
    // Each rotated key costs 532 bytes in place (an addition and a removal,
    // and a registration and deregistration either path pays). Replacing
    // costs the same whatever the count: the removal and addition (484), the
    // policies' reinstallation and re-registration (928), and 288 to
    // deregister and re-register each of the rule's keys. With eight keys
    // six rotate in place and seven or eight replace the rule; at the caps
    // (five keys) every rotation stays in place.
    let replace = 484 + 928 + 288 * n;
    let expected: std::vec::Vec<Step> = (1..=n)
        .map(|k| {
            if 532 * k <= replace {
                Step::InPlace
            } else {
                Step::Replace
            }
        })
        .collect();
    assert_eq!(sweep(&a, "r1", 1, n), expected);
}

#[test]
fn minimal_and_maximal_documents_round_trip() {
    let minimal = doc(delegated(1), std::vec![admin(&[0])]);
    // At the document caps.
    let (n_signers, n_rules) = (MAX_DOC_SIGNERS as usize, MAX_DOC_RULES as usize);
    let mut rules = std::vec![admin(&[0, 1 % n_signers, 2 % n_signers])];
    for (i, name) in RULE_NAMES.iter().take(n_rules - 1).enumerate() {
        let mut r = rule(
            name,
            Some(i % SCOPE_POOL),
            &[i % n_signers, (i + 1) % n_signers, (i + 2) % n_signers],
        );
        if i % 3 == 0 {
            r.functions = Some(std::vec!["transfer"]);
        }
        if i % 4 == 1 {
            r.cap = Some((1_000, 100));
        }
        rules.push(r);
    }
    let mut maximal = doc(delegated(n_signers), rules);
    maximal.recovery = Some(RecoveryModel {
        quorum: 2,
        delay: 10,
        expiry: 100,
        max_cancels: 3,
    });
    let (w, _, _, after) = case(&minimal, &maximal);
    assert_eq!(
        after.len() as usize,
        n_rules + 1,
        "the document's rules and the recovery rule"
    );
    let (w, _, _, back) = transition_after(&w, &minimal, w.installed(&w.delta));
    assert_eq!(back.len(), 1);
    let (_w, _, _, again) = transition_after(&w, &maximal, w.installed(&w.delta));
    assert_eq!(again.len() as usize, n_rules + 1);
}

#[test]
fn reformatting_the_same_document_is_a_no_op() {
    let w = DeltaWorld::new();
    let d = doc(
        delegated(2),
        std::vec![admin(&[0]), rule("r1", Some(0), &[1])],
    );
    w.apply(&w.delta, &d).unwrap();
    let before = raw_entries(&w.env);
    // Insignificant whitespace and member order: the canonical form, and so
    // the document, is unchanged.
    let json = d.json(&w);
    let reformatted = json
        .replacen(r#"{"version":1,"#, "{ \n  \"version\" : 1 ,", 1)
        .replace(r#"{"name":"r1","#, r#"{ "name" : "r1" , "#);
    let out = perch_account::PerchAccountClient::new(&w.env, &w.delta).apply_doc(
        &soroban_sdk::Bytes::from_slice(&w.env, reformatted.as_bytes()),
        &0,
    );
    // The apply's own events, before the next call replaces them.
    let events = w.events();
    assert_eq!(
        Some(out),
        perch_account::PerchAccountClient::new(&w.env, &w.delta).applied_doc_hash()
    );
    assert!(names(&events, &w.delta).is_empty());
    assert!(changed(&before, &raw_entries(&w.env)).is_empty());
}

#[test]
fn reordering_rules_changes_the_document_but_touches_no_rule() {
    let a = doc(
        delegated(2),
        std::vec![
            admin(&[0]),
            rule("r1", Some(0), &[1]),
            rule("r2", Some(1), &[0])
        ],
    );
    let mut b = a.clone();
    b.rules.swap(1, 2);
    let (w, events, before, after) = case(&a, &b);
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    assert!(
        names(&events, &w.delta).is_empty(),
        "only the record and the document change"
    );
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
    assert_eq!(names(&events, &w.delta), sorted(&["rule_edited"]));
}

#[test]
fn recovery_changes_edit_only_the_recovery_rule() {
    let mut a = doc(
        delegated(1),
        std::vec![admin(&[0]), rule("r1", Some(0), &[0])],
    );
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
        sorted(&["context_rule_removed", "context_rule_added"])
    );
}
