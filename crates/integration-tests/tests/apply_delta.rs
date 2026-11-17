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
//! - After every generated apply, on both accounts, the stored rule-eval
//!   rule set equals the lowering of the document's model and the
//!   denotation of the account's context rules with the programs and caps
//!   the compiler emits for them (`perch_testkit::rule_set`), signer order
//!   included.
//!
//! Proptest case counts default low enough for CI; set `PERCH_DELTA_CASES`
//! to run more.

use arbitrary::Unstructured;
use perch_doc_compiler::{MAX_DOC_RULES, MAX_DOC_SIGNERS};
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
    // The oracle shares compile and the desired rule set with the delta;
    // the model's own grant shares neither.
    if delta.is_ok() {
        for account in [&w.delta, &w.oracle] {
            if let Err(x) = perch_testkit::rule_set::check(&w.env, account) {
                panic!("the stored rule set for {d:?}: {x}");
            }
        }
        assert_eq!(
            live_rules(w, &w.delta),
            d.expected_rules(w, &w.delta),
            "the delta account's live rules vs the model's grant for {d:?}"
        );
        assert_eq!(
            live_rules(w, &w.oracle),
            d.expected_rules(w, &w.oracle),
            "the full replace's live rules vs the model's grant for {d:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Oracle equivalence
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(48))]

    /// For any sequence of documents, with the ledger advancing between
    /// them past rule expiries, the delta account and the full-replace
    /// oracle accept and refuse the same documents and end every step with
    /// identical normalized storage: rules, signers, policies and their
    /// parameters, registries, the canonical applied document, and the
    /// recovery wiring. Both grant exactly the rules the model computes.
    #[test]
    fn delta_apply_matches_full_replace(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let w = DeltaWorld::new();
        for (advance, d) in DocModel::sequence(&mut Unstructured::new(&bytes), 5).unwrap() {
            w.advance(advance);
            apply_both(&w, &d);
        }
    }
}

// ---------------------------------------------------------------------------
// Algebra
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(32))]

    /// Re-applying the applied document writes nothing but the advanced
    /// configuration revision and emits nothing but the account's own
    /// `DocApplied`.
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
        // The entries an authorized apply always writes: its auth nonce, and
        // the instance for the revision.
        prop_assert_eq!(written, 2);
        prop_assert_eq!(changed(&before, &raw_entries(&w.env)), only_the_instance(&w));
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
        // A rule keeps its signers in its document's order, so a reorder is
        // a change.
        && a.signers == b.signers
        && policy_set(a) == policy_set(b)
        && a.valid_until == b.valid_until
}

/// Whether changed rule `b` keeps its id as `a`: always, except a recovery
/// rule keeping its controller under a new configuration, the one rule
/// OZ's registry installed again under a new id.
fn keeps_id(b: &InstalledRule, a: &InstalledRule) -> bool {
    let controllers = |r: &InstalledRule| -> BTreeSet<String> {
        r.policies
            .iter()
            .map(|p| format!("{:?}", p.policy))
            .collect()
    };
    !b.recovery || !controllers(a).is_subset(&controllers(b))
}

/// The account's own entries keyed by rule `id`, as [`raw_entries`] names
/// them: the spending record and the scope tag.
fn keyed_by(me: &str, id: u32) -> [String; 2] {
    [
        format!("{me}/[SpendRecords,{id}]"),
        format!("{me}/[GrantTags,{id}]"),
    ]
}

/// Check one transition's events and writes against the rule diff: each
/// rule kept, edited in place, installed again under a new id, removed, or
/// added as the id rule says, the `DocApplied` summary exactly that, and no
/// entry keyed by an unchanged rule written.
fn check_accounting(
    w: &DeltaWorld,
    before: &soroban_sdk::Vec<InstalledRule>,
    after: &soroban_sdk::Vec<InstalledRule>,
    events: &[Event],
    changed_keys: &[String],
) {
    let me = contract_hex(&w.delta);
    // Rule changes publish nothing of their own, so the account's only event
    // is `DocApplied`, whose summary must be exactly what the diff of the
    // records says was done.
    let ours: std::vec::Vec<&Event> = events.iter().filter(|e| e.contract == me).collect();
    assert!(
        ours.iter().all(|e| e.name == "doc_applied"),
        "per-item events: {ours:?}"
    );
    let mut expected = Summary::default();
    let mut untouched_ids: std::vec::Vec<u32> = std::vec::Vec::new();

    for b in before.iter() {
        match after.iter().find(|a| same_slot(&b, a)) {
            Some(a) if same_content(&b, &a) => {
                assert_eq!(a.id, b.id, "unchanged rule {:?} keeps its id", b.name);
                untouched_ids.push(b.id);
            }
            Some(a) if keeps_id(&b, &a) => {
                assert_eq!(a.id, b.id, "{:?} edited in place keeps its id", b.name);
                let (sb, sa) = (signer_set(&b), signer_set(&a));
                let (pb, pa) = (policy_set(&b), policy_set(&a));
                expected.rules_edited += 1;
                expected.signers_added += sa.difference(&sb).count();
                expected.signers_removed += sb.difference(&sa).count();
                expected.policies_added += pa.difference(&pb).count();
                expected.policies_removed += pb.difference(&pa).count();
            }
            Some(a) => {
                assert!(a.id > b.id, "{:?} installed again gets a new id", b.name);
                expected.rules_removed += 1;
                expected.rules_added += 1;
            }
            None => expected.rules_removed += 1,
        }
    }
    for a in after.iter() {
        if !before.iter().any(|b| same_slot(&b, &a)) {
            assert!(
                before.iter().all(|b| b.id < a.id),
                "{:?} added gets a new id",
                a.name
            );
            expected.rules_added += 1;
        }
    }
    assert_eq!(
        summary(events, &w.delta),
        expected,
        "the summary is the diff"
    );

    // Nothing keyed by an unchanged rule's id was written: OZ's entry kept
    // for it, its spending record, its scope tag, or another contract's
    // state for it.
    for id in untouched_ids {
        let by_id = format!("{me},{id}]");
        for k in changed_keys {
            assert!(
                !keyed_by(&me, id).contains(k) && !k.ends_with(&by_id),
                "storage of an unchanged rule (id {id}) was written: {k}"
            );
        }
    }
}

/// Apply `b` over `a` on both accounts; check the delta's accounting against
/// the rule diff, and that it emits no more event bytes and writes no more
/// entries than the full replace.
fn transition(w: &DeltaWorld, a: &DocModel, b: &DocModel) {
    apply_both(w, a);
    let before = w.installed(&w.delta);
    let raw_before = raw_entries(&w.env);
    w.apply(&w.delta, b).unwrap();
    let events = w.events();
    let delta_bytes = event_bytes(&w.env);
    let delta_writes = w.env.cost_estimate().resources().write_entries;
    let changed_keys = changed(&raw_before, &raw_entries(&w.env));
    let after = w.installed(&w.delta);
    check_accounting(w, &before, &after, &events, &changed_keys);
    if let Err(x) = perch_testkit::rule_set::check(&w.env, &w.delta) {
        panic!("the stored rule set after {b:?} over {a:?}: {x}");
    }
    w.apply(&w.oracle, b).unwrap();
    let oracle_bytes = event_bytes(&w.env);
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

proptest! {
    #![proptest_config(config(48))]

    /// Every transition keeps, edits, or installs again each rule as the id
    /// rule says, reports exactly that in `DocApplied`, writes nothing keyed
    /// by an unchanged rule, and emits and writes no more than the full
    /// replace.
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
        spelling: Spelling::default(),
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

/// The stored rule-eval rule of the installed rule named `name` on the
/// delta account.
fn stored(w: &DeltaWorld, name: &str) -> perch_smart_account::StoredRule {
    let client = perch_account::PerchAccountClient::new(&w.env, &w.delta);
    let at = client
        .installed_rules()
        .iter()
        .position(|r| !r.recovery && r.name == soroban_sdk::String::from_str(&w.env, name))
        .unwrap();
    client.rule_set().get(at as u32).unwrap()
}

#[test]
fn a_rule_keeping_its_name_with_new_functions_changes_only_its_stored_rule() {
    let mut a = rule("r1", Some(0), &[0]);
    a.functions = Some(std::vec!["transfer"]);
    let mut b = a.clone();
    b.functions = Some(std::vec!["transfer", "approve"]);
    let w = DeltaWorld::new();
    apply_both(&w, &doc(delegated(1), std::vec![admin(&[0]), a]));
    let old = stored(&w, "r1");
    let before = w.installed(&w.delta);
    let (w, events, _, after) = transition_after(
        &w,
        &doc(delegated(1), std::vec![admin(&[0]), b]),
        before.clone(),
    );
    // The record holds the rule's contract, signers and last ledger, none
    // of which changed, so no record changes: the stored rule alone does.
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert!(names(&events, &w.delta).is_empty());
    let new = stored(&w, "r1");
    assert_ne!(new.functions, old.functions);
    assert_eq!((new.signers, new.threshold), (old.signers, old.threshold));
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
fn new_cap_parameters_change_only_that_rules_stored_cap() {
    let mut a = rule("r1", Some(0), &[0]);
    a.cap = Some((1_000, 100));
    let mut b = a.clone();
    b.cap = Some((2_000, 100));
    let (w, events, before, after) = case(
        &doc(delegated(1), std::vec![admin(&[0]), a]),
        &doc(delegated(1), std::vec![admin(&[0]), b]),
    );
    // The cap lives in the stored rule, so no record changes and both keep
    // their ids; the record the old cap charged is dropped
    // (`gate.rs`).
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    assert!(names(&events, &w.delta).is_empty());
    let cap = stored(&w, "r1").cap.get(0).unwrap();
    assert_eq!((cap.limit, cap.period), (2_000, 100));
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
fn adding_several_signers_is_one_edit() {
    // Up to the signer cap.
    let n = MAX_DOC_SIGNERS as usize;
    let added = n - 3;
    let all: std::vec::Vec<usize> = (0..n).collect();
    let a = doc(delegated(3), std::vec![admin(&[0, 1, 2])]);
    let b = doc(delegated(n), std::vec![admin(&all)]);
    let (w, events, before, after) = case(&a, &b);
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    // The summary counts the additions, as one edit of the rule.
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
fn a_changed_rule_leaves_the_other_stored_rules_alone() {
    let mut r1 = rule("r1", Some(0), &[0]);
    r1.functions = Some(std::vec!["transfer"]);
    let mut r2 = rule("r2", Some(1), &[0]);
    r2.functions = Some(std::vec!["mint"]);
    let mut r1b = r1.clone();
    r1b.functions = Some(std::vec!["approve"]);
    let w = DeltaWorld::new();
    apply_both(
        &w,
        &doc(delegated(1), std::vec![admin(&[0]), r1, r2.clone()]),
    );
    let (admin_before, r2_before) = (stored(&w, "admin"), stored(&w, "r2"));
    let before = w.installed(&w.delta);
    let (w, events, _, after) = transition_after(
        &w,
        &doc(delegated(1), std::vec![admin(&[0]), r1b, r2]),
        before.clone(),
    );
    assert!(names(&events, &w.delta).is_empty());
    for name in ["admin", "r1", "r2"] {
        assert_eq!(id_of(&before, name), id_of(&after, name));
    }
    assert_eq!(stored(&w, "admin"), admin_before);
    assert_eq!(stored(&w, "r2"), r2_before);
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
    // survives; one `reconcile_signers` swaps the key, checking the final
    // set as a whole, so the rule is never empty.
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

#[test]
fn reordering_a_rules_signers_gives_the_record_and_the_view_the_new_order() {
    // The same signer set in a new order: a rule keeps the order its
    // document gives, so the rule is edited in place (no signer added or
    // removed) and the record and `get_context_rule` take the new order, as
    // a full replace would.
    let a = doc(delegated(3), std::vec![admin(&[0, 1, 2])]);
    let b = doc(delegated(3), std::vec![admin(&[2, 0, 1])]);
    let (w, events, before, after) = case(&a, &b);
    let id = id_of(&after, "admin");
    assert_eq!(id_of(&before, "admin"), id);
    assert_eq!(names(&events, &w.delta), sorted(&["rule_edited"]));
    let record = after.iter().find(|r| r.id == id).unwrap();
    assert_ne!(
        record.signers,
        before.iter().find(|r| r.id == id).unwrap().signers
    );
    let view = perch_account::PerchAccountClient::new(&w.env, &w.delta).get_context_rule(&id);
    assert_eq!(view.signers, record.signers);
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

#[test]
fn an_edit_where_nothing_survives_keeps_the_id() {
    // Every part of r1 changes: its signer, its functions, and a new cap.
    // The record's signer changes and the stored rule takes the rest; the
    // rule keeps its id and reaches the full replace's state.
    let mut a = rule("r1", Some(0), &[1]);
    a.functions = Some(std::vec!["transfer"]);
    let mut b = rule("r1", Some(0), &[2]);
    b.functions = Some(std::vec!["transfer", "approve"]);
    b.cap = Some((1_000, 100));
    let (w, events, before, after) = case(
        &doc(delegated(3), std::vec![admin(&[0]), a]),
        &doc(delegated(3), std::vec![admin(&[0]), b]),
    );
    assert_eq!(id_of(&before, "r1"), id_of(&after, "r1"));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["signer_added", "signer_removed", "rule_edited"])
    );
}

#[test]
fn a_full_swap_at_the_signer_cap_is_one_edit() {
    // Every key of the admin rule swapped for fresh ones, at the signer cap:
    // the rule keeps its id.
    let n = MAX_DOC_SIGNERS as usize;
    let ids: std::vec::Vec<usize> = (0..n).collect();
    let a = doc(delegated_keys(n, 0), std::vec![admin(&ids)]);
    let b = doc(delegated_keys(n, n), std::vec![admin(&ids)]);
    let (w, events, before, after) = case(&a, &b);
    assert_eq!(id_of(&before, "admin"), id_of(&after, "admin"));
    let mut expected = std::vec!["signer_added"; n];
    expected.extend(std::vec!["signer_removed"; n]);
    expected.push("rule_edited");
    assert_eq!(names(&events, &w.delta), sorted(&expected));
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
        &None,
    );
    // The apply's own events, before the next call replaces them.
    let events = w.events();
    assert_eq!(
        Some(out),
        perch_account::PerchAccountClient::new(&w.env, &w.delta).applied_doc_hash()
    );
    assert!(names(&events, &w.delta).is_empty());
    assert_eq!(
        changed(&before, &raw_entries(&w.env)),
        only_the_instance(&w)
    );
}

/// The one entry a no-op apply changes: the account's instance, for the
/// advanced revision.
fn only_the_instance(w: &DeltaWorld) -> std::vec::Vec<String> {
    std::vec![instance_key(&w.delta)]
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
    // The recovery rule keeps its controller under a new configuration, so
    // it is installed again under a new id.
    assert_ne!(recovery_id(&before), recovery_id(&after));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["context_rule_removed", "context_rule_added"])
    );
}

#[test]
fn a_new_controller_is_swapped_in_place() {
    let mut a = doc(delegated(1), std::vec![admin(&[0])]);
    a.recovery = Some(RecoveryModel {
        quorum: 1,
        delay: 10,
        expiry: 100,
        max_cancels: 3,
    });
    let w = DeltaWorld::new();
    apply_both(&w, &a);
    let before = w.installed(&w.delta);
    // The same document at another controller.
    let w = DeltaWorld {
        controller: w.env.register(perch_recovery::PerchRecovery, ()),
        ..w
    };
    let (w, events, _, after) = transition_after(&w, &a, before.clone());
    assert_eq!(recovery_id(&before), recovery_id(&after));
    assert_eq!(
        names(&events, &w.delta),
        sorted(&["policy_added", "policy_removed", "rule_edited"])
    );
    let id = recovery_id(&after);
    let view = perch_account::PerchAccountClient::new(&w.env, &w.delta).get_context_rule(&id);
    assert_eq!(
        view.policies,
        soroban_sdk::vec![&w.env, w.controller.clone()]
    );
}

fn recovery_id(rules: &soroban_sdk::Vec<InstalledRule>) -> u32 {
    rules.iter().find(|r| r.recovery).unwrap().id
}
