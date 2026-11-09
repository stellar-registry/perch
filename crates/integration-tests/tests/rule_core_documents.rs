//! rule-core's document traces (`conformance/vectors/documents` at the rev
//! the workspace pins), and Perch's own in the same format
//! (`rule_core/documents`, whose expectations rule-core's runner checks),
//! through Perch's real pipeline (`rule_core/mod.rs`).
//!
//! Each trace runs twice: on a fresh account, and on one whose applied
//! document (for a scoped trace, whose scope) has other rule names (the delta
//! then adds every rule and removes every earlier one). An admin trace's
//! document goes through `apply_doc`; a scoped trace's through `apply_grant`
//! under the trace's account document and generation. Whether Perch refuses
//! the document, its lowering of the document's rules, each verdict, and
//! each accepted authorization's spending records must equal the trace's,
//! which rule-core's Lean model computed, refined as the account refines the
//! model: a capped rule, and a grant's rule for a token function whose
//! argument 0 is the owner, act only when argument 0 is the account
//! (`rule_core::refined`): the records are the ones the
//! account keeps, which rule-eval charges. After every apply the account's
//! stored rule-eval rule set for the document must equal the lowering of its
//! model and the denotation of what it installed (`perch_testkit::rule_set`).
//! `__check_auth` decides with rule-eval over those sets, and after every
//! accepted authorization the account must keep a record only for a rule
//! stored with a cap (`perch_testkit::rule_set::check_records`). Every
//! difference is reported, by trace and authorization.

mod rule_core;
mod support;

use rule_core::{differences, expected, refined, run, Start};
use rule_eval_conformance::documents;

/// rule-core's traces and Perch's own.
fn traces() -> Vec<(std::path::PathBuf, documents::Trace)> {
    let mut traces = documents::load_dir(&rule_core::vectors().join("documents"))
        .unwrap_or_else(|e| panic!("{e}"));
    traces
        .extend(documents::load_dir(&rule_core::perch_vectors()).unwrap_or_else(|e| panic!("{e}")));
    traces
}

/// Perch's own traces state what rule-core's model gives: its runner
/// lowers each document and replays each authorization against them.
#[test]
fn perch_traces_agree_with_rule_core() {
    let traces = documents::load_dir(&rule_core::perch_vectors()).unwrap_or_else(|e| panic!("{e}"));
    assert!(!traces.is_empty());
    for (path, t) in &traces {
        documents::check(t).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn every_document_trace_agrees_with_perch() {
    let traces = traces();
    let (mut admin, mut scoped, mut refused, mut recovery) = (0, 0, 0, 0);
    let (mut authorizations, mut delegated, mut external, mut empty) = (0, 0, 0, 0);
    let (mut rule_sets, mut stored_rules) = (0, 0);
    let (mut records, mut charged) = (0, 0);
    let mut refinements = 0;
    let mut failures = vec![];
    for (_, t) in &traces {
        refinements += refined(t)
            .iter()
            .zip(&t.authorizations)
            .filter(|(got, a)| **got != expected(&a.expected))
            .count();
        if t.scoped.is_some() {
            scoped += 1;
            refused += usize::from(matches!(t.lowered, documents::Lowered::Error(_)));
        } else {
            admin += 1;
            recovery += usize::from(t.document.recovery.is_some());
        }
        for start in [Start::Fresh, Start::AfterPredecessor] {
            match run(t, start) {
                Ok(r) => {
                    authorizations += r.verdicts.len();
                    delegated += r.delegated;
                    external += r.external;
                    empty += r.empty;
                    rule_sets += r.rule_sets;
                    stored_rules += r.stored_rules;
                    records += r.records_compared;
                    charged += r.records_charged;
                    for d in differences(t, &r) {
                        failures.push(format!("{} ({start:?}): {d}", t.name));
                    }
                }
                Err(e) => failures.push(format!("{} ({start:?}): {e}", t.name)),
            }
        }
    }
    println!(
        "traces: {}, admin traces run: {admin} (with recovery: {recovery}), scoped traces run: \
         {scoped} (refused: {refused}), authorizations run: {authorizations} (with a delegated \
         signer: {delegated}, with an external signer: {external}, of an empty batch: {empty}), \
         rule sets checked: {rule_sets} ({stored_rules} rules), records compared: {records} \
         (holding a spend: {charged}), verdicts the refinement changes: {refinements}, \
         differences: {}",
        traces.len(),
        failures.len()
    );
    assert!(admin > 0, "no admin trace found");
    assert!(refinements > 0, "the refinement changed no verdict");
    assert!(scoped > refused, "no scoped trace that authorizes found");
    assert!(charged > 0, "no charged record compared");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // An admin trace applies one document on a fresh account and two after
    // a predecessor; a scoped trace also applies its account document first,
    // and a grant document Perch refuses stores nothing.
    assert_eq!(rule_sets, 3 * admin + 5 * (scoped - refused) + 3 * refused);
}

/// The comparison is not vacuous: a trace whose expected verdict, records or
/// lowering is changed is reported.
#[test]
fn a_changed_expectation_is_reported() {
    let path = rule_core::perch_vectors().join("perch-capped-own-transfers.json");
    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let parse =
        |v: &serde_json::Value| -> documents::Trace { serde_json::from_value(v.clone()).unwrap() };
    let check = |v: serde_json::Value, what: &str| {
        let t = parse(&v);
        let r = run(&t, Start::Fresh).unwrap();
        assert!(!differences(&t, &r).is_empty(), "{what} passed");
    };
    let t = parse(&original);
    assert!(differences(&t, &run(&t, Start::Fresh).unwrap()).is_empty());

    let accepted = original["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .position(|a| a["expected"].get("ok").is_some())
        .expect("an accepted authorization");
    let mut v = original.clone();
    v["authorizations"][accepted]["expected"] = serde_json::json!("refused");
    check(v, "a flipped verdict");

    let mut v = original.clone();
    let records = v["authorizations"][accepted]["expected"]["ok"]
        .as_array_mut()
        .unwrap();
    let capped = records
        .iter()
        .position(|r| !r["history"].as_array().unwrap().is_empty())
        .expect("a charged record");
    records[capped]["total"] = serde_json::json!("999");
    check(v, "a changed total");

    let mut v = original.clone();
    v["lowered"]["ok"][1]["threshold"] = serde_json::json!(7);
    check(v, "a changed lowered rule");
}

/// The scoped leg is not vacuous either: a refused grant document said to
/// lower, an accepted authorization moved to a later generation, and a
/// grant rule's generation changed are each reported.
#[test]
fn a_changed_scoped_expectation_is_reported() {
    let load = |name: &str| -> serde_json::Value {
        let path = rule_core::vectors().join(format!("documents/{name}.json"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    };
    let parse =
        |v: &serde_json::Value| -> documents::Trace { serde_json::from_value(v.clone()).unwrap() };
    let check = |v: serde_json::Value, what: &str| {
        let t = parse(&v);
        let r = run(&t, Start::Fresh).unwrap();
        assert!(!differences(&t, &r).is_empty(), "{what} passed");
    };

    let refused = load("document-scoped-controller");
    let t = parse(&refused);
    assert!(differences(&t, &run(&t, Start::Fresh).unwrap()).is_empty());
    let mut v = refused.clone();
    v["lowered"] = serde_json::json!({ "ok": [] });
    check(v, "a refused grant document said to lower");

    let issued = load("document-scoped-issued");
    let t = parse(&issued);
    assert!(differences(&t, &run(&t, Start::Fresh).unwrap()).is_empty());

    // An authorization the account accepts, under a grant issued in
    // generation 0: Perch's own trace, since the account refines every
    // accepted authorization of rule-core's scoped traces that names a
    // rule (`rule_core::refined`).
    let path = rule_core::perch_vectors().join("perch-grant-own-funds.json");
    let own: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let t = parse(&own);
    assert!(differences(&t, &run(&t, Start::Fresh).unwrap()).is_empty());
    let mut v = own.clone();
    v["authorizations"][0]["generation"] = serde_json::json!("1");
    check(v, "an authorization in a later generation");

    let mut v = own.clone();
    v["lowered"]["ok"][0]["generation"] = serde_json::json!("1");
    check(v, "a changed grant rule generation");
}
