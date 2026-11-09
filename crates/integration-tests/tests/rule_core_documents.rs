//! rule-core's document traces (`conformance/vectors/documents` at the rev
//! the workspace pins) through Perch's real pipeline (`rule_core/mod.rs`).
//!
//! Each trace runs twice: on a fresh account, and on one whose applied
//! document (for a scoped trace, whose scope) has other rule names (the delta
//! then adds every rule and removes every earlier one). An admin trace's
//! document goes through `apply_doc`; a scoped trace's through `apply_scope`
//! under the trace's admin document and generation. Whether Perch refuses
//! the document, its lowering of the document's rules, each verdict, and
//! each accepted authorization's spending records must equal the trace's,
//! which rule-core's Lean model computed. After every apply the account's
//! stored rule-eval rule set for the document must equal the lowering of its
//! model and the denotation of what it installed (`perch_testkit::rule_set`).
//! `__check_auth` runs OZ and then rule-eval over those sets, both of which
//! must accept, and after every accepted authorization each capped rule's
//! rule-eval spending record must equal OZ's (records parity). Every
//! difference is reported, by trace and authorization.

mod rule_core;
mod support;

use rule_core::{differences, run, Start};
use rule_eval_conformance::documents;

#[test]
fn every_document_trace_agrees_with_perch() {
    let traces = documents::load_dir(&rule_core::vectors().join("documents"))
        .unwrap_or_else(|e| panic!("{e}"));
    let (mut admin, mut scoped, mut refused, mut recovery) = (0, 0, 0, 0);
    let (mut authorizations, mut delegated, mut external, mut empty) = (0, 0, 0, 0);
    let (mut rule_sets, mut stored_rules) = (0, 0);
    let (mut records, mut charged) = (0, 0);
    let mut failures = vec![];
    for (_, t) in &traces {
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
         (holding a spend: {charged}), differences: {}",
        traces.len(),
        failures.len()
    );
    assert!(admin > 0, "no admin trace found");
    assert!(scoped > refused, "no scoped trace that authorizes found");
    assert!(charged > 0, "no charged record compared");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // An admin trace applies one document on a fresh account and two after
    // a predecessor; a scoped trace also applies its admin document first,
    // and a scoped document Perch refuses stores nothing.
    assert_eq!(rule_sets, 3 * admin + 5 * (scoped - refused) + 3 * refused);
}

/// The comparison is not vacuous: a trace whose expected verdict, records or
/// lowering is changed is reported.
#[test]
fn a_changed_expectation_is_reported() {
    let path = rule_core::vectors().join("documents/document-capped-approve.json");
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

/// The scoped leg is not vacuous either: a refused scoped document said to
/// lower, an accepted authorization moved to a later generation, and a
/// scoped rule's generation changed are each reported.
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
    check(v, "a refused scoped document said to lower");

    let issued = load("document-scoped-issued");
    let t = parse(&issued);
    assert!(differences(&t, &run(&t, Start::Fresh).unwrap()).is_empty());
    let accepted = issued["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .position(|a| a["expected"].get("ok").is_some())
        .expect("an accepted authorization");
    let mut v = issued.clone();
    v["authorizations"][accepted]["generation"] = serde_json::json!("4");
    check(v, "an authorization in a later generation");

    let mut v = issued.clone();
    v["lowered"]["ok"][0]["generation"] = serde_json::json!("4");
    check(v, "a changed scoped rule generation");
}
