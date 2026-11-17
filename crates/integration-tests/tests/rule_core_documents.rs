//! rule-core's document traces (`conformance/vectors/documents` at the rev
//! the workspace pins) through Perch's real pipeline (`rule_core/mod.rs`).
//!
//! Each admin trace runs twice: on a fresh account, and on one whose applied
//! document has other rule names (the delta then adds every rule and removes
//! every earlier one). Perch's lowering of the document's rules, each
//! verdict, and each accepted authorization's spending records must equal
//! the trace's, which rule-core's Lean model computed. Every difference is
//! reported, by trace and authorization.
//!
//! Scoped traces need `apply_scope`, which Perch does not have: they are the
//! only traces not run, and the test checks that.

mod rule_core;
mod support;

use rule_core::{differences, run, Start};
use rule_eval_conformance::documents;

#[test]
fn every_admin_document_trace_agrees_with_perch() {
    let traces = documents::load_dir(&rule_core::vectors().join("documents"))
        .unwrap_or_else(|e| panic!("{e}"));
    let scoped = traces.iter().filter(|(_, t)| t.scoped.is_some()).count();
    let mut skipped = vec![];
    let mut ran = 0;
    let mut recovery = 0;
    let (mut authorizations, mut delegated, mut external) = (0, 0, 0);
    let mut failures = vec![];
    for (_, t) in &traces {
        if t.scoped.is_some() {
            skipped.push(t.name.clone());
            continue;
        }
        ran += 1;
        recovery += usize::from(t.document.recovery.is_some());
        for start in [Start::Fresh, Start::AfterPredecessor] {
            match run(t, start) {
                Ok(r) => {
                    authorizations += r.verdicts.len();
                    delegated += r.delegated;
                    external += r.external;
                    for d in differences(t, &r) {
                        failures.push(format!("{} ({start:?}): {d}", t.name));
                    }
                }
                Err(e) => failures.push(format!("{} ({start:?}): {e}", t.name)),
            }
        }
    }
    println!(
        "traces: {}, admin traces run: {ran} (with recovery: {recovery}), scoped not run: {}, \
         authorizations run: {authorizations} (with a delegated signer: {delegated}, with an \
         external signer: {external}), differences: {}",
        traces.len(),
        skipped.len(),
        failures.len()
    );
    assert!(ran > 0, "no admin trace found");
    assert_eq!(ran + skipped.len(), traces.len());
    assert_eq!(skipped.len(), scoped, "a trace was not run: {skipped:?}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
