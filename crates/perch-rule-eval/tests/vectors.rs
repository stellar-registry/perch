//! The pinned `rule-eval` and `soroban-facade` against every conformance
//! vector rule-core carries at the same rev: rule-set and attenuation
//! vectors, cap traces, authorization traces, budget traces, document traces,
//! and the facade's Soroban value, context and storage vectors. The vectors
//! are generated from rule-core's Lean model, so a failure here is a
//! difference between the pinned evaluator and the model it is proven
//! against.
//!
//! The vectors are read from `rule_eval_conformance::vectors_dir()`: the
//! `conformance/vectors` directory of cargo's checkout of the same rev, or
//! the directory `CONFORMANCE_VECTORS` names.

use std::path::PathBuf;

use rule_eval_conformance::{authorize, budget, caps, documents, soroban};

/// The vectors directory of the pinned rev.
fn root() -> PathBuf {
    rule_eval_conformance::vectors_dir()
}

/// Every failure of `check` over `vectors`, one line each; panics when there
/// are no vectors, so a moved directory cannot pass as an empty one.
fn failures<T>(
    kind: &str,
    vectors: Result<Vec<(PathBuf, T)>, String>,
    check: impl Fn(&T) -> Result<(), String>,
) -> Vec<String> {
    let vectors = vectors.unwrap_or_else(|e| panic!("{kind}: {e}"));
    assert!(!vectors.is_empty(), "{kind}: no vectors found");
    println!("{kind}: {} vectors", vectors.len());
    vectors
        .iter()
        .filter_map(|(path, v)| check(v).err().map(|e| format!("{}: {e}", path.display())))
        .collect()
}

fn assert_none(failed: Vec<String>) {
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

#[test]
fn rule_eval_reproduces_every_rule_vector() {
    assert_none(failures(
        "rules",
        rule_eval_conformance::load_dir(&root()),
        rule_eval_conformance::check,
    ));
}

#[test]
fn rule_eval_reproduces_every_cap_trace() {
    assert_none(failures(
        "caps",
        caps::load_dir(&root().join("caps")),
        caps::check,
    ));
}

#[test]
fn rule_eval_reproduces_every_authorization_trace() {
    assert_none(failures(
        "authorize",
        authorize::load_dir(&root().join("authorize")),
        authorize::check,
    ));
}

#[test]
fn rule_eval_reproduces_every_budget_trace() {
    assert_none(failures(
        "budget",
        budget::load_dir(&root().join("budget")),
        budget::check,
    ));
}

#[test]
fn rule_eval_reproduces_every_document_trace() {
    assert_none(failures(
        "documents",
        documents::load_dir(&root().join("documents")),
        documents::check,
    ));
}

#[test]
fn soroban_facade_reproduces_every_value_context_and_storage_vector() {
    let mut failed = failures(
        "soroban values",
        soroban::load_dir(&soroban::vectors_dir("values")),
        soroban::check_values,
    );
    failed.extend(failures(
        "soroban contexts",
        soroban::load_dir(&soroban::vectors_dir("contexts")),
        soroban::check_context,
    ));
    failed.extend(failures(
        "soroban storage",
        soroban::load_dir(&soroban::vectors_dir("storage")),
        soroban::check_storage,
    ));
    assert_none(failed);
}
