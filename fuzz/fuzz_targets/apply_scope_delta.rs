//! Arbitrary interleavings of admin `apply_doc`, `apply_scope`, and
//! `remove_scope` over a few scope ids, with the ledger advancing between
//! steps past rule expiries (`perch_testkit::delta::ScopeOp::sequence`).
//! After every step `ScopeModel::step` checks that each scope grants exactly
//! the rules the model computes for its own document, that a scope
//! operation leaves the admin document's records, rules, signers, policies,
//! and applied document as they were, that an operation leaves every other
//! scope as it was, and that a refused operation changes no ledger entry.
//! The proptest suite (`crates/integration-tests/tests/apply_scope_delta.rs`)
//! checks the same property from the same generator.

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use perch_testkit::delta::{DeltaWorld, ScopeModel, ScopeOp};

fuzz_target!(|data: &[u8]| {
    let Ok(ops) = ScopeOp::sequence(&mut Unstructured::new(data), 6) else {
        return;
    };
    let w = DeltaWorld::new();
    let mut model = ScopeModel::default();
    for (advance, op) in &ops {
        w.advance(*advance);
        let _ = model.step(&w, op);
    }
});
