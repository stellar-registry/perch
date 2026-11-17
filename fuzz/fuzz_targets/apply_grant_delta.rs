//! Arbitrary interleavings of admin `apply_doc`, `apply_grant`, and
//! `remove_grant` over a few grant ids, with the ledger advancing between
//! steps past rule expiries (`perch_testkit::delta::GrantOp::sequence`).
//! After every step `GrantModel::step` checks that each grant grants exactly
//! the rules the model computes for its own document, that a grant
//! operation leaves the account document's records, rules, signers, policies,
//! and applied document as they were, that an operation leaves every other
//! grant as it was, and that a refused operation changes no ledger entry.
//! The proptest suite (`crates/integration-tests/tests/apply_grant_delta.rs`)
//! checks the same property from the same generator.

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use perch_testkit::delta::{DeltaWorld, GrantModel, GrantOp};

fuzz_target!(|data: &[u8]| {
    let Ok(ops) = GrantOp::sequence(&mut Unstructured::new(data), 6) else {
        return;
    };
    let w = DeltaWorld::new();
    let mut model = GrantModel::default();
    for (advance, op) in &ops {
        w.advance(*advance);
        let _ = model.step(&w, op);
    }
});
