//! Arbitrary document sequences through `apply_doc`'s delta reconciliation
//! and through the full replace it replaced (`perch_testkit::delta`), with
//! the ledger advancing between documents past rule expiries: both must
//! accept and refuse the same documents and end every step with identical
//! normalized storage — rules, signers, policies and their parameters,
//! registries, the canonical applied document, and the recovery wiring.
//! The full replace shares compile and the desired rule set with the delta,
//! so each accepted step is also checked against the grant the model
//! computes on its own (`DocModel::expected_rules` vs `live_rules`). The
//! proptest suite (`crates/integration-tests/tests/apply_delta.rs`) checks
//! the same property from the same generator.

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use perch_testkit::delta::{live_rules, storage_state, DeltaWorld, DocModel, History};

fuzz_target!(|data: &[u8]| {
    let Ok(docs) = DocModel::sequence(&mut Unstructured::new(data), 4) else {
        return;
    };
    let w = DeltaWorld::new();
    for (advance, d) in &docs {
        w.advance(*advance);
        let delta = w.apply(&w.delta, d);
        let oracle = w.apply(&w.oracle, d);
        assert_eq!(delta, oracle, "the delta and the full replace disagree on {d:?}");
        assert_eq!(
            storage_state(&w.env, &w.delta, History::Keep),
            storage_state(&w.env, &w.oracle, History::Keep),
            "storage diverged after {d:?}"
        );
        if delta.is_ok() {
            assert_eq!(
                live_rules(&w, &w.delta),
                d.expected_rules(&w, &w.delta),
                "the live rules differ from the model's grant after {d:?}"
            );
        }
    }
});
