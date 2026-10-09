//! Arbitrary document sequences through `apply_doc`'s delta reconciliation
//! and through the full replace it replaced (`perch_testkit::delta`): both
//! must accept and refuse the same documents and end every step with
//! identical normalized storage — rules, signers, policies and their
//! parameters, registries, the canonical applied document, and the recovery
//! wiring. The proptest suite (`crates/integration-tests/tests/apply_delta.rs`)
//! checks the same property from the same generator.

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use perch_testkit::delta::{storage_state, DeltaWorld, DocModel, History};

fuzz_target!(|data: &[u8]| {
    let Ok(docs) = DocModel::sequence(&mut Unstructured::new(data), 4) else {
        return;
    };
    let w = DeltaWorld::new();
    for d in &docs {
        let delta = w.apply(&w.delta, d);
        let oracle = w.apply(&w.oracle, d);
        assert_eq!(delta, oracle, "the delta and the full replace disagree on {d:?}");
        assert_eq!(
            storage_state(&w.env, &w.delta, History::Keep),
            storage_state(&w.env, &w.oracle, History::Keep),
            "storage diverged after {d:?}"
        );
    }
});
