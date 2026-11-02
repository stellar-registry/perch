//! `apply_scope` and `remove_scope` interleaved with admin `apply_doc`
//! (`docs/recovery/spec.md` §7.6), checked against the documents a model
//! says are applied. See `perch_testkit::delta` for the generator
//! (`ScopeOp::sequence`, `DocModel::generate_scoped`) and the checks
//! (`ScopeModel::step`): after every step, each scope grants exactly its own
//! document's rules, a scope operation leaves the admin document and the
//! other scopes as they were, and a refused operation changes no ledger
//! entry. The fuzz target `fuzz/fuzz_targets/apply_scope_delta.rs` checks the
//! same property from the same generator.
//!
//! Authorization is mocked here (the harness checks storage, not
//! authorization); `scoped_docs.rs` covers the scoped tier under enforcing
//! authorization. Proptest case counts default low enough for CI; set
//! `PERCH_DELTA_CASES` to run more.

use arbitrary::Unstructured;
use perch_testkit::delta::*;
use proptest::prelude::*;

fn cases(default: u32) -> u32 {
    std::env::var("PERCH_DELTA_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(32),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// For any interleaving of admin documents, scoped documents, and scope
    /// removals over a few scope ids, with the ledger advancing between
    /// steps past rule expiries, every step keeps each scope to its own
    /// document, leaves the admin document and the other scopes alone, and
    /// changes nothing when refused.
    #[test]
    fn scoped_documents_reconcile_alone(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let w = DeltaWorld::new();
        let mut model = ScopeModel::default();
        for (advance, op) in ScopeOp::sequence(&mut Unstructured::new(&bytes), 8).unwrap() {
            w.advance(advance);
            let _ = model.step(&w, &op);
        }
    }
}

// ---------------------------------------------------------------------------
// A named sequence through every path the property checks
// ---------------------------------------------------------------------------

fn signer(id: &'static str, key: usize) -> SignerModel {
    SignerModel {
        id,
        key: KeyModel::Delegated(key),
    }
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
        cap_token: None,
        recipient: None,
    }
}

fn doc(signers: std::vec::Vec<SignerModel>, rules: std::vec::Vec<RuleModel>) -> DocModel {
    DocModel {
        signers,
        rules,
        recovery: None,
        spelling: Spelling::default(),
    }
}

/// Every outcome the generator draws, in one sequence: scopes sharing keys
/// with the admin document and with each other, a capped and an expiring
/// rule, edits and removals, refusals (an escalating document, an unknown
/// scope), and admin documents applied over live scopes.
#[test]
fn every_scope_path_keeps_each_document_to_itself() {
    let w = DeltaWorld::new();
    let mut m = ScopeModel::default();
    let admin = doc(
        std::vec![signer("owner", 0), signer("s1", 1)],
        std::vec![rule("admin", None, &[0]), rule("r1", Some(0), &[1])],
    );
    let mut capped = rule("r2", Some(1), &[1]);
    capped.cap = Some((1_000, 100));
    let mut expiring = rule("r3", Some(2), &[0]);
    expiring.not_after = Some(1_050);
    let grant = doc(
        std::vec![signer("owner", 0), signer("s1", 1)],
        std::vec![rule("r1", Some(0), &[1]), capped, expiring],
    );
    let other = doc(
        std::vec![signer("s1", 1), signer("s2", 2)],
        std::vec![rule("r1", Some(0), &[0, 1])],
    );
    let mut escalating = grant.clone();
    escalating.rules.push(rule("x", None, &[0]));

    let steps: [(u32, ScopeOp, bool); 11] = [
        (0, ScopeOp::Admin(admin.clone()), true),
        (0, ScopeOp::Apply(0, grant.clone()), true),
        (0, ScopeOp::Apply(7, other.clone()), true),
        (0, ScopeOp::Apply(1, escalating), false),
        (0, ScopeOp::Remove(1), false),
        // Past `r3`'s bound: scope 0 now grants two rules.
        (60, ScopeOp::Admin(other.clone()), false),
        (0, ScopeOp::Apply(0, other.clone()), true),
        (0, ScopeOp::Admin(admin.clone()), true),
        (0, ScopeOp::Remove(0), true),
        (0, ScopeOp::Apply(0, grant), true),
        (0, ScopeOp::Remove(7), true),
    ];
    for (advance, op, accepted) in steps {
        w.advance(advance);
        let out = m.step(&w, &op);
        assert_eq!(out.is_ok(), accepted, "{op:?}: {out:?}");
    }
    assert_eq!(m.scopes.keys().copied().collect::<std::vec::Vec<_>>(), [0]);
}
