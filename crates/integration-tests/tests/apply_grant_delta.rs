//! `apply_grant` and `remove_grant` interleaved with admin `apply_doc`
//! (`docs/recovery/spec.md` §7.6), checked against the documents a model
//! says are applied. See `perch_testkit::delta` for the generator
//! (`GrantOp::sequence`, `DocModel::generate_grant`) and the checks
//! (`GrantModel::step`): after every step, each grant grants exactly its own
//! document's rules, a grant operation leaves the account document and the
//! other grants as they were, and a refused operation changes no ledger
//! entry. The fuzz target `fuzz/fuzz_targets/apply_grant_delta.rs` checks the
//! same property from the same generator.
//!
//! Authorization is mocked here (the harness checks storage, not
//! authorization); `grant_docs.rs` covers the grant tier under enforcing
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

    /// For any interleaving of account documents, grant documents, and grant
    /// removals over a few grant ids, with the ledger advancing between
    /// steps past rule expiries, every step keeps each grant to its own
    /// document, leaves the account document and the other grants alone, and
    /// changes nothing when refused.
    #[test]
    fn grant_documents_reconcile_alone(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let w = DeltaWorld::new();
        let mut model = GrantModel::default();
        for (advance, op) in GrantOp::sequence(&mut Unstructured::new(&bytes), 8).unwrap() {
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

/// Every outcome the generator draws, in one sequence: grants sharing keys
/// with the account document and with each other, a capped and an expiring
/// rule, edits and removals, refusals (an escalating document, one not in
/// normal form, one whose rule has expired, an unknown grant), and account
/// documents applied over live grants.
#[test]
fn every_grant_path_keeps_each_document_to_itself() {
    let w = DeltaWorld::new();
    let mut m = GrantModel::default();
    let admin = doc(
        std::vec![signer("owner", 0), signer("s1", 1)],
        std::vec![rule("admin", None, &[0]), rule("r1", Some(0), &[1])],
    );
    let mut capped = rule("r2", Some(1), &[0]);
    capped.functions = Some(std::vec!["transfer"]);
    capped.cap = Some((1_000, 100));
    let mut expiring = rule("r3", Some(2), &[1]);
    expiring.not_after = Some(1_050);
    let grant = doc(
        std::vec![signer("s1", 1), signer("owner", 0)],
        std::vec![rule("r1", Some(0), &[0]), capped, expiring],
    );
    // `grant` without `r3`, and without `owner`, whom only `r3` names.
    let mut lasting = grant.clone();
    lasting.rules.pop();
    lasting.signers.pop();
    let other = doc(
        std::vec![signer("s1", 1), signer("s2", 2)],
        std::vec![rule("r1", Some(0), &[0, 1])],
    );
    let mut escalating = grant.clone();
    escalating.rules.push(rule("x", None, &[0]));
    // `grant` with its signers declared in another order.
    let mut unordered = grant.clone();
    unordered.signers.reverse();
    for r in &mut unordered.rules {
        for i in &mut r.signers {
            *i = 1 - *i;
        }
    }
    assert!(!unordered.normal_form(w.env.ledger().sequence()));

    let steps: [(u32, GrantOp, bool); 13] = [
        (0, GrantOp::Admin(admin.clone()), true),
        (0, GrantOp::Apply(0, grant.clone()), true),
        (0, GrantOp::Apply(7, other.clone()), true),
        (0, GrantOp::Apply(1, escalating), false),
        (0, GrantOp::Apply(1, unordered), false),
        (0, GrantOp::Remove(1), false),
        // Past `r3`'s bound: grant 0 now grants two rules.
        (60, GrantOp::Admin(other.clone()), false),
        (0, GrantOp::Apply(0, other.clone()), true),
        (0, GrantOp::Admin(admin.clone()), true),
        (0, GrantOp::Remove(0), true),
        // `r3` has expired: refused, not dropped.
        (0, GrantOp::Apply(0, grant), false),
        (0, GrantOp::Apply(0, lasting), true),
        (0, GrantOp::Remove(7), true),
    ];
    for (advance, op, accepted) in steps {
        w.advance(advance);
        let out = m.step(&w, &op);
        assert_eq!(out.is_ok(), accepted, "{op:?}: {out:?}");
    }
    assert_eq!(m.grants.keys().copied().collect::<std::vec::Vec<_>>(), [0]);
}
