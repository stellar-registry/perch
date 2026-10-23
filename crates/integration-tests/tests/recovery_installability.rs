//! A document that compiles must also install, and a recovery target must
//! stay installable even when one of its time-bounded rules expired between
//! publish and completion.
//!
//! The compiler advertises the "compiles ⇒ installs" invariant
//! (`perch-doc-compiler/src/lib.rs`: the rule-name cap "so that a document
//! that compiles also installs"). This suite holds `not-after-ledger` to the
//! same bar:
//!
//! - a rule whose bound has already passed must not make `apply_doc` trap
//!   where `compile_doc` succeeded — the account drops the dead rule at
//!   install (`rules::desired`), since OZ's `add_context_rule` refuses a past
//!   `valid_until`;
//! - a thief must not be able to brick compromise recovery by dropping a
//!   baseline rule that later expires — the completion drops the dead rule
//!   and installs the rest;
//! - the drop can never remove the account's only admin rule, because the
//!   anti-brick check (`admin_survives`) refuses any document whose sole
//!   self-admin rule is bounded by `not-after-ledger` (a latent brick).

mod support;

use perch_account::PerchAccountError;
use perch_doc_compiler::{admin_survives, CompiledRule, RuleScope};
use perch_recovery::EvidenceDomain::Initiate;
use perch_recovery_interface::RecoveryAction;
use perch_testkit::delta::{DeltaWorld, DocModel, KeyModel, RuleModel, SignerModel, Spelling};
use perch_testkit::FIXTURE_NETWORK;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Bytes, Env, String, Vec};
use support::*;

/// A baseline document of `owner` (admin) + `device`, an `admin` self-admin
/// rule, a `target` rule, and — when `session_not_after` is set — a `session`
/// rule bounded by `not-after-ledger`. Optionally carries recovery and a
/// `thief` signer. When `admin_not_after` is set the `admin` rule itself
/// carries a bound (an anti-brick probe).
fn doc_json(
    w: &World,
    session_not_after: Option<u32>,
    admin_not_after: Option<u32>,
    thief: Option<&soroban_sdk::Address>,
    recovery: Option<&Recovery>,
) -> Bytes {
    let bound = |n: Option<u32>| {
        n.map(|n| format!(r#","not-after-ledger":{n}"#))
            .unwrap_or_default()
    };
    let mut signers = std::vec![
        format!(r#"{{"id":"owner","address":"{}"}}"#, strkey(&w.owner)),
        format!(r#"{{"id":"device","address":"{}"}}"#, strkey(&w.device)),
    ];
    if let Some(t) = thief {
        signers.push(format!(r#"{{"id":"thief","address":"{}"}}"#, strkey(t)));
    }
    let mut rules = std::vec![
        format!(
            r#"{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}{}}}"#,
            bound(admin_not_after)
        ),
        format!(
            r#"{{"name":"target","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}"#,
            strkey(&w.target)
        ),
    ];
    if let Some(n) = session_not_after {
        rules.push(format!(
            r#"{{"name":"session","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["device"]}},"not-after-ledger":{n}}}"#,
            strkey(&w.target)
        ));
    }
    let rec = recovery
        .map(|r| format!(r#","recovery":{}"#, r.json(w)))
        .unwrap_or_default();
    let s = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]{rec}}}"#,
        signers.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, s.as_bytes())
}

// ---------------------------------------------------------------------------
// Compiles ⇒ installs, for an ordinary (non-recovery) apply_doc
// ---------------------------------------------------------------------------

/// `compile_doc` (and so `publish_baseline`/`derive_target`) must not admit a
/// rule whose `not-after-ledger` is already at or before the current ledger
/// unless `apply_doc` of the same bytes also installs it. With the install
/// drop, the compiler accepts the document and `apply_doc` installs it,
/// silently dropping the dead rule.
#[test]
fn a_document_that_compiles_also_installs_with_a_past_not_after_ledger() {
    let w = world();
    // not-after-ledger == current ledger: OZ's lowered `valid_until = X - 1`
    // is one below the current sequence, which `add_context_rule` rejects.
    let doc = doc_json(&w, Some(w.ledger()), None, None, None);
    let compiled = w.compiler().try_compile_doc(&doc);
    let applied = w.apply_bytes(&doc, 0);
    assert!(
        compiled.is_err() || applied.is_ok(),
        "compile_doc accepted ({:?}) a document apply_doc cannot install: {applied:?}",
        compiled.map(|c| c.map(|c| c.doc_hash))
    );
    // The dead rule is not installed; the live `target` rule still is.
    assert!(
        w.client().try_applied_doc().is_ok(),
        "the account has a coherent applied document"
    );
    assert!(
        w.activity(),
        "the owner's live `target` rule still authorizes"
    );
}

/// A rule whose bound is still in the future installs and authorizes as
/// before — the drop is strictly for already-dead bounds, nothing earlier.
#[test]
fn a_future_not_after_ledger_rule_installs_normally() {
    let w = world();
    let doc = doc_json(&w, Some(w.ledger() + 1_000), None, None, None);
    w.apply_bytes(&doc, 0).expect("apply with a future bound");
    // The `session` rule (device-scoped to `target`) is installed while it is
    // live; `rule_id` returns `u32::MAX` when no such rule exists.
    assert_ne!(
        w.rule_id(&w.account, "session"),
        u32::MAX,
        "the live session rule is installed"
    );
}

// ---------------------------------------------------------------------------
// Anti-brick: the surviving admin rule must never expire
// ---------------------------------------------------------------------------

/// A document whose only self-admin rule carries `not-after-ledger` is a
/// latent brick: once the bound passes, no `apply_doc` can be authorized
/// through it and the install drop would leave the account with no admin
/// rule at all. The anti-brick check must refuse it up front — whether the
/// bound is already past or still in the future.
#[test]
fn an_expiring_admin_rule_is_refused_by_the_anti_brick_check() {
    let w = world();
    // Future bound: not yet expired, but still refused.
    let future = doc_json(&w, None, Some(w.ledger() + 5), None, None);
    assert_eq!(
        w.apply_bytes(&future, 0),
        Err(Ok(PerchAccountError::AdminLockout)),
        "an admin rule with a future not-after-ledger must be refused"
    );
    // Already-past bound: also refused (never dropped into a brick).
    let past = doc_json(&w, None, Some(w.ledger()), None, None);
    assert_eq!(
        w.apply_bytes(&past, 0),
        Err(Ok(PerchAccountError::AdminLockout)),
        "an admin rule with a past not-after-ledger must be refused"
    );
}

/// Unit check of the anti-brick predicate itself: a bounded self-admin rule
/// never counts as a surviving admin rule, an unbounded one does.
#[test]
fn admin_survives_requires_an_unbounded_admin_rule() {
    let env = Env::default();
    let signer =
        stellar_accounts::smart_account::Signer::Delegated(soroban_sdk::Address::generate(&env));
    let make = |valid_until: Option<u32>| CompiledRule {
        name: String::from_str(&env, "admin"),
        scope: RuleScope::SelfAdmin,
        signers: soroban_sdk::vec![&env, signer.clone()],
        valid_until,
        install: Vec::new(&env),
        cap: Vec::new(&env),
    };
    assert!(
        admin_survives(&soroban_sdk::vec![&env, make(None)]),
        "an unbounded policy-free self-admin rule survives"
    );
    assert!(
        !admin_survives(&soroban_sdk::vec![&env, make(Some(1_000_000))]),
        "a bounded self-admin rule — even far in the future — does not survive"
    );
    assert!(
        !admin_survives(&soroban_sdk::vec![&env, make(Some(0))]),
        "a bounded self-admin rule does not survive"
    );
}

// ---------------------------------------------------------------------------
// Compromise recovery stays installable through a bounded rule's expiry
// ---------------------------------------------------------------------------

/// A thief holding the owner key under Protected must not be able to defeat
/// compromise recovery by dropping a baseline rule whose `not-after-ledger`
/// has since passed: the completion must still install the baseline (minus
/// the dead rule) and revoke the thief.
#[test]
fn a_thief_cannot_block_compromise_recovery_with_an_expired_baseline_rule() {
    let w = world();
    let session_until = w.ledger() + 30;
    let baseline = doc_json(&w, Some(session_until), None, None, None);

    let mut r = w.recovery("protected", Mode::Guardian);
    r.baseline = Some(w.compiler().compile_doc(&baseline).doc_hash);
    w.apply_bytes(&doc_json(&w, Some(session_until), None, None, Some(&r)), 0)
        .expect("enroll");

    // The thief, holding the owner key, adds a key and drops the session
    // rule (no recovery text changes, so no condition is needed under
    // Protected).
    let thief = w.new_key();
    w.apply_bytes(&doc_json(&w, None, None, Some(&thief), Some(&r)), 0)
        .expect("thief apply");

    // The baseline still compiles and publishes after its rule expired.
    w.advance(40);
    w.ctl().publish_baseline(&w.account, &baseline);

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let id = w.ctl().begin_compromise(&w.account, &replacements);
    let source = w.ctl().baseline(&w.account).unwrap();
    let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    w.advance(DELAY);
    let done = w.complete(&target);
    assert!(
        done.is_ok(),
        "compromise completion cannot install the baseline (the expired \
         session rule must be dropped, not re-added): {done:?}"
    );
    // Recovery actually took effect: the new owner controls the account, the
    // thief is locked out.
    assert!(
        w.activity_as(&new_owner),
        "new owner should control the account"
    );
    assert!(!w.activity_as(&thief), "thief must be locked out");
}

/// A bounded rule that is live when the baseline is published but expires
/// during the recovery delay must not block completion: the completion drops
/// it deterministically and installs the rest.
#[test]
fn a_bounded_rule_that_expires_mid_delay_still_completes() {
    let w = world();
    // Live at enroll and publish (START), dead by completion (START + DELAY).
    let session_until = w.ledger() + 5;
    let baseline = doc_json(&w, Some(session_until), None, None, None);

    let mut r = w.recovery("protected", Mode::Guardian);
    r.baseline = Some(w.compiler().compile_doc(&baseline).doc_hash);
    w.apply_bytes(&doc_json(&w, Some(session_until), None, None, Some(&r)), 0)
        .expect("enroll");

    // Publish the baseline while the session rule is still live.
    w.ctl().publish_baseline(&w.account, &baseline);
    assert!(
        session_until > w.ledger(),
        "the session rule is live at publish time"
    );

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let id = w.ctl().begin_compromise(&w.account, &replacements);
    let source = w.ctl().baseline(&w.account).unwrap();
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    // The bound lapses inside the delay window.
    w.advance(DELAY);
    assert!(
        session_until < w.ledger(),
        "the session rule expired during the delay"
    );
    let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    w.complete(&target)
        .expect("completion drops the now-dead session rule and installs the rest");
    assert!(w.activity_as(&new_owner), "new owner controls the account");
}

// ---------------------------------------------------------------------------
// Delta and full-replace agree across expiry
// ---------------------------------------------------------------------------

fn signer(id: &'static str, k: usize) -> SignerModel {
    SignerModel {
        id,
        key: KeyModel::Delegated(k),
    }
}

fn rule(
    name: &'static str,
    scope: Option<usize>,
    signers: std::vec::Vec<usize>,
    not_after: Option<u32>,
) -> RuleModel {
    RuleModel {
        name,
        scope,
        signers,
        threshold: None,
        functions: None,
        not_after,
        cap: None,
    }
}

/// The delta path keeps an installed rule that has since expired; the full
/// replace re-adds it. Both must now drop it, so they accept and refuse the
/// same documents (the `apply_doc_delta` fuzz target's equivalence property).
#[test]
fn delta_and_full_replace_agree_after_a_rule_expires() {
    let w = DeltaWorld::new();
    let a = DocModel {
        signers: std::vec![signer("owner", 0), signer("s1", 1)],
        rules: std::vec![
            rule("admin", None, std::vec![0], None),
            rule("r1", Some(0), std::vec![1], Some(1_010)),
        ],
        recovery: None,
        spelling: Spelling::default(),
    };
    assert!(w.apply(&w.delta, &a).is_ok());
    assert!(w.apply(&w.oracle, &a).is_ok());
    // Advance past r1's bound; add one new rule.
    w.env.ledger().with_mut(|l| l.sequence_number = 1_100);
    let mut b = a.clone();
    b.rules.push(rule("r2", Some(1), std::vec![0], None));
    let delta = w.apply(&w.delta, &b);
    let oracle = w.apply(&w.oracle, &b);
    assert_eq!(
        delta.is_ok(),
        oracle.is_ok(),
        "delta {delta:?} vs full replace {oracle:?}"
    );
    assert!(
        delta.is_ok(),
        "both drop the dead r1 and install r2: {delta:?}"
    );
}

/// After a rule expires, an edit to it (a signer change) must be accepted the
/// same way on the in-place path and the replacement path: both drop the dead
/// rule, so the outcome no longer depends on which path the cost model prices
/// lower.
#[test]
fn an_expired_rule_edit_does_not_depend_on_the_reconcile_path() {
    let a = DocModel {
        signers: std::vec![signer("owner", 0), signer("s1", 1), signer("s2", 2)],
        rules: std::vec![
            rule("admin", None, std::vec![0], None),
            rule("r1", Some(0), std::vec![1], Some(1_010)),
        ],
        recovery: None,
        spelling: Spelling::default(),
    };
    let mut b = a.clone();
    b.rules[1].signers = std::vec![1, 2];
    let run = |in_place: bool| {
        let w = DeltaWorld::new();
        assert!(w.apply_forced(&a, in_place).is_ok());
        w.env.ledger().with_mut(|l| l.sequence_number = 1_100);
        w.apply_forced(&b, in_place)
    };
    let (edit, replace) = (run(true), run(false));
    assert_eq!(
        edit.is_ok(),
        replace.is_ok(),
        "in-place edit {edit:?} vs replacement {replace:?} of an expired rule"
    );
}
