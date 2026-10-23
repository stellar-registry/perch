//! Two-digest recovery target binding (`docs/recovery/spec.md` §6.3 T1 and
//! T5; RFC #109 §1, option A). An attempt records the target's document
//! identity and the digest of its canonical bytes, both from one
//! `derive_target` call. Authorization binds the bytes; application binds
//! the identity.
//!
//! The properties that must hold under any identity scheme run twice:
//! with the real compiler (CANON v1, where the identity is the bytes
//! digest), and with a test compiler whose identity is another function of
//! the same document, standing in for a CANON v2 root. One test runs a
//! faulty compiler whose identity does not name the bytes it returns.

mod support;

use perch_recovery::{AttemptState, EvidenceDomain};
use perch_recovery_interface::{RecoveryAction, StatementSubject};
use soroban_sdk::{Address, Bytes, BytesN};
use support::*;

use EvidenceDomain::Initiate;

/// The identity schemes every binding property must hold under.
const SCHEMES: [TestCompiler; 2] = [TestCompiler::Real, TestCompiler::StandInIdentity];

fn world_of(compiler: TestCompiler) -> World {
    world_with(Opts {
        compiler,
        ..Opts::default()
    })
}

fn open_lost_key(w: &World) -> (u64, Address, Bytes) {
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    (id, new_owner, target)
}

fn authorize(w: &World, id: u64) {
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
}

fn state(w: &World, id: u64) -> AttemptState {
    w.ctl().attempt(&w.account, &id).unwrap().state
}

fn sha256(w: &World, b: &Bytes) -> BytesN<32> {
    w.env.crypto().sha256(b).to_bytes()
}

#[test]
fn both_digests_come_from_one_derivation_and_bind_one_attempt() {
    for scheme in SCHEMES {
        let w = world_of(scheme);
        w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
        let (id, _, target) = open_lost_key(&w);
        let attempt = w.ctl().attempt(&w.account, &id).unwrap();

        // The bytes digest is the controller's own hash of the derived
        // bytes; the identity is the compiler's, of the same document.
        assert_eq!(attempt.target_bytes_hash, sha256(&w, &target));
        assert_eq!(
            attempt.target_doc_hash,
            w.compiler().compile_doc(&target).doc_hash
        );
        assert_eq!(
            scheme == TestCompiler::StandInIdentity,
            attempt.target_doc_hash != attempt.target_bytes_hash
        );
        // The source is the account's applied identity, not a hash of bytes.
        assert_eq!(
            Some(attempt.source_doc_hash.clone()),
            w.client().applied_doc_hash()
        );
        // The statement names identities only.
        match w.statement(id, Initiate).subject {
            StatementSubject::LostKey(s) => {
                assert_eq!(s.target_doc_hash, attempt.target_doc_hash);
                assert_eq!(s.source_doc_hash, attempt.source_doc_hash);
            }
            other => panic!("{other:?}"),
        }

        authorize(&w, id);
        w.advance(DELAY);
        let applied = w.complete(&target).expect("completion");
        assert_eq!(applied, attempt.target_doc_hash, "{scheme:?}");
        assert_eq!(w.client().applied_doc_hash(), Some(applied));
        assert_eq!(w.client().applied_doc(), Some(target));
        assert_eq!(state(&w, id), AttemptState::Completed);
    }
}

#[test]
fn substituted_target_bytes_are_refused_at_authorization() {
    for scheme in SCHEMES {
        let w = world_of(scheme);
        w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
        let before = w.client().applied_doc_hash();
        let (id, _, target) = open_lost_key(&w);
        authorize(&w, id);
        w.advance(DELAY);

        // Another document: the current one, and a target derived for other
        // replacements.
        let current = w.client().applied_doc().unwrap();
        assert!(w.complete(&current).is_err());
        let other = w.target_bytes(
            RecoveryAction::LostKey,
            &current,
            &w.replacements(&w.new_key(), None),
        );
        assert!(w.complete(&other).is_err());
        // The target in a non-canonical spelling: the same identity, other
        // bytes. Refused by the bytes digest, though it compiles to the
        // target's identity.
        let mut spaced = Bytes::from_slice(&w.env, b" ");
        spaced.append(&target);
        assert_eq!(
            w.compiler().compile_doc(&spaced).doc_hash,
            w.compiler().compile_doc(&target).doc_hash
        );
        assert!(w.complete(&spaced).is_err());

        assert_eq!(w.client().applied_doc_hash(), before, "nothing applied");
        assert_eq!(state(&w, id), AttemptState::Authorized);
        w.complete(&target).expect("the exact bytes complete");
    }
}

#[test]
fn an_inconsistent_pair_completes_nothing() {
    let w = world_of(TestCompiler::InconsistentPair);
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let before = w.client().applied_doc_hash();
    let (id, _, target) = open_lost_key(&w);
    let attempt = w.ctl().attempt(&w.account, &id).unwrap();
    assert_ne!(
        attempt.target_doc_hash,
        w.compiler().compile_doc(&target).doc_hash,
        "the faulty compiler's identity does not name its bytes"
    );
    authorize(&w, id);
    w.advance(DELAY);

    // The exact bytes pass `enforce` but compile to another identity, so
    // `rcv_sync` does not recognise a completion and refuses the apply in
    // the authorized window; any other bytes fail `enforce`.
    assert!(w.complete(&target).is_err());
    let mut spaced = Bytes::from_slice(&w.env, b" ");
    spaced.append(&target);
    assert!(w.complete(&spaced).is_err());
    assert_eq!(w.client().applied_doc_hash(), before, "nothing applied");
    assert_eq!(state(&w, id), AttemptState::Authorized);

    // It can only expire.
    w.advance(EXPIRY);
    assert!(!w.ctl().attempt_live(&w.account, &id));
    assert!(w.complete(&target).is_err());
    assert_eq!(w.client().applied_doc_hash(), before);
}

#[test]
fn a_lost_key_target_is_stale_after_a_document_change_and_current_again_after_a_to_b_to_a() {
    for scheme in SCHEMES {
        let w = world_of(scheme);
        let a = w.doc(Some(w.recovery("loss", Mode::Guardian)));
        w.enroll(&a);
        let mut b = a.clone();
        b.signers[1].1 = w.new_key();

        // Changed before T4: invalidated by comparing identities.
        let (stale, _, _) = open_lost_key(&w);
        w.guardian(0, stale, Initiate);
        w.enroll(&b);
        w.guardian(1, stale, Initiate);
        assert_eq!(state(&w, stale), AttemptState::Invalidated, "{scheme:?}");

        // A -> B -> A before T4: the source identity is current again, and
        // the target derived from A is still exactly A with the
        // replacements.
        w.enroll(&a);
        let (id, _, target) = open_lost_key(&w);
        w.guardian(0, id, Initiate);
        w.enroll(&b);
        w.enroll(&a);
        w.guardian(1, id, Initiate);
        assert_eq!(state(&w, id), AttemptState::Authorized, "{scheme:?}");
        // Inside the authorized window the document cannot change.
        assert!(w.apply(&b, 0).is_err());
        w.advance(DELAY);
        w.complete(&target).expect("completion");
    }
}

#[test]
fn a_compromise_source_is_the_enrolled_baseline_identity() {
    for scheme in SCHEMES {
        let w = world_of(scheme);
        let baseline = w.doc(None);
        let mut r = w.recovery("protected", Mode::Guardian);
        r.baseline = Some(w.doc_hash(&baseline));
        w.enroll(&w.doc(Some(r.clone())));
        let mut stolen = w.doc(Some(r));
        stolen.signers.push(("thief", w.new_key()));
        w.enroll(&stolen);
        w.ctl().publish_baseline(&w.account, &baseline.bytes(&w));

        let replacements = w.replacements(&w.new_key(), None);
        let id = w.ctl().begin_compromise(&w.account, &replacements);
        let attempt = w.ctl().attempt(&w.account, &id).unwrap();
        assert_eq!(attempt.source_doc_hash, w.doc_hash(&baseline), "{scheme:?}");
        let source = w.ctl().baseline(&w.account).unwrap();
        let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
        assert_eq!(attempt.target_bytes_hash, sha256(&w, &target));
        authorize(&w, id);
        w.advance(DELAY);
        assert_eq!(
            w.complete(&target).expect("compromise completion"),
            attempt.target_doc_hash
        );
    }
}
