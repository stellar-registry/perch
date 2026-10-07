//! The recovery controller and the account's recovery wiring, end to end,
//! under ENFORCING authorization (`docs/recovery/spec.md`). See
//! `support/mod.rs` for the world: the real account, compiler, controller,
//! and membership pool; stand-in keys and guardians; a statement-bound mock
//! ZK adapter.

mod support;

use perch_account::{PerchAccount, PerchAccountClient, PerchAccountError, PerchAuthError};
use perch_recovery::{AttemptState, EvidenceDomain, RecoveryError};
use perch_recovery_interface::credential::{Credential, ZkEnrollment};
use perch_recovery_interface::zk::ZkEvidence;
use perch_recovery_interface::{ConfigChange, RecoveryAction, StatementSubject};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{vec, Address, Bytes, BytesN, IntoVal, Symbol};
use stellar_accounts::smart_account::{AuthPayload, Signer};
use support::*;

use EvidenceDomain::{Cancel, Initiate};

fn rec(e: RecoveryError) -> PerchAccountError {
    PerchAccountError::Recovery(e)
}

fn fingerprint(w: &World, key: &Address) -> BytesN<32> {
    Credential::Delegated(key.clone())
        .fingerprint(&w.env)
        .unwrap()
}

/// Open a lost-key attempt replacing `owner`. Returns the attempt id, the
/// new owner key, and the target bytes a completer submits.
fn open_lost_key(w: &World, zk: Option<ZkEnrollment>) -> (u64, Address, Bytes) {
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, zk);
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

// ---------------------------------------------------------------------------
// T1-T5: lost-key recovery
// ---------------------------------------------------------------------------

#[test]
fn guardian_lost_key_recovery_installs_the_derived_target_and_revokes_the_old_key() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (id, new_owner, target) = open_lost_key(&w, None);

    w.guardian(0, id, Initiate);
    assert_eq!(state(&w, id), AttemptState::Collecting);
    assert_eq!(
        w.try_guardian(0, id, Initiate),
        Err(Ok(RecoveryError::AlreadyCounted)),
        "a guardian counts once"
    );
    w.guardian(1, id, Initiate);
    let attempt = w.ctl().attempt(&w.account, &id).unwrap();
    assert_eq!(attempt.state, AttemptState::Authorized);
    assert_eq!(attempt.executable_after, w.ledger() + DELAY);

    assert!(w.complete(&target).is_err(), "timelock not elapsed");
    w.advance(DELAY);
    let hash = w.complete(&target).expect("completion");
    assert_eq!(w.client().applied_doc(), Some(target.clone()));
    assert_eq!(hash, w.compiler().compile_doc(&target).doc_hash);
    assert_eq!(state(&w, id), AttemptState::Completed);
    assert_eq!(w.ctl().epoch(&w.account), 2, "enrollment and completion");

    // The replaced key is permanently revoked; the new one works.
    assert!(w.client().is_revoked(&fingerprint(&w, &w.owner)));
    assert!(!w.client().is_revoked(&fingerprint(&w, &new_owner)));
    assert!(w.activity_as(&new_owner));
    assert!(
        !w.activity_as(&w.owner),
        "the old key is no longer a signer"
    );

    // A revoked credential can never return through an ordinary apply_doc.
    let mut back = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    back.signers[0].1 = new_owner.clone();
    back.signers[1].1 = w.owner.clone();
    assert_eq!(
        err(w.apply_as(&new_owner, &back.bytes(&w), 0)),
        PerchAccountError::RevokedCredential
    );

    // Completion cannot be replayed.
    assert!(w.complete(&target).is_err());
}

#[test]
fn completion_must_submit_exactly_the_target_inside_its_window() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (id, _, target) = open_lost_key(&w, None);
    authorize(&w, id);
    w.advance(DELAY);

    // Any other bytes, even the current document, are refused.
    let current = w.client().applied_doc().unwrap();
    assert!(w.complete(&current).is_err());
    // The same document in a non-canonical spelling hashes differently.
    let mut spaced = Bytes::from_slice(&w.env, b" ");
    spaced.append(&target);
    assert!(w.complete(&spaced).is_err());

    w.advance(EXPIRY);
    assert!(w.complete(&target).is_err(), "expired");
    assert!(!w.ctl().attempt_live(&w.account, &id));
    // An expired authorization blocks nothing any more.
    assert!(w
        .apply(&w.doc(Some(w.recovery("loss", Mode::Guardian))), 0)
        .is_ok());
}

#[test]
fn a_lost_key_attempt_whose_source_changed_needs_a_fresh_attempt() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (stale, _, _) = open_lost_key(&w, None);
    w.guardian(0, stale, Initiate);

    // The owner rotates the device key: the agreed snapshot is gone.
    let original = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    let mut rotated = original.clone();
    rotated.signers[1].1 = w.new_key();
    w.enroll(&rotated);
    // The evidence that meets the condition succeeds and records the
    // invalidation (spec §6.3 T4): a refusal would roll it back.
    assert_eq!(w.try_guardian(1, stale, Initiate), Ok(()));
    assert_eq!(state(&w, stale), AttemptState::Invalidated);
    assert!(!w.ctl().attempt_live(&w.account, &stale));

    // Changing the document back does not revive it.
    w.enroll(&original);
    assert_eq!(
        w.client().applied_doc_hash(),
        Some(w.ctl().attempt(&w.account, &stale).unwrap().source_doc_hash)
    );
    assert!(!w.ctl().attempt_live(&w.account, &stale));
    assert_eq!(
        w.try_guardian(0, stale, Initiate),
        Err(Ok(RecoveryError::AttemptNotLive))
    );

    let (fresh, _, target) = open_lost_key(&w, None);
    authorize(&w, fresh);
    w.advance(DELAY);
    w.complete(&target).expect("the fresh attempt completes");
}

// ---------------------------------------------------------------------------
// D2, #89: evidence-free attempts; replacement; epochs
// ---------------------------------------------------------------------------

#[test]
fn evidence_free_attempts_freeze_nothing_and_block_nothing() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    for _ in 0..5 {
        open_lost_key(&w, None);
    }
    assert_eq!(w.client().recovery_gate(), None);
    assert!(w.activity());
    // Key rotation needs no recovery evidence, even under Protected.
    let mut rotated = w.doc(Some(w.recovery("protected", Mode::Guardian)));
    rotated.signers[1].1 = w.new_key();
    assert!(w.apply(&rotated, 0).is_ok());
    let gate = w.ctl().activity_gate(&w.account);
    assert_eq!(gate.authorized_attempt, None);
}

#[test]
fn the_first_authorized_attempt_invalidates_its_siblings() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (a, _, _) = open_lost_key(&w, None);
    let (b, _, _) = open_lost_key(&w, None);
    let (c, _, _) = open_lost_key(&w, None);
    w.guardian(0, a, Initiate);
    authorize(&w, b);

    assert_eq!(
        w.try_guardian(1, a, Initiate),
        Err(Ok(RecoveryError::AttemptNotLive))
    );
    assert_eq!(
        w.try_guardian(0, c, Initiate),
        Err(Ok(RecoveryError::AttemptNotLive))
    );
    let replacements = w.replacements(&w.new_key(), None);
    assert_eq!(
        w.ctl().try_begin_lost_key(&w.account, &replacements),
        Err(Ok(RecoveryError::AttemptAuthorized)),
        "no attempt opens while one is authorized"
    );
}

#[test]
fn every_configuration_change_kills_earlier_attempts_and_evidence() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    let (id, _, _) = open_lost_key(&w, None);
    w.guardian(0, id, Initiate);
    let epoch = w.ctl().epoch(&w.account);

    let mut quorum_one = w.recovery("loss", Mode::Guardian);
    quorum_one.quorum = 1;
    w.enroll(&w.doc(Some(quorum_one)));
    assert_eq!(w.ctl().epoch(&w.account), epoch + 1);
    assert_eq!(
        w.try_guardian(1, id, Initiate),
        Err(Ok(RecoveryError::AttemptNotLive))
    );

    // Removal clears the controller's state for the account (#93), and
    // re-enrolling the same configuration does not revive anything.
    w.enroll(&w.doc(None));
    assert_eq!(w.ctl().config(&w.account), None);
    assert_eq!(w.client().recovery_controller(), None);
    w.enroll(&doc);
    assert_eq!(w.ctl().epoch(&w.account), epoch + 3);
    assert!(!w.ctl().attempt_live(&w.account, &id));
    assert_eq!(
        w.try_guardian(1, id, Initiate),
        Err(Ok(RecoveryError::AttemptNotLive))
    );
}

// ---------------------------------------------------------------------------
// D1, D3, §9: activity and policy restrictions
// ---------------------------------------------------------------------------

#[test]
fn protected_freezes_every_path_except_the_completion() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let (id, new_owner, target) = open_lost_key(&w, None);
    assert!(w.activity(), "collecting attempts freeze nothing");
    authorize(&w, id);

    let attempt = w.ctl().attempt(&w.account, &id).unwrap();
    let gate = w
        .client()
        .recovery_gate()
        .expect("the controller set the mirror");
    assert_eq!((gate.attempt_id, gate.until), (id, attempt.expires_at));

    // Direct authorization of anything.
    assert!(!w.activity());
    assert!(w
        .apply(&w.doc(Some(w.recovery("protected", Mode::Guardian))), 0)
        .is_err());
    // `execute` and every other account entry point need the account's own
    // authorization first.
    let exec = w.invocation(
        &w.account,
        "execute",
        std::vec![
            w.sc(w.target.clone()),
            w.sc(Symbol::new(&w.env, "protected")),
            w.sc(vec![
                &w.env,
                IntoVal::<_, soroban_sdk::Val>::into_val(&w.account, &w.env)
            ]),
        ],
    );
    w.env.set_auths(&[w.owner_entry("admin", exec)]);
    assert!(w
        .client()
        .try_execute(
            &w.target,
            &Symbol::new(&w.env, "protected"),
            &vec![
                &w.env,
                IntoVal::<_, soroban_sdk::Val>::into_val(&w.account, &w.env)
            ]
        )
        .is_err());
    w.env.set_auths(&[]);

    // CAP-0071 delegation: as anyone's delegate, the host hands this
    // account the other account's contexts, and the frozen account refuses
    // them before evaluating any rule.
    let foreign = Context::Contract(ContractContext {
        contract: w.target.clone(),
        fn_name: Symbol::new(&w.env, "protected"),
        args: vec![&w.env],
    });
    let payload = AuthPayload {
        signers: soroban_sdk::Map::new(&w.env),
        context_rule_ids: vec![&w.env, w.rule_id(&w.account, "target")],
    };
    let refused = w.env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &w.account,
        &BytesN::from_array(&w.env, &[7; 32]),
        payload.into_val(&w.env),
        &vec![&w.env, foreign],
    );
    assert_eq!(refused, Err(Ok(PerchAuthError::AccountFrozen.into())));

    // Only the authorized attempt's cancellation evidence is accepted in the
    // window: no reconfiguration or upgrade approvals.
    let remove = StatementSubject::Reconfigure(ConfigChange::Remove);
    assert_eq!(
        w.ctl()
            .try_approve_change(&w.account, &remove, &(w.ledger() + 1), &w.guardians[0]),
        Err(Ok(RecoveryError::AttemptAuthorized))
    );

    // The recovery rule still completes, and completion lifts the freeze.
    w.advance(DELAY);
    w.complete(&target).expect("completion while frozen");
    assert_eq!(w.client().recovery_gate(), None);
    assert!(w.activity_as(&new_owner));
}

#[test]
fn loss_keeps_ordinary_activity_but_blocks_policy_changes_and_the_owner_can_always_cancel() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    for round in 0..4u32 {
        let (id, _, _) = open_lost_key(&w, None);
        authorize(&w, id);
        assert_eq!(w.client().recovery_gate(), None, "Loss never freezes");
        assert!(w.activity());
        assert_eq!(err(w.apply(&doc, 0)), rec(RecoveryError::AttemptAuthorized));

        // T7: uncapped, even past max-cancels (3).
        let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(id)]);
        w.env.set_auths(&[w.owner_entry("admin", cancel)]);
        w.client().cancel_recovery(&id);
        w.env.set_auths(&[]);
        assert_eq!(state(&w, id), AttemptState::Cancelled, "round {round}");
        assert!(w.apply(&doc, 0).is_ok());
    }
}

#[test]
fn evidence_cancellation_counts_toward_max_cancels_only_for_authorized_attempts() {
    let w = world();
    let mut r = w.recovery("protected", Mode::Guardian);
    r.max_cancels = 1;
    w.enroll(&w.doc(Some(r)));

    // The owner cannot cancel under Protected.
    let (collecting, _, _) = open_lost_key(&w, None);
    let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(collecting)]);
    w.env.set_auths(&[w.owner_entry("admin", cancel)]);
    assert_eq!(
        err(w.client().try_cancel_recovery(&collecting)),
        rec(RecoveryError::OwnerCancelRefused)
    );
    w.env.set_auths(&[]);

    // Cancelling a collecting attempt is free.
    w.guardian(0, collecting, Cancel);
    w.guardian(1, collecting, Cancel);
    assert_eq!(state(&w, collecting), AttemptState::Cancelled);

    // Cancelling an authorized one counts, and lifts the freeze.
    let (first, _, _) = open_lost_key(&w, None);
    authorize(&w, first);
    assert!(w.client().recovery_gate().is_some());
    w.guardian(0, first, Cancel);
    w.guardian(1, first, Cancel);
    assert_eq!(state(&w, first), AttemptState::Cancelled);
    assert_eq!(w.client().recovery_gate(), None);
    assert!(w.activity());

    // The cap is used up: the next authorized attempt cannot be cancelled.
    let (second, _, target) = open_lost_key(&w, None);
    authorize(&w, second);
    w.guardian(0, second, Cancel);
    assert_eq!(
        w.try_guardian(1, second, Cancel),
        Err(Ok(RecoveryError::MaxCancelsReached))
    );
    assert_eq!(state(&w, second), AttemptState::Authorized);
    w.advance(DELAY);
    w.complete(&target)
        .expect("the uncancellable attempt completes");
}

// ---------------------------------------------------------------------------
// D4, §10: reconfiguration versus completion
// ---------------------------------------------------------------------------

#[test]
fn protected_reconfiguration_needs_the_currently_enrolled_condition() {
    let w = world();
    let doc = w.doc(Some(w.recovery("protected", Mode::Guardian)));
    w.enroll(&doc);
    let mut quorum_one = w.recovery("protected", Mode::Guardian);
    quorum_one.quorum = 1;
    let next = w.doc(Some(quorum_one));
    let change = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next)));
    let until = w.ledger() + 50;

    assert_eq!(
        err(w.apply(&next, until)),
        rec(RecoveryError::ConditionNotMet)
    );
    w.approve_change(0, &change, until);
    assert_eq!(
        err(w.apply(&next, until)),
        rec(RecoveryError::ConditionNotMet),
        "1 of 2"
    );
    w.approve_change(1, &change, until);
    // The approvals bind their freshness bound and the exact configuration.
    assert_eq!(
        err(w.apply(&next, until + 1)),
        rec(RecoveryError::ConditionNotMet)
    );
    let mut other = w.recovery("protected", Mode::Guardian);
    other.quorum = 3;
    assert_eq!(
        err(w.apply(&w.doc(Some(other)), until)),
        rec(RecoveryError::ConditionNotMet)
    );
    // Removal is a different change.
    assert_eq!(
        err(w.apply(&w.doc(None), until)),
        rec(RecoveryError::ConditionNotMet)
    );

    let epoch = w.ctl().epoch(&w.account);
    w.apply(&next, until).expect("approved reconfiguration");
    assert_eq!(w.ctl().epoch(&w.account), epoch + 1);
    // The approvals died with the epoch: they cannot be replayed.
    assert_eq!(
        err(w.apply(&doc, until)),
        rec(RecoveryError::ConditionNotMet)
    );

    // Removal, approved by the condition now enrolled (quorum 1).
    let remove = StatementSubject::Reconfigure(ConfigChange::Remove);
    w.approve_change(2, &remove, until);
    w.apply(&w.doc(None), until).expect("approved removal");
    assert_eq!(w.ctl().config(&w.account), None);
}

#[test]
fn approvals_cannot_outlive_the_enrolled_window() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let change = StatementSubject::Reconfigure(ConfigChange::Remove);
    let g = w.guardians[0].clone();
    let too_far = w.ledger() + EXPIRY + 1;
    assert_eq!(
        w.ctl()
            .try_approve_change(&w.account, &change, &too_far, &g),
        Err(Ok(RecoveryError::EvidenceExpired))
    );
    // An attempt subject is not a change subject.
    let attempt_subject = w.statement(open_lost_key(&w, None).0, Initiate).subject;
    assert_eq!(
        w.ctl()
            .try_approve_change(&w.account, &attempt_subject, &(w.ledger() + 1), &g),
        Err(Ok(RecoveryError::InvalidStatement))
    );
}

#[test]
fn rotating_a_key_is_not_a_reconfiguration() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let config = w.ctl().config(&w.account).unwrap();
    let epoch = w.ctl().epoch(&w.account);

    // Even the replaceable owner key: the recovery text is unchanged.
    let fresh = w.new_key();
    let mut rotated = w.doc(Some(w.recovery("protected", Mode::Guardian)));
    rotated.signers[0].1 = fresh.clone();
    w.apply(&rotated, 0).expect("no condition needed");
    assert_eq!(
        w.ctl().config(&w.account).unwrap().config_hash,
        config.config_hash
    );
    assert_eq!(w.ctl().epoch(&w.account), epoch);
    assert!(w.activity_as(&fresh));
}

// ---------------------------------------------------------------------------
// #90, §15: invoker-only hooks
// ---------------------------------------------------------------------------

#[test]
fn hooks_are_unreachable_except_from_the_accounts_own_flows() {
    let w = world();
    let mut doc = w.doc(Some(w.recovery("loss", Mode::Zk)));
    // Rules scoped to the controller are allowed (guardian accounts use
    // them); the reserved-name guard is what protects the hooks.
    doc.rules.push(("ctl", w.controller.clone()));
    w.enroll(&doc);
    let config = w.ctl().config(&w.account).unwrap();
    let hash = w.client().applied_doc_hash().unwrap();

    // No auth entries at all.
    assert!(w
        .ctl()
        .try_rcv_sync(&w.account, &hash, &vec![&w.env, config.clone()], &0)
        .is_err());
    assert!(w.ctl().try_rcv_cancel(&w.account, &0).is_err());
    assert!(w
        .ctl()
        .try_rcv_upgrade(
            &w.account,
            &perch_recovery::UpgradeStep::Execute(w.ctl().epoch(&w.account))
        )
        .is_err());
    assert!(w.client().try_rcv_gate(&0, &u32::MAX).is_err());
    assert!(w
        .pool_client()
        .try_rcv_insert(
            &w.account,
            &BytesN::from_array(&w.env, &[9; 32]),
            &config.zk().unwrap().commitment
        )
        .is_err());

    // A signature through a rule scoped to the hook's contract is refused
    // by name before any rule is evaluated: rcv_* on the controller...
    let sync = w.invocation(
        &w.controller,
        "rcv_sync",
        std::vec![
            w.sc(w.account.clone()),
            w.sc(hash.clone()),
            w.sc(vec![&w.env, config.clone()]),
            w.sc(0u32),
        ],
    );
    w.env.set_auths(&[w.owner_entry("ctl", sync)]);
    assert!(w
        .ctl()
        .try_rcv_sync(&w.account, &hash, &vec![&w.env, config], &0)
        .is_err());
    // ...and an OZ policy hook name on any contract.
    let install = w.invocation(&w.target, "install", std::vec![w.sc(w.account.clone())]);
    w.env.set_auths(&[w.owner_entry("target", install)]);
    assert!(TargetClient::new(&w.env, &w.target)
        .try_install(&w.account)
        .is_err());
    w.env.set_auths(&[]);
    // The same owner signature authorizes a non-reserved call on that rule.
    assert!(w.activity());
}

/// Spec §15: a rule scoped to the controller is allowed (a perch account
/// approves, as a guardian, at the controller it uses itself), so the
/// reserved-name guard alone must keep that rule's signers from every
/// invoker-only hook.
#[test]
fn a_controller_scoped_rule_reaches_no_reserved_controller_entry_point() {
    let w = world();
    let mut doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    doc.rules.push(("ctl", w.controller.clone()));
    w.enroll(&doc);
    let (attempt, _, _) = open_lost_key(&w, None);
    authorize(&w, attempt);
    let ctl_rule = w.rule_id(&w.account, "ctl");

    // Every reserved name, as a context on the controller, is refused by the
    // account's own `__check_auth` before OZ evaluates the rule.
    let owner_payload = AuthPayload {
        signers: soroban_sdk::map![
            &w.env,
            (Signer::Delegated(w.owner.clone()), Bytes::new(&w.env))
        ],
        context_rule_ids: vec![&w.env, ctl_rule],
    };
    let check = |fn_name: &str| {
        let context = Context::Contract(ContractContext {
            contract: w.controller.clone(),
            fn_name: Symbol::new(&w.env, fn_name),
            args: vec![&w.env, w.account.clone().into_val(&w.env)],
        });
        w.env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(&w.env, &[3; 32]),
            owner_payload.clone().into_val(&w.env),
            &vec![&w.env, context],
        )
    };
    for name in perch_recovery_interface::account::RESERVED_INVOKER_ONLY_FNS {
        assert_eq!(
            check(name),
            Err(Ok(PerchAuthError::ReservedFunction.into())),
            "{name}"
        );
    }
    // A non-reserved controller entry point gets past the guard to OZ.
    assert_ne!(
        check("submit_guardian"),
        Err(Ok(PerchAuthError::ReservedFunction.into()))
    );

    // End to end: the owner signs each controller hook through that rule,
    // and every call fails without changing the controller's state.
    let config = w.ctl().config(&w.account).unwrap();
    let epoch = w.ctl().epoch(&w.account);
    let hash = w.client().applied_doc_hash().unwrap();
    let recovery_rule = w
        .client()
        .get_context_rule(&w.rule_id(&w.account, "recovery"));
    let signed = |fn_name: &str, args: std::vec::Vec<soroban_sdk::xdr::ScVal>| {
        let root = w.invocation(&w.controller, fn_name, args);
        w.env.set_auths(&[w.owner_entry("ctl", root)]);
    };
    let ctl = w.ctl();

    signed(
        "rcv_sync",
        std::vec![
            w.sc(w.account.clone()),
            w.sc(hash.clone()),
            w.sc(vec![&w.env, config.clone()]),
            w.sc(0u32)
        ],
    );
    assert!(ctl
        .try_rcv_sync(&w.account, &hash, &vec![&w.env, config.clone()], &0)
        .is_err());
    signed(
        "rcv_cancel",
        std::vec![w.sc(w.account.clone()), w.sc(attempt)],
    );
    assert!(ctl.try_rcv_cancel(&w.account, &attempt).is_err());
    let execute = perch_recovery::UpgradeStep::Execute(epoch);
    signed(
        "rcv_upgrade",
        std::vec![w.sc(w.account.clone()), w.sc(execute.clone())],
    );
    assert!(ctl.try_rcv_upgrade(&w.account, &execute).is_err());
    signed(
        "install",
        std::vec![
            w.sc(config.config_hash.clone()),
            w.sc(recovery_rule.clone()),
            w.sc(w.account.clone())
        ],
    );
    assert!(ctl
        .try_install(&config.config_hash, &recovery_rule, &w.account)
        .is_err());
    signed(
        "uninstall",
        std::vec![w.sc(recovery_rule.clone()), w.sc(w.account.clone())],
    );
    assert!(ctl.try_uninstall(&recovery_rule, &w.account).is_err());
    let forged = Context::Contract(ContractContext {
        contract: w.account.clone(),
        fn_name: Symbol::new(&w.env, "apply_doc"),
        args: vec![&w.env, w.client().applied_doc().unwrap().into_val(&w.env)],
    });
    let no_signers: soroban_sdk::Vec<Signer> = soroban_sdk::Vec::new(&w.env);
    signed(
        "enforce",
        std::vec![
            w.sc(forged.clone()),
            w.sc(no_signers.clone()),
            w.sc(recovery_rule.clone()),
            w.sc(w.account.clone())
        ],
    );
    assert!(ctl
        .try_enforce(&forged, &no_signers, &recovery_rule, &w.account)
        .is_err());
    w.env.set_auths(&[]);

    assert_eq!(w.ctl().epoch(&w.account), epoch);
    assert_eq!(w.ctl().config(&w.account), Some(config));
    assert_eq!(
        state(&w, attempt),
        AttemptState::Authorized,
        "not cancelled"
    );
}

#[test]
fn an_account_cannot_be_its_own_guardian() {
    let w = world();
    let mut r = w.recovery("loss", Mode::Guardian);
    r.guardians = Some(std::vec![w.account.clone(), w.guardians[0].clone()]);
    assert_eq!(
        err(w.apply(&w.doc(Some(r)), 0)),
        rec(RecoveryError::InvalidConfiguration)
    );
}

// ---------------------------------------------------------------------------
// D16: a perch account guards another through the same controller
// ---------------------------------------------------------------------------

#[test]
fn a_perch_account_guards_another_at_its_own_controller_until_it_is_frozen() {
    let w = world();
    // The guardian account: enrolled at the same controller, with a rule
    // letting its owner approve there.
    let g_owner = w.new_key();
    let g_account = w.env.register(
        PerchAccount,
        (vec![&w.env, Signer::Delegated(g_owner.clone())],),
    );
    let g_doc = Doc {
        signers: std::vec![("owner", g_owner.clone())],
        rules: std::vec![("ctl", w.controller.clone())],
        recovery: Some(w.recovery("protected", Mode::Guardian)),
    };
    let g_client = PerchAccountClient::new(&w.env, &g_account);
    let g_bytes = g_doc.bytes(&w);
    let root = w.invocation(
        &g_account,
        "apply_doc",
        std::vec![w.sc(g_bytes.clone()), w.sc(0u32), w.sc(None::<u64>)],
    );
    w.env.set_auths(&[w.delegated_entry(
        &g_account,
        &g_owner,
        w.rule_id(&g_account, "admin"),
        root,
    )]);
    g_client.apply_doc(&g_bytes, &0, &None);
    w.env.set_auths(&[]);

    let mut r = w.recovery("loss", Mode::Guardian);
    r.quorum = 1;
    r.guardians = Some(std::vec![g_account.clone()]);
    w.enroll(&w.doc(Some(r)));

    let approve = |id: u64| {
        let digest = w.digest(&w.statement(id, Initiate));
        let root = w.invocation(&w.controller, "submit_guardian", std::vec![w.sc(digest)]);
        w.env.set_auths(&[w.delegated_entry(
            &g_account,
            &g_owner,
            w.rule_id(&g_account, "ctl"),
            root,
        )]);
        let out = w
            .ctl()
            .try_submit_guardian(&w.account, &id, &Initiate, &g_account);
        w.env.set_auths(&[]);
        out
    };

    let (id, _, _) = open_lost_key(&w, None);
    assert!(
        approve(id).is_ok(),
        "no re-entry: the freeze is a local mirror"
    );
    assert_eq!(state(&w, id), AttemptState::Authorized);
    let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(id)]);
    w.env.set_auths(&[w.owner_entry("admin", cancel)]);
    w.client().cancel_recovery(&id);
    w.env.set_auths(&[]);

    // Freeze the guardian account: an attempt on it is authorized by its
    // own (stand-in) guardians.
    let g_replacements = w.replacements(&w.new_key(), None);
    let g_attempt = w.ctl().begin_lost_key(&g_account, &g_replacements);
    for i in 0..2 {
        let g = w.guardians[i].clone();
        let st = w.ctl().statement(&g_account, &g_attempt, &Initiate);
        w.env
            .set_auths(&[w.guardian_entry(&g, "submit_guardian", &w.digest(&st))]);
        w.ctl()
            .submit_guardian(&g_account, &g_attempt, &Initiate, &g);
    }
    w.env.set_auths(&[]);
    assert!(g_client.recovery_gate().is_some());

    let (id, _, _) = open_lost_key(&w, None);
    assert!(approve(id).is_err(), "a frozen account approves nothing");
}

// ---------------------------------------------------------------------------
// ZK: completion with rotation, nullifiers, the reconfigure domain
// ---------------------------------------------------------------------------

#[test]
fn a_zk_completion_spends_the_nullifier_and_installs_the_declared_enrollment() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Zk))));
    let first = enrollment(&w.env, 1);
    assert!(
        w.pool_client().enrollment(&w.account, &first.id).is_some(),
        "enrollment inserted the leaf"
    );
    assert!(w.client().is_enrolled_id(&first.id));

    let next = enrollment(&w.env, 2);
    let (id, new_owner, target) = open_lost_key(&w, Some(next.clone()));
    // Evidence is bound to the statement: a cancel proof does not initiate.
    let cancel_proof = w.proof(&w.statement(id, Cancel), &first.id);
    assert_eq!(
        w.ctl()
            .try_submit_zk(&w.account, &id, &Initiate, &cancel_proof),
        Err(Ok(RecoveryError::ZkEvidenceRejected))
    );
    w.try_zk(id, Initiate, &first.id).expect("proof");
    assert_eq!(state(&w, id), AttemptState::Authorized);
    assert!(w.client().recovery_gate().is_some());

    w.advance(DELAY);
    w.complete(&target)
        .expect("completion is not a reconfiguration");
    let n = nullifier(&w.env, &first.id);
    assert!(w.ctl().nullifier_spent(&w.account, &n));
    assert!(w.pool_client().enrollment(&w.account, &next.id).is_some());
    assert!(w.client().is_enrolled_id(&next.id));
    let config = w.ctl().config(&w.account).unwrap();
    assert_eq!(config.zk().unwrap().enrollment_id, next.id);
    assert!(w.activity_as(&new_owner));

    // The spent credential's nullifier is refused for any later statement,
    // even if an adapter accepted the proof.
    let (later, _, _) = open_lost_key(&w, Some(enrollment(&w.env, 3)));
    let st = w.statement(later, Initiate);
    let at = w.pool_client().enrollment(&w.account, &next.id).unwrap();
    let spent = ZkEvidence {
        tree_id: at.tree_id,
        root: w.pool_client().tree(&at.tree_id).root,
        nullifier: n.clone(),
        proof: mock_proof(&w.env, &w.digest(&st), &next.id, &n),
    };
    assert_eq!(
        w.ctl().try_submit_zk(&w.account, &later, &Initiate, &spent),
        Err(Ok(RecoveryError::NullifierSpent))
    );
}

/// Spent nullifiers are recorded per account. Any contract can enroll at
/// the shared controller with an adapter that accepts whatever nullifier it
/// likes (here the mock, which binds but does not derive it); its completion
/// must not spend the same value for anyone else.
#[test]
fn one_accounts_completion_never_spends_anothers_nullifier() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Zk))));
    let victim_credential = enrollment(&w.env, 1).id;
    let victim_n = nullifier(&w.env, &victim_credential);

    // A second account at the same controller, adapter, and pool.
    let other_key = w.new_key();
    let other = w.env.register(
        PerchAccount,
        (vec![&w.env, Signer::Delegated(other_key.clone())],),
    );
    let other_client = PerchAccountClient::new(&w.env, &other);
    let mut r = w.recovery("loss", Mode::Zk);
    r.enrollment = Some(enrollment(&w.env, 7));
    let other_doc = Doc {
        signers: std::vec![("owner", other_key.clone())],
        rules: std::vec![],
        recovery: Some(r),
    }
    .bytes(&w);
    let root = w.invocation(
        &other,
        "apply_doc",
        std::vec![w.sc(other_doc.clone()), w.sc(0u32), w.sc(None::<u64>)],
    );
    w.env
        .set_auths(&[w.delegated_entry(&other, &other_key, w.rule_id(&other, "admin"), root)]);
    other_client.apply_doc(&other_doc, &0, &None);
    w.env.set_auths(&[]);

    // It completes a recovery whose evidence carries the victim's nullifier.
    let replacements = w.replacements(&w.new_key(), Some(enrollment(&w.env, 8)));
    let source = other_client.applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&other, &replacements);
    let target = w
        .compiler()
        .derive_target(&source, &source, &RecoveryAction::LostKey, &replacements)
        .canonical;
    let own = enrollment(&w.env, 7).id;
    let at = w.pool_client().enrollment(&other, &own).unwrap();
    let st = w.ctl().statement(&other, &id, &Initiate);
    let evidence = ZkEvidence {
        tree_id: at.tree_id,
        root: w.pool_client().tree(&at.tree_id).root,
        nullifier: victim_n.clone(),
        proof: mock_proof(&w.env, &w.digest(&st), &own, &victim_n),
    };
    w.ctl().submit_zk(&other, &id, &Initiate, &evidence);
    w.advance(DELAY);
    let root = w.invocation(
        &other,
        "apply_doc",
        std::vec![w.sc(target.clone()), w.sc(0u32), w.sc(None::<u64>)],
    );
    w.env.set_auths(&[w.recovery_rule_entry_for(&other, root)]);
    other_client.apply_doc(&target, &0, &None);
    w.env.set_auths(&[]);
    assert!(w.ctl().nullifier_spent(&other, &victim_n));
    assert!(!w.ctl().nullifier_spent(&w.account, &victim_n));

    // The victim's credential still proves, and its own completion spends it.
    let (victim_attempt, _, victim_target) = open_lost_key(&w, Some(enrollment(&w.env, 2)));
    w.try_zk(victim_attempt, Initiate, &victim_credential)
        .expect("the victim's proof is still accepted");
    w.advance(DELAY);
    w.complete(&victim_target).unwrap();
    assert!(w.ctl().nullifier_spent(&w.account, &victim_n));
}

/// `enforce` runs for every context in an authorization tree, including a
/// sub-invocation that never executes. The marker it leaves must not turn a
/// later, unrelated `apply_doc` into a (failing) completion.
#[test]
fn a_marker_left_by_an_unexecuted_sub_invocation_is_ignored() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    let (id, _, target) = open_lost_key(&w, None);
    authorize(&w, id);
    w.advance(DELAY);

    // The owner signs `execute`, with an `apply_doc(target)` sub-invocation
    // selecting the recovery rule that never runs.
    let f = Symbol::new(&w.env, "protected");
    let call_args = vec![
        &w.env,
        IntoVal::<_, soroban_sdk::Val>::into_val(&w.account, &w.env),
    ];
    let mut root = w.invocation(
        &w.account,
        "execute",
        std::vec![
            w.sc(w.target.clone()),
            w.sc(f.clone()),
            w.sc(call_args.clone())
        ],
    );
    root.sub_invocations = std::vec![w.invocation(
        &w.account,
        "apply_doc",
        std::vec![w.sc(target.clone()), w.sc(0u32), w.sc(None::<u64>)],
    )]
    .try_into()
    .unwrap();
    let mut entry = w.owner_entry("admin", root);
    if let soroban_sdk::xdr::SorobanCredentials::AddressWithDelegates(c) = &mut entry.credentials {
        c.address_credentials.signature = w.sc(AuthPayload {
            signers: soroban_sdk::map![
                &w.env,
                (Signer::Delegated(w.owner.clone()), Bytes::new(&w.env))
            ],
            context_rule_ids: vec![
                &w.env,
                w.rule_id(&w.account, "admin"),
                w.rule_id(&w.account, "recovery"),
            ],
        });
    }
    w.env.set_auths(&[entry]);
    w.client().execute(&w.target, &f, &call_args);
    w.env.set_auths(&[]);

    // Same ledger: the owner cancels, then applies an unrelated document.
    let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(id)]);
    w.env.set_auths(&[w.owner_entry("admin", cancel)]);
    w.client().cancel_recovery(&id);
    w.env.set_auths(&[]);
    let mut quorum_one = w.recovery("loss", Mode::Guardian);
    quorum_one.quorum = 1;
    w.apply(&w.doc(Some(quorum_one)), 0)
        .expect("the stale marker is dropped, not taken for a completion");
}

#[test]
fn nullifiers_are_never_reserved_or_released() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Combined))));
    let credential = enrollment(&w.env, 1).id;
    let n = nullifier(&w.env, &credential);
    let (a, _, _) = open_lost_key(&w, Some(enrollment(&w.env, 2)));
    let (b, _, target) = open_lost_key(&w, Some(enrollment(&w.env, 3)));

    // The same credential evidences both attempts: nothing is reserved.
    w.try_zk(a, Initiate, &credential).unwrap();
    w.try_zk(b, Initiate, &credential).unwrap();
    assert!(!w.ctl().nullifier_spent(&w.account, &n));

    // Cancelling one attempt needs both factors, and releases nothing.
    w.guardian(0, a, Cancel);
    w.guardian(1, a, Cancel);
    assert_eq!(
        state(&w, a),
        AttemptState::Collecting,
        "guardians alone do not cancel Combined"
    );
    w.try_zk(a, Cancel, &credential).unwrap();
    assert_eq!(state(&w, a), AttemptState::Cancelled);
    assert!(!w.ctl().nullifier_spent(&w.account, &n));

    // The other attempt needs both factors too, then completes and spends.
    w.guardian(0, b, Initiate);
    assert_eq!(state(&w, b), AttemptState::Collecting);
    w.guardian(1, b, Initiate);
    assert_eq!(state(&w, b), AttemptState::Authorized);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert!(w.ctl().nullifier_spent(&w.account, &n));
}

#[test]
fn protected_zk_reconfiguration_is_its_own_proven_action() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Zk))));
    let credential = enrollment(&w.env, 1).id;
    let mut slower = w.recovery("protected", Mode::Zk);
    slower.delay = DELAY * 2;
    let next = w.doc(Some(slower));
    let until = w.ledger() + 50;
    let set = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next)));

    // A proof of another action does not serve.
    let remove = StatementSubject::Reconfigure(ConfigChange::Remove);
    let wrong = w.proof(
        &w.ctl().change_statement(&w.account, &remove, &until),
        &credential,
    );
    assert_eq!(
        w.ctl()
            .try_submit_zk_change(&w.account, &set, &until, &wrong),
        Err(Ok(RecoveryError::ZkEvidenceRejected))
    );
    assert_eq!(
        err(w.apply(&next, until)),
        rec(RecoveryError::ConditionNotMet)
    );

    let proof = w.proof(
        &w.ctl().change_statement(&w.account, &set, &until),
        &credential,
    );
    w.ctl().submit_zk_change(&w.account, &set, &until, &proof);
    w.apply(&next, until).expect("proven reconfiguration");
    assert_eq!(w.ctl().config(&w.account).unwrap().delay_ledgers, DELAY * 2);
    // Proving a change spends nothing.
    assert!(!w
        .ctl()
        .nullifier_spent(&w.account, &nullifier(&w.env, &credential)));
}

/// Spec §7.3 rule 8: a replaced credential leaves the account. Swapping two
/// replaceable slots' credentials would keep both replaced credentials
/// authorizing, and the completion would revoke credentials it installs.
#[test]
fn swapping_credentials_between_slots_is_refused() {
    let w = world();
    let mut r = w.recovery("loss", Mode::Guardian);
    r.replaceable = std::vec!["device", "owner"];
    w.enroll(&w.doc(Some(r)));
    let swap = perch_recovery_interface::credential::ReplacementSet {
        signers: vec![
            &w.env,
            perch_recovery_interface::credential::Replacement {
                signer_id: soroban_sdk::String::from_str(&w.env, "device"),
                credential: Credential::Delegated(w.owner.clone()),
            },
            perch_recovery_interface::credential::Replacement {
                signer_id: soroban_sdk::String::from_str(&w.env, "owner"),
                credential: Credential::Delegated(w.device.clone()),
            },
        ],
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    assert_eq!(
        w.ctl().try_begin_lost_key(&w.account, &swap),
        Err(Ok(RecoveryError::ReplacedCredentialRetained))
    );
    // Moving one slot's credential into another while the first gets a
    // fresh key also keeps a replaced credential.
    let shuffle = perch_recovery_interface::credential::ReplacementSet {
        signers: vec![
            &w.env,
            perch_recovery_interface::credential::Replacement {
                signer_id: soroban_sdk::String::from_str(&w.env, "device"),
                credential: Credential::Delegated(w.owner.clone()),
            },
            perch_recovery_interface::credential::Replacement {
                signer_id: soroban_sdk::String::from_str(&w.env, "owner"),
                credential: Credential::Delegated(w.new_key()),
            },
        ],
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    assert_eq!(
        w.ctl().try_begin_lost_key(&w.account, &shuffle),
        Err(Ok(RecoveryError::ReplacedCredentialRetained))
    );
}

/// Spec §7.3 rule 4: the enrollment-id freshness check is the controller's,
/// against the account's `is_enrolled_id`; the pure derivation cannot see
/// the account's history.
#[test]
fn a_recovery_cannot_rotate_to_an_enrollment_id_the_account_used() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Zk))));
    let mut rotated = w.recovery("loss", Mode::Zk);
    rotated.enrollment = Some(enrollment(&w.env, 2));
    w.enroll(&w.doc(Some(rotated)));
    for used in [1u8, 2] {
        let replacements = w.replacements(&w.new_key(), Some(enrollment(&w.env, used)));
        assert_eq!(
            w.ctl().try_begin_lost_key(&w.account, &replacements),
            Err(Ok(RecoveryError::EnrollmentIdReused)),
            "enrollment {used}"
        );
    }
    // The pure derivation accepts the same rotation: freshness is history.
    let replacements = w.replacements(&w.new_key(), Some(enrollment(&w.env, 1)));
    let current = w.client().applied_doc().unwrap();
    w.compiler()
        .derive_target(&current, &current, &RecoveryAction::LostKey, &replacements);
    w.ctl().begin_lost_key(
        &w.account,
        &w.replacements(&w.new_key(), Some(enrollment(&w.env, 3))),
    );
}

#[test]
fn zk_enrollments_are_fresh_wired_and_never_changed_in_place() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Zk))));

    let mut in_place = w.recovery("loss", Mode::Zk);
    in_place.enrollment.as_mut().unwrap().commitment = BytesN::from_array(&w.env, &[0x02; 32]);
    assert_eq!(
        err(w.apply(&w.doc(Some(in_place)), 0)),
        PerchAccountError::ZkFactorChangedInPlace
    );

    let mut rotated = w.recovery("loss", Mode::Zk);
    rotated.enrollment = Some(enrollment(&w.env, 2));
    w.enroll(&w.doc(Some(rotated)));
    assert!(w
        .pool_client()
        .enrollment(&w.account, &enrollment(&w.env, 2).id)
        .is_some());

    // Going back to an id this account enrolled before is refused, even
    // after removing recovery.
    w.enroll(&w.doc(None));
    assert_eq!(
        err(w.apply(&w.doc(Some(w.recovery("loss", Mode::Zk))), 0)),
        PerchAccountError::EnrollmentReused
    );

    // A factor no proof could satisfy is refused at enrollment.
    let mut unwired = w.recovery("loss", Mode::Zk);
    unwired.enrollment = Some(enrollment(&w.env, 4));
    unwired.adapter = w.new_key();
    assert_eq!(
        err(w.apply(&w.doc(Some(unwired)), 0)),
        rec(RecoveryError::ZkWiringMismatch)
    );
}

// ---------------------------------------------------------------------------
// §3.5, §7, §8: compromise recovery and revocation
// ---------------------------------------------------------------------------

#[test]
fn compromise_restores_the_baseline_and_revokes_everything_added_since() {
    let w = world();
    let baseline = w.doc(None);
    let mut r = w.recovery("protected", Mode::Guardian);
    r.baseline = Some(w.doc_hash(&baseline));
    w.enroll(&w.doc(Some(r.clone())));

    // A thief with the owner key adds a signer: no recovery text changes,
    // so no condition is needed under Protected.
    let thief = w.new_key();
    let mut stolen = w.doc(Some(r));
    stolen.signers.push(("thief", thief.clone()));
    w.enroll(&stolen);

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    assert_eq!(
        w.ctl().try_begin_compromise(&w.account, &replacements),
        Err(Ok(RecoveryError::BaselineNotPublished))
    );
    assert_eq!(
        w.ctl().try_publish_baseline(&w.account, &stolen.bytes(&w)),
        Err(Ok(RecoveryError::BaselineMismatch))
    );
    w.ctl().publish_baseline(&w.account, &baseline.bytes(&w));

    let id = w.ctl().begin_compromise(&w.account, &replacements);
    let source = w.ctl().baseline(&w.account).unwrap();
    let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    authorize(&w, id);
    w.advance(DELAY);
    w.complete(&target).expect("compromise completion");

    assert!(w.client().is_revoked(&fingerprint(&w, &w.owner)));
    assert!(
        w.client().is_revoked(&fingerprint(&w, &thief)),
        "added since the baseline"
    );
    assert!(!w.client().is_revoked(&fingerprint(&w, &w.device)));
    assert!(w.activity_as(&new_owner));
    assert!(!w.activity_as(&thief));
}

/// The review's sequence (spec §8): the baseline names owner A, the
/// current document has moved to owner B, and a compromise recovery
/// replaces A's slot with C. A must be revoked although the current
/// document no longer had it, or a second compromise recovery from the same
/// baseline would restore it.
#[test]
fn a_replaced_baseline_credential_never_returns() {
    let w = world();
    let baseline = w.doc(None);
    let mut r = w.recovery("loss", Mode::Guardian);
    r.baseline = Some(w.doc_hash(&baseline));
    w.enroll(&w.doc(Some(r.clone())));
    let (a, b, c) = (w.owner.clone(), w.new_key(), w.new_key());
    let mut moved = w.doc(Some(r));
    moved.signers[0].1 = b.clone();
    w.enroll(&moved);
    w.ctl().publish_baseline(&w.account, &baseline.bytes(&w));

    let replacements = w.replacements(&c, None);
    let id = w.ctl().begin_compromise(&w.account, &replacements);
    let source = w.ctl().baseline(&w.account).unwrap();
    let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    authorize(&w, id);
    w.advance(DELAY);
    w.complete(&target).unwrap();

    assert!(
        w.client().is_revoked(&fingerprint(&w, &a)),
        "replaced in the baseline"
    );
    assert!(
        w.client().is_revoked(&fingerprint(&w, &b)),
        "dropped from the current document"
    );
    assert!(!w.client().is_revoked(&fingerprint(&w, &c)));

    // A second compromise recovery from the same baseline cannot restore A.
    let empty = perch_recovery_interface::credential::ReplacementSet {
        signers: soroban_sdk::Vec::new(&w.env),
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    assert_eq!(
        w.ctl().try_begin_compromise(&w.account, &empty),
        Err(Ok(RecoveryError::CredentialRevoked))
    );
    assert!(!w.activity_as(&a));
    assert!(w.activity_as(&c));
}

/// Names for the rules that bring a test document (its two own rules plus
/// these) to the rule cap.
const CAP_RULE_NAMES: [&str; 14] = [
    "r00", "r01", "r02", "r03", "r04", "r05", "r06", "r07", "r08", "r09", "r10", "r11", "r12",
    "r13",
];
const CAP_RULES: &[&str] = CAP_RULE_NAMES
    .split_at(perch_doc_compiler::MAX_DOC_RULES as usize - 2)
    .0;

/// Spec §7.5: a completion's cost is bounded by the document caps, not by
/// the account's history. `apply_doc` once scanned every rule id ever
/// assigned, so (the review's regression) 19 applications of a 16-rule
/// document (the cap then) pushed a completion past the 400-entry footprint limit, and a
/// twentieth ordinary application failed at 403. The test host enforces
/// the mainnet limits, so every application and the completion here must
/// fit, and the completion's footprint must not depend on the churn.
#[test]
fn completion_cost_does_not_grow_with_policy_churn() {
    let completion_entries = |applications: u32| {
        let w = world();
        let mut doc = w.doc(Some(w.recovery("protected", Mode::Guardian)));
        for &name in CAP_RULES {
            doc.rules.push((name, w.new_key()));
        }
        for _ in 0..applications {
            w.enroll(&doc);
        }
        let (id, _, target) = open_lost_key(&w, None);
        authorize(&w, id);
        w.advance(DELAY);
        w.complete(&target)
            .expect("completion within the footprint limits");
        let used = w.env.cost_estimate().resources();
        used.disk_read_entries + used.memory_read_entries + used.write_entries
    };
    let once = completion_entries(1);
    let churned = completion_entries(40);
    assert_eq!(once, churned, "completion footprint grew with history");
    assert!(once <= 400);
}

#[test]
fn an_old_baseline_cannot_restore_a_revoked_credential() {
    let w = world();
    let baseline = w.doc(None);
    let mut r = w.recovery("loss", Mode::Guardian);
    r.baseline = Some(w.doc_hash(&baseline));
    w.enroll(&w.doc(Some(r)));
    w.ctl().publish_baseline(&w.account, &baseline.bytes(&w));

    // A lost-key recovery revokes the original owner key.
    let (id, new_owner, target) = open_lost_key(&w, None);
    authorize(&w, id);
    w.advance(DELAY);
    w.complete(&target).unwrap();

    // The baseline still names that key: restoring it as is is refused...
    let empty = perch_recovery_interface::credential::ReplacementSet {
        signers: soroban_sdk::Vec::new(&w.env),
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    assert_eq!(
        w.ctl().try_begin_compromise(&w.account, &empty),
        Err(Ok(RecoveryError::CredentialRevoked))
    );
    // ...and so is replacing it with another revoked key; a fresh one works.
    assert_eq!(
        w.ctl()
            .try_begin_compromise(&w.account, &w.replacements(&w.owner, None)),
        Err(Ok(RecoveryError::CredentialRevoked))
    );
    let _ = new_owner;
    w.ctl()
        .begin_compromise(&w.account, &w.replacements(&w.new_key(), None));
}

#[test]
fn replacement_sets_follow_the_permitted_change_rules() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let refused = |set: &perch_recovery_interface::credential::ReplacementSet| {
        w.ctl().try_begin_lost_key(&w.account, set)
    };
    // Not replaceable.
    let mut device = w.replacements(&w.new_key(), None);
    device.signers.set(
        0,
        perch_recovery_interface::credential::Replacement {
            signer_id: soroban_sdk::String::from_str(&w.env, "device"),
            credential: Credential::Delegated(w.new_key()),
        },
    );
    assert_eq!(
        refused(&device),
        Err(Ok(RecoveryError::InvalidReplacements))
    );
    // A different kind of credential for the slot.
    let mut external = w.replacements(&w.new_key(), None);
    external.signers.set(
        0,
        perch_recovery_interface::credential::Replacement {
            signer_id: soroban_sdk::String::from_str(&w.env, "owner"),
            credential: Credential::External(w.target.clone(), Bytes::from_array(&w.env, &[1; 32])),
        },
    );
    assert_eq!(
        refused(&external),
        Err(Ok(RecoveryError::InvalidReplacements))
    );
    // A ZK enrollment for a guardian-only mode.
    assert_eq!(
        refused(&w.replacements(&w.new_key(), Some(enrollment(&w.env, 9)))),
        Err(Ok(RecoveryError::InvalidReplacements))
    );
    // Nothing to replace.
    let empty = perch_recovery_interface::credential::ReplacementSet {
        signers: soroban_sdk::Vec::new(&w.env),
        zk_enrollment: soroban_sdk::Vec::new(&w.env),
    };
    assert_eq!(refused(&empty), Err(Ok(RecoveryError::InvalidReplacements)));
    // Spec §7.3 rule 8: "replacing" a slot with the credential it already
    // holds keeps a replaced credential in the target.
    assert_eq!(
        refused(&w.replacements(&w.owner, None)),
        Err(Ok(RecoveryError::ReplacedCredentialRetained))
    );
    // A replacement key equal to another signer's fails document validation.
    assert_eq!(
        refused(&w.replacements(&w.device, None)),
        Err(Ok(RecoveryError::InvalidReplacements))
    );
}
