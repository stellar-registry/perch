//! The shared account's capabilities under ENFORCING authorization:
//! execution through the account, full applied-document reads, and the
//! delayed, recovery-aware upgrade path (`docs/recovery/spec.md` §12, §15).

mod support;

use perch_account::PerchAccountError;
use perch_recovery::{EvidenceDomain, RecoveryError};
use perch_recovery_interface::account::ACCOUNT_UPGRADE_DELAY_LEDGERS;
use perch_recovery_interface::{RecoveryAction, StatementSubject, UpgradeSubject};
use perch_smart_account::infra;
use soroban_sdk::{vec, Address, Bytes, BytesN, IntoVal, Symbol, Val, Vec};
use support::*;

fn rec(e: RecoveryError) -> PerchAccountError {
    PerchAccountError::Recovery(e)
}

/// Any real Wasm to upgrade to: the fetched spending-limit build the
/// account already pins (`scripts/fetch-infra-wasm.sh`).
const UPGRADE_WASM: &[u8] =
    include_bytes!("../../perch-smart-account/wasm/perch-spending-limit.wasm");

fn upload(w: &World) -> BytesN<32> {
    w.env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&w.env, UPGRADE_WASM))
}

fn args(w: &World, account: &Address) -> Vec<Val> {
    vec![&w.env, IntoVal::<_, Val>::into_val(account, &w.env)]
}

fn execute(
    w: &World,
    target: &Address,
    fn_name: &str,
    call_args: Vec<Val>,
) -> Result<Val, Result<PerchAccountError, soroban_sdk::InvokeError>> {
    let f = Symbol::new(&w.env, fn_name);
    let root = w.invocation(
        &w.account,
        "execute",
        std::vec![
            w.sc(target.clone()),
            w.sc(f.clone()),
            w.sc(call_args.clone())
        ],
    );
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    let out = w.client().try_execute(target, &f, &call_args);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

fn schedule(
    w: &World,
    wasm: &BytesN<32>,
    valid_until: u32,
) -> Result<u64, Result<PerchAccountError, soroban_sdk::InvokeError>> {
    let root = w.invocation(
        &w.account,
        "schedule_upgrade",
        std::vec![w.sc(wasm.clone()), w.sc(valid_until)],
    );
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    let out = w.client().try_schedule_upgrade(wasm, &valid_until);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

fn execute_upgrade(
    w: &World,
    request: u64,
) -> Result<(), Result<PerchAccountError, soroban_sdk::InvokeError>> {
    let root = w.invocation(&w.account, "execute_upgrade", std::vec![w.sc(request)]);
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    let out = w.client().try_execute_upgrade(&request);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

#[test]
fn execute_calls_as_the_account_and_refuses_invoker_only_hooks() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Zk))));

    // The target's `account.require_auth()` passes by invoker authorization.
    let hits = execute(&w, &w.target, "protected", args(&w, &w.account)).expect("execute");
    let hits: u32 = soroban_sdk::FromVal::from_val(&w.env, &hits);
    assert_eq!(hits, 1);

    // Reserved names, on any contract: execute would make the account the
    // invoker of a hook.
    for (target, f) in [
        (&w.controller, "rcv_cancel"),
        (&w.pool, "rcv_insert"),
        (&w.target, "install"),
        (&w.account, "rcv_gate"),
    ] {
        assert_eq!(
            err(execute(&w, target, f, args(&w, &w.account))),
            PerchAccountError::ReservedFunction,
            "{f}"
        );
    }

    // Execution needs the owner's authorization.
    let f = Symbol::new(&w.env, "protected");
    assert!(w
        .client()
        .try_execute(&w.target, &f, &args(&w, &w.account))
        .is_err());
}

// ---------------------------------------------------------------------------
// Full applied-document reads
// ---------------------------------------------------------------------------

#[test]
fn the_account_serves_its_full_canonical_applied_document() {
    let w = world();
    assert_eq!(w.client().applied_doc(), None);
    assert_eq!(
        w.client().doc_compiler(),
        infra::perch_doc_compiler::address(&w.env)
    );

    // Submitted with insignificant whitespace; stored canonical.
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    let pretty = doc.json(&w).replace(",", ", ").replace("{", "{ ");
    let hash = w
        .apply_bytes(&Bytes::from_slice(&w.env, pretty.as_bytes()), 0)
        .unwrap();
    let stored = w.client().applied_doc().unwrap();
    assert_eq!(w.env.crypto().sha256(&stored).to_bytes(), hash);
    assert_eq!(w.client().applied_doc_hash(), Some(hash));
    assert_eq!(stored, w.compiler().compile_doc(&doc.bytes(&w)).canonical);
    assert_ne!(stored.len() as usize, pretty.len());
}

// ---------------------------------------------------------------------------
// Upgrades
// ---------------------------------------------------------------------------

#[test]
fn an_upgrade_waits_out_the_delay_then_replaces_the_code() {
    let w = world();
    w.enroll(&w.doc(None));
    let wasm = upload(&w);
    assert_eq!(w.client().next_upgrade_request_id(), 0);

    // Owner authorization is required.
    assert!(w.client().try_schedule_upgrade(&wasm, &0).is_err());
    let id = schedule(&w, &wasm, 0).unwrap();
    assert_eq!(id, 0);
    let pending = w.client().pending_upgrade().unwrap();
    assert_eq!(
        pending.executable_at,
        w.ledger() + ACCOUNT_UPGRADE_DELAY_LEDGERS
    );
    assert_eq!(pending.controller_epoch, None);
    assert_eq!(pending.generation, w.client().recovery_generation());

    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::UpgradeNotReady
    );
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS - 1);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::UpgradeNotReady
    );
    w.advance(1);
    assert_eq!(
        err(execute_upgrade(&w, id + 1)),
        PerchAccountError::UpgradeRequestMismatch
    );
    assert_eq!(execute_upgrade(&w, id), Ok(()));
    // The account now runs the new code, which has no perch entry points.
    assert!(w.client().try_applied_doc_hash().is_err());
}

#[test]
fn cancelling_or_rescheduling_drops_the_pending_upgrade() {
    let w = world();
    w.enroll(&w.doc(None));
    let wasm = upload(&w);
    let first = schedule(&w, &wasm, 0).unwrap();
    let second = schedule(&w, &wasm, 0).unwrap();
    assert_eq!(second, first + 1, "request ids are never reused");
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(
        err(execute_upgrade(&w, first)),
        PerchAccountError::UpgradeRequestMismatch
    );

    let root = w.invocation(&w.account, "cancel_upgrade", std::vec![]);
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    w.client().cancel_upgrade();
    w.env.set_auths(&[]);
    assert_eq!(w.client().pending_upgrade(), None);
    assert_eq!(
        err(execute_upgrade(&w, second)),
        PerchAccountError::NoPendingUpgrade
    );
}

#[test]
fn any_recovery_transition_makes_a_queued_upgrade_stale() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    assert_eq!(w.client().recovery_generation(), 1, "enrollment");
    let wasm = upload(&w);
    let id = schedule(&w, &wasm, 0).unwrap();
    assert_eq!(
        w.client().pending_upgrade().unwrap().controller_epoch,
        Some(w.ctl().epoch(&w.account))
    );

    // A reconfiguration advances the generation.
    let mut quorum_one = w.recovery("loss", Mode::Guardian);
    quorum_one.quorum = 1;
    w.enroll(&w.doc(Some(quorum_one)));
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    let pending = w.client().pending_upgrade();
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade
    );
    assert_eq!(
        w.client().pending_upgrade(),
        pending,
        "refused, so nothing is cleared"
    );
    assert!(
        w.client().try_applied_doc_hash().is_ok(),
        "the code is unchanged"
    );

    // So does dropping a controller. Scheduling replaces the inert request.
    let id = schedule(&w, &wasm, 0).unwrap();
    assert_eq!(w.client().pending_upgrade().unwrap().request_id, id);
    w.enroll(&w.doc(None));
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade
    );
}

/// Spec §12: a stale request is refused whether or not its delay has
/// passed, and the refusal records nothing. The request stays, inert,
/// until it is cancelled or replaced.
#[test]
fn a_stale_upgrade_is_refused_without_being_cleared() {
    let w = world();
    w.enroll(&w.doc(None));
    let wasm = upload(&w);
    let id = schedule(&w, &wasm, 0).unwrap();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let pending = w.client().pending_upgrade();

    // Before the delay: stale wins over not-yet.
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade
    );
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade
    );
    assert!(
        perch_testkit::delta::events(&w.env).is_empty(),
        "a refused call publishes nothing"
    );
    assert_eq!(w.client().pending_upgrade(), pending);

    // It never becomes executable: nothing lowers the generation.
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade
    );

    let root = w.invocation(&w.account, "cancel_upgrade", std::vec![]);
    w.env.set_auths(&[w.owner_entry("admin", root)]);
    w.client().cancel_upgrade();
    w.env.set_auths(&[]);
    assert_eq!(w.client().pending_upgrade(), None);
}

/// Spec §12: completion advances the generation and also clears the slot.
#[test]
fn a_completed_recovery_clears_the_pending_upgrade() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let wasm = upload(&w);
    schedule(&w, &wasm, 0).unwrap();
    let generation = w.client().recovery_generation();

    let replacements = w.replacements(&w.new_key(), None);
    let source = w.client().applied_doc().unwrap();
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(
        perch_recovery_interface::RecoveryAction::LostKey,
        &source,
        &replacements,
    );
    w.guardian(0, attempt, EvidenceDomain::Initiate);
    w.guardian(1, attempt, EvidenceDomain::Initiate);
    let authorized = w.ctl().attempt(&w.account, &attempt).unwrap();
    w.advance(authorized.executable_after - w.ledger());
    w.complete(&target).expect("completes");

    assert_eq!(w.client().pending_upgrade(), None);
    assert_eq!(w.client().recovery_generation(), generation + 1);
}

/// The review's sequence: schedule while unenrolled, enroll, remove, wait
/// out the delay. The account ends with no controller, as at scheduling,
/// but its recovery generation moved twice, so the request is dead. Only an
/// account-owned counter catches this: no controller epoch spans the
/// unenrolled periods.
#[test]
fn enrolling_and_removing_recovery_stales_an_unenrolled_upgrade() {
    let w = world();
    w.enroll(&w.doc(None));
    assert_eq!(
        w.client().recovery_generation(),
        0,
        "no recovery transition yet"
    );
    let wasm = upload(&w);
    let id = schedule(&w, &wasm, 0).unwrap();
    assert_eq!(w.client().pending_upgrade().unwrap().controller_epoch, None);

    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    w.enroll(&w.doc(None));
    assert_eq!(w.client().recovery_generation(), 2);
    assert_eq!(w.client().recovery_controller(), None);

    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        PerchAccountError::StaleUpgrade,
        "stale, not executed"
    );
    assert!(
        w.client().try_applied_doc_hash().is_ok(),
        "the code is unchanged"
    );

    // A request scheduled after the cycle, with no transition since, runs.
    let id = schedule(&w, &wasm, 0).unwrap();
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(execute_upgrade(&w, id), Ok(()));
}

#[test]
fn a_controller_switch_and_an_executed_upgrade_advance_the_generation() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    assert_eq!(w.client().recovery_generation(), 1);
    // Re-applying the same configuration is not a transition.
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    assert_eq!(w.client().recovery_generation(), 1);

    // A switch removes at one controller and enrolls at the other.
    let other = w.env.register(perch_recovery::PerchRecovery, ());
    let mut switched = w.recovery("loss", Mode::Guardian);
    switched.controller = other.clone();
    w.enroll(&w.doc(Some(switched)));
    assert_eq!(w.client().recovery_controller(), Some(other));
    assert_eq!(w.client().recovery_generation(), 3);

    let wasm = upload(&w);
    let id = schedule(&w, &wasm, 0).unwrap();
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    assert_eq!(execute_upgrade(&w, id), Ok(()));
}

#[test]
fn upgrades_are_blocked_while_an_attempt_is_authorized() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let wasm = upload(&w);
    let id = schedule(&w, &wasm, 0).unwrap();

    let replacements = w.replacements(&w.new_key(), None);
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    w.guardian(0, attempt, EvidenceDomain::Initiate);
    w.guardian(1, attempt, EvidenceDomain::Initiate);
    assert_eq!(
        err(schedule(&w, &wasm, 0)),
        rec(RecoveryError::AttemptAuthorized)
    );
    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    // The attempt expired by now under these short windows; re-authorize one
    // that is live at execution time.
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    w.guardian(0, attempt, EvidenceDomain::Initiate);
    w.guardian(1, attempt, EvidenceDomain::Initiate);
    assert_eq!(
        err(execute_upgrade(&w, id)),
        rec(RecoveryError::AttemptAuthorized)
    );
    assert!(
        w.client().pending_upgrade().is_some(),
        "a refusal changes nothing"
    );

    // Once the Loss owner cancels it, the upgrade runs.
    let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(attempt)]);
    w.env.set_auths(&[w.owner_entry("admin", cancel)]);
    w.client().cancel_recovery(&attempt);
    w.env.set_auths(&[]);
    assert_eq!(execute_upgrade(&w, id), Ok(()));
}

#[test]
fn protected_upgrades_need_the_condition_over_the_exact_wasm() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let wasm = upload(&w);
    let other = BytesN::from_array(&w.env, &[0xee; 32]);
    let until = w.ledger() + 50;
    let request_id = w.client().next_upgrade_request_id();

    assert_eq!(
        err(schedule(&w, &wasm, until)),
        rec(RecoveryError::ConditionNotMet)
    );
    let approve = |wasm_hash: &BytesN<32>| {
        let subject = StatementSubject::Upgrade(UpgradeSubject {
            request_id,
            wasm_hash: wasm_hash.clone(),
        });
        w.approve_change(0, &subject, until);
        w.approve_change(1, &subject, until);
    };
    approve(&other);
    assert_eq!(
        err(schedule(&w, &wasm, until)),
        rec(RecoveryError::ConditionNotMet)
    );
    approve(&wasm);
    let id = schedule(&w, &wasm, until).expect("approved");
    assert_eq!(id, request_id);

    // A successful recovery clears it.
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, attempt, EvidenceDomain::Initiate);
    w.guardian(1, attempt, EvidenceDomain::Initiate);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert_eq!(w.client().pending_upgrade(), None);
}
