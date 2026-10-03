//! The testnet scenarios: the four flows of
//! `crates/integration-tests/tests/release_stack.rs`, on the deployed
//! contracts, with real G-account guardians. A step that must fail is
//! simulated under enforcing authorization and never submitted.

use anyhow::{ensure, Result};
use perch_account::PerchAccountError;
use perch_recovery::{EvidenceDomain, RecoveryError};
use perch_recovery_interface::{ConfigChange, StatementSubject, UpgradeSubject};
use soroban_sdk::{Bytes, BytesN};
use soroban_sdk_tools::ContractError as _;

use crate::world::{tamper, Mode, Rec, World, DELAY, EXPIRY};

fn code(e: RecoveryError) -> Option<u32> {
    Some(e.into_code())
}

/// `ZkOnly` under `Loss`: a lost passkey replaced with a real proof.
pub fn zk_lost_key(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("zk-only / loss: lost-key recovery with a real proof");
    let a = w.new_account("zk-loss", w.passkey("zk-loss/owner"))?;
    let zk1 = w.zk("zk-loss/zk1");
    let rec = Rec {
        profile: "loss",
        mode: Mode::Zk,
        zk: Some(zk1.clone()),
        guardians: vec![],
        delay: DELAY,
    };
    let doc = w.doc(&a.owner, Some(&rec));
    w.apply(
        "enroll ZkOnly through apply_doc (pool insert)",
        &a,
        &a.owner,
        &doc,
        0,
    )?;
    w.activity("ordinary activity: direct authorization", &a, &a.owner)?;
    w.execute("ordinary activity: execute", &a, &a.owner)?;

    let new_owner = w.passkey("zk-loss/new-owner");
    let zk2 = w.zk("zk-loss/zk2");
    let r = w.replacements(&new_owner, Some(&zk2));
    let attempt = w.begin_lost_key("begin_lost_key", &a, &r)?;
    let decoy = w.begin_lost_key("begin_lost_key (a second, evidence-free attempt)", &a, &r)?;
    // Collecting attempts block nothing.
    w.activity("activity while attempts collect", &a, &a.owner)?;

    let statement = w.statement(&a, attempt, EvidenceDomain::Initiate)?;
    let ev = w.prove(&a, &zk1, &statement)?;
    let rejected = code(RecoveryError::ZkEvidenceRejected);
    let submit = |label: &str, ev: &perch_recovery_interface::zk::ZkEvidence, code| {
        c.refused(
            label,
            &w.s.controller,
            "submit_zk",
            w.zk_args(&a, attempt, EvidenceDomain::Initiate, ev),
            &[],
            code,
        )
    };
    let decoy_ev = w.prove(&a, &zk1, &w.statement(&a, decoy, EvidenceDomain::Initiate)?)?;
    submit("another attempt's proof", &decoy_ev, rejected)?;
    let cancel_ev = w.prove(&a, &zk1, &w.statement(&a, attempt, EvidenceDomain::Cancel)?)?;
    submit("a Cancel proof submitted as Initiate", &cancel_ev, rejected)?;
    submit("a tampered proof", &tamper(&c.env, &ev), rejected)?;
    let mut wrong_root = ev.clone();
    wrong_root.root = BytesN::from_array(&c.env, &w.field("not a root"));
    submit("a root the pool never had", &wrong_root, rejected)?;

    c.call(
        "submit_zk (real proof; authorizes the attempt)",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, attempt, EvidenceDomain::Initiate, &ev),
        &[],
    )?;
    submit(
        "the same proof again",
        &ev,
        code(RecoveryError::AttemptNotCollecting),
    )?;

    // Loss: activity continues, conflicting policy changes do not.
    w.activity("Loss: activity during the authorized window", &a, &a.owner)?;
    w.apply_refused(
        "Loss: an owner policy change during the window",
        &a,
        &a.owner,
        &w.doc(&a.owner, None),
        0,
        Some(PerchAccountError::Recovery(
            RecoveryError::AttemptAuthorized,
        )),
    )?;

    let target = w.target_bytes(&a, &r)?;
    w.complete_refused("completion before the delay", &a, &target)?;
    c.wait_for_ledger(w.attempt(&a, attempt)?.executable_after)?;
    let mut wrong = Bytes::from_slice(&c.env, b" ");
    wrong.append(&target);
    w.complete_refused("completion with other bytes than the target", &a, &wrong)?;
    w.complete(
        "completion apply_doc (spends the nullifier, rotates the leaf)",
        &a,
        &target,
    )?;

    let applied: Option<BytesN<32>> = c.read_as(&a.address, "applied_doc_hash", vec![])?;
    ensure!(
        applied == Some(c.env.crypto().sha256(&target).to_bytes()),
        "target not applied"
    );
    let spent: bool = c.read_as(
        &w.s.controller,
        "nullifier_spent",
        vec![c.sc(c.address(&a.address)), c.sc(ev.nullifier.clone())],
    )?;
    ensure!(spent, "nullifier not spent");
    w.activity_refused("the lost passkey after recovery", &a, &a.owner)?;
    w.activity("the new passkey after recovery", &a, &new_owner)?;

    // The consumed credential can never recover again.
    let next = w.passkey("zk-loss/next-owner");
    let zk3 = w.zk("zk-loss/zk3");
    let again = w.begin_lost_key(
        "begin_lost_key (after recovery)",
        &a,
        &w.replacements(&next, Some(&zk3)),
    )?;
    let stale = w.prove(&a, &zk1, &w.statement(&a, again, EvidenceDomain::Initiate)?)?;
    c.refused(
        "a proof by the consumed credential",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, again, EvidenceDomain::Initiate, &stale),
        &[],
        rejected,
    )?;
    Ok(())
}

/// `Combined` under `Protected`: G-account guardians and a real proof
/// authorize; the account freezes on every path; the condition's
/// cancellation lifts it; reconfiguration needs both factors.
pub fn combined_protected(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("combined / protected: freeze, cancellation, reconfiguration");
    let guardians = [
        w.g_account("combined/g0")?,
        w.g_account("combined/g1")?,
        w.g_account("combined/g2")?,
    ];
    let a = w.new_account("combined-protected", w.passkey("combined/owner"))?;
    let zk = w.zk("combined/zk");
    let rec = Rec {
        profile: "protected",
        mode: Mode::Combined,
        zk: Some(zk.clone()),
        guardians: guardians.iter().map(|g| g.account()).collect(),
        delay: DELAY,
    };
    w.apply(
        "enroll Combined through apply_doc",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;

    let thief = w.passkey("combined/thief");
    let r = w.replacements(&thief, Some(&w.zk("combined/thief-zk")));
    let attempt = w.begin_lost_key("begin_lost_key", &a, &r)?;
    w.guardian(
        "submit_guardian (G-account, 1 of 2)",
        &guardians[0],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.guardian(
        "submit_guardian (G-account, 2 of 2)",
        &guardians[1],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.activity("activity before the condition is met", &a, &a.owner)?;
    let ev = w.prove(
        &a,
        &zk,
        &w.statement(&a, attempt, EvidenceDomain::Initiate)?,
    )?;
    c.call(
        "submit_zk (Combined, promoting; sets the freeze)",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, attempt, EvidenceDomain::Initiate, &ev),
        &[],
    )?;

    w.activity_refused("frozen: direct authorization", &a, &a.owner)?;
    w.execute_refused("frozen: execute", &a, &a.owner)?;
    w.apply_refused_at_auth("frozen: apply_doc", &a, &a.owner, &w.doc(&a.owner, None))?;

    c.refused(
        "an Initiate proof submitted as Cancel",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, attempt, EvidenceDomain::Cancel, &ev),
        &[],
        code(RecoveryError::ZkEvidenceRejected),
    )?;
    w.guardian(
        "cancel: guardian 1 of 2",
        &guardians[0],
        &a,
        attempt,
        EvidenceDomain::Cancel,
    )?;
    w.guardian(
        "cancel: guardian 2 of 2",
        &guardians[2],
        &a,
        attempt,
        EvidenceDomain::Cancel,
    )?;
    let cancel = w.prove(&a, &zk, &w.statement(&a, attempt, EvidenceDomain::Cancel)?)?;
    c.call(
        "cancellation (Combined: the ZK Cancel proof completes it, clears the freeze)",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, attempt, EvidenceDomain::Cancel, &cancel),
        &[],
    )?;
    w.activity("activity after the cancellation", &a, &a.owner)?;
    w.execute("execute after the cancellation", &a, &a.owner)?;

    // Reconfiguring a Combined account needs both factors.
    let next = Rec {
        delay: DELAY * 2,
        ..rec.clone()
    };
    let next_doc = w.doc(&a.owner, Some(&next));
    let valid_until = c.latest_ledger()? + EXPIRY - 20;
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next_doc)?));
    let proof = w.prove(&a, &zk, &w.change_statement(&a, &subject, valid_until)?)?;
    c.call(
        "submit_zk_change (Reconfigure)",
        &w.s.controller,
        "submit_zk_change",
        vec![
            c.sc(c.address(&a.address)),
            c.sc(subject.clone()),
            c.sc(valid_until),
            c.sc(proof),
        ],
        &[],
    )?;
    w.apply_refused(
        "reconfiguration with ZK evidence alone",
        &a,
        &a.owner,
        &next_doc,
        valid_until,
        Some(PerchAccountError::Recovery(RecoveryError::ConditionNotMet)),
    )?;
    w.approve_change(
        "approve_change (G-account, 1 of 2)",
        &guardians[0],
        &a,
        &subject,
        valid_until,
    )?;
    w.approve_change(
        "approve_change (G-account, 2 of 2)",
        &guardians[1],
        &a,
        &subject,
        valid_until,
    )?;
    w.apply(
        "Protected Combined reconfiguration apply_doc",
        &a,
        &a.owner,
        &next_doc,
        valid_until,
    )?;
    Ok(())
}

/// `ZkOnly` under `Protected`: reconfiguration and an upgrade need real
/// proofs over their own statements.
pub fn zk_protected_changes(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("zk-only / protected: reconfiguration and upgrade evidence");
    let a = w.new_account("zk-protected", w.passkey("zk-protected/owner"))?;
    let zk = w.zk("zk-protected/zk");
    let rec = Rec {
        profile: "protected",
        mode: Mode::Zk,
        zk: Some(zk.clone()),
        guardians: vec![],
        delay: DELAY,
    };
    w.apply(
        "enroll ZkOnly Protected",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;

    let next = Rec {
        delay: DELAY * 2,
        ..rec.clone()
    };
    let next_doc = w.doc(&a.owner, Some(&next));
    let valid_until = c.latest_ledger()? + EXPIRY - 20;
    w.apply_refused(
        "owner alone cannot reconfigure",
        &a,
        &a.owner,
        &next_doc,
        valid_until,
        Some(PerchAccountError::Recovery(RecoveryError::ConditionNotMet)),
    )?;
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&next_doc)?));
    let other = Rec {
        delay: DELAY * 3,
        ..rec.clone()
    };
    let other_subject = StatementSubject::Reconfigure(ConfigChange::Set(
        w.config_hash(&w.doc(&a.owner, Some(&other)))?,
    ));
    let other_proof = w.prove(
        &a,
        &zk,
        &w.change_statement(&a, &other_subject, valid_until)?,
    )?;
    let change_args = |s: &StatementSubject, p| {
        vec![
            c.sc(c.address(&a.address)),
            c.sc(s.clone()),
            c.sc(valid_until),
            c.sc(p),
        ]
    };
    c.refused(
        "a proof for another configuration",
        &w.s.controller,
        "submit_zk_change",
        change_args(&subject, other_proof),
        &[],
        code(RecoveryError::ZkEvidenceRejected),
    )?;
    let proof = w.prove(&a, &zk, &w.change_statement(&a, &subject, valid_until)?)?;
    c.call(
        "submit_zk_change (Reconfigure)",
        &w.s.controller,
        "submit_zk_change",
        change_args(&subject, proof),
        &[],
    )?;
    w.apply(
        "Protected reconfiguration apply_doc",
        &a,
        &a.owner,
        &next_doc,
        valid_until,
    )?;

    // An upgrade request names the exact wasm and request id.
    let wasm = BytesN::from_array(&c.env, &w.s.account_wasm);
    let request_id: u64 = c.read_as(&a.address, "next_upgrade_request_id", vec![])?;
    let valid_until = c.latest_ledger()? + EXPIRY - 20;
    let schedule_args = vec![c.sc(wasm.clone()), c.sc(valid_until)];
    let owner = w.owner_auth(&a, &a.owner, "admin")?;
    c.refused(
        "owner alone cannot schedule an upgrade",
        &a.address,
        "schedule_upgrade",
        schedule_args.clone(),
        &[owner],
        None,
    )?;
    let subject = StatementSubject::Upgrade(UpgradeSubject {
        request_id,
        wasm_hash: wasm,
    });
    let proof = w.prove(&a, &zk, &w.change_statement(&a, &subject, valid_until)?)?;
    c.call(
        "submit_zk_change (Upgrade)",
        &w.s.controller,
        "submit_zk_change",
        vec![
            c.sc(c.address(&a.address)),
            c.sc(subject),
            c.sc(valid_until),
            c.sc(proof),
        ],
        &[],
    )?;
    let owner = w.owner_auth(&a, &a.owner, "admin")?;
    c.call(
        "Protected schedule_upgrade",
        &a.address,
        "schedule_upgrade",
        schedule_args,
        &[owner],
    )?;
    let owner = w.owner_auth(&a, &a.owner, "admin")?;
    c.refused(
        "execute_upgrade before the seven-day delay",
        &a.address,
        "execute_upgrade",
        vec![c.sc(request_id)],
        &[owner],
        None,
    )?;
    Ok(())
}

/// `GuardianOnly` under `Loss`: no ZK anywhere, and the owner's veto.
pub fn guardian_loss(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("guardian-only / loss: veto and completion, no ZK");
    let guardians = [
        w.g_account("guardian/g0")?,
        w.g_account("guardian/g1")?,
        w.g_account("guardian/g2")?,
    ];
    let a = w.new_account("guardian-loss", w.passkey("guardian/owner"))?;
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        guardians: guardians.iter().map(|g| g.account()).collect(),
        delay: DELAY,
    };
    w.apply(
        "enroll GuardianOnly through apply_doc",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;
    let new_owner = w.passkey("guardian/new-owner");
    let r = w.replacements(&new_owner, None);

    let vetoed = w.begin_lost_key("begin_lost_key", &a, &r)?;
    w.guardian(
        "submit_guardian (1 of 2)",
        &guardians[0],
        &a,
        vetoed,
        EvidenceDomain::Initiate,
    )?;
    w.guardian(
        "submit_guardian (2 of 2, promoting)",
        &guardians[1],
        &a,
        vetoed,
        EvidenceDomain::Initiate,
    )?;
    c.refused(
        "a third guardian on an authorized attempt",
        &w.s.controller,
        "submit_guardian",
        vec![
            c.sc(c.address(&a.address)),
            c.sc(vetoed),
            c.sc(EvidenceDomain::Initiate),
            c.sc(c.address(&guardians[2].account())),
        ],
        &[crate::chain::Auth::Account(&guardians[2])],
        code(RecoveryError::AttemptNotCollecting),
    )?;
    let owner = w.owner_auth(&a, &a.owner, "admin")?;
    c.call(
        "Loss owner cancel_recovery (the veto)",
        &a.address,
        "cancel_recovery",
        vec![c.sc(vetoed)],
        &[owner],
    )?;

    let attempt = w.begin_lost_key("begin_lost_key (again)", &a, &r)?;
    w.guardian(
        "submit_guardian (1 of 2)",
        &guardians[1],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.guardian(
        "submit_guardian (2 of 2, promoting)",
        &guardians[2],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    let target = w.target_bytes(&a, &r)?;
    c.wait_for_ledger(w.attempt(&a, attempt)?.executable_after)?;
    w.complete("completion apply_doc (GuardianOnly)", &a, &target)?;
    w.activity_refused("the lost passkey after recovery", &a, &a.owner)?;
    w.activity("the new passkey after recovery", &a, &new_owner)?;
    Ok(())
}
