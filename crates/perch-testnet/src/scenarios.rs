//! The testnet scenarios: the flows of
//! `crates/integration-tests/tests/release_stack.rs`, on the deployed
//! contracts, with real G-account guardians, and a perch-account guardian's
//! approval carried by the relay. A step that must fail is simulated under
//! enforcing authorization and never submitted.

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
        baseline: None,
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
        baseline: None,
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
    w.was_frozen()?;
    w.execute_refused("frozen: execute", &a, &a.owner)?;
    w.was_frozen()?;
    w.apply_refused_at_auth("frozen: apply_doc", &a, &a.owner, &w.doc(&a.owner, None))?;
    w.was_frozen()?;

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
        baseline: None,
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
        Some(PerchAccountError::UpgradeNotReady.into_code()),
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
        baseline: None,
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

/// `Combined` under `Loss`: both factors authorize, activity continues, and
/// the completion spends the nullifier and rotates the ZK credential.
pub fn combined_loss(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("combined / loss: both factors, ZK rotation");
    let guardians = [
        w.g_account("combined-loss/g0")?,
        w.g_account("combined-loss/g1")?,
        w.g_account("combined-loss/g2")?,
    ];
    let a = w.new_account("combined-loss", w.passkey("combined-loss/owner"))?;
    let zk1 = w.zk("combined-loss/zk1");
    let rec = Rec {
        profile: "loss",
        mode: Mode::Combined,
        zk: Some(zk1.clone()),
        guardians: guardians.iter().map(|g| g.account()).collect(),
        delay: DELAY,
        baseline: None,
    };
    w.apply(
        "enroll Combined Loss",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;
    let new_owner = w.passkey("combined-loss/new-owner");
    let zk2 = w.zk("combined-loss/zk2");
    let r = w.replacements(&new_owner, Some(&zk2));
    let attempt = w.begin_lost_key("begin_lost_key", &a, &r)?;
    w.guardian(
        "submit_guardian (1 of 2)",
        &guardians[0],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    let ev = w.prove(
        &a,
        &zk1,
        &w.statement(&a, attempt, EvidenceDomain::Initiate)?,
    )?;
    c.call(
        "submit_zk (Combined, not yet promoting)",
        &w.s.controller,
        "submit_zk",
        w.zk_args(&a, attempt, EvidenceDomain::Initiate, &ev),
        &[],
    )?;
    w.guardian(
        "submit_guardian (2 of 2, promoting: ZK already in)",
        &guardians[1],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.activity("Loss: activity during the authorized window", &a, &a.owner)?;
    let target = w.target_bytes(&a, &r)?;
    c.wait_for_ledger(w.attempt(&a, attempt)?.executable_after)?;
    w.complete("completion apply_doc (Combined, ZK rotation)", &a, &target)?;
    let spent: bool = c.read_as(
        &w.s.controller,
        "nullifier_spent",
        vec![c.sc(c.address(&a.address)), c.sc(ev.nullifier.clone())],
    )?;
    ensure!(spent, "nullifier not spent");
    w.activity_refused("the lost passkey after recovery", &a, &a.owner)?;
    w.activity("the new passkey after recovery", &a, &new_owner)?;
    Ok(())
}

/// `GuardianOnly` under `Protected`, compromise recovery: a thief with the
/// owner key adds a signer; the guardians restore the published baseline
/// with a new owner key; the stolen key and the thief's signer are revoked.
pub fn guardian_protected_compromise(w: &World<'_>) -> Result<()> {
    let c = w.c;
    c.begin_scenario("guardian-only / protected: compromise recovery from the baseline");
    let guardians = [
        w.g_account("compromise/g0")?,
        w.g_account("compromise/g1")?,
        w.g_account("compromise/g2")?,
    ];
    let a = w.new_account("guardian-protected", w.passkey("compromise/owner"))?;
    let baseline = w.doc(&a.owner, None);
    let rec = Rec {
        profile: "protected",
        mode: Mode::Guardian,
        zk: None,
        guardians: guardians.iter().map(|g| g.account()).collect(),
        delay: DELAY,
        baseline: Some(w.doc_hash(&baseline)?.to_array()),
    };
    w.apply(
        "enroll GuardianOnly Protected with a baseline",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;
    let thief = w.passkey("compromise/thief");
    let stolen = w.doc_with(&a.owner, Some(&thief), Some(&rec));
    w.apply(
        "the thief adds a signer with the stolen owner key",
        &a,
        &a.owner,
        &stolen,
        0,
    )?;
    w.activity_via("the thief's signer moves XLM", &a, &thief, "thief")?;

    let new_owner = w.passkey("compromise/new-owner");
    let r = w.replacements(&new_owner, None);
    let account = c.sc(c.address(&a.address));
    c.refused(
        "begin_compromise before the baseline is published",
        &w.s.controller,
        "begin_compromise",
        vec![account.clone(), c.sc(r.clone())],
        &[],
        code(RecoveryError::BaselineNotPublished),
    )?;
    c.refused(
        "publish_baseline of another document",
        &w.s.controller,
        "publish_baseline",
        vec![account.clone(), c.sc(stolen.clone())],
        &[],
        code(RecoveryError::BaselineMismatch),
    )?;
    c.call(
        "publish_baseline",
        &w.s.controller,
        "publish_baseline",
        vec![account.clone(), c.sc(baseline)],
        &[],
    )?;
    let out = c.call(
        "begin_compromise",
        &w.s.controller,
        "begin_compromise",
        vec![account, c.sc(r.clone())],
        &[],
    )?;
    let attempt: u64 = c.decode(&out.value)?;
    w.guardian(
        "submit_guardian (1 of 2)",
        &guardians[0],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.guardian(
        "submit_guardian (2 of 2, promoting; sets the freeze)",
        &guardians[1],
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;
    w.activity_refused_via("frozen: the thief's signer", &a, &thief, "thief")?;
    w.was_frozen()?;
    w.activity_refused("frozen: the owner key", &a, &a.owner)?;
    w.was_frozen()?;
    let target = w.compromise_target(&a, &r)?;
    c.wait_for_ledger(w.attempt(&a, attempt)?.executable_after)?;
    w.complete(
        "completion apply_doc (compromise: revokes the stolen and added keys)",
        &a,
        &target,
    )?;
    w.activity("the new owner after recovery", &a, &new_owner)?;
    w.activity_refused("the stolen owner key after recovery", &a, &a.owner)?;
    ensure!(
        w.rule_id(&a, "thief").is_err(),
        "the baseline has no thief rule"
    );
    w.apply_refused(
        "re-adding the thief's key, signed by the new owner",
        &a,
        &new_owner,
        &w.doc_with(&new_owner, Some(&thief), Some(&rec)),
        0,
        Some(PerchAccountError::RevokedCredential),
    )?;
    Ok(())
}

/// A guardian that is itself a perch account, approving through a CAP-0071
/// delegated signer, its approval carried by the relay
/// (`packages/perch-relay`) and submitted by someone else. The relay admits
/// an entry only after simulating the whole `submit_guardian` under
/// enforcing authorization, so forgeries posted first never take the
/// guardian's slot.
pub fn relayed_delegated_guardian(w: &World<'_>) -> Result<()> {
    use stellar_xdr::{ScVal, SorobanAuthorizedFunction, SorobanCredentials};
    let c = w.c;
    c.begin_scenario("relay: a delegated perch guardian's approval, relayed");
    let relay = crate::relay::Relay::start(&w.s.controller, &c.passphrase, &c.rpc_url)?;

    // The guardian: a factory account whose `approve` rule lets a delegated
    // G-account sign calls to the controller.
    let approver = w.g_account("relay/approver")?;
    let attacker = w.g_account("relay/attacker")?;
    let guardian = w.new_account("relay-guardian", w.passkey("relay/guardian-owner"))?;
    w.apply(
        "guardian account: a delegated approver for the controller",
        &guardian,
        &guardian.owner,
        &w.guardian_doc(&guardian.owner, &approver.account()),
        0,
    )?;
    let approve_rule = w.rule_id(&guardian, "approve")?;
    let admin_rule = w.rule_id(&guardian, "admin")?;

    let g0 = w.g_account("relay/g0")?;
    let a = w.new_account("relay-loss", w.passkey("relay/owner"))?;
    let rec = Rec {
        profile: "loss",
        mode: Mode::Guardian,
        zk: None,
        guardians: vec![g0.account(), guardian.address.clone()],
        delay: DELAY,
        baseline: None,
    };
    w.apply(
        "enroll GuardianOnly (a perch account among the guardians)",
        &a,
        &a.owner,
        &w.doc(&a.owner, Some(&rec)),
        0,
    )?;
    let new_owner = w.passkey("relay/new-owner");
    let r = w.replacements(&new_owner, None);
    let attempt = w.begin_lost_key("begin_lost_key", &a, &r)?;
    w.guardian(
        "submit_guardian (1 of 2)",
        &g0,
        &a,
        attempt,
        EvidenceDomain::Initiate,
    )?;

    // The guardian's wallet: the entry recording-mode simulation asks for,
    // signed by the delegate.
    let args = vec![
        c.sc(c.address(&a.address)),
        c.sc(attempt),
        c.sc(EvidenceDomain::Initiate),
        c.sc(c.address(&guardian.address)),
    ];
    let templates = c.templates(&w.s.controller, "submit_guardian", args.clone())?;
    ensure!(
        templates.len() == 1,
        "submit_guardian asks for {} entries",
        templates.len()
    );
    let template = &templates[0];
    let SorobanAuthorizedFunction::ContractFn(call) = &template.root_invocation.function else {
        anyhow::bail!("the template does not authorize a contract call");
    };
    let digest = match call.args.first() {
        Some(ScVal::Bytes(b)) => hex::encode(b.as_slice()),
        other => anyhow::bail!("the template's argument is not the digest: {other:?}"),
    };
    let statement = w.statement(&a, attempt, EvidenceDomain::Initiate)?;
    let expected = statement
        .digest(&c.env)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ensure!(
        digest == hex::encode(expected.to_array()),
        "the guardian is asked to sign {digest}, not the statement's digest"
    );
    let genuine = c.delegated_entry(template, &approver, approve_rule)?;

    // An attacker posts first, more forgeries than the old per-guardian cap
    // of eight: another delegate, the approver under a rule it is not in,
    // and the genuine entry with its delegate signature tampered with.
    let tampered = {
        let mut e = genuine.clone();
        let SorobanCredentials::AddressWithDelegates(d) = &mut e.credentials else {
            anyhow::bail!("the delegated entry is not AddressWithDelegates");
        };
        let mut delegates = d.delegates.to_vec();
        delegates[0].signature = flip_last_byte(&delegates[0].signature)?;
        d.delegates = delegates.try_into()?;
        e
    };
    let forgeries = [
        (
            "another delegate",
            c.delegated_entry(template, &attacker, approve_rule)?,
        ),
        (
            "the approver under a rule it is not in",
            c.delegated_entry(template, &approver, admin_rule)?,
        ),
        ("a tampered delegate signature", tampered),
    ];
    for round in 0..3 {
        for (what, forged) in &forgeries {
            let (status, body) = relay.put(&digest, forged, &args)?;
            ensure!(
                status == 403,
                "relay admitted a forged approval ({what}): {status} {body}"
            );
            if round == 0 {
                let error: serde_json::Value = serde_json::from_str(&body)?;
                c.note_refusal(
                    &format!("relay: forged approval, {what}"),
                    &format!("{status} {}", error["error"].as_str().unwrap_or(&body)),
                    "relay",
                );
            }
        }
    }
    let (status, body) = relay.put(&digest, &genuine, &args)?;
    ensure!(
        status == 201,
        "relay refused the genuine approval: {status} {body}"
    );

    // A collector fetches it and submits it as served.
    let relayed = relay.get(&digest)?;
    ensure!(
        relayed.len() == 1,
        "relay serves {} approvals, expected the genuine one",
        relayed.len()
    );
    let got = &relayed[0];
    ensure!(
        got.guardian == guardian.address && got.entry == genuine && got.admitted_by == "simulation",
        "relay served something other than the genuine approval, unchanged"
    );
    c.call_with(
        "submit_guardian (2 of 2, promoting; a delegated perch guardian, relayed)",
        &w.s.controller,
        "submit_guardian",
        got.args.clone(),
        &[],
        crate::chain::Entries::Given(vec![got.entry.clone()]),
    )?;
    let at = w.attempt(&a, attempt)?;
    ensure!(
        at.guardians.contains(c.address(&guardian.address)),
        "the controller did not record the perch guardian's approval"
    );
    let target = w.target_bytes(&a, &r)?;
    c.wait_for_ledger(at.executable_after)?;
    w.complete("completion apply_doc (GuardianOnly)", &a, &target)?;
    w.activity("the new passkey after recovery", &a, &new_owner)?;
    Ok(())
}

/// `sig` with its final byte changed, wherever the bytes are nested.
fn flip_last_byte(sig: &stellar_xdr::ScVal) -> Result<stellar_xdr::ScVal> {
    use stellar_xdr::{Limits, ReadXdr, WriteXdr};
    let mut bytes = sig.to_xdr(Limits::none())?;
    // The XDR of the account signature ends with the 64 signature bytes.
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    Ok(stellar_xdr::ScVal::from_xdr(bytes, Limits::none())?)
}
