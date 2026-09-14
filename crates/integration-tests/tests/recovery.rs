//! End-to-end account recovery, guardian-only mode: enrollment, initiation,
//! guardian quorum, the timelock, completion (Variant A — recovery
//! authorizes `apply_doc` itself, via the real OZ `do_check_auth` /
//! `Policy::enforce` path), replay/expiry/wrong-target refusal, and the
//! unconditional pending-attempt guard on ordinary `apply_doc` calls. See
//! `docs/recovery/controller-governance.md`.
//!
//! Setup (enrollment, evidence submission) goes through
//! `perch_testkit::Bootstrap`'s mocked-auth world — real auth *mechanics*
//! aren't what's under test there (`matrix.rs` already proves those). The
//! completion assertions instead call `do_check_auth` directly, matching
//! `matrix.rs`'s own pattern: under host-level auth mocking (recording mode),
//! the host never invokes a custom account's `__check_auth` at all (confirmed
//! against `soroban-env-host`'s own source — recording mode explicitly skips
//! it), so exercising `Policy::enforce` for real requires driving
//! `do_check_auth` directly with an explicit rule selection, exactly as
//! `__check_auth` itself does.

use perch_recovery::{PerchRecovery, PerchRecoveryClient};
use perch_testkit::{no_recovery_evidence, Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{
    contract, contractimpl, crypto::Hash, vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol,
    Vec,
};
use stellar_accounts::smart_account::{do_check_auth, AuthPayload};

const ADMIN_VERIFIER: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
const ADMIN_KEY: &str = "045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e";
const NEW_ADMIN_VERIFIER: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
const NEW_ADMIN_KEY: &str = "1ce6040b0d03232ac6c911b0c375f1a52ebdefff56fd361d13680e23ca578a17";

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

fn strkey(a: &Address) -> std::string::String {
    // `Address::to_string` returns a `soroban_sdk::String`; `Display` on
    // that yields the strkey, which `.to_string()` again collects into a
    // plain Rust `String` for building JSON.
    a.to_string().to_string()
}

fn enroll_doc(controller: &Address, guardians: &[Address], quorum: u32) -> std::string::String {
    let guardian_list = guardians
        .iter()
        .map(|g| format!("\"{}\"", strkey(g)))
        .collect::<std::vec::Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}" }}
  ],
  "rules": [
    {{ "name": "admin", "scope": {{ "type": "self-admin" }},
       "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ],
  "recovery": {{
    "profile": "loss",
    "mode": {{ "type": "guardian-only", "guardians": [{guardian_list}], "quorum": {quorum} }},
    "controller": "{controller}",
    "replaceable": ["admin"],
    "delay-ledgers": 5,
    "expiry-ledgers": 1000,
    "max-cancels": 3,
    "pending-activity": "continue"
  }}
}}"#,
        controller = strkey(controller),
    )
}

/// The lost-key target: the enrolled document with the admin credential
/// replaced. Same recovery section — a legitimate completion never changes
/// enrolled configuration (see `guard_apply_doc`'s design).
fn target_doc(controller: &Address, guardians: &[Address], quorum: u32) -> std::string::String {
    enroll_doc(controller, guardians, quorum).replace(
        &format!(r#""verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}""#),
        &format!(r#""verifier": "{NEW_ADMIN_VERIFIER}", "key": "{NEW_ADMIN_KEY}""#),
    )
}

/// A minimal `ZkVerifierInterface`-shaped mock: no real circuit, per
/// `docs/recovery/controller-governance.md`'s "ZK adapter scope". Validity is
/// controlled purely by whether the caller passed a non-empty `proof`, so
/// tests can exercise the controller's own evidence-tracking/gating logic
/// (which factors it requires, and when) without a real verifier.
#[contract]
struct MockZkVerifier;

#[contractimpl]
impl MockZkVerifier {
    pub fn verify_proof(
        _e: &Env,
        _statement: BytesN<32>,
        _nullifier: BytesN<32>,
        proof: Bytes,
        _pool: Vec<Address>,
    ) -> bool {
        !proof.is_empty()
    }
}

/// Same document shape as `enroll_doc`/`target_doc`, but with an arbitrary
/// recovery `mode` block — for zk-only/combined-mode tests that don't need
/// guardian-only's specific JSON.
fn enroll_doc_with_mode(controller: &Address, mode_json: &str) -> std::string::String {
    format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}" }}
  ],
  "rules": [
    {{ "name": "admin", "scope": {{ "type": "self-admin" }},
       "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ],
  "recovery": {{
    "profile": "loss",
    "mode": {mode_json},
    "controller": "{controller}",
    "replaceable": ["admin"],
    "delay-ledgers": 5,
    "expiry-ledgers": 1000,
    "max-cancels": 3,
    "pending-activity": "continue"
  }}
}}"#,
        controller = strkey(controller),
    )
}

fn zk_only_mode_json(verifier: &Address) -> std::string::String {
    format!(
        r#"{{ "type": "zk-only", "verifier": "{}", "circuit-id": "ab" }}"#,
        strkey(verifier)
    )
}

fn combined_mode_json(
    verifier: &Address,
    guardians: &[Address],
    quorum: u32,
) -> std::string::String {
    let guardian_list = guardians
        .iter()
        .map(|g| format!("\"{}\"", strkey(g)))
        .collect::<std::vec::Vec<_>>()
        .join(",");
    format!(
        r#"{{ "type": "combined", "guardians": [{guardian_list}], "quorum": {quorum}, "verifier": "{}", "circuit-id": "ab" }}"#,
        strkey(verifier)
    )
}

fn recovery_rule_id(w: &World) -> u32 {
    let client = w.account_client();
    let n = client.get_context_rules_count();
    // ids are assigned sequentially and never reused; scan from the top.
    let mut found = None;
    for id in (1..=n + 10).rev() {
        if let Ok(Ok(rule)) = client.try_get_context_rule(&id) {
            if rule.name == soroban_sdk::String::from_str(&w.env, "recovery") {
                found = Some(id);
                break;
            }
        }
    }
    found.expect("recovery rule installed")
}

/// Drive `do_check_auth` directly (matching `matrix.rs`), selecting `rule_id`
/// with zero signers — the shape a policy-only, zero-signer rule requires —
/// authorizing `account.apply_doc(doc_bytes)`.
fn complete_via_rule(
    w: &World,
    account: &Address,
    rule_id: u32,
    doc_bytes: &Bytes,
) -> Result<(), ()> {
    let ctx = Context::Contract(ContractContext {
        contract: account.clone(),
        fn_name: Symbol::new(&w.env, "apply_doc"),
        args: vec![
            &w.env,
            doc_bytes.into_val(&w.env),
            no_recovery_evidence(&w.env).into_val(&w.env),
        ],
    });
    let payload = AuthPayload {
        signers: Map::new(&w.env),
        context_rule_ids: vec![&w.env, rule_id],
    };
    let hash: Hash<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_array(&w.env, &[0x11; 32]));
    let contexts = vec![&w.env, ctx];
    let account = account.clone();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        w.env.as_contract(&account, || {
            do_check_auth(&w.env, &hash, &payload, &contexts).unwrap();
        });
    }))
    .map_err(|_| ())
}

/// Enroll guardian-only 2-of-2 and begin a lost-key attempt against `target`,
/// returning `(world, controller_client, rule_id, target_bytes)`. Shared by
/// the completion-refusal tests below, each of which then does exactly one
/// `complete_via_rule` call — kept to one such call per test (rather than a
/// chain of expected-panic-then-continue calls in one `Env`) since Soroban's
/// test host's call-stack bookkeeping does not reliably survive multiple
/// `catch_unwind`-recovered host panics within a single `Env`.
fn setup_pending_attempt(quorum_approvals: &[bool]) -> (World, Address, u32, Bytes) {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);

    let doc = enroll_doc(&controller, &[g1.clone(), g2.clone()], 2);
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let rule_id = recovery_rule_id(&w);

    let target = target_doc(&controller, &[g1.clone(), g2.clone()], 2);
    let target_bytes = Bytes::from_slice(&w.env, target.as_bytes());
    let target_hash: BytesN<32> = w.env.crypto().sha256(&target_bytes).to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    if quorum_approvals.first().copied().unwrap_or(false) {
        recovery.submit_guardian_approval(&w.account, &g1);
    }
    if quorum_approvals.get(1).copied().unwrap_or(false) {
        recovery.submit_guardian_approval(&w.account, &g2);
    }
    (w, controller, rule_id, target_bytes)
}

#[test]
fn completion_refused_with_no_evidence_at_all() {
    let (w, controller, rule_id, target_bytes) = setup_pending_attempt(&[false, false]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_err());
    assert!(recovery.has_pending(&w.account));
}

#[test]
fn completion_refused_below_guardian_quorum() {
    let (w, controller, rule_id, target_bytes) = setup_pending_attempt(&[true, false]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    assert_eq!(
        recovery.get_attempt(&w.account).unwrap().executable_after,
        0
    );
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_err());
    assert!(recovery.has_pending(&w.account));
}

#[test]
fn completion_refused_before_the_timelock_elapses() {
    let (w, controller, rule_id, target_bytes) = setup_pending_attempt(&[true, true]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    assert!(attempt.executable_after > w.env.ledger().sequence());
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_err());
}

#[test]
fn completion_refused_for_the_wrong_target_document() {
    let (w, controller, rule_id, _) = setup_pending_attempt(&[true, true]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);
    let wrong = Bytes::from_slice(
        &w.env,
        enroll_doc(&Address::generate(&w.env), &[], 1).as_bytes(),
    );
    assert!(complete_via_rule(&w, &w.account, rule_id, &wrong).is_err());
    assert!(recovery.has_pending(&w.account)); // not consumed by the refusal
}

#[test]
fn guardian_only_lost_key_recovery_completes_and_installs_the_target_document() {
    let (w, controller, rule_id, target_bytes) = setup_pending_attempt(&[true, true]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);

    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_ok());
    assert!(!recovery.has_pending(&w.account));
    assert_eq!(
        recovery.get_attempt(&w.account).unwrap().state,
        perch_recovery::types::AttemptState::Completed
    );
}

#[test]
fn completion_cannot_be_replayed() {
    let (w, controller, rule_id, target_bytes) = setup_pending_attempt(&[true, true]);
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_ok());
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_err());
}

#[test]
fn guardian_quorum_alone_never_promotes_without_being_reached() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);
    let g3 = Address::generate(&w.env);

    let doc = enroll_doc(&controller, &[g1.clone(), g2.clone(), g3.clone()], 3);
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let target = target_doc(&controller, &[g1.clone(), g2.clone(), g3.clone()], 3);
    let target_hash: BytesN<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, target.as_bytes()))
        .to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    recovery.submit_guardian_approval(&w.account, &g1);
    recovery.submit_guardian_approval(&w.account, &g2);
    // 2 of 3: not yet quorum.
    assert_eq!(
        recovery.get_attempt(&w.account).unwrap().executable_after,
        0
    );

    recovery.submit_guardian_approval(&w.account, &g3);
    assert!(recovery.get_attempt(&w.account).unwrap().executable_after > 0);
}

#[test]
fn guardian_cancel_is_a_separate_domain_from_initiation_approval() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);

    let doc = enroll_doc(&controller, &[g1.clone(), g2.clone()], 2);
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let target = target_doc(&controller, &[g1.clone(), g2.clone()], 2);
    let target_hash: BytesN<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, target.as_bytes()))
        .to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    // g1's INITIATION approval does not count toward cancellation.
    recovery.submit_guardian_approval(&w.account, &g1);
    recovery.submit_guardian_cancel(&w.account, &g1);
    assert!(recovery.has_pending(&w.account)); // only 1 of 2 cancel votes

    recovery.submit_guardian_cancel(&w.account, &g2);
    assert!(!recovery.has_pending(&w.account)); // cancelled

    // A fresh attempt can be started after cancellation.
    let id2 = recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);
    assert_eq!(id2, 1);
}

#[test]
fn protected_reconfigure_requires_guardian_evidence_admin_alone_is_refused() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);

    let protected_doc = enroll_doc(&controller, &[g1.clone(), g2.clone()], 2)
        .replace("\"profile\": \"loss\"", "\"profile\": \"protected\"");
    let client = w.account_client();
    client.apply_doc(
        &Bytes::from_slice(&w.env, protected_doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );

    // Disable recovery entirely (omit the `recovery` field) with ordinary
    // admin authorization only — must be refused: an admin key alone cannot
    // downgrade or disable `Protected` recovery.
    let plain_doc = format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}" }}
  ],
  "rules": [
    {{ "name": "admin", "scope": {{ "type": "self-admin" }},
       "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ]
}}"#
    );
    assert!(client
        .try_apply_doc(
            &Bytes::from_slice(&w.env, plain_doc.as_bytes()),
            &no_recovery_evidence(&w.env)
        )
        .is_err());
    // Nothing changed: still enrolled.
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    assert!(recovery.get_config(&w.account).is_some());
}

#[test]
fn zk_only_cancellation_requires_a_valid_proof() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let verifier = w.env.register(MockZkVerifier, ());

    let doc = enroll_doc_with_mode(&controller, &zk_only_mode_json(&verifier));
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let target_hash: BytesN<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, b"target"))
        .to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    let invalid_proof = Bytes::new(&w.env);
    let nullifier1 = BytesN::from_array(&w.env, &[1u8; 32]);
    assert!(recovery
        .try_submit_zk_cancel(&w.account, &nullifier1, &invalid_proof)
        .is_err());
    assert!(recovery.has_pending(&w.account));

    let valid_proof = Bytes::from_array(&w.env, &[1u8; 1]);
    let nullifier2 = BytesN::from_array(&w.env, &[2u8; 32]);
    recovery.submit_zk_cancel(&w.account, &nullifier2, &valid_proof);
    assert!(!recovery.has_pending(&w.account));
}

#[test]
fn combined_cancellation_guardian_quorum_alone_does_not_cancel() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let verifier = w.env.register(MockZkVerifier, ());
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);

    let doc = enroll_doc_with_mode(
        &controller,
        &combined_mode_json(&verifier, &[g1.clone(), g2.clone()], 2),
    );
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let target_hash: BytesN<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, b"target"))
        .to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    // Guardian quorum alone does not cancel a `Combined`-mode attempt.
    recovery.submit_guardian_cancel(&w.account, &g1);
    recovery.submit_guardian_cancel(&w.account, &g2);
    assert!(recovery.has_pending(&w.account));

    // The ZK factor completes the requirement.
    let valid_proof = Bytes::from_array(&w.env, &[1u8; 1]);
    let nullifier = BytesN::from_array(&w.env, &[3u8; 32]);
    recovery.submit_zk_cancel(&w.account, &nullifier, &valid_proof);
    assert!(!recovery.has_pending(&w.account));
}

#[test]
fn combined_cancellation_zk_proof_alone_does_not_cancel() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let verifier = w.env.register(MockZkVerifier, ());
    let g1 = Address::generate(&w.env);
    let g2 = Address::generate(&w.env);

    let doc = enroll_doc_with_mode(
        &controller,
        &combined_mode_json(&verifier, &[g1.clone(), g2.clone()], 2),
    );
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let target_hash: BytesN<32> = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, b"target"))
        .to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    // A ZK cancellation proof alone does not cancel a `Combined`-mode attempt.
    let valid_proof = Bytes::from_array(&w.env, &[1u8; 1]);
    let nullifier = BytesN::from_array(&w.env, &[4u8; 32]);
    recovery.submit_zk_cancel(&w.account, &nullifier, &valid_proof);
    assert!(recovery.has_pending(&w.account));

    // The guardian factor completes the requirement.
    recovery.submit_guardian_cancel(&w.account, &g1);
    recovery.submit_guardian_cancel(&w.account, &g2);
    assert!(!recovery.has_pending(&w.account));
}

#[test]
fn a_completed_attempts_nullifier_is_never_released() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let verifier = w.env.register(MockZkVerifier, ());

    let doc = enroll_doc_with_mode(&controller, &zk_only_mode_json(&verifier));
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let rule_id = recovery_rule_id(&w);
    let target = enroll_doc_with_mode(&controller, &zk_only_mode_json(&verifier)).replace(
        &format!(r#""verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}""#),
        &format!(r#""verifier": "{NEW_ADMIN_VERIFIER}", "key": "{NEW_ADMIN_KEY}""#),
    );
    let target_bytes = Bytes::from_slice(&w.env, target.as_bytes());
    let target_hash: BytesN<32> = w.env.crypto().sha256(&target_bytes).to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    let proof = Bytes::from_array(&w.env, &[1u8; 1]);
    let nullifier = BytesN::from_array(&w.env, &[5u8; 32]);
    recovery.submit_zk_proof(&w.account, &nullifier, &proof);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_ok());

    // A fresh attempt after completion must not resurrect the spent nullifier.
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);
    assert!(recovery
        .try_submit_zk_proof(&w.account, &nullifier, &proof)
        .is_err());
}

#[test]
fn guardian_cancellation_is_refused_once_the_attempt_has_completed() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let g1 = Address::generate(&w.env);

    let doc = enroll_doc(&controller, std::slice::from_ref(&g1), 1);
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let rule_id = recovery_rule_id(&w);
    let target = target_doc(&controller, std::slice::from_ref(&g1), 1);
    let target_bytes = Bytes::from_slice(&w.env, target.as_bytes());
    let target_hash: BytesN<32> = w.env.crypto().sha256(&target_bytes).to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);
    recovery.submit_guardian_approval(&w.account, &g1);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_ok());

    // A cancellation factor arriving after completion must not flip the
    // attempt back to `Cancelled`.
    assert!(recovery
        .try_submit_guardian_cancel(&w.account, &g1)
        .is_err());
    assert_eq!(
        recovery.get_attempt(&w.account).unwrap().state,
        perch_recovery::types::AttemptState::Completed
    );
}

#[test]
fn zk_cancellation_is_refused_once_the_attempt_has_completed() {
    let w = setup();
    let controller = w.env.register(PerchRecovery, ());
    let recovery = PerchRecoveryClient::new(&w.env, &controller);
    let verifier = w.env.register(MockZkVerifier, ());

    let doc = enroll_doc_with_mode(&controller, &zk_only_mode_json(&verifier));
    w.account_client().apply_doc(
        &Bytes::from_slice(&w.env, doc.as_bytes()),
        &no_recovery_evidence(&w.env),
    );
    let rule_id = recovery_rule_id(&w);
    let target = enroll_doc_with_mode(&controller, &zk_only_mode_json(&verifier)).replace(
        &format!(r#""verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}""#),
        &format!(r#""verifier": "{NEW_ADMIN_VERIFIER}", "key": "{NEW_ADMIN_KEY}""#),
    );
    let target_bytes = Bytes::from_slice(&w.env, target.as_bytes());
    let target_hash: BytesN<32> = w.env.crypto().sha256(&target_bytes).to_bytes();
    let replaceable = recovery.get_config(&w.account).unwrap().replaceable;
    recovery.begin_lost_key_attempt(&w.account, &target_hash, &replaceable);

    let proof = Bytes::from_array(&w.env, &[1u8; 1]);
    let init_nullifier = BytesN::from_array(&w.env, &[6u8; 32]);
    recovery.submit_zk_proof(&w.account, &init_nullifier, &proof);
    let attempt = recovery.get_attempt(&w.account).unwrap();
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = attempt.executable_after);
    assert!(complete_via_rule(&w, &w.account, rule_id, &target_bytes).is_ok());

    let cancel_nullifier = BytesN::from_array(&w.env, &[7u8; 32]);
    assert!(recovery
        .try_submit_zk_cancel(&w.account, &cancel_nullifier, &proof)
        .is_err());
    assert_eq!(
        recovery.get_attempt(&w.account).unwrap().state,
        perch_recovery::types::AttemptState::Completed
    );
}
