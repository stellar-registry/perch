//! Drives the EXPORTED `__check_auth` of the real `PerchAccount` through the
//! host's check-auth frame (`try_invoke_contract_check_auth`) — the exact path
//! a production `SorobanAuthorizationEntry` takes, including the real
//! cross-contract calls into the verifier: the constructor-installed admin
//! rule (id 0), decided by rule-eval over the rule the constructor stores,
//! the contract-level export, and the least-privilege boundary of the
//! fixture's ci-publish rule, stored as `apply_doc` stores it
//! (`perch_testkit::ci_publish_rule`) and decided by rule-eval.

use ed25519_dalek::{Signer as _, SigningKey};
use perch_account::PerchAccount;
use perch_account_types::{AuthPayload, Signer, SmartAccountError};
use perch_ed25519_verifier::PerchEd25519Verifier;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol};

use perch_testkit::{auth_digest, ci_publish_rule, FIXTURE_REGISTRY};

struct World {
    env: Env,
    account: Address,
    verifier: Address,
    registry: Address,
    admin_key: SigningKey,
    admin_pub: BytesN<32>,
    ci_key: SigningKey,
    ci_pub: BytesN<32>,
    ci_rule_id: u32,
}

/// Deploy the real verifier + PerchAccount (constructor installs admin as
/// rule 0). With `ci`, also install the fixture's ci-publish rule with the
/// ci key, as `apply_doc` stores it.
fn setup(ci: bool) -> World {
    let env = Env::default();
    env.mock_all_auths();

    let verifier = env.register(PerchEd25519Verifier, ());

    let admin_key = SigningKey::from_bytes(&[9u8; 32]);
    let admin_pub = BytesN::from_array(&env, &admin_key.verifying_key().to_bytes());
    let ci_key = SigningKey::from_bytes(&[7u8; 32]);
    let ci_pub = BytesN::from_array(&env, &ci_key.verifying_key().to_bytes());

    let admin_signers = vec![
        &env,
        Signer::External(verifier.clone(), admin_pub.clone().into()),
    ];
    let account = env.register(PerchAccount, (admin_signers,));

    let registry = Address::from_str(&env, FIXTURE_REGISTRY);
    let ci_signer = Signer::External(verifier.clone(), ci_pub.clone().into());
    let ci_rule_id = if ci {
        let rule = ci_publish_rule(&env, &account, &registry, vec![&env, ci_signer], None);
        env.as_contract(&account, || {
            perch_smart_account::testutils::install_rule(&env, "ci-publish", &rule)
        })
    } else {
        u32::MAX
    };

    World {
        env,
        account,
        verifier,
        registry,
        admin_key,
        admin_pub,
        ci_key,
        ci_pub,
        ci_rule_id,
    }
}

fn payload_hash(env: &Env) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_array(env, &[0x11; 32]))
        .to_bytes()
}

fn signed_payload(w: &World, key: &SigningKey, pubkey: &BytesN<32>, rule_id: u32) -> AuthPayload {
    let ids = vec![&w.env, rule_id];
    let digest = auth_digest(&w.env, &w.account, &payload_hash(&w.env), &ids);
    let sig = key.sign(&digest).to_bytes();
    let signer = Signer::External(w.verifier.clone(), pubkey.clone().into());
    let signers: Map<Signer, Bytes> = map![&w.env, (signer, Bytes::from_array(&w.env, &sig))];
    AuthPayload {
        signers,
        context_rule_ids: ids,
    }
}

/// A `registry.<fn_name>(arg0, author)` context (author at arg index 1).
fn registry_context(w: &World, fn_name: &str, author: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: w.registry.clone(),
        fn_name: Symbol::new(&w.env, fn_name),
        args: vec![&w.env, 0u32.into_val(&w.env), author.into_val(&w.env)],
    })
}

/// A self-admin context: a mutator on the account itself.
fn self_admin_context(w: &World, fn_name: &str) -> Context {
    Context::Contract(ContractContext {
        contract: w.account.clone(),
        fn_name: Symbol::new(&w.env, fn_name),
        args: vec![&w.env, 0u32.into_val(&w.env)],
    })
}

/// Drive the exported __check_auth through the host's check-auth frame.
fn check(w: &World, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
    let contexts = vec![&w.env, ctx];
    w.env
        .try_invoke_contract_check_auth::<SmartAccountError>(
            &w.account,
            &payload_hash(&w.env),
            payload.clone().into_val(&w.env),
            &contexts,
        )
        .map_err(|_| ())
}

#[test]
fn admin_authorizes_self_admin() {
    let w = setup(false);
    let payload = signed_payload(&w, &w.admin_key, &w.admin_pub, 0);
    assert!(check(&w, &payload, self_admin_context(&w, "add_signer")).is_ok());
}

#[test]
fn admin_denied_on_registry_scope() {
    // Rule 0 is CallContract(self), not Default: the admin key must NOT
    // authorize registry calls.
    let w = setup(false);
    let payload = signed_payload(&w, &w.admin_key, &w.admin_pub, 0);
    assert!(check(
        &w,
        &payload,
        registry_context(&w, "publish_hash", &w.account)
    )
    .is_err());
}

#[test]
fn ci_publishes_as_self() {
    let w = setup(true);
    let payload = signed_payload(&w, &w.ci_key, &w.ci_pub, w.ci_rule_id);
    assert!(check(
        &w,
        &payload,
        registry_context(&w, "publish_hash", &w.account)
    )
    .is_ok());
}

#[test]
fn ci_denied_other_function() {
    let w = setup(true);
    let payload = signed_payload(&w, &w.ci_key, &w.ci_pub, w.ci_rule_id);
    assert!(check(
        &w,
        &payload,
        registry_context(&w, "set_manager", &w.account)
    )
    .is_err());
}

#[test]
fn ci_denied_author_not_self() {
    let w = setup(true);
    let payload = signed_payload(&w, &w.ci_key, &w.ci_pub, w.ci_rule_id);
    let someone_else = Address::generate(&w.env);
    assert!(check(
        &w,
        &payload,
        registry_context(&w, "publish_hash", &someone_else)
    )
    .is_err());
}

#[test]
fn ci_denied_on_self_admin() {
    // The ci key must not be able to manage the account.
    let w = setup(true);
    let payload = signed_payload(&w, &w.ci_key, &w.ci_pub, w.ci_rule_id);
    assert!(check(&w, &payload, self_admin_context(&w, "add_signer")).is_err());
}

#[test]
fn admin_signature_rejected_for_ci_rule() {
    // Selecting the ci rule with an admin signature must fail: the rule's only
    // signer is the ci key.
    let w = setup(true);
    let payload = signed_payload(&w, &w.admin_key, &w.admin_pub, w.ci_rule_id);
    assert!(check(
        &w,
        &payload,
        registry_context(&w, "publish_hash", &w.account)
    )
    .is_err());
}
