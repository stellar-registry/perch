//! End-to-end matrix (#9): compile the ci-publish document, install the real
//! interpreter as an OZ policy, and drive the real `do_check_auth` with real
//! ed25519 signatures. No mocked auth for the signer under test — the ci key is
//! verified on-chain by a real verifier contract.

use ed25519_dalek::{Signer as _, SigningKey};
use perch_compile::{compile, CompileConfig};
use perch_ed25519_verifier::PerchEd25519Verifier;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, crypto::Hash, map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString,
    Symbol, Val,
};
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, remove_context_rule, AuthPayload, ContextRuleType, Signer,
};

mod common;
use common::{auth_digest, fixture};

const REGISTRY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

// --- the account under test (bare); the verifier is the real deployable -----

#[contract]
struct Account;

struct World {
    env: Env,
    account: Address,
    verifier: Address,
    registry: Address,
    signing_key: SigningKey,
    pubkey: BytesN<32>,
    rule_id: u32,
}

/// Compile ci-publish, deploy account+verifier+interpreter, and install the
/// ci-publish rule with the interpreter attached. `valid_until` lets the
/// expiry test install a rule that is already stale.
fn setup(valid_until: Option<u32>) -> World {
    let env = Env::default();
    env.mock_all_auths();

    let account = env.register(Account, ());
    let verifier = env.register(PerchEd25519Verifier, ());
    let interpreter = env.register(perch_interpreter::PerchInterpreter, ());

    // A deterministic ed25519 signer — the "ci" key.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    // Compile the real document → the ci-publish install params.
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    perch_ir::validate(&doc).expect("valid");
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(&env, &[0xAB; 32]),
    };
    let plan = compile(&env, &doc, &cfg).expect("compile");
    let install = plan.rules[1]
        .install
        .clone()
        .expect("ci-publish attaches interpreter");

    let registry = Address::from_str(&env, REGISTRY);
    let signer = Signer::External(verifier.clone(), pubkey.clone().into());
    let policies: Map<Address, Val> = map![&env, (interpreter.clone(), install.into_val(&env))];

    let rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(registry.clone()),
            &SString::from_str(&env, "ci-publish"),
            valid_until,
            &vec![&env, signer],
            &policies,
        )
    });

    World {
        env,
        account,
        verifier,
        registry,
        signing_key,
        pubkey,
        rule_id: rule.id,
    }
}

/// A signed auth payload from the ci key for `rule_id`.
fn signed_payload(w: &World, payload: &Hash<32>) -> AuthPayload {
    let ids = vec![&w.env, w.rule_id];
    let digest = auth_digest(&w.env, &payload.to_bytes(), &ids);
    let sig = w.signing_key.sign(&digest).to_bytes();
    let sig_bytes = Bytes::from_array(&w.env, &sig);
    let signer = Signer::External(w.verifier.clone(), w.pubkey.clone().into());
    let signers: Map<Signer, Bytes> = map![&w.env, (signer, sig_bytes)];
    AuthPayload {
        signers,
        context_rule_ids: ids,
    }
}

/// An empty (zero-signature) payload selecting `rule_id`.
fn empty_payload(w: &World) -> AuthPayload {
    AuthPayload {
        signers: Map::new(&w.env),
        context_rule_ids: vec![&w.env, w.rule_id],
    }
}

/// A `registry.<fn_name>(arg0, author)` context (author at arg index 1).
fn context(w: &World, fn_name: &str, author: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: w.registry.clone(),
        fn_name: Symbol::new(&w.env, fn_name),
        args: vec![&w.env, 0u32.into_val(&w.env), author.into_val(&w.env)],
    })
}

fn payload_hash(env: &Env) -> Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0x11; 32]))
}

fn run(w: &World, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
    let hash = payload_hash(&w.env);
    let contexts = vec![&w.env, ctx];
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        w.env.as_contract(&w.account, || {
            do_check_auth(&w.env, &hash, payload, &contexts).unwrap();
        });
    }));
    r.map_err(|_| ())
}

// --- the matrix -------------------------------------------------------------

#[test]
fn happy_path_ci_key_publishes_as_self() {
    let w = setup(None);
    let payload = signed_payload(&w, &payload_hash(&w.env));
    assert!(run(&w, &payload, context(&w, "publish_hash", &w.account)).is_ok());
}

#[test]
fn deny_other_function() {
    let w = setup(None);
    let payload = signed_payload(&w, &payload_hash(&w.env));
    assert!(run(&w, &payload, context(&w, "set_manager", &w.account)).is_err());
}

#[test]
fn deny_author_not_self() {
    let w = setup(None);
    let payload = signed_payload(&w, &payload_hash(&w.env));
    let someone_else = Address::generate(&w.env);
    assert!(run(&w, &payload, context(&w, "publish_hash", &someone_else)).is_err());
}

#[test]
fn deny_zero_signature_attack() {
    // The signer-sufficiency invariant end-to-end: selecting the rule with no
    // signatures must fail (INV-1 in the compiled program + the interpreter's
    // C4 floor).
    let w = setup(None);
    let payload = empty_payload(&w);
    assert!(run(&w, &payload, context(&w, "publish_hash", &w.account)).is_err());
}

#[test]
fn deny_expired_rule() {
    let w = setup(Some(5));
    w.env.ledger().with_mut(|l| l.sequence_number = 1000);
    let payload = signed_payload(&w, &payload_hash(&w.env));
    assert!(run(&w, &payload, context(&w, "publish_hash", &w.account)).is_err());
}

#[test]
fn deny_after_revocation() {
    let w = setup(None);
    // Same signed entry works before revocation...
    let payload = signed_payload(&w, &payload_hash(&w.env));
    assert!(run(&w, &payload, context(&w, "publish_hash", &w.account)).is_ok());
    // ...and fails after remove_context_rule.
    w.env.as_contract(&w.account, || {
        remove_context_rule(&w.env, w.rule_id);
    });
    let payload2 = signed_payload(&w, &payload_hash(&w.env));
    assert!(run(&w, &payload2, context(&w, "publish_hash", &w.account)).is_err());
}
