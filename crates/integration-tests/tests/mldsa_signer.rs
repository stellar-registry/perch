//! The end-to-end matrix (#9, `matrix.rs`) with a post-quantum ci key: the
//! compiled ci-publish rule with the real interpreter attached, and the ci
//! key an ML-DSA-65 signer, `External(perch-mldsa-verifier, sha256(public
//! key))`, verified by the real verifier contract. No mocked auth for the
//! signer under test.
//!
//! Also: a key or signature the rule does not hold is refused, a passkey and
//! an ML-DSA key in one rule must both sign, and a document naming an ML-DSA
//! signer compiles through the doc compiler, which canonicalizes the key
//! through the verifier.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use perch_compile::{compile, CompileConfig};
use perch_doc_compiler::{DocCompilerError, PerchDocCompiler, PerchDocCompilerClient};
use perch_mldsa_verifier::{key_commitment, MlDsaSigData, PerchMlDsaVerifier, SIG_CONTEXT};
use perch_testkit::passkey::{self, SoftPasskey};
use perch_testkit::FIXTURE_REGISTRY as REGISTRY;
use perch_testkit::{auth_digest, fixture, AnyKeyVerifier, FIXTURE_NETWORK, FIXTURE_VERIFIERS};
use perch_webauthn_verifier::PerchWebAuthnVerifier;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, crypto::Hash, map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString,
    Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    add_context_rule, remove_context_rule, AuthPayload, ContextRuleType, Signer,
};

#[contract]
struct Account;

/// An ML-DSA-65 key from a seed, as the signer's tooling holds it.
struct MlDsaKey {
    public_key: [u8; ml_dsa_65::PK_LEN],
    sk: ml_dsa_65::PrivateKey,
}

impl MlDsaKey {
    fn from_seed(seed: u8) -> Self {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        MlDsaKey {
            public_key: pk.into_bytes(),
            sk,
        }
    }

    fn key_data(&self, env: &Env) -> Bytes {
        key_commitment(env, &Bytes::from_slice(env, &self.public_key)).into()
    }

    /// `sig_data` for `digest`: the public key and a signature over it.
    fn sign(&self, env: &Env, digest: &[u8; 32]) -> Bytes {
        let signature = self
            .sk
            .try_sign_with_seed(&[0; 32], digest, SIG_CONTEXT)
            .unwrap();
        sig_data(env, &self.public_key, &signature)
    }
}

fn sig_data(env: &Env, public_key: &[u8], signature: &[u8]) -> Bytes {
    MlDsaSigData {
        public_key: Bytes::from_slice(env, public_key),
        signature: Bytes::from_slice(env, signature),
    }
    .to_xdr(env)
}

struct World {
    env: Env,
    account: Address,
    verifier: Address,
    registry: Address,
    ci: MlDsaKey,
    rule_id: u32,
}

impl World {
    fn signer(&self) -> Signer {
        Signer::External(self.verifier.clone(), self.ci.key_data(&self.env))
    }

    fn digest(&self, rule_ids: &Vec<u32>) -> [u8; 32] {
        auth_digest(
            &self.env,
            &self.account,
            &payload_hash(&self.env).to_bytes(),
            rule_ids,
        )
    }

    /// The ci key's signed payload for the ci-publish rule.
    fn signed(&self) -> AuthPayload {
        let ids = vec![&self.env, self.rule_id];
        let sig = self.ci.sign(&self.env, &self.digest(&ids));
        payload(map![&self.env, (self.signer(), sig)], ids)
    }

    /// A `registry.<fn_name>(0, author)` context (author at arg index 1).
    fn context(&self, fn_name: &str, author: &Address) -> Context {
        Context::Contract(ContractContext {
            contract: self.registry.clone(),
            fn_name: Symbol::new(&self.env, fn_name),
            args: vec![
                &self.env,
                0u32.into_val(&self.env),
                author.into_val(&self.env),
            ],
        })
    }

    fn publish(&self) -> Context {
        self.context("publish_hash", &self.account)
    }
}

/// Compile ci-publish and install its rule, with the ci key an ML-DSA signer
/// and the interpreter attached, on a fresh account.
fn setup(valid_until: Option<u32>) -> World {
    let env = Env::default();
    env.mock_all_auths();
    let account = env.register(Account, ());
    let verifier = env.register(PerchMlDsaVerifier, ());
    let interpreter = env.register(perch_interpreter::PerchInterpreter, ());
    let ci = MlDsaKey::from_seed(7);

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
    let signer = Signer::External(verifier.clone(), ci.key_data(&env));
    let policies: Map<Address, Val> = map![&env, (interpreter, install.into_val(&env))];
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
        ci,
        rule_id: rule.id,
    }
}

fn payload(signers: Map<Signer, Bytes>, ids: Vec<u32>) -> AuthPayload {
    AuthPayload {
        signers,
        context_rule_ids: ids,
    }
}

fn payload_hash(env: &Env) -> Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0x11; 32]))
}

/// The account's own `check_auth` (it binds the digest to the account's
/// address) around OZ's `do_check_auth`.
fn run_on(env: &Env, account: &Address, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
    let hash = payload_hash(env);
    let contexts = vec![env, ctx];
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(account, || {
            perch_smart_account::check_auth(env, &hash, payload, &contexts).unwrap();
        });
    }))
    .map_err(|_| ())
}

fn run(w: &World, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
    run_on(&w.env, &w.account, payload, ctx)
}

// --- the #9 matrix ----------------------------------------------------------

#[test]
fn happy_path_ml_dsa_ci_key_publishes_as_self() {
    let w = setup(None);
    assert!(run(&w, &w.signed(), w.publish()).is_ok());
}

#[test]
fn deny_other_function() {
    let w = setup(None);
    assert!(run(&w, &w.signed(), w.context("set_manager", &w.account)).is_err());
}

#[test]
fn deny_author_not_self() {
    let w = setup(None);
    let someone_else = Address::generate(&w.env);
    assert!(run(&w, &w.signed(), w.context("publish_hash", &someone_else)).is_err());
}

#[test]
fn deny_zero_signature_attack() {
    let w = setup(None);
    let empty = payload(Map::new(&w.env), vec![&w.env, w.rule_id]);
    assert!(run(&w, &empty, w.publish()).is_err());
}

#[test]
fn deny_expired_rule() {
    let w = setup(Some(5));
    w.env.ledger().with_mut(|l| l.sequence_number = 1000);
    assert!(run(&w, &w.signed(), w.publish()).is_err());
}

#[test]
fn deny_after_revocation() {
    let w = setup(None);
    assert!(run(&w, &w.signed(), w.publish()).is_ok());
    w.env.as_contract(&w.account, || {
        remove_context_rule(&w.env, w.rule_id);
    });
    assert!(run(&w, &w.signed(), w.publish()).is_err());
}

// --- keys and signatures the rule does not hold -----------------------------

#[test]
fn deny_another_ml_dsa_key() {
    // Another key's valid signature, presented for the ci signer: its public
    // key is not the one the signer's commitment names.
    let w = setup(None);
    let ids = vec![&w.env, w.rule_id];
    let other = MlDsaKey::from_seed(8);
    let sig = other.sign(&w.env, &w.digest(&ids));
    let forged = payload(map![&w.env, (w.signer(), sig)], ids);
    assert!(run(&w, &forged, w.publish()).is_err());
}

#[test]
fn deny_a_tampered_signature() {
    let w = setup(None);
    let ids = vec![&w.env, w.rule_id];
    let mut signature =
        w.ci.sk
            .try_sign_with_seed(&[0; 32], &w.digest(&ids), SIG_CONTEXT)
            .unwrap();
    signature[100] ^= 1;
    let sig = sig_data(&w.env, &w.ci.public_key, &signature);
    let tampered = payload(map![&w.env, (w.signer(), sig)], ids);
    assert!(run(&w, &tampered, w.publish()).is_err());
}

#[test]
fn deny_a_signature_made_for_another_account() {
    // The digest binds the account's address: one ML-DSA key on two accounts
    // with the same rule ids still signs a different digest for each.
    let w = setup(None);
    let replayed = w.signed();
    let other = w.env.register(Account, ());
    let rule = w.env.as_contract(&other, || {
        add_context_rule(
            &w.env,
            &ContextRuleType::CallContract(w.registry.clone()),
            &SString::from_str(&w.env, "ci-publish"),
            None,
            &vec![&w.env, w.signer()],
            &Map::new(&w.env),
        )
    });
    assert_eq!(rule.id, w.rule_id);
    let ctx = || w.context("publish_hash", &other);
    assert!(run_on(&w.env, &other, &replayed, ctx()).is_err());

    // The key signing for the other account's own digest passes.
    let ids = vec![&w.env, rule.id];
    let digest = auth_digest(&w.env, &other, &payload_hash(&w.env).to_bytes(), &ids);
    let own = payload(map![&w.env, (w.signer(), w.ci.sign(&w.env, &digest))], ids);
    assert!(run_on(&w.env, &other, &own, ctx()).is_ok());
}

// --- a passkey and an ML-DSA key in one rule --------------------------------

/// An account whose Default rule holds a passkey and an ML-DSA key: OZ's
/// policy-less rule needs every signer, so both must sign.
struct Hybrid {
    w: World,
    passkey: SoftPasskey,
    passkey_signer: Signer,
    rule_id: u32,
}

fn hybrid() -> Hybrid {
    let w = setup(None);
    let passkey = SoftPasskey::from_seed([2; 32]);
    let webauthn = w.env.register(PerchWebAuthnVerifier, ());
    let passkey_signer =
        Signer::External(webauthn, Bytes::from_slice(&w.env, &passkey.public_key()));
    let rule = w.env.as_contract(&w.account, || {
        add_context_rule(
            &w.env,
            &ContextRuleType::Default,
            &SString::from_str(&w.env, "hybrid"),
            None,
            &vec![&w.env, passkey_signer.clone(), w.signer()],
            &Map::new(&w.env),
        )
    });
    Hybrid {
        w,
        passkey,
        passkey_signer,
        rule_id: rule.id,
    }
}

impl Hybrid {
    fn signed_by(&self, passkey: bool, ml_dsa: bool) -> AuthPayload {
        let env = &self.w.env;
        let ids = vec![env, self.rule_id];
        let digest = self.w.digest(&ids);
        let mut signers = Map::new(env);
        if passkey {
            let sig = passkey::sig_data(env, &self.passkey.assert(&digest));
            signers.set(self.passkey_signer.clone(), sig);
        }
        if ml_dsa {
            signers.set(self.w.signer(), self.w.ci.sign(env, &digest));
        }
        payload(signers, ids)
    }

    fn transfer(&self) -> Context {
        Context::Contract(ContractContext {
            contract: Address::generate(&self.w.env),
            fn_name: Symbol::new(&self.w.env, "transfer"),
            args: vec![&self.w.env],
        })
    }
}

#[test]
fn a_hybrid_rule_passes_with_both_signatures() {
    let h = hybrid();
    assert!(run(&h.w, &h.signed_by(true, true), h.transfer()).is_ok());
}

#[test]
fn a_hybrid_rule_refuses_the_passkey_alone() {
    let h = hybrid();
    assert!(run(&h.w, &h.signed_by(true, false), h.transfer()).is_err());
}

#[test]
fn a_hybrid_rule_refuses_the_ml_dsa_key_alone() {
    let h = hybrid();
    assert!(run(&h.w, &h.signed_by(false, true), h.transfer()).is_err());
}

// --- a document naming an ML-DSA signer -------------------------------------

/// The ci-publish fixture with its ci signer an ML-DSA signer on a
/// registered verifier, holding `key_hex`, compiled by the doc compiler
/// contract.
fn compile_with_ci(key_hex: &str) -> Result<(), DocCompilerError> {
    let env = Env::default();
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);
    env.register_at(
        &Address::from_str(&env, FIXTURE_VERIFIERS[0]),
        AnyKeyVerifier,
        (),
    );
    let verifier = env.register(PerchMlDsaVerifier, ());
    let compiler = env.register(PerchDocCompiler, ());

    let mut doc: serde_json::Value = serde_json::from_str(&fixture()).unwrap();
    let ci = &mut doc["signers"][1];
    assert_eq!(ci["id"], "ci");
    ci["verifier"] = verifier.to_string().to_string().into(); // the C... strkey
    ci["key"] = key_hex.into();
    let json = serde_json::to_string(&doc).unwrap();
    match PerchDocCompilerClient::new(&env, &compiler)
        .try_compile_doc(&Bytes::from_slice(&env, json.as_bytes()))
    {
        Ok(Ok(_)) => Ok(()),
        Err(Ok(e)) => Err(e),
        other => panic!("compile_doc: {other:?}"),
    }
}

#[test]
fn a_document_with_an_ml_dsa_signer_compiles() {
    let env = Env::default();
    let key = MlDsaKey::from_seed(7).key_data(&env);
    let mut hex_key = [0u8; 32];
    key.copy_into_slice(&mut hex_key);
    assert_eq!(compile_with_ci(&hex::encode(hex_key)), Ok(()));
}

#[test]
fn a_document_with_an_ml_dsa_key_of_another_length_is_refused() {
    // The raw public key instead of its commitment, and a commitment with a
    // byte appended: the verifier traps on a key that is not 32 bytes.
    let key = MlDsaKey::from_seed(7);
    let env = Env::default();
    let mut commitment = [0u8; 32];
    key.key_data(&env).copy_into_slice(&mut commitment);
    let mut long = commitment.to_vec();
    long.push(0);
    for bad in [&key.public_key[..200], &long[..]] {
        assert_eq!(
            compile_with_ci(&hex::encode(bad)),
            Err(DocCompilerError::KeyNotCanonicalizable)
        );
    }
}
