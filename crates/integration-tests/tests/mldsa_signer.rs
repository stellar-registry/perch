//! A post-quantum signer on the account: an ML-DSA-65 key as
//! `External(perch-mldsa-verifier, sha256(public key))`, verified by the real
//! verifier contract, on a real `PerchAccount` through its exported
//! `__check_auth` (`try_invoke_contract_check_auth`), which decides with
//! rule-eval over the rules the account stores. No mocked auth for the signer
//! under test.
//!
//! - The constructor's admin rule with the ML-DSA key as its signer: it
//!   authorizes the account; another key's signature, a tampered one, one
//!   made for another account, and an empty payload are refused. The raw
//!   1,952-byte public key as the signer's key is refused at construction
//!   (`KeyDataTooLarge`, #3013) before any verifier runs.
//! - The fixture's ci-publish rule with the ML-DSA key as its ci signer
//!   (`perch_testkit::ci_publish_rule`): `publish_hash` as the account
//!   passes; another function, another author, an expired rule, and a
//!   removed rule are refused.
//! - A hybrid admin, an ML-DSA key and an Ed25519 key, needs both
//!   signatures.
//! - A document naming an ML-DSA signer compiles through the doc compiler,
//!   which canonicalizes the key through the verifier.

use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use perch_account::PerchAccount;
use perch_account_types::{AuthPayload, Signer};
use perch_doc_compiler::{DocCompilerError, PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_mldsa_verifier::{key_commitment, MlDsaSigData, PerchMlDsaVerifier, SIG_CONTEXT};
use perch_smart_account::testutils::{install_rule, remove_rule};
use perch_testkit::{
    auth_digest, ci_publish_rule, fixture, AnyKeyVerifier, FIXTURE_NETWORK, FIXTURE_VERIFIERS,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, Vec};

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

/// The host's signature payload every check here hands the account.
fn payload_hash(env: &Env) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_array(env, &[0x11; 32]))
        .to_bytes()
}

fn payload(signers: Map<Signer, Bytes>, ids: Vec<u32>) -> AuthPayload {
    AuthPayload {
        signers,
        context_rule_ids: ids,
    }
}

/// Drive `account`'s exported `__check_auth` over one context.
fn check(env: &Env, account: &Address, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
    env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        account,
        &payload_hash(env),
        payload.clone().into_val(env),
        &vec![env, ctx],
    )
    .map_err(|_| ())
}

/// A call on `account` itself, which its admin rule authorizes.
fn on_account(env: &Env, account: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: account.clone(),
        fn_name: Symbol::new(env, "execute"),
        args: vec![env],
    })
}

/// A `PerchAccount` whose constructor installs `signers` as its admin rule
/// (rule 0).
fn account_with_admin(env: &Env, signers: Vec<Signer>) -> Address {
    env.register(PerchAccount, (signers,))
}

/// The admin id the constructor gives.
const ADMIN: u32 = 0;

struct World {
    env: Env,
    account: Address,
    verifier: Address,
    registry: Address,
    key: MlDsaKey,
}

/// A `PerchAccount` whose constructor admin is the ML-DSA key.
fn setup() -> World {
    let env = Env::default();
    let verifier = perch_testkit::verifiers::deploy(&env, PerchMlDsaVerifier);
    let key = MlDsaKey::from_seed(7);
    let signer = Signer::External(verifier.clone(), key.key_data(&env));
    let account = account_with_admin(&env, vec![&env, signer]);
    let registry = Address::generate(&env);
    World {
        env,
        account,
        verifier,
        registry,
        key,
    }
}

impl World {
    fn signer(&self) -> Signer {
        Signer::External(self.verifier.clone(), self.key.key_data(&self.env))
    }

    fn digest_on(&self, account: &Address, rule_ids: &Vec<u32>) -> [u8; 32] {
        auth_digest(&self.env, account, &payload_hash(&self.env), rule_ids)
    }

    /// The ML-DSA key's signed payload choosing `rule`.
    fn signed(&self, rule: u32) -> AuthPayload {
        let ids = vec![&self.env, rule];
        let sig = self
            .key
            .sign(&self.env, &self.digest_on(&self.account, &ids));
        payload(map![&self.env, (self.signer(), sig)], ids)
    }

    fn check(&self, payload: &AuthPayload, ctx: Context) -> Result<(), ()> {
        check(&self.env, &self.account, payload, ctx)
    }

    fn on_account(&self) -> Context {
        on_account(&self.env, &self.account)
    }

    /// Install the fixture's ci-publish rule with the ML-DSA key as its ci
    /// signer, last valid at `valid_until`; returns its id.
    fn ci_publish(&self, valid_until: Option<u32>) -> u32 {
        let rule = ci_publish_rule(
            &self.env,
            &self.account,
            &self.registry,
            vec![&self.env, self.signer()],
            valid_until,
        );
        self.env.as_contract(&self.account, || {
            install_rule(&self.env, "ci-publish", &rule)
        })
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

// --- the constructor's admin rule -------------------------------------------

#[test]
fn an_ml_dsa_admin_authorizes_the_account() {
    let w = setup();
    assert!(w.check(&w.signed(ADMIN), w.on_account()).is_ok());
}

#[test]
fn deny_zero_signature_attack() {
    let w = setup();
    let empty = payload(Map::new(&w.env), vec![&w.env, ADMIN]);
    assert!(w.check(&empty, w.on_account()).is_err());
}

#[test]
fn deny_another_ml_dsa_key() {
    // Another key's valid signature, presented for the admin signer: its
    // public key is not the one the signer's commitment names.
    let w = setup();
    let ids = vec![&w.env, ADMIN];
    let other = MlDsaKey::from_seed(8);
    let sig = other.sign(&w.env, &w.digest_on(&w.account, &ids));
    let forged = payload(map![&w.env, (w.signer(), sig)], ids);
    assert!(w.check(&forged, w.on_account()).is_err());
}

#[test]
fn deny_a_tampered_signature() {
    let w = setup();
    let ids = vec![&w.env, ADMIN];
    let mut signature = w
        .key
        .sk
        .try_sign_with_seed(&[0; 32], &w.digest_on(&w.account, &ids), SIG_CONTEXT)
        .unwrap();
    signature[100] ^= 1;
    let sig = sig_data(&w.env, &w.key.public_key, &signature);
    let tampered = payload(map![&w.env, (w.signer(), sig)], ids);
    assert!(w.check(&tampered, w.on_account()).is_err());
}

#[test]
fn deny_a_signature_made_for_another_account() {
    // The digest binds the account's address: one ML-DSA key admin of two
    // accounts, under the same rule id, still signs a different digest for
    // each.
    let w = setup();
    let replayed = w.signed(ADMIN);
    let other = account_with_admin(&w.env, vec![&w.env, w.signer()]);
    assert!(check(&w.env, &other, &replayed, on_account(&w.env, &other)).is_err());

    // The key signing the other account's own digest passes.
    let ids = vec![&w.env, ADMIN];
    let own_sig = w.key.sign(&w.env, &w.digest_on(&other, &ids));
    let own = payload(map![&w.env, (w.signer(), own_sig)], ids);
    assert!(check(&w.env, &other, &own, on_account(&w.env, &other)).is_ok());
}

#[test]
fn the_raw_public_key_is_refused_as_a_signer_key() {
    // The signer's key is the 32-byte commitment; the 1,952-byte public key
    // itself is over the account's key limit, refused before any verifier
    // is asked.
    let env = Env::default();
    let verifier = perch_testkit::verifiers::deploy(&env, PerchMlDsaVerifier);
    let key = MlDsaKey::from_seed(7);
    let raw = Signer::External(verifier, Bytes::from_slice(&env, &key.public_key));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        account_with_admin(&env, vec![&env, raw])
    }));
    let msg = out.map(|_| String::new()).unwrap_or_else(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    });
    assert!(msg.contains("Error(Contract, #3013)"), "got: {msg}");
}

// --- the ci-publish rule with an ML-DSA ci key ------------------------------

#[test]
fn happy_path_ml_dsa_ci_key_publishes_as_self() {
    let w = setup();
    let ci = w.ci_publish(None);
    assert!(w.check(&w.signed(ci), w.publish()).is_ok());
}

#[test]
fn deny_other_function() {
    let w = setup();
    let ci = w.ci_publish(None);
    assert!(w
        .check(&w.signed(ci), w.context("set_manager", &w.account))
        .is_err());
}

#[test]
fn deny_author_not_self() {
    let w = setup();
    let ci = w.ci_publish(None);
    let someone_else = Address::generate(&w.env);
    assert!(w
        .check(&w.signed(ci), w.context("publish_hash", &someone_else))
        .is_err());
}

#[test]
fn deny_expired_rule() {
    let w = setup();
    let ci = w.ci_publish(Some(5));
    w.env.ledger().with_mut(|l| l.sequence_number = 1000);
    assert!(w.check(&w.signed(ci), w.publish()).is_err());
}

#[test]
fn deny_after_revocation() {
    let w = setup();
    let ci = w.ci_publish(None);
    assert!(w.check(&w.signed(ci), w.publish()).is_ok());
    w.env.as_contract(&w.account, || remove_rule(&w.env, ci));
    assert!(w.check(&w.signed(ci), w.publish()).is_err());
}

// --- an ML-DSA key and an Ed25519 key in one rule ---------------------------

/// A `PerchAccount` whose admin rule holds an ML-DSA key and an Ed25519 key:
/// the constructor's rule requires every signer, so both must sign.
struct Hybrid {
    w: World,
    ed25519: SigningKey,
    ed25519_signer: Signer,
}

fn hybrid() -> Hybrid {
    let mut w = setup();
    let ed25519 = SigningKey::from_bytes(&[2; 32]);
    let verifier = perch_testkit::verifiers::deploy(&w.env, PerchEd25519Verifier);
    let ed25519_signer = Signer::External(
        verifier,
        Bytes::from_array(&w.env, &ed25519.verifying_key().to_bytes()),
    );
    w.account = account_with_admin(&w.env, vec![&w.env, w.signer(), ed25519_signer.clone()]);
    Hybrid {
        w,
        ed25519,
        ed25519_signer,
    }
}

impl Hybrid {
    fn signed_by(&self, ml_dsa: bool, ed25519: bool) -> AuthPayload {
        let env = &self.w.env;
        let ids = vec![env, ADMIN];
        let digest = self.w.digest_on(&self.w.account, &ids);
        let mut signers = Map::new(env);
        if ml_dsa {
            signers.set(self.w.signer(), self.w.key.sign(env, &digest));
        }
        if ed25519 {
            let sig = self.ed25519.sign(&digest).to_bytes();
            signers.set(self.ed25519_signer.clone(), Bytes::from_array(env, &sig));
        }
        payload(signers, ids)
    }
}

#[test]
fn a_hybrid_rule_passes_with_both_signatures() {
    let h = hybrid();
    assert!(h
        .w
        .check(&h.signed_by(true, true), h.w.on_account())
        .is_ok());
}

#[test]
fn a_hybrid_rule_refuses_the_ed25519_key_alone() {
    let h = hybrid();
    assert!(h
        .w
        .check(&h.signed_by(false, true), h.w.on_account())
        .is_err());
}

#[test]
fn a_hybrid_rule_refuses_the_ml_dsa_key_alone() {
    let h = hybrid();
    assert!(h
        .w
        .check(&h.signed_by(true, false), h.w.on_account())
        .is_err());
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
    // An admin document names its verifiers: the fixture's admin verifier
    // and the ML-DSA verifier, from `perch/verifiers`.
    let admin = perch_testkit::verifiers::deploy_named(
        &env,
        AnyKeyVerifier,
        "fixture-admin-verifier@1.0.0",
    );
    let verifier = perch_testkit::verifiers::deploy_named(
        &env,
        PerchMlDsaVerifier,
        "perch-mldsa-verifier@1.0.0",
    );
    let compiler = env.register(PerchDocCompiler, ());

    let mut doc: serde_json::Value = serde_json::from_str(&fixture()).unwrap();
    let signers = doc["signers"].as_array_mut().unwrap();
    assert_eq!(signers[0]["verifier"], FIXTURE_VERIFIERS[0]);
    signers[0]["verifier"] = perch_testkit::delta::strkey(&admin).into();
    signers[0]["verifier-name"] = "fixture-admin-verifier@1.0.0".into();
    let ci = &mut signers[1];
    assert_eq!(ci["id"], "ci");
    ci["verifier"] = perch_testkit::delta::strkey(&verifier).into();
    ci["verifier-name"] = "perch-mldsa-verifier@1.0.0".into();
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
