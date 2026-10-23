//! The digest a Perch account's `check_auth` makes an `External` signer
//! authenticate against must bind the account's own address, so a signature
//! collected for one account cannot be replayed on another that happens to
//! share the same key and the same selected rule ids.
//!
//! Soroban's `HashIdPreimage::SorobanAuthorization` (the `signature_payload`
//! the host hands a non-delegated custom-account credential) binds the
//! network, nonce, expiration, and invocation, but NOT the address of the
//! account whose `__check_auth` runs. The host's per-account nonce namespace
//! stops reuse *within* one account, never across two. OZ then layers only the
//! selected rule ids into the signed digest
//! (`sha256(signature_payload || rule_ids.to_xdr())`), still with no account
//! address. Two accounts with the same `External` key and matching rule ids
//! therefore demand a byte-identical digest — a legacy signature is replayable.
//!
//! The `Signer::Delegated` (CAP-0071 / `AddressWithDelegates`) path is
//! unaffected: it never consumes this digest (the host validates it under
//! `SorobanAuthorizationWithAddress`, which is already address-bound).

use ed25519_dalek::{Signer as _, SigningKey};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_testkit::auth_digest;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    contract, contractimpl, crypto::Hash, map, symbol_short, vec, Address, Bytes, BytesN, Env,
    IntoVal, Map, String as SString, Symbol, Vec,
};
use stellar_accounts::smart_account::{add_context_rule, AuthPayload, ContextRuleType, Signer};
use stellar_accounts::verifiers::Verifier;

/// A verifier that records the last `signature_payload` (the account's
/// auth digest) it was asked to check and always approves, so a test can read
/// back exactly what digest the account's `check_auth` bound a signature to.
#[contract]
struct RecordingVerifier;

const LAST: Symbol = symbol_short!("last");

#[contractimpl]
impl Verifier for RecordingVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    fn verify(e: &Env, signature_payload: Bytes, _key: Bytes, _sig: Bytes) -> bool {
        e.storage().instance().set(&LAST, &signature_payload);
        true
    }

    fn canonicalize_key(_e: &Env, key: Bytes) -> Bytes {
        key
    }

    fn batch_canonicalize_key(_e: &Env, keys: Vec<Bytes>) -> Vec<Bytes> {
        keys
    }
}

#[contract]
struct Account;

/// Install one `CallContract(target)` rule whose only signer is
/// `External(verifier, key)`, then drive the account's real `check_auth`
/// once and return the digest the verifier recorded.
fn digest_for_account(env: &Env, verifier: &Address, key: &Bytes, target: &Address) -> BytesN<32> {
    let account = env.register(Account, ());
    let signer = Signer::External(verifier.clone(), key.clone());
    let rule = env.as_contract(&account, || {
        add_context_rule(
            env,
            &ContextRuleType::CallContract(target.clone()),
            &SString::from_str(env, "r"),
            None,
            &vec![env, signer.clone()],
            &Map::new(env),
        )
    });

    let ids = vec![env, rule.id];
    let payload: Map<Signer, Bytes> = map![env, (signer, Bytes::from_array(env, &[9u8; 64]))];
    let signatures = AuthPayload {
        signers: payload,
        context_rule_ids: ids,
    };
    // A fixed host payload: identical for both accounts, so any difference in
    // the recorded digest comes only from the account-address binding.
    let host_payload: Hash<32> = env.crypto().sha256(&Bytes::from_array(env, &[0x11; 32]));
    let contexts = vec![
        env,
        Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: Symbol::new(env, "publish"),
            args: vec![env, 0u32.into_val(env)],
        }),
    ];

    env.as_contract(&account, || {
        perch_smart_account::check_auth(env, &host_payload, &signatures, &contexts)
            .expect("recording verifier approves");
    });
    env.as_contract(verifier, || {
        env.storage()
            .instance()
            .get::<Symbol, Bytes>(&LAST)
            .map(|b| {
                let mut out = [0u8; 32];
                b.copy_into_slice(&mut out);
                BytesN::from_array(env, &out)
            })
            .expect("verifier recorded a digest")
    })
}

#[test]
fn external_digest_binds_the_account_address() {
    let env = Env::default();
    let verifier = env.register(RecordingVerifier, ());
    let target = Address::generate(&env);
    // The same external key and the same rule id (both accounts install rule 0).
    let key = Bytes::from_array(&env, &[0xaa; 65]);

    let digest_a = digest_for_account(&env, &verifier, &key, &target);
    let digest_b = digest_for_account(&env, &verifier, &key, &target);

    // Two distinct accounts, same key, same selected rule id, same host
    // payload: the signed digest must still differ, or a signature made for
    // one account authorizes the other.
    assert_ne!(
        digest_a, digest_b,
        "External-signer digest is identical across accounts: a legacy signature is replayable"
    );
}

/// Install rule 0 as `CallContract(target)` with one `External(verifier, key)`
/// signer and return the account.
fn account_with_rule(env: &Env, verifier: &Address, key: &BytesN<32>, target: &Address) -> Address {
    let account = env.register(Account, ());
    let signer = Signer::External(verifier.clone(), key.clone().into());
    env.as_contract(&account, || {
        add_context_rule(
            env,
            &ContextRuleType::CallContract(target.clone()),
            &SString::from_str(env, "r"),
            None,
            &vec![env, signer],
            &Map::new(env),
        );
    });
    account
}

/// A real end-to-end replay: an ed25519 `External` signature collected for one
/// account, with a matching rule id, must not authorize a second account that
/// shares the same key. The legitimate use (same account) must still succeed.
#[test]
fn ed25519_external_signature_is_not_replayable_across_accounts() {
    let env = Env::default();
    let verifier = env.register(PerchEd25519Verifier, ());
    let target = Address::generate(&env);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    let account_a = account_with_rule(&env, &verifier, &pubkey, &target);
    let account_b = account_with_rule(&env, &verifier, &pubkey, &target);

    // Both accounts installed rule 0, so the selected rule ids match too.
    let ids = vec![&env, 0u32];
    let host_hash: Hash<32> = env.crypto().sha256(&Bytes::from_array(&env, &[0x11; 32]));
    let host_payload: BytesN<32> = host_hash.to_bytes();

    // The signature a wallet produces for account A.
    let digest_a = auth_digest(&env, &account_a, &host_payload, &ids);
    let sig = signing_key.sign(&digest_a).to_bytes();
    let signer = Signer::External(verifier.clone(), pubkey.clone().into());
    let payload = AuthPayload {
        signers: map![&env, (signer, Bytes::from_array(&env, &sig))],
        context_rule_ids: ids,
    };
    let contexts = vec![
        &env,
        Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: Symbol::new(&env, "publish"),
            args: vec![&env, 0u32.into_val(&env)],
        }),
    ];

    // Legitimate use on account A succeeds.
    env.as_contract(&account_a, || {
        perch_smart_account::check_auth(&env, &host_hash, &payload, &contexts)
            .expect("account A authorizes its own signature");
    });

    // Replaying the same signature on account B is rejected.
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account_b, || {
            perch_smart_account::check_auth(&env, &host_hash, &payload, &contexts)
        })
    }));
    let rejected = match replay {
        Err(_) => true,     // OZ panics with ExternalVerificationFailed
        Ok(Err(_)) => true, // or check_auth returns an error
        Ok(Ok(())) => false,
    };
    assert!(
        rejected,
        "account B accepted a signature made for account A: cross-account replay"
    );
}
