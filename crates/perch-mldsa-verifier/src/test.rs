extern crate std;

use crate::{
    key_commitment, MlDsaSigData, MlDsaVerifierError, PerchMlDsaVerifier, PerchMlDsaVerifierClient,
    PAYLOAD_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, SIG_CONTEXT,
};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};

/// A deterministic ML-DSA-65 key: its encoded public key and private key.
fn key(seed: u8) -> ([u8; PUBLIC_KEY_LEN], ml_dsa_65::PrivateKey) {
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
    (pk.into_bytes(), sk)
}

/// A deterministic signature (FIPS 204's `rnd` of zeros) over `message`.
fn sign(sk: &ml_dsa_65::PrivateKey, message: &[u8], context: &[u8]) -> [u8; SIGNATURE_LEN] {
    sk.try_sign_with_seed(&[0; 32], message, context)
        .expect("ML-DSA-65 signs")
}

fn sig_data(env: &Env, public_key: &[u8], signature: &[u8]) -> Bytes {
    MlDsaSigData {
        public_key: Bytes::from_slice(env, public_key),
        signature: Bytes::from_slice(env, signature),
    }
    .to_xdr(env)
}

fn commitment(env: &Env, public_key: &[u8]) -> BytesN<32> {
    key_commitment(env, &Bytes::from_slice(env, public_key))
}

struct Fixture {
    env: Env,
    id: Address,
    public_key: [u8; PUBLIC_KEY_LEN],
    sk: ml_dsa_65::PrivateKey,
    payload: [u8; PAYLOAD_LEN],
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        let id = env.register(PerchMlDsaVerifier, ());
        let (public_key, sk) = key(7);
        Fixture {
            env,
            id,
            public_key,
            sk,
            payload: [0x42; PAYLOAD_LEN],
        }
    }

    fn client(&self) -> PerchMlDsaVerifierClient<'_> {
        PerchMlDsaVerifierClient::new(&self.env, &self.id)
    }

    fn payload(&self) -> Bytes {
        Bytes::from_array(&self.env, &self.payload)
    }

    fn key_data(&self) -> BytesN<32> {
        commitment(&self.env, &self.public_key)
    }

    fn signed(&self) -> Bytes {
        let signature = sign(&self.sk, &self.payload, SIG_CONTEXT);
        sig_data(&self.env, &self.public_key, &signature)
    }

    /// `verify` through the host; `Some(verdict)`, or `None` if it trapped.
    fn verdict(&self, payload: &Bytes, key_data: &BytesN<32>, sig_data: &Bytes) -> Option<bool> {
        match self.client().try_verify(payload, key_data, sig_data) {
            Ok(Ok(verdict)) => Some(verdict),
            _ => None,
        }
    }

    fn error(&self, payload: &Bytes, sig_data: &Bytes) -> MlDsaVerifierError {
        match self
            .client()
            .try_verify(payload, &self.key_data(), sig_data)
        {
            Err(Ok(e)) => e.try_into().expect("a verifier error"),
            other => panic!("expected a verifier error, got {other:?}"),
        }
    }
}

#[test]
fn a_signature_over_the_payload_verifies() {
    let f = Fixture::new();
    assert!(f.client().verify(&f.payload(), &f.key_data(), &f.signed()));
}

#[test]
fn a_hedged_signature_verifies() {
    let f = Fixture::new();
    let signature =
        f.sk.try_sign_with_seed(&[0x5a; 32], &f.payload, SIG_CONTEXT)
            .unwrap();
    assert_ne!(signature, sign(&f.sk, &f.payload, SIG_CONTEXT));
    let sig = sig_data(&f.env, &f.public_key, &signature);
    assert!(f.client().verify(&f.payload(), &f.key_data(), &sig));
}

#[test]
fn a_signature_over_another_payload_is_refused() {
    let f = Fixture::new();
    let mut other = f.payload;
    other[31] ^= 1;
    let verdict = f.verdict(
        &Bytes::from_array(&f.env, &other),
        &f.key_data(),
        &f.signed(),
    );
    assert_eq!(verdict, Some(false));
}

#[test]
fn a_tampered_signature_is_refused() {
    let f = Fixture::new();
    let signature = sign(&f.sk, &f.payload, SIG_CONTEXT);
    // The commitment hash c~ (bytes 0..48), the response z, and the hint h
    // (the last 61 bytes: omega + k).
    for at in [0, 47, 48, 1000, SIGNATURE_LEN - 62, SIGNATURE_LEN - 1] {
        let mut tampered = signature;
        tampered[at] ^= 1;
        let sig = sig_data(&f.env, &f.public_key, &tampered);
        let verdict = f.verdict(&f.payload(), &f.key_data(), &sig);
        assert_eq!(verdict, Some(false), "a flipped bit at byte {at} verified");
    }
}

#[test]
fn another_keys_signature_is_refused() {
    let f = Fixture::new();
    let (other_key, other_sk) = key(8);
    let signature = sign(&other_sk, &f.payload, SIG_CONTEXT);
    // Presenting the other key fails the commitment; presenting the signer's
    // own key fails the signature.
    for presented in [other_key, f.public_key] {
        let sig = sig_data(&f.env, &presented, &signature);
        assert_eq!(f.verdict(&f.payload(), &f.key_data(), &sig), Some(false));
    }
}

#[test]
fn a_key_the_commitment_does_not_name_is_refused() {
    let f = Fixture::new();
    // A valid signature, checked against a signer whose commitment names
    // another key.
    let (other_key, _) = key(8);
    let verdict = f.verdict(&f.payload(), &commitment(&f.env, &other_key), &f.signed());
    assert_eq!(verdict, Some(false));

    // A tampered key under its own commitment: the commitment matches, the
    // signature does not.
    let mut tampered = f.public_key;
    tampered[100] ^= 1;
    let signature = sign(&f.sk, &f.payload, SIG_CONTEXT);
    let sig = sig_data(&f.env, &tampered, &signature);
    let verdict = f.verdict(&f.payload(), &commitment(&f.env, &tampered), &sig);
    assert_eq!(verdict, Some(false));
}

#[test]
fn a_signature_under_another_context_is_refused() {
    let f = Fixture::new();
    for context in [&b""[..], b"perch-mldsa-v1", b"nido-mldsa-v2"] {
        let signature = sign(&f.sk, &f.payload, context);
        let sig = sig_data(&f.env, &f.public_key, &signature);
        let verdict = f.verdict(&f.payload(), &f.key_data(), &sig);
        assert_eq!(verdict, Some(false), "context {context:?} verified");
    }
}

#[test]
fn a_payload_of_another_length_traps() {
    let f = Fixture::new();
    for len in [0, PAYLOAD_LEN - 1, PAYLOAD_LEN + 1, 64] {
        let payload = Bytes::from_slice(&f.env, &std::vec![0x42; len]);
        assert_eq!(
            f.error(&payload, &f.signed()),
            MlDsaVerifierError::PayloadLength
        );
    }
}

#[test]
fn a_public_key_of_another_length_traps() {
    let f = Fixture::new();
    let signature = sign(&f.sk, &f.payload, SIG_CONTEXT);
    let short = &f.public_key[..PUBLIC_KEY_LEN - 1];
    let mut long = f.public_key.to_vec();
    long.push(0);
    for public_key in [short, &long[..], &[][..]] {
        let sig = sig_data(&f.env, public_key, &signature);
        assert_eq!(
            f.error(&f.payload(), &sig),
            MlDsaVerifierError::PublicKeyLength
        );
    }
}

#[test]
fn a_signature_of_another_length_traps() {
    let f = Fixture::new();
    let signature = sign(&f.sk, &f.payload, SIG_CONTEXT);
    let short = &signature[..SIGNATURE_LEN - 1];
    let mut long = signature.to_vec();
    long.push(0);
    for signature in [short, &long[..], &[][..]] {
        let sig = sig_data(&f.env, &f.public_key, signature);
        assert_eq!(
            f.error(&f.payload(), &sig),
            MlDsaVerifierError::SignatureLength
        );
    }
}

#[test]
fn sig_data_that_is_not_ml_dsa_sig_data_traps() {
    let f = Fixture::new();
    // Well-formed XDR of another value.
    let not_sig_data = [
        7u32.to_xdr(&f.env),
        Bytes::from_slice(&f.env, &f.public_key).to_xdr(&f.env),
    ];
    for sig in not_sig_data {
        assert_eq!(
            f.error(&f.payload(), &sig),
            MlDsaVerifierError::SigDataEncoding
        );
    }
    // Bytes that are not XDR at all trap in the host, before the contract.
    let garbage = Bytes::from_array(&f.env, &[0xff; 16]);
    assert_eq!(f.verdict(&f.payload(), &f.key_data(), &garbage), None);
}

/// `verify` and `canonicalize_key` invoked with a key of `len` bytes, as an
/// account passes a signer's key: untyped `Bytes`.
fn untyped_key_calls(f: &Fixture, len: usize) -> [bool; 2] {
    let key: Val = Bytes::from_slice(&f.env, &std::vec![7u8; len]).into_val(&f.env);
    let verify = f.env.try_invoke_contract::<bool, soroban_sdk::Error>(
        &f.id,
        &Symbol::new(&f.env, "verify"),
        vec![
            &f.env,
            f.payload().into_val(&f.env),
            key,
            f.signed().into_val(&f.env),
        ],
    );
    let canonicalize = f.env.try_invoke_contract::<Bytes, soroban_sdk::Error>(
        &f.id,
        &Symbol::new(&f.env, "canonicalize_key"),
        vec![&f.env, key],
    );
    [verify.is_ok(), canonicalize.is_ok()]
}

#[test]
fn a_key_of_another_length_traps() {
    let f = Fixture::new();
    assert_eq!(untyped_key_calls(&f, 32), [true, true]);
    for len in [0, 31, 33, 65, PUBLIC_KEY_LEN] {
        assert_eq!(untyped_key_calls(&f, len), [false, false], "{len}-byte key");
    }
}

#[test]
fn the_canonical_key_is_the_commitment() {
    let f = Fixture::new();
    let key_data = f.key_data();
    let canonical = f.client().canonicalize_key(&key_data);
    assert_eq!(canonical, Bytes::from(key_data.clone()));
    // Round trip: the canonical bytes are a key that canonicalizes to itself.
    let again: BytesN<32> = canonical.clone().try_into().unwrap();
    assert_eq!(f.client().canonicalize_key(&again), canonical);
}

#[test]
fn a_batch_canonicalizes_each_key_in_order() {
    let f = Fixture::new();
    let keys = Vec::from_array(
        &f.env,
        [
            commitment(&f.env, &key(1).0),
            commitment(&f.env, &key(2).0),
            commitment(&f.env, &key(1).0),
        ],
    );
    let canonical = f.client().batch_canonicalize_key(&keys);
    assert_eq!(canonical.len(), keys.len());
    for (k, c) in keys.iter().zip(canonical.iter()) {
        assert_eq!(f.client().canonicalize_key(&k), c);
    }
    assert_eq!(canonical.get(0), canonical.get(2));
    assert_ne!(canonical.get(0), canonical.get(1));
    assert!(f
        .client()
        .batch_canonicalize_key(&Vec::new(&f.env))
        .is_empty());
}
