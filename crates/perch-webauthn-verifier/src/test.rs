extern crate std;

use crate::{PerchWebAuthnVerifier, PerchWebAuthnVerifierClient};
use perch_testkit::passkey::{sig_data, SoftPasskey, FLAGS_UP_UV};
use soroban_sdk::{Bytes, Env, Vec};

fn setup() -> (Env, PerchWebAuthnVerifierClient<'static>, SoftPasskey) {
    let env = Env::default();
    let id = env.register(PerchWebAuthnVerifier, ());
    let client = PerchWebAuthnVerifierClient::new(&env, &id);
    (env, client, SoftPasskey::from_seed([7; 32]))
}

#[test]
fn a_passkey_assertion_over_the_payload_verifies() {
    let (env, v, key) = setup();
    let payload = [0x42; 32];
    let sig = sig_data(&env, &key.assert(&payload));
    assert!(v.verify(
        &Bytes::from_array(&env, &payload),
        &Bytes::from_slice(&env, &key.key_data()),
        &sig,
    ));
}

#[test]
fn an_assertion_over_another_payload_is_refused() {
    let (env, v, key) = setup();
    let sig = sig_data(&env, &key.assert(&[0x42; 32]));
    let refused = v.try_verify(
        &Bytes::from_array(&env, &[0x43; 32]),
        &Bytes::from_slice(&env, &key.key_data()),
        &sig,
    );
    assert!(!matches!(refused, Ok(Ok(true))));
}

#[test]
fn another_keys_assertion_is_refused() {
    let (env, v, key) = setup();
    let other = SoftPasskey::from_seed([8; 32]);
    let payload = [0x42; 32];
    let sig = sig_data(&env, &other.assert(&payload));
    let refused = v.try_verify(
        &Bytes::from_array(&env, &payload),
        &Bytes::from_slice(&env, &key.key_data()),
        &sig,
    );
    assert!(!matches!(refused, Ok(Ok(true))));
}

#[test]
fn an_assertion_without_user_verification_is_refused() {
    let (env, v, key) = setup();
    let payload = [0x42; 32];
    let sig = sig_data(&env, &key.assert_with_flags(&payload, FLAGS_UP_UV & !0x04));
    let refused = v.try_verify(
        &Bytes::from_array(&env, &payload),
        &Bytes::from_slice(&env, &key.key_data()),
        &sig,
    );
    assert!(!matches!(refused, Ok(Ok(true))));
}

#[test]
fn canonical_keys_drop_the_credential_id() {
    let (env, v, key) = setup();
    let canonical = Bytes::from_slice(&env, &key.public_key());
    assert_eq!(
        v.canonicalize_key(&Bytes::from_slice(&env, &key.key_data())),
        canonical
    );
    let batch = v.batch_canonicalize_key(&Vec::from_array(
        &env,
        [
            Bytes::from_slice(&env, &key.key_data()),
            Bytes::from_slice(&env, &key.public_key()),
        ],
    ));
    assert_eq!(batch, Vec::from_array(&env, [canonical.clone(), canonical]));
}
