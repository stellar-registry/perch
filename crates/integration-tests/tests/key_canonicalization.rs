//! External signer keys must be canonical at the point a document is
//! compiled. A verifier's `canonicalize_key` can map several raw byte strings
//! to one physical key — the WebAuthn verifier, for instance, keeps only the
//! first 65 bytes and drops any credential-id suffix a wallet appended. The
//! compiler fingerprints (and OZ deduplicates) the *canonical* key, but the
//! document — its `doc_hash`, and a recovery attempt's `replacements_hash` —
//! binds the *declared* bytes. So a non-canonical spelling lets a signer carry
//! suffix bytes that change the document's identity while changing nothing
//! about the installed credential: the bytes are bound but otherwise ignored,
//! and two "distinct" signers can resolve to one physical key.
//!
//! CANON refuses non-canonical input rather than silently repairing it, so the
//! compiler must reject a key that is not already its verifier-canonical form.

use perch_doc_compiler::{DocCompilerError, PerchDocCompiler, PerchDocCompilerClient};
use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet};
use perch_recovery_interface::RecoveryAction;
use perch_testkit::passkey::SoftPasskey;
use perch_testkit::FIXTURE_NETWORK;
use perch_webauthn_verifier::PerchWebAuthnVerifier;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, Bytes, Env, String as SString, Vec};

/// A minimal admin-only document whose sole signer is a WebAuthn `External`
/// signer on `verifier`, carrying `key` (hex).
fn admin_doc(verifier: &str, key_hex: &str) -> String {
    format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "{verifier}", "key": "{key_hex}" }}
  ],
  "rules": [
    {{ "name": "admin",
      "scope": {{ "type": "self-admin" }},
      "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ]
}}"#
    )
}

struct Fixture {
    env: Env,
    compiler: Address,
    verifier: Address,
    verifier_strkey: String,
    passkey: SoftPasskey,
}

fn setup() -> Fixture {
    let env = Env::default();
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);

    let verifier = env.register(PerchWebAuthnVerifier, ());
    let compiler = env.register(PerchDocCompiler, ());

    let verifier_strkey = {
        let s = verifier.to_string();
        let mut buf = std::vec![0u8; s.len() as usize];
        s.copy_into_slice(&mut buf);
        String::from_utf8(buf).unwrap()
    };

    Fixture {
        env,
        compiler,
        verifier,
        verifier_strkey,
        passkey: SoftPasskey::from_seed([3u8; 32]),
    }
}

#[test]
fn canonical_webauthn_key_compiles() {
    let f = setup();
    // The bare 65-byte public key is already canonical.
    let key_hex = hex::encode(f.passkey.public_key());
    let doc = admin_doc(&f.verifier_strkey, &key_hex);
    let client = PerchDocCompilerClient::new(&f.env, &f.compiler);
    let res = client.try_compile_doc(&Bytes::from_slice(&f.env, doc.as_bytes()));
    assert!(res.is_ok(), "a canonical key must compile: {res:?}");
}

#[test]
fn non_canonical_webauthn_key_is_refused() {
    let f = setup();
    // The public key followed by the credential-id suffix, as a browser wallet
    // stores it: the verifier canonicalizes the suffix away, so these bytes are
    // bound into the document yet ignored by the installed credential.
    let non_canonical = f.passkey.key_data();
    assert!(
        non_canonical.len() > 65,
        "key_data carries a credential-id suffix"
    );
    let key_hex = hex::encode(&non_canonical);
    let doc = admin_doc(&f.verifier_strkey, &key_hex);
    let client = PerchDocCompilerClient::new(&f.env, &f.compiler);
    let res = client.try_compile_doc(&Bytes::from_slice(&f.env, doc.as_bytes()));
    assert_eq!(
        res,
        Err(Ok(DocCompilerError::KeyNotCanonicalizable)),
        "a non-canonical key must be refused, not silently canonicalized"
    );
}

/// A guardian-only loss recovery document whose replaceable "owner" signer is a
/// canonical WebAuthn `External` signer.
fn recovery_doc(verifier: &str, key_hex: &str, controller: &str, guardian: &str) -> String {
    format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "owner", "verifier": "{verifier}", "key": "{key_hex}" }}
  ],
  "rules": [
    {{ "name": "admin",
      "scope": {{ "type": "self-admin" }},
      "principals": {{ "type": "all", "signers": ["owner"] }} }}
  ],
  "recovery": {{
    "profile": "loss",
    "mode": {{ "type": "guardian-only", "guardians": ["{guardian}"], "quorum": 1 }},
    "controller": "{controller}",
    "replaceable": ["owner"],
    "delay-ledgers": 10,
    "expiry-ledgers": 100,
    "max-cancels": 1
  }}
}}"#
    )
}

#[test]
fn recovery_refuses_a_non_canonical_replacement_key() {
    let f = setup();
    let controller = Address::generate(&f.env);
    let guardian = Address::generate(&f.env);
    let strkey = |a: &Address| {
        let s = a.to_string();
        let mut buf = std::vec![0u8; s.len() as usize];
        s.copy_into_slice(&mut buf);
        String::from_utf8(buf).unwrap()
    };

    // Source and current document: the replaceable "owner" is a canonical key.
    let source = recovery_doc(
        &f.verifier_strkey,
        &hex::encode(f.passkey.public_key()),
        &strkey(&controller),
        &strkey(&guardian),
    );
    let source_bytes = Bytes::from_slice(&f.env, source.as_bytes());

    // The replacement a lost-key attempt declares for "owner": the same
    // verifier and kind (so the replacement is otherwise accepted), but a
    // non-canonical key carrying a credential-id suffix — the bytes
    // `replacements_hash` would bind yet the installed credential drops.
    let new_key = SoftPasskey::from_seed([5u8; 32]);
    let non_canonical = new_key.key_data();
    assert!(non_canonical.len() > 65);
    let replacements = ReplacementSet {
        signers: vec![
            &f.env,
            Replacement {
                signer_id: SString::from_str(&f.env, "owner"),
                credential: Credential::External(
                    f.verifier.clone(),
                    Bytes::from_slice(&f.env, &non_canonical),
                ),
            },
        ],
        zk_enrollment: Vec::new(&f.env),
    };

    let client = PerchDocCompilerClient::new(&f.env, &f.compiler);
    let res = client.try_derive_target(
        &source_bytes,
        &source_bytes,
        &RecoveryAction::LostKey,
        &replacements,
    );
    assert_eq!(
        res,
        Err(Ok(DocCompilerError::KeyNotCanonicalizable)),
        "derive_target must refuse a non-canonical replacement key"
    );
}
