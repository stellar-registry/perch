//! Known-answer vectors for the verifier.
//!
//! - NIST's ACVP ML-DSA sigVer vectors for ML-DSA-65 through the pure
//!   external interface (`ML-DSA.Verify` with a context string), the check
//!   the contract runs, through [`verify_signature`]: valid signatures, and
//!   ones with a modified message, commitment hash, response, or hint.
//! - Keys and signatures made by `@noble/post-quantum`, the signer Nido's SDK
//!   uses, through the contract: the off-chain signer and this verifier agree
//!   on the key, its commitment, the context, and the signature.
//!
//! `tests/vectors/*.json` record where each set comes from.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes};
use perch_mldsa_verifier::{
    key_commitment, verify_signature, MlDsaSigData, PerchMlDsaVerifier, PerchMlDsaVerifierClient,
    PUBLIC_KEY_LEN, SIGNATURE_LEN, SIG_CONTEXT,
};
use serde_json::Value;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Bytes, BytesN, Env};

fn vectors(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn array<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().unwrap()
}

#[test]
fn nist_acvp_ml_dsa_65_sigver() {
    let set = vectors("acvp-sigver-ml-dsa-65.json");
    let tests = set["tests"].as_array().unwrap();
    assert_eq!(tests.len(), 15);
    let mut reasons = std::collections::BTreeSet::new();
    for t in tests {
        let expected = t["testPassed"].as_bool().unwrap();
        let verified = verify_signature(
            &array::<PUBLIC_KEY_LEN>(&t["pk"]),
            &bytes(&t["message"]),
            &bytes(&t["context"]),
            &array::<SIGNATURE_LEN>(&t["signature"]),
        );
        assert_eq!(verified, expected, "tcId {} ({})", t["tcId"], t["reason"]);
        reasons.insert((expected, t["reason"].as_str().unwrap().to_owned()));
    }
    // Every kind of case the set holds was checked: valid signatures and
    // each kind of modification.
    assert_eq!(
        reasons.into_iter().collect::<Vec<_>>(),
        [
            (false, "modified message".to_owned()),
            (false, "modified signature - commitment".to_owned()),
            (false, "modified signature - hint".to_owned()),
            (false, "modified signature - z".to_owned()),
            (
                true,
                "valid signature and message - signature should verify successfully".to_owned()
            ),
        ]
    );
}

#[test]
fn noble_signatures_verify_through_the_contract() {
    let set = vectors("noble-ml-dsa-65.json");
    assert_eq!(set["context"].as_str().unwrap().as_bytes(), SIG_CONTEXT);
    let env = Env::default();
    let id = env.register(PerchMlDsaVerifier, ());
    let verifier = PerchMlDsaVerifierClient::new(&env, &id);
    for v in set["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let public_key = bytes(&v["public_key"]);

        // The same seed gives the same key in both implementations, so a
        // seed backed up from Nido signs here too.
        let (pk, _) = ml_dsa_65::KG::keygen_from_seed(&array::<32>(&v["seed"]));
        assert_eq!(pk.into_bytes().to_vec(), public_key, "{name}: keygen");

        let commitment = key_commitment(&env, &Bytes::from_slice(&env, &public_key));
        let recorded: BytesN<32> = BytesN::from_array(&env, &array::<32>(&v["key_commitment"]));
        assert_eq!(commitment, recorded, "{name}: commitment");

        let mut message = array::<32>(&v["message"]);
        let sig_data = MlDsaSigData {
            public_key: Bytes::from_slice(&env, &public_key),
            signature: Bytes::from_slice(&env, &bytes(&v["signature"])),
        }
        .to_xdr(&env);
        assert!(
            verifier.verify(&Bytes::from_array(&env, &message), &commitment, &sig_data),
            "{name}: verifies"
        );
        message[0] ^= 1;
        assert!(
            !verifier.verify(&Bytes::from_array(&env, &message), &commitment, &sig_data),
            "{name}: another message"
        );
    }
}
