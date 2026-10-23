//! The fragment hashes (`CANONICAL.md`, "Fragment hashes") as the deployed
//! code computes them: the per-rule hash the compiler stamps into every
//! interpreter program, and the doc compiler's `config_hash`. Both are
//! checked against values computed independently of this code, and the
//! perch-js suite pins the same values.

use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_recovery_interface::{config, fragment};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, FromVal, Val, Vec};
use std::path::PathBuf;

fn testdata(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    std::fs::read_to_string(p).unwrap()
}

fn hex32(e: &Env, h: &str) -> BytesN<32> {
    BytesN::from_array(e, &hex::decode(h).unwrap().try_into().unwrap())
}

#[test]
fn one_rule_hash_definition() {
    assert_eq!(perch_ir::RULE_HASH_DOMAIN.as_bytes(), fragment::RULE_DOMAIN);
}

/// `testdata/rule-hashes.json` is cut out of the canonical fixtures by
/// `scripts/rule-hash-vectors.py`, independently of any Rust code.
#[test]
fn every_installed_programs_provenance_matches_the_vectors() {
    let e = Env::default();
    let v: serde_json::Value = serde_json::from_str(&testdata("rule-hashes.json")).unwrap();
    for f in v["fixtures"].as_array().unwrap() {
        let name = f["fixture"]
            .as_str()
            .unwrap()
            .trim_start_matches("testdata/")
            .replace(".canonical.json", ".json");
        let doc = perch_ir::from_json(&testdata(&name)).unwrap();
        for (rule, want) in doc.rules.iter().zip(f["rules"].as_array().unwrap()) {
            let want = hex32(&e, want["rule_hash"].as_str().unwrap());
            let canonical = Bytes::from_slice(&e, perch_ir::rule_canonical_json(rule).as_bytes());
            assert_eq!(fragment::rule_hash(&e, &canonical), want, "{name}");
            assert_eq!(perch_compile::rule_hash_onchain(&e, rule), want, "{name}");
        }
    }
}

/// A verifier whose canonical key is the key itself, standing in for the
/// fixtures' verifiers so the doc compiler can fingerprint their signers.
#[contract]
struct IdentityVerifier;

#[contractimpl]
impl IdentityVerifier {
    pub fn batch_canonicalize_key(e: Env, key_data: Vec<Val>) -> Vec<Bytes> {
        let mut out = Vec::new(&e);
        for k in key_data.iter() {
            out.push_back(Bytes::from_val(&e, &k));
        }
        out
    }
}

/// Pinned from an independent cut of each fixture's canonical `recovery`
/// member: `sha256("perch/recovery/config" || bytes)`. perch-js's
/// `configHash` is pinned to the same values (`test/fragment.test.ts`).
#[test]
fn the_doc_compilers_config_hash_matches_the_pinned_values() {
    let e = Env::default();
    let network = e
        .crypto()
        .sha256(&Bytes::from_slice(&e, b"Test SDF Network ; September 2015"))
        .to_array();
    e.ledger().with_mut(|l| l.network_id = network);
    let compiler = PerchDocCompilerClient::new(&e, &e.register(PerchDocCompiler, ()));
    for (fixture, want) in [
        (
            "ci-publish-recovery.json",
            "82157c6fc97d9dbf5216417cae232e2301a78e3c373580c70013586b4c342d14",
        ),
        (
            "ci-publish-recovery-combined.json",
            "6f44a3313c66ff6bab1719f684e4f58b04b10ec930624f8a6432ba761cd1ae78",
        ),
    ] {
        let json = testdata(fixture);
        let doc = perch_ir::from_json(&json).unwrap();
        for signer in &doc.signers {
            if let perch_ir::SignerMethod::External { verifier, .. } = &signer.method {
                e.register_at(&Address::from_str(&e, verifier), IdentityVerifier, ());
            }
        }
        let compiled = compiler.compile_doc(&Bytes::from_slice(&e, json.as_bytes()));
        let got = compiled.recovery.get(0).unwrap().config_hash;
        assert_eq!(got, hex32(&e, want), "{fixture}");
        let member = perch_ir::recovery_canonical_json(doc.recovery.as_ref().unwrap());
        assert_eq!(
            config::config_hash(&e, &Bytes::from_slice(&e, member.as_bytes())),
            got
        );
    }
}
