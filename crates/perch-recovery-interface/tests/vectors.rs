//! Cross-implementation vectors: `testdata/recovery/statement-v2.json` is
//! written by `scripts/recovery-statement-vectors.py`, an independent
//! standard-library implementation of `docs/recovery/statement.md`. Every
//! vector must match this crate byte for byte. Other implementations
//! (perch-js, the Noir witness generator, Nido's SDK) assert the same file.

use perch_recovery_interface::credential::{Credential, Replacement, ReplacementSet};
use perch_recovery_interface::zk::{
    zk_statement_fields, DOM_AUTH, DOM_BIND, DOM_LEAF, DOM_NULLIFIER,
};
use perch_recovery_interface::{
    AttemptSubject, CancelSubject, ConfigBinding, ConfigChange, RecoveryStatement,
    StatementSubject, StatementTiming, UpgradeSubject,
};
use serde_json::Value;
use soroban_sdk::{Address, Bytes, BytesN, Env, String, Vec};

const VECTORS: &str = include_str!("../../../testdata/recovery/statement-v2.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn h32(e: &Env, v: &Value) -> BytesN<32> {
    let raw = hex::decode(v.as_str().unwrap()).unwrap();
    BytesN::from_array(e, &raw.try_into().unwrap())
}

fn addr(e: &Env, v: &Value) -> Address {
    Address::from_str(e, v.as_str().unwrap())
}

fn bytes_hex(b: &Bytes) -> std::string::String {
    let mut buf = std::vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut buf);
    hex::encode(buf)
}

fn credential(e: &Env, v: &Value) -> Credential {
    match v["kind"].as_str().unwrap() {
        "delegated" => Credential::Delegated(addr(e, &v["address"])),
        "external" => Credential::External(
            addr(e, &v["verifier"]),
            Bytes::from_slice(e, &hex::decode(v["key"].as_str().unwrap()).unwrap()),
        ),
        k => panic!("unknown credential kind {k}"),
    }
}

fn statement(e: &Env, v: &Value) -> RecoveryStatement {
    let s = &v["subject"];
    let subject = match v["action"].as_str().unwrap() {
        a @ ("lost-key" | "compromise") => {
            let sub = AttemptSubject {
                attempt_id: s["attempt_id"].as_u64().unwrap(),
                source_doc_hash: h32(e, &s["source_doc_hash"]),
                target_doc_hash: h32(e, &s["target_doc_hash"]),
                replacements_hash: h32(e, &s["replacements_hash"]),
            };
            if a == "lost-key" {
                StatementSubject::LostKey(sub)
            } else {
                StatementSubject::Compromise(sub)
            }
        }
        "cancel" => StatementSubject::Cancel(CancelSubject {
            attempt_id: s["attempt_id"].as_u64().unwrap(),
            attempt_statement: h32(e, &s["attempt_statement"]),
        }),
        "reconfigure" => StatementSubject::Reconfigure(match s["change"].as_str().unwrap() {
            "remove" => ConfigChange::Remove,
            _ => ConfigChange::Set(h32(e, &s["new_config_hash"])),
        }),
        "upgrade" => StatementSubject::Upgrade(UpgradeSubject {
            request_id: s["request_id"].as_u64().unwrap(),
            wasm_hash: h32(e, &s["wasm_hash"]),
        }),
        a => panic!("unknown action {a}"),
    };
    RecoveryStatement {
        network_id: h32(e, &v["network_id"]),
        account: addr(e, &v["account"]),
        controller: addr(e, &v["controller"]),
        config: ConfigBinding {
            epoch: v["config_epoch"].as_u64().unwrap(),
            config_hash: h32(e, &v["config_hash"]),
        },
        timing: StatementTiming {
            delay_ledgers: v["delay_ledgers"].as_u64().unwrap() as u32,
            expiry_ledgers: v["expiry_ledgers"].as_u64().unwrap() as u32,
            valid_until_ledger: v["valid_until_ledger"].as_u64().unwrap() as u32,
        },
        subject,
    }
}

#[test]
fn network_id_vector_is_the_testnet_passphrase_hash() {
    let e = Env::default();
    let v = vectors();
    let expected = e
        .crypto()
        .sha256(&Bytes::from_slice(
            &e,
            v["network"].as_str().unwrap().as_bytes(),
        ))
        .to_bytes();
    for s in v["statements"].as_array().unwrap() {
        assert_eq!(h32(&e, &s["network_id"]), expected);
    }
}

#[test]
fn statement_encodings_and_digests_match() {
    let e = Env::default();
    let v = vectors();
    let statements = v["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 6);
    for sv in statements {
        let name = sv["name"].as_str().unwrap();
        let st = statement(&e, sv);
        assert_eq!(
            bytes_hex(&st.encode(&e).unwrap()),
            sv["encoding"].as_str().unwrap(),
            "{name}: encoding"
        );
        assert_eq!(
            hex::encode(st.digest(&e).unwrap().to_array()),
            sv["digest"].as_str().unwrap(),
            "{name}: digest"
        );
    }
}

#[test]
fn zk_projection_matches() {
    let e = Env::default();
    let v = vectors();
    for sv in v["statements"].as_array().unwrap() {
        let name = sv["name"].as_str().unwrap();
        let z = &sv["zk_fields"];
        let f = zk_statement_fields(&e, &statement(&e, sv), &h32(&e, &z["enrollment_id"])).unwrap();
        for (field, got) in [
            ("account_hi", f.account_hi),
            ("account_lo", f.account_lo),
            ("enrollment_hi", f.enrollment_hi),
            ("enrollment_lo", f.enrollment_lo),
            ("digest_hi", f.digest_hi),
            ("digest_lo", f.digest_lo),
        ] {
            assert_eq!(
                hex::encode(got),
                z[field].as_str().unwrap(),
                "{name}: {field}"
            );
        }
    }
}

#[test]
fn credential_fingerprints_match() {
    let e = Env::default();
    let v = vectors();
    for cv in v["credentials"].as_array().unwrap() {
        let c = credential(&e, cv);
        assert_eq!(
            bytes_hex(&c.encode(&e).unwrap()),
            cv["encoding"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(c.fingerprint(&e).unwrap().to_array()),
            cv["fingerprint"].as_str().unwrap()
        );
    }
}

#[test]
fn replacement_set_hash_matches_and_is_what_attempts_bind() {
    let e = Env::default();
    let v = vectors();
    let rv = &v["replacements"];
    let mut signers = Vec::new(&e);
    for r in rv["signers"].as_array().unwrap() {
        signers.push_back(Replacement {
            signer_id: String::from_str(&e, r["signer_id"].as_str().unwrap()),
            credential: credential(&e, &r["credential"]),
        });
    }
    let set = ReplacementSet {
        signers,
        zk_enrollment: Some(h32(&e, &rv["zk_enrollment"])),
    };
    assert_eq!(
        bytes_hex(&set.encode(&e).unwrap()),
        rv["encoding"].as_str().unwrap()
    );
    let hash = set.hash(&e).unwrap();
    assert_eq!(hex::encode(hash.to_array()), rv["hash"].as_str().unwrap());
    // The attempt vectors bind exactly this replacement set.
    for sv in v["statements"].as_array().unwrap() {
        if let Some(rh) = sv["subject"].get("replacements_hash") {
            assert_eq!(h32(&e, rh), hash);
        }
    }
}

#[test]
fn zk_domain_tags_match() {
    let v = vectors();
    let d = &v["zk_domains"];
    for (name, tag) in [
        ("leaf", DOM_LEAF),
        ("bind", DOM_BIND),
        ("nullifier", DOM_NULLIFIER),
        ("auth", DOM_AUTH),
    ] {
        assert_eq!(
            hex::encode(tag),
            d[name]["value"].as_str().unwrap(),
            "{name}"
        );
    }
}
