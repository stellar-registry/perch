//! Criterion 1 + the constraint source-of-truth: every limit the schema
//! encodes is checked against perch-ir's own parser + validator, in both
//! directions. If perch-ir tightens or loosens a representable rule (the brief's
//! motivating example: a string-length rule in `validate.rs`) without the schema
//! moving with it, one of these assertions fails — "a test that fails when
//! perch-ir's validator constants and the schema disagree".

mod common;

use common::{ir_outcome_of, schema_accepts, validator};
use jsonschema::Validator;
use serde_json::{json, Value};

const VALID_C: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
const VALID_G: &str = "GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH";

/// Assert the schema and perch-ir agree (accept together, reject together) on a
/// document. `expect_accept` is what both should do.
fn agree(v: &Validator, doc: &Value, expect_accept: bool, label: &str) {
    let schema_ok = schema_accepts(v, doc);
    let ir_ok = ir_outcome_of(doc).accepted;
    assert_eq!(
        schema_ok, expect_accept,
        "[{label}] schema accept={schema_ok}, expected {expect_accept}",
    );
    assert_eq!(
        ir_ok, expect_accept,
        "[{label}] perch-ir accept={ir_ok}, expected {expect_accept}",
    );
}

#[test]
fn signer_key_pattern_is_built_from_the_perch_ir_constant() {
    // Direct binding: the one perch-ir constant drives the schema's key length.
    let expected = format!("^([0-9a-fA-F]{{2}}){{1,{}}}$", perch_ir::MAX_SIGNER_KEY_LEN);
    assert_eq!(perch_schema::signer_key_pattern(), expected);
    let schema = perch_schema::policy_schema();
    let key_pattern = schema["$defs"]["signerDecl"]["oneOf"][0]["properties"]["key"]["pattern"]
        .as_str()
        .expect("the external signer's key carries a pattern");
    assert_eq!(
        key_pattern, expected,
        "schema key pattern tracks MAX_SIGNER_KEY_LEN"
    );
}

#[test]
fn ack_sentinel_const_is_the_perch_ir_sentinel() {
    let schema = perch_schema::policy_schema();
    let ack = &schema["$defs"]["principals"]["oneOf"][2]["properties"]["ack"]["const"];
    assert_eq!(
        ack,
        &json!(perch_ir::ACK_SENTINEL),
        "schema ack const is perch-ir's sentinel"
    );

    // Behavioural: wrong ack rejected by both, exact ack accepted by both.
    let v = validator();
    let make = |ack: &str| {
        json!({
            "version": 1,
            "signers": [],
            "rules": [{
                "name": "open",
                "scope": { "type": "self-admin" },
                "principals": {
                    "type": "self-authenticating",
                    "policy": VALID_C,
                    "install-param-hex": "",
                    "ack": ack,
                },
            }],
        })
    };
    agree(&v, &make(perch_ir::ACK_SENTINEL), true, "ack-exact");
    agree(&v, &make("i-acknowledge"), false, "ack-wrong");
}

#[test]
fn contract_strkey_shape_matches_is_contract_address_shape() {
    let v = validator();
    let doc = |verifier: &str| {
        json!({
            "version": 1,
            "signers": [{ "id": "a", "verifier": verifier, "key": "ab" }],
            "rules": [{ "name": "r", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["a"] } }],
        })
    };
    // Each candidate: the schema (verifier pattern) and perch-ir
    // (is_contract_address_shape, surfaced via InvalidVerifierAddress) must land
    // the same way.
    for s in [
        VALID_C,                       // valid 56-char C
        &VALID_C[..55],                // 55: too short
        &format!("{VALID_C}A"),        // 57: too long
        VALID_G,                       // G-prefix: not a contract
        &VALID_C.to_ascii_lowercase(), // lowercase: not base32
        "CSHORT",                      // obviously malformed
    ] {
        let expect = perch_ir::is_contract_address_shape(s);
        agree(&v, &doc(s), expect, &format!("contract-strkey:{s}"));
    }
}

#[test]
fn address_strkey_shape_matches_is_address_shape() {
    let v = validator();
    let doc = |address: &str| {
        json!({
            "version": 1,
            "signers": [{ "id": "a", "address": address }],
            "rules": [{ "name": "r", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["a"] } }],
        })
    };
    for s in [
        VALID_C,
        VALID_G,
        &VALID_C[..55],
        &format!("{VALID_G}A"),
        &VALID_G.to_ascii_lowercase(),
    ] {
        let expect = perch_ir::is_address_shape(s);
        agree(&v, &doc(s), expect, &format!("address-strkey:{s}"));
    }
}

/// A recovery document whose zk-only commitment is `commitment`; everything
/// else is a known-valid canonical value.
fn recovery_doc_with_commitment(commitment: &str) -> Value {
    json!({
        "version": 1,
        "signers": [{ "id": "admin", "verifier": VALID_C, "key": "ab" }],
        "rules": [{ "name": "r", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["admin"] } }],
        "recovery": {
            "profile": "loss",
            "mode": {
                "type": "zk-only",
                "adapter": "CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ",
                "circuit-id": "21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb",
                "pool": "CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5",
                "enrollment-id": "6f0d1c2b3a49586776859483a2b1c0dfeefdfcfbfaf9f8f7f6f5f4f3f2f1f0e1",
                "commitment": commitment,
            },
            "controller": "CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF",
            "replaceable": ["admin"],
            "delay-ledgers": 100,
            "expiry-ledgers": 1000,
            "max-cancels": 3,
        },
    })
}

#[test]
fn sha256_hex_shape_matches_the_validator() {
    let v = validator();
    // A canonical 64-lowercase-hex commitment (well below the BN254 modulus):
    // both accept.
    let canonical = "0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff0";
    agree(
        &v,
        &recovery_doc_with_commitment(canonical),
        true,
        "commitment-64-hex",
    );
    // 63 chars: both reject (schema pattern, validator length).
    agree(
        &v,
        &recovery_doc_with_commitment(&canonical[..63]),
        false,
        "commitment-63-hex",
    );
    // 65 chars: both reject.
    agree(
        &v,
        &recovery_doc_with_commitment(&format!("{canonical}a")),
        false,
        "commitment-65-hex",
    );
    // Uppercase hex: both reject (is_sha256_hex requires lowercase; schema
    // pattern is [0-9a-f]).
    agree(
        &v,
        &recovery_doc_with_commitment(&canonical.to_ascii_uppercase()),
        false,
        "commitment-uppercase",
    );
}

#[test]
fn non_zero_u32_minimum_matches_the_validator() {
    let v = validator();
    let doc = |n: u64| {
        json!({
            "version": 1,
            "signers": [{ "id": "a", "verifier": VALID_C, "key": "ab" }],
            "rules": [{
                "name": "r",
                "scope": { "type": "self-admin" },
                "principals": { "type": "all", "signers": ["a"] },
                "not-after-ledger": n,
            }],
        })
    };
    // 0 is refused by both (schema minimum 1, validator ZeroNotAfterLedger);
    // 1 is accepted by both.
    agree(&v, &doc(0), false, "not-after-ledger-0");
    agree(&v, &doc(1), true, "not-after-ledger-1");
}
