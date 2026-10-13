//! Criterion 1 + the constraint source-of-truth: every limit the schema
//! encodes is checked against its single declared source, in both directions.
//! If a limit tightens or loosens without the schema moving with it, one of
//! these assertions fails — "a test that fails when the validator constants and
//! the schema disagree".
//!
//! Two source boundaries:
//!
//! - **perch-ir's `validate`** (format/range/collection rules). Checked
//!   behaviourally via `agree`: perch-ir's `from_json` + `validate` and the
//!   schema accept/reject the same documents. This covers `m <= N`, guardian
//!   `quorum <= count`, the `limit` positivity/overflow shape, and the hex
//!   shapes (the brief's motivating example: a string-length rule in
//!   `validate.rs`).
//! - **the compiler's per-document caps** (`perch_doc_compiler`'s
//!   `MAX_DOC_SIGNERS` / `MAX_DOC_RULES` / `MAX_RULE_NAME_BYTES`). These are the
//!   compiler's, not perch-ir's, so they are checked by *constant equality*: the
//!   generator reads the constant and the committed schema's keyword must equal
//!   it. Over/under-cap behaviour (where perch-ir's validator still accepts) is
//!   proved in `conformance.rs`.

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
fn aggregate_caps_track_the_compiler_constants() {
    // The compiler owns the per-document caps; the generator reads its
    // constants, so the committed schema's keywords must equal them. A drift in
    // either direction (the constant moves, or someone hand-edits the schema)
    // fails here. This is the "constant" half of the source-of-truth guarantee
    // for caps perch-ir's validator does not itself enforce.
    let schema = perch_schema::policy_schema();

    assert_eq!(
        schema["properties"]["signers"]["maxItems"],
        json!(perch_doc_compiler::MAX_DOC_SIGNERS),
        "signers maxItems tracks MAX_DOC_SIGNERS",
    );
    assert_eq!(
        schema["properties"]["rules"]["maxItems"],
        json!(perch_doc_compiler::MAX_DOC_RULES),
        "rules maxItems tracks MAX_DOC_RULES",
    );
    assert_eq!(
        schema["$defs"]["rule"]["properties"]["name"]["maxLength"],
        json!(perch_doc_compiler::MAX_RULE_NAME_BYTES),
        "rule name maxLength tracks MAX_RULE_NAME_BYTES",
    );
    // The ASCII pattern is what makes that maxLength a byte cap (one char = one
    // byte); pin it so the two cannot drift apart.
    assert_eq!(
        schema["$defs"]["rule"]["properties"]["name"]["pattern"],
        json!(perch_schema::RULE_NAME_PATTERN),
        "rule name pattern is the ASCII class",
    );
}

#[test]
fn threshold_m_upper_bound_matches_the_validator() {
    let v = validator();
    // Two declared signers so N can be 2. m in 1..=N accepted by both; m > N
    // rejected by both (schema's if/then chain, validator's InvalidThreshold).
    let doc = |m: u64| {
        json!({
            "version": 1,
            "signers": [
                { "id": "a", "verifier": VALID_C, "key": "ab" },
                { "id": "b", "verifier": "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG", "key": "cd" },
            ],
            "rules": [{
                "name": "r",
                "scope": { "type": "self-admin" },
                "principals": { "type": "threshold", "signers": ["a", "b"], "m": m },
            }],
        })
    };
    agree(&v, &doc(1), true, "threshold-m1-of-2");
    agree(&v, &doc(2), true, "threshold-m2-of-2");
    agree(&v, &doc(3), false, "threshold-m3-of-2");
}

#[test]
fn guardian_quorum_upper_bound_matches_the_validator() {
    let v = validator();
    // Two guardians so the count is 2. quorum in 1..=2 accepted by both;
    // quorum > 2 rejected by both (schema's recoveryMode if/then chain,
    // validator's InvalidGuardianQuorum).
    let doc = |quorum: u64| {
        json!({
            "version": 1,
            "signers": [{ "id": "admin", "verifier": VALID_C, "key": "ab" }],
            "rules": [{ "name": "r", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["admin"] } }],
            "recovery": {
                "profile": "loss",
                "mode": {
                    "type": "guardian-only",
                    // Two distinct, valid-shape addresses (a guardian may be a
                    // C- or G-address); neither is the controller below.
                    "guardians": [VALID_G, VALID_C],
                    "quorum": quorum,
                },
                "controller": "CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF",
                "replaceable": ["admin"],
                "delay-ledgers": 100,
                "expiry-ledgers": 1000,
                "max-cancels": 3,
            },
        })
    };
    agree(&v, &doc(1), true, "quorum-1-of-2");
    agree(&v, &doc(2), true, "quorum-2-of-2");
    agree(&v, &doc(3), false, "quorum-3-of-2");
}

#[test]
fn cap_limit_pattern_matches_the_validator() {
    // The generator's pattern is the one the schema ships.
    let expected = perch_schema::limit_pattern();
    let schema = perch_schema::policy_schema();
    assert_eq!(
        schema["$defs"]["capConstraint"]["properties"]["limit"]["pattern"],
        json!(expected),
        "schema limit pattern is the generator's",
    );

    // Behavioural, at perch-ir's `parse::<i128>()` + positivity boundary.
    let v = validator();
    let doc = |limit: &str| {
        json!({
            "version": 1,
            "signers": [{ "id": "a", "verifier": VALID_C, "key": "ab" }],
            "rules": [{
                "name": "r",
                "scope": { "type": "contract", "address": "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL" },
                "principals": { "type": "all", "signers": ["a"] },
                "cap": { "limit": limit, "period-ledgers": 10 },
            }],
        })
    };
    // Positive values, including the non-canonical spellings the parser accepts
    // today (leading zeros, leading plus) — both accept (CANON v2 would reject
    // the spellings; this schema does not).
    agree(&v, &doc("5"), true, "limit-5");
    agree(&v, &doc("007"), true, "limit-leading-zeros");
    agree(&v, &doc("+5"), true, "limit-leading-plus");
    // Not positive, or not an i128-width integer — both reject.
    agree(&v, &doc("0"), false, "limit-zero");
    agree(&v, &doc("-5"), false, "limit-negative");
    agree(&v, &doc("abc"), false, "limit-non-numeric");
    agree(
        &v,
        &doc("123456789012345678901234567890123456789012345"),
        false,
        "limit-overflow",
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
