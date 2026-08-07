//! Canonicalization goldens: identical canonical bytes and hashes regardless
//! of construction path, exact golden strings/hashes pinned as literals, and
//! round-trip fixed points.

mod common;

use common::{
    base_doc, rule, signer, ADMIN_KEY_HEX, CI_KEY_HEX, ED25519_VERIFIER, REGISTRY,
    WEBAUTHN_VERIFIER,
};
use perch_ir::{
    canonical_json, doc_hash, doc_hash_hex, from_json, ArgConstraint, ArgPred, PolicyDoc, Scope,
};

/// Golden doc used by the byte-level tests below: two signers, two rules,
/// exercising functions/args/not-after.
fn golden_doc() -> PolicyDoc {
    let mut doc = base_doc();
    doc.network = Some("testnet".into());
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    let mut publish = rule("publish", Scope::contract(REGISTRY), &["ci"]);
    publish.functions = Some(vec!["publish".into(), "publish_hash".into()]);
    publish.args = Some(vec![ArgConstraint {
        index: 1,
        pred: ArgPred::is_self(),
    }]);
    publish.not_after = Some(1_893_456_000);
    doc.rules.push(publish);
    doc
}

/// The same document as [`golden_doc`], written as JSON with shuffled key
/// order and gratuitous whitespace.
fn golden_doc_shuffled_json() -> String {
    format!(
        r#"{{
        "rules": [
            {{ "principals": {{ "signers": [ "admin" ], "type": "all" }},
               "scope": {{ "type": "self-admin" }},
               "name": "admin-root" }},
            {{ "not-after": 1893456000,
               "args": [ {{ "pred": {{ "type": "is-self" }}, "index": 1 }} ],
               "functions": [ "publish", "publish_hash" ],
               "principals": {{ "signers": [ "ci" ], "type": "all" }},
               "scope": {{ "address": "{REGISTRY}", "type": "contract" }},
               "name": "publish" }}
        ],
        "signers": [
            {{ "key": "{ADMIN_KEY_HEX}", "verifier": "{WEBAUTHN_VERIFIER}", "id": "admin" }},
            {{ "verifier": "{ED25519_VERIFIER}", "id": "ci", "key": "{CI_KEY_HEX}" }}
        ],
        "network": "testnet",
        "version": 1
    }}"#
    )
}

/// Pinned SHA-256 (hex) of the golden document's canonical bytes. Computed
/// once from this crate and frozen; a change here is a breaking change to the
/// canonical form and must be deliberate.
const GOLDEN_HASH_HEX: &str = "411952cb9ebf4ca538d4d62228cbddf4c9892fca978a223078ca02f743c9a924";

#[test]
fn struct_literal_and_shuffled_json_canonicalize_identically() {
    let from_struct = golden_doc();
    let from_json_doc = from_json(&golden_doc_shuffled_json()).expect("shuffled JSON must parse");
    assert_eq!(from_struct, from_json_doc);
    assert_eq!(canonical_json(&from_struct), canonical_json(&from_json_doc));
    assert_eq!(doc_hash(&from_struct), doc_hash(&from_json_doc));
}

#[test]
fn golden_hash_is_pinned() {
    assert_eq!(doc_hash_hex(&golden_doc()), GOLDEN_HASH_HEX);
    // doc_hash and doc_hash_hex agree.
    assert_eq!(hex::encode(doc_hash(&golden_doc())), GOLDEN_HASH_HEX);
}

#[test]
fn canonical_form_of_minimal_doc_is_pinned_byte_for_byte() {
    let mut doc = base_doc();
    doc.signers[0].key = "ab".into();
    let expected = format!(
        r#"{{"rules":[{{"name":"admin-root","principals":{{"signers":["admin"],"type":"all"}},"scope":{{"type":"self-admin"}}}}],"signers":[{{"id":"admin","key":"ab","verifier":"{WEBAUTHN_VERIFIER}"}}],"version":1}}"#
    );
    assert_eq!(canonical_json(&doc), expected);
}

#[test]
fn round_trip_is_a_fixed_point() {
    let doc = golden_doc();
    let canon1 = canonical_json(&doc);
    let reparsed = from_json(&canon1).expect("canonical form must parse");
    let canon2 = canonical_json(&reparsed);
    assert_eq!(canon1, canon2);
    assert_eq!(doc, reparsed);
    assert_eq!(doc_hash(&doc), doc_hash(&reparsed));
}

#[test]
fn absent_options_are_omitted_not_null() {
    let doc = base_doc(); // network/functions/args/not_after all None
    let canon = canonical_json(&doc);
    assert!(!canon.contains("null"), "{canon}");
    assert!(!canon.contains("network"), "{canon}");
    assert!(!canon.contains("not-after"), "{canon}");
}

#[test]
fn u32_extremes_serialize_as_plain_decimal() {
    let mut doc = golden_doc();
    doc.rules[1].not_after = Some(u32::MAX);
    let canon = canonical_json(&doc);
    // Plain decimal digits: no exponent, no decimal point, no sign.
    assert!(canon.contains("\"not-after\":4294967295"), "{canon}");
    doc.rules[1].args = Some(vec![ArgConstraint {
        index: 0,
        pred: ArgPred::U32Eq(perch_ir::U32EqPred { value: 0 }),
    }]);
    let canon = canonical_json(&doc);
    assert!(canon.contains("\"value\":0"), "{canon}");
}

#[test]
fn network_strings_are_jcs_escaped() {
    let mut doc = base_doc();
    doc.network = Some("Test \"SDF\" Network \\ 2015\n".into());
    let canon = canonical_json(&doc);
    assert!(
        canon.contains(r#""network":"Test \"SDF\" Network \\ 2015\n""#),
        "{canon}"
    );
    // Round-trips through parsing to the same bytes.
    let reparsed = from_json(&canon).expect("must parse");
    assert_eq!(canonical_json(&reparsed), canon);
}
