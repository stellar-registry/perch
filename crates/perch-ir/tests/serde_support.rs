//! `PolicyDoc` keeps its serde `Serialize`/`Deserialize` derives for off-chain
//! interop, even though the on-chain parse/canonicalize path is hand-written and
//! serde-free (serde_json's float lexer cannot ride the Soroban VM — see
//! `perch-ir/src/parse.rs`). These tests pin that the serde route still works:
//! a document round-trips through `serde_json`, and the derived deserializer
//! still enforces the same fail-closed rules (`deny_unknown_fields`).

mod common;

use common::{ADMIN_KEY_HEX, WEBAUTHN_VERIFIER};

/// A representative document as (kebab-case) JSON.
fn doc_json() -> String {
    format!(
        r#"{{"version":1,"network":"testnet","signers":[{{"id":"admin","verifier":"{WEBAUTHN_VERIFIER}","key":"{ADMIN_KEY_HEX}"}}],"rules":[{{"name":"r","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}}]}}"#
    )
}

#[test]
fn policydoc_round_trips_through_serde_json() {
    // Deserialize via the serde derive, re-serialize, deserialize again: the two
    // documents must be equal — proving the derives are intact and usable.
    let doc: perch_ir::PolicyDoc = serde_json::from_str(&doc_json()).expect("serde parse");
    let reserialized = serde_json::to_string(&doc).expect("serde serialize");
    let doc2: perch_ir::PolicyDoc = serde_json::from_str(&reserialized).expect("serde reparse");
    assert_eq!(doc, doc2);

    // And it agrees with the crate's own hand-written parser on the same input.
    let via_from_json = perch_ir::from_json(&doc_json()).expect("from_json parse");
    assert_eq!(doc, via_from_json);
}

#[test]
fn serde_derive_still_denies_unknown_fields() {
    // The `deny_unknown_fields` attribute must still bite through the serde
    // route, independent of the hand-written parser.
    let bad = doc_json().replace(r#""network":"testnet""#, r#""network":"testnet","extra":1"#);
    let err = serde_json::from_str::<perch_ir::PolicyDoc>(&bad).expect_err("must reject");
    assert!(err.to_string().contains("extra"), "{err}");
}
