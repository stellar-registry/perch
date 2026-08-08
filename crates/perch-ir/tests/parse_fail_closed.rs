//! Fail-closed parsing: unknown fields anywhere in the tree, unknown enum
//! tags, and unsupported versions are all rejected.

mod common;

use common::{ADMIN_KEY_HEX, G_ADDR, POLICY_CONTRACT, REGISTRY, WEBAUTHN_VERIFIER};
use perch_ir::{from_json, ParseError, ACK_SENTINEL};

/// A minimal valid document with one rule, where `{rule_extra}` lets a test
/// splice fields into the rule and `{scope}` / `{principals}` / `{pred}`
/// substitute whole sub-objects.
fn doc(scope: &str, principals: &str, pred: &str) -> String {
    format!(
        r#"{{"version":1,"network":"testnet","signers":[{{"id":"admin","verifier":"{WEBAUTHN_VERIFIER}","key":"{ADMIN_KEY_HEX}"}}],"rules":[{{"name":"r","scope":{scope},"principals":{principals},"functions":["publish"],"args":[{{"index":1,"pred":{pred}}}],"not-after-ledger":999}}]}}"#
    )
}

fn contract_scope() -> String {
    format!(r#"{{"type":"contract","address":"{REGISTRY}"}}"#)
}

const ALL_PRINCIPALS: &str = r#"{"type":"all","signers":["admin"]}"#;
const IS_SELF: &str = r#"{"type":"is-self"}"#;

fn valid() -> String {
    doc(&contract_scope(), ALL_PRINCIPALS, IS_SELF)
}

fn assert_json_err(input: &str, needle: &str) {
    match from_json(input) {
        Err(ParseError::Json(e)) => {
            let msg = e.to_string();
            assert!(msg.contains(needle), "error `{msg}` missing `{needle}`");
        }
        other => panic!("expected ParseError::Json, got {other:?}"),
    }
}

#[test]
fn parses_a_fully_featured_valid_doc() {
    let doc = from_json(&valid()).expect("valid doc must parse");
    assert_eq!(doc.version, 1);
    assert_eq!(doc.network.as_deref(), Some("testnet"));
    assert_eq!(doc.signers.len(), 1);
    assert_eq!(doc.rules.len(), 1);
    assert_eq!(doc.rules[0].not_after_ledger, Some(999));
    perch_ir::validate(&doc).expect("valid doc must validate");
}

// --- version gate ------------------------------------------------------------

#[test]
fn rejects_version_2_with_distinct_error() {
    let input = valid().replace(r#""version":1"#, r#""version":2"#);
    match from_json(&input) {
        Err(ParseError::UnsupportedVersion(2)) => {}
        other => panic!("expected UnsupportedVersion(2), got {other:?}"),
    }
}

#[test]
fn rejects_version_0_with_distinct_error() {
    let input = valid().replace(r#""version":1"#, r#""version":0"#);
    match from_json(&input) {
        Err(ParseError::UnsupportedVersion(0)) => {}
        other => panic!("expected UnsupportedVersion(0), got {other:?}"),
    }
}

#[test]
fn version_check_runs_before_other_schema_errors() {
    // Bogus top-level field AND bad version: the version error must win.
    let input = valid().replace(r#""version":1"#, r#""version":7,"bogus":true"#);
    match from_json(&input) {
        Err(ParseError::UnsupportedVersion(7)) => {}
        other => panic!("expected UnsupportedVersion(7), got {other:?}"),
    }
}

#[test]
fn non_numeric_or_missing_version_is_a_schema_error() {
    // A string version is not the distinct UnsupportedVersion error — it is a
    // type mismatch surfaced by serde.
    let input = valid().replace(r#""version":1"#, r#""version":"1""#);
    assert_json_err(&input, "expected u32");

    let input = valid().replace(r#""version":1,"#, "");
    assert_json_err(&input, "version");
}

#[test]
fn rejects_malformed_json_syntax() {
    match from_json("{ not json") {
        Err(ParseError::Json(_)) => {}
        other => panic!("expected ParseError::Json, got {other:?}"),
    }
}

// --- unknown fields ----------------------------------------------------------

#[test]
fn rejects_unknown_top_level_field() {
    let input = valid().replace(r#""network":"testnet""#, r#""network":"testnet","extra":1"#);
    assert_json_err(&input, "extra");
}

#[test]
fn rejects_unknown_field_in_signer() {
    let input = valid().replace(r#""id":"admin""#, r#""id":"admin","role":"boss""#);
    assert_json_err(&input, "role");
}

#[test]
fn rejects_unknown_field_in_rule() {
    let input = valid().replace(r#""name":"r""#, r#""name":"r","priority":9"#);
    assert_json_err(&input, "priority");
}

#[test]
fn rejects_unknown_field_in_contract_scope() {
    let scope = format!(r#"{{"type":"contract","address":"{REGISTRY}","chain":"stellar"}}"#);
    let input = doc(&scope, ALL_PRINCIPALS, IS_SELF);
    assert_json_err(&input, "chain");
}

#[test]
fn rejects_extra_field_beside_self_admin_tag() {
    let input = doc(
        r#"{"type":"self-admin","extra":1}"#,
        ALL_PRINCIPALS,
        IS_SELF,
    );
    assert_json_err(&input, "extra");
}

#[test]
fn self_admin_scope_parses_clean() {
    let input = doc(r#"{"type":"self-admin"}"#, ALL_PRINCIPALS, IS_SELF);
    from_json(&input).expect("self-admin scope must parse");
}

#[test]
fn rejects_unknown_field_in_all_principals() {
    let input = doc(
        &contract_scope(),
        r#"{"type":"all","signers":["admin"],"quorum":2}"#,
        IS_SELF,
    );
    assert_json_err(&input, "quorum");
}

#[test]
fn rejects_unknown_field_in_self_authenticating_principals() {
    let principals = format!(
        r#"{{"type":"self-authenticating","policy":"{POLICY_CONTRACT}","install-param-hex":"","ack":"{ACK_SENTINEL}","note":"x"}}"#
    );
    let input = doc(&contract_scope(), &principals, IS_SELF);
    assert_json_err(&input, "note");
}

#[test]
fn self_authenticating_principals_parse_clean() {
    let principals = format!(
        r#"{{"type":"self-authenticating","policy":"{POLICY_CONTRACT}","install-param-hex":"deadbeef","ack":"{ACK_SENTINEL}"}}"#
    );
    let input = doc(&contract_scope(), &principals, IS_SELF);
    let parsed = from_json(&input).expect("self-authenticating must parse");
    perch_ir::validate(&parsed).expect("and validate");
}

#[test]
fn rejects_unknown_field_in_arg_constraint() {
    let input = valid().replace(
        r#"{"index":1,"pred":{"type":"is-self"}}"#,
        r#"{"index":1,"pred":{"type":"is-self"},"why":"because"}"#,
    );
    assert_json_err(&input, "why");
}

#[test]
fn rejects_extra_field_beside_is_self_tag() {
    let input = doc(
        &contract_scope(),
        ALL_PRINCIPALS,
        r#"{"type":"is-self","sneaky":true}"#,
    );
    assert_json_err(&input, "sneaky");
}

#[test]
fn rejects_unknown_field_in_pred_payload() {
    let input = doc(
        &contract_scope(),
        ALL_PRINCIPALS,
        r#"{"type":"u32-eq","value":5,"fuzz":1}"#,
    );
    assert_json_err(&input, "fuzz");
}

#[test]
fn rejects_snake_case_field_names() {
    // The wire format is kebab-case: snake_case aliases must not sneak in.
    let input = valid().replace(r#""not-after-ledger":999"#, r#""not_after_ledger":999"#);
    assert_json_err(&input, "not_after_ledger");
}

// --- explicit null is not "absent" -------------------------------------------

#[test]
fn rejects_explicit_null_functions() {
    // `null` must not collapse to None (= "all functions"), which would make
    // `"functions": null` silently authorize everything.
    let input = valid().replace(r#""functions":["publish"]"#, r#""functions":null"#);
    assert_json_err(&input, "null");
}

#[test]
fn rejects_explicit_null_args() {
    let input = valid().replace(
        r#""args":[{"index":1,"pred":{"type":"is-self"}}]"#,
        r#""args":null"#,
    );
    assert_json_err(&input, "null");
}

#[test]
fn rejects_explicit_null_not_after_ledger() {
    let input = valid().replace(r#""not-after-ledger":999"#, r#""not-after-ledger":null"#);
    assert_json_err(&input, "null");
}

#[test]
fn rejects_explicit_null_network() {
    let input = valid().replace(r#""network":"testnet""#, r#""network":null"#);
    assert_json_err(&input, "null");
}

// --- duplicate object keys ---------------------------------------------------
//
// JSON parsers legitimately disagree on whether the first or last occurrence
// of a duplicated key wins, so duplicates are a content-aliasing vector: a
// reviewer's first-wins tooling could display different content than what
// perch canonicalizes and hashes. All duplicates must be rejected, at every
// nesting level.

#[test]
fn rejects_duplicate_top_level_key() {
    let input = valid().replace(
        r#""network":"testnet""#,
        r#""network":"first","network":"second""#,
    );
    assert_json_err(&input, "duplicate field");
}

#[test]
fn rejects_duplicate_key_inside_signer() {
    let input = valid().replace(r#""id":"admin""#, r#""id":"admin","id":"other""#);
    assert_json_err(&input, "duplicate field");
}

#[test]
fn rejects_duplicate_key_inside_tagged_payload() {
    // Duplicate key inside the buffered content of an internally tagged enum
    // (a contract scope) must be rejected too.
    let scope = format!(r#"{{"type":"contract","address":"{REGISTRY}","address":"{REGISTRY}"}}"#);
    let input = doc(&scope, ALL_PRINCIPALS, IS_SELF);
    assert_json_err(&input, "duplicate field");
}

#[test]
fn rejects_duplicate_version_key() {
    // {"version":2,"version":1}: a last-wins Value pre-check alone would see
    // only the collapsed 1 and let the document through. The typed parse must
    // still reject the duplicate.
    let input = valid().replace(r#""version":1"#, r#""version":2,"version":1"#);
    assert!(
        from_json(&input).is_err(),
        "duplicate version keys must be rejected"
    );
}

#[test]
fn rejects_duplicate_version_key_both_valid() {
    // Even when both occurrences are the accepted version, the duplication
    // itself is rejected.
    let input = valid().replace(r#""version":1"#, r#""version":1,"version":1"#);
    assert_json_err(&input, "duplicate field");
}

// --- unknown enum tags -------------------------------------------------------

#[test]
fn rejects_unknown_scope_tag() {
    let input = doc(r#"{"type":"galaxy"}"#, ALL_PRINCIPALS, IS_SELF);
    assert_json_err(&input, "galaxy");
}

#[test]
fn rejects_unknown_principals_tag() {
    let input = doc(
        &contract_scope(),
        r#"{"type":"any","signers":["admin"]}"#,
        IS_SELF,
    );
    assert_json_err(&input, "any");
}

#[test]
fn rejects_unknown_pred_tag() {
    let input = doc(
        &contract_scope(),
        ALL_PRINCIPALS,
        r#"{"type":"regex","pattern":".*"}"#,
    );
    assert_json_err(&input, "regex");
}

#[test]
fn all_pred_tags_parse() {
    let preds = [
        r#"{"type":"is-self"}"#.to_string(),
        format!(r#"{{"type":"address-eq","address":"{G_ADDR}"}}"#),
        r#"{"type":"string-in","values":["a","b"]}"#.to_string(),
        r#"{"type":"string-prefix","prefix":"v1-"}"#.to_string(),
        r#"{"type":"u32-eq","value":42}"#.to_string(),
    ];
    for pred in &preds {
        let input = doc(&contract_scope(), ALL_PRINCIPALS, pred);
        from_json(&input).unwrap_or_else(|e| panic!("pred {pred} failed: {e}"));
    }
}
