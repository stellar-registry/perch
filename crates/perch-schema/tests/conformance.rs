//! Criterion 3 (conformance): validate canonical fixtures and negative
//! examples against the schema and compare with perch-ir's real parser and
//! document validator at the applicable boundary.
//!
//! The shared declarative cases live in `testdata/schema/cases.json` (also run
//! by the perch-js suite). The boundary cases whose inputs must be generated —
//! the signer-key length window, duplicate raw JSON keys, and canonical
//! encoding — are expressed here directly.

mod common;

use common::{ir_outcome, ir_outcome_of, schema_accepts, validator, workspace_root};
use serde_json::{json, Value};

fn load_cases() -> Vec<Value> {
    let path = workspace_root().join("testdata/schema/cases.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let parsed: Value = serde_json::from_str(&text).expect("cases.json is valid JSON");
    parsed["cases"]
        .as_array()
        .expect("cases.json has a `cases` array")
        .clone()
}

/// Resolve a case's document: inline `doc`, or a `file` under `testdata/`.
fn case_doc(case: &Value) -> Value {
    if let Some(doc) = case.get("doc") {
        return doc.clone();
    }
    let file = case["file"].as_str().expect("a case has `doc` or `file`");
    let path = workspace_root().join("testdata").join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file} is valid JSON: {e}"))
}

#[test]
fn declared_cases_agree_at_the_applicable_boundary() {
    let v = validator();
    let cases = load_cases();
    assert!(
        cases.len() >= 30,
        "expected a broad case set, got {}",
        cases.len()
    );

    for case in &cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let expect = case["expect"].as_str().expect("case has `expect`");
        let doc = case_doc(case);
        let schema_ok = schema_accepts(&v, &doc);
        let ir = ir_outcome_of(&doc);

        match expect {
            // Schema accepts, and perch-ir parses AND validates.
            "accept" => {
                assert!(
                    schema_ok,
                    "[{name}] schema should accept a canonical document"
                );
                assert!(ir.accepted, "[{name}] perch-ir should accept it");
            }
            // perch-ir's PARSER rejects (shape/tag/version/unknown/null), and
            // the schema rejects too.
            "reject-structural" => {
                assert!(
                    !schema_ok,
                    "[{name}] schema should reject this structural defect"
                );
                assert!(!ir.parsed, "[{name}] perch-ir's parser should reject it");
            }
            // perch-ir's VALIDATOR rejects a representable format/range/
            // collection rule (the document still parses), and the schema
            // rejects it too. This is the single-source boundary: the schema
            // encodes the same limit perch-ir enforces.
            "reject-constraint" => {
                assert!(
                    !schema_ok,
                    "[{name}] schema should reject this representable constraint"
                );
                assert!(
                    ir.parsed,
                    "[{name}] the document should still parse (shape is well-formed)"
                );
                assert!(
                    !ir.accepted,
                    "[{name}] perch-ir's validator should reject it"
                );
            }
            // The schema ACCEPTS, but perch-ir's validator rejects a
            // non-representable cross-reference/semantic rule. This proves the
            // documented boundary (docs/schema.md criterion 4): schema-valid is
            // not validator-valid.
            "accept-semantic-invalid" => {
                assert!(
                    schema_ok,
                    "[{name}] schema should accept (the defect is not representable)"
                );
                assert!(ir.parsed, "[{name}] the document should parse");
                assert!(
                    !ir.accepted,
                    "[{name}] perch-ir's validator should still reject it"
                );
            }
            other => panic!("[{name}] unknown expect `{other}`"),
        }
    }
}

/// A minimal document carrying one external signer with the given hex `key`.
fn doc_with_key(key: &str) -> Value {
    json!({
        "version": 1,
        "signers": [{
            "id": "a",
            "verifier": "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN",
            "key": key,
        }],
        "rules": [{
            "name": "r",
            "scope": { "type": "self-admin" },
            "principals": { "type": "all", "signers": ["a"] },
        }],
    })
}

#[test]
fn signer_key_length_window_matches_the_validator() {
    let v = validator();
    let max = perch_ir::MAX_SIGNER_KEY_LEN;

    // At the cap: MAX_SIGNER_KEY_LEN bytes of key (2 hex chars/byte). Both
    // accept.
    let at_limit = doc_with_key(&"ab".repeat(max));
    assert!(
        schema_accepts(&v, &at_limit),
        "schema accepts a key at the byte cap"
    );
    assert!(
        ir_outcome_of(&at_limit).accepted,
        "validator accepts a key at the byte cap"
    );

    // One byte over: both reject (schema via the `{1,N}` pattern, perch-ir via
    // SignerKeyLength). This is the boundary the brief's string-length example
    // is about — the schema and the validator flip together.
    let over = doc_with_key(&"ab".repeat(max + 1));
    assert!(
        !schema_accepts(&v, &over),
        "schema rejects a key over the byte cap"
    );
    let ir = ir_outcome_of(&over);
    assert!(
        ir.parsed,
        "the over-cap document still parses (shape is fine)"
    );
    assert!(!ir.accepted, "validator rejects a key over the byte cap");

    // Empty key: both reject (pattern requires >= 1 byte; validator rejects an
    // empty decoded key).
    let empty = doc_with_key("");
    assert!(!schema_accepts(&v, &empty), "schema rejects an empty key");
    assert!(
        !ir_outcome_of(&empty).accepted,
        "validator rejects an empty key"
    );
}

const VALID_C: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";

/// A document with `n` distinct, valid external signers and one self-admin rule
/// referencing the first. Each key is distinct hex so no `DuplicateSignerKey`
/// fires (the count, not the key material, is what varies).
fn doc_with_n_signers(n: u32) -> Value {
    let signers: Vec<Value> = (0..n)
        .map(|i| json!({ "id": format!("s{i}"), "verifier": VALID_C, "key": format!("{i:02x}") }))
        .collect();
    json!({
        "version": 1,
        "signers": signers,
        "rules": [{ "name": "r", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["s0"] } }],
    })
}

/// A document with one signer and `m` distinct-named self-admin rules.
fn doc_with_n_rules(m: u32) -> Value {
    let rules: Vec<Value> = (0..m)
        .map(|i| json!({ "name": format!("r{i}"), "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["a"] } }))
        .collect();
    json!({
        "version": 1,
        "signers": [{ "id": "a", "verifier": VALID_C, "key": "ab" }],
        "rules": rules,
    })
}

/// A document with one signer and one rule whose name is `len` ASCII bytes.
fn doc_with_rule_name(len: usize) -> Value {
    json!({
        "version": 1,
        "signers": [{ "id": "a", "verifier": VALID_C, "key": "ab" }],
        "rules": [{ "name": "n".repeat(len), "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["a"] } }],
    })
}

#[test]
fn aggregate_caps_are_a_schema_then_compiler_boundary() {
    // Criterion 1 + 3 for the per-document caps. These are the COMPILER's caps
    // (`perch-doc-compiler`), not perch-ir's: perch-ir's `validate` accepts an
    // over-cap document (it is structurally and semantically fine); only the
    // compiler's `DocTooLarge` refuses it. The schema now encodes the
    // representable ones (maxItems / maxLength) so an editor catches them before
    // compilation. So, uniquely, these cases are: schema REJECTS, yet perch-ir
    // PARSES AND VALIDATES. The constant equality is asserted in limits_parity.
    let v = validator();
    let max_signers = perch_doc_compiler::MAX_DOC_SIGNERS;
    let max_rules = perch_doc_compiler::MAX_DOC_RULES;
    let max_name = perch_doc_compiler::MAX_RULE_NAME_BYTES as usize;

    // Signers: at the cap both admit; one over, the schema rejects while
    // perch-ir's validator still accepts (the cap is the compiler's).
    let at = doc_with_n_signers(max_signers);
    assert!(schema_accepts(&v, &at), "schema accepts signers at the cap");
    assert!(
        ir_outcome_of(&at).accepted,
        "perch-ir accepts signers at the cap"
    );
    let over = doc_with_n_signers(max_signers + 1);
    assert!(
        !schema_accepts(&v, &over),
        "schema rejects signers over the cap"
    );
    assert!(
        ir_outcome_of(&over).accepted,
        "perch-ir's validator still accepts an over-cap document — the cap is the compiler's",
    );

    // Rules: same shape.
    let at = doc_with_n_rules(max_rules);
    assert!(schema_accepts(&v, &at), "schema accepts rules at the cap");
    assert!(
        ir_outcome_of(&at).accepted,
        "perch-ir accepts rules at the cap"
    );
    let over = doc_with_n_rules(max_rules + 1);
    assert!(
        !schema_accepts(&v, &over),
        "schema rejects rules over the cap"
    );
    assert!(
        ir_outcome_of(&over).accepted,
        "perch-ir's validator still accepts an over-cap rule count",
    );

    // Rule name: at the byte cap (ASCII, so bytes == chars) both admit; one
    // byte over, the schema rejects via maxLength while perch-ir still accepts.
    let at = doc_with_rule_name(max_name);
    assert!(
        schema_accepts(&v, &at),
        "schema accepts a rule name at the byte cap"
    );
    assert!(
        ir_outcome_of(&at).accepted,
        "perch-ir accepts a rule name at the byte cap"
    );
    let over = doc_with_rule_name(max_name + 1);
    assert!(
        !schema_accepts(&v, &over),
        "schema rejects a rule name over the byte cap"
    );
    assert!(
        ir_outcome_of(&over).accepted,
        "perch-ir's validator still accepts an over-cap rule name",
    );
}

#[test]
fn non_ascii_rule_name_is_schema_stricter_than_the_validator() {
    // The one place the schema is deliberately STRICTER than perch-ir/compiler:
    // a non-ASCII rule name within the byte cap. JSON Schema's maxLength counts
    // code points, so the schema requires ASCII to make maxLength a byte cap;
    // the parser has no charset rule. Documented in docs/schema.md.
    let v = validator();
    let doc = json!({
        "version": 1,
        "signers": [{ "id": "a", "verifier": VALID_C, "key": "ab" }],
        "rules": [{ "name": "café", "scope": { "type": "self-admin" }, "principals": { "type": "all", "signers": ["a"] } }],
    });
    assert!(
        !schema_accepts(&v, &doc),
        "schema rejects a non-ASCII rule name"
    );
    assert!(
        ir_outcome_of(&doc).accepted,
        "perch-ir accepts it (no charset rule) — the schema is intentionally stricter here",
    );
}

#[test]
fn duplicate_raw_keys_are_a_parser_only_rejection() {
    // Criterion 4: duplicate raw JSON keys are outside JSON Schema. A validator
    // works on already-parsed JSON (the duplicate is collapsed), so the schema
    // cannot see it — only perch-ir's raw-text parser rejects it.
    let v = validator();
    let raw = r#"{"version":1,"version":1,"signers":[{"id":"a","verifier":"CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN","key":"ab"}],"rules":[{"name":"r","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["a"]}}]}"#;

    // perch-ir's parser rejects the duplicate key.
    assert!(
        !ir_outcome(raw).parsed,
        "perch-ir rejects duplicate raw keys"
    );

    // The schema, over the parsed value (duplicate collapsed), accepts it —
    // demonstrating the boundary, not a bug.
    let collapsed: Value = serde_json::from_str(raw).expect("serde collapses duplicate keys");
    assert!(
        schema_accepts(&v, &collapsed),
        "the schema cannot see collapsed duplicate keys (documented boundary)",
    );
}

#[test]
fn schema_valid_is_not_canonically_encoded() {
    // Criterion 4: lexical/canonical (RFC 8785) encoding is outside JSON Schema.
    // The committed ci-publish fixture is schema-valid and perch-ir-valid, yet
    // its pretty, unsorted bytes are not the canonical form.
    let v = validator();
    let path = workspace_root().join("testdata/ci-publish.json");
    let text = std::fs::read_to_string(&path).expect("read ci-publish.json");
    let value: Value = serde_json::from_str(&text).expect("ci-publish.json parses");

    assert!(schema_accepts(&v, &value), "the fixture is schema-valid");
    let doc = perch_ir::from_json(&text).expect("perch-ir parses the fixture");
    assert!(
        perch_ir::validate(&doc).is_ok(),
        "perch-ir validates the fixture"
    );

    let canonical = perch_ir::canonical_json(&doc);
    assert_ne!(
        text.trim_end(),
        canonical,
        "the pretty fixture bytes are not the canonical form — schema-valid does not mean canonically encoded",
    );
}
