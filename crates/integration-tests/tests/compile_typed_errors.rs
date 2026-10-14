//! A document whose lowering would trap — a function name that is not a
//! Soroban `Symbol`, or an address strkey with a bad CRC16 checksum — is
//! refused by validation with a typed `DocCompilerError`, never an untyped
//! host trap. `try_compile_doc` returns the typed error as
//! `Err(Ok(DocCompilerError::_))`; a host trap would be `Err(Err(_))`.

mod support;

use perch_doc_compiler::DocCompilerError;
use perch_testkit::FIXTURE_NETWORK;
use soroban_sdk::Bytes;
use support::*;

/// The `owner` admin plus one extra rule given as raw JSON.
fn doc(w: &World, extra_rule: &str) -> Bytes {
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"owner","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}}{}]}}"#,
        strkey(&w.owner),
        extra_rule,
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

#[test]
fn an_invalid_function_name_is_a_typed_refusal_not_a_trap() {
    let w = world();
    // '-' and '.' are outside the Symbol alphabet; 33 chars exceeds the max.
    for f in ["transfer-from", "a.b", "x".repeat(33).as_str()] {
        let rule = format!(
            r#",{{"name":"f","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["{f}"]}}"#,
            strkey(&w.target)
        );
        let r = w.compiler().try_compile_doc(&doc(&w, &rule));
        assert!(
            matches!(r, Err(Ok(DocCompilerError::DocInvalid))),
            "function {f:?}: expected a typed DocInvalid, got {r:?}"
        );
    }
}

#[test]
fn a_bad_strkey_checksum_is_a_typed_refusal_not_a_trap() {
    let w = world();
    let good = strkey(&w.target);
    // Flip the last base32 character to break the CRC while keeping the shape.
    let last = good.chars().last().unwrap();
    let bad = format!("{}{}", &good[..55], if last == 'A' { 'B' } else { 'A' });
    let rule = format!(
        r#",{{"name":"t","scope":{{"type":"contract","address":"{bad}"}},"principals":{{"type":"all","signers":["owner"]}}}}"#
    );
    let r = w.compiler().try_compile_doc(&doc(&w, &rule));
    assert!(
        matches!(r, Err(Ok(DocCompilerError::DocInvalid))),
        "bad-checksum scope address: expected a typed DocInvalid, got {r:?}"
    );
}

/// Guard against a false positive: a well-formed document with a valid function
/// name and a correct-checksum address still compiles.
#[test]
fn a_valid_function_and_address_still_compile() {
    let w = world();
    let rule = format!(
        r#",{{"name":"f","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["transfer"]}}"#,
        strkey(&w.target)
    );
    let r = w.compiler().try_compile_doc(&doc(&w, &rule));
    assert!(
        matches!(r, Ok(Ok(_))),
        "valid doc should compile, got {r:?}"
    );
}
