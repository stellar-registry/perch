mod common;

use common::{base_doc, rule, G_ADDR, POLICY_CONTRACT, REGISTRY};
use perch_ir::{canonical_json, doc_hash, from_json, rule_hash, validate, AuthRoot, Scope};

fn document() -> perch_ir::PolicyDoc {
    let mut doc = base_doc();
    doc.rules = vec![rule("transfer", Scope::contract(REGISTRY), &["admin"])];
    doc
}

#[test]
fn root_is_optional_but_binds_both_document_and_rule_identity() {
    let mut doc = document();
    let legacy = canonical_json(&doc);
    let legacy_hash = doc_hash(&doc);
    let legacy_rule_hash = rule_hash(&doc.rules[0]);
    doc.rules[0].auth_root = Some(AuthRoot {
        contract: POLICY_CONTRACT.into(),
        function: "guess".into(),
    });
    validate(&doc).unwrap();
    assert_eq!(from_json(&canonical_json(&doc)).unwrap(), doc);
    assert_ne!(doc_hash(&doc), legacy_hash);
    assert_ne!(rule_hash(&doc.rules[0]), legacy_rule_hash);
    let restricted_hash = doc_hash(&doc);
    doc.rules[0].auth_root.as_mut().unwrap().function = "guess_again".into();
    assert_ne!(doc_hash(&doc), restricted_hash);
    doc.rules[0].auth_root.as_mut().unwrap().function = "guess".into();
    doc.rules[0].auth_root.as_mut().unwrap().contract = REGISTRY.into();
    assert_ne!(doc_hash(&doc), restricted_hash);
    doc.rules[0].auth_root = None;
    assert_eq!(canonical_json(&doc), legacy);
    assert_eq!(doc_hash(&doc), legacy_hash);
}

#[test]
fn malformed_root_never_becomes_unrestricted() {
    let base: serde_json::Value = serde_json::from_str(&canonical_json(&document())).unwrap();
    for root in [
        "null".to_string(),
        "{}".to_string(),
        format!(r#"{{"contract":"{POLICY_CONTRACT}"}}"#),
        r#"{"function":"guess"}"#.into(),
        format!(r#"{{"contract":"{POLICY_CONTRACT}","function":null}}"#),
        format!(r#"{{"contract":"{POLICY_CONTRACT}","function":"guess","depth":0}}"#),
        format!(r#"{{"contract":"{POLICY_CONTRACT}","function":"guess","function":"transfer"}}"#),
    ] {
        let text = serde_json::to_string(&base).unwrap();
        let text = text.replacen("\"name\":", &format!("\"auth-root\":{root},\"name\":"), 1);
        assert!(from_json(&text).is_err(), "accepted {root}");
    }
}

#[test]
fn root_requires_a_contract_and_symbol_and_cannot_restrict_admin() {
    let mut doc = document();
    for (contract, function) in [
        (G_ADDR, "guess"),
        ("C-invalid", "guess"),
        (POLICY_CONTRACT, ""),
        (POLICY_CONTRACT, "*"),
        (POLICY_CONTRACT, "a-b"),
        (POLICY_CONTRACT, "abcdefghijklmnopqrstuvwxyz1234567"),
    ] {
        doc.rules[0].auth_root = Some(AuthRoot {
            contract: contract.into(),
            function: function.into(),
        });
        assert!(validate(&doc).is_err(), "accepted {contract}/{function}");
    }
    doc.rules[0].auth_root = Some(AuthRoot {
        contract: POLICY_CONTRACT.into(),
        function: "guess".into(),
    });
    doc.rules[0].scope = Scope::self_admin();
    assert!(validate(&doc).is_err());
}

#[test]
fn shared_root_canonical_vector() {
    let doc = from_json(include_str!("../../../testdata/auth-root.json")).unwrap();
    validate(&doc).unwrap();
    assert_eq!(
        canonical_json(&doc),
        include_str!("../../../testdata/auth-root.canonical.json").trim_end()
    );
    assert_eq!(
        perch_ir::doc_hash_hex(&doc),
        include_str!("../../../testdata/auth-root.doc-hash").trim_end()
    );
}
