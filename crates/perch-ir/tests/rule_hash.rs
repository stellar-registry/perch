//! The rule hash (`CANONICAL.md`, "Fragment hashes"): an interpreter
//! program's provenance, domain-separated from the document hash. Checked
//! against the independently generated `testdata/rule-hashes.json`.

use perch_ir::{doc_hash, from_json, rule_canonical_json, rule_hash, RULE_HASH_DOMAIN};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn testdata(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    std::fs::read_to_string(p).unwrap()
}

/// One rule's vector: name, canonical bytes, `rule_hash` hex.
type RuleVector = (String, String, String);

/// `(fixture json name, its rules' vectors)` from `testdata/rule-hashes.json`.
fn vectors() -> Vec<(String, Vec<RuleVector>)> {
    let raw = testdata("rule-hashes.json");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["domain"], RULE_HASH_DOMAIN);
    v["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let path = f["fixture"].as_str().unwrap();
            let json = path
                .trim_start_matches("testdata/")
                .replace(".canonical.json", ".json");
            let rules = f["rules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        r["name"].as_str().unwrap().to_owned(),
                        r["canonical"].as_str().unwrap().to_owned(),
                        r["rule_hash"].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            (json, rules)
        })
        .collect()
}

#[test]
fn every_rule_hash_matches_the_independent_vectors() {
    let vectors = vectors();
    assert!(!vectors.is_empty());
    for (fixture, rules) in vectors {
        let doc = from_json(&testdata(&fixture)).unwrap();
        assert_eq!(doc.rules.len(), rules.len(), "{fixture}");
        for (rule, (name, canonical, hash)) in doc.rules.iter().zip(&rules) {
            assert_eq!(&rule.name, name, "{fixture}");
            assert_eq!(&rule_canonical_json(rule), canonical, "{fixture}/{name}");
            assert_eq!(&hex::encode(rule_hash(rule)), hash, "{fixture}/{name}");
        }
    }
}

#[test]
fn a_rules_canonical_json_is_its_slice_of_the_document() {
    let doc = from_json(&testdata("ci-publish.json")).unwrap();
    let whole = perch_ir::canonical_json(&doc);
    let rules: Vec<String> = doc.rules.iter().map(rule_canonical_json).collect();
    assert!(whole.contains(&format!(r#""rules":[{}]"#, rules.join(","))));
}

#[test]
fn the_rule_hash_is_domain_separated() {
    let doc = from_json(&testdata("ci-publish.json")).unwrap();
    let rule = &doc.rules[1];
    let mut h = Sha256::new();
    h.update(b"perch/rule");
    h.update(rule_canonical_json(rule).as_bytes());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(rule_hash(rule), expected);
    assert_ne!(rule_hash(rule), doc_hash(&doc));
    let plain: [u8; 32] = Sha256::digest(rule_canonical_json(rule).as_bytes()).into();
    assert_ne!(
        rule_hash(rule),
        plain,
        "the domain tag is part of the preimage"
    );
}
