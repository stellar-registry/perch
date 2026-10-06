//! The rule hash (`CANONICAL.md` "Derived hashes"): an interpreter program's
//! provenance, domain-separated from the document hash.

use perch_ir::{doc_hash, from_json, rule_canonical_json, rule_hash, RULE_HASH_DOMAIN};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn fixture() -> perch_ir::PolicyDoc {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ci-publish.json");
    from_json(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn a_rules_canonical_json_is_its_slice_of_the_document() {
    let doc = fixture();
    let whole = perch_ir::canonical_json(&doc);
    let rules: Vec<String> = doc.rules.iter().map(rule_canonical_json).collect();
    assert!(whole.contains(&format!(r#""rules":[{}]"#, rules.join(","))));
}

#[test]
fn the_rule_hash_is_domain_separated_and_pinned() {
    let doc = fixture();
    let rule = &doc.rules[1];
    let mut h = Sha256::new();
    h.update(RULE_HASH_DOMAIN.as_bytes());
    h.update(rule_canonical_json(rule).as_bytes());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(rule_hash(rule), expected);
    assert_ne!(rule_hash(rule), doc_hash(&doc));
    let plain: [u8; 32] = Sha256::digest(rule_canonical_json(rule).as_bytes()).into();
    assert_ne!(
        rule_hash(rule),
        plain,
        "the domain prefix is part of the preimage"
    );
    assert_eq!(
        hex::encode(rule_hash(rule)),
        PINNED_CI_PUBLISH_RULE_HASH,
        "a change here is a provenance break for every installed program"
    );
}

const PINNED_CI_PUBLISH_RULE_HASH: &str =
    "9eed09668050056b1d721e8fd3db8a16cf2fab7d4a610aba38782b1fa6d02836";
