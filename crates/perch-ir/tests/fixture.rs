//! The CI-publish golden fixture: the pretty source under `testdata/`, its
//! committed canonical form, and its pinned hash must all agree with what
//! this crate computes. These files seed the cross-language golden vectors
//! (<https://github.com/stellar-registry/perch/issues/3>).

mod common;

use perch_ir::{canonical_json, doc_hash_hex, from_json, validate, Principals, Scope};
use std::fs;
use std::path::PathBuf;

/// Pinned doc_hash (hex) of the fixture. Must match
/// `testdata/ci-publish.doc-hash`; a change is a canonical-form break.
const FIXTURE_HASH_HEX: &str = "12a0f9b9c63f45d48c6695785439ed61341b47fa19b4f8768ea82b44474d2d76";

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn read(name: &str) -> String {
    fs::read_to_string(testdata(name)).unwrap_or_else(|e| panic!("reading testdata/{name}: {e}"))
}

#[test]
fn fixture_parses_and_validates() {
    let doc = from_json(&read("ci-publish.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    // Shape sanity: admin webauthn signer + ci ed25519 signer, self-admin
    // root rule + contract-scoped publish rule.
    assert_eq!(doc.signers.len(), 2);
    assert_eq!(doc.signers[0].id, "admin");
    assert_eq!(doc.signers[1].id, "ci");
    assert_eq!(doc.rules.len(), 2);
    assert!(matches!(doc.rules[0].scope, Scope::SelfAdmin(_)));
    assert!(matches!(doc.rules[1].scope, Scope::Contract(_)));
    assert!(matches!(doc.rules[1].principals, Principals::All(_)));
    assert_eq!(
        doc.rules[1].functions.as_deref(),
        Some(["publish".to_string(), "publish_hash".to_string()].as_slice())
    );
    assert_eq!(doc.rules[1].args.as_ref().map(Vec::len), Some(1));
    assert_eq!(doc.rules[1].not_after, Some(1_893_456_000));
}

#[test]
fn fixture_canonical_form_matches_committed_file() {
    let doc = from_json(&read("ci-publish.json")).expect("fixture must parse");
    let committed = read("ci-publish.canonical.json");
    // The canonical form has no trailing newline; tolerate one in the
    // committed file (editors/hooks add it) by comparing trimmed-end.
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));
}

#[test]
fn fixture_hash_matches_committed_and_pinned_values() {
    let doc = from_json(&read("ci-publish.json")).expect("fixture must parse");
    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish.doc-hash").trim());
    assert_eq!(hash, FIXTURE_HASH_HEX);
}

#[test]
fn fixture_pretty_and_canonical_files_are_the_same_document() {
    let pretty = from_json(&read("ci-publish.json")).expect("pretty must parse");
    let canonical = from_json(read("ci-publish.canonical.json").trim_end_matches('\n'))
        .expect("canonical must parse");
    assert_eq!(pretty, canonical);
}
