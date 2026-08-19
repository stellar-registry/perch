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
const FIXTURE_HASH_HEX: &str = "38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d";

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
    assert_eq!(doc.rules[1].not_after_ledger, Some(55_000_000));
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

// --- the delegated variant of the fixture ------------------------------------
//
// Same document with the ci signer as a CAP-0071 delegated address instead of
// an external verifier+key. Pins the delegated signer shape's canonical form.

/// Pinned doc_hash (hex) of the delegated fixture. Must match
/// `testdata/ci-publish-delegated.doc-hash`.
const DELEGATED_FIXTURE_HASH_HEX: &str =
    "8c9a85cf81cb7b556ca6292c1a3b38ae876a1703b97471753caa93f6c11e2c46";

#[test]
fn delegated_fixture_parses_validates_and_matches_committed_files() {
    let doc = from_json(&read("ci-publish-delegated.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    assert_eq!(doc.signers.len(), 2);
    assert!(matches!(
        doc.signers[0].method,
        perch_ir::SignerMethod::External { .. }
    ));
    assert!(matches!(
        doc.signers[1].method,
        perch_ir::SignerMethod::Delegated { .. }
    ));

    let committed = read("ci-publish-delegated.canonical.json");
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));

    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish-delegated.doc-hash").trim());
    assert_eq!(hash, DELEGATED_FIXTURE_HASH_HEX);
}
