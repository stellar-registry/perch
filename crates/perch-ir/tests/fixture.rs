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
const FIXTURE_HASH_HEX: &str = "27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98";

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
    "0e2f8e7c826d8252ce0bec1528a079e21ba6b628649762a7cae3fb823e6155ea";

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

// --- the threshold + cap variant of the fixture -------------------------------
//
// Same document with the publish rule authorized by a 1-of-2 quorum over
// {admin, ci} and carrying a cumulative spend cap. Pins the `threshold`
// principals and `cap` canonical forms (the two rule shapes the base fixtures
// don't reach).

/// Pinned doc_hash (hex) of the threshold+cap fixture. Must match
/// `testdata/ci-publish-threshold.doc-hash`.
const THRESHOLD_FIXTURE_HASH_HEX: &str =
    "6748e7aa1340fbd97dce386fbeaef41c474edde0e4dd7fa75df482a2d58cd748";

#[test]
fn threshold_fixture_parses_validates_and_matches_committed_files() {
    let doc = from_json(&read("ci-publish-threshold.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    let publish = &doc.rules[1];
    match &publish.principals {
        Principals::Threshold(t) => {
            assert_eq!(t.signers, ["admin".to_string(), "ci".to_string()]);
            assert_eq!(t.m, 1);
        }
        other => panic!("expected threshold principals, got {other:?}"),
    }
    let cap = publish.cap.as_ref().expect("publish rule must carry a cap");
    assert_eq!(cap.token, None);
    assert_eq!(cap.limit, "1000000000");
    assert_eq!(cap.period_ledgers, 17280);

    let committed = read("ci-publish-threshold.canonical.json");
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));

    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish-threshold.doc-hash").trim());
    assert_eq!(hash, THRESHOLD_FIXTURE_HASH_HEX);
}
