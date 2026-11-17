//! `verifier-name`: how a document names a verifier from Perch's
//! `perch/verifiers` registry, what the canonical form binds, and the reads
//! the doc compiler's verification checks are built on.

mod common;

use common::{
    assert_accepts, assert_rejects, base_doc, rule, signer, ADMIN_KEY_HEX, CI_KEY_HEX,
    ED25519_VERIFIER, REGISTRY, WEBAUTHN_VERIFIER,
};
use perch_ir::recovery::{derive_target, DeriveAction, Replacement};
use perch_ir::{
    canonical_json, doc_hash, from_json, is_admin_document, unverified_reuse, unverified_verifiers,
    PolicyDoc, Principals, Scope, SignerDecl, SignerMethod, ThresholdPrincipals, ValidationError,
};

const NAME: &str = "perch-webauthn-verifier@0.1.0";

fn named(id: &str, verifier: &str, key: &str, name: &str) -> SignerDecl {
    SignerDecl {
        id: id.into(),
        method: SignerMethod::External {
            verifier: verifier.into(),
            key: key.into(),
            verifier_name: Some(name.into()),
        },
    }
}

fn named_doc() -> PolicyDoc {
    let mut doc = base_doc();
    doc.signers[0] = named("admin", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX, NAME);
    doc
}

#[test]
fn a_named_signer_reads_and_canonicalizes_with_its_name_beside_its_address() {
    let json = format!(
        r#"{{"version":1,"signers":[{{"verifier-name":"{NAME}","key":"{ADMIN_KEY_HEX}","id":"admin","verifier":"{WEBAUTHN_VERIFIER}"}}],
            "rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}}]}}"#
    );
    let doc = from_json(&json).unwrap();
    assert_eq!(doc, named_doc());
    assert_accepts(&doc);
    assert_eq!(
        canonical_json(&doc),
        format!(
            r#"{{"rules":[{{"name":"admin","principals":{{"signers":["admin"],"type":"all"}},"scope":{{"type":"self-admin"}}}}],"signers":[{{"id":"admin","key":"{ADMIN_KEY_HEX}","verifier":"{WEBAUTHN_VERIFIER}","verifier-name":"{NAME}"}}],"version":1}}"#
        )
    );
    assert_eq!(from_json(&canonical_json(&doc)).unwrap(), doc);
}

#[test]
fn the_hash_binds_the_name_the_version_and_the_address() {
    let doc = named_doc();
    let unnamed = base_doc();
    assert_ne!(doc_hash(&doc), doc_hash(&unnamed));
    let mut other_version = named_doc();
    other_version.signers[0] = named(
        "admin",
        WEBAUTHN_VERIFIER,
        ADMIN_KEY_HEX,
        "perch-webauthn-verifier@0.1.1",
    );
    assert_ne!(doc_hash(&doc), doc_hash(&other_version));
    let mut other_address = named_doc();
    other_address.signers[0] = named("admin", ED25519_VERIFIER, ADMIN_KEY_HEX, NAME);
    assert_ne!(doc_hash(&doc), doc_hash(&other_address));
}

#[test]
fn an_unnamed_signer_hashes_as_before() {
    // No `verifier-name` member is written for a signer without one, so a
    // document that names no verifier keeps its bytes.
    let doc = base_doc();
    assert!(!canonical_json(&doc).contains("verifier-name"));
}

#[test]
fn a_name_is_only_an_external_signers_and_never_null() {
    let rules = r#""rules":[{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["admin"]}}]"#;
    for signer in [
        format!(r#"{{"id":"admin","address":"{REGISTRY}","verifier-name":"{NAME}"}}"#),
        format!(
            r#"{{"id":"admin","verifier":"{WEBAUTHN_VERIFIER}","key":"{ADMIN_KEY_HEX}","verifier-name":null}}"#
        ),
        format!(
            r#"{{"id":"admin","verifier":"{WEBAUTHN_VERIFIER}","key":"{ADMIN_KEY_HEX}","verifier-name":7}}"#
        ),
        format!(
            r#"{{"id":"admin","verifier":"{WEBAUTHN_VERIFIER}","key":"{ADMIN_KEY_HEX}","verifier-name":"{NAME}","verifier-name":"{NAME}"}}"#
        ),
        format!(r#"{{"id":"admin","verifier-name":"{NAME}","key":"{ADMIN_KEY_HEX}"}}"#),
    ] {
        let json = format!(r#"{{"version":1,"signers":[{signer}],{rules}}}"#);
        assert!(from_json(&json).is_err(), "{json}");
    }
}

#[test]
fn a_misspelled_name_fails_validation() {
    for bad in [
        "perch-webauthn-verifier",
        "Perch-Webauthn-Verifier@0.1.0",
        "perch_webauthn_verifier@0.1.0",
        "perch-webauthn-verifier@0.1",
        "perch-webauthn-verifier@v0.1.0",
        "perch-webauthn-verifier@0.01.0",
        "perch-webauthn-verifier@0.1.0-rc.1",
    ] {
        let mut doc = base_doc();
        doc.signers[0] = named("admin", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX, bad);
        assert_rejects(
            &doc,
            &ValidationError::InvalidVerifierName {
                id: "admin".into(),
                name: bad.into(),
            },
        );
    }
}

#[test]
fn an_admin_document_has_a_self_admin_rule_or_a_recovery_member() {
    assert!(is_admin_document(&base_doc()));
    let mut scoped = base_doc();
    scoped.rules = vec![rule("app", Scope::contract(REGISTRY), &["admin"])];
    assert!(!is_admin_document(&scoped));
    let recovery = from_json(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/ci-publish-recovery.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut recovery_only = recovery.clone();
    recovery_only
        .rules
        .retain(|r| !matches!(r.scope, Scope::SelfAdmin(_)));
    assert!(recovery_only.recovery.is_some());
    assert!(is_admin_document(&recovery_only));
}

#[test]
fn the_unverified_verifiers_are_the_ones_named_by_contract_id_alone() {
    let mut doc = base_doc();
    doc.signers[0] = named("admin", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX, NAME);
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    doc.signers
        .push(signer("ci2", ED25519_VERIFIER, ADMIN_KEY_HEX));
    doc.signers
        .push(signer("raw", WEBAUTHN_VERIFIER, CI_KEY_HEX));
    assert_eq!(
        unverified_verifiers(&doc),
        vec![ED25519_VERIFIER, WEBAUTHN_VERIFIER]
    );
    assert!(unverified_verifiers(&named_doc()).is_empty());
}

#[test]
fn a_rule_may_hold_one_signer_per_unverified_verifier() {
    let mut doc = base_doc();
    doc.signers[0] = named("admin", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX, NAME);
    doc.signers.push(signer("a", ED25519_VERIFIER, CI_KEY_HEX));
    doc.signers
        .push(signer("b", ED25519_VERIFIER, ADMIN_KEY_HEX));
    doc.signers
        .push(named("c", WEBAUTHN_VERIFIER, CI_KEY_HEX, NAME));
    // One unverified signer per rule, beside named ones of the same address.
    doc.rules
        .push(rule("one", Scope::contract(REGISTRY), &["admin", "a", "c"]));
    doc.rules
        .push(rule("other", Scope::contract(REGISTRY), &["b"]));
    assert_eq!(unverified_reuse(&doc), None);
    // Two under one unverified verifier, in a threshold as in an `all`.
    let mut two = doc.clone();
    two.rules
        .push(PolicyRule::threshold("pair", &["a", "c", "b"], 2));
    assert_eq!(unverified_reuse(&two), Some((3, ED25519_VERIFIER)));
    let mut all = doc.clone();
    all.rules[1] = rule("one", Scope::contract(REGISTRY), &["b", "a"]);
    assert_eq!(unverified_reuse(&all), Some((1, ED25519_VERIFIER)));
}

/// A `threshold` rule on the registry.
struct PolicyRule;

impl PolicyRule {
    fn threshold(name: &str, signers: &[&str], m: u32) -> perch_ir::Rule {
        let mut r = rule(name, Scope::contract(REGISTRY), &[]);
        r.principals = Principals::Threshold(ThresholdPrincipals {
            signers: signers.iter().map(|s| (*s).into()).collect(),
            m,
        });
        r
    }
}

#[test]
fn a_recovery_replacement_keeps_the_signers_verifier_name() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/ci-publish-recovery.json");
    let mut source = from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
    let SignerMethod::External { verifier, .. } = source.signers[0].method.clone() else {
        panic!("the fixture's admin is external");
    };
    source.signers[0] = named("admin", &verifier, ADMIN_KEY_HEX, NAME);
    let new_key = "04".to_string() + &"aa".repeat(64);
    let target = derive_target(
        &source,
        &source,
        DeriveAction::LostKey,
        &[Replacement {
            signer_id: "admin".into(),
            method: SignerMethod::External {
                verifier: verifier.clone(),
                key: new_key.clone(),
                verifier_name: None,
            },
        }],
        None,
    )
    .unwrap();
    assert_eq!(
        target.signers[0],
        named("admin", &verifier, &new_key, NAME),
        "the replacement takes the key; the signer keeps its verifier and its name"
    );
}
