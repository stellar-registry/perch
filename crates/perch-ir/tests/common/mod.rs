//! Shared builders and checksum-valid strkey constants for the perch-ir test
//! suite. All addresses are real strkeys (valid CRC16) derived from fixed
//! seeds, so they stay valid if shape checks ever grow checksum verification.
#![allow(dead_code)]

use perch_ir::{AllPrincipals, PolicyDoc, Principals, Rule, Scope, SignerDecl};

/// WebAuthn verifier contract (C-address, checksum-valid).
pub const WEBAUTHN_VERIFIER: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
/// Ed25519 verifier contract (C-address, checksum-valid).
pub const ED25519_VERIFIER: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
/// Registry contract targeted by contract-scoped rules (C-address).
pub const REGISTRY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
/// A second contract address (C-address) for policy references.
pub const POLICY_CONTRACT: &str = "CAPS4YALJ6I4D3NDMRG5JZGDAAT266PSPLSHIITGUKBXUVAH5SUPZQKE";
/// A G-address (account strkey, checksum-valid).
pub const G_ADDR: &str = "GCY63ZN3C232UXXWENGF5I3PUHSYLR45MKCXS53MI3NSCWBFERWKHEPH";

/// 65-byte uncompressed P-256 public key, hex.
pub const ADMIN_KEY_HEX: &str = "045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e";
/// 32-byte ed25519 public key, hex.
pub const CI_KEY_HEX: &str = "1ce6040b0d03232ac6c911b0c375f1a52ebdefff56fd361d13680e23ca578a17";

/// Build a signer declaration.
pub fn signer(id: &str, verifier: &str, key: &str) -> SignerDecl {
    SignerDecl {
        id: id.into(),
        verifier: verifier.into(),
        key: key.into(),
    }
}

/// Build a rule with the given name and scope, authorized by `signers`,
/// with no functions/args/expiry.
pub fn rule(name: &str, scope: Scope, signers: &[&str]) -> Rule {
    Rule {
        name: name.into(),
        scope,
        principals: Principals::All(AllPrincipals {
            signers: signers.iter().map(|s| (*s).into()).collect(),
        }),
        functions: None,
        args: None,
        not_after: None,
    }
}

/// A minimal valid document: one admin signer and one self-admin root rule.
pub fn base_doc() -> PolicyDoc {
    PolicyDoc {
        version: 1,
        network: None,
        signers: vec![signer("admin", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX)],
        rules: vec![rule("admin-root", Scope::self_admin(), &["admin"])],
    }
}

/// Assert `doc` fails validation and the error list contains `expected`.
pub fn assert_rejects(doc: &PolicyDoc, expected: &perch_ir::ValidationError) {
    let errors = perch_ir::validate(doc).expect_err("expected validation to fail");
    assert!(
        errors.contains(expected),
        "expected {expected:?} in {errors:?}"
    );
}

/// Assert `doc` passes validation.
pub fn assert_accepts(doc: &PolicyDoc) {
    if let Err(errors) = perch_ir::validate(doc) {
        panic!("expected valid doc, got {errors:?}");
    }
}
