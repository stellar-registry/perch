//! Validation matrix: for every [`ValidationError`] variant, at least one
//! rejecting case and a nearby accepting case.

mod common;

use common::{
    assert_accepts, assert_rejects, base_doc, delegated_signer, rule, signer, ADMIN_KEY_HEX,
    CI_KEY_HEX, ED25519_VERIFIER, G_ADDR, POLICY_CONTRACT, REGISTRY, WEBAUTHN_VERIFIER,
};
use perch_ir::{
    validate, AddressEqPred, ArgConstraint, ArgPred, CapConstraint, Principals, Scope,
    SelfAuthenticatingPrincipals, StringInPred, StringPrefixPred, U32EqPred, ValidationError,
    ACK_SENTINEL,
};

// --- UnsupportedVersion ------------------------------------------------------

#[test]
fn rejects_version_other_than_1() {
    let mut doc = base_doc();
    doc.version = 2;
    assert_rejects(&doc, &ValidationError::UnsupportedVersion { version: 2 });
    doc.version = 0;
    assert_rejects(&doc, &ValidationError::UnsupportedVersion { version: 0 });
}

#[test]
fn accepts_version_1() {
    assert_accepts(&base_doc());
}

// --- EmptySignerId -----------------------------------------------------------

#[test]
fn rejects_empty_signer_id() {
    let mut doc = base_doc();
    doc.signers[0].id = String::new();
    assert_rejects(&doc, &ValidationError::EmptySignerId { position: 0 });
}

#[test]
fn accepts_non_empty_signer_id() {
    assert_accepts(&base_doc());
}

// --- DuplicateSignerId -------------------------------------------------------

#[test]
fn rejects_duplicate_signer_ids() {
    let mut doc = base_doc();
    doc.signers
        .push(signer("admin", ED25519_VERIFIER, CI_KEY_HEX));
    assert_rejects(
        &doc,
        &ValidationError::DuplicateSignerId { id: "admin".into() },
    );
}

#[test]
fn accepts_distinct_signer_ids() {
    let mut doc = base_doc();
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    assert_accepts(&doc);
}

// --- DuplicateSignerKey ------------------------------------------------------

#[test]
fn rejects_two_ids_sharing_one_key() {
    let mut doc = base_doc();
    // Same verifier and key as "admin" under a new id: reads as two signers
    // (e.g. a 2-of-2 rule) but is one physical key.
    doc.signers
        .push(signer("backup", WEBAUTHN_VERIFIER, ADMIN_KEY_HEX));
    assert_rejects(
        &doc,
        &ValidationError::DuplicateSignerKey {
            id: "backup".into(),
            first_id: "admin".into(),
        },
    );
}

#[test]
fn duplicate_signer_key_detection_is_hex_case_insensitive() {
    let mut doc = base_doc();
    doc.signers.push(signer(
        "backup",
        WEBAUTHN_VERIFIER,
        &ADMIN_KEY_HEX.to_uppercase(),
    ));
    assert_rejects(
        &doc,
        &ValidationError::DuplicateSignerKey {
            id: "backup".into(),
            first_id: "admin".into(),
        },
    );
}

#[test]
fn accepts_same_key_under_different_verifier() {
    let mut doc = base_doc();
    // Identical key material but a different verifier is a genuinely distinct
    // signer, so it must not trip the duplicate-key check.
    doc.signers
        .push(signer("other", ED25519_VERIFIER, ADMIN_KEY_HEX));
    assert_accepts(&doc);
}

// --- InvalidSignerKeyHex -----------------------------------------------------

#[test]
fn rejects_non_hex_signer_key() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], "zz");
    assert_rejects(
        &doc,
        &ValidationError::InvalidSignerKeyHex { id: "admin".into() },
    );
}

#[test]
fn rejects_odd_length_signer_key_hex() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], "abc");
    assert_rejects(
        &doc,
        &ValidationError::InvalidSignerKeyHex { id: "admin".into() },
    );
}

#[test]
fn accepts_valid_hex_signer_key() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], "deadbeef");
    assert_accepts(&doc);
}

// --- SignerKeyLength ---------------------------------------------------------

#[test]
fn rejects_empty_signer_key() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], "");
    assert_rejects(
        &doc,
        &ValidationError::SignerKeyLength {
            id: "admin".into(),
            len: 0,
        },
    );
}

#[test]
fn rejects_signer_key_over_256_bytes() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], &"ab".repeat(257));
    assert_rejects(
        &doc,
        &ValidationError::SignerKeyLength {
            id: "admin".into(),
            len: 257,
        },
    );
}

#[test]
fn accepts_signer_key_boundary_lengths() {
    let mut doc = base_doc();
    common::set_key(&mut doc.signers[0], "ab"); // 1 byte
    assert_accepts(&doc);
    common::set_key(&mut doc.signers[0], &"ab".repeat(256)); // 256 bytes
    assert_accepts(&doc);
}

// --- InvalidVerifierAddress --------------------------------------------------

#[test]
fn rejects_verifier_that_is_not_a_c_address() {
    let mut doc = base_doc();
    // A G-address is a valid strkey but not a contract address.
    common::set_verifier(&mut doc.signers[0], G_ADDR);
    assert_rejects(
        &doc,
        &ValidationError::InvalidVerifierAddress {
            id: "admin".into(),
            address: G_ADDR.into(),
        },
    );
}

#[test]
fn rejects_verifier_with_bad_length_case_or_charset() {
    for bad in [
        &WEBAUTHN_VERIFIER[..55],                  // too short
        &format!("{WEBAUTHN_VERIFIER}A"),          // too long
        &WEBAUTHN_VERIFIER.to_lowercase(),         // lowercase
        &format!("C1{}", &WEBAUTHN_VERIFIER[2..]), // '1' outside base32
        "",                                        // empty
    ] {
        let mut doc = base_doc();
        common::set_verifier(&mut doc.signers[0], bad);
        assert_rejects(
            &doc,
            &ValidationError::InvalidVerifierAddress {
                id: "admin".into(),
                address: (*bad).to_string(),
            },
        );
    }
}

#[test]
fn accepts_shape_valid_verifier() {
    assert_accepts(&base_doc());
}

// --- EmptyRuleName -----------------------------------------------------------

#[test]
fn rejects_empty_rule_name() {
    let mut doc = base_doc();
    doc.rules[0].name = String::new();
    assert_rejects(&doc, &ValidationError::EmptyRuleName { position: 0 });
}

#[test]
fn accepts_non_empty_rule_name() {
    assert_accepts(&base_doc());
}

// --- DuplicateRuleName -------------------------------------------------------

#[test]
fn rejects_duplicate_rule_names() {
    let mut doc = base_doc();
    doc.rules
        .push(rule("admin", Scope::contract(REGISTRY), &["admin"]));
    assert_rejects(
        &doc,
        &ValidationError::DuplicateRuleName {
            name: "admin".into(),
        },
    );
}

#[test]
fn accepts_distinct_rule_names() {
    let mut doc = base_doc();
    doc.rules
        .push(rule("publish", Scope::contract(REGISTRY), &["admin"]));
    assert_accepts(&doc);
}

// --- InvalidContractAddress --------------------------------------------------

#[test]
fn rejects_contract_scope_with_non_c_address() {
    let mut doc = base_doc();
    doc.rules[0].scope = Scope::contract(G_ADDR);
    assert_rejects(
        &doc,
        &ValidationError::InvalidContractAddress {
            rule: "admin".into(),
            address: G_ADDR.into(),
        },
    );
}

#[test]
fn accepts_contract_scope_with_c_address() {
    let mut doc = base_doc();
    doc.rules[0].scope = Scope::contract(REGISTRY);
    assert_accepts(&doc);
}

// --- EmptyPrincipalSigners ---------------------------------------------------

#[test]
fn rejects_empty_all_principals() {
    let mut doc = base_doc();
    doc.rules[0].principals = Principals::All(perch_ir::AllPrincipals { signers: vec![] });
    assert_rejects(
        &doc,
        &ValidationError::EmptyPrincipalSigners {
            rule: "admin".into(),
        },
    );
}

#[test]
fn accepts_non_empty_all_principals() {
    assert_accepts(&base_doc());
}

// --- DuplicatePrincipalSigner ------------------------------------------------

#[test]
fn rejects_repeated_signer_in_principals_list() {
    let mut doc = base_doc();
    doc.rules[0].principals = Principals::All(perch_ir::AllPrincipals {
        signers: vec!["admin".into(), "admin".into()],
    });
    assert_rejects(
        &doc,
        &ValidationError::DuplicatePrincipalSigner {
            rule: "admin".into(),
            id: "admin".into(),
        },
    );
}

#[test]
fn accepts_distinct_signers_in_principals_list() {
    let mut doc = base_doc();
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    doc.rules[0].principals = Principals::All(perch_ir::AllPrincipals {
        signers: vec!["admin".into(), "ci".into()],
    });
    assert_accepts(&doc);
}

// --- UnknownSignerRef --------------------------------------------------------

#[test]
fn rejects_reference_to_undeclared_signer() {
    let mut doc = base_doc();
    doc.rules[0].principals = Principals::All(perch_ir::AllPrincipals {
        signers: vec!["admin".into(), "ghost".into()],
    });
    assert_rejects(
        &doc,
        &ValidationError::UnknownSignerRef {
            rule: "admin".into(),
            id: "ghost".into(),
        },
    );
}

#[test]
fn accepts_references_to_declared_signers() {
    let mut doc = base_doc();
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    doc.rules[0].principals = Principals::All(perch_ir::AllPrincipals {
        signers: vec!["admin".into(), "ci".into()],
    });
    assert_accepts(&doc);
}

// --- Threshold (M-of-N) ------------------------------------------------------

/// A two-signer base doc whose admin rule is an M-of-N threshold.
fn threshold_doc(m: u32) -> perch_ir::PolicyDoc {
    let mut doc = base_doc();
    doc.signers.push(signer("ci", ED25519_VERIFIER, CI_KEY_HEX));
    doc.rules[0].principals = Principals::Threshold(perch_ir::ThresholdPrincipals {
        signers: vec!["admin".into(), "ci".into()],
        m,
    });
    doc
}

#[test]
fn accepts_valid_threshold() {
    // 1-of-2 and 2-of-2 are both in range.
    assert_accepts(&threshold_doc(1));
    assert_accepts(&threshold_doc(2));
}

#[test]
fn rejects_zero_threshold() {
    // m = 0 would authorize with no signatures (INV-1).
    assert_rejects(
        &threshold_doc(0),
        &ValidationError::InvalidThreshold {
            rule: "admin".into(),
            m: 0,
            n: 2,
        },
    );
}

#[test]
fn rejects_threshold_above_signer_count() {
    // m > N can never be met.
    assert_rejects(
        &threshold_doc(3),
        &ValidationError::InvalidThreshold {
            rule: "admin".into(),
            m: 3,
            n: 2,
        },
    );
}

#[test]
fn rejects_empty_threshold_principals() {
    let mut doc = base_doc();
    doc.rules[0].principals = Principals::Threshold(perch_ir::ThresholdPrincipals {
        signers: vec![],
        m: 1,
    });
    assert_rejects(
        &doc,
        &ValidationError::EmptyPrincipalSigners {
            rule: "admin".into(),
        },
    );
}

#[test]
fn rejects_repeated_signer_in_threshold() {
    let mut doc = base_doc();
    // Two ids resolving to the "admin" ref would silently lower the real
    // quorum, so the duplicate reference is rejected.
    doc.rules[0].principals = Principals::Threshold(perch_ir::ThresholdPrincipals {
        signers: vec!["admin".into(), "admin".into()],
        m: 2,
    });
    assert_rejects(
        &doc,
        &ValidationError::DuplicatePrincipalSigner {
            rule: "admin".into(),
            id: "admin".into(),
        },
    );
}

#[test]
fn rejects_undeclared_signer_in_threshold() {
    let mut doc = base_doc();
    doc.rules[0].principals = Principals::Threshold(perch_ir::ThresholdPrincipals {
        signers: vec!["admin".into(), "ghost".into()],
        m: 1,
    });
    assert_rejects(
        &doc,
        &ValidationError::UnknownSignerRef {
            rule: "admin".into(),
            id: "ghost".into(),
        },
    );
}

// --- WrongAckSentinel / InvalidPolicyAddress / InvalidInstallParamHex --------

fn self_auth(policy: &str, install_param_hex: &str, ack: &str) -> Principals {
    Principals::SelfAuthenticating(SelfAuthenticatingPrincipals {
        policy: policy.into(),
        install_param_hex: install_param_hex.into(),
        ack: ack.into(),
    })
}

#[test]
fn rejects_wrong_ack_sentinel() {
    for bad_ack in [
        "",
        "yes",
        "this-policy-authenticates",
        ACK_SENTINEL.to_uppercase().as_str(),
    ] {
        let mut doc = base_doc();
        doc.rules[0].principals = self_auth(POLICY_CONTRACT, "", bad_ack);
        assert_rejects(
            &doc,
            &ValidationError::WrongAckSentinel {
                rule: "admin".into(),
            },
        );
    }
}

#[test]
fn rejects_self_auth_policy_that_is_not_a_c_address() {
    let mut doc = base_doc();
    doc.rules[0].principals = self_auth(G_ADDR, "", ACK_SENTINEL);
    assert_rejects(
        &doc,
        &ValidationError::InvalidPolicyAddress {
            rule: "admin".into(),
            address: G_ADDR.into(),
        },
    );
}

#[test]
fn rejects_self_auth_with_invalid_install_param_hex() {
    let mut doc = base_doc();
    doc.rules[0].principals = self_auth(POLICY_CONTRACT, "xyz", ACK_SENTINEL);
    assert_rejects(
        &doc,
        &ValidationError::InvalidInstallParamHex {
            rule: "admin".into(),
        },
    );
}

#[test]
fn accepts_self_auth_with_exact_sentinel_and_valid_fields() {
    let mut doc = base_doc();
    doc.rules[0].principals = self_auth(POLICY_CONTRACT, "", ACK_SENTINEL);
    assert_accepts(&doc);
    doc.rules[0].principals = self_auth(POLICY_CONTRACT, "deadbeef", ACK_SENTINEL);
    assert_accepts(&doc);
}

// --- EmptyFunctions / EmptyFunctionName / DuplicateFunction ------------------

#[test]
fn rejects_present_but_empty_functions() {
    let mut doc = base_doc();
    doc.rules[0].functions = Some(vec![]);
    assert_rejects(
        &doc,
        &ValidationError::EmptyFunctions {
            rule: "admin".into(),
        },
    );
}

#[test]
fn rejects_empty_function_name() {
    let mut doc = base_doc();
    doc.rules[0].functions = Some(vec!["publish".into(), String::new()]);
    assert_rejects(
        &doc,
        &ValidationError::EmptyFunctionName {
            rule: "admin".into(),
        },
    );
}

#[test]
fn rejects_duplicate_function_names() {
    let mut doc = base_doc();
    doc.rules[0].functions = Some(vec!["publish".into(), "publish".into()]);
    assert_rejects(
        &doc,
        &ValidationError::DuplicateFunction {
            rule: "admin".into(),
            name: "publish".into(),
        },
    );
}

#[test]
fn accepts_absent_functions_and_distinct_function_names() {
    let mut doc = base_doc();
    doc.rules[0].functions = None;
    assert_accepts(&doc);
    doc.rules[0].functions = Some(vec!["publish".into(), "publish_hash".into()]);
    assert_accepts(&doc);
}

// --- EmptyArgs / DuplicateArgIndex -------------------------------------------

fn arg(index: u32, pred: ArgPred) -> ArgConstraint {
    ArgConstraint { index, pred }
}

#[test]
fn rejects_present_but_empty_args() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![]);
    assert_rejects(
        &doc,
        &ValidationError::EmptyArgs {
            rule: "admin".into(),
        },
    );
}

#[test]
fn rejects_duplicate_arg_indexes() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![
        arg(0, ArgPred::is_self()),
        arg(0, ArgPred::U32Eq(U32EqPred { value: 7 })),
    ]);
    assert_rejects(
        &doc,
        &ValidationError::DuplicateArgIndex {
            rule: "admin".into(),
            index: 0,
        },
    );
}

#[test]
fn accepts_absent_args_and_distinct_indexes() {
    let mut doc = base_doc();
    doc.rules[0].args = None;
    assert_accepts(&doc);
    doc.rules[0].args = Some(vec![
        arg(0, ArgPred::is_self()),
        arg(
            1,
            ArgPred::StringPrefix(StringPrefixPred { prefix: "v".into() }),
        ),
    ]);
    assert_accepts(&doc);
}

// --- EmptyStringInValues -----------------------------------------------------

#[test]
fn rejects_string_in_with_empty_values() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        2,
        ArgPred::StringIn(StringInPred { values: vec![] }),
    )]);
    assert_rejects(
        &doc,
        &ValidationError::EmptyStringInValues {
            rule: "admin".into(),
            index: 2,
        },
    );
}

#[test]
fn accepts_string_in_with_values() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        2,
        ArgPred::StringIn(StringInPred {
            values: vec!["a".into(), "b".into()],
        }),
    )]);
    assert_accepts(&doc);
}

// --- DuplicateStringInValue --------------------------------------------------

#[test]
fn rejects_string_in_with_repeated_value() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        2,
        ArgPred::StringIn(StringInPred {
            values: vec!["a".into(), "b".into(), "a".into()],
        }),
    )]);
    assert_rejects(
        &doc,
        &ValidationError::DuplicateStringInValue {
            rule: "admin".into(),
            index: 2,
            value: "a".into(),
        },
    );
}

#[test]
fn accepts_string_in_with_distinct_values() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        2,
        ArgPred::StringIn(StringInPred {
            values: vec!["a".into(), "b".into()],
        }),
    )]);
    assert_accepts(&doc);
}

// --- InvalidArgAddress -------------------------------------------------------

#[test]
fn rejects_address_eq_with_malformed_address() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        0,
        ArgPred::AddressEq(AddressEqPred {
            address: "not-an-address".into(),
        }),
    )]);
    assert_rejects(
        &doc,
        &ValidationError::InvalidArgAddress {
            rule: "admin".into(),
            index: 0,
            address: "not-an-address".into(),
        },
    );
}

#[test]
fn accepts_address_eq_with_c_or_g_address() {
    let mut doc = base_doc();
    doc.rules[0].args = Some(vec![arg(
        0,
        ArgPred::AddressEq(AddressEqPred {
            address: REGISTRY.into(),
        }),
    )]);
    assert_accepts(&doc);
    doc.rules[0].args = Some(vec![arg(
        0,
        ArgPred::AddressEq(AddressEqPred {
            address: G_ADDR.into(),
        }),
    )]);
    assert_accepts(&doc);
}

// --- ZeroNotAfterLedger ------------------------------------------------------

#[test]
fn rejects_zero_not_after_ledger() {
    let mut doc = base_doc();
    doc.rules[0].not_after_ledger = Some(0);
    assert_rejects(
        &doc,
        &ValidationError::ZeroNotAfterLedger {
            rule: "admin".into(),
        },
    );
}

#[test]
fn accepts_positive_or_absent_not_after_ledger() {
    let mut doc = base_doc();
    doc.rules[0].not_after_ledger = Some(1);
    assert_accepts(&doc);
    doc.rules[0].not_after_ledger = None;
    assert_accepts(&doc);
}

// --- Error collection & display ----------------------------------------------

#[test]
fn collects_all_errors_not_just_the_first() {
    let mut doc = base_doc();
    doc.version = 3;
    common::set_key(&mut doc.signers[0], "zz");
    doc.signers
        .push(signer("admin", ED25519_VERIFIER, CI_KEY_HEX));
    doc.rules[0].not_after_ledger = Some(0);
    doc.rules[0].functions = Some(vec![]);
    let errors = validate(&doc).expect_err("expected failure");
    assert!(errors.len() >= 5, "expected >= 5 errors, got {errors:?}");
    assert!(errors.contains(&ValidationError::UnsupportedVersion { version: 3 }));
    assert!(errors.contains(&ValidationError::InvalidSignerKeyHex { id: "admin".into() }));
    assert!(errors.contains(&ValidationError::DuplicateSignerId { id: "admin".into() }));
    assert!(errors.contains(&ValidationError::ZeroNotAfterLedger {
        rule: "admin".into()
    }));
    assert!(errors.contains(&ValidationError::EmptyFunctions {
        rule: "admin".into()
    }));
}

#[test]
fn display_names_the_offender() {
    let err = ValidationError::UnknownSignerRef {
        rule: "publish".into(),
        id: "ghost".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("publish") && msg.contains("ghost"), "{msg}");

    let err = ValidationError::SignerKeyLength {
        id: "admin".into(),
        len: 300,
    };
    let msg = err.to_string();
    assert!(msg.contains("admin") && msg.contains("300"), "{msg}");
}

// --- cap (#19 PR6): InvalidCapLimit / ZeroCapPeriod / InvalidCapToken /
// --- CapWithoutToken / CapTokenMismatch -------------------------------------

fn capped_doc(token: Option<&str>, limit: &str, period: u32) -> perch_ir::PolicyDoc {
    let mut doc = base_doc();
    let mut r = rule("spend", Scope::contract(REGISTRY), &["admin"]);
    r.cap = Some(CapConstraint {
        token: token.map(str::to_string),
        limit: limit.to_string(),
        period_ledgers: period,
    });
    doc.rules.push(r);
    doc
}

#[test]
fn accepts_valid_cap_with_and_without_token() {
    // Explicit token equal to the scope, and token-less (denominates in scope).
    assert_accepts(&capped_doc(Some(REGISTRY), "1000", 100));
    assert_accepts(&capped_doc(None, "1000", 100));
}

#[test]
fn rejects_cap_token_differing_from_scope() {
    // OZ spending_limit meters the scope contract's token, so an explicit token
    // that isn't the scope would silently cap a different contract.
    assert_rejects(
        &capped_doc(Some(POLICY_CONTRACT), "1000", 100),
        &ValidationError::CapTokenMismatch {
            rule: "spend".into(),
            token: POLICY_CONTRACT.into(),
            scope: REGISTRY.into(),
        },
    );
}

#[test]
fn rejects_non_positive_or_unparsable_cap_limit() {
    for bad in ["0", "-5", "abc"] {
        assert_rejects(
            &capped_doc(Some(REGISTRY), bad, 100),
            &ValidationError::InvalidCapLimit {
                rule: "spend".into(),
                limit: bad.into(),
            },
        );
    }
}

#[test]
fn rejects_zero_cap_period() {
    assert_rejects(
        &capped_doc(Some(REGISTRY), "1000", 0),
        &ValidationError::ZeroCapPeriod {
            rule: "spend".into(),
        },
    );
}

#[test]
fn rejects_invalid_cap_token() {
    assert_rejects(
        &capped_doc(Some("not-an-address"), "1000", 100),
        &ValidationError::InvalidCapToken {
            rule: "spend".into(),
            address: "not-an-address".into(),
        },
    );
    // A G-address is a valid strkey but not a contract address.
    assert_rejects(
        &capped_doc(Some(G_ADDR), "1000", 100),
        &ValidationError::InvalidCapToken {
            rule: "spend".into(),
            address: G_ADDR.into(),
        },
    );
}

#[test]
fn rejects_cap_without_token_on_self_admin() {
    let mut doc = base_doc();
    doc.rules[0].cap = Some(CapConstraint {
        token: None,
        limit: "1000".into(),
        period_ledgers: 100,
    });
    assert_rejects(
        &doc,
        &ValidationError::CapWithoutToken {
            rule: "admin".into(),
        },
    );
}

// --- delegated signers ---------------------------------------------------------

#[test]
fn accepts_delegated_signers_with_g_or_c_addresses() {
    let mut doc = base_doc();
    doc.signers.push(delegated_signer("dg", G_ADDR));
    doc.signers.push(delegated_signer("dc", REGISTRY));
    assert_accepts(&doc);
}

#[test]
fn rejects_a_malformed_delegated_address() {
    let mut doc = base_doc();
    doc.signers.push(delegated_signer("dg", "not-an-address"));
    assert_rejects(
        &doc,
        &ValidationError::InvalidDelegatedAddress {
            id: "dg".into(),
            address: "not-an-address".into(),
        },
    );
}

#[test]
fn rejects_the_same_delegated_address_under_two_ids() {
    // The delegated analogue of DuplicateSignerKey: an address IS the key, so
    // two ids over one address misrepresent the rule's real threshold.
    let mut doc = base_doc();
    doc.signers.push(delegated_signer("dg1", G_ADDR));
    doc.signers.push(delegated_signer("dg2", G_ADDR));
    assert_rejects(
        &doc,
        &ValidationError::DuplicateSignerKey {
            id: "dg2".into(),
            first_id: "dg1".into(),
        },
    );
}
