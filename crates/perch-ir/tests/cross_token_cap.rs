mod common;
use common::*;
use perch_ir::{AddressEqPred, CapRecipient, ValidationError};

fn doc() -> perch_ir::PolicyDoc {
    perch_ir::from_json(include_str!("../../../testdata/cross-token-cap.json")).unwrap()
}

#[test]
fn recipient_canonical_form_and_hash_match_the_independent_vector() {
    let d = doc();
    assert_accepts(&d);
    assert_eq!(d.compiled_rule_count(), 3);
    assert_eq!(
        perch_ir::canonical_json(&d),
        include_str!("../../../testdata/cross-token-cap.canonical.json").trim()
    );
    assert_eq!(
        perch_ir::doc_hash_hex(&d),
        include_str!("../../../testdata/cross-token-cap.doc-hash").trim()
    );
    for recipient in [
        None,
        Some(CapRecipient::Any),
        Some(CapRecipient::AddressEq(AddressEqPred {
            address: G_ADDR.into(),
        })),
    ] {
        let mut d = d.clone();
        d.rules[1].cap.as_mut().unwrap().recipient = recipient;
        assert_accepts(&d);
        assert_eq!(
            perch_ir::from_json(&perch_ir::canonical_json(&d)).unwrap(),
            d
        );
    }
}

#[test]
fn cross_token_scope_cannot_leave_token_operations_uncapped() {
    for function in perch_ir::validate::TOKEN_MOVING_FUNCTIONS {
        let mut d = doc();
        d.rules[1].functions = Some(vec!["guess".into(), (*function).into()]);
        assert_rejects(
            &d,
            &ValidationError::UnsafeCrossTokenFunctions {
                rule: "game".into(),
            },
        );
    }
    let mut d = doc();
    d.rules[1].functions = None;
    assert_rejects(
        &d,
        &ValidationError::UnsafeCrossTokenFunctions {
            rule: "game".into(),
        },
    );
}

#[test]
fn recipient_requires_a_cross_token_cap_and_a_valid_address() {
    for token in [None, Some(REGISTRY.to_string())] {
        let mut d = doc();
        d.rules[1].cap.as_mut().unwrap().token = token;
        assert_rejects(
            &d,
            &ValidationError::CapRecipientWithoutCrossToken {
                rule: "game".into(),
            },
        );
    }
    for address in [
        "bad",
        "M",
        "GCY63ZN3C232UXXWENGF5I3PUHSYLR45MKCXS53MI3NSCWBFERWKHEPA",
    ] {
        let mut d = doc();
        d.rules[1].cap.as_mut().unwrap().recipient = Some(CapRecipient::AddressEq(AddressEqPred {
            address: address.into(),
        }));
        assert_rejects(
            &d,
            &ValidationError::InvalidCapRecipient {
                rule: "game".into(),
                address: address.into(),
            },
        );
    }
}

#[test]
fn generated_transfer_cannot_target_the_documents_zk_contracts() {
    let base = perch_ir::from_json(include_str!(
        "../../../testdata/ci-publish-recovery-combined.json"
    ))
    .unwrap();
    let zk = match &base.recovery.as_ref().unwrap().mode {
        perch_ir::RecoveryMode::Combined(_, zk) => zk.clone(),
        _ => unreachable!(),
    };
    for contract in [zk.adapter, zk.pool] {
        let mut d = base.clone();
        let mut r = doc().rules.remove(1);
        r.cap.as_mut().unwrap().token = Some(contract.clone());
        d.rules.push(r);
        assert_rejects(
            &d,
            &ValidationError::RuleScopedToRecoveryContract {
                rule: "game".into(),
                address: contract,
            },
        );
    }
}
