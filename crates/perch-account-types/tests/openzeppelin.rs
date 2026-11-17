//! Each type is OpenZeppelin's on the wire and in the contract spec: the
//! same spec entry, and values with the same XDR that read back as the
//! other type's. `SmartAccountError`'s cases are a subset of OZ's, each with
//! OZ's name, code, and doc.

use perch_account_types::{AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccountError};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::{Limits, ReadXdr, ScSpecEntry, ToXdr};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, Map, String, TryFromVal, Val, Vec};
use stellar_accounts::smart_account as oz;

#[test]
fn the_spec_entries_are_openzeppelins() {
    assert_eq!(Signer::spec_xdr(), oz::Signer::spec_xdr());
    assert_eq!(AuthPayload::spec_xdr(), oz::AuthPayload::spec_xdr());
    assert_eq!(ContextRuleType::spec_xdr(), oz::ContextRuleType::spec_xdr());
    assert_eq!(ContextRule::spec_xdr(), oz::ContextRule::spec_xdr());
}

#[test]
fn every_error_case_is_openzeppelins() {
    let entry = |xdr: &[u8]| match ScSpecEntry::from_xdr(xdr, Limits::none()).unwrap() {
        ScSpecEntry::UdtErrorEnumV0(e) => e,
        other => panic!("not an error enum: {other:?}"),
    };
    let ours = entry(&SmartAccountError::spec_xdr());
    let theirs = entry(&oz::SmartAccountError::spec_xdr());
    assert_eq!(
        (&ours.doc, &ours.lib, &ours.name),
        (&theirs.doc, &theirs.lib, &theirs.name)
    );
    let codes: std::vec::Vec<u32> = ours.cases.iter().map(|c| c.value).collect();
    assert_eq!(codes, [3000, 3002, 3003, 3014, 3016]);
    for case in ours.cases.iter() {
        assert!(theirs.cases.contains(case), "{case:?} is not OZ's");
    }
    let pairs = [
        (
            SmartAccountError::ContextRuleNotFound,
            oz::SmartAccountError::ContextRuleNotFound,
        ),
        (
            SmartAccountError::UnvalidatedContext,
            oz::SmartAccountError::UnvalidatedContext,
        ),
        (
            SmartAccountError::ExternalVerificationFailed,
            oz::SmartAccountError::ExternalVerificationFailed,
        ),
        (
            SmartAccountError::ContextRuleIdsLengthMismatch,
            oz::SmartAccountError::ContextRuleIdsLengthMismatch,
        ),
        (
            SmartAccountError::UnauthorizedSigner,
            oz::SmartAccountError::UnauthorizedSigner,
        ),
    ];
    for (ours, theirs) in pairs {
        assert_eq!(
            soroban_sdk::Error::from(ours),
            soroban_sdk::Error::from(theirs)
        );
    }
}

/// `ours` and `theirs` have the same XDR, and each reads back as the other.
fn same_value<A, B>(e: &Env, ours: A, theirs: B)
where
    A: Clone + core::fmt::Debug + PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,
    B: Clone + core::fmt::Debug + PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    let a: Val = ours.clone().into_val(e);
    let b: Val = theirs.clone().into_val(e);
    assert_eq!(a.to_xdr(e), b.to_xdr(e));
    assert_eq!(B::try_from_val(e, &a).ok(), Some(theirs));
    assert_eq!(A::try_from_val(e, &b).ok(), Some(ours));
}

#[test]
fn values_encode_as_openzeppelins() {
    let e = Env::default();
    let verifier = Address::generate(&e);
    let delegate = Address::generate(&e);
    let key = Bytes::from_slice(&e, &[7; 65]);
    let signers = [
        (
            Signer::Delegated(delegate.clone()),
            oz::Signer::Delegated(delegate),
        ),
        (
            Signer::External(verifier.clone(), key.clone()),
            oz::Signer::External(verifier, key),
        ),
    ];
    for (ours, theirs) in signers.clone() {
        same_value(&e, ours, theirs);
    }

    let sig = Bytes::from_slice(&e, &[9; 64]);
    let ids = Vec::from_array(&e, [0u32, 3]);
    let mut our_map = Map::new(&e);
    let mut their_map = Map::new(&e);
    for (ours, theirs) in signers.clone() {
        our_map.set(ours, sig.clone());
        their_map.set(theirs, sig.clone());
    }
    same_value(
        &e,
        AuthPayload {
            signers: our_map,
            context_rule_ids: ids.clone(),
        },
        oz::AuthPayload {
            signers: their_map,
            context_rule_ids: ids,
        },
    );

    let owner = Address::generate(&e);
    let tag = String::from_str(&e, "tag");
    let hash = BytesN::from_array(&e, &[1; 32]);
    let types = [
        (ContextRuleType::Default, oz::ContextRuleType::Default),
        (
            ContextRuleType::CallContract(owner.clone()),
            oz::ContextRuleType::CallContract(owner.clone()),
        ),
        (
            ContextRuleType::CreateContract(hash.clone()),
            oz::ContextRuleType::CreateContract(hash),
        ),
        (
            ContextRuleType::CreateContractExternalRef(owner.clone(), tag.clone()),
            oz::ContextRuleType::CreateContractExternalRef(owner.clone(), tag),
        ),
    ];
    for (ours, theirs) in types.iter().cloned() {
        same_value(&e, ours, theirs);
    }

    let policy = Address::generate(&e);
    let (our_type, their_type) = types[1].clone();
    let name = String::from_str(&e, "admin");
    same_value(
        &e,
        ContextRule {
            id: 4,
            context_type: our_type,
            name: name.clone(),
            signers: Vec::from_array(&e, [signers[0].0.clone(), signers[1].0.clone()]),
            signer_ids: Vec::from_array(&e, [1, 2]),
            policies: Vec::from_array(&e, [policy.clone()]),
            policy_ids: Vec::from_array(&e, [5]),
            valid_until: Some(100),
        },
        oz::ContextRule {
            id: 4,
            context_type: their_type,
            name,
            signers: Vec::from_array(&e, [signers[0].1.clone(), signers[1].1.clone()]),
            signer_ids: Vec::from_array(&e, [1, 2]),
            policies: Vec::from_array(&e, [policy]),
            policy_ids: Vec::from_array(&e, [5]),
            valid_until: Some(100),
        },
    );
}
