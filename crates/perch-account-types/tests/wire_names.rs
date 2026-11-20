//! Which names are inside the bytes. A `#[contracttype]` type's name is in
//! the contract spec only, so renaming `Signer` would keep every encoded
//! value; its variant and field names are in the encoding, so renaming
//! `Delegated`/`External` or `AuthPayload.signers` would change every stored
//! rule, every `__check_auth` payload a wallet builds, and the factory's
//! address salt. Perch keeps OpenZeppelin's names on the wire
//! (`tests/openzeppelin.rs`) and says *credential* only in prose: a signer is
//! a slot a document names by its signer id, a credential the
//! `Delegated(address)` or `External(verifier, key)` value that fills it.

use perch_account_types::{AuthPayload, Signer};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, Address, Bytes, Env, IntoVal, Map, Val, Vec};

/// `Signer` under another type name.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Credential {
    Delegated(Address),
    External(Address, Bytes),
}

/// `Signer` with its variants renamed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Renamed {
    Account(Address),
    Verified(Address, Bytes),
}

/// `AuthPayload` with its `signers` field renamed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenamedField {
    pub credentials: Map<Signer, Bytes>,
    pub context_rule_ids: Vec<u32>,
}

fn xdr<T: IntoVal<Env, Val>>(e: &Env, v: T) -> std::vec::Vec<u8> {
    let v: Val = v.into_val(e);
    v.to_xdr(e).iter().collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_type_rename_keeps_the_bytes_a_variant_or_field_rename_does_not() {
    let e = Env::default();
    let verifier = Address::generate(&e);
    let key = Bytes::from_slice(&e, &[7; 65]);
    let signer = xdr(&e, Signer::External(verifier.clone(), key.clone()));
    assert_eq!(
        signer,
        xdr(&e, Credential::External(verifier.clone(), key.clone()))
    );
    assert_ne!(signer, xdr(&e, Renamed::Verified(verifier, key)));

    let delegate = Address::generate(&e);
    let mut signers = Map::new(&e);
    signers.set(Signer::Delegated(delegate), Bytes::from_slice(&e, &[9; 64]));
    let ids = Vec::from_array(&e, [0u32]);
    let payload = xdr(
        &e,
        AuthPayload {
            signers: signers.clone(),
            context_rule_ids: ids.clone(),
        },
    );
    assert_ne!(
        payload,
        xdr(
            &e,
            RenamedField {
                credentials: signers,
                context_rule_ids: ids,
            }
        )
    );
    assert!(contains(&payload, b"signers"));
    assert!(contains(&payload, b"Delegated"));
}
